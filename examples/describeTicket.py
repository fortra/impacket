#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script that describes the values of the ticket (TGT or Service Ticket).
#
# Authors:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)

import json
import logging
import sys
import traceback
import argparse
import binascii
from Cryptodome.Hash import MD4
import datetime
import base64
from binascii import unhexlify, hexlify
from pyasn1.codec.der import decoder
from impacket import LOG, version
from impacket.examples import logger
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, EncTicketPart, AD_IF_RELEVANT
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum, string_to_key
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO


def parse_ccache(args):
    ccache = CCache.loadFile(args.ticket)

    principal = ccache.credentials[0].header['server'].prettyPrint()
    creds = ccache.getCredential(principal.decode())
    TGS = creds.toTGS(principal)
    decodedTGS = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

    for creds in ccache.credentials:
        logging.info("%-25s: %s" % ("UserName", creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')))
        logging.info("%-25s: %s" % ("UserRealm", creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')))
        spn = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
        logging.info("%-25s: %s" % ("ServiceName", spn))
        logging.info("%-25s: %s" % ("ServiceRealm", creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')))
        logging.info("%-25s: %s" % ("StartTime", datetime.datetime.fromtimestamp(creds['time']['starttime']).strftime("%d/%m/%Y %H:%H:%S %p")))
        logging.info("%-25s: %s" % ("EndTime", datetime.datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%H:%S %p")))
        logging.info("%-25s: %s" % ("RenewTill", datetime.datetime.fromtimestamp(creds['time']['renew_till']).strftime("%d/%m/%Y %H:%H:%S %p")))

        flags = []
        for k in constants.TicketFlags:
            if ((creds['tktflags'] >> (31 - k.value)) & 1) == 1:
                flags.append(constants.TicketFlags(k.value).name)
        logging.info("%-25s: (0x%x) %s" % ("Flags", creds['tktflags'], ", ".join(flags)))
        keyType = constants.EncryptionTypes(creds["key"]["keytype"]).name
        logging.info("%-25s: %s" % ("KeyType", keyType))
        logging.info("%-25s: %s" % ("Base64(key)", base64.b64encode(creds["key"]["keyvalue"]).decode("utf-8")))

        if spn.split('/')[0] != 'krbtgt':
            logging.debug("Attempting to create Kerberoast hash")
            # code adapted from Rubeus's DisplayTicket() (https://github.com/GhostPack/Rubeus/blob/3620814cd2c5f05e87cddd50211197bd932fec51/Rubeus/lib/LSA.cs)
            # if this isn't a TGT, try to display a Kerberoastable hash
            if keyType != "rc4_hmac"  and keyType != "aes256_cts_hmac_sha1_96":
                # can only display rc4_hmac ad it doesn't have a salt. DES/AES keys require the user/domain as a salt, and we don't have
                # the user account name that backs the requested SPN for the ticket, no no dice :(
                logging.debug("Service ticket uses encryption key type %s, unable to extract hash and salt" % keyType)
            elif keyType == "rc4_hmac":
                kerberoast_hash = kerberoast_from_ccache(decodedTGS = decodedTGS, spn = spn, username = args.user, domain = args.domain)
            elif args.user:
                if args.user.endswith("$"):
                    user = "host%s.%s" % (args.user.rstrip('$').lower(), args.domain.lower())
                else:
                    user = args.user
                kerberoast_hash = kerberoast_from_ccache(decodedTGS = decodedTGS, spn = spn, username = user, domain = args.domain)
            else:
                logging.error("AES256 in use but no '-u/--user' passed, unable to generate crackable hash")
            if kerberoast_hash:
                logging.info("%-25s: %s" % ("Kerberoast hash", kerberoast_hash))

    logging.debug("Handling Kerberos keys")
    ekeys = generate_kerberos_keys(args)
    # TODO : show message when decrypting ticket, unable to decrypt ticket if not enough arguments are given. Say what is missing

    # copypasta from krbrelayx.py
    # Select the correct encryption key
    etype = decodedTGS['ticket']['enc-part']['etype']
    try:
        logging.debug('Ticket is encrypted with %s (etype %d)' % (constants.EncryptionTypes(etype).name, etype))
        key = ekeys[etype]
        logging.debug('Using corresponding key: %s' % hexlify(key.contents).decode('utf-8'))
    # This raises a KeyError (pun intended) if our key is not found
    except KeyError:
        LOG.error('Could not find the correct encryption key! Ticket is encrypted with keytype %d, but keytype(s) %s were supplied',
                  decodedTGS['ticket']['enc-part']['etype'],
                  ', '.join([str(enctype) for enctype in ekeys.keys()]))
        return None

    # Recover plaintext info from ticket
    try:
        cipherText = decodedTGS['ticket']['enc-part']['cipher']
        newCipher = _enctype_table[int(etype)]
        plainText = newCipher.decrypt(key, 2, cipherText)
    except InvalidChecksum:
        logging.error('Ciphertext integrity failed. Most likely the account password or AES key is incorrect')
        if args.salt:
            logging.info('Make sure the salt/username/domain are set and with the proper values. In case of a computer account, append a "$" to the name.')
        return

    logging.debug('Ticket successfully decrypted')
    encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]
    sessionKey = Key(encTicketPart['key']['keytype'], bytes(encTicketPart['key']['keyvalue']))
    adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
    # So here we have the PAC
    pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
    parsed_pac = parse_pac(pacType)
    logging.info("  %-23s:" % ("LogonInfo"))
    logging.info("    %-21s: %s" % ("LogonTime", parsed_pac[0]["LogonTime"]))
    logging.info("    %-21s: %s" % ("LogoffTime", parsed_pac[0]["LogoffTime"]))
    logging.info("    %-21s: %s" % ("KickOffTime", parsed_pac[0]["KickOffTime"]))
    logging.info("    %-21s: %s" % ("PasswordLastSet", parsed_pac[0]["PasswordLastSet"]))
    logging.info("    %-21s: %s" % ("PasswordCanChange", parsed_pac[0]["PasswordCanChange"]))
    logging.info("    %-21s: %s" % ("PasswordMustChange", parsed_pac[0]["PasswordMustChange"]))
    logging.info("    %-21s: %s" % ("EffectiveName", parsed_pac[0]["EffectiveName"]))
    logging.info("    %-21s: %s" % ("FullName", parsed_pac[0]["FullName"]))
    logging.info("    %-21s: %s" % ("LogonScript", parsed_pac[0]["LogonScript"]))
    logging.info("    %-21s: %s" % ("ProfilePath", parsed_pac[0]["ProfilePath"]))
    logging.info("    %-21s: %s" % ("HomeDirectory", parsed_pac[0]["HomeDirectory"]))
    logging.info("    %-21s: %s" % ("HomeDirectoryDrive", parsed_pac[0]["HomeDirectoryDrive"]))
    logging.info("    %-21s: %s" % ("LogonCount", parsed_pac[0]["LogonCount"]))
    logging.info("    %-21s: %s" % ("BadPasswordCount", parsed_pac[0]["BadPasswordCount"]))
    logging.info("    %-21s: %s" % ("UserId", parsed_pac[0]["UserId"]))
    logging.info("    %-21s: %s" % ("PrimaryGroupId", parsed_pac[0]["PrimaryGroupId"]))
    logging.info("    %-21s: %s" % ("GroupCount", parsed_pac[0]["GroupCount"]))
    logging.info("    %-21s: %s" % ("Groups", ', '.join([str(gid['RelativeId']) for gid in parsed_pac[0]["GroupIds"]])))
    logging.info("    %-21s: %s" % ("UserFlags", parsed_pac[0]["UserFlags"]))
    logging.info("    %-21s: %s" % ("UserSessionKey", parsed_pac[0]["UserSessionKey"]))
    logging.info("    %-21s: %s" % ("LogonServer", parsed_pac[0]["LogonServer"]))
    logging.info("    %-21s: %s" % ("LogonDomainName", parsed_pac[0]["LogonDomainName"]))
    logging.info("    %-21s: %s" % ("LogonDomainId", parsed_pac[0]["LogonDomainId"]))
    # Todo parse UserAccountControl
    logging.info("    %-21s: %s" % ("UserAccountControl", parsed_pac[0]["UserAccountControl"]))
    logging.info("    %-21s: %s" % ("ExtraSIDs", ', '.join([sid for sid in parsed_pac[0]["ExtraSids"]])))
    logging.info("    %-21s: %s" % ("ResourceGroupCount", parsed_pac[0]["ResourceGroupCount"]))


def parse_pac(pacType):
    def format_sid(data):
        return "S-%d-%d-%d-%s" % (data['Revision'], data['IdentifierAuthority'], data['SubAuthorityCount'], '-'.join([str(e) for e in data['SubAuthority']]))
    def PACinfiniteData(obj):
        while 'fields' in dir(obj):
            if 'Data' in obj.fields.keys():
                obj = obj.fields['Data']
            else:
                return obj.fields
        return obj
    def PACparseFILETIME(data):
        # FILETIME structure (minwinbase.h)
        # Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
        # https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
        v_ticks = PACinfiniteData(data['dwLowDateTime']) + 2^32 * PACinfiniteData(data['dwHighDateTime'])
        v_FILETIME = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(seconds=v_ticks/ 1e7)
        return v_FILETIME
    def PACparseGroupIds(data):
        groups = []
        for group in PACinfiniteData(data):
            groupMembership = {}
            groupMembership['RelativeId'] = PACinfiniteData(group.fields['RelativeId'])
            groupMembership['Attributes'] = PACinfiniteData(group.fields['Attributes'])
            groups.append(groupMembership)
        return groups
    def PACparseSID(sid):
        str_sid = format_sid({
            'Revision': PACinfiniteData(sid['Revision']),
            'SubAuthorityCount': PACinfiniteData(sid['SubAuthorityCount']),
            'IdentifierAuthority': int(binascii.hexlify(PACinfiniteData(sid['IdentifierAuthority'])), 16),
            'SubAuthority': PACinfiniteData(sid['SubAuthority'])
        })
        return str_sid
    def PACparseExtraSids(data):
        _ExtraSids = []
        for sid in PACinfiniteData(PACinfiniteData(data.fields)['Data']):
            _d = { 'Attributes': PACinfiniteData(sid.fields['Attributes']), 'Sid': PACparseSID(sid.fields['Sid']) }
            _ExtraSids.append(_d['Sid'])
        return _ExtraSids
    def PACparseResourceGroupDomainSid(data):
        data = {
            'Revision': PACinfiniteData(data['Revision']),
            'SubAuthorityCount': PACinfiniteData(data['SubAuthorityCount']),
            'IdentifierAuthority': int(binascii.hexlify(data['IdentifierAuthority']), 16),
            'SubAuthority': PACinfiniteData(data['SubAuthority'])
        }
        return data
    #
    parsed_tuPAC = []
    #
    buff = pacType['Buffers']
    infoBuffer = PAC_INFO_BUFFER(buff)
    for bufferN in range(pacType['cBuffers']):
        data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
        if infoBuffer['ulType'] == PAC_LOGON_INFO:
            type1 = TypeSerialization1(data)
            newdata = data[len(type1)+4:]
            kerbdata = KERB_VALIDATION_INFO()
            kerbdata.fromString(newdata)
            kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
            parsed_data = {}

            parsed_data['EffectiveName']      = PACinfiniteData(kerbdata.fields['EffectiveName']).decode('utf-16-le')
            parsed_data['FullName']           = PACinfiniteData(kerbdata.fields['FullName']).decode('utf-16-le')
            parsed_data['LogonScript']        = PACinfiniteData(kerbdata.fields['LogonScript']).decode('utf-16-le')
            parsed_data['ProfilePath']        = PACinfiniteData(kerbdata.fields['ProfilePath']).decode('utf-16-le')
            parsed_data['HomeDirectory']      = PACinfiniteData(kerbdata.fields['HomeDirectory']).decode('utf-16-le')
            parsed_data['HomeDirectoryDrive'] = PACinfiniteData(kerbdata.fields['HomeDirectoryDrive']).decode('utf-16-le')
            parsed_data['LogonCount']         = PACinfiniteData(kerbdata.fields['LogonCount'])
            parsed_data['BadPasswordCount']   = PACinfiniteData(kerbdata.fields['BadPasswordCount'])
            parsed_data['UserId']             = PACinfiniteData(kerbdata.fields['UserId'])
            parsed_data['PrimaryGroupId']     = PACinfiniteData(kerbdata.fields['PrimaryGroupId'])
            parsed_data['UserFlags']          = PACinfiniteData(kerbdata.fields['UserFlags'])
            parsed_data['UserSessionKey']     = hexlify(PACinfiniteData(kerbdata.fields['UserSessionKey'])).decode('utf-8')
            parsed_data['LogonServer']        = PACinfiniteData(kerbdata.fields['LogonServer']).decode('utf-16-le')
            parsed_data['LogonDomainName']    = PACinfiniteData(kerbdata.fields['LogonDomainName']).decode('utf-16-le')
            parsed_data['LogonDomainId']        = PACparseSID(PACinfiniteData(kerbdata.fields['LogonDomainId']))
            parsed_data['LMKey']                = hexlify(PACinfiniteData(kerbdata.fields['LMKey'])).decode('utf-8')
            parsed_data['UserAccountControl']   = PACinfiniteData(kerbdata.fields['UserAccountControl'])
            parsed_data['SubAuthStatus']        = PACinfiniteData(kerbdata.fields['SubAuthStatus'])
            parsed_data['LastSuccessfulILogon'] = PACparseFILETIME(kerbdata.fields['LastSuccessfulILogon'])
            parsed_data['LastFailedILogon']     = PACparseFILETIME(kerbdata.fields['LastFailedILogon'])
            parsed_data['FailedILogonCount']    = PACinfiniteData(kerbdata.fields['FailedILogonCount'])
            parsed_data['Reserved3']            = PACinfiniteData(kerbdata.fields['Reserved3'])
            parsed_data['LogonTime']            = PACparseFILETIME(kerbdata.fields['LogonTime'])
            parsed_data['LogoffTime']           = PACparseFILETIME(kerbdata.fields['LogoffTime'])
            parsed_data['KickOffTime']          = PACparseFILETIME(kerbdata.fields['KickOffTime'])
            parsed_data['PasswordLastSet']      = PACparseFILETIME(kerbdata.fields['PasswordLastSet'])
            parsed_data['PasswordCanChange']    = PACparseFILETIME(kerbdata.fields['PasswordCanChange'])
            parsed_data['PasswordMustChange']   = PACparseFILETIME(kerbdata.fields['PasswordMustChange'])
            parsed_data['GroupCount'] = PACinfiniteData(kerbdata.fields['GroupCount'])
            parsed_data['GroupIds'] = PACparseGroupIds(kerbdata.fields['GroupIds'])
            parsed_data['SidCount']             = PACinfiniteData(kerbdata.fields['SidCount'])
            parsed_data['ExtraSids']            = PACparseExtraSids(kerbdata.fields['ExtraSids'])
            parsed_data['ResourceGroupDomainSid'] = PACparseResourceGroupDomainSid(kerbdata.fields['ResourceGroupDomainSid'])
            parsed_data['ResourceGroupCount']   = PACinfiniteData(kerbdata.fields['ResourceGroupCount'])
            parsed_data['ResourceGroupIds']     = PACparseGroupIds(kerbdata.fields['ResourceGroupIds'])

            parsed_tuPAC.append(parsed_data)
        elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
            type1 = TypeSerialization1(data)
            # TODO: Not implemented
            print(dir(type1))
            pass
        elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
            clientInfo = PAC_CLIENT_INFO(data)
            # TODO: Not implemented
            print(dir(clientInfo))
            pass
        elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
            signatureData = PAC_SIGNATURE_DATA(data)
            # TODO: Not implemented
            print(dir(signatureData))
            pass
        elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
            upn = UPN_DNS_INFO(data)
            # TODO: Not implemented
            print(dir(upn))
            pass
    return parsed_tuPAC


def generate_kerberos_keys(args):
    # copypasta from krbrelayx.py
    # Store Kerberos keys
    keys = {}
    if args.hashes:
        keys[int(constants.EncryptionTypes.rc4_hmac.value)] = unhexlify(args.hashes.split(':')[1])
    if args.aesKey:
        if len(args.aesKey) == 64:
            keys[int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)] = unhexlify(args.aesKey)
        else:
            keys[int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)] = unhexlify(args.aesKey)
    ekeys = {}
    for kt, key in keys.items():
        ekeys[kt] = Key(kt, key)

    allciphers = [
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)
    ]

    # Calculate Kerberos keys from specified password/salt
    if args.password or args.hexpass:
        if not args.salt and args.user and args.domain: # https://www.thehacker.recipes/ad/movement/kerberos
            if args.user.endswith('$'):
                args.salt = "%shost%s.%s" % (args.domain.upper(), args.user.rstrip('$').lower(), args.domain.lower())
            else:
                args.salt = "%s%s" % (args.domain.upper(), args.user)
        for cipher in allciphers:
            if cipher == 23 and args.hexpass:
                # RC4 calculation is done manually for raw passwords
                md4 = MD4.new()
                md4.update(unhexlify(args.krbhexpass))
                ekeys[cipher] = Key(cipher, md4.digest().decode('utf-8'))
            else:
                # Do conversion magic for raw passwords
                if args.hexpass:
                    rawsecret = unhexlify(args.krbhexpass).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
                else:
                    # If not raw, it was specified from the command line, assume it's not UTF-16
                    rawsecret = args.password
                ekeys[cipher] = string_to_key(cipher, rawsecret, args.salt)
            logging.debug('Calculated type %s (%d) Kerberos key: %s' % (constants.EncryptionTypes(cipher).name, cipher, hexlify(ekeys[cipher].contents).decode('utf-8')))
    return ekeys


def kerberoast_from_ccache(decodedTGS, spn, username, domain):
    try:
        if not domain:
            domain = decodedTGS['ticket']['realm'].upper()
        else:
            domain = domain.upper()

        if not username:
            username = "USER"

        username = username.rstrip('$')

        # Copy-pasta from GestUserSPNs.py
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode)
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logging.debug('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))
        return entry
    except Exception as e:
        logging.debug("Not able to parse ticket: %s" % e)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Ticket describor')

    parser.add_argument('ticket', action='store', help='Path to ticket.ccache')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    # Authentication arguments
    group = parser.add_argument_group('Some account information')
    group.add_argument('-p', '--password', action="store", metavar="PASSWORD", help='placeholder')
    group.add_argument('-hp', '--hexpass', dest='hexpass', action="store", metavar="PASSWORD", help='placeholder')
    group.add_argument('-u', '--user', action="store", metavar="USER", help='placeholder') # used for kerberoast_from_ccache()
    group.add_argument('-d', '--domain', action="store", metavar="DOMAIN", help='placeholder') # used for kerberoast_from_ccache()
    group.add_argument('-s', '--salt', action="store", metavar="SALT", help='placeholder')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='placeholder')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='placeholder')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    return args


def init_logger(args):
    # Init the example's logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)


def main():
    print(version.BANNER)
    args = parse_args()
    init_logger(args)

    try:
        parse_ccache(args)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))

if __name__ == '__main__':
    main()
