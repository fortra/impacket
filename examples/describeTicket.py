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

import logging
import sys
import traceback
import argparse
import binascii
from enum import Enum

from Cryptodome.Hash import MD4
import datetime
import base64
from binascii import unhexlify, hexlify

from impacket.krb5.constants import ChecksumTypes
from pyasn1.codec.der import decoder
from impacket import LOG, version
from impacket.examples import logger
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REP, EncTicketPart, AD_IF_RELEVANT
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum, string_to_key
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
    PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO, PAC_CREDENTIALS_INFO, PAC_DELEGATION_INFO, S4U_DELEGATION_INFO

class User_Flags(Enum):
    LOGON_EXTRA_SIDS = 0x0020
    LOGON_RESOURCE_GROUPS = 0x0200

class UserAccountControl_Flags(Enum):
    UF_SCRIPT = 0x00000001
    UF_ACCOUNTDISABLE = 0x00000002
    UF_HOMEDIR_REQUIRED = 0x00000008
    UF_LOCKOUT = 0x00000010
    UF_PASSWD_NOTREQD = 0x00000020
    UF_PASSWD_CANT_CHANGE = 0x00000040
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080
    UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100
    UF_NORMAL_ACCOUNT = 0x00000200
    UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800
    UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000
    UF_SERVER_TRUST_ACCOUNT = 0x00002000
    UF_DONT_EXPIRE_PASSWD = 0x00010000
    UF_MNS_LOGON_ACCOUNT = 0x00020000
    UF_SMARTCARD_REQUIRED = 0x00040000
    UF_TRUSTED_FOR_DELEGATION = 0x00080000
    UF_NOT_DELEGATED = 0x00100000
    UF_USE_DES_KEY_ONLY = 0x00200000
    UF_DONT_REQUIRE_PREAUTH = 0x00400000
    UF_PASSWORD_EXPIRED = 0x00800000
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
    UF_NO_AUTH_DATA_REQUIRED = 0x02000000
    UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000
    UF_USE_AES_KEYS = 0x08000000


def parse_ccache(args):
    # todo : decodedTicket['ticket']['enc-part'] is handled. Handle decodedTicket['enc-part']?
    ccache = CCache.loadFile(args.ticket)

    principal = ccache.credentials[0].header['server'].prettyPrint()
    creds = ccache.getCredential(principal.decode())
    TGS = creds.toTGS(principal)
    decodedTicket = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

    for creds in ccache.credentials:
        logging.info("%-30s: %s" % ("User Name", creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')))
        logging.info("%-30s: %s" % ("User Realm", creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')))
        spn = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
        logging.info("%-30s: %s" % ("Service Name", spn))
        logging.info("%-30s: %s" % ("Service Realm", creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')))
        logging.info("%-30s: %s" % ("Start Time", datetime.datetime.fromtimestamp(creds['time']['starttime']).strftime("%d/%m/%Y %H:%M:%S %p")))
        logging.info("%-30s: %s" % ("End Time", datetime.datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%M:%S %p")))
        logging.info("%-30s: %s" % ("RenewTill", datetime.datetime.fromtimestamp(creds['time']['renew_till']).strftime("%d/%m/%Y %H:%M:%S %p")))

        flags = []
        for k in constants.TicketFlags:
            if ((creds['tktflags'] >> (31 - k.value)) & 1) == 1:
                flags.append(constants.TicketFlags(k.value).name)
        logging.info("%-30s: (0x%x) %s" % ("Flags", creds['tktflags'], ", ".join(flags)))
        keyType = constants.EncryptionTypes(creds["key"]["keytype"]).name
        logging.info("%-30s: %s" % ("KeyType", keyType))
        logging.info("%-30s: %s" % ("Base64(key)", base64.b64encode(creds["key"]["keyvalue"]).decode("utf-8")))

        if spn.split('/')[0] != 'krbtgt':
            logging.debug("Attempting to create Kerberoast hash")
            # code adapted from Rubeus's DisplayTicket() (https://github.com/GhostPack/Rubeus/blob/3620814cd2c5f05e87cddd50211197bd932fec51/Rubeus/lib/LSA.cs)
            # if this isn't a TGT, try to display a Kerberoastable hash
            if keyType != "rc4_hmac"  and keyType != "aes256_cts_hmac_sha1_96":
                # can only display rc4_hmac ad it doesn't have a salt. DES/AES keys require the user/domain as a salt, and we don't have
                # the user account name that backs the requested SPN for the ticket, no no dice :(
                logging.debug("Service ticket uses encryption key type %s, unable to extract hash and salt" % keyType)
            elif keyType == "rc4_hmac":
                kerberoast_hash = kerberoast_from_ccache(decodedTGS = decodedTicket, spn = spn, username = args.user, domain = args.domain)
            elif args.user:
                if args.user.endswith("$"):
                    user = "host%s.%s" % (args.user.rstrip('$').lower(), args.domain.lower())
                else:
                    user = args.user
                kerberoast_hash = kerberoast_from_ccache(decodedTGS = decodedTicket, spn = spn, username = user, domain = args.domain)
            else:
                logging.error("AES256 in use but no '-u/--user' passed, unable to generate crackable hash")
            if kerberoast_hash:
                logging.info("%-30s: %s" % ("Kerberoast hash", kerberoast_hash))

    logging.debug("Handling Kerberos keys")
    ekeys = generate_kerberos_keys(args)

    # copypasta from krbrelayx.py
    # Select the correct encryption key
    etype = decodedTicket['ticket']['enc-part']['etype']
    try:
        logging.debug('Ticket is encrypted with %s (etype %d)' % (constants.EncryptionTypes(etype).name, etype))
        key = ekeys[etype]
        logging.debug('Using corresponding key: %s' % hexlify(key.contents).decode('utf-8'))
    # This raises a KeyError (pun intended) if our key is not found
    except KeyError:
        if len(ekeys) > 0:
            LOG.error('Could not find the correct encryption key! Ticket is encrypted with %s (etype %d), but only keytype(s) %s were calculated/supplied',
                      constants.EncryptionTypes(etype).name,
                      etype,
                      ', '.join([str(enctype) for enctype in ekeys.keys()]))
        else:
            LOG.error('Could not find the correct encryption key! Ticket is encrypted with %s (etype %d), but no keys/creds were supplied',
                      constants.EncryptionTypes(etype).name,
                      etype)
        return None

    # Recover plaintext info from ticket
    try:
        cipherText = decodedTicket['ticket']['enc-part']['cipher']
        newCipher = _enctype_table[int(etype)]
        plainText = newCipher.decrypt(key, 2, cipherText)
    except InvalidChecksum:
        logging.error('Ciphertext integrity failed. Most likely the account password or AES key is incorrect')
        if args.salt:
            logging.info('Make sure the salt/username/domain are set and with the proper values. In case of a computer account, append a "$" to the name.')
            logging.debug('Remember: the encrypted-part of the ticket is secured with one of the target service\'s Kerberos keys. The target service is the one who owns the \'Service Name\' SPN printed above')
        return

    logging.debug('Ticket successfully decrypted')
    encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]
    sessionKey = Key(encTicketPart['key']['keytype'], bytes(encTicketPart['key']['keyvalue']))
    adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
    # So here we have the PAC
    pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
    parsed_pac = parse_pac(pacType)
    logging.info("%-30s:" % "Decrypted PAC")
    for element_type in parsed_pac:
        element_type_name = list(element_type.keys())[0]
        logging.info("  %-28s:" % element_type_name)
        for attribute in element_type[element_type_name]:
            logging.info("    %-26s: %s" % (attribute, element_type[element_type_name][attribute]))


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
        dwLowDateTime = data['dwLowDateTime']
        dwHighDateTime = data['dwHighDateTime']
        v_FILETIME = "Infinity (absolute time)"
        if dwLowDateTime != 0xffffffff and dwHighDateTime != 0x7fffffff:
            temp_time = dwHighDateTime
            temp_time <<= 32
            temp_time |= dwLowDateTime
            if datetime.timedelta(microseconds=temp_time / 10).total_seconds() != 0:
                v_FILETIME = (datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(microseconds=temp_time / 10)).strftime("%d/%m/%Y %H:%M:%S %p")
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
        if type(sid) == dict:
            str_sid = format_sid({
                'Revision': PACinfiniteData(sid['Revision']),
                'SubAuthorityCount': PACinfiniteData(sid['SubAuthorityCount']),
                'IdentifierAuthority': int(binascii.hexlify(PACinfiniteData(sid['IdentifierAuthority'])), 16),
                'SubAuthority': PACinfiniteData(sid['SubAuthority'])
            })
            return str_sid
        else:
            return ''
    def PACparseExtraSids(data):
        _ExtraSids = []
        for sid in PACinfiniteData(PACinfiniteData(data.fields)['Data']):
            _d = { 'Attributes': PACinfiniteData(sid.fields['Attributes']), 'Sid': PACparseSID(sid.fields['Sid']) }
            _ExtraSids.append(_d['Sid'])
        return _ExtraSids
    parsed_tuPAC = []
    buff = pacType['Buffers']
    for bufferN in range(pacType['cBuffers']):
        infoBuffer = PAC_INFO_BUFFER(buff)
        data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
        if infoBuffer['ulType'] == PAC_LOGON_INFO:
            type1 = TypeSerialization1(data)
            newdata = data[len(type1)+4:]
            kerbdata = KERB_VALIDATION_INFO()
            kerbdata.fromString(newdata)
            kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
            parsed_data = {}

            parsed_data['Logon Time'] = PACparseFILETIME(kerbdata.fields['LogonTime'])
            parsed_data['Logoff Time'] = PACparseFILETIME(kerbdata.fields['LogoffTime'])
            parsed_data['Kickoff Time'] = PACparseFILETIME(kerbdata.fields['KickOffTime'])
            parsed_data['Password Last Set'] = PACparseFILETIME(kerbdata.fields['PasswordLastSet'])
            parsed_data['Password Can Change'] = PACparseFILETIME(kerbdata.fields['PasswordCanChange'])
            parsed_data['Password Must Change'] = PACparseFILETIME(kerbdata.fields['PasswordMustChange'])
            # parsed_data['LastSuccessfulILogon'] = PACparseFILETIME(kerbdata.fields['LastSuccessfulILogon'])
            # parsed_data['LastFailedILogon'] = PACparseFILETIME(kerbdata.fields['LastFailedILogon'])
            # parsed_data['FailedILogonCount'] = PACinfiniteData(kerbdata.fields['FailedILogonCount'])
            parsed_data['Account Name'] = PACinfiniteData(kerbdata.fields['EffectiveName']).decode('utf-16-le')
            parsed_data['Full Name'] = PACinfiniteData(kerbdata.fields['FullName']).decode('utf-16-le')
            parsed_data['Logon Script'] = PACinfiniteData(kerbdata.fields['LogonScript']).decode('utf-16-le')
            parsed_data['Profile Path'] = PACinfiniteData(kerbdata.fields['ProfilePath']).decode('utf-16-le')
            parsed_data['Home Dir'] = PACinfiniteData(kerbdata.fields['HomeDirectory']).decode('utf-16-le')
            parsed_data['Dir Drive'] = PACinfiniteData(kerbdata.fields['HomeDirectoryDrive']).decode('utf-16-le')
            parsed_data['Logon Count'] = PACinfiniteData(kerbdata.fields['LogonCount'])
            parsed_data['Bad Password Count'] = PACinfiniteData(kerbdata.fields['BadPasswordCount'])
            parsed_data['User RID'] = PACinfiniteData(kerbdata.fields['UserId'])
            parsed_data['Group RID'] = PACinfiniteData(kerbdata.fields['PrimaryGroupId'])
            parsed_data['Group Count'] = PACinfiniteData(kerbdata.fields['GroupCount'])
            parsed_data['Groups'] = ', '.join([str(gid['RelativeId']) for gid in PACparseGroupIds(kerbdata.fields['GroupIds'])])
            UserFlags = PACinfiniteData(kerbdata.fields['UserFlags'])
            User_Flags_Flags = []
            for flag in User_Flags:
                if UserFlags & flag.value:
                    User_Flags_Flags.append(flag.name)
            parsed_data['User Flags']            = "(%s) %s" % (UserFlags, ", ".join(User_Flags_Flags))
            parsed_data['User Session Key']       = hexlify(PACinfiniteData(kerbdata.fields['UserSessionKey'])).decode('utf-8')
            parsed_data['Logon Server']          = PACinfiniteData(kerbdata.fields['LogonServer']).decode('utf-16-le')
            parsed_data['Logon Domain Name']      = PACinfiniteData(kerbdata.fields['LogonDomainName']).decode('utf-16-le')
            parsed_data['Logon Domain SID']        = PACparseSID(PACinfiniteData(kerbdata.fields['LogonDomainId']))
            UAC = PACinfiniteData(kerbdata.fields['UserAccountControl'])
            UAC_Flags = []
            for flag in UserAccountControl_Flags:
                if UAC & flag.value:
                    UAC_Flags.append(flag.name)
            parsed_data['User Account Control']   = "(%s) %s" % (UAC, ", ".join(UAC_Flags))
            parsed_data['Extra SID Count']        = PACinfiniteData(kerbdata.fields['SidCount'])
            parsed_data['Extra SIDs']            = ', '.join([sid for sid in PACparseExtraSids(kerbdata.fields['ExtraSids'])])
            parsed_data['Resource Group Domain SID'] = PACparseSID(kerbdata.fields['ResourceGroupDomainSid'])
            parsed_data['Resource Group Count']   = PACinfiniteData(kerbdata.fields['ResourceGroupCount'])
            parsed_data['Resource Group Ids']     = ', '.join([str(gid['RelativeId']) for gid in PACparseGroupIds(kerbdata.fields['ResourceGroupIds'])])
            # parsed_data['LMKey']                = hexlify(PACinfiniteData(kerbdata.fields['LMKey'])).decode('utf-8')
            # parsed_data['SubAuthStatus']        = PACinfiniteData(kerbdata.fields['SubAuthStatus'])
            # parsed_data['Reserved3']            = PACinfiniteData(kerbdata.fields['Reserved3'])
            parsed_tuPAC.append({"LoginInfo": parsed_data})

        elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
            clientInfo = PAC_CLIENT_INFO()
            clientInfo.fromString(data)
            parsed_data = {}
            parsed_data['Client Id'] = PACparseFILETIME(clientInfo.fields['ClientId'])
            # In case PR fixing pac.py's PAC_CLIENT_INFO structure doesn't get through
            # parsed_data['Client Id'] = PACparseFILETIME(FILETIME(data[:32]))
            parsed_data['Client Name'] = clientInfo.fields['Name'].decode('utf-16-le')
            parsed_tuPAC.append({"ClientName": parsed_data})

        elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
            upn = UPN_DNS_INFO(data)
            UpnLength = upn.fields['UpnLength']
            UpnOffset = upn.fields['UpnOffset']
            UpnName = data[UpnOffset:UpnOffset+UpnLength].decode('utf-16-le')
            DnsDomainNameLength = upn.fields['DnsDomainNameLength']
            DnsDomainNameOffset = upn.fields['DnsDomainNameOffset']
            DnsName = data[DnsDomainNameOffset:DnsDomainNameOffset + DnsDomainNameLength].decode('utf-16-le')
            parsed_data = {}
            parsed_data['Flags'] = upn.fields['Flags']
            parsed_data['UPN'] = UpnName
            parsed_data['DNS Domain Name'] = DnsName
            parsed_tuPAC.append({"UpnDns": parsed_data})

        elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
            signatureData = PAC_SIGNATURE_DATA(data)
            parsed_data = {}
            parsed_data['Signature Type'] = ChecksumTypes(signatureData.fields['SignatureType']).name
            parsed_data['Signature'] = hexlify(signatureData.fields['Signature']).decode('utf-8')
            parsed_tuPAC.append({"ServerChecksum": parsed_data})

        elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
            signatureData = PAC_SIGNATURE_DATA(data)
            parsed_data = {}
            parsed_data['Signature Type'] = ChecksumTypes(signatureData.fields['SignatureType']).name
            # signatureData.dump()
            parsed_data['Signature'] = hexlify(signatureData.fields['Signature']).decode('utf-8')
            parsed_tuPAC.append({"KDCChecksum": parsed_data})

        elif infoBuffer['ulType'] == PAC_CREDENTIALS_INFO:
            logging.debug("TODO: implement PAC_CREDENTIALS_INFO parsing")

        elif infoBuffer['ulType'] == PAC_DELEGATION_INFO:
            delegationInfo = S4U_DELEGATION_INFO(data)
            parsed_data = {}
            parsed_data['S4U2proxyTarget'] = PACinfiniteData(delegationInfo.fields['S4U2proxyTarget']).decode('utf-16-le')
            parsed_data['TransitedListSize'] = delegationInfo.fields['TransitedListSize'].fields['Data']
            parsed_data['S4UTransitedServices'] = PACinfiniteData(delegationInfo.fields['S4UTransitedServices']).decode('utf-16-le')
            parsed_tuPAC.append({"DelegationInfo": parsed_data})

        buff = buff[len(infoBuffer):]
    return parsed_tuPAC


def generate_kerberos_keys(args):
    # copypasta from krbrelayx.py
    # Store Kerberos keys
    keys = {}
    if args.rc4:
        keys[int(constants.EncryptionTypes.rc4_hmac.value)] = unhexlify(args.rc4)
    if args.aes:
        if len(args.aes) == 64:
            keys[int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)] = unhexlify(args.aes)
        else:
            keys[int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)] = unhexlify(args.aes)
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
    else:
        logging.debug('No password (-p/--password or -hp/--hexpass supplied, skipping Kerberos keys calculation')
    return ekeys


def kerberoast_from_ccache(decodedTGS, spn, username, domain):
    try:
        if not domain:
            domain = decodedTGS['ticket']['realm']._value.upper()
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
        raise
        logging.debug("Not able to parse ticket: %s" % e)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Ticket describer. Parses ticket, decrypts the enc-part, and parses the PAC.')

    parser.add_argument('ticket', action='store', help='Path to ticket.ccache')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    group = parser.add_argument_group()
    group.title = 'Ticket decryption credentials (optional)'
    group.description = 'Tickets carry a set of information encrypted by one of the target service account\'s Kerberos keys.' \
                        '(example: if the ticket is for user:"john" for service:"cifs/service.domain.local", you need to supply credentials or keys ' \
                        'of the service account who owns SPN "cifs/service.domain.local")'
    group.add_argument('-p', '--password', action="store", metavar="PASSWORD", help='Cleartext password of the service account')
    group.add_argument('-hp', '--hexpass', dest='hexpass', action="store", metavar="HEX PASSWORD", help='placeholder')
    group.add_argument('-u', '--user', action="store", metavar="USER", help='Name of the service account')
    group.add_argument('-d', '--domain', action="store", metavar="DOMAIN", help='FQDN Domain')
    group.add_argument('-s', '--salt', action="store", metavar="SALT", help='Salt for keys calculation (DOMAIN.LOCALSomeuser for users, DOMAIN.LOCALhostsomemachine.domain.local for machines)')
    group.add_argument('--rc4', action="store", metavar="RC4", help='RC4 KEY (i.e. NT hash)')
    group.add_argument('--aes', action="store", metavar="HEX KEY", help='AES128 or AES256 key')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not args.salt:
        if args.user and not args.domain:
            parser.error('without -s/--salt, and with -u/--user, argument -d/--domain is required to calculate the salt')
            parser.print_help()
        elif not args.user and args.domain:
            parser.error('without -s/--salt, and with -d/--domain, argument -u/--user is required to calculate the salt')
            parser.print_help()

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
