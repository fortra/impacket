#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Ticket describer. Parses ticket, decrypts the enc-part, and parses the PAC.
#
# Authors:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)
#   Mathieu Calemard du Gardin (@Dramelac_)

import logging
import sys
import traceback
import argparse
import datetime
import base64
from typing import Sequence

from Cryptodome.Hash import MD4
from enum import Enum
from binascii import unhexlify, hexlify
from pyasn1.codec.der import decoder

from impacket import version
from impacket.dcerpc.v5.dtypes import FILETIME, PRPC_SID
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples import logger
from impacket.krb5 import constants, pac
from impacket.krb5.asn1 import TGS_REP, EncTicketPart, AD_IF_RELEVANT
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import ChecksumTypes
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum, string_to_key
from impacket.ldap.ldaptypes import LDAP_SID

PSID = PRPC_SID

class User_Flags(Enum):
    LOGON_EXTRA_SIDS = 0x0020
    LOGON_RESOURCE_GROUPS = 0x0200

# 2.2.1.10 SE_GROUP Attributes
class SE_GROUP_Attributes(Enum):
    SE_GROUP_MANDATORY = 0x00000001
    SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
    SE_GROUP_ENABLED = 0x00000004

# 2.2.1.12 USER_ACCOUNT Codes
class USER_ACCOUNT_Codes(Enum):
    USER_ACCOUNT_DISABLED = 0x00000001
    USER_HOME_DIRECTORY_REQUIRED = 0x00000002
    USER_PASSWORD_NOT_REQUIRED = 0x00000004
    USER_TEMP_DUPLICATE_ACCOUNT = 0x00000008
    USER_NORMAL_ACCOUNT = 0x00000010
    USER_MNS_LOGON_ACCOUNT = 0x00000020
    USER_INTERDOMAIN_TRUST_ACCOUNT = 0x00000040
    USER_WORKSTATION_TRUST_ACCOUNT = 0x00000080
    USER_SERVER_TRUST_ACCOUNT = 0x00000100
    USER_DONT_EXPIRE_PASSWORD = 0x00000200
    USER_ACCOUNT_AUTO_LOCKED = 0x00000400
    USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000800
    USER_SMARTCARD_REQUIRED = 0x00001000
    USER_TRUSTED_FOR_DELEGATION = 0x00002000
    USER_NOT_DELEGATED = 0x00004000
    USER_USE_DES_KEY_ONLY = 0x00008000
    USER_DONT_REQUIRE_PREAUTH = 0x00010000
    USER_PASSWORD_EXPIRED = 0x00020000
    USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000
    USER_NO_AUTH_DATA_REQUIRED = 0x00080000
    USER_PARTIAL_SECRETS_ACCOUNT = 0x00100000
    USER_USE_AES_KEYS = 0x00200000

# 2.2.1.13 UF_FLAG Codes
class UF_FLAG_Codes(Enum):
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

# PAC_ATTRIBUTES_INFO Flags code
class Upn_Dns_Flags(Enum):
    U_UsernameOnly = 0x00000001
    S_SidSamSupplied = 0x00000002

# PAC_ATTRIBUTES_INFO Flags code
class Attributes_Flags(Enum):
    PAC_WAS_REQUESTED = 0x00000001
    PAC_WAS_GIVEN_IMPLICITLY = 0x00000002


# Builtin known Windows Group
MsBuiltInGroups = {
    "498": "Enterprise Read-Only Domain Controllers",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers",
    "522": "Cloneable Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers",
    "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Owner Server",
    "S-1-3-3": "Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "System (or LocalSystem)",
    "S-1-5-19": "NT Authority (LocalService)",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": "Builtin\\Pre-Windows",
    "S-1-5-32-555": "Builtin\\Remote Desktop Users",
    "S-1-5-32-556": "Builtin\\Network Configuration Operators",
    "S-1-5-32-557": "Builtin\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "Builtin\\Performance Monitor Users",
    "S-1-5-32-559": "Builtin\\Performance Log Users",
    "S-1-5-32-560": "Builtin\\Windows Authorization Access Group",
    "S-1-5-32-561": "Builtin\\Terminal Server License Servers",
    "S-1-5-32-562": "Builtin\\Distributed COM Users",
    "S-1-5-32-568": "Builtin\\IIS_IUSRS",
    "S-1-5-32-569": "Builtin\\Cryptographic Operators",
    "S-1-5-32-573": "Builtin\\Event Log Readers",
    "S-1-5-32-574": "Builtin\\Certificate Service DCOM Access",
    "S-1-5-32-575": "Builtin\\RDS Remote Access Servers",
    "S-1-5-32-576": "Builtin\\RDS Endpoint Servers",
    "S-1-5-32-577": "Builtin\\RDS Management Servers",
    "S-1-5-32-578": "Builtin\\Hyper-V Administrators",
    "S-1-5-32-579": "Builtin\\Access Control Assistance Operators",
    "S-1-5-32-580": "Builtin\\Remote Management Users",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
    "S-1-5-80-0": "All Services",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-5-113": "Local Account",
    "S-1-5-114": "Local Account and member of Administrators group",
    "S-1-5-1000": "Other Organization",
    "S-1-15-2-1": "All app packages",
    "S-1-16-0": "ML Untrusted",
    "S-1-16-4096": "ML Low",
    "S-1-16-8192": "ML Medium",
    "S-1-16-8448": "ML Medium Plus",
    "S-1-16-12288": "ML High",
    "S-1-16-16384": "ML System",
    "S-1-16-20480": "ML Protected Process",
    "S-1-16-28672": "ML Secure Process",
    "S-1-18-1": "Authentication authority asserted identity",
    "S-1-18-2": "Service asserted identity",
    "S-1-18-3": "Fresh public key identity",
    "S-1-18-4": "Key trust identity",
    "S-1-18-5": "Key property MFA",
    "S-1-18-6": "Key property attestation",
}


def parse_ccache(args):
    ccache = CCache.loadFile(args.ticket)

    cred_number = 0
    logging.info('Number of credentials in cache: %d' % len(ccache.credentials))

    for creds in ccache.credentials:
        logging.info('Parsing credential[%d]:' % cred_number)

        rawTicket = creds.toTGS()
        decodedTicket = decoder.decode(rawTicket['KDC_REP'], asn1Spec=TGS_REP())[0]

        # Printing the session key
        sessionKey = hexlify(rawTicket['sessionKey'].contents).decode('utf-8')
        logging.info("%-30s: %s" % ("Ticket Session Key", sessionKey))

        # Beginning the parsing of the ticket
        logging.info("%-30s: %s" % ("User Name", creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')))
        logging.info("%-30s: %s" % ("User Realm", creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')))
        spn = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
        logging.info("%-30s: %s" % ("Service Name", spn))
        logging.info("%-30s: %s" % ("Service Realm", creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')))
        logging.info("%-30s: %s" % ("Start Time", datetime.datetime.fromtimestamp(creds['time']['starttime']).strftime("%d/%m/%Y %H:%M:%S %p")))
        if datetime.datetime.fromtimestamp(creds['time']['endtime']) < datetime.datetime.now():
            logging.info("%-30s: %s (expired)" % ("End Time", datetime.datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%M:%S %p")))
        else:
            logging.info("%-30s: %s" % ("End Time", datetime.datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%M:%S %p")))
        if datetime.datetime.fromtimestamp(creds['time']['renew_till']) < datetime.datetime.now():
            logging.info("%-30s: %s (expired)" % ("RenewTill", datetime.datetime.fromtimestamp(creds['time']['renew_till']).strftime("%d/%m/%Y %H:%M:%S %p")))
        else:
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
            kerberoast_hash = None
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

        logging.info("%-30s:" % "Decoding unencrypted data in credential[%d]['ticket']" % cred_number)
        spn = "/".join(list([str(sname_component) for sname_component in decodedTicket['ticket']['sname']['name-string']]))
        etype = decodedTicket['ticket']['enc-part']['etype']
        logging.info("  %-28s: %s" % ("Service Name", spn))
        logging.info("  %-28s: %s" % ("Service Realm", decodedTicket['ticket']['realm']))
        logging.info("  %-28s: %s (etype %d)" % ("Encryption type", constants.EncryptionTypes(etype).name, etype))
        if not decodedTicket['ticket']['enc-part']['kvno'].isNoValue():
            logging.debug("No kvno in ticket, skipping")
            logging.info("  %-28s: %d" % ("Key version number (kvno)", decodedTicket['ticket']['enc-part']['kvno']))
        logging.debug("Handling Kerberos keys")
        ekeys = generate_kerberos_keys(args)

        # copypasta from krbrelayx.py
        # Select the correct encryption key
        try:
            logging.debug('Ticket is encrypted with %s (etype %d)' % (constants.EncryptionTypes(etype).name, etype))
            key = ekeys[etype]
            logging.debug('Using corresponding key: %s' % hexlify(key.contents).decode('utf-8'))
        # This raises a KeyError (pun intended) if our key is not found
        except KeyError:
            if len(ekeys) > 0:
                logging.error('Could not find the correct encryption key! Ticket is encrypted with %s (etype %d), but only keytype(s) %s were calculated/supplied',
                              constants.EncryptionTypes(etype).name,
                              etype,
                              ', '.join([str(enctype) for enctype in ekeys.keys()]))
            else:
                logging.error('Could not find the correct encryption key! Ticket is encrypted with %s (etype %d), but no keys/creds were supplied',
                              constants.EncryptionTypes(etype).name,
                              etype)
            return None

        # todo : decodedTicket['ticket']['enc-part'] is handled. Handle decodedTicket['enc-part']?
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
        pacType = pac.PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
        # parsing every PAC
        parsed_pac = parse_pac(pacType, args)
        logging.info("%-30s:" % "Decoding credential[%d]['ticket']['enc-part']" % cred_number)
        # One section per PAC
        for element_type in parsed_pac:
            element_type_name = list(element_type.keys())[0]
            logging.info("  %-28s" % element_type_name)
            # iterate over each attribute of the current PAC
            for attribute in element_type[element_type_name]:
                value = element_type[element_type_name][attribute]
                if isinstance(value, Sequence) and not isinstance(value, str):
                    # If the value is an array, print as a multiline view for better readability
                    if len(value) > 0:
                        logging.info("    %-26s: %s" % (attribute, value[0]))
                        for subvalue in value[1:]:
                            logging.info(" "*32+"%s" % subvalue)
                    else:
                        logging.info("    %-26s:" % attribute)
                else:
                    logging.info("    %-26s: %s" % (attribute, value))

        cred_number += 1


def parse_pac(pacType, args):
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
        for group in data:
            groupMembership = {}
            groupMembership['RelativeId'] = group['RelativeId']
            groupMembership['Attributes'] = group['Attributes']
            groups.append(groupMembership)
        return groups


    parsed_tuPAC = []
    buff = pacType['Buffers']

    for bufferN in range(pacType['cBuffers']):
        infoBuffer = pac.PAC_INFO_BUFFER(buff)
        data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
        if infoBuffer['ulType'] == pac.PAC_LOGON_INFO:
            type1 = TypeSerialization1(data)
            newdata = data[len(type1)+4:]
            kerbdata = pac.KERB_VALIDATION_INFO()
            kerbdata.fromString(newdata)
            kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
            parsed_data = {}
            parsed_data['Logon Time'] = PACparseFILETIME(kerbdata['LogonTime'])
            parsed_data['Logoff Time'] = PACparseFILETIME(kerbdata['LogoffTime'])
            parsed_data['Kickoff Time'] = PACparseFILETIME(kerbdata['KickOffTime'])
            parsed_data['Password Last Set'] = PACparseFILETIME(kerbdata['PasswordLastSet'])
            parsed_data['Password Can Change'] = PACparseFILETIME(kerbdata['PasswordCanChange'])
            parsed_data['Password Must Change'] = PACparseFILETIME(kerbdata['PasswordMustChange'])
            parsed_data['LastSuccessfulILogon'] = PACparseFILETIME(kerbdata['LastSuccessfulILogon'])
            parsed_data['LastFailedILogon'] = PACparseFILETIME(kerbdata['LastFailedILogon'])
            parsed_data['FailedILogonCount'] = kerbdata['FailedILogonCount']
            parsed_data['Account Name'] = kerbdata['EffectiveName']
            parsed_data['Full Name'] = kerbdata['FullName']
            parsed_data['Logon Script'] = kerbdata['LogonScript']
            parsed_data['Profile Path'] = kerbdata['ProfilePath']
            parsed_data['Home Dir'] = kerbdata['HomeDirectory']
            parsed_data['Dir Drive'] = kerbdata['HomeDirectoryDrive']
            parsed_data['Logon Count'] = kerbdata['LogonCount']
            parsed_data['Bad Password Count'] = kerbdata['BadPasswordCount']
            parsed_data['User RID'] = kerbdata['UserId']
            parsed_data['Group RID'] = kerbdata['PrimaryGroupId']
            parsed_data['Group Count'] = kerbdata['GroupCount']

            all_groups_id = [str(gid['RelativeId']) for gid in PACparseGroupIds(kerbdata['GroupIds'])]
            parsed_data['Groups'] = ", ".join(all_groups_id)
            groups = []
            unknown_count = 0
            # Searching for common group name
            for gid in all_groups_id:
                group_name = MsBuiltInGroups.get(gid)
                if group_name:
                    groups.append(f"({gid}) {group_name}")
                else:
                    unknown_count += 1
            if unknown_count > 0:
                groups.append(f"+{unknown_count} Unknown custom group{'s' if unknown_count > 1 else ''}")
            parsed_data['Groups (decoded)'] = groups

            # UserFlags parsing
            UserFlags = kerbdata['UserFlags']
            User_Flags_Flags = []
            for flag in User_Flags:
                if UserFlags & flag.value:
                    User_Flags_Flags.append(flag.name)
            parsed_data['User Flags'] = "(%s) %s" % (UserFlags, ", ".join(User_Flags_Flags))
            parsed_data['User Session Key'] = hexlify(kerbdata['UserSessionKey']).decode('utf-8')
            parsed_data['Logon Server'] = kerbdata['LogonServer']
            parsed_data['Logon Domain Name'] = kerbdata['LogonDomainName']

            # LogonDomainId parsing
            if kerbdata['LogonDomainId'] == b'':
                parsed_data['Logon Domain SID'] = kerbdata['LogonDomainId']
            else:
                parsed_data['Logon Domain SID'] = kerbdata['LogonDomainId'].formatCanonical()

            # UserAccountControl parsing
            UAC = kerbdata['UserAccountControl']
            UAC_Flags = []
            for flag in USER_ACCOUNT_Codes:
                if UAC & flag.value:
                    UAC_Flags.append(flag.name)
            parsed_data['User Account Control'] = "(%s) %s" % (UAC, ", ".join(UAC_Flags))
            parsed_data['Extra SID Count'] = kerbdata['SidCount']
            extraSids = []

            # ExtraSids parsing
            for extraSid in kerbdata['ExtraSids']:
                sid = extraSid['Sid'].formatCanonical()
                attributes = extraSid['Attributes']
                attributes_flags = []
                for flag in SE_GROUP_Attributes:
                    if attributes & flag.value:
                        attributes_flags.append(flag.name)
                # Group name matching
                group_name = MsBuiltInGroups.get(sid, '')
                if not group_name and len(sid.split('-')) == 8:
                    # Try to find an RID match
                    group_name = MsBuiltInGroups.get(sid.split('-')[-1], '')
                if group_name:
                    group_name = f" {group_name}"
                extraSids.append("%s%s (%s)" % (sid, group_name, ', '.join(attributes_flags)))
            parsed_data['Extra SIDs'] = extraSids

            # ResourceGroupDomainSid parsing
            if kerbdata['ResourceGroupDomainSid'] == b'':
                parsed_data['Resource Group Domain SID'] = kerbdata['ResourceGroupDomainSid']
            else:
                parsed_data['Resource Group Domain SID'] = kerbdata['ResourceGroupDomainSid'].formatCanonical()

            parsed_data['Resource Group Count'] = kerbdata['ResourceGroupCount']
            parsed_data['Resource Group Ids'] = ', '.join([str(gid['RelativeId']) for gid in PACparseGroupIds(kerbdata['ResourceGroupIds'])])
            parsed_data['LMKey'] = hexlify(kerbdata['LMKey']).decode('utf-8')
            parsed_data['SubAuthStatus'] = kerbdata['SubAuthStatus']
            parsed_data['Reserved3'] = kerbdata['Reserved3']
            parsed_tuPAC.append({"LoginInfo": parsed_data})

        elif infoBuffer['ulType'] == pac.PAC_CLIENT_INFO_TYPE:
            clientInfo = pac.PAC_CLIENT_INFO()
            clientInfo.fromString(data)
            parsed_data = {}
            try:
                parsed_data['Client Id'] = PACparseFILETIME(clientInfo['ClientId'])
            except:
                try:
                    parsed_data['Client Id'] = PACparseFILETIME(FILETIME(data[:32]))
                except Exception as e:
                    logging.error(e)
            parsed_data['Client Name'] = clientInfo['Name'].decode('utf-16-le')
            parsed_tuPAC.append({"ClientName": parsed_data})

        elif infoBuffer['ulType'] == pac.PAC_UPN_DNS_INFO:
            upn = pac.UPN_DNS_INFO(data)
            # UPN PArsing
            UpnLength = upn['UpnLength']
            UpnOffset = upn['UpnOffset']
            UpnName = data[UpnOffset:UpnOffset+UpnLength].decode('utf-16-le')

            # DNS Name Parsing
            DnsDomainNameLength = upn['DnsDomainNameLength']
            DnsDomainNameOffset = upn['DnsDomainNameOffset']
            DnsName = data[DnsDomainNameOffset:DnsDomainNameOffset + DnsDomainNameLength].decode('utf-16-le')

            # Flag parsing
            flags = upn['Flags']
            attr_flags = []
            for flag_lib in Upn_Dns_Flags:
                if flags & flag_lib.value:
                    attr_flags.append(flag_lib.name)
            parsed_data = {}
            parsed_data['Flags'] = f"({flags}) {', '.join(attr_flags)}"
            parsed_data['UPN'] = UpnName
            parsed_data['DNS Domain Name'] = DnsName

            # Depending on the flag supplied, additional data may be supplied
            if Upn_Dns_Flags.S_SidSamSupplied.name in attr_flags:
                # SamAccountName and Sid is also supplied
                upn = pac.UPN_DNS_INFO_FULL(data)
                # Sam parsing
                SamNameLength = upn['SamNameLength']
                SamNameOffset = upn['SamNameOffset']
                SamName = data[SamNameOffset:SamNameOffset+SamNameLength].decode('utf-16-le')

                # Sid parsing
                SidLength = upn['SidLength']
                SidOffset = upn['SidOffset']
                Sid = LDAP_SID(data[SidOffset:SidOffset+SidLength])  # Using LDAP_SID instead of RPC_SID (https://github.com/SecureAuthCorp/impacket/issues/1386)

                parsed_data["SamAccountName"] = SamName
                parsed_data["UserSid"] = Sid.formatCanonical()
            parsed_tuPAC.append({"UpnDns": parsed_data})

        elif infoBuffer['ulType'] == pac.PAC_SERVER_CHECKSUM:
            signatureData = pac.PAC_SIGNATURE_DATA(data)
            parsed_data = {}
            parsed_data['Signature Type'] = ChecksumTypes(signatureData['SignatureType']).name
            parsed_data['Signature'] = hexlify(signatureData['Signature']).decode('utf-8')
            parsed_tuPAC.append({"ServerChecksum": parsed_data})

        elif infoBuffer['ulType'] == pac.PAC_PRIVSVR_CHECKSUM:
            signatureData = pac.PAC_SIGNATURE_DATA(data)
            parsed_data = {}
            parsed_data['Signature Type'] = ChecksumTypes(signatureData['SignatureType']).name
            # signatureData.dump()
            parsed_data['Signature'] = hexlify(signatureData['Signature']).decode('utf-8')
            parsed_tuPAC.append({"KDCChecksum": parsed_data})

        elif infoBuffer['ulType'] == pac.PAC_CREDENTIALS_INFO:
            # Parsing 2.6.1 PAC_CREDENTIAL_INFO
            credential_info = pac.PAC_CREDENTIAL_INFO(data)
            parsed_credential_info = {}
            parsed_credential_info['Version'] = "(0x%x) %d" % (credential_info.fields['Version'], credential_info.fields['Version'])
            credinfo_enctype = credential_info.fields['EncryptionType']
            parsed_credential_info['Encryption Type'] = "(0x%x) %s" % (credinfo_enctype, constants.EncryptionTypes(credential_info.fields['EncryptionType']).name)
            if not args.asrep_key:
                parsed_credential_info['Encryption Type'] = "<Cannot decrypt, --asrep-key missing>"
                logging.error('No ASREP key supplied, cannot decrypt PAC Credentials')
                parsed_tuPAC.append({"Credential Info": parsed_credential_info})
            else:
                parsed_tuPAC.append({"Credential Info": parsed_credential_info})
                newCipher = _enctype_table[credinfo_enctype]
                key = Key(credinfo_enctype, unhexlify(args.asrep_key))
                plain_credential_data = newCipher.decrypt(key, 16, credential_info.fields['SerializedData'])
                type1 = TypeSerialization1(plain_credential_data)
                newdata = plain_credential_data[len(type1) + 4:]
                # Parsing 2.6.2 PAC_CREDENTIAL_DATA
                credential_data = pac.PAC_CREDENTIAL_DATA(newdata)
                parsed_credential_data = {}
                parsed_credential_data['  Credential Count'] = credential_data['CredentialCount']
                parsed_tuPAC.append({"  Credential Data": parsed_credential_data})
                # Parsing (one or many) 2.6.3 SECPKG_SUPPLEMENTAL_CRED
                for credential in credential_data['Credentials']:
                    parsed_secpkg_supplemental_cred = {}
                    parsed_secpkg_supplemental_cred['      Package Name'] = credential['PackageName']
                    parsed_secpkg_supplemental_cred['      Credential Size'] = credential['CredentialSize']
                    parsed_tuPAC.append({"      SecPkg Credentials": parsed_secpkg_supplemental_cred})
                    # Parsing 2.6.4 NTLM_SUPPLEMENTAL_CREDENTIAL
                    ntlm_supplemental_cred = pac.NTLM_SUPPLEMENTAL_CREDENTIAL(b''.join(credential['Credentials']))
                    parsed_ntlm_supplemental_cred = {}
                    parsed_ntlm_supplemental_cred['        Version'] = ntlm_supplemental_cred['Version']
                    parsed_ntlm_supplemental_cred['        Flags'] = ntlm_supplemental_cred['Flags']
                    parsed_ntlm_supplemental_cred['        LmPasword'] = hexlify(ntlm_supplemental_cred['LmPassword']).decode('utf-8')
                    parsed_ntlm_supplemental_cred['        NtPasword'] = hexlify(ntlm_supplemental_cred['NtPassword']).decode('utf-8')
                    parsed_tuPAC.append({"        NTLM Credentials": parsed_ntlm_supplemental_cred})

        elif infoBuffer['ulType'] == pac.PAC_DELEGATION_INFO:
            delegationInfo = pac.S4U_DELEGATION_INFO(data)
            parsed_data = {}
            parsed_data['S4U2proxyTarget'] = delegationInfo['S4U2proxyTarget']
            parsed_data['TransitedListSize'] = delegationInfo.fields['TransitedListSize'].fields['Data']
            parsed_data['S4UTransitedServices'] = delegationInfo['S4UTransitedServices'].decode('utf-8')
            parsed_tuPAC.append({"DelegationInfo": parsed_data})
        elif infoBuffer['ulType'] == pac.PAC_ATTRIBUTES_INFO:
            # Parsing 2.14 PAC_ATTRIBUTES_INFO
            attributeInfo = pac.PAC_ATTRIBUTE_INFO(data)
            flags = attributeInfo['Flags']
            attr_flags = []
            for flag_lib in Attributes_Flags:
                if flags & flag_lib.value:
                    attr_flags.append(flag_lib.name)

            parsed_data = {
                'Flags': f"({flags}) {', '.join(attr_flags)}"
            }
            parsed_tuPAC.append({"Attributes Info": parsed_data})
        elif infoBuffer['ulType'] == pac.PAC_REQUESTOR_INFO:
            # Parsing 2.15 PAC_REQUESTOR
            requestorInfo = pac.PAC_REQUESTOR(data)
            parsed_data = {
                'UserSid': requestorInfo['UserSid'].formatCanonical()
            }
            parsed_tuPAC.append({"Requestor Info": parsed_data})
        else:
            logging.debug("Unsupported PAC structure: %s. Please raise an issue or PR" % infoBuffer['ulType'])

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
    if args.password or args.hex_pass:
        if not args.salt and args.user and args.domain: # https://www.thehacker.recipes/ad/movement/kerberos
            if args.user.endswith('$'):
                args.salt = "%shost%s.%s" % (args.domain.upper(), args.user.rstrip('$').lower(), args.domain.lower())
            else:
                args.salt = "%s%s" % (args.domain.upper(), args.user)
        for cipher in allciphers:
            if cipher == 23 and args.hex_pass:
                # RC4 calculation is done manually for raw passwords
                md4 = MD4.new()
                md4.update(unhexlify(args.hex_pass))
                ekeys[cipher] = Key(cipher, md4.digest())
                logging.debug('Calculated type %s (%d) Kerberos key: %s' % (constants.EncryptionTypes(cipher).name, cipher, hexlify(ekeys[cipher].contents).decode('utf-8')))
            elif args.salt:
                # Do conversion magic for raw passwords
                if args.hex_pass:
                    rawsecret = unhexlify(args.hex_pass).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
                else:
                    # If not raw, it was specified from the command line, assume it's not UTF-16
                    rawsecret = args.password
                ekeys[cipher] = string_to_key(cipher, rawsecret, args.salt)
                logging.debug('Calculated type %s (%d) Kerberos key: %s' % (constants.EncryptionTypes(cipher).name, cipher, hexlify(ekeys[cipher].contents).decode('utf-8')))
            else:
                logging.debug('Cannot calculate type %s (%d) Kerberos key: salt is None: Missing -s/--salt or (-u/--user and -d/--domain)' % (constants.EncryptionTypes(cipher).name, cipher))
    else:
        logging.debug('No password (-p/--password or -hp/--hex_pass supplied, skipping Kerberos keys calculation')
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

    ticket_decryption = parser.add_argument_group()
    ticket_decryption.title = 'Ticket decryption credentials (optional)'
    ticket_decryption.description = 'Tickets carry a set of information encrypted by one of the target service account\'s Kerberos keys.' \
                        '(example: if the ticket is for user:"john" for service:"cifs/service.domain.local", you need to supply credentials or keys ' \
                        'of the service account who owns SPN "cifs/service.domain.local")'
    ticket_decryption.add_argument('-p', '--password', action="store", metavar="PASSWORD", help='Cleartext password of the service account')
    ticket_decryption.add_argument('-hp', '--hex-password', dest='hex_pass', action="store", metavar="HEXPASSWORD", help='Hex password of the service account')
    ticket_decryption.add_argument('-u', '--user', action="store", metavar="USER", help='Name of the service account')
    ticket_decryption.add_argument('-d', '--domain', action="store", metavar="DOMAIN", help='FQDN Domain')
    ticket_decryption.add_argument('-s', '--salt', action="store", metavar="SALT", help='Salt for keys calculation (DOMAIN.LOCALSomeuser for users, DOMAIN.LOCALhostsomemachine.domain.local for machines)')
    ticket_decryption.add_argument('--rc4', action="store", metavar="RC4", help='RC4 KEY (i.e. NT hash)')
    ticket_decryption.add_argument('--aes', action="store", metavar="HEXKEY", help='AES128 or AES256 key')

    credential_info = parser.add_argument_group()
    credential_info.title = 'PAC Credentials decryption material'
    credential_info.description = '[MS-PAC] section 2.6 (PAC Credentials) describes an element that is used to send credentials for alternate security protocols to the client during initial logon.' \
                                  'This PAC credentials is typically used when PKINIT is conducted for pre-authentication. This structure contains LM and NT hashes.' \
                                  'The information is encrypted using the AS reply key. Attack primitive known as UnPAC-the-Hash. (https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)'
    credential_info.add_argument('--asrep-key', action="store", metavar="HEXKEY", help='AS reply key for PAC Credentials decryption')


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not args.salt:
        if args.user and not args.domain:
            parser.error('without -s/--salt, and with -u/--user, argument -d/--domain is required to calculate the salt')
        elif not args.user and args.domain:
            parser.error('without -s/--salt, and with -d/--domain, argument -u/--user is required to calculate the salt')

    if args.domain and not '.' in args.domain:
        parser.error('Domain supplied in -d/--domain should be FQDN')

    return args

def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    try:
        parse_ccache(args)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))

if __name__ == '__main__':
    main()
