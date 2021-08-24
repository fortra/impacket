#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will get the PAC of the specified target user just having a normal authenticated user credentials.
#   It does so by using a mix of [MS-SFU]'s S4USelf + User to User Kerberos Authentication.
#   Original idea (or accidental discovery :) ) of adding U2U capabilities inside a S4USelf by Benjamin Delpy (@gentilkiwi)
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   - U2U: https://tools.ietf.org/html/draft-ietf-cat-user2user-02
#   - [MS-SFU]: https://msdn.microsoft.com/en-us/library/cc246071.aspx
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import re
import struct
import sys
from binascii import unhexlify
from six import b

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
    PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.winregistry import hexdump


class S4U2SELF:

    def printPac(self, data):
        encTicketPart = decoder.decode(data, asn1Spec=EncTicketPart())[0]
        adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[
            0]
        # So here we have the PAC
        pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
        buff = pacType['Buffers']

        for bufferN in range(pacType['cBuffers']):
            infoBuffer = PAC_INFO_BUFFER(buff)
            data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
            if logging.getLogger().level == logging.DEBUG:
                print("TYPE 0x%x" % infoBuffer['ulType'])
            if infoBuffer['ulType'] == 1:
                type1 = TypeSerialization1(data)
                # I'm skipping here 4 bytes with its the ReferentID for the pointer
                newdata = data[len(type1)+4:]
                kerbdata = KERB_VALIDATION_INFO()
                kerbdata.fromString(newdata)
                kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
                kerbdata.dump()
                print()
                print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
                print()
            elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
                clientInfo = PAC_CLIENT_INFO(data)
                if logging.getLogger().level == logging.DEBUG:
                    clientInfo.dump()
                    print()
            elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
                signatureData = PAC_SIGNATURE_DATA(data)
                if logging.getLogger().level == logging.DEBUG:
                    signatureData.dump()
                    print()
            elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
                signatureData = PAC_SIGNATURE_DATA(data)
                if logging.getLogger().level == logging.DEBUG:
                    signatureData.dump()
                    print()
            elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
                upn = UPN_DNS_INFO(data)
                if logging.getLogger().level == logging.DEBUG:
                    upn.dump()
                    print(data[upn['DnsDomainNameOffset']:])
                    print()
            else:
                hexdump(data)

            if logging.getLogger().level == logging.DEBUG:
                print("#"*80)

            buff = buff[len(infoBuffer):]


    def __init__(self, behalfUser, username = '', password = '', domain='', hashes = None):
        self.__username = username
        self.__password = password
        self.__domain = domain.upper()
        self.__behalfUser = behalfUser
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self):
        # Try all requested protocols until one works.

        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash), unhexlify(self.__nthash))

        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] =  constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print ('\n')

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

        tgsReq['pvno'] =  5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
        # requests a service ticket to itself on behalf of a user. The user is
        # identified to the KDC by the user's name and realm.
        clientName = Principal(self.__behalfUser, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I',constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += b(self.__behalfUser) + b(self.__domain) + b'Kerberos'

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
        opts.append( constants.KDCOptions.forwardable.value )
        opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.renewable_ok.value )
        opts.append( constants.KDCOptions.canonicalize.value )
        opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        serverName = Principal(self.__username, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        #serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                      (int(cipher.enctype),int(constants.EncryptionTypes.rc4_hmac.value)))

        # If you comment these two lines plus enc_tkt_in_skey as option, it is bassically a S4USelf
        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        message = encoder.encode(tgsReq)

        r = sendReceive(message, self.__domain, None)

        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        cipherText = tgs['ticket']['enc-part']['cipher']

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
        #  application session key), encrypted with the service key
        #  (section 5.4.2)

        newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]

        # Pass the hash/aes key :P
        if self.__nthash != '' and (isinstance(self.__nthash, bytes) and self.__nthash != b''):
            key = Key(newCipher.enctype, unhexlify(self.__nthash))
        else:
            if newCipher.enctype == Enctype.RC4:
                key = newCipher.string_to_key(password, '', None)
            else:
                key = newCipher.string_to_key(password, self.__domain.upper()+self.__username, None)

        try:
            # If is was plain U2U, this is the key
            plainText = newCipher.decrypt(key, 2, str(cipherText))
        except:
            # S4USelf + U2U uses this other key
            plainText = cipher.decrypt(sessionKey, 2, cipherText)

        self.printPac(plainText)

# Process command-line arguments.
if __name__ == '__main__':
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('credentials', action='store', help='domain/username[:password]. Valid domain credentials to use '
                                                       'for grabbing targetUser\'s PAC')
    parser.add_argument('-targetUser', action='store', required=True, help='the target user to retrieve the PAC of')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password = parse_credentials(options.credentials)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        dumper = S4U2SELF(options.targetUser, username, password, domain, options.hashes)
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
