# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   A Socks Proxy for the SMB Protocol
#
#   A simple SOCKS server that proxy connection to relayed connections
#
# Author:
#   Alberto Solino (@agsolino)
#
import calendar
import time
import random
import string
from struct import unpack
from binascii import hexlify
from six import b

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay
from impacket.nmb import NetBIOSTCPSession
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_SIGN
from impacket.smb import NewSMBPacket, SMBCommand, SMB, SMBExtended_Security_Data, \
    SMBExtended_Security_Parameters, SMBNTLMDialect_Parameters, SMBNTLMDialect_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Parameters, SMBSessionSetupAndX_Extended_Data
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_AID
from impacket.smb3 import SMB2Packet, SMB2_FLAGS_SERVER_TO_REDIR, SMB2_NEGOTIATE, SMB2Negotiate_Response, \
    SMB2_SESSION_SETUP, SMB2SessionSetup_Response, SMB2SessionSetup, SMB2_LOGOFF, SMB2Logoff_Response, \
    SMB2_DIALECT_WILDCARD, SMB2_FLAGS_SIGNED, SMB2_SESSION_FLAG_IS_GUEST
from impacket.spnego import MechTypes, ASN1_SUPPORTED_MECH
from impacket.smb import SMB_DIALECT
from impacket.smbserver import getFileTime

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "SMBSocksRelay"

class SMBSocksRelay(SocksRelay):
    PLUGIN_NAME = 'SMB Socks Plugin'
    PLUGIN_SCHEME = 'SMB'
    
    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.__NBSession = None
        self.isSMB2 = False
        self.serverDialect = SMB_DIALECT

        # Let's verify the target's server SMB version, will need it for later.
        # We're assuming all connections to the target server use the same SMB version
        for key in list(activeRelays.keys()):
            if key != 'data' and key != 'scheme':
                if 'protocolClient' in activeRelays[key]:
                    self.serverDialect = activeRelays[key]['protocolClient'].session.getDialect()
                    self.isSMB2 = activeRelays[key]['protocolClient'].session.getDialect() is not SMB_DIALECT
                    break

    @staticmethod
    def getProtocolPort():
        return 445

    def initConnection(self):
        # An incoming SMB Connection. Nice
        self.__NBSession = NetBIOSTCPSession('', 'HOST', self.targetHost, sess_port=self.targetPort, sock=self.socksSocket)

    def skipAuthentication(self):
        packet, smbCommand = self.getSMBPacket()

        if isinstance(packet, SMB2Packet) is False:
            if packet['Command'] == SMB.SMB_COM_NEGOTIATE:
                # Nego packet, we should answer with supporting only SMBv1
                resp = self.getNegoAnswer(packet)
                self.__NBSession.send_packet(resp.getData())
                # If target Server is running SMB2+ and we're here, there should be a SMB2+ NEGO packet coming
                # calling skipAuth again and go from there
                if self.isSMB2:
                    return self.skipAuthentication()
                packet, smbCommand = self.getSMBPacket()

            if packet['Command'] == SMB.SMB_COM_SESSION_SETUP_ANDX:
                # We have a session setup, let's answer what the original target answered us.
                self.clientConnection, self.username = self.processSessionSetup(packet)
                if self.clientConnection is None:
                    return False
        else:
            if packet['Command'] == SMB2_NEGOTIATE:
                resp = self.getNegoAnswer(packet)
                self.__NBSession.send_packet(resp.getData())
                packet, smbCommand = self.getSMBPacket()

            if packet['Command'] == SMB2_SESSION_SETUP:
                self.clientConnection, self.username = self.processSessionSetup(packet)
                if self.clientConnection is None:
                    return False

        return True

    def tunnelConnection(self):
        # For the rest of the remaining packets, we should just read and send. Except when trying to log out,
        # that's forbidden! ;)
        while True:
            # 1. Get Data from client
            data = self.__NBSession.recv_packet().get_trailer()

            if len(data) == 0:
                break

            if self.isSMB2 is False:
                packet = NewSMBPacket(data=data)

                if packet['Command'] == SMB.SMB_COM_LOGOFF_ANDX:
                    # We do NOT want to get logged off do we?
                    LOG.debug('SOCKS: Avoiding logoff for %s@%s:%s' % (self.username, self.targetHost, self.targetPort))
                    data = self.getLogOffAnswer(packet)
                else:
                    # 2. Send it to the relayed session
                    self.clientConnection.getSMBServer()._sess.send_packet(data)

                    # 3. Get the target's answer
                    data = self.clientConnection.getSMBServer()._sess.recv_packet().get_trailer()

                    packet = NewSMBPacket(data=data)

                    if packet['Command'] == SMB.SMB_COM_TRANSACTION or packet['Command'] == SMB.SMB_COM_TRANSACTION2:
                        try:
                            while True:
                                # Anything else to read? with timeout of 1 sec. This is something to test or find
                                # a better way to control
                                data2 = self.clientConnection.getSMBServer()._sess.recv_packet(timeout=1).get_trailer()
                                self.__NBSession.send_packet(data)
                                data = data2
                        except Exception as e:
                            if str(e).find('timed out') > 0:
                                pass
                            else:
                                raise

                    if len(data) == 0:
                        break
            else:
                packet = SMB2Packet(data=data)
                origID = packet['MessageID']

                # Just in case, let's remove any signing attempt
                packet['Signature'] = ""
                packet['Flags'] &= ~(SMB2_FLAGS_SIGNED)

                # Let's be sure the TreeConnect Table is filled with fake data
                if (packet['TreeID'] in self.clientConnection.getSMBServer()._Session['TreeConnectTable']) is False:
                    self.clientConnection.getSMBServer()._Session['TreeConnectTable'][packet['TreeID']] = {}
                    self.clientConnection.getSMBServer()._Session['TreeConnectTable'][packet['TreeID']]['EncryptData'] = False

                if packet['Command'] == SMB2_LOGOFF:
                    # We do NOT want to get logged off do we?
                    LOG.debug('SOCKS: Avoiding logoff for %s@%s:%s' % (self.username, self.targetHost, self.targetPort))
                    data = self.getLogOffAnswer(packet)
                else:
                    # 2. Send it to the relayed session
                    self.clientConnection.getSMBServer().sendSMB(packet)

                    # 3. Get the target's answer
                    packet = self.clientConnection.getSMBServer().recvSMB()

                    if len(packet.getData()) == 0:
                        break
                    else:
                        packet['MessageID'] = origID
                        data = packet.getData()

            # 4. Send it back to the client
            self.__NBSession.send_packet(data)

        return True

    def getSMBPacket(self):
        data = self.__NBSession.recv_packet()
        try:
            packet = NewSMBPacket(data=data.get_trailer())
            smbCommand = SMBCommand(packet['Data'][0])
        except Exception:
            # Maybe a SMB2 packet?
            try:
                packet = SMB2Packet(data = data.get_trailer())
                smbCommand = None
            except Exception as e:
                LOG.debug("Exception:", exc_info=True)
                LOG.error('SOCKS: %s' % str(e))

        return packet, smbCommand

    def getNegoAnswer(self, recvPacket):

        if self.isSMB2 is False:
            smbCommand = SMBCommand(recvPacket['Data'][0])
            respSMBCommand = SMBCommand(SMB.SMB_COM_NEGOTIATE)

            resp = NewSMBPacket()
            resp['Flags1'] = SMB.FLAGS1_REPLY
            resp['Pid'] = recvPacket['Pid']
            resp['Tid'] = recvPacket['Tid']
            resp['Mid'] = recvPacket['Mid']

            dialects = smbCommand['Data'].split(b'\x02')
            index = dialects.index(b'NT LM 0.12\x00') - 1
            # Let's fill the data for NTLM
            if recvPacket['Flags2'] & SMB.FLAGS2_EXTENDED_SECURITY:
                resp['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_UNICODE
                _dialects_data = SMBExtended_Security_Data()
                _dialects_data['ServerGUID'] = b'A' * 16
                blob = SPNEGO_NegTokenInit()
                blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
                _dialects_data['SecurityBlob'] = blob.getData()

                _dialects_parameters = SMBExtended_Security_Parameters()
                _dialects_parameters[
                    'Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_NT_SMBS | SMB.CAP_UNICODE
                _dialects_parameters['ChallengeLength'] = 0

            else:
                resp['Flags2'] = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_UNICODE
                _dialects_parameters = SMBNTLMDialect_Parameters()
                _dialects_data = SMBNTLMDialect_Data()
                _dialects_data['Payload'] = b''
                _dialects_data['Challenge'] = b'\x11\x22\x33\x44\x55\x66\x77\x88'
                _dialects_parameters['ChallengeLength'] = 8
                _dialects_parameters['Capabilities'] = SMB.CAP_USE_NT_ERRORS | SMB.CAP_NT_SMBS

            _dialects_parameters['Capabilities'] |= SMB.CAP_RPC_REMOTE_APIS
            _dialects_parameters['DialectIndex'] = index
            _dialects_parameters['SecurityMode'] = SMB.SECURITY_AUTH_ENCRYPTED | SMB.SECURITY_SHARE_USER
            _dialects_parameters['MaxMpxCount'] = 1
            _dialects_parameters['MaxNumberVcs'] = 1
            _dialects_parameters['MaxBufferSize'] = 64000
            _dialects_parameters['MaxRawSize'] = 65536
            _dialects_parameters['SessionKey'] = 0
            _dialects_parameters['LowDateTime'] = 0
            _dialects_parameters['HighDateTime'] = 0
            _dialects_parameters['ServerTimeZone'] = 0

            respSMBCommand['Data'] = _dialects_data
            respSMBCommand['Parameters'] = _dialects_parameters

            resp.addCommand(respSMBCommand)
        else:
            resp= SMB2Packet()
            resp['Flags'] = SMB2_FLAGS_SERVER_TO_REDIR
            resp['Status'] = STATUS_SUCCESS
            resp['CreditRequestResponse'] = 1
            resp['CreditCharge'] = 1
            resp['Command'] = SMB2_NEGOTIATE
            resp['SessionID'] = 0
            resp['MessageID'] = 0
            resp['TreeID'] = 0

            respSMBCommand = SMB2Negotiate_Response()

            respSMBCommand['SecurityMode'] = 1
            if isinstance(recvPacket, NewSMBPacket):
                respSMBCommand['DialectRevision'] = SMB2_DIALECT_WILDCARD
            else:
                respSMBCommand['DialectRevision'] = self.serverDialect
                resp['MessageID'] = 1
            respSMBCommand['ServerGuid'] = b(''.join([random.choice(string.ascii_letters) for _ in range(16)]))
            respSMBCommand['Capabilities'] = 0x7
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

            resp['Data'] = respSMBCommand

        return resp

    def processSessionSetup(self, recvPacket):

        if self.isSMB2 is False:
            respSMBCommand = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
            smbCommand = SMBCommand(recvPacket['Data'][0])

            if smbCommand['WordCount'] == 12:
                respParameters = SMBSessionSetupAndX_Extended_Response_Parameters()
                respData = SMBSessionSetupAndX_Extended_Response_Data()

                # First of all, we should received a type 1 message. Let's answer it
                # NEGOTIATE_MESSAGE
                challengeMessage = self.sessionData['CHALLENGE_MESSAGE']
                challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SIGN)

                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegState'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
                respToken['ResponseToken'] = challengeMessage.getData()

                respParameters['SecurityBlobLength'] = len(respToken.getData())
                respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
                respData['SecurityBlob'] = respToken.getData()

                respData['NativeOS'] = ''
                respData['NativeLanMan'] = ''
                respSMBCommand['Parameters'] = respParameters
                respSMBCommand['Data'] = respData

                resp = NewSMBPacket()
                resp['Flags1'] = SMB.FLAGS1_REPLY
                resp['Flags2'] = SMB.FLAGS2_NT_STATUS
                resp['Pid'] = recvPacket['Pid']
                resp['Tid'] = recvPacket['Tid']
                resp['Mid'] = recvPacket['Mid']
                resp['Uid'] = 0
                errorCode = STATUS_MORE_PROCESSING_REQUIRED
                resp['ErrorCode'] = errorCode >> 16
                resp['ErrorClass'] = errorCode & 0xff
                resp.addCommand(respSMBCommand)

                self.__NBSession.send_packet(resp.getData())
                recvPacket, smbCommand = self.getSMBPacket()

                sessionSetupParameters = SMBSessionSetupAndX_Extended_Parameters(smbCommand['Parameters'])
                sessionSetupData = SMBSessionSetupAndX_Extended_Data()
                sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
                sessionSetupData.fromString(smbCommand['Data'])

                if unpack('B', sessionSetupData['SecurityBlob'][0:1])[0] != ASN1_AID:
                    # If there no GSSAPI ID, it must be an AUTH packet
                    blob = SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
                    token = blob['ResponseToken']
                else:
                    # NEGOTIATE packet
                    blob = SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
                    token = blob['MechToken']

                # Now we should've received a type 3 message
                authenticateMessage = NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                try:
                    username = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                           authenticateMessage['user_name'].decode('utf-16le'))).upper()
                except UnicodeDecodeError:
                    # Not Unicode encoded?
                    username = ('%s/%s' % (authenticateMessage['domain_name'], authenticateMessage['user_name'])).upper()

                # Check if we have a connection for the user
                if username in self.activeRelays:
                    LOG.info('SOCKS: Proxying client session for %s@%s(445)' % (username, self.targetHost))
                    errorCode = STATUS_SUCCESS
                    smbClient = self.activeRelays[username]['protocolClient'].session
                    uid = smbClient.getSMBServer().get_uid()
                else:
                    LOG.error('SOCKS: No session for %s@%s(445) available' % (username, self.targetHost))
                    errorCode = STATUS_ACCESS_DENIED
                    uid = 0
                    smbClient = None

                resp = NewSMBPacket()
                resp['Flags1'] = recvPacket['Flags1'] | SMB.FLAGS1_REPLY
                resp['Flags2'] = recvPacket['Flags2'] | SMB.FLAGS2_EXTENDED_SECURITY
                resp['Command'] = recvPacket['Command']
                resp['Pid'] = recvPacket['Pid']
                resp['Tid'] = recvPacket['Tid']
                resp['Mid'] = recvPacket['Mid']
                resp['Uid'] = uid
                resp['ErrorCode'] = errorCode >> 16
                resp['ErrorClass'] = errorCode & 0xff
                respData['NativeOS'] = ''
                respData['NativeLanMan'] = ''

                if uid == 0:
                    resp['Data'] = b'\x00\x00\x00'
                    smbClient = None
                else:
                    respToken = SPNEGO_NegTokenResp()
                    # accept-completed
                    respToken['NegState'] = b'\x00'
                    respParameters['SecurityBlobLength'] = len(respToken)
                    respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
                    respData['SecurityBlob'] = respToken.getData()

                    respSMBCommand['Parameters'] = respParameters
                    respSMBCommand['Data'] = respData
                    resp.addCommand(respSMBCommand)

                self.__NBSession.send_packet(resp.getData())


                return smbClient, username
            else:
                LOG.error('SOCKS: Can\'t handle standard security at the moment!')
                return None
        else:
            respSMBCommand = SMB2SessionSetup_Response()
            sessionSetupData = SMB2SessionSetup(recvPacket['Data'])

            securityBlob = sessionSetupData['Buffer']

            rawNTLM = False
            if unpack('B', securityBlob[0:1])[0] == ASN1_AID:
                # NEGOTIATE packet
                blob = SPNEGO_NegTokenInit(securityBlob)
                token = blob['MechToken']
                if len(blob['MechTypes'][0]) > 0:
                    # Is this GSSAPI NTLM or something else we don't support?
                    mechType = blob['MechTypes'][0]
                    if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                        # Nope, do we know it?
                        if mechType in MechTypes:
                            mechStr = MechTypes[mechType]
                        else:
                            mechStr = hexlify(mechType)
                        LOG.debug("Unsupported MechType '%s', we just want NTLMSSP, answering" % mechStr)
                        # We don't know the token, we answer back again saying
                        # we just support NTLM.
                        # ToDo: Build this into a SPNEGO_NegTokenResp()
                        respToken = b'\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                        respSMBCommand['SecurityBufferOffset'] = 0x48
                        respSMBCommand['SecurityBufferLength'] = len(respToken)
                        respSMBCommand['Buffer'] = respToken

                        resp = SMB2Packet()
                        resp['Flags'] = SMB2_FLAGS_SERVER_TO_REDIR
                        resp['Status'] = STATUS_SUCCESS
                        resp['CreditRequestResponse'] = 1
                        resp['CreditCharge'] = recvPacket['CreditCharge']
                        resp['Command'] = recvPacket['Command']
                        resp['SessionID'] = 0
                        resp['Reserved'] = recvPacket['Reserved']
                        resp['MessageID'] = recvPacket['MessageID']
                        resp['TreeID'] = recvPacket['TreeID']
                        resp['Data'] = respSMBCommand

                        self.__NBSession.send_packet(resp.getData())
                        recvPacket, smbCommand = self.getSMBPacket()
                        return self.processSessionSetup(recvPacket)

            elif unpack('B', securityBlob[0:1])[0] == ASN1_SUPPORTED_MECH:
                # AUTH packet
                blob = SPNEGO_NegTokenResp(securityBlob)
                token = blob['ResponseToken']
            else:
                # No GSSAPI stuff, raw NTLMSSP
                rawNTLM = True
                token = securityBlob

            # NEGOTIATE_MESSAGE
            # First of all, we should received a type 1 message. Let's answer it
            challengeMessage = self.sessionData['CHALLENGE_MESSAGE']
            challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SIGN)

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegState'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()
            else:
                respToken = challengeMessage

            resp = SMB2Packet()
            resp['Flags'] = SMB2_FLAGS_SERVER_TO_REDIR
            resp['Status'] = STATUS_MORE_PROCESSING_REQUIRED
            resp['CreditRequestResponse'] = 1
            resp['CreditCharge'] = recvPacket['CreditCharge']
            resp['Command'] = recvPacket['Command']
            resp['SessionID'] = 0
            resp['Reserved'] = recvPacket['Reserved']
            resp['MessageID'] = recvPacket['MessageID']
            resp['TreeID'] = recvPacket['TreeID']

            respSMBCommand['SecurityBufferOffset'] = 0x48
            respSMBCommand['SecurityBufferLength'] = len(respToken)
            respSMBCommand['Buffer'] = respToken.getData()
            resp['Data'] = respSMBCommand

            self.__NBSession.send_packet(resp.getData())
            recvPacket, smbCommand = self.getSMBPacket()

            sessionSetupData = SMB2SessionSetup(recvPacket['Data'])
            securityBlob = sessionSetupData['Buffer']

            blob = SPNEGO_NegTokenResp(securityBlob)
            token = blob['ResponseToken']

            # AUTHENTICATE_MESSAGE, here we deal with authentication
            authenticateMessage = NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)

            try:
                username = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                       authenticateMessage['user_name'].decode('utf-16le'))).upper()
            except UnicodeDecodeError:
                # Not Unicode encoded?
                username = ('%s/%s' % (authenticateMessage['domain_name'], authenticateMessage['user_name'])).upper()

            respToken = SPNEGO_NegTokenResp()

            # Check if we have a connection for the user
            if username in self.activeRelays:
                LOG.info('SOCKS: Proxying client session for %s@%s(445)' % (username, self.targetHost))
                errorCode = STATUS_SUCCESS
                smbClient = self.activeRelays[username]['protocolClient'].session
                uid = smbClient.getSMBServer()._Session['SessionID']
            else:
                LOG.error('SOCKS: No session for %s@%s(445) available' % (username, self.targetHost))
                errorCode = STATUS_ACCESS_DENIED
                uid = 0
                smbClient = None

            # accept-completed
            respToken['NegState'] = b'\x00'

            resp = SMB2Packet()
            resp['Flags'] = SMB2_FLAGS_SERVER_TO_REDIR
            resp['Status'] = errorCode
            resp['CreditRequestResponse'] = 1
            resp['CreditCharge'] = recvPacket['CreditCharge']
            resp['Command'] = recvPacket['Command']
            resp['SessionID'] = uid
            resp['Reserved'] = recvPacket['Reserved']
            resp['MessageID'] = recvPacket['MessageID']
            resp['TreeID'] = recvPacket['TreeID']

            respSMBCommand['SecurityBufferOffset'] = 0x48

            # This is important for SAMBA client to work. If it is not set as a guest session,
            # SAMBA will *not* like the fact that the packets are not signed (even tho it was not enforced).
            respSMBCommand['SessionFlags'] = SMB2_SESSION_FLAG_IS_GUEST
            respSMBCommand['SecurityBufferLength'] = len(respToken)
            respSMBCommand['Buffer'] = respToken.getData()
            resp['Data'] = respSMBCommand

            self.__NBSession.send_packet(resp.getData())
            return smbClient, username

    def getLogOffAnswer(self, recvPacket):

        if self.isSMB2 is False:
            respSMBCommand = SMBCommand(SMB.SMB_COM_LOGOFF_ANDX)

            resp = NewSMBPacket()
            resp['Flags1'] = SMB.FLAGS1_REPLY
            resp['Pid'] = recvPacket['Pid']
            resp['Tid'] = recvPacket['Tid']
            resp['Mid'] = recvPacket['Mid']
            resp['Uid'] = recvPacket['Uid']

            respParameters = b''
            respData = b''
            respSMBCommand['Parameters']   = respParameters
            respSMBCommand['Data']         = respData

            resp.addCommand(respSMBCommand)

        else:
            respSMBCommand = SMB2Logoff_Response()

            resp = SMB2Packet()
            resp['Flags'] = SMB2_FLAGS_SERVER_TO_REDIR
            resp['Status'] = STATUS_SUCCESS
            resp['CreditRequestResponse'] = 1
            resp['CreditCharge'] = recvPacket['CreditCharge']
            resp['Command'] = recvPacket['Command']
            resp['SessionID'] = recvPacket['SessionID']
            resp['Reserved'] = recvPacket['Reserved']
            resp['MessageID'] = recvPacket['MessageID']
            resp['TreeID'] = recvPacket['TreeID']
            resp['Data'] = respSMBCommand

        return resp
