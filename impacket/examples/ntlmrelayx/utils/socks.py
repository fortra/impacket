#!/usr/bin/env python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SOCKS proxy server/client
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#  A simple SOCKS server that proxy connection to relayed connections
#
# ToDo:
# [ ] Handle better the SOCKS specification (RFC1928), e.g. BIND
# [ ] Port handlers should be dynamically subscribed, and coded in another place. This will help coding
#     proxies for different protocols (e.g. MSSQL)

import SocketServer
import socket
import time
from Queue import Queue
from struct import unpack, pack
from threading import Timer

from impacket import LOG
from impacket.dcerpc.v5.enum import Enum
from impacket.nmb import NetBIOSTCPSession
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_SIGN
from impacket.smb import NewSMBPacket, SMBCommand, SMB, SMBExtended_Security_Data, \
    SMBExtended_Security_Parameters, SMBNTLMDialect_Parameters, SMBNTLMDialect_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Parameters, SMBSessionSetupAndX_Extended_Data
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_AID
from impacket.structure import Structure

class enumItems(Enum):
    NO_AUTHENTICATION = 0
    GSSAPI            = 1
    USER_PASS         = 2
    UNACCEPTABLE      = 0xFF

class replyField(Enum):
    SUCCEEDED             = 0
    SOCKS_FAILURE         = 1
    NOT_ALLOWED           = 2
    NETWORK_UNREACHABLE   = 3
    HOST_UNREACHABLE      = 4
    CONNECTION_REFUSED    = 5
    TTL_EXPIRED           = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_NOT_SUPPORTED = 8

class ATYP(Enum):
    IPv4 = 1
    DOMAINNAME = 3
    IPv6 = 4

class SOCKS5_GREETINGS(Structure):
    structure = (
        ('VER','B=5'),
        #('NMETHODS','B=0'),
        ('METHODS','B*B'),
    )


class SOCKS5_GREETINGS_BACK(Structure):
    structure = (
        ('VER','B=5'),
        ('METHODS','B=0'),
    )

class SOCKS5_REQUEST(Structure):
    structure = (
        ('VER','B=5'),
        ('CMD','B=0'),
        ('RSV','B=0'),
        ('ATYP','B=0'),
        ('PAYLOAD',':'),
    )

class SOCKS5_REPLY(Structure):
    structure = (
        ('VER','B=5'),
        ('REP','B=5'),
        ('RSV','B=0'),
        ('ATYP','B=1'),
        ('PAYLOAD',':="AAAAA"'),
    )

class SOCKS4_REQUEST(Structure):
    structure = (
        ('VER','B=4'),
        ('CMD','B=0'),
        ('PORT','>H=0'),
        ('ADDR','4s="'),
        ('PAYLOAD',':'),
    )

class SOCKS4_REPLY(Structure):
    structure = (
        ('VER','B=0'),
        ('REP','B=0x5A'),
        ('RSV','<H=0'),
        ('RSV','<L=0'),
    )

activeConnections = Queue()

# Taken from https://stackoverflow.com/questions/474528/what-is-the-best-way-to-repeatedly-execute-a-function-every-x-seconds-in-python
# Thanks https://stackoverflow.com/users/624066/mestrelion
class RepeatedTimer(object):
  def __init__(self, interval, function, *args, **kwargs):
    self._timer = None
    self.interval = interval
    self.function = function
    self.args = args
    self.kwargs = kwargs
    self.is_running = False
    self.next_call = time.time()
    self.start()

  def _run(self):
    self.is_running = False
    self.start()
    self.function(*self.args, **self.kwargs)

  def start(self):
    if not self.is_running:
      self.next_call += self.interval
      self._timer = Timer(self.next_call - time.time(), self._run)
      self._timer.start()
      self.is_running = True

  def stop(self):
    self._timer.cancel()
    self.is_running = False

def keepAliveTimer(server):
    LOG.debug('KeepAlive Timer reached. Updating connections')

    for target in server.activeRelays.iterkeys():
        if server.activeRelays[target].has_key(445):
            # Now cycle thru the users
            for user in server.activeRelays[target][445].iterkeys():
                if user != 'data':
                    # Let's call an echo request if the connection is not used
                    if server.activeRelays[target][445][user]['inUse'] is False:
                        LOG.debug('Sending keep alive to %s@%s:445' % (user, target))
                        tid = server.activeRelays[target][445][user]['client'].connect_tree('IPC$')
                        server.activeRelays[target][445][user]['client'].disconnect_tree(tid)
                    else:
                        LOG.debug('Skipping %s@%s:445 since it\'s being used at the moment' % (user, target))

    # Let's parse new connections if available
    while activeConnections.empty() is not True:
        target, port, userName, smb, data = activeConnections.get()
        LOG.debug('SOCKS: Adding %s:%s to list of relayConnections' % (target, port))
        # ToDo: Careful. Dicts are not thread safe right?
        if server.activeRelays.has_key(target) is not True:
            server.activeRelays[target] = {}
        if server.activeRelays[target].has_key(port) is not True:
            server.activeRelays[target][port] = {}
        server.activeRelays[target][port][userName] = {}
        server.activeRelays[target][port][userName]['client'] = smb
        server.activeRelays[target][port][userName]['inUse'] = False
        server.activeRelays[target][port]['data'] = data


class SocksRequestHandler(SocketServer.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.__socksServer = server
        self.__ip, self.__port = client_address
        self.__connSocket= request
        self.__socksVersion = 5
        self.targetHost = None
        self.targetPort = None
        self.__NBSession= None
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def sendReplyError(self, error = replyField.CONNECTION_REFUSED):

        if self.__socksVersion == 5:
            reply = SOCKS5_REPLY()
            reply['REP'] = error.value
        else:
            reply = SOCKS4_REPLY()
            if error.value != 0:
                reply['REP'] = 0x5B
        return self.__connSocket.send(reply.getData())

    def getNegoAnswer(self, recvPacket):
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

    def processSessionSetup(self, activeRelays, recvPacket, smbData, targetHost):
        respSMBCommand = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        smbCommand = SMBCommand(recvPacket['Data'][0])

        if smbCommand['WordCount'] == 12:
            respParameters = SMBSessionSetupAndX_Extended_Response_Parameters()
            respData = SMBSessionSetupAndX_Extended_Response_Data()

            # First of all, we should received a type 1 message. Let's answer it
            # NEGOTIATE_MESSAGE
            challengeMessage = smbData['CHALLENGE_MESSAGE']
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
            if activeRelays.has_key(authenticateMessage['user_name']):
                LOG.info('SOCKS: Proxying client session for %s@%s(445)' % (
                authenticateMessage['user_name'].decode('utf-16le'), targetHost))
                errorCode = STATUS_SUCCESS
                smbClient = activeRelays[authenticateMessage['user_name']]['client']
                uid = smbClient.get_uid()
            else:
                LOG.error('SOCKS: No session for %s@%s(445) available' % (
                authenticateMessage['user_name'].decode('utf-16le'), targetHost))
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

    def getSMBPacket(self):
        data = self.__NBSession.recv_packet()
        try:
            packet = NewSMBPacket(data=data.get_trailer())
            smbCommand = SMBCommand(packet['Data'][0])
        except Exception, e:
            LOG.error('SOCKS: %s' % str(e))
            return None, None

        return packet, smbCommand

    def getLogOffAnswer(self,recvPacket):
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

    def handle(self):
        LOG.debug("SOCKS: New Connection from %s(%s)" % (self.__ip, self.__port))

        # Let's parse new connections if available
        while activeConnections.empty() is not True:
            target, port, userName, smb, data = activeConnections.get()
            LOG.debug('SOCKS: Adding %s:%s to list of relayConnections' % (target, port))
            if self.__socksServer.activeRelays.has_key(target) is not True:
                self.__socksServer.activeRelays[target] = {}
            if self.__socksServer.activeRelays[target].has_key(port) is not True:
                self.__socksServer.activeRelays[target][port] = {}

            self.__socksServer.activeRelays[target][port][userName] = {}
            self.__socksServer.activeRelays[target][port][userName]['client'] = smb
            self.__socksServer.activeRelays[target][port][userName]['inUse'] = False
            self.__socksServer.activeRelays[target][port]['data'] = data

        # Ok we should have all the updated data now. Let's play

        data = self.__connSocket.recv(8192)
        grettings = SOCKS5_GREETINGS_BACK(data)
        self.__socksVersion = grettings['VER']

        if self.__socksVersion == 5:
            # We need to answer back with a no authentication response. We're not dealing with auth for now
            self.__connSocket.send(str(SOCKS5_GREETINGS_BACK()))
            data = self.__connSocket.recv(8192)
            request = SOCKS5_REQUEST(data)
        else:
            # We're in version 4, we just received the request
            request = SOCKS4_REQUEST(data)

        # Let's process the request to extract the target to connect.
        if self.__socksVersion == 5:
            if request['ATYP'] == ATYP.IPv4.value:
                self.targetHost = socket.inet_ntoa(request['PAYLOAD'][:4])
                self.targetPort = unpack('>H',request['PAYLOAD'][4:])[0]
            else:
                LOG.error('No support for IPv6 yet!')
        else:
            # SOCKS4
            self.targetHost = socket.inet_ntoa(request['ADDR'])
            self.targetPort = request['PORT']

        LOG.debug('SOCKS: Target is %s(%s)' % (self.targetHost, self.targetPort))

        canHandle = False
        if self.targetPort != 53:
            # Do we have an active connection for the target host/port asked?
            # Still don't know the username, but it's a start
            if self.__socksServer.activeRelays.has_key(self.targetHost):
                if self.__socksServer.activeRelays[self.targetHost].has_key(self.targetPort):
                    canHandle = True

            if canHandle is False:
                LOG.error('SOCKS: Don\'t have a relay for %s(%s)' % (self.targetHost, self.targetPort))
                self.sendReplyError(replyField.CONNECTION_REFUSED)
                return

        # Now let's get into the loops
        if self.targetPort == 53:
            # Somebody wanting a DNS request. Should we handle this?
            s = socket.socket()
            try:
                LOG.debug('SOCKS: Connecting to %s(%s)' %(self.targetHost, self.targetPort))
                s.connect((self.targetHost, self.targetPort))
            except Exception, e:
                LOG.error('SOCKS: %s' %str(e))
                self.sendReplyError(replyField.CONNECTION_REFUSED)
                return

            if self.__socksVersion == 5:
                reply = SOCKS5_REPLY()
                reply['REP'] = replyField.SUCCEEDED.value
                addr, port = s.getsockname()
                reply['PAYLOAD'] = socket.inet_aton(addr) + pack('>H', port)
            else:
                reply = SOCKS4_REPLY()

            self.__connSocket.sendall(reply.getData())

            while True:
                try:
                    data = self.__connSocket.recv(8192)
                    if data == '':
                        break
                    s.sendall(data)
                    data = s.recv(8192)
                    self.__connSocket.sendall(data)
                except Exception, e:
                    LOG.error('SOCKS: ', str(e))

        elif self.targetPort == 445:
            # An incoming SMB Connection. Nice
            self.__NBSession = NetBIOSTCPSession('', 'HOST', self.targetHost, sess_port=445, sock=self.__connSocket)
            smbData = self.__socksServer.activeRelays[self.targetHost][self.targetPort]['data']

            # Let's answer back saying we've got the connection. Data is fake
            if self.__socksVersion == 5:
                reply = SOCKS5_REPLY()
                reply['REP'] = replyField.SUCCEEDED.value
                addr, port = self.__connSocket.getsockname()
                reply['PAYLOAD'] = socket.inet_aton(addr) + pack('>H', port)
            else:
                reply = SOCKS4_REPLY()

            self.__connSocket.sendall(reply.getData())

            packet, smbCommand = self.getSMBPacket()

            if packet['Command'] == SMB.SMB_COM_NEGOTIATE:
                # Nego packet, we should answer with supporting only SMBv1
                resp = self.getNegoAnswer(packet)
                self.__NBSession.send_packet(resp.getData())
                packet, smbCommand = self.getSMBPacket()

            if packet['Command'] == SMB.SMB_COM_SESSION_SETUP_ANDX:
                # We have a session setup, let's answer what the original target answered us.
                smbClient, username = self.processSessionSetup(
                    self.__socksServer.activeRelays[self.targetHost][self.targetPort], packet, smbData, self.targetHost)
                if smbClient is None:
                    return

            # Ok, so we have a valid connection to play with. Let's lock it while we use it so the Timer doesn't send a
            # keep alive to this one.
            self.__socksServer.activeRelays[self.targetHost][self.targetPort][username]['inUse'] = True

            # For the rest of the remaining packets, we should just read and send. Except when trying to log out,
            # that's forbidden! ;)
            try:
                while True:
                    # 1. Get Data from client
                    data = self.__NBSession.recv_packet().get_trailer()

                    if len(data) == 0:
                        break

                    packet = NewSMBPacket(data = data)

                    if packet['Command'] == SMB.SMB_COM_LOGOFF_ANDX:
                        # We do NOT want to get logged off do we?
                        LOG.debug('SOCKS: Avoiding logoff for %s@%s:%s' % (username, self.targetHost, self.targetPort))
                        data = self.getLogOffAnswer(packet)
                    else:
                        # 2. Send it to the relayed session
                        smbClient._sess.send_packet(str(data))

                        # 3. Get the target's answer
                        data = smbClient._sess.recv_packet().get_trailer()

                        packet = NewSMBPacket(data = data)

                        if packet['Command'] == SMB.SMB_COM_TRANSACTION or packet['Command'] == SMB.SMB_COM_TRANSACTION2:
                            try:
                                while True:
                                    # Anything else to read? with timeout of 1 sec. This is something to test or find
                                    # a better way to control
                                    data2 = smbClient._sess.recv_packet(timeout = 1).get_trailer()
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
            except Exception, e:
                LOG.debug('SOCKS: %s' % str(e))
                pass

            # Freeing up this connection
            self.__socksServer.activeRelays[self.targetHost][self.targetPort][username]['inUse'] = False
        else:
            LOG.error('SOCKS: I don\'t have a handler for this port')

        LOG.debug('SOCKS: Shuting down connection')
        self.sendReplyError(replyField.CONNECTION_REFUSED)

class SOCKS(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    def __init__(self, server_address=('0.0.0.0', 1080), handler_class=SocksRequestHandler):
        LOG.info('SOCKS proxy started. Listening at port %d', server_address[1] )

        self.activeRelays = {}
        SocketServer.TCPServer.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        # Let's create a timer to keep the connections up.
        t = RepeatedTimer(300.0, keepAliveTimer, self)

if __name__ == '__main__':
    from impacket.examples import logger
    logger.init()
    s = SOCKS()
    s.serve_forever()


