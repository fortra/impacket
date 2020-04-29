# SECUREAUTH LABS. Copyright 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Initial [MS-RCPH] Interface implementation
#
# Authors:
#  Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#

import re
import ssl
import socket
import base64
import binascii

try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection

from impacket import ntlm, system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException

from impacket import uuid
from impacket.uuid import EMPTY_UUID
from impacket.structure import Structure
from impacket.dcerpc.v5.rpcrt import MSRPCHeader, MSRPC_RTS, PFC_FIRST_FRAG, PFC_LAST_FRAG

class RPCProxyClientException(DCERPCException):
    parser = re.compile(r'RPC Error: ([a-fA-F0-9]{1,8})')

    def __init__(self, error_string=None, proxy_error=None):
        rpc_error_code = None

        if proxy_error is not None:
            try:
                search = self.parser.search(proxy_error)
                rpc_error_code = int(search.group(1), 16)
            except:
                error_string += ': ' + proxy_error

        DCERPCException.__init__(self, error_string, rpc_error_code)

    def __str__(self):
        if self.error_code is not None:
            key = self.error_code
            if key in system_errors.ERROR_MESSAGES:
                error_msg_short = system_errors.ERROR_MESSAGES[key][0]
                return '%s, code: 0x%x - %s ' % (self.error_string, self.error_code, error_msg_short)
            else:
                return '%s: unknown code: 0x%x' % (self.error_string, self.error_code)
        else:
            return self.error_string

################################################################################
# CONSTANTS
################################################################################

RPC_OVER_HTTP_v1 = 1
RPC_OVER_HTTP_v2 = 2

# 2.2.3.3 Forward Destinations
FDClient   = 0x00000000
FDInProxy  = 0x00000001
FDServer   = 0x00000002
FDOutProxy = 0x00000003

RTS_FLAG_NONE            = 0x0000
RTS_FLAG_PING            = 0x0001
RTS_FLAG_OTHER_CMD       = 0x0002
RTS_FLAG_RECYCLE_CHANNEL = 0x0004
RTS_FLAG_IN_CHANNEL      = 0x0008
RTS_FLAG_OUT_CHANNEL     = 0x0010
RTS_FLAG_EOF             = 0x0020
RTS_FLAG_ECHO            = 0x0040

# 2.2.3.5 RTS Commands
RTS_CMD_RECEIVE_WINDOW_SIZE      = 0x00000000
RTS_CMD_FLOW_CONTROL_ACK         = 0x00000001
RTS_CMD_CONNECTION_TIMEOUT       = 0x00000002
RTS_CMD_COOKIE                   = 0x00000003
RTS_CMD_CHANNEL_LIFETIME         = 0x00000004
RTS_CMD_CLIENT_KEEPALIVE         = 0x00000005
RTS_CMD_VERSION                  = 0x00000006
RTS_CMD_EMPTY                    = 0x00000007
RTS_CMD_PADDING                  = 0x00000008
RTS_CMD_NEGATIVE_ANCE            = 0x00000009
RTS_CMD_ANCE                     = 0x0000000A
RTS_CMD_CLIENT_ADDRESS           = 0x0000000B
RTS_CMD_ASSOCIATION_GROUP_ID     = 0x0000000C
RTS_CMD_DESTINATION              = 0x0000000D
RTS_CMD_PING_TRAFFIC_SENT_NOTIFY = 0x0000000E

################################################################################
# STRUCTURES
################################################################################

# 2.2.3.1 RTS Cookie
class RTSCookie(Structure):
    structure = (
        ('Cookie','16s=b"\x00"*16'),
    )

# 2.2.3.4 Flow Control Acknowledgment
class Ack(Structure):
    structure = (
        ('BytesReceived','<L=0'),
        ('AvailableWindow','<L=0'),
        ('ChannelCookie',':',RTSCookie),
    )

# 2.2.3.5.1 ReceiveWindowSize
class ReceiveWindowSize(Structure):
    structure = (
        ('CommandType','<L=0'),
        ('ReceiveWindowSize','<L=262144'),
    )

# 2.2.3.5.2 FlowControlAck
class FlowControlAck(Structure):
    structure = (
        ('CommandType','<L=1'),
        ('Ack',':',Ack),
    )

# 2.2.3.5.3 ConnectionTimeout
class ConnectionTimeout(Structure):
    structure = (
        ('CommandType','<L=2'),
        ('ConnectionTimeout','<L=120000'),
    )

# 2.2.3.5.4 Cookie
class Cookie(Structure):
    structure = (
        ('CommandType','<L=3'),
        ('Cookie',':',RTSCookie),
    )

# 2.2.3.5.5 ChannelLifetime
class ChannelLifetime(Structure):
    structure = (
        ('CommandType','<L=4'),
        ('ChannelLifetime','<L=1073741824'),
    )

# 2.2.3.5.6 ClientKeepalive
#
# By the spec, ClientKeepalive value can be 0 or in the inclusive
# range of 60,000 through 4,294,967,295.
# If it is 0, it MUST be interpreted as 300,000.
#
# But do not set it to 0, it will cause 0x6c0 rpc error.
class ClientKeepalive(Structure):
    structure = (
        ('CommandType','<L=5'),
        ('ClientKeepalive','<L=300000'),
    )

# 2.2.3.5.7 Version
class Version(Structure):
    structure = (
        ('CommandType','<L=6'),
        ('Version','<L=1'),
    )

# 2.2.3.5.8 Empty
class Empty(Structure):
    structure = (
        ('CommandType','<L=7'),
    )

# ...

# 2.2.3.5.13 AssociationGroupId
class AssociationGroupId(Structure):
    structure = (
        ('CommandType','<L=0xC'),
        ('AssociationGroupId',':',RTSCookie),
    )

# 2.2.3.5.14 Destination
class Destination(Structure):
    structure = (
        ('CommandType','<L=0xD'),
        ('Destination','<L'),
    )

# 2.2.3.5.15 PingTrafficSentNotify
class PingTrafficSentNotify(Structure):
    structure = (
        ('CommandType','<L=0xE'),
        ('PingTrafficSent','<L'),
    )

# 2.2.3.6.1 RTS PDU Header
class RTSHeader(MSRPCHeader):
    _SIZE = 20
    commonHdr = MSRPCHeader.commonHdr + (
        ('Flags','<H=0'),             # 16
        ('NumberOfCommands','<H=0'),  # 18
    )

    def __init__(self, data=None, alignment=0):
        MSRPCHeader.__init__(self, data, alignment)
        self['type'] = MSRPC_RTS
        self['flags'] = PFC_FIRST_FRAG | PFC_LAST_FRAG
        self['auth_length'] = 0
        self['call_id'] = 0

# 2.2.4.2 CONN/A1 RTS PDU
#
# The CONN/A1 RTS PDU MUST be sent from the client to the outbound proxy on the OUT channel to
# initiate the establishment of a virtual connection.
class CONN_A1_RTS_PDU(Structure):
    structure = (
        ('Version',':',Version),
        ('VirtualConnectionCookie',':',Cookie),
        ('OutChannelCookie',':',Cookie),
        ('ReceiveWindowSize',':',ReceiveWindowSize),
    )

# 2.2.4.5 CONN/B1 RTS PDU
#
# The CONN/B1 RTS PDU MUST be sent from the client to the inbound proxy on the IN channel to
# initiate the establishment of a virtual connection.
class CONN_B1_RTS_PDU(Structure):
    structure = (
        ('Version',':',Version),
        ('VirtualConnectionCookie',':',Cookie),
        ('INChannelCookie',':',Cookie),
        ('ChannelLifetime',':',ChannelLifetime),
        ('ClientKeepalive',':',ClientKeepalive),
        ('AssociationGroupId',':',AssociationGroupId),
    )

# 2.2.4.4 CONN/A3 RTS PDU
#
# The CONN/A3 RTS PDU MUST be sent from the outbound proxy to the client on the OUT channel to
# continue the establishment of the virtual connection.
class CONN_A3_RTS_PDU(Structure):
    structure = (
        ('ConnectionTimeout',':',ConnectionTimeout),
    )

# 2.2.4.9 CONN/C2 RTS PDU
#
# The CONN/C2 RTS PDU MUST be sent from the outbound proxy to the client on the OUT channel to
# notify it that a virtual connection has been established.
class CONN_C2_RTS_PDU(Structure):
    structure = (
        ('Version',':',Version),
        ('ReceiveWindowSize',':',ReceiveWindowSize),
        ('ConnectionTimeout',':',ConnectionTimeout),
    )

################################################################################
# HELPERS
################################################################################
def hCONN_A1(virtualConnectionCookie=EMPTY_UUID, outChannelCookie=EMPTY_UUID):
    conn_a1 = CONN_A1_RTS_PDU()
    conn_a1['Version'] = Version()
    conn_a1['VirtualConnectionCookie'] = Cookie()
    conn_a1['VirtualConnectionCookie']['Cookie'] = virtualConnectionCookie
    conn_a1['OutChannelCookie'] = Cookie()
    conn_a1['OutChannelCookie']['Cookie'] = outChannelCookie
    conn_a1['ReceiveWindowSize'] = ReceiveWindowSize()

    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_NONE
    packet['NumberOfCommands'] = len(conn_a1.structure)
    packet['pduData'] = conn_a1.getData()

    return packet.getData()

def hCONN_B1(virtualConnectionCookie=EMPTY_UUID, inChannelCookie=EMPTY_UUID, associationGroupId=EMPTY_UUID):
    conn_b1 = CONN_B1_RTS_PDU()
    conn_b1['Version'] = Version()
    conn_b1['VirtualConnectionCookie'] = Cookie()
    conn_b1['VirtualConnectionCookie']['Cookie'] = virtualConnectionCookie
    conn_b1['INChannelCookie'] = Cookie()
    conn_b1['INChannelCookie']['Cookie'] = inChannelCookie
    conn_b1['ChannelLifetime'] = ChannelLifetime()
    conn_b1['ClientKeepalive'] = ClientKeepalive()
    conn_b1['AssociationGroupId'] = AssociationGroupId()
    conn_b1['AssociationGroupId']['AssociationGroupId'] = RTSCookie()
    conn_b1['AssociationGroupId']['AssociationGroupId']['Cookie'] = associationGroupId

    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_NONE
    packet['NumberOfCommands'] = len(conn_b1.structure)
    packet['pduData'] = conn_b1.getData()

    return packet.getData()

################################################################################
# CLASSES
################################################################################

class RPCProxyClient:
    default_headers = {'User-Agent'   : 'MSRPC',
                       'Cache-Control': 'no-cache',
                       'Connection'   : 'Keep-Alive',
                       'Expect'       : '100-continue',
                       'Accept'       : 'application/rpc',
                       'Pragma'       : 'No-cache'
                      }

    def __init__(self, remoteName=None, dstport=593):
        self.__remoteName  = remoteName
        self.__dstport     = dstport
        self.__domain      = ''
        self.__lmhash      = ''
        self.__nthash      = ''
        self.__username    = ''
        self.__password    = ''
        self.__channels    = {}
        self.__ntlmssp_info = None

        self.__inChannelCookie         = uuid.generate()
        self.__outChannelCookie        = uuid.generate()
        self.__associationGroupId      = uuid.generate()
        self.__virtualConnectionCookie = uuid.generate()

        self.__serverChunked = False
        self.__serverReceiveWindowSize = 262144 # 256k

    def set_proxy_credentials(self, username, password, domain='', lmhash='', nthash=''):
        self.__username = username
        self.__password = password
        self.__domain   = domain
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try: # just in case they were converted already
                self.__lmhash = binascii.unhexlify(lmhash)
                self.__nthash = binascii.unhexlify(nthash)
            except:
                self.__lmhash = lmhash
                self.__nthash = nthash
                pass

    def get_ntlmssp_info(self):
        return self.__ntlmssp_info

    def create_rpc_in_channel(self):
        headers = self.default_headers.copy()
        headers['Content-Length'] = '1073741824'

        self.create_channel('RPC_IN_DATA', headers)

    def create_rpc_out_channel(self):
        headers = self.default_headers.copy()
        headers['Content-Length'] = '76'

        self.create_channel('RPC_OUT_DATA', headers)

    def create_channel(self, method, headers):
        if self._rpcProxyUrl.scheme == 'http':
            self.__channels[method] = HTTPConnection(self._rpcProxyUrl.netloc)
        else:
            try:
                uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                self.__channels[method] = HTTPSConnection(self._rpcProxyUrl.netloc, context=uv_context)
            except AttributeError:
                self.__channels[method] = HTTPSConnection(self._rpcProxyUrl.netloc)

        auth = ntlm.getNTLMSSPType1(domain=self.__domain)
        auth_headers = headers.copy()
        auth_headers['Content-Length'] = '0'
        auth_headers['Authorization']  = b'NTLM ' + base64.b64encode(auth.getData())

        self.__channels[method].request(method, self._rpcProxyUrl.path, headers=auth_headers)

        res = self.__channels[method].getresponse()
        res.read()

        if res.status != 401:
            raise RPCProxyClientException('Status code returned: %d. Authentication does not seem required for url %s'
                                  % (res.status, self._rpcProxyUrl.path))

        if res.getheader('WWW-Authenticate') is None:
            raise RPCProxyClientException('No authentication requested by the server for url %s' % self._rpcProxyUrl.path)

        if 'NTLM' not in res.getheader('WWW-Authenticate'):
            raise RPCProxyClientException('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))

        try:
            serverChallengeBase64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
        except (IndexError, KeyError, AttributeError):
            raise RPCProxyClientException('No NTLM challenge returned from server for url %s' % self._rpcProxyUrl.path)

        # Default ACL in HKLM\SOFTWARE\Microsoft\Rpc\ValidPorts allows connections only by NetBIOS name of the server.
        # If remoteName is empty we assume the target is the rpcproxy server, and get its NetBIOS name from NTLMSSP.
        #
        # Interestingly, if Administrator renames the server, the ACL remains the original.
        if not self.__ntlmssp_info:
            challenge = ntlm.NTLMAuthChallenge(serverChallenge)
            self.__ntlmssp_info = ntlm.AV_PAIRS(challenge['TargetInfoFields'])

        if not self.__remoteName:
            self.__remoteName = self.__ntlmssp_info[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
            self._stringbinding.set_network_address(self.__remoteName)

        if not self._rpcProxyUrl.query:
            query = self.__remoteName + ':' + str(self.__dstport)
            self._rpcProxyUrl = self._rpcProxyUrl._replace(query=query)

        type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, serverChallenge, self.__username, self.__password,
                                                             self.__domain, self.__lmhash, self.__nthash)

        headers['Authorization']  = b'NTLM ' + base64.b64encode(type3.getData())

        self.__channels[method].request(method, self._rpcProxyUrl.path + '?' + self._rpcProxyUrl.query, headers=headers)

        auth_resp = self.__channels[method].sock.recv(8192)

        if auth_resp != b'HTTP/1.1 100 Continue\r\n\r\n':
            try:
                auth_resp = auth_resp.split(b'\r\n')[0].decode("utf-8", errors='replace')
                raise RPCProxyClientException('RPC Proxy authentication failed in %s channel' % method, proxy_error=auth_resp)
            except (IndexError, KeyError, AttributeError):
                raise RPCProxyClientException('RPC Proxy authentication failed in %s channel' % method)

    def create_tunnel(self):
        # 3.2.1.5.3.1 Connection Establishment
        packet = hCONN_A1(self.__virtualConnectionCookie, self.__outChannelCookie)
        self.get_socket_out().send(packet)

        packet = hCONN_B1(self.__virtualConnectionCookie, self.__inChannelCookie, self.__associationGroupId)
        self.get_socket_in().send(packet)

        resp = self.get_socket_out().recv(8192)

        if resp[9:12] != b'200':
            try:
                resp = resp.split(b'\r\n')[0].decode("utf-8", errors='replace')
                raise RPCProxyClientException('RPC Proxy CONN/A1 request failed', proxy_error=resp)
            except (IndexError, KeyError, AttributeError):
                raise RPCProxyClientException('RPC Proxy CONN/A1 request failed')

        if b'Transfer-Encoding: chunked' in resp:
            self.__serverChunked = True

        resp_body = resp[resp.find(b'\r\n\r\n') + 4:]

        # Recieving CONN/A3
        if len(resp_body) > 0:
            # CONN/A3 is already received
            pass
        else:
            conn_a3_rpc = self.recv()

        # Recieving and parsing CONN/C2
        conn_c2_rpc = self.recv()
        conn_c2_pdu = RTSHeader(conn_c2_rpc)['pduData']
        conn_c2 = CONN_C2_RTS_PDU(conn_c2_pdu)

        self.__serverReceiveWindowSize = conn_c2['ReceiveWindowSize']['ReceiveWindowSize']

    def get_socket_in(self):
        return self.__channels['RPC_IN_DATA'].sock

    def get_socket_out(self):
        return self.__channels['RPC_OUT_DATA'].sock

    def close_rpc_in_channel(self):
        return self.__channels['RPC_IN_DATA'].close()

    def close_rpc_out_channel(self):
        return self.__channels['RPC_OUT_DATA'].close()

    def rpc_out_recv1(self, amt=None):
        sock = self.get_socket_out()
        buffer = sock.recv(amt)

        if buffer[:22] == b'HTTP/1.0 503 RPC Error':
            raise RPCProxyClientException('RPC Proxy request failed', proxy_error=buffer)

        if self.__serverChunked is False:
            return buffer
        else:
            chunksize = int(buffer[:buffer.find(b'\r\n')], 16)
            buffer = buffer[buffer.find(b'\r\n') + 2:]

            while len(buffer) - 2 < chunksize:
                buffer += sock.recv(chunksize - len(buffer) + 2)

            return buffer[:-2]

    def send(self, data, forceWriteAndx=0, forceRecv=0):
        sock_in = self.get_socket_in()
        offset = 0
        while 1:
            toSend = data[offset:offset+self.__serverReceiveWindowSize]
            if not toSend:
                break
            sock_in.send(toSend)
            offset += len(toSend)

    def recv(self, forceRecv=0, count=0):
        if count:
            buffer = b''
            while len(buffer) < count:
                buffer += self.rpc_out_recv1(count-len(buffer))
        else:
            buffer = self.rpc_out_recv1(8192)

        return buffer

    def connect(self):
        self.create_rpc_in_channel()
        self.create_rpc_out_channel()
        self.create_tunnel()

    def disconnect(self):
        self.close_rpc_in_channel()
        self.close_rpc_out_channel()
