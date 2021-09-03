# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Initial [MS-RCPH] Interface implementation
#
# Author:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#

import re
import binascii
from struct import unpack

from impacket import uuid, ntlm, system_errors, nt_errors, LOG
from impacket.dcerpc.v5.rpcrt import DCERPCException

from impacket.uuid import EMPTY_UUID
from impacket.http import HTTPClientSecurityProvider, AUTH_BASIC
from impacket.structure import Structure
from impacket.dcerpc.v5.rpcrt import MSRPCHeader, \
    MSRPC_RTS, PFC_FIRST_FRAG, PFC_LAST_FRAG

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
                return '%s, code: 0x%x - %s' % (self.error_string, self.error_code, error_msg_short)
            elif key in nt_errors.ERROR_MESSAGES:
                error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
                return '%s, code: 0x%x - %s' % (self.error_string, self.error_code, error_msg_short)
            else:
                return '%s: unknown code: 0x%x' % (self.error_string, self.error_code)
        else:
            return self.error_string

################################################################################
# CONSTANTS
################################################################################

RPC_OVER_HTTP_v1 = 1
RPC_OVER_HTTP_v2 = 2

# Errors which might need handling

# RPCProxyClient internal errors
RPC_PROXY_REMOTE_NAME_NEEDED_ERR = 'Basic authentication in RPC proxy is used, ' \
                                   'so coudn\'t obtain a target NetBIOS name from NTLMSSP to connect.'

# Errors below contain a part of server responses
RPC_PROXY_INVALID_RPC_PORT_ERR = 'Invalid RPC Port'
RPC_PROXY_CONN_A1_0X6BA_ERR    = 'RPC Proxy CONN/A1 request failed, code: 0x6ba'
RPC_PROXY_CONN_A1_404_ERR      = 'CONN/A1 request failed: HTTP/1.1 404 Not Found'
RPC_PROXY_RPC_OUT_DATA_404_ERR = 'RPC_OUT_DATA channel: HTTP/1.1 404 Not Found'
RPC_PROXY_CONN_A1_401_ERR      = 'CONN/A1 request failed: HTTP/1.1 401 Unauthorized'
RPC_PROXY_HTTP_IN_DATA_401_ERR = 'RPC_IN_DATA channel: HTTP/1.1 401 Unauthorized'


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
        ('Cookie','16s=b"\\x00"*16'),
    )

# 2.2.3.2 Client Address
class EncodedClientAddress(Structure):
    structure = (
        ('AddressType','<L=(0 if len(ClientAddress) == 4 else 1)'),
        ('_ClientAddress','_-ClientAddress','4 if AddressType == 0 else 16'),
        ('ClientAddress',':'),
        ('Padding','12s=b"\\x00"*12'),
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

# 2.2.3.5.9 Padding
class Padding(Structure):
    structure = (
        ('CommandType','<L=8'),
        ('ConformanceCount','<L=len(Padding)'),
        ('Padding','*ConformanceCount'),
    )

# 2.2.3.5.10 NegativeANCE
class NegativeANCE(Structure):
    structure = (
        ('CommandType','<L=9'),
    )

# 2.2.3.5.11 ANCE
class ANCE(Structure):
    structure = (
        ('CommandType','<L=0xA'),
    )

# 2.2.3.5.12 ClientAddress
class ClientAddress(Structure):
    structure = (
        ('CommandType','<L=0xB'),
        ('ClientAddress',':',EncodedClientAddress),
    )

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

COMMANDS = {
    0x0: ReceiveWindowSize,
    0x1: FlowControlAck,
    0x2: ConnectionTimeout,
    0x3: Cookie,
    0x4: ChannelLifetime,
    0x5: ClientKeepalive,
    0x6: Version,
    0x7: Empty,
    0x8: Padding,
    0x9: NegativeANCE,
    0xA: ANCE,
    0xB: ClientAddress,
    0xC: AssociationGroupId,
    0xD: Destination,
    0xE: PingTrafficSentNotify,
}

# 2.2.3.6.1 RTS PDU Header
# The RTS PDU Header has the same layout as the common header of
# the connection-oriented RPC PDU as specified in [C706] section 12.6.1,
# with a few additional requirements around the contents of the header fields.
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

# 2.2.4.51 FlowControlAckWithDestination RTS PDU
class FlowControlAckWithDestination_RTS_PDU(Structure):
    structure = (
        ('Destination',':',Destination),
        ('FlowControlAck',':',FlowControlAck),
    )

################################################################################
# HELPERS
################################################################################
def hCONN_A1(virtualConnectionCookie=EMPTY_UUID, outChannelCookie=EMPTY_UUID, receiveWindowSize=262144):
    conn_a1 = CONN_A1_RTS_PDU()
    conn_a1['Version'] = Version()
    conn_a1['VirtualConnectionCookie'] = Cookie()
    conn_a1['VirtualConnectionCookie']['Cookie'] = virtualConnectionCookie
    conn_a1['OutChannelCookie'] = Cookie()
    conn_a1['OutChannelCookie']['Cookie'] = outChannelCookie
    conn_a1['ReceiveWindowSize'] = ReceiveWindowSize()
    conn_a1['ReceiveWindowSize']['ReceiveWindowSize'] = receiveWindowSize

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

def hFlowControlAckWithDestination(destination, bytesReceived, availableWindow, channelCookie):
    rts_pdu = FlowControlAckWithDestination_RTS_PDU()
    rts_pdu['Destination'] = Destination()
    rts_pdu['Destination']['Destination'] = destination
    rts_pdu['FlowControlAck'] = FlowControlAck()
    rts_pdu['FlowControlAck']['Ack'] = Ack()
    rts_pdu['FlowControlAck']['Ack']['BytesReceived'] = bytesReceived
    rts_pdu['FlowControlAck']['Ack']['AvailableWindow'] = availableWindow

    # Cookie of the channel for which the traffic received is being acknowledged
    rts_pdu['FlowControlAck']['Ack']['ChannelCookie'] = RTSCookie()
    rts_pdu['FlowControlAck']['Ack']['ChannelCookie']['Cookie'] = channelCookie

    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_OTHER_CMD
    packet['NumberOfCommands'] = len(rts_pdu.structure)
    packet['pduData'] = rts_pdu.getData()

    return packet.getData()

def hPing():
    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_PING

    return packet.getData()

################################################################################
# CLASSES
################################################################################
class RPCProxyClient(HTTPClientSecurityProvider):
    RECV_SIZE = 8192
    default_headers = {'User-Agent'   : 'MSRPC',
                       'Cache-Control': 'no-cache',
                       'Connection'   : 'Keep-Alive',
                       'Expect'       : '100-continue',
                       'Accept'       : 'application/rpc',
                       'Pragma'       : 'No-cache'
                      }

    def __init__(self, remoteName=None, dstport=593):
        HTTPClientSecurityProvider.__init__(self)
        self.__remoteName  = remoteName
        self.__dstport     = dstport

        # Chosen auth type
        self.__auth_type = None

        self.init_state()

    def init_state(self):
        self.__channels    = {}

        self.__inChannelCookie         = uuid.generate()
        self.__outChannelCookie        = uuid.generate()
        self.__associationGroupId      = uuid.generate()
        self.__virtualConnectionCookie = uuid.generate()

        self.__serverConnectionTimeout = None
        self.__serverReceiveWindowSize = None
        self.__availableWindowAdvertised = 262144 # 256k
        self.__receiverAvailableWindow = self.__availableWindowAdvertised
        self.__bytesReceived = 0

        self.__serverChunked = False
        self.__readBuffer = b''
        self.__chunkLeft = 0

        self.rts_ping_received = False

    def set_proxy_credentials(self, username, password, domain='', lmhash='', nthash=''):
        LOG.error("DeprecationWarning: Call to deprecated method set_proxy_credentials (use set_credentials).")
        self.set_credentials(username, password, domain, lmhash, nthash)

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
        HTTPClientSecurityProvider.set_credentials(self, username, password,
            domain, lmhash, nthash, aesKey, TGT, TGS)

    def create_rpc_in_channel(self):
        headers = self.default_headers.copy()
        headers['Content-Length'] = '1073741824'

        self.create_channel('RPC_IN_DATA', headers)

    def create_rpc_out_channel(self):
        headers = self.default_headers.copy()
        headers['Content-Length'] = '76'

        self.create_channel('RPC_OUT_DATA', headers)

    def create_channel(self, method, headers):
        self.__channels[method] = HTTPClientSecurityProvider.connect(self, self._rpcProxyUrl.scheme,
                                    self._rpcProxyUrl.netloc)

        auth_headers = HTTPClientSecurityProvider.get_auth_headers(self, self.__channels[method],
                           method, self._rpcProxyUrl.path, headers)[0]

        headers_final = {}
        headers_final.update(headers)
        headers_final.update(auth_headers)

        self.__auth_type = HTTPClientSecurityProvider.get_auth_type(self)

        # To connect to an RPC Server, we need to let the RPC Proxy know
        # where to connect. The target RPC Server name and its port are passed
        # in the query of the HTTP request. The target RPC Server must be the ncacn_http
        # service.
        #
        # The utilized format: /rpc/rpcproxy.dll?RemoteName:RemotePort
        #
        # For RDG servers, you can specify localhost:3388, but in other cases you cannot
        # use localhost as there will be no ACL for it.
        #
        # To know what RemoteName to use, we rely on Default ACL. It's specified
        # in the HKLM\SOFTWARE\Microsoft\Rpc\RpcProxy key:
        #
        # ValidPorts    REG_SZ   COMPANYSERVER04:593;COMPANYSERVER04:49152-65535
        #
        # In this way, we can at least connect to the endpoint mapper on port 593.
        # So, if the caller set remoteName to an empty string, we assume the target
        # is the RPC Proxy server itself, and get its NetBIOS name from the NTLMSSP.
        #
        # Interestingly, if the administrator renames the server after RPC Proxy installation
        # or joins the server to the domain after RPC Proxy installation, the ACL will remain
        # the original. So, sometimes the ValidPorts values have the format WIN-JCKEDQVDOQU, and
        # we are not able to use them.
        #
        # For Exchange servers, the value of the default ACL doesn't matter as they
        # allow connections by their own mechanisms:
        # - Exchange 2003 / 2007 / 2010 servers add their own ACL, which includes
        #   NetBIOS names of all Exchange servers (and some other servers).
        #   This ACL is regularly and automatically updated on each server.
        #   Allowed ports: 6001-6004
        #
        #   6001 is used for MS-OXCRPC
        #   6002 is used for MS-OXABREF
        #   6003 is not used
        #   6004 is used for MS-OXNSPI
        #
        #   Tests on Exchange 2010 show that MS-OXNSPI and MS-OXABREF are available
        #   on both 6002 and 6004.
        #
        # - Exchange 2013 / 2016 / 2019 servers process RemoteName on their own
        #   (via RpcProxyShim.dll), and the NetBIOS name format is supported only for
        #   backward compatibility.
        #
        #   ! Default ACL is never used, so there is no way to connect to the endpoint mapper!
        #
        #   Allowed ports: 6001-6004
        #
        #   6001 is used for MS-OXCRPC
        #   6002 is used for MS-OXABREF
        #   6003 is not used
        #   6004 is used for MS-OXNSPI
        #
        # Tests show that all protocols are available on the 6001 / 6002 / 6004 ports via
        # RPC over HTTP v2, and the separation is only used for backward compatibility.
        #
        # The pure ncacn_http endpoint is available only on the 6001 TCP/IP port.
        #
        # RpcProxyShim.dll allows you to skip authentication on the RPC level to get
        # a faster connection, and it makes Exchange 2013 / 2016 / 2019 RPC over HTTP v2
        # endpoints vulnerable to NTLM-Relaying attacks.
        #
        # If the target is Exchange behind Microsoft TMG, you most likely need to specify
        # the remote name manually using the value from /autodiscover/autodiscover.xml.
        # Note that /autodiscover/autodiscover.xml might not be available with
        # a non-outlook User-Agent.
        #
        # There may be multiple RPC Proxy servers with different NetBIOS names on
        # a single external IP. We store the first one's NetBIOS name and use it for all
        # the following channels.
        # It's acceptable to assume all RPC Proxies have the same ACLs (true for Exchange).
        if not self.__remoteName and self.__auth_type == AUTH_BASIC:
            raise RPCProxyClientException(RPC_PROXY_REMOTE_NAME_NEEDED_ERR)

        if not self.__remoteName:
            ntlmssp = self.get_ntlmssp_info()
            self.__remoteName = ntlmssp[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
            self._stringbinding.set_network_address(self.__remoteName)
            LOG.debug('StringBinding has been changed to %s' % self._stringbinding)

        if not self._rpcProxyUrl.query:
            query = self.__remoteName + ':' + str(self.__dstport)
            self._rpcProxyUrl = self._rpcProxyUrl._replace(query=query)

        path = self._rpcProxyUrl.path + '?' + self._rpcProxyUrl.query

        self.__channels[method].request(method, path, headers=headers_final)
        self._read_100_continue(method)

    def _read_100_continue(self, method):
        resp = self.__channels[method].sock.recv(self.RECV_SIZE)

        while resp.find(b'\r\n\r\n') == -1:
            resp += self.__channels[method].sock.recv(self.RECV_SIZE)

        # Continue responses can have multiple lines, for example:
        #
        # HTTP/1.1 100 Continue
        # Via: 1.1 FIREWALL1
        #
        # Don't expect the response to contain "100 Continue\r\n\r\n"
        if resp[9:23] != b'100 Continue\r\n':
            try:
                # The server (IIS) may return localized error messages in
                # the first line. Tests shown they are in UTF-8.
                resp = resp.split(b'\r\n')[0].decode("UTF-8", errors='replace')

                raise RPCProxyClientException('RPC Proxy Client: %s authentication failed in %s channel' %
                    (self.__auth_type, method), proxy_error=resp)
            except (IndexError, KeyError, AttributeError):
                raise RPCProxyClientException('RPC Proxy Client: %s authentication failed in %s channel' %
                    (self.__auth_type, method))

    def create_tunnel(self):
        # 3.2.1.5.3.1 Connection Establishment
        packet = hCONN_A1(self.__virtualConnectionCookie, self.__outChannelCookie, self.__availableWindowAdvertised)
        self.get_socket_out().send(packet)

        packet = hCONN_B1(self.__virtualConnectionCookie, self.__inChannelCookie, self.__associationGroupId)
        self.get_socket_in().send(packet)

        resp = self.get_socket_out().recv(self.RECV_SIZE)

        while resp.find(b'\r\n\r\n') == -1:
            resp += self.get_socket_out().recv(self.RECV_SIZE)

        if resp[9:12] != b'200':
            try:
                # The server (IIS) may return localized error messages in
                # the first line. Tests shown they are in UTF-8.
                resp = resp.split(b'\r\n')[0].decode("UTF-8", errors='replace')

                raise RPCProxyClientException('RPC Proxy CONN/A1 request failed', proxy_error=resp)
            except (IndexError, KeyError, AttributeError):
                raise RPCProxyClientException('RPC Proxy CONN/A1 request failed')

        resp_ascii = resp.decode("ASCII", errors='replace')
        if "transfer-encoding: chunked" in resp_ascii.lower():
            self.__serverChunked = True

        # If the body is here, let's send it to rpc_out_recv1()
        self.__readBuffer = resp[resp.find(b'\r\n\r\n') + 4:]

        # Recieving and parsing CONN/A3
        conn_a3_rpc = self.rpc_out_read_pkt()
        conn_a3_pdu = RTSHeader(conn_a3_rpc)['pduData']
        conn_a3 = CONN_A3_RTS_PDU(conn_a3_pdu)
        self.__serverConnectionTimeout = conn_a3['ConnectionTimeout']['ConnectionTimeout']

        # Recieving and parsing CONN/C2
        conn_c2_rpc = self.rpc_out_read_pkt()
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

    def check_http_error(self, buffer):
        if buffer[:22] == b'HTTP/1.0 503 RPC Error':
            raise RPCProxyClientException('RPC Proxy request failed', proxy_error=buffer)

    def rpc_out_recv1(self, amt=None):
        # Read with at most one underlying system call.
        # The function MUST return the maximum amt bytes.
        #
        # Strictly speaking, it may cause more than one read,
        # but that is ok, since that is to satisfy the chunked protocol.
        sock = self.get_socket_out()

        if self.__serverChunked is False:
            if len(self.__readBuffer) > 0:
                buffer = self.__readBuffer
                self.__readBuffer = b''
            else:
                # Let's read RECV_SIZE bytes and not amt bytes.
                # We would need to check the answer for HTTP errors, as
                # they can just appear in the middle of the stream.
                buffer = sock.recv(self.RECV_SIZE)

            self.check_http_error(buffer)

            if len(buffer) <= amt:
                return buffer

            # We received more than we need
            self.__readBuffer = buffer[amt:]
            return buffer[:amt]

        # Check if the previous chunk is still there
        if self.__chunkLeft > 0:
            # If the previous chunk is still there,
            # just give the caller what we already have
            if amt >= self.__chunkLeft:
                buffer = self.__readBuffer[:self.__chunkLeft]
                # We may have recieved a part of a new chunk
                self.__readBuffer = self.__readBuffer[self.__chunkLeft + 2:]
                self.__chunkLeft = 0

                return buffer
            else:
                buffer = self.__readBuffer[:amt]
                self.__readBuffer = self.__readBuffer[amt:]
                self.__chunkLeft -= amt

                return buffer

        # Let's start to process a new chunk
        buffer = self.__readBuffer
        self.__readBuffer = b''

        self.check_http_error(buffer)

        # Let's receive a chunk size field which ends with CRLF
        # For Microsoft TMG 2010 it can cause more than one read
        while buffer.find(b'\r\n') == -1:
            buffer += sock.recv(self.RECV_SIZE)
            self.check_http_error(buffer)

        chunksize = int(buffer[:buffer.find(b'\r\n')], 16)
        buffer = buffer[buffer.find(b'\r\n') + 2:]

        # Let's read at least our chunk including final CRLF
        while len(buffer) - 2 < chunksize:
            buffer += sock.recv(chunksize - len(buffer) + 2)

        # We should not be using any information from
        # the TCP level to determine HTTP boundaries.
        # So, we may have received more than we need.
        if len(buffer) - 2 > chunksize:
            self.__readBuffer = buffer[chunksize + 2:]
            buffer = buffer[:chunksize + 2]

        # Checking the amt
        if len(buffer) - 2 > amt:
            self.__chunkLeft = chunksize - amt
            # We may have recieved a part of a new chunk before,
            # so the concatenation is crucual
            self.__readBuffer = buffer[amt:] + self.__readBuffer

            return buffer[:amt]
        else:
            # Removing CRLF
            return buffer[:-2]

    def send(self, data, forceWriteAndx=0, forceRecv=0):
        # We don't use chunked encoding for IN channel as
        # Microsoft software is developed this way.
        # If you do this, it may fail.
        self.get_socket_in().send(data)

    def rpc_out_read_pkt(self, handle_rts=False):
        while True:
            response_data = b''

            # Let's receive common RPC header and no more
            #
            # C706
            # 12.4 Common Fields
            # Header encodings differ between connectionless and connection-oriented PDUs.
            # However, certain fields use common sets of values with a consistent
            # interpretation across the two protocols.
            #
            # This MUST recv MSRPCHeader._SIZE bytes, and not MSRPCRespHeader._SIZE bytes!
            #
            while len(response_data) < MSRPCHeader._SIZE:
                response_data += self.rpc_out_recv1(MSRPCHeader._SIZE - len(response_data))

            response_header = MSRPCHeader(response_data)

            # frag_len contains the full length of the packet for both
            # MSRPC and RTS
            frag_len = response_header['frag_len']

            # Receiving the full pkt and no more
            while len(response_data) < frag_len:
               response_data += self.rpc_out_recv1(frag_len - len(response_data))

            # We need to do the Flow Control procedures
            #
            # 3.2.1.1.4
            # This protocol specifies that only RPC PDUs are subject to the flow control abstract data
            # model. RTS PDUs and the HTTP request and response headers are not subject to flow control.
            if response_header['type'] != MSRPC_RTS:
                self.flow_control(frag_len)

            if handle_rts is True and response_header['type'] == MSRPC_RTS:
                self.handle_out_of_sequence_rts(response_data)
            else:
                return response_data

    def recv(self, forceRecv=0, count=0):
        return self.rpc_out_read_pkt(handle_rts=True)

    def handle_out_of_sequence_rts(self, response_data):
        packet = RTSHeader(response_data)

        #print("=========== RTS PKT ===========")
        #print("RAW: %s" % binascii.hexlify(response_data))
        #packet.dump()
        #
        #pduData = packet['pduData']
        #numberOfCommands = packet['NumberOfCommands']
        #
        #server_cmds = []
        #while numberOfCommands > 0:
        #    numberOfCommands -= 1
        #
        #    cmd_type = unpack('<L', pduData[:4])[0]
        #    cmd = COMMANDS[cmd_type](pduData)
        #    server_cmds.append(cmd)
        #    pduData = pduData[len(cmd):]
        #
        #for cmd in server_cmds:
        #    cmd.dump()
        #print("=========== / RTS PKT ===========")

        # 2.2.4.49 Ping RTS PDU
        if packet['Flags'] == RTS_FLAG_PING:
            # 3.2.1.2.1 PingTimer
            #
            # If the SendingChannel is part of a Virtual Connection in the Outbound Proxy or Client roles, the
            # SendingChannel maintains a PingTimer that on expiration indicates a PING PDU must be sent to the
            # receiving channel. The PING PDU is sent to the receiving channel when no data has been sent within
            # half of the value of the KeepAliveInterval.

            # As we do not do long-term connections with no data transfer,
            # it means something on the server-side is going wrong.
            self.rts_ping_received = True
            LOG.error("Ping RTS PDU packet received. Is the RPC Server alive?")

            # Just in case it's a long operation, let's send PING PDU to IN Channel like in xfreerdp
            # It's better to send more than one PING packet as it only 20 bytes long
            packet = hPing()
            self.send(packet)
            self.send(packet)
        # 2.2.4.24 OUT_R1/A2 RTS PDU
        elif packet['Flags'] == RTS_FLAG_RECYCLE_CHANNEL:
            raise RPCProxyClientException("The server requested recycling of a virtual OUT channel, " \
                "but this function is not supported!")
        # Ignore all other messages, most probably flow control acknowledgments
        else:
            pass

    def flow_control(self, frag_len):
        self.__bytesReceived += frag_len
        self.__receiverAvailableWindow -= frag_len

        if (self.__receiverAvailableWindow < self.__availableWindowAdvertised // 2):
            self.__receiverAvailableWindow = self.__availableWindowAdvertised
            packet = hFlowControlAckWithDestination(FDOutProxy, self.__bytesReceived,
                self.__availableWindowAdvertised, self.__outChannelCookie)
            self.send(packet)

    def connect(self):
        self.create_rpc_in_channel()
        self.create_rpc_out_channel()
        self.create_tunnel()

    def disconnect(self):
        self.close_rpc_in_channel()
        self.close_rpc_out_channel()
        self.init_state()
