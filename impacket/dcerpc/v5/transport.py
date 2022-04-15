# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Transport implementations for the DCE/RPC protocol.
#
# Author:
#   Alberto Solino (@agsolino)
#
from __future__ import division
from __future__ import print_function

import binascii
import os
import re
import socket

try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

from impacket import ntlm
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC_v5, DCERPC_v4
from impacket.dcerpc.v5.rpch import RPCProxyClient, RPCProxyClientException, RPC_OVER_HTTP_v1, RPC_OVER_HTTP_v2
from impacket.smbconnection import SMBConnection


class DCERPCStringBinding:
    parser = re.compile(r"(?:([a-fA-F0-9-]{8}(?:-[a-fA-F0-9-]{4}){3}-[a-fA-F0-9-]{12})@)?" +  # UUID (opt.)
                        r"([_a-zA-Z0-9]*):" +  # Protocol Sequence
                        r"([^\[]*)" +  # Network Address (opt.)
                        r"(?:\[([^]]*)])?")  # Endpoint and options (opt.)

    def __init__(self, stringbinding):
        match = DCERPCStringBinding.parser.match(stringbinding)
        self.__uuid = match.group(1)
        self.__ps = match.group(2)
        self.__na = match.group(3)
        options = match.group(4)
        if options:
            options = options.split(',')
            
            self.__endpoint = options[0]
            try:
                self.__endpoint.index('endpoint=')
                self.__endpoint = self.__endpoint[len('endpoint='):]
            except:
                pass

            self.__options = {}
            for option in options[1:]:
                vv = option.split('=', 1)
                self.__options[vv[0]] = vv[1] if len(vv) > 1 else ''
        else:
            self.__endpoint = ''
            self.__options = {}

    def get_uuid(self):
        return self.__uuid

    def get_protocol_sequence(self):
        return self.__ps

    def get_network_address(self):
        return self.__na

    def set_network_address(self, addr):
        self.__na = addr

    def get_endpoint(self):
        return self.__endpoint

    def get_options(self):
        return self.__options

    def get_option(self, option_name):
        return self.__options[option_name]

    def is_option_set(self, option_name):
        return option_name in self.__options

    def unset_option(self, option_name):
        del self.__options[option_name]

    def __str__(self):
        return DCERPCStringBindingCompose(self.__uuid, self.__ps, self.__na, self.__endpoint, self.__options)


def DCERPCStringBindingCompose(uuid=None, protocol_sequence='', network_address='', endpoint='', options={}):
    s = ''
    if uuid:
        s += uuid + '@'
    s += protocol_sequence + ':'
    if network_address:
        s += network_address
    if endpoint or options:
        s += '[' + endpoint
        if options:
            s += ',' + ','.join([key if str(val) == '' else "=".join([key, str(val)]) for key, val in options.items()])
        s += ']'

    return s


def DCERPCTransportFactory(stringbinding):
    sb = DCERPCStringBinding(stringbinding)

    na = sb.get_network_address()
    ps = sb.get_protocol_sequence()
    if 'ncadg_ip_udp' == ps:
        port = sb.get_endpoint()
        if port:
            rpctransport = UDPTransport(na, int(port))
        else:
            rpctransport = UDPTransport(na)
    elif 'ncacn_ip_tcp' == ps:
        port = sb.get_endpoint()
        if port:
            rpctransport = TCPTransport(na, int(port))
        else:
            rpctransport = TCPTransport(na)
    elif 'ncacn_http' == ps:
        port = sb.get_endpoint()
        if port:
            rpctransport = HTTPTransport(na, int(port))
        else:
            rpctransport = HTTPTransport(na)
    elif 'ncacn_np' == ps:
        named_pipe = sb.get_endpoint()
        if named_pipe:
            named_pipe = named_pipe[len(r'\pipe'):]
            rpctransport = SMBTransport(na, filename = named_pipe)
        else:
            rpctransport = SMBTransport(na)
    elif 'ncalocal' == ps:
        named_pipe = sb.get_endpoint()
        rpctransport = LOCALTransport(filename = named_pipe)
    else:
        raise DCERPCException("Unknown protocol sequence.")

    rpctransport.set_stringbinding(sb)
    return rpctransport

class DCERPCTransport:

    DCERPC_class = DCERPC_v5

    def __init__(self, remoteName, dstport):
        self.__remoteName = remoteName
        self.__remoteHost = remoteName
        self.__dstport = dstport
        self._stringbinding = None
        self._max_send_frag = None
        self._max_recv_frag = None
        self._domain = ''
        self._lmhash = ''
        self._nthash = ''
        self.__connect_timeout = None
        self._doKerberos = False
        self._username = ''
        self._password = ''
        self._domain   = ''
        self._aesKey   = None
        self._TGT      = None
        self._TGS      = None
        self._kdcHost  = None
        self.set_credentials('','')
        # Strict host validation - off by default and currently only for
        # SMBTransport
        self._strict_hostname_validation = False
        self._validation_allow_absent = True
        self._accepted_hostname = ''

    def connect(self):
        raise RuntimeError('virtual function')
    def send(self,data=0, forceWriteAndx = 0, forceRecv = 0):
        raise RuntimeError('virtual function')
    def recv(self, forceRecv = 0, count = 0):
        raise RuntimeError('virtual function')
    def disconnect(self):
        raise RuntimeError('virtual function')
    def get_socket(self):
        raise RuntimeError('virtual function')

    def get_connect_timeout(self):
        return self.__connect_timeout
    def set_connect_timeout(self, timeout):
        self.__connect_timeout = timeout

    def getRemoteName(self):
        return self.__remoteName

    def setRemoteName(self, remoteName):
        """This method only makes sense before connection for most protocols."""
        self.__remoteName = remoteName

    def getRemoteHost(self):
        return self.__remoteHost

    def setRemoteHost(self, remoteHost):
        """This method only makes sense before connection for most protocols."""
        self.__remoteHost = remoteHost

    def get_dport(self):
        return self.__dstport
    def set_dport(self, dport):
        """This method only makes sense before connection for most protocols."""
        self.__dstport = dport

    def get_stringbinding(self):
        return self._stringbinding

    def set_stringbinding(self, stringbinding):
        self._stringbinding = stringbinding

    def get_addr(self):
        return self.getRemoteHost(), self.get_dport()
    def set_addr(self, addr):
        """This method only makes sense before connection for most protocols."""
        self.setRemoteHost(addr[0])
        self.set_dport(addr[1])

    def set_kerberos(self, flag, kdcHost = None):
        self._doKerberos = flag
        self._kdcHost = kdcHost

    def get_kerberos(self):
        return self._doKerberos

    def get_kdcHost(self):
        return self._kdcHost

    def set_max_fragment_size(self, send_fragment_size):
        # -1 is default fragment size: 0 (don't fragment)
        #  0 is don't fragment
        #    other values are max fragment size
        if send_fragment_size == -1:
            self.set_default_max_fragment_size()
        else:
            self._max_send_frag = send_fragment_size

    def set_hostname_validation(self, validate, accept_empty, hostname):
        self._strict_hostname_validation = validate
        self._validation_allow_absent = accept_empty
        self._accepted_hostname = hostname

    def set_default_max_fragment_size(self):
        # default is 0: don't fragment.
        # subclasses may override this method
        self._max_send_frag = 0

    def get_credentials(self):
        return (
            self._username,
            self._password,
            self._domain,
            self._lmhash,
            self._nthash,
            self._aesKey,
            self._TGT,
            self._TGS)

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
        self._username = username
        self._password = password
        self._domain   = domain
        self._aesKey   = aesKey
        self._TGT      = TGT
        self._TGS      = TGS
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try: # just in case they were converted already
               self._lmhash = binascii.unhexlify(lmhash)
               self._nthash = binascii.unhexlify(nthash)
            except:
               self._lmhash = lmhash
               self._nthash = nthash
               pass

    def doesSupportNTLMv2(self):
        # By default we'll be returning the library's default. Only on SMB Transports we might be able to know it beforehand
        return ntlm.USE_NTLMv2

    def get_dce_rpc(self):
        return DCERPC_v5(self)

class UDPTransport(DCERPCTransport):
    "Implementation of ncadg_ip_udp protocol sequence"

    DCERPC_class = DCERPC_v4

    def __init__(self, remoteName, dstport = 135):
        DCERPCTransport.__init__(self, remoteName, dstport)
        self.__socket = 0
        self.set_connect_timeout(30)
        self.__recv_addr = ''

    def connect(self):
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(self.getRemoteHost(), self.get_dport(), 0, socket.SOCK_DGRAM)[0]
            self.__socket = socket.socket(af, socktype, proto)
            self.__socket.settimeout(self.get_connect_timeout())
        except socket.error as msg:
            self.__socket = None
            raise DCERPCException("Could not connect: %s" % msg)

        return 1

    def disconnect(self):
        try:
            self.__socket.close()
        except socket.error:
            self.__socket = None
            return 0
        return 1

    def send(self,data, forceWriteAndx = 0, forceRecv = 0):
        self.__socket.sendto(data, (self.getRemoteHost(), self.get_dport()))

    def recv(self, forceRecv = 0, count = 0):
        buffer, self.__recv_addr = self.__socket.recvfrom(8192)
        return buffer

    def get_recv_addr(self):
        return self.__recv_addr

    def get_socket(self):
        return self.__socket

class TCPTransport(DCERPCTransport):
    """Implementation of ncacn_ip_tcp protocol sequence"""

    def __init__(self, remoteName, dstport = 135):
        DCERPCTransport.__init__(self, remoteName, dstport)
        self.__socket = 0
        self.set_connect_timeout(30)

    def connect(self):
        af, socktype, proto, canonname, sa = socket.getaddrinfo(self.getRemoteHost(), self.get_dport(), 0, socket.SOCK_STREAM)[0]
        self.__socket = socket.socket(af, socktype, proto)
        try:
            self.__socket.settimeout(self.get_connect_timeout())
            self.__socket.connect(sa)
        except socket.error as msg:
            self.__socket.close()
            raise DCERPCException("Could not connect: %s" % msg)
        return 1

    def disconnect(self):
        try:
            self.__socket.close()
        except socket.error:
            self.__socket = None
            return 0
        return 1

    def send(self,data, forceWriteAndx = 0, forceRecv = 0):
        if self._max_send_frag:
            offset = 0
            while 1:
                toSend = data[offset:offset+self._max_send_frag]
                if not toSend:
                    break
                self.__socket.send(toSend)
                offset += len(toSend)
        else:
            self.__socket.send(data)

    def recv(self, forceRecv = 0, count = 0):
        if count:
            buffer = b''
            while len(buffer) < count:
               buffer += self.__socket.recv(count-len(buffer))
        else:
            buffer = self.__socket.recv(8192)
        return buffer

    def get_socket(self):
        return self.__socket

class HTTPTransport(TCPTransport, RPCProxyClient):
    """Implementation of ncacn_http protocol sequence"""

    def __init__(self, remoteName=None, dstport=593):
        self._useRpcProxy = False
        self._rpcProxyUrl = None
        self._transport   = TCPTransport
        self._version     = RPC_OVER_HTTP_v2

        DCERPCTransport.__init__(self, remoteName, dstport)
        RPCProxyClient.__init__(self, remoteName, dstport)
        self.set_connect_timeout(30)

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
        return self._transport.set_credentials(self, username, password,
            domain, lmhash, nthash, aesKey, TGT, TGS)

    def rpc_proxy_init(self):
        self._useRpcProxy = True
        self._transport   = RPCProxyClient

    def set_rpc_proxy_url(self, url):
        self.rpc_proxy_init()
        self._rpcProxyUrl = urlparse(url)

    def get_rpc_proxy_url(self):
        return urlunparse(self._rpcProxyUrl)

    def set_stringbinding(self, set_stringbinding):
        DCERPCTransport.set_stringbinding(self, set_stringbinding)

        if self._stringbinding.is_option_set("RpcProxy"):
            self.rpc_proxy_init()

            rpcproxy = self._stringbinding.get_option("RpcProxy").split(":")

            if rpcproxy[1] == '443':
                self.set_rpc_proxy_url('https://%s/rpc/rpcproxy.dll' % rpcproxy[0])
            elif rpcproxy[1] == '80':
                self.set_rpc_proxy_url('http://%s/rpc/rpcproxy.dll' % rpcproxy[0])
            else:
                # 2.1.2.1
                # RPC over HTTP always uses port 80 for HTTP traffic and port 443 for HTTPS traffic.
                # But you can use set_rpc_proxy_url method to set any URL / query you want.
                raise DCERPCException("RPC Proxy port must be 80 or 443")

    def connect(self):
        if self._useRpcProxy == False:
            # Connecting directly to the ncacn_http port
            #
            # Here we using RPC over HTTPv1 instead complex RPC over HTTP v2 syntax
            # RPC over HTTP v2 here can be implemented in the future
            self._version = RPC_OVER_HTTP_v1

            TCPTransport.connect(self)

            # Reading legacy server response
            data = self.get_socket().recv(8192)

            if data != b'ncacn_http/1.0':
                raise DCERPCException("%s:%s service is not ncacn_http" % (self.__remoteName, self.__dstport))
        else:
            RPCProxyClient.connect(self)

    def send(self, data, forceWriteAndx=0, forceRecv=0):
        return self._transport.send(self, data, forceWriteAndx, forceRecv)

    def recv(self, forceRecv=0, count=0):
        return self._transport.recv(self, forceRecv, count)

    def get_socket(self):
        if self._useRpcProxy == False:
            return TCPTransport.get_socket(self)
        else:
            raise DCERPCException("This method is not supported for RPC Proxy connections")

    def disconnect(self):
        return self._transport.disconnect(self)

class SMBTransport(DCERPCTransport):
    """Implementation of ncacn_np protocol sequence"""

    def __init__(self, remoteName, dstport=445, filename='', username='', password='', domain='', lmhash='', nthash='',
                 aesKey='', TGT=None, TGS=None, remote_host='', smb_connection=0, doKerberos=False, kdcHost=None):
        DCERPCTransport.__init__(self, remoteName, dstport)
        self.__socket = None
        self.__tid = 0
        self.__filename = filename
        self.__handle = 0
        self.__pending_recv = 0
        self.set_credentials(username, password, domain, lmhash, nthash, aesKey, TGT, TGS)
        self._doKerberos = doKerberos
        self._kdcHost = kdcHost

        if remote_host != '':
            self.setRemoteHost(remote_host)

        if smb_connection == 0:
            self.__existing_smb = False
        else:
            self.__existing_smb = True
            self.set_credentials(*smb_connection.getCredentials())

        self.__prefDialect = None
        self.__smb_connection = smb_connection
        self.set_connect_timeout(30)

    def preferred_dialect(self, dialect):
        self.__prefDialect = dialect

    def setup_smb_connection(self):
        if not self.__smb_connection:
            self.__smb_connection = SMBConnection(self.getRemoteName(), self.getRemoteHost(), sess_port=self.get_dport(),
                                                  preferredDialect=self.__prefDialect, timeout=self.get_connect_timeout())
            if self._strict_hostname_validation:
                self.__smb_connection.setHostnameValidation(self._strict_hostname_validation, self._validation_allow_absent, self._accepted_hostname)

    def connect(self):
        # Check if we have a smb connection already setup
        if self.__smb_connection == 0:
            self.setup_smb_connection()
            if self._doKerberos is False:
                self.__smb_connection.login(self._username, self._password, self._domain, self._lmhash, self._nthash)
            else:
                self.__smb_connection.kerberosLogin(self._username, self._password, self._domain, self._lmhash,
                                                    self._nthash, self._aesKey, kdcHost=self._kdcHost, TGT=self._TGT,
                                                    TGS=self._TGS)
        self.__tid = self.__smb_connection.connectTree('IPC$')
        self.__handle = self.__smb_connection.openFile(self.__tid, self.__filename)
        self.__socket = self.__smb_connection.getSMBServer().get_socket()
        return 1

    def disconnect(self):
        self.__smb_connection.disconnectTree(self.__tid)
        # If we created the SMB connection, we close it, otherwise
        # that's up for the caller
        if self.__existing_smb is False:
            self.__smb_connection.logoff()
            self.__smb_connection.close()
            self.__smb_connection = 0

    def send(self,data, forceWriteAndx = 0, forceRecv = 0):
        if self._max_send_frag:
            offset = 0
            while 1:
                toSend = data[offset:offset+self._max_send_frag]
                if not toSend:
                    break
                self.__smb_connection.writeFile(self.__tid, self.__handle, toSend, offset = offset)
                offset += len(toSend)
        else:
            self.__smb_connection.writeFile(self.__tid, self.__handle, data)
        if forceRecv:
            self.__pending_recv += 1

    def recv(self, forceRecv = 0, count = 0 ):
        if self._max_send_frag or self.__pending_recv:
            # _max_send_frag is checked because it's the same condition we checked
            # to decide whether to use write_andx() or send_trans() in send() above.
            if self.__pending_recv:
                self.__pending_recv -= 1
            return self.__smb_connection.readFile(self.__tid, self.__handle, bytesToRead = self._max_recv_frag)
        else:
            return self.__smb_connection.readFile(self.__tid, self.__handle)

    def get_smb_connection(self):
        return self.__smb_connection

    def set_smb_connection(self, smb_connection):
        self.__smb_connection = smb_connection
        self.set_credentials(*smb_connection.getCredentials())
        self.__existing_smb = True

    def get_smb_server(self):
        # Raw Access to the SMBServer (whatever type it is)
        return self.__smb_connection.getSMBServer()

    def get_socket(self):
        return self.__socket

    def doesSupportNTLMv2(self):
        return self.__smb_connection.doesSupportNTLMv2()

class LOCALTransport(DCERPCTransport):
    """
    Implementation of ncalocal protocol sequence, not the same
    as ncalrpc (I'm not doing LPC just opening the local pipe)
    """

    def __init__(self, filename = ''):
        DCERPCTransport.__init__(self, '', 0)
        self.__filename = filename
        self.__handle = 0

    def connect(self):
        if self.__filename.upper().find('PIPE') < 0:
            self.__filename = '\\PIPE\\%s' % self.__filename
        self.__handle = os.open('\\\\.\\%s' % self.__filename, os.O_RDWR|os.O_BINARY)
        return 1

    def disconnect(self):
        os.close(self.__handle)

    def send(self,data, forceWriteAndx = 0, forceRecv = 0):
        os.write(self.__handle, data)

    def recv(self, forceRecv = 0, count = 0 ):
        data = os.read(self.__handle, 65535)
        return data
