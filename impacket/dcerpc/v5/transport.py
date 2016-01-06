# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   Transport implementations for the DCE/RPC protocol.
#

import re
import socket
import binascii
import os

from impacket.smbconnection import smb, SMBConnection
from impacket import nmb
from impacket import ntlm
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC_v5, DCERPC_v4


class DCERPCStringBinding:
    parser = re.compile(r'(?:([a-fA-F0-9-]{8}(?:-[a-fA-F0-9-]{4}){3}-[a-fA-F0-9-]{12})@)?' # UUID (opt.)
                        +'([_a-zA-Z0-9]*):' # Protocol Sequence
                        +'([^\[]*)' # Network Address (opt.)
                        +'(?:\[([^\]]*)\])?') # Endpoint and options (opt.)

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
            self.__options = options[1:]
        else:
            self.__endpoint = ''
            self.__options = []

    def get_uuid(self):
        return self.__uuid

    def get_protocol_sequence(self):
        return self.__ps

    def get_network_address(self):
        return self.__na

    def get_endpoint(self):
        return self.__endpoint

    def get_options(self):
        return self.__options

    def __str__(self):
        return DCERPCStringBindingCompose(self.__uuid, self.__ps, self.__na, self.__endpoint, self.__options)

def DCERPCStringBindingCompose(uuid=None, protocol_sequence='', network_address='', endpoint='', options=[]):
    s = ''
    if uuid: s += uuid + '@'
    s += protocol_sequence + ':'
    if network_address: s += network_address
    if endpoint or options:
        s += '[' + endpoint
        if options: s += ',' + ','.join(options)
        s += ']'

    return s

def DCERPCTransportFactory(stringbinding):
    sb = DCERPCStringBinding(stringbinding)

    na = sb.get_network_address()
    ps = sb.get_protocol_sequence()
    if 'ncadg_ip_udp' == ps:
        port = sb.get_endpoint()
        if port:
            return UDPTransport(na, int(port))
        else:
            return UDPTransport(na)
    elif 'ncacn_ip_tcp' == ps:
        port = sb.get_endpoint()
        if port:
            return TCPTransport(na, int(port))
        else:
            return TCPTransport(na)
    elif 'ncacn_http' == ps:
        port = sb.get_endpoint()
        if port:
            return HTTPTransport(na, int(port))
        else:
            return HTTPTransport(na)
    elif 'ncacn_np' == ps:
        named_pipe = sb.get_endpoint()
        if named_pipe:
            named_pipe = named_pipe[len(r'\pipe'):]
            return SMBTransport(na, filename = named_pipe)
        else:
            return SMBTransport(na)
    elif 'ncalocal' == ps:
        named_pipe = sb.get_endpoint()
        return LOCALTransport(filename = named_pipe)
    else:
        raise DCERPCException("Unknown protocol sequence.")


class DCERPCTransport:

    DCERPC_class = DCERPC_v5

    def __init__(self, dstip, dstport):
        self.__dstip = dstip
        self.__dstport = dstport
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
        self.set_credentials('','')

    def connect(self):
        raise RuntimeError, 'virtual function'
    def send(self,data=0, forceWriteAndx = 0, forceRecv = 0):
        raise RuntimeError, 'virtual function'
    def recv(self, forceRecv = 0, count = 0):
        raise RuntimeError, 'virtual function'
    def disconnect(self):
        raise RuntimeError, 'virtual function'
    def get_socket(self):
        raise RuntimeError, 'virtual function'

    def get_connect_timeout(self):
        return self.__connect_timeout
    def set_connect_timeout(self, timeout):
        self.__connect_timeout = timeout

    def get_dip(self):
        return self.__dstip
    def set_dip(self, dip):
        """This method only makes sense before connection for most protocols."""
        self.__dstip = dip

    def get_dport(self):
        return self.__dstport
    def set_dport(self, dport):
        """This method only makes sense before connection for most protocols."""
        self.__dstport = dport

    def get_addr(self):
        return self.get_dip(), self.get_dport()
    def set_addr(self, addr):
        """This method only makes sense before connection for most protocols."""
        self.set_dip(addr[0])
        self.set_dport(addr[1])

    def set_kerberos(self, flag):
        self._doKerberos = flag

    def get_kerberos(self):
        return self._doKerberos

    def set_max_fragment_size(self, send_fragment_size):
        # -1 is default fragment size: 0 (don't fragment)
        #  0 is don't fragment
        #    other values are max fragment size
        if send_fragment_size == -1:
            self.set_default_max_fragment_size()
        else:
            self._max_send_frag = send_fragment_size

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
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try: # just in case they were converted already
               self._lmhash = binascii.unhexlify(lmhash)
               self._nthash = binascii.unhexlify(nthash)
            except:
               self._lmhash = lmhash
               self._nthash = nthash
               pass

    def doesSupportNTLMv2(self):
        # By default we'll be returning the library's deafult. Only on SMB Transports we might be able to know it beforehand
        return ntlm.USE_NTLMv2

    def get_dce_rpc(self):
        return DCERPC_v5(self)

class UDPTransport(DCERPCTransport):
    "Implementation of ncadg_ip_udp protocol sequence"

    DCERPC_class = DCERPC_v4

    def __init__(self,dstip, dstport = 135):
        DCERPCTransport.__init__(self, dstip, dstport)
        self.__socket = 0
        self.set_connect_timeout(30)
        self.__recv_addr = ''

    def connect(self):
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(self.get_dip(), self.get_dport(), 0, socket.SOCK_DGRAM)[0]
            self.__socket = socket.socket(af, socktype, proto)
            self.__socket.settimeout(self.get_connect_timeout())
        except socket.error, msg:
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
        self.__socket.sendto(data,(self.get_dip(),self.get_dport()))

    def recv(self, forceRecv = 0, count = 0):
        buffer, self.__recv_addr = self.__socket.recvfrom(8192)
        return buffer

    def get_recv_addr(self):
        return self.__recv_addr

    def get_socket(self):
        return self.__socket

class TCPTransport(DCERPCTransport):
    """Implementation of ncacn_ip_tcp protocol sequence"""

    def __init__(self, dstip, dstport = 135):
        DCERPCTransport.__init__(self, dstip, dstport)
        self.__socket = 0
        self.set_connect_timeout(30)

    def connect(self):
        af, socktype, proto, canonname, sa = socket.getaddrinfo(self.get_dip(), self.get_dport(), 0, socket.SOCK_STREAM)[0]
        self.__socket = socket.socket(af, socktype, proto)
        try:
            self.__socket.settimeout(self.get_connect_timeout())
            self.__socket.connect((self.get_dip(), self.get_dport()))
        except socket.error, msg:
            self.__socket.close()
            raise DCERPCException("Could not connect: %s" % msg)
        return 1

    def disconnect(self):
        try:
            self.__socket.close()
        except socket.error, msg:
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
            buffer = ''
            while len(buffer) < count:
               buffer += self.__socket.recv(count-len(buffer))
        else:
            buffer = self.__socket.recv(8192)
        return buffer

    def get_socket(self):
        return self.__socket

class HTTPTransport(TCPTransport):
    """Implementation of ncacn_http protocol sequence"""

    def connect(self):
        TCPTransport.connect(self)

        self.get_socket().send('RPC_CONNECT ' + self.get_dip() + ':593 HTTP/1.0\r\n\r\n')
        data = self.get_socket().recv(8192)
        if data[10:13] != '200':
            raise DCERPCException("Service not supported.")

class SMBTransport(DCERPCTransport):
    """Implementation of ncacn_np protocol sequence"""

    def __init__(self, dstip, dstport=445, filename='', username='', password='', domain='', lmhash='', nthash='',
                 aesKey='', TGT=None, TGS=None, remote_name='', smb_connection=0, doKerberos=False):
        DCERPCTransport.__init__(self, dstip, dstport)
        self.__socket = None
        self.__tid = 0
        self.__filename = filename
        self.__handle = 0
        self.__pending_recv = 0
        self.set_credentials(username, password, domain, lmhash, nthash, aesKey, TGT, TGS)
        self.__remote_name = remote_name
        self._doKerberos = doKerberos

        if smb_connection == 0:
            self.__existing_smb = False
        else:
            self.__existing_smb = True
            self.set_credentials(*smb_connection.getCredentials())

        self.__prefDialect = None

        if isinstance(smb_connection, smb.SMB):
            # Backward compatibility hack, let's return a
            # SMBBackwardCompatibilityTransport instance
            return SMBBackwardCompatibilityTransport(filename = filename, smb_server = smb_connection)
        else:
            self.__smb_connection = smb_connection

    def preferred_dialect(self, dialect):
        self.__prefDialect = dialect

    def setup_smb_connection(self):
        if not self.__smb_connection:
            if self.__remote_name == '':
                if self.get_dport() == nmb.NETBIOS_SESSION_PORT:
                    self.__smb_connection = SMBConnection('*SMBSERVER', self.get_dip(), sess_port = self.get_dport(),preferredDialect = self.__prefDialect)
                else:
                    self.__smb_connection = SMBConnection(self.get_dip(), self.get_dip(), sess_port = self.get_dport(),preferredDialect = self.__prefDialect)
            else:
                self.__smb_connection = SMBConnection(self.__remote_name, self.get_dip(), sess_port = self.get_dport(),preferredDialect = self.__prefDialect)

    def connect(self):
        # Check if we have a smb connection already setup
        if self.__smb_connection == 0:
           self.setup_smb_connection()
           if self._doKerberos is False:
               self.__smb_connection.login(self._username, self._password, self._domain, self._lmhash, self._nthash)
           else:
               self.__smb_connection.kerberosLogin(self._username, self._password, self._domain, self._lmhash, self._nthash, self._aesKey, TGT=self._TGT, TGS=self._TGS)
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
