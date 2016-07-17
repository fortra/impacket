# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#


# -*- mode: python; tab-width: 4 -*-
#
# Copyright (C) 2001 Michael Teo <michaelteo@bigfoot.com>
# nmb.py - NetBIOS library
#
# This software is provided 'as-is', without any express or implied warranty. 
# In no event will the author be held liable for any damages arising from the 
# use of this software.
#
# Permission is granted to anyone to use this software for any purpose, 
# including commercial applications, and to alter it and redistribute it 
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not 
#    claim that you wrote the original software. If you use this software 
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
# 2. Altered source versions must be plainly marked as such, and must not be 
#    misrepresented as being the original software.
#
# 3. This notice cannot be removed or altered from any source distribution.
#
# Altered source done by Alberto Solino (@agsolino)

import errno
import re
import select
import socket
import string
import time
from random import randint
from struct import pack, unpack

from structure import Structure

################################################################################
# CONSTANTS
################################################################################
# Taken from socket module reference
INADDR_ANY = '0.0.0.0'
BROADCAST_ADDR = '<broadcast>'

# Default port for NetBIOS name service
NETBIOS_NS_PORT = 137
# Default port for NetBIOS session service
NETBIOS_SESSION_PORT = 139

# Default port for SMB session service
SMB_SESSION_PORT = 445

# Owner Node Type Constants
NODE_B = 0x0000
NODE_P = 0x2000
NODE_M = 0x4000
NODE_RESERVED = 0x6000
NODE_GROUP = 0x8000
NODE_UNIQUE = 0x0

# Name Type Constants
TYPE_UNKNOWN = 0x01
TYPE_WORKSTATION = 0x00
TYPE_CLIENT = 0x03
TYPE_SERVER = 0x20
TYPE_DOMAIN_MASTER = 0x1B
TYPE_DOMAIN_CONTROLLER = 0x1C
TYPE_MASTER_BROWSER = 0x1D
TYPE_BROWSER = 0x1E
TYPE_NETDDE  = 0x1F
TYPE_STATUS = 0x21

# Opcodes values
OPCODE_QUERY = 0
OPCODE_REGISTRATION = 0x5 << 11
OPCODE_RELEASE = 0x6 << 11
OPCODE_WACK = 0x7 << 11
OPCODE_REFRESH = 0x8 << 11
OPCODE_REQUEST = 0 << 11
OPCODE_RESPONSE = 0x10 << 11

# NM_FLAGS
NM_FLAGS_BROADCAST = 0x1 << 4
NM_FLAGS_UNICAST = 0 << 4
NM_FLAGS_RA = 0x8 << 4
NM_FLAGS_RD = 0x10 << 4
NM_FLAGS_TC = 0x20 << 4
NM_FLAGS_AA = 0x40 << 4

# QUESTION_TYPE
QUESTION_TYPE_NB = 0x20     # NetBIOS general Name Service Resource Record
QUESTION_TYPE_NBSTAT = 0x21 # NetBIOS NODE STATUS Resource Record
# QUESTION_CLASS
QUESTION_CLASS_IN = 0x1     # Internet class

# RESOURCE RECORD RR_TYPE field definitions
RR_TYPE_A = 0x1             # IP address Resource Record
RR_TYPE_NS = 0x2            # Name Server Resource Record
RR_TYPE_NULL = 0xA          # NULL Resource Record
RR_TYPE_NB = 0x20           # NetBIOS general Name Service Resource Record
RR_TYPE_NBSTAT = 0x21       # NetBIOS NODE STATUS Resource Record

# RESOURCE RECORD RR_CLASS field definitions
RR_CLASS_IN = 1             # Internet class

# RCODE values
RCODE_FMT_ERR   = 0x1       # Format Error.  Request was invalidly formatted.
RCODE_SRV_ERR   = 0x2       # Server failure.  Problem with NBNS, cannot process name.
RCODE_IMP_ERR   = 0x4       # Unsupported request error.  Allowable only for challenging NBNS when gets an Update type
                            # registration request.
RCODE_RFS_ERR   = 0x5       # Refused error.  For policy reasons server will not register this name from this host.
RCODE_ACT_ERR   = 0x6       # Active error.  Name is owned by another node.
RCODE_CFT_ERR   = 0x7       # Name in conflict error.  A UNIQUE name is owned by more than one node.

# NAME_FLAGS
NAME_FLAGS_PRM = 0x0200       # Permanent Name Flag.  If one (1) then entry is for the permanent node name.  Flag is zero
                              # (0) for all other names.
NAME_FLAGS_ACT = 0x0400       # Active Name Flag.  All entries have this flag set to one (1).
NAME_FLAG_CNF  = 0x0800       # Conflict Flag.  If one (1) then name on this node is in conflict.
NAME_FLAG_DRG  = 0x1000       # Deregister Flag.  If one (1) then this name is in the process of being deleted.

# NB_FLAGS
NB_FLAGS_ONT_B = 0
NB_FLAGS_ONT_P = 1 << 13
NB_FLAGS_ONT_M = 2 << 13
NB_FLAGS_G     = 1 << 15

NAME_TYPES = {TYPE_UNKNOWN: 'Unknown', TYPE_WORKSTATION: 'Workstation', TYPE_CLIENT: 'Client',
              TYPE_SERVER: 'Server', TYPE_DOMAIN_MASTER: 'Domain Master', TYPE_DOMAIN_CONTROLLER: 'Domain Controller',
              TYPE_MASTER_BROWSER: 'Master Browser', TYPE_BROWSER: 'Browser Server', TYPE_NETDDE: 'NetDDE Server',
              TYPE_STATUS: 'Status'}

# NetBIOS Session Types
NETBIOS_SESSION_MESSAGE = 0x0
NETBIOS_SESSION_REQUEST = 0x81
NETBIOS_SESSION_POSITIVE_RESPONSE = 0x82
NETBIOS_SESSION_NEGATIVE_RESPONSE = 0x83
NETBIOS_SESSION_RETARGET_RESPONSE = 0x84
NETBIOS_SESSION_KEEP_ALIVE = 0x85

################################################################################
# HELPERS
################################################################################
# Perform first and second level encoding of name as specified in RFC 1001 (Section 4)
def encode_name(name, type, scope):
    if name == '*':
        name += '\0' * 15
    elif len(name) > 15:
        name = name[:15] + chr(type)
    else:
        name = string.ljust(name, 15) + chr(type)

    encoded_name = chr(len(name) * 2) + re.sub('.', _do_first_level_encoding, name)
    if scope:
        encoded_scope = ''
        for s in string.split(scope, '.'):
            encoded_scope = encoded_scope + chr(len(s)) + s
        return encoded_name + encoded_scope + '\0'
    else:
        return encoded_name.encode('ascii') + '\0'

# Internal method for use in encode_name()
def _do_first_level_encoding(m):
    s = ord(m.group(0))
    return string.uppercase[s >> 4] + string.uppercase[s & 0x0f]

def decode_name(name):
    name_length = ord(name[0])
    assert name_length == 32

    decoded_name = re.sub('..', _do_first_level_decoding, name[1:33])
    if name[33] == '\0':
        return 34, decoded_name, ''
    else:
        decoded_domain = ''
        offset = 34
        while 1:
            domain_length = ord(name[offset])
            if domain_length == 0:
                break
            decoded_domain = '.' + name[offset:offset + domain_length]
            offset += domain_length
        return offset + 1, decoded_name, decoded_domain

def _do_first_level_decoding(m):
    s = m.group(0)
    return chr(((ord(s[0]) - ord('A')) << 4) | (ord(s[1]) - ord('A')))

ERRCLASS_QUERY = 0x00
ERRCLASS_SESSION = 0xf0
ERRCLASS_OS = 0xff

QUERY_ERRORS = {0x01: 'Format Error. Request was invalidly formatted',
                0x02: 'Server failure. Problem with NBNS, cannot process name.',
                0x03: 'Name does not exist',
                0x04: 'Unsupported request error.  Allowable only for challenging NBNS when gets an Update type registration request.',
                0x05: 'Refused error.  For policy reasons server will not register this name from this host.',
                0x06: 'Active error.  Name is owned by another node.',
                0x07: 'Name in conflict error.  A UNIQUE name is owned by more than one node.',

                }

SESSION_ERRORS = {0x80: 'Not listening on called name',
                  0x81: 'Not listening for calling name',
                  0x82: 'Called name not present',
                  0x83: 'Sufficient resources',
                  0x8f: 'Unspecified error'
                  }

class NetBIOSError(Exception):
    def __init__(self, error_message='', error_class=None, error_code=None):
        self.error_class = error_class
        self.error_code = error_code
        self.error_msg = error_message

    def get_error_code(self):
        return self.error

    def getErrorCode(self):
        return self.get_error_code()

    def get_error_string(self):
        return str(self)

    def getErrorString(self):
        return str(self)

    def __str__(self):
        if self.error_code is not None:
            if QUERY_ERRORS.has_key(self.error_code):
                return '%s-%s(%s)' % (self.error_msg, QUERY_ERRORS[self.error_code], self.error_code)
            elif SESSION_ERRORS.has_key(self.error_code):
                return '%s-%s(%s)' % (self.error_msg, SESSION_ERRORS[self.error_code], self.error_code)
            else:
                return '%s(%s)' % (self.error_msg, self.error_code)
        else:
            return '%s' % self.error_msg

class NetBIOSTimeout(Exception):
    def __init__(self, message = 'The NETBIOS connection with the remote host timed out.'):
        Exception.__init__(self, message)

################################################################################
# 4.2 NAME SERVER PACKETS
################################################################################
class NBNSResourceRecord(Structure):
    structure = (
        ('RR_NAME','z=\x00'),
        ('RR_TYPE','>H=0'),
        ('RR_CLASS','>H=0'),
        ('TTL','>L=0'),
        ('RDLENGTH','>H-RDATA'),
        ('RDATA',':=""'),
    )

class NBNodeStatusResponse(NBNSResourceRecord):
    def __init__(self, data = 0):
        NBNSResourceRecord.__init__(self, data)
        self.mac = '00-00-00-00-00-00'
        self.num_names = unpack('B', self['RDATA'][:1])[0]
        self.entries = list()
        data = self['RDATA'][1:]
        for _ in range(self.num_names):
            entry = NODE_NAME_ENTRY(data)
            data = data[len(entry):]
            self.entries.append(entry)
        self.statistics = STATISTICS(data)
        self.set_mac_in_hexa(self.statistics['UNIT_ID'])

    def set_mac_in_hexa(self, data):
        data_aux = ''
        for d in data:
            if data_aux == '':
                data_aux = '%02x' % ord(d)
            else:
                data_aux += '-%02x' % ord(d)
        self.mac = string.upper(data_aux)

    def get_mac(self):
        return self.mac

    def rawData(self):
        res = pack('!B', self.num_names )
        for i in range(0, self.num_names):
            res += self.entries[i].getData()

class NBPositiveNameQueryResponse(NBNSResourceRecord):
    def __init__(self, data = 0):
        NBNSResourceRecord.__init__(self, data)
        self.entries = [ ]
        rdata = self['RDATA']
        while len(rdata) > 0:
            entry = ADDR_ENTRY(rdata)
            rdata = rdata[len(entry):]
            self.entries.append(socket.inet_ntoa(entry['NB_ADDRESS']))

# 4.2.1.  GENERAL FORMAT OF NAME SERVICE PACKETS
class NAME_SERVICE_PACKET(Structure):
    commonHdr = (
        ('NAME_TRN_ID','>H=0'),
        ('FLAGS','>H=0'),
        ('QDCOUNT','>H=0'),
        ('ANCOUNT','>H=0'),
        ('NSCOUNT','>H=0'),
        ('ARCOUNT','>H=0'),
    )
    structure = (
        ('ANSWERS',':'),
    )

# 4.2.1.2.  QUESTION SECTION
class QUESTION_ENTRY(Structure):
    commonHdr = (
        ('QUESTION_NAME','z'),
        ('QUESTION_TYPE','>H=0'),
        ('QUESTION_CLASS','>H=0'),
    )

# 4.2.1.3.  RESOURCE RECORD
class RESOURCE_RECORD(Structure):
    structure = (
        ('RR_NAME','z=\x00'),
        ('RR_TYPE','>H=0'),
        ('RR_CLASS','>H=0'),
        ('TTL','>L=0'),
        ('RDLENGTH','>H-RDATA'),
        ('RDATA',':=""'),
    )

# 4.2.2.  NAME REGISTRATION REQUEST
class NAME_REGISTRATION_REQUEST(NAME_SERVICE_PACKET):
    structure = (
        ('QUESTION_NAME', 'z'),
        ('QUESTION_TYPE', '>H=0'),
        ('QUESTION_CLASS', '>H=0'),
        ('RR_NAME','z', ),
        ('RR_TYPE', '>H=0'),
        ('RR_CLASS','>H=0'),
        ('TTL', '>L=0'),
        ('RDLENGTH', '>H=6'),
        ('NB_FLAGS', '>H=0'),
        ('NB_ADDRESS', '4s=""'),
    )
    def __init__(self, data=None):
        NAME_SERVICE_PACKET.__init__(self,data)
        self['FLAGS'] = OPCODE_REQUEST | NM_FLAGS_RD | OPCODE_REGISTRATION
        self['QDCOUNT'] = 1
        self['ANCOUNT'] = 0
        self['NSCOUNT'] = 0
        self['ARCOUNT'] = 1

        self['QUESTION_TYPE'] = QUESTION_TYPE_NB
        self['QUESTION_CLASS'] = QUESTION_CLASS_IN

        self['RR_TYPE'] = RR_TYPE_NB
        self['RR_CLASS'] = RR_CLASS_IN

# 4.2.3.  NAME OVERWRITE REQUEST & DEMAND
class NAME_OVERWRITE_REQUEST(NAME_REGISTRATION_REQUEST):
    def __init__(self, data=None):
        NAME_REGISTRATION_REQUEST.__init__(self,data)
        self['FLAGS'] = OPCODE_REQUEST | OPCODE_REGISTRATION
        self['QDCOUNT'] = 1
        self['ANCOUNT'] = 0
        self['NSCOUNT'] = 0
        self['ARCOUNT'] = 1

# 4.2.4.  NAME REFRESH REQUEST
class NAME_REFRESH_REQUEST(NAME_REGISTRATION_REQUEST):
    def __init__(self, data=None):
        NAME_REGISTRATION_REQUEST.__init__(self,data)
        self['FLAGS'] = OPCODE_REFRESH | 0x1
        self['QDCOUNT'] = 1
        self['ANCOUNT'] = 0
        self['NSCOUNT'] = 0
        self['ARCOUNT'] = 1

# 4.2.5.  POSITIVE NAME REGISTRATION RESPONSE
# 4.2.6.  NEGATIVE NAME REGISTRATION RESPONSE
# 4.2.7.  END-NODE CHALLENGE REGISTRATION RESPONSE
class NAME_REGISTRATION_RESPONSE(NAME_REGISTRATION_REQUEST):
    def __init__(self, data=None):
        NAME_REGISTRATION_REQUEST.__init__(self,data)

# 4.2.8.  NAME CONFLICT DEMAND
class NAME_CONFLICT_DEMAND(NAME_REGISTRATION_REQUEST):
    def __init__(self, data=None):
        NAME_REGISTRATION_REQUEST.__init__(self,data)

# ToDo: 4.2.9.  NAME RELEASE REQUEST & DEMAND
# ToDo: 4.2.10.  POSITIVE NAME RELEASE RESPONSE
# ToDo: 4.2.11.  NEGATIVE NAME RELEASE RESPONSE

# 4.2.12.  NAME QUERY REQUEST
class NAME_QUERY_REQUEST(NAME_SERVICE_PACKET):
    structure = (
        ('QUESTION_NAME', 'z'),
        ('QUESTION_TYPE', '>H=0'),
        ('QUESTION_CLASS', '>H=0'),
    )
    def __init__(self, data=None):
        NAME_SERVICE_PACKET.__init__(self,data)
        self['FLAGS'] = OPCODE_REQUEST | OPCODE_REGISTRATION | NM_FLAGS_RD
        self['RCODE'] = 0
        self['QDCOUNT'] = 1
        self['ANCOUNT'] = 0
        self['NSCOUNT'] = 0
        self['ARCOUNT'] = 0

        self['QUESTION_TYPE'] = QUESTION_TYPE_NB
        self['QUESTION_CLASS'] = QUESTION_CLASS_IN

# 4.2.13.  POSITIVE NAME QUERY RESPONSE
class ADDR_ENTRY(Structure):
    structure = (
        ('NB_FLAGS', '>H=0'),
        ('NB_ADDRESS', '4s=""'),
    )

# ToDo: 4.2.15.  REDIRECT NAME QUERY RESPONSE
# ToDo: 4.2.16.  WAIT FOR ACKNOWLEDGEMENT (WACK) RESPONSE

# 4.2.17.  NODE STATUS REQUEST
class NODE_STATUS_REQUEST(NAME_QUERY_REQUEST):
    def __init__(self, data=None):
        NAME_QUERY_REQUEST.__init__(self,data)

        self['FLAGS'] = 0
        self['QUESTION_TYPE'] = QUESTION_TYPE_NBSTAT

# 4.2.18.  NODE STATUS RESPONSE
class NODE_NAME_ENTRY(Structure):
    structure = (
        ('NAME','15s=""'),
        ('TYPE','B=0'),
        ('NAME_FLAGS','>H'),
    )

class STATISTICS(Structure):
    structure = (
        ('UNIT_ID','6s=""'),
        ('JUMPERS','B'),
        ('TEST_RESULT','B'),
        ('VERSION_NUMBER','>H'),
        ('PERIOD_OF_STATISTICS','>H'),
        ('NUMBER_OF_CRCs','>H'),
        ('NUMBER_ALIGNMENT_ERRORS','>H'),
        ('NUMBER_OF_COLLISIONS','>H'),
        ('NUMBER_SEND_ABORTS','>H'),
        ('NUMBER_GOOD_SENDS','>L'),
        ('NUMBER_GOOD_RECEIVES','>L'),
        ('NUMBER_RETRANSMITS','>H'),
        ('NUMBER_NO_RESOURCE_CONDITIONS','>H'),
        ('NUMBER_FREE_COMMAND_BLOCKS','>H'),
        ('TOTAL_NUMBER_COMMAND_BLOCKS','>H'),
        ('MAX_TOTAL_NUMBER_COMMAND_BLOCKS','>H'),
        ('NUMBER_PENDING_SESSIONS','>H'),
        ('MAX_NUMBER_PENDING_SESSIONS','>H'),
        ('MAX_TOTAL_SESSIONS_POSSIBLE','>H'),
        ('SESSION_DATA_PACKET_SIZE','>H'),
    )

class NetBIOS:
    # Creates a NetBIOS instance without specifying any default NetBIOS domain nameserver.
    # All queries will be sent through the servport.
    def __init__(self, servport = NETBIOS_NS_PORT):
        self.__servport = NETBIOS_NS_PORT
        self.__nameserver = None
        self.__broadcastaddr = BROADCAST_ADDR
        self.mac = '00-00-00-00-00-00'

    def _setup_connection(self, dstaddr, timeout=None):
        port = randint(10000, 60000)
        af, socktype, proto, _canonname, _sa = socket.getaddrinfo(dstaddr, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        s = socket.socket(af, socktype, proto)
        has_bind = 1
        for _i in range(0, 10):
            # We try to bind to a port for 10 tries
            try:
                s.bind((INADDR_ANY, randint(10000, 60000)))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                has_bind = 1
            except socket.error:
                pass
        if not has_bind:
            raise NetBIOSError, ('Cannot bind to a good UDP port', ERRCLASS_OS, errno.EAGAIN)
        self.__sock = s

    def send(self, request, destaddr, timeout):
        self._setup_connection(destaddr)

        tries = 3
        while 1:
            try:
                self.__sock.sendto(request.getData(), 0, (destaddr, self.__servport))
                ready, _, _ = select.select([self.__sock.fileno()], [], [], timeout)
                if not ready:
                    if tries:
                        # Retry again until tries == 0
                        tries -= 1
                    else:
                        raise NetBIOSTimeout
                else:
                    try:
                        data, _ = self.__sock.recvfrom(65536, 0)
                    except Exception, e:
                        raise NetBIOSError, "recvfrom error: %s" % str(e)
                    self.__sock.close()
                    res = NAME_SERVICE_PACKET(data)
                    if res['NAME_TRN_ID'] == request['NAME_TRN_ID']:
                        if (res['FLAGS'] & 0xf) > 0:
                            raise NetBIOSError, ('Negative response', ERRCLASS_QUERY, res['FLAGS'] & 0xf)
                        return res
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ('Error occurs while waiting for response', ERRCLASS_OS, ex[0])
            except socket.error, ex:
                raise NetBIOSError, 'Connection error: %s' % str(ex)

    # Set the default NetBIOS domain nameserver.
    def set_nameserver(self, nameserver):
        self.__nameserver = nameserver

    # Return the default NetBIOS domain nameserver, or None if none is specified.
    def get_nameserver(self):
        return self.__nameserver

    # Set the broadcast address to be used for query.
    def set_broadcastaddr(self, broadcastaddr):
        self.__broadcastaddr = broadcastaddr

    # Return the broadcast address to be used, or BROADCAST_ADDR if default broadcast address is used.   
    def get_broadcastaddr(self):
        return self.__broadcastaddr

    # Returns a NBPositiveNameQueryResponse instance containing the host information for nbname.
    # If a NetBIOS domain nameserver has been specified, it will be used for the query.
    # Otherwise, the query is broadcasted on the broadcast address.
    def gethostbyname(self, nbname, qtype = TYPE_WORKSTATION, scope = None, timeout = 1):
        resp = self.name_query_request(nbname, self.__nameserver, qtype, scope, timeout)
        return resp

    # Returns a list of NBNodeEntry instances containing node status information for nbname.
    # If destaddr contains an IP address, then this will become an unicast query on the destaddr.
    # Raises NetBIOSTimeout if timeout (in secs) is reached.
    # Raises NetBIOSError for other errors
    def getnodestatus(self, nbname, destaddr = None, type = TYPE_WORKSTATION, scope = None, timeout = 1):
        if destaddr:
            return self.node_status_request(nbname, destaddr, type, scope, timeout)
        else:
            return self.node_status_request(nbname, self.__nameserver, type, scope, timeout)

    def getnetbiosname(self, ip):
        entries = self.getnodestatus('*',ip)
        entries = filter(lambda x:x['TYPE'] == TYPE_SERVER, entries)
        return entries[0]['NAME'].strip()

    def getmacaddress(self):
        return self.mac

    def name_registration_request(self, nbname, destaddr, qtype, scope, nb_flags=0, nb_address='0.0.0.0'):
        netbios_name = nbname.upper()
        qn_label = encode_name(netbios_name, qtype, scope)

        p = NAME_REGISTRATION_REQUEST()
        p['NAME_TRN_ID'] = randint(1, 32000)
        p['QUESTION_NAME'] = qn_label[:-1]
        p['RR_NAME'] = qn_label[:-1]
        p['TTL'] = 0xffff
        p['NB_FLAGS'] = nb_flags
        p['NB_ADDRESS'] = socket.inet_aton(nb_address)
        if not destaddr:
            p['FLAGS'] |= NM_FLAGS_BROADCAST
            destaddr = self.__broadcastaddr
        req = p.getData()

        res = self.send(p, destaddr, 1)
        return res

    def name_query_request(self, nbname, destaddr = None, qtype = TYPE_SERVER, scope = None, timeout = 1):
        netbios_name = nbname.upper()
        qn_label = encode_name(netbios_name, qtype, scope)

        p = NAME_QUERY_REQUEST()
        p['NAME_TRN_ID'] = randint(1, 32000)
        p['QUESTION_NAME'] = qn_label[:-1]
        p['FLAGS'] = NM_FLAGS_RD
        if not destaddr:
            p['FLAGS'] |= NM_FLAGS_BROADCAST

            destaddr = self.__broadcastaddr
        req = p.getData()

        res = self.send(p, destaddr, timeout)
        return NBPositiveNameQueryResponse(res['ANSWERS'])

    def node_status_request(self, nbname, destaddr, type, scope, timeout):
        netbios_name = string.upper(nbname)
        qn_label = encode_name(netbios_name, type, scope)
        p = NODE_STATUS_REQUEST()
        p['NAME_TRN_ID'] = randint(1, 32000)
        p['QUESTION_NAME'] = qn_label[:-1]

        if not destaddr:
            p['FLAGS'] = NM_FLAGS_BROADCAST
            destaddr = self.__broadcastaddr

        res = self.send(p, destaddr, timeout)
        answ = NBNodeStatusResponse(res['ANSWERS'])
        self.mac = answ.get_mac()
        return answ.entries

################################################################################
# 4.2 SESSION SERVICE PACKETS
################################################################################

class NetBIOSSessionPacket:
    def __init__(self, data=0):
        self.type = 0x0
        self.flags = 0x0
        self.length = 0x0
        if data == 0:
            self._trailer = ''
        else:
            try:
                self.type = ord(data[0])
                if self.type == NETBIOS_SESSION_MESSAGE:
                    self.length = ord(data[1]) << 16 | (unpack('!H', data[2:4])[0])
                else:
                    self.flags = ord(data[1])
                    self.length = unpack('!H', data[2:4])[0]

                self._trailer = data[4:]
            except:
                raise NetBIOSError('Wrong packet format ')

    def set_type(self, type):
        self.type = type

    def get_type(self):
        return self.type

    def rawData(self):
        if self.type == NETBIOS_SESSION_MESSAGE:
            data = pack('!BBH', self.type, self.length >> 16, self.length & 0xFFFF) + self._trailer
        else:
            data = pack('!BBH', self.type, self.flags, self.length) + self._trailer
        return data

    def set_trailer(self, data):
        self._trailer = data
        self.length = len(data)

    def get_length(self):
        return self.length

    def get_trailer(self):
        return self._trailer
        
class NetBIOSSession:
    def __init__(self, myname, remote_name, remote_host, remote_type=TYPE_SERVER, sess_port=NETBIOS_SESSION_PORT,
                 timeout=None, local_type=TYPE_WORKSTATION, sock=None):
        if len(myname) > 15:
            self.__myname = string.upper(myname[:15])
        else:
            self.__myname = string.upper(myname)
        self.__local_type = local_type

        assert remote_name
        # if destination port SMB_SESSION_PORT and remote name *SMBSERVER, we're changing it to its IP address
        # helping solving the client mistake ;)
        if remote_name == '*SMBSERVER' and sess_port == SMB_SESSION_PORT:
            remote_name = remote_host

        # If remote name is *SMBSERVER let's try to query its name.. if can't be guessed, continue and hope for the best
        if remote_name == '*SMBSERVER':
            nb = NetBIOS()
            try:
                res = nb.getnetbiosname(remote_host)
            except:
                res = None
                pass

            if res is not None:
                remote_name = res

        if len(remote_name) > 15:
            self.__remote_name = string.upper(remote_name[:15])
        else:
            self.__remote_name = string.upper(remote_name)
        self.__remote_type = remote_type
        self.__remote_host = remote_host

        if sock is not None:
            # We are acting as a server
            self._sock = sock
        else:
            self._sock = self._setup_connection((remote_host, sess_port), timeout)

        if sess_port == NETBIOS_SESSION_PORT:
            self._request_session(remote_type, local_type, timeout)

    def _request_session(self, remote_type, local_type, timeout):
        raise NotImplementedError('Not Implemented!')

    def _setup_connection(self, peer, timeout=None):
        raise NotImplementedError('Not Implemented!')

    def get_myname(self):
        return self.__myname

    def get_mytype(self):
        return self.__local_type

    def get_remote_host(self):
        return self.__remote_host

    def get_remote_name(self):
        return self.__remote_name

    def get_remote_type(self):
        return self.__remote_type

    def close(self):
        self._sock.close()

    def get_socket(self):
        return self._sock

class NetBIOSUDPSessionPacket(Structure):
    TYPE_DIRECT_UNIQUE = 16
    TYPE_DIRECT_GROUP  = 17

    FLAGS_MORE_FRAGMENTS = 1
    FLAGS_FIRST_FRAGMENT = 2
    FLAGS_B_NODE         = 0

    structure = (
        ('Type','B=16'),    # Direct Unique Datagram
        ('Flags','B=2'),    # FLAGS_FIRST_FRAGMENT
        ('ID','<H'),
        ('_SourceIP','>L'),
        ('SourceIP','"'),
        ('SourcePort','>H=138'),
        ('DataLegth','>H-Data'),
        ('Offset','>H=0'),
        ('SourceName','z'),
        ('DestinationName','z'),
        ('Data',':'),
    )

    def getData(self):
        addr = self['SourceIP'].split('.')
        addr = [int(x) for x in addr]
        addr = (((addr[0] << 8) + addr[1] << 8) + addr[2] << 8) + addr[3]
        self['_SourceIP'] = addr
        return Structure.getData(self)

    def get_trailer(self):
        return self['Data']

class NetBIOSUDPSession(NetBIOSSession):
    def _setup_connection(self, peer, timeout=None):
        af, socktype, proto, canonname, sa = socket.getaddrinfo(peer[0], peer[1], 0, socket.SOCK_DGRAM)[0]
        sock = socket.socket(af, socktype, proto)
        sock.connect(sa)

        sock = socket.socket(af, socktype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((INADDR_ANY, 138))
        self.peer = peer
        return sock

    def _request_session(self, remote_type, local_type, timeout = None):
        pass

    def next_id(self):
        if hasattr(self, '__dgram_id'):
            answer = self.__dgram_id
        else:
            self.__dgram_id = randint(1,65535)
            answer = self.__dgram_id
        self.__dgram_id += 1
        return answer

    def send_packet(self, data):
        # Yes... I know...
        self._sock.connect(self.peer)

        p = NetBIOSUDPSessionPacket()
        p['ID'] = self.next_id()
        p['SourceIP'] = self._sock.getsockname()[0]
        p['SourceName'] = encode_name(self.get_myname(), self.get_mytype(), '')[:-1]
        p['DestinationName'] = encode_name(self.get_remote_name(), self.get_remote_type(), '')[:-1]
        p['Data'] = data

        self._sock.sendto(str(p), self.peer)
        self._sock.close()

        self._sock = self._setup_connection(self.peer)

    def recv_packet(self, timeout = None):
        # The next loop is a workaround for a bigger problem:
        # When data reaches higher layers, the lower headers are lost,
        # and with them, for example, the source IP. Hence, SMB users
        # can't know where packets are comming from... we need a better
        # solution, right now, we will filter everything except packets
        # coming from the remote_host specified in __init__()

        while 1:
            data, peer = self._sock.recvfrom(8192)
#            print "peer: %r  self.peer: %r" % (peer, self.peer)
            if peer == self.peer: break

        return NetBIOSUDPSessionPacket(data)

class NetBIOSTCPSession(NetBIOSSession):
    def __init__(self, myname, remote_name, remote_host, remote_type=TYPE_SERVER, sess_port=NETBIOS_SESSION_PORT,
                 timeout=None, local_type=TYPE_WORKSTATION, sock=None, select_poll=False):
        self.__select_poll = select_poll
        if self.__select_poll:
            self.read_function = self.polling_read
        else:
            self.read_function = self.non_polling_read
        NetBIOSSession.__init__(self, myname, remote_name, remote_host, remote_type=remote_type, sess_port=sess_port,
                                timeout=timeout, local_type=local_type, sock=sock)

    def _setup_connection(self, peer, timeout=None):
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(peer[0], peer[1], 0, socket.SOCK_STREAM)[0]
            sock = socket.socket(af, socktype, proto)
            oldtimeout = sock.gettimeout()
            sock.settimeout(timeout)
            sock.connect(sa)
            sock.settimeout(oldtimeout)
        except socket.error, e:
            raise socket.error("Connection error (%s:%s)" % (peer[0], peer[1]), e)
        return sock

    def send_packet(self, data):
        p = NetBIOSSessionPacket()
        p.set_type(NETBIOS_SESSION_MESSAGE)
        p.set_trailer(data)
        self._sock.send(p.rawData())

    def recv_packet(self, timeout = None):
        data = self.__read(timeout)
        return NetBIOSSessionPacket(data)

    def _request_session(self, remote_type, local_type, timeout = None):
        p = NetBIOSSessionPacket()
        remote_name = encode_name(self.get_remote_name(), remote_type, '')
        myname = encode_name(self.get_myname(), local_type, '')
        p.set_type(NETBIOS_SESSION_REQUEST)
        p.set_trailer(remote_name + myname)

        self._sock.send(p.rawData())
        while 1:
            p = self.recv_packet(timeout)
            if p.get_type() == NETBIOS_SESSION_NEGATIVE_RESPONSE:
                raise NetBIOSError, ('Cannot request session (Called Name:%s)' % self.get_remote_name())
            elif p.get_type() == NETBIOS_SESSION_POSITIVE_RESPONSE:
                break
            else:
                # Ignore all other messages, most probably keepalive messages
                pass

    def polling_read(self, read_length, timeout):
        data = ''
        if timeout is None:
            timeout = 3600

        time_left = timeout
        CHUNK_TIME = 0.025
        bytes_left = read_length

        while bytes_left > 0:
            try:
                ready, _, _ = select.select([self._sock.fileno()], [], [], 0)

                if not ready:
                    if time_left <= 0:
                        raise NetBIOSTimeout
                    else:
                        time.sleep(CHUNK_TIME)
                        time_left -= CHUNK_TIME
                        continue

                received = self._sock.recv(bytes_left)
                if len(received) == 0:
                    raise NetBIOSError, ('Error while reading from remote', ERRCLASS_OS, None)

                data = data + received
                bytes_left = read_length - len(data)
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ('Error occurs while reading from remote', ERRCLASS_OS, ex[0])

        return data

    def non_polling_read(self, read_length, timeout):
        data = ''
        bytes_left = read_length

        while bytes_left > 0:
            try:
                ready, _, _ = select.select([self._sock.fileno()], [], [], timeout)

                if not ready:
                    raise NetBIOSTimeout

                received = self._sock.recv(bytes_left)
                if len(received) == 0:
                    raise NetBIOSError, ('Error while reading from remote', ERRCLASS_OS, None)

                data = data + received
                bytes_left = read_length - len(data)
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ('Error occurs while reading from remote', ERRCLASS_OS, ex[0])

        return data

    def __read(self, timeout = None):
        data = self.read_function(4, timeout)
        type, flags, length = unpack('>ccH', data)
        if ord(type) == NETBIOS_SESSION_MESSAGE:
            length |= ord(flags) << 16
        else:
            if ord(flags) & 0x01:
                length |= 0x10000
        data2 = self.read_function(length, timeout)

        return data + data2

def main():
    def get_netbios_host_by_name(name):
        n = NetBIOS()
        n.set_broadcastaddr('255.255.255.255')  # To avoid use "<broadcast>" in socket
        for qtype in (TYPE_WORKSTATION, TYPE_CLIENT, TYPE_SERVER, TYPE_DOMAIN_MASTER, TYPE_DOMAIN_CONTROLLER):
            try:
                addrs = n.gethostbyname(name, qtype=qtype).entries
            except NetBIOSTimeout:
                continue
            else:
                return addrs
        raise Exception("Host not found")

    n = get_netbios_host_by_name("some-host")
    print n

if __name__ == '__main__':
    main()
