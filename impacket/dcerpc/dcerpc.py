# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#   Handle basic DCE/RPC protocol, version 5.
#
# Author:
#   Alberto Solino (beto)
#   Javier Kohen (jkohen)

import array
import struct
from impact import ImpactPacket

# MS/RPC Constants
MSRPC_REQUEST   = 0x00
MSRPC_RESPONSE  = 0x02
MSRPC_ACK       = 0x07
MSRPC_BIND      = 0x0B
MSRPC_BINDACK   = 0x0C
MSRPC_BINDNAK   = 0x0D

# MS/RPC Packet Flags
MSRPC_FIRSTFRAG = 0x01
MSRPC_LASTFRAG  = 0x02
MSRPC_NOTAFRAG  = 0x04
MSRPC_RECRESPOND= 0x08
MSRPC_NOMULTIPLEX = 0x10
MSRPC_NOTFORIDEMP = 0x20
MSRPC_NOTFORBCAST = 0x40
MSRPC_NOUUID    = 0x80

def unicode_to_ascii(anUnicodeStr):
    ascii_str = ''
    i = 0
    for c in anUnicodeStr:
        if i & 0x1 == 0:
            ascii_str += c
        i += 1
    return ascii_str

def ascii_to_unicode(anAsciiStr):
    unicode_str = ''
    for c in anAsciiStr:
        unicode_str += c + '\0'
    return unicode_str

class MSRPCArray:
    def __init__(self, id=0, len=0, size=0):
        self._length = len
        self._size = size
        self._id = id
        self._max_len = 0
        self._offset = 0
        self._length2 = 0
        self._name = ''
    def __is_valid_unicode(self,data):
        i = 0
        for c in data:
            if (i & 0x1) != 0:
                if c != '\0':
                    return 0
            i ^= 1
        return 1
    def set_max_len(self, n):
        self._max_len = n
    def set_offset(self, n):
        self._offset = n
    def set_length2(self, n):
        self._length2 = n
    def get_size(self):
        return self._size
    def set_name(self, n):
        self._name = n
    def get_name(self):
        if self.__is_valid_unicode(self._name):
            return unicode_to_ascii(self._name)
        else:
            return self._name
    def get_id(self):
        return self._id
    def rawData(self):
        return struct.pack('<HHLLLL', self._length, self._size, 0x12345678, self._max_len, self._offset, self._length2) + self._name


class MSRPCNameArray:
    def __init__(self, data = None):
        self._count = 0
        self._max_count = 0
        self._elements = []

        if data: self.load(data)

    def load(self, data):
        ptr = struct.unpack('<L', data[:4])[0]
        index = 4
        if 0 == ptr: # No data. May be a bug in certain versions of Samba.
            return

        self._count, _, self._max_count = struct.unpack('<LLL', data[index:index+12])
        index += 12

        # Read each object's description.
        for i in range(0, self._count):
            aindex, length, size, _ = struct.unpack('<LHHL', data[index:index+12])
            self._elements.append(MSRPCArray(aindex, length, size))
            index += 12

        # Read the objects themselves.
        for element in self._elements:
            max_len, offset, curlen = struct.unpack('<LLL', data[index:index+12])
            index += 12
            element.set_name(data[index:index+2*curlen])
            element.set_max_len(max_len)
            element.set_offset(offset)
            element.set_length2(curlen)
            index += 2*curlen
            if curlen & 0x1: index += 2 # Skip padding.

    def elements(self):
        return self._elements

    def rawData(self):
        ret = struct.pack('<LLLL', 0x74747474, self._count, 0x47474747, self._max_count)
        pos_ret = []
        for i in xrange(0, self._count):
            ret += struct.pack('<L', self._elements[i].get_id())
            data = self._elements[i].rawData()
            ret += data[:8]
            pos_ret += data[8:]

        return ret + pos_ret


class MSRPCHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, MSRPCHeader.__SIZE)

        self.set_version((5, 0))
        self.set_type(MSRPC_REQUEST)
        self.set_flags(MSRPC_FIRSTFRAG | MSRPC_LASTFRAG)
        self.set_representation(0x10)
        self.set_frag_len(MSRPCHeader.__SIZE)
        self.set_auth_len(0)
        self.set_call_id(1)
        self.set_ctx_id(0)
        self.set_alloc_hint(0)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_alloc_hint(self):
        return self.get_long(16, '<')
    def set_alloc_hint(self, len):
        self.set_long(16, len, '<')

    def get_ctx_id(self):
        return self.get_word(20, '<')
    def set_ctx_id(self, id):
        self.set_word(20, id, '<')

    def get_op_num(self):
        return self.get_word(22, '<')
    def set_op_num(self, op):
        self.set_word(22, op, '<')


    def get_header_size(self):
        return MSRPCHeader.__SIZE

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            contents_size = self.child().get_size()
            self.set_op_num(self.child().OP_NUM)
            self.set_frag_len(self.get_header_size() + contents_size)
            self.set_alloc_hint(contents_size)


class MSRPCRespHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, MSRPCRespHeader.__SIZE)

        self.set_type(MSRPC_RESPONSE)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_alloc_hint(self):
        return self.get_long(16, '<')
    def set_alloc_hint(self, len):
        self.set_long(16, len, '<')

    def get_ctx_id(self):
        return self.get_word(20, '<')
    def set_ctx_id(self, id):
        self.set_word(20, id, '<')

    def get_cancel_count(self):
        return self.get_byte(22)
    def set_op_num(self, op):
        self.set_byte(22, op)


    def get_header_size(self):
        return MSRPCRespHeader.__SIZE

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            contents_size = self.child().get_size()
            self.set_frag_len(self.get_header_size() + contents_size)
            self.set_alloc_hint(contents_size)


class MSRPCBind(ImpactPacket.Header):
    __SIZE = 72

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, MSRPCBind.__SIZE)

        self.set_version((5, 0))
        self.set_type(MSRPC_BIND)
        self.set_flags(MSRPC_FIRSTFRAG | MSRPC_LASTFRAG)
        self.set_representation(0x10)
        self.set_frag_len(MSRPCBind.__SIZE)
        self.set_auth_len(0)
        self.set_call_id(1)
        self.set_max_tfrag(5840)
        self.set_max_rfrag(5840)
        self.set_assoc_group(0)
        self.set_ctx_num(1)
        self.set_ctx_id(0)
        self.set_trans_num(1)
        self.set_xfer_syntax_binuuid('\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_max_tfrag(self):
        return self.get_word(16, '<')
    def set_max_tfrag(self, size):
        self.set_word(16, size, '<')

    def get_max_rfrag(self):
        return self.get_word(18, '<')
    def set_max_rfrag(self, size):
        self.set_word(18, size, '<')

    def get_assoc_group(self):
        return self.get_long(20, '<')
    def set_assoc_group(self, id):
        self.set_long(20, id, '<')

    def get_ctx_num(self):
        return self.get_byte(24)
    def set_ctx_num(self, num):
        self.set_byte(24, num)

    def get_ctx_id(self):
        return self.get_word(28, '<')
    def set_ctx_id(self, id):
        self.set_word(28, id, '<')

    def get_trans_num(self):
        return self.get_word(30, '<')
    def set_trans_num(self, op):
        self.set_word(30, op, '<')

    def get_if_binuuid(self):
        return self.get_bytes().tolist()[32:32+20]
    def set_if_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[32:32+20] = array.array('B', binuuid)

    def get_xfer_syntax_binuuid(self):
        return self.get_bytes().tolist()[52:52+20]
    def set_xfer_syntax_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[52:52+20] = array.array('B', binuuid)


    def get_header_size(self):
        return MSRPCBind.__SIZE

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            contents_size = self.child().get_size()
            self.set_op_num(self.child().OP_NUM)
            self.set_frag_len(self.get_header_size() + contents_size)
            self.set_alloc_hint(contents_size)


class MSRPCBindAck(ImpactPacket.Header):
    __SIZE = 56

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, MSRPCBindAck.__SIZE)

        self.set_type(MSRPC_BINDACK)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_max_tfrag(self):
        return self.get_word(16, '<')
    def set_max_tfrag(self, size):
        self.set_word(16, size, '<')

    def get_max_rfrag(self):
        return self.get_word(18, '<')
    def set_max_rfrag(self, size):
        self.set_word(18, size, '<')

    def get_assoc_group(self):
        return self.get_long(20, '<')
    def set_assoc_group(self, id):
        self.set_long(20, id, '<')

    def get_secondary_addr_len(self):
        return self.get_word(24, '<')
    def set_secondary_addr_len(self, len):
        self.set_word(24, len, '<')

    def get_secondary_addr(self):
        return self.get_bytes().tolist()[26:-28]
    def set_secondary_addr(self, addr):
        self.get_bytes()[26:-28] = array.array('B', addr)
        self.set_secondary_addr_len(len(addr))

    def get_results_num(self):
        return self.get_byte(-28)
    def set_results_num(self, num):
        self.set_byte(-28, num)

    def get_result(self):
        return self.get_word(-24, '<')
    def set_result(self, res):
        self.set_word(-24, res, '<')

    def get_xfer_syntax_binuuid(self):
        return self.get_bytes().tolist()[-20:]
    def set_xfer_syntax_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[-20:] = array.array('B', binuuid)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - MSRPCBindAck.__SIZE
        assert var_size > 0
        return MSRPCBindAck.__SIZE + var_size

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            contents_size = self.child().get_size()
            self.set_op_num(self.child().OP_NUM)
            self.set_frag_len(self.get_header_size() + contents_size)
            self.set_alloc_hint(contents_size)


class MSRPCBindNak(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, MSRPCBindNak.__SIZE)

        self.set_type(MSRPC_BINDNAK)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_reason(self):
        return self.get_word(16, '<')
    def set_reason(self, reason):
        self.set_word(16, reason, '<')

##     def get_(self):
##         return self.get_word(18, '<')
##     def set_(self, size):
##         self.set_word(18, size, '<')

    def get_assoc_group(self):
        return self.get_long(20, '<')
    def set_assoc_group(self, id):
        self.set_long(20, id, '<')


    def get_header_size(self):
        return MSRPCBindNak.__SIZE


class DCERPC:
    def __init__(self,transport):
        self._transport = transport

    def connect(self):
        return self._transport.connect()
    def disconnect(self):
        return self._transport.disconnect()

    def send(self, data): raise RuntimeError, 'virtual method'
    def recv(self): raise RuntimeError, 'virtual method'


class DCERPC_v5(DCERPC):
    def __init__(self, transport):
        DCERPC.__init__(self, transport)

    def bind(self, uuid):
        bind = MSRPCBind()
        bind.set_if_binuuid(uuid)
        self._transport.send(bind.get_packet())
        s = self._transport.recv()
        if s != 0:
            resp = MSRPCBindAck(s)
            return resp
        return 0

    def send(self, data):
        rpc = MSRPCHeader()
        rpc.contains(data)
        self._transport.send(rpc.get_packet())

    def recv(self):
        data = self._transport.recv()
        rpc = MSRPCHeader(data)
        off = rpc.get_header_size()
        return data[off:]
