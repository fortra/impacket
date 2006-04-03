# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#   Handle basic DCE/RPC protocol, version 4.
#
# Author:
#   Javier Kohen (jkohen)

import array
import socket
import struct

from impacket import ImpactPacket
from impacket import uuid
import dcerpc, conv


class MSRPCHeader(ImpactPacket.Header):
    __SIZE = 80

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, MSRPCHeader.__SIZE)

        self.set_version(4)
        self.set_type(dcerpc.MSRPC_REQUEST)
        self.set_flags((0x08, 0x00))
        self.set_representation((0x10, 0x00, 0x00))
        self.set_serial((0, 0))
##         self.set_if_version(3)
        self.set_seq_num(0)
        self.set_if_hint(0xFFFF)
        self.set_activity_hint(0xFFFF)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        return self.get_byte(0)
    def set_version(self, version):
        self.set_byte(0, version)

    def get_type(self):
        return self.get_byte(1)
    def set_type(self, type):
        self.set_byte(1, type)

    def get_flags(self):
        """ This method returns a tuple in (flags1, flags2) form."""
        return (self.get_byte(2), self.get_byte(3))
    def set_flags(self, flags):
        """ This method takes a tuple in (flags1, flags2) form."""
        self.set_byte(2, flags[0])
        self.set_byte(3, flags[1])

    def get_representation(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(4), self.get_byte(5), self.get_byte(6))
    def set_representation(self, representation):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(4, representation[0])
        self.set_byte(5, representation[1])
        self.set_byte(6, representation[1])

    def get_serial(self):
        """ This method returns a tuple in (high, low) form."""
        return (self.get_byte(7), self.get_byte(79))
    def set_serial(self, serial):
        """ This method takes a tuple in (high, low) form."""
        self.set_byte(7, serial[0])
        self.set_byte(79, serial[1])

    def get_obj_binuuid(self):
        return self.get_bytes().tolist()[8:8+16]
    def set_obj_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[8:8+16] = array.array('B', binuuid)

    def get_if_binuuid(self):
        return self.get_bytes().tolist()[24:24+16]
    def set_if_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[24:24+16] = array.array('B', binuuid)

    def get_activity_binuuid(self):
        return self.get_bytes().tolist()[40:40+16]
    def set_activity_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[40:40+16] = array.array('B', binuuid)

    def get_server_boottime(self):
        return self.get_long(56, '<')
    def set_server_boottime(self, time):
        self.set_long(56, time, '<')

    def get_if_version(self):
        return self.get_long(60, '<')
    def set_if_version(self, version):
        self.set_long(60, version, '<')

    def get_seq_num(self):
        return self.get_long(64, '<')
    def set_seq_num(self, num):
        self.set_long(64, num, '<')

    def get_op_num(self):
        return self.get_word(68, '<')
    def set_op_num(self, op):
        self.set_word(68, op, '<')

    def get_if_hint(self):
        return self.get_word(70, '<')
    def set_if_hint(self, hint):
        self.set_word(70, hint, '<')

    def get_activity_hint(self):
        return self.get_word(72, '<')
    def set_activity_hint(self, hint):
        self.set_word(72, hint, '<')

    def get_frag_len(self):
        return self.get_word(74, '<')
    def set_frag_len(self, len):
        self.set_word(74, len, '<')

    def get_frag_num(self):
        return self.get_word(76, '<')
    def set_frag_num(self, num):
        self.set_word(76, num, '<')

    def get_auth_proto(self):
        return self.get_byte(78)
    def set_auth_proto(self, proto):
        self.set_byte(78, proto)


    def get_header_size(self):
        return MSRPCHeader.__SIZE

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            contents_size = self.child().get_size()
            self.set_op_num(self.child().OP_NUM)
            self.set_frag_len(contents_size)


class DCERPC_v4(dcerpc.DCERPC):
    DEFAULT_FRAGMENT_SIZE = 1392

    def __init__(self, transport):
        dcerpc.DCERPC.__init__(self, transport)
        self.__activity_uuid = uuid.generate()
        self.__seq_num = 0
        self._bind = 0 # Don't attempt binding unless it explicitly requested.

    def bind(self, uuid, idempotent = 0):
        """If idempotent is non-zero, the package will be sent with
        that flag enabled. Certain services react by skiping the CONV
        phase during the binding.
        """

        self._bind = 1 # Will bind later, when the first packet is transferred.
        self.__if_uuid = uuid[:16]
        self.__if_version = struct.unpack('<L', uuid[16:20])[0]
	self.__idempotent = idempotent
        self.__frag_size = DCERPC_v4.DEFAULT_FRAGMENT_SIZE

    def conv_bind(self):
        # Receive CONV handshake.
        # ImpactDecode: this block.
        data = self._transport.recv()
        rpc = MSRPCHeader(data)
        activity_uuid = rpc.get_activity_binuuid()
        _conv = conv.WhoAreYou(data[rpc.get_header_size():])
        # ImpactDecode
        rpc = MSRPCHeader()
        rpc.set_type(dcerpc.MSRPC_RESPONSE)
        rpc.set_if_binuuid(conv.MSRPC_UUID_CONV)
        flags = rpc.get_flags()
        rpc.set_flags((flags[0], 0x04))
        rpc.set_activity_binuuid(activity_uuid)
        _conv = conv.WhoAreYou2()
        rpc.contains(_conv)

        # The CONV response must be sent to the endpoint from where the request was received.
        old_address = self._transport.get_addr()
        peer_address = self._transport.get_recv_addr()
        self._transport.set_addr(peer_address)
        self._transport.send(rpc.get_packet())
        self._transport.set_addr(old_address)

    def get_fragment_size(self):
        return self.__frag_size

    def set_fragment_size(self, size):
        self.__frag_size = size

    def send(self, data):
        MAX_FRAG = self.__frag_size
        packet = data.get_packet()
        datasize = data.get_size()
        datasent = 0
        frag_size = MAX_FRAG
        frag_num = 0

        while datasent < datasize:
            frag_flags = 0xc
            if self.__idempotent: frag_flags |= 0x20

            # If last fragment...
            if datasize - datasent <= MAX_FRAG:
                frag_flags |= 2
                frag_size = (datasize-datasent)

            rpc = MSRPCHeader()
            rpc.set_seq_num(self.__seq_num)
            rpc.set_if_binuuid(self.__if_uuid)
            flags = rpc.get_flags()
            rpc.set_flags((flags[0] | frag_flags,flags[1]))
            rpc.set_if_version(self.__if_version)
            rpc.set_activity_binuuid(self.__activity_uuid)

            frag = ImpactPacket.Data()
            frag.set_bytes_from_string(packet[datasent:datasent+frag_size])
            frag.OP_NUM = data.OP_NUM
            rpc.contains(frag)
            rpc.set_frag_num(frag_num)
            self._transport.send(rpc.get_packet())

            datasent += frag_size
            frag_num += 1

            if self._bind and not self.__idempotent:
                self._bind = 0
                self.conv_bind()
                self.recv() # Discard RPC_ACK.

        self.__seq_num += 1

    def recv(self):
        data = self._transport.recv()
        rpc = MSRPCHeader(data)
        off = rpc.get_header_size()
        return data[off:]
