################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#

import array

from impacket import ImpactPacket
from impacket import dcerpc
from impacket.dcerpc import ndrutils
from struct import *

MSRPC_UUID_REMOTE_ACTIVATION ='\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57\x00\x00\x00\x00'
MSRPC_UUID_SYSTEM_ACTIVATOR = '\xa0\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00'

class ORPCTHIS:
    __SIZE = 32

    def __init__(self,data=0):
        self._version_hi = 5
        self._version_low = 6
        self._flags = 1
        self._reserved1 = 0
        self._cid = '\xf1\x59\xeb\x61\xfb\x1e\xd1\x11\xbc\xd9\x00\x60\x97\x92\xd2\x6c'
        self._extensions = '\x60\x5e\x0d\x00'

    def set_version(self, mayor, minor):
        self._version_hi = mayor
        self._version_low = minor

    def set_cid(self, uuid):
        self._cid = uuid

    def rawData(self):
        return pack('<HHLL', self._version_hi, self._version_low, self._flags, self._reserved1) + self._cid + self._extensions


class UnknownOpnum3RequestHeader(ImpactPacket.Header):
    OP_NUM = 3

    __SIZE = 48

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, UnknownOpnum3RequestHeader.__SIZE)

##         self.parent().set_callid(19)
        self.set_bytes_from_string('\x05\x00\x06\x01\x00\x00\x00\x00' + '\x31'*32 + '\x00'*8)

        if aBuffer: self.load_header(aBuffer)


    def get_header_size(self):
        return UnknownOpnum3RequestHeader.__SIZE


class UnknownOpnum4RequestHeader(ImpactPacket.Header):
    OP_NUM = 4

    __SIZE = 48

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, UnknownOpnum4RequestHeader.__SIZE)

##         self.parent().set_callid(19)
##         self.set_bytes(self, '\x05\x00\x06\x01\x00\x00\x00\x00' + '\x31'*32 + '\x00'*8)
        self.get_bytes()[:32] = array.array('B', ORPCTHIS().rawData())
        self.set_cls_binuuid('\x01\x00\x00\x00\x00\x00\x00\x00\x70\x5e\x0d\x00\x02\x00\x00\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_c_binuuid(self):
        return self.get_bytes().tolist()[12:12+16]
    def set_c_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[12:12+16] = array.array('B', binuuid)

    def get_cls_binuuid(self):
        return self.get_bytes().tolist()[32:32+16]
    def set_cls_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[32:32+16] = array.array('B', binuuid)


    def get_header_size(self):
        return UnknownOpnum4RequestHeader.__SIZE


class RemoteActivationRequestHeader(ImpactPacket.Header):
    OP_NUM = 0

    __SIZE = 124

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, UnknownOpnum4RequestHeader.__SIZE)

        self.get_bytes()[:32] = array.array('B', ORPCTHIS().rawData())
        self.set_cls_binuuid('\xbe\x1d\x8d\x47\xff\xd6\xe1\x4c\xac\x54\xaa\xd5\x4e\xf3\x45\xd3')
        self.set_client_implementation_level(2)
        self.set_interfaces_num(1)
        self.get_bytes()[68:76] = array.array('B', '\x80\x3f\x15\x00\x01\x00\x00\x00')
        self.set_pi_binuuid('\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46')
        self.get_bytes()[92:124] = array.array('B', '\x01\x00\x00\x00\x01\x00\x00\x00\x07\x00\x64\x00\x04\x00\x69\x00\x01\x00\x00\x00\x87\x03\xb2\xd6\x99\xee\xac\x65\xc7\x53\x81\xa4')

        if aBuffer: self.load_header(aBuffer)

    def get_c_binuuid(self):
        return self.get_bytes().tolist()[12:12+16]
    def set_c_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[12:12+16] = array.array('B', binuuid)

    def get_cls_binuuid(self):
        return self.get_bytes().tolist()[32:32+16]
    def set_cls_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[32:32+16] = array.array('B', binuuid)

    def get_object_name_len(self):
        return self.get_word(48, '<')
    def set_object_name_len(self, len):
        self.set_word(48, len, '<')

    def get_object_storage(self):
        return self.get_word(52, '<')
    def set_object_storage(self, storage):
        self.set_word(52, storage, '<')

    def get_client_implementation_level(self):
        return self.get_long(56, '<')
    def set_client_implementation_level(self, level):
        self.set_long(56, level, '<')

    def get_mode(self):
        return self.get_long(60, '<')
    def set_mode(self, mode):
        self.set_long(60, mode, '<')

    def get_interfaces_num(self):
        return self.get_long(64, '<')
    def set_interfaces_num(self, num):
        self.set_long(64, num, '<')

    def get_pi_binuuid(self):
        return self.get_bytes().tolist()[76:76+16]
    def set_pi_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[76:76+16] = array.array('B', binuuid)


    def get_header_size(self):
        return UnknownOpnum4RequestHeader.__SIZE


class DCERPCDcom:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def test(self):
        request = RemoteActivationRequestHeader()
        self._dcerpc.send(request)
        data = self._dcerpc.recv()
        return data

    def test2(self):
        request = UnknownOpnum3RequestHeader()
        self._dcerpc.send(request)

    def test_lsd(self):
        request = UnknownOpnum4RequestHeader()
        self._dcerpc.send(request)
