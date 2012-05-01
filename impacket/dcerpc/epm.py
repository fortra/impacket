# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#

import array
import struct

from impacket import ImpactPacket
from impacket import uuid
from impacket import dcerpc
from impacket.dcerpc import ndrutils
from impacket.dcerpc import transport
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_PORTMAP = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

class EPMLookupRequestHeader(ImpactPacket.Header):
    OP_NUM = 2

    __SIZE = 76

    def __init__(self, aBuffer = None, endianness = '<'):
        ImpactPacket.Header.__init__(self, EPMLookupRequestHeader.__SIZE)
        self.endianness = endianness

        self.set_inquiry_type(0)
        self.set_referent_id(1)
        self.set_referent_id2(2)
        self.set_max_entries(1)

        if aBuffer: self.load_header(aBuffer)

    def get_inquiry_type(self):
        return self.get_long(0, self.endianness)
    def set_inquiry_type(self, type):
        self.set_long(0, type, self.endianness)

    def get_referent_id(self):
        return self.get_long(4, self.endianness)
    def set_referent_id(self, id):
        self.set_long(4, id, self.endianness)

    def get_obj_binuuid(self):
        return self.get_bytes().tolist()[8:8+16]
    def set_obj_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[8:8+16] = array.array('B', binuuid)

    def get_referent_id2(self):
        return self.get_long(24, self.endianness)
    def set_referent_id2(self, id):
        self.set_long(24, id, self.endianness)

    def get_if_binuuid(self):
        return self.get_bytes().tolist()[28:28+20]
    def set_if_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[28:28+20] = array.array('B', binuuid)

    def get_version_option(self):
        return self.get_long(48, self.endianness)
    def set_version_option(self, opt):
        self.set_long(48, opt, self.endianness)

    def get_handle(self):
        return self.get_bytes().tolist()[52:52+20]
    def set_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[52:52+20] = array.array('B', handle)

    def get_max_entries(self):
        return self.get_long(72, self.endianness)
    def set_max_entries(self, num):
        self.set_long(72, num, self.endianness)


    def get_header_size(self):
        return EPMLookupRequestHeader.__SIZE


class EPMRespLookupRequestHeader(ImpactPacket.Header):
    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, EPMRespLookupRequestHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_handle(self):
        return self.get_bytes().tolist()[0:0+20]
    def set_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[0:0+20] = array.array('B', handle)

    def get_entries_num(self):
        return self.get_long(20, '<')
    def set_entries_num(self, num):
        self.set_long(20, num, '<')

    def get_entry(self):
        return ndrutils.NDREntries(self.get_bytes().tostring()[24:-4])
    def set_entry(self, entry):
        raise Exception, "method not implemented"

    def get_status(self):
        off = self.get_entry().get_entries_len()
        return self.get_long(24 + off, '<')
    def set_status(self, status):
        off = self.get_entry().get_entries_len()
        self.set_long(24 + off, status, '<')


    def get_header_size(self):
        entries_size = self.get_entry().get_entries_len()
        return EPMRespLookupRequestHeader.__SIZE + entries_size


class DCERPCEpm:
    endianness = '<'
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def portmap_dump(self, rpc_handle = '\x00'*20):
        if self.endianness == '>':
            from impacket.structure import unpack,pack
            try:
                rpc_handle = ''.join(map(chr, rpc_handle))
            except:
                pass
            
            uuid = list(unpack('<LLHHBB6s', rpc_handle))
            rpc_handle = pack('>LLHHBB6s', *uuid)

        lookup = EPMLookupRequestHeader(endianness = self.endianness)
        lookup.set_handle(rpc_handle);
        self._dcerpc.send(lookup)

        data = self._dcerpc.recv()
        resp = EPMRespLookupRequestHeader(data)

        return resp

class EpmEntry:
    def __init__(self, uuid, version, annotation, objuuid, protocol, endpoint):
        self.__uuid = uuid
        self.__version = version
        self.__annotation = annotation
        self.__objuuid = objuuid
        self.__protocol = protocol
        self.__endpoint = endpoint

    def getUUID(self):
        return self.__uuid

    def setUUID(self, uuid):
        self.__uuid = uuid

    def getProviderName(self):
        return ndrutils.uuid_to_exe(uuid.string_to_bin(self.getUUID()) + struct.pack('<H', self.getVersion()))

    def getVersion(self):
        return self.__version

    def setVersion(self, version):
        self.__version = version

    def isZeroObjUUID(self):
        return self.__objuuid == '00000000-0000-0000-0000-000000000000'

    def getObjUUID(self):
        return self.__objuuid

    def setObjUUID(self, objuuid):
        self.__objuuid = objuuid

    def getAnnotation(self):
        return self.__annotation

    def setAnnotation(self, annotation):
        self.__annotation = annotation

    def getProtocol(self):
        return self.__protocol

    def setProtocol(self, protocol):
        self.__protocol = protocol

    def getEndpoint(self):
        return self.__endpoint

    def setEndpoint(self, endpoint):
        self.__endpoint = endpoint

    def __str__(self):
        stringbinding = transport.DCERPCStringBindingCompose(self.getObjUUID(), self.getProtocol(), '', self.getEndpoint())
        s = '['
        if self.getAnnotation(): s += "Annotation: \"%s\", " % self.getAnnotation()
        s += "UUID=%s, version %d, %s]" % (self.getUUID(), self.getVersion(), stringbinding)

        return s

    def __cmp__(self, o):
        if (self.getUUID() == o.getUUID()
            and self.getVersion() == o.getVersion()
            and self.getAnnotation() == o.getAnnotation()
            and self.getObjUUID() == o.getObjUUID()
            and self.getProtocol() == o.getProtocol()
            and self.getEndpoint() == o.getEndpoint()):
            return 0
        else:
            return -1 # or +1, for what we care.
