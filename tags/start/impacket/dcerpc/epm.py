# ---
# $Id$
#
# Description:
#   EPM (Endpoint Mapper) interface implementation.
#
# Author:
#   Alberto Solino (beto)
#   Javier Kohen (jkohen)
#
# Copyright (c) 2001-2003 CORE Security Technologies, CORE SDI Inc.
# All rights reserved.
#
# This computer software is owned by Core SDI Inc. and is
# protected by U.S. copyright laws and other laws and by international
# treaties.  This computer software is furnished by CORE SDI Inc.
# pursuant to a written license agreement and may be used, copied,
# transmitted, and stored only in accordance with the terms of such
# license and with the inclusion of the above copyright notice.  This
# computer software or any other copies thereof may not be provided or
# otherwise made available to any other person.
#
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL CORE SDI Inc. BE LIABLE
# FOR ANY DIRECT,  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
# CONSEQUENTIAL  DAMAGES RESULTING FROM THE USE OR MISUSE OF
# THIS SOFTWARE
#
#--

import array
import struct

from impact import ImpactPacket
from impact import uuid
import dcerpc
import ndrutils
import transport

MSRPC_UUID_PORTMAP ='\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00\x00'

class EPMLookupRequestHeader(ImpactPacket.Header):
    OP_NUM = 2

    __SIZE = 76

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, EPMLookupRequestHeader.__SIZE)

        self.set_inquiry_type(0)
        self.set_referent_id(1)
        self.set_referent_id2(2)
        self.set_max_entries(1)

        if aBuffer: self.load_header(aBuffer)

    def get_inquiry_type(self):
        return self.get_long(0, '<')
    def set_inquiry_type(self, type):
        self.set_long(0, type, '<')

    def get_referent_id(self):
        return self.get_long(4, '<')
    def set_referent_id(self, id):
        self.set_long(4, id, '<')

    def get_obj_binuuid(self):
        return self.get_bytes().tolist()[8:8+16]
    def set_obj_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[8:8+16] = array.array('B', binuuid)

    def get_referent_id2(self):
        return self.get_long(24, '<')
    def set_referent_id2(self, id):
        self.set_long(24, id, '<')

    def get_if_binuuid(self):
        return self.get_bytes().tolist()[28:28+20]
    def set_if_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[28:28+20] = array.array('B', binuuid)

    def get_version_option(self):
        return self.get_long(48, '<')
    def set_version_option(self, opt):
        self.set_long(48, opt, '<')

    def get_handle(self):
        return self.get_bytes().tolist()[52:52+20]
    def set_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[52:52+20] = array.array('B', handle)

    def get_max_entries(self):
        return self.get_long(72, '<')
    def set_max_entries(self, num):
        self.set_long(72, num, '<')


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
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def portmap_dump(self, rpc_handle = '\x00'*20):
        lookup = EPMLookupRequestHeader()
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
	self.__uuid = objuuid

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
