################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
# Copyright (c) 2003-2010 CORE Security Technologies
# Copyright (c) 2011 Catalin Patulea
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

MSRPC_UUID_MGMT = uuid.uuidtup_to_bin(("afa8bd80-7d8a-11c9-bef4-08002b102989", "1.0"))

class IfIdsRequestHeader(ImpactPacket.Header):
    OP_NUM = 0

    def get_header_size(self):
        return 0

class IdIdsResponseHeader(ImpactPacket.Header):
    __SIZE = 12

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, IdIdsResponseHeader.__SIZE)
        self.endianness = '<'
        if aBuffer: self.load_header(aBuffer)

    def get_ifcount(self):
        return self.get_long(4, self.endianness)

    def _get_iflists_offset(self):
        return 12 + 4 * self.get_ifcount()

    def get_if_binuuid(self, index):
        offset = self._get_iflists_offset() + 20*index
        #print "offset: %08x" % offset
        #print "bytes:", repr(self.get_bytes())
        return self.get_bytes()[offset:offset+20]

    def get_header_size(self):
        return IdIdsResponseHeader.__SIZE + 4 * self.get_ifcount() + 20 * self.get_ifcount()

class DCERPCMgmt:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def inq_if_ids(self):
        req = IfIdsRequestHeader()
        self._dcerpc.send(req)

        data = self._dcerpc.recv()
        resp = IdIdsResponseHeader(data)

        return resp
