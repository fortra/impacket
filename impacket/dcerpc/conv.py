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
# Description:
#   Implement CONV protocol, used to establish an RPC session over UDP.
#

import array
from impacket import ImpactPacket

MSRPC_UUID_CONV = '\x76\x22\x3a\x33\x00\x00\x00\x00\x0d\x00\x00\x80\x9c\x00\x00\x00'

class WhoAreYou(ImpactPacket.Header):
    OP_NUM = 1

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WhoAreYou.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_activity_binuuid(self):
        return self.get_bytes().tolist()[0:0+16]
    def set_activity_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[0:0+16] = array.array('B', binuuid)

    def get_boot_time(self):
        return self.get_long(16, '<')
    def set_boot_time(self, time):
        self.set_long(16, time, '<')


    def get_header_size(self):
        return WhoAreYou.__SIZE


class WhoAreYou2(ImpactPacket.Header):
    OP_NUM = 1

    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WhoAreYou2.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_seq_num(self):
        return self.get_long(0, '<')
    def set_seq_num(self, num):
        self.set_long(0, num, '<')

    def get_cas_binuuid(self):
        return self.get_bytes().tolist()[4:4+16]
    def set_cas_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[4:4+16] = array.array('B', binuuid)

    def get_status(self):
        return self.get_long(20, '<')
    def set_status(self, status):
        self.set_long(20, status, '<')


    def get_header_size(self):
        return WhoAreYou2.__SIZE
