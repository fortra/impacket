# ---
# $Id$
#
# Description:
#   SVCCTL (Services Control) interface implementation.
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
from struct import *

from impact import ImpactPacket
import dcerpc

MSRPC_UUID_SVCCTL = '\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03\x02\x00\x00\x00'

class SVCCTLOpenSCManagerHeader(ImpactPacket.Header):
    OP_NUM = 0x1B

    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLOpenSCManagerHeader.__SIZE)

        self.set_referent_id(0xFFFFFF)
        self.set_access_mask(0xF003F)

        if aBuffer: self.load_header(aBuffer)

    def get_referent_id(self):
        return self.get_long(0, '<')
    def set_referent_id(self, id):
        self.set_long(0, id, '<')

    def get_max_count(self):
        return self.get_long(4, '<')
    def set_max_count(self, num):
        self.set_long(4, num, '<')

    def get_offset(self):
        return self.get_long(8, '<')
    def set_offset(self, num):
        self.set_long(8, num, '<')

    def get_cur_count(self):
        return self.get_long(12, '<')
    def set_cur_count(self, num):
        self.set_long(12, num, '<')

    def get_machine_name(self):
        return self.get_bytes().tostring()[:20]
    def set_machine_name(self, name):
        assert len(name) <= 8
        self.set_max_count(len(name) + 1)
        self.set_cur_count(len(name) + 1)
        self.get_bytes()[16:24] = array.array('B', name + (8 - len(name)) * '\x00')

    def get_access_mask(self):
        return self.get_long(28, '<')
    def set_access_mask(self, mask):
        self.set_long(28, mask, '<')


    def get_header_size(self):
        return SVCCTLOpenSCManagerHeader.__SIZE


class SVCCTLRespOpenSCManagerHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespOpenSCManagerHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SVCCTLRespOpenSCManagerHeader.__SIZE


class SVCCTLOpenServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x1C

    __SIZE = 48


    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLOpenServiceHeader.__SIZE)

        self.set_max_count(9)
        self.set_cur_count(9)
        # Write some unknown fluff.
        self.get_bytes()[40:] = array.array('B', '\x00\x10\x48\x60\xff\x01\x0f\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_max_count(self):
        return self.get_long(20, '<')
    def set_max_count(self, num):
        self.set_long(20, num, '<')

    def get_offset(self):
        return self.get_long(24, '<')
    def set_offset(self, num):
        self.set_long(24, num, '<')

    def get_cur_count(self):
        return self.get_long(28, '<')
    def set_cur_count(self, num):
        self.set_long(28, num, '<')

    def get_service_name(self):
        return self.get_bytes().tostring()[32:40]
    def set_service_name(self, name):
        assert len(name) <= 8
        self.get_bytes()[32:40] = array.array('B', name + (8 - len(name)) * '\x00')


    def get_header_size(self):
        return SVCCTLOpenServiceHeader.__SIZE


class SVCCTLRespOpenServiceHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespOpenServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SVCCTLRespOpenServiceHeader.__SIZE


class SVCCTLCloseServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x0

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLCloseServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:] = array.array('B', handle)


    def get_header_size(self):
        return SVCCTLCloseServiceHeader.__SIZE


class SVCCTLRespCloseServiceHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespCloseServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SVCCTLRespCloseServiceHeader.__SIZE


class SVCCTLCreateServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x18

    __SIZE = 132

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLCreateServiceHeader.__SIZE)

        self.set_name_max_count(9)
        self.set_name_cur_count(9)
        self.set_service_flags(0x110)
        self.set_start_mode(2)
        self.get_bytes()[40:48] = array.array('B', '\x00\x10\x48\x60\xe4\xa3\x40\x00')
        self.get_bytes()[68:76] = array.array('B', '\x00\x00\x00\x00\xff\x01\x0f\x00')
        self.get_bytes()[84:88] = array.array('B', '\x01\x00\x00\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_name_max_count(self):
        return self.get_long(4, '<')
    def set_name_max_count(self, num):
        self.set_long(20, num, '<')
        self.set_long(48, num, '<')

    def get_name_offset(self):
        return self.get_long(8, '<')
    def set_name_offset(self, num):
        self.set_long(24, num, '<')
        self.set_long(52, num, '<')

    def get_name_cur_count(self):
        return self.get_long(12, '<')
    def set_name_cur_count(self, num):
        self.set_long(28, num, '<')
        self.set_long(56, num, '<')

    def get_service_name(self):
        return self.get_bytes().tostring()[32:40]
    def set_service_name(self, name):
        self.get_bytes()[32:40] = array.array('B', name + (8 - len(name)) * '\x00')
        self.get_bytes()[60:68] = array.array('B', name + (8 - len(name)) * '\x00')

    # 0x0000100 = Allow service to interact with desktop (needed by vnc server for example)
    # 0x0000010 = Log as: Local System Account
    def get_service_flags(self):
        return self.get_long(76, '<')
    def set_service_flags(self, flags):
        self.set_long(76, flags, '<')

    # 2 Automatic
    # 3 Manual
    # 4 Disabled
    def get_start_mode(self):
        return self.get_long(80, '<')
    def set_start_mode(self, mode):
        self.set_long(80, mode, '<')

    def get_path_max_count(self):
        return self.get_long(88, '<')
    def set_path_max_count(self, num):
        self.set_long(88, num, '<')

    def get_path_offset(self):
        return self.get_long(92, '<')
    def set_path_offset(self, num):
        self.set_long(92, num, '<')

    def get_path_cur_count(self):
        return self.get_long(96, '<')
    def set_path_cur_count(self, num):
        self.set_long(96, num, '<')

    def get_service_path(self):
        return self.get_bytes().tostring()[100:-32]
    def set_service_path(self, path):
        self.get_bytes()[100:-32] = array.array('B', path)
        self.set_path_max_count(len(path)+1)
        self.set_path_cur_count(len(path)+1)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SVCCTLCreateServiceHeader.__SIZE
        assert var_size > 0
        return SVCCTLCreateServiceHeader.__SIZE + var_size


class SVCCTLRespCreateServiceHeader(ImpactPacket.Header):
    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespCreateServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(24, '<')
    def set_return_code(self, code):
        self.set_long(24, code, '<')


    def get_header_size(self):
        return SVCCTLRespCreateServiceHeader.__SIZE


class SVCCTLDeleteServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x2

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLDeleteServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_header_size(self):
        return SVCCTLDeleteServiceHeader.__SIZE


class SVCCTLRespDeleteServiceHeader(dcerpc.MSRPCHeader):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespDeleteServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return SVCCTLRespDeleteServiceHeader.__SIZE


class SVCCTLStopServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x1

    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLStopServiceHeader.__SIZE)

        # Write some unknown fluff.
        self.get_bytes()[20:] = array.array('B', '\x01\x00\x00\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_header_size(self):
        return SVCCTLStopServiceHeader.__SIZE


class SVCCTLRespStopServiceHeader(ImpactPacket.Header):
    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespStopServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(28, '<')
    def set_return_code(self, code):
        self.set_long(28, code, '<')


    def get_header_size(self):
        return SVCCTLRespStopServiceHeader.__SIZE


class SVCCTLStartServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x1F

    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLStartServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_arguments(self):
        raise Exception, "method not implemented"
    def set_arguments(self, arguments):
        args_data = apply(pack, ['<' + 'L'*len(arguments)] + map(id, arguments) )
        args_data += reduce(lambda a, b: a+b,
                            map(lambda element: pack('<LLL', len(element)+1, 0, len(element)+1) + element + '\x00' + '\x00' * ((4 - (len(element) + 1) % 4) % 4), arguments),
                            '')
        data = pack('<LLL', len(arguments), id(arguments), len(arguments)) + args_data
        self.get_bytes()[20:] = array.array('B', data)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SVCCTLStartServiceHeader.__SIZE
        assert var_size > 0
        return SVCCTLStartServiceHeader.__SIZE + var_size


class SVCCTLRespStartServiceHeader(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespStartServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return SVCCTLRespStartServiceHeader.__SIZE


class DCERPCSvcCtl:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def open_manager(self):
        hostname = 'IMPACT'
        opensc = SVCCTLOpenSCManagerHeader()
        opensc.set_machine_name(hostname)
        self._dcerpc.send(opensc)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespOpenSCManagerHeader(data)
        return retVal

    def create_service(self, context_handle, service_name, service_path):
        creates = SVCCTLCreateServiceHeader()
        creates.set_context_handle(context_handle)
        creates.set_service_name(service_name)
        creates.set_service_path(service_path)
        self._dcerpc.send(creates)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespCreateServiceHeader(data)
        return retVal

    def close_handle(self, context_handle):
        closeh = SVCCTLCloseServiceHeader()
        closeh.set_context_handle(context_handle)
        self._dcerpc.send(closeh)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespCloseServiceHeader(data)
        return retVal

    def delete_service(self, context_handle):
        deletes = SVCCTLDeleteServiceHeader()
        deletes.set_context_handle(context_handle)
        self._dcerpc.send(deletes)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespDeleteServiceHeader(data)
        return retVal

    def open_service(self, context_handle, service_name):
        opens = SVCCTLOpenServiceHeader()
        opens.set_context_handle(context_handle)
        opens.set_service_name(service_name)
        self._dcerpc.send(opens)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespOpenServiceHeader(data)
        return retVal

    def stop_service(self, context_handle):
        stops = SVCCTLStopServiceHeader()
        stops.set_context_handle(context_handle)
        self._dcerpc.send(stops)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespStopServiceHeader(data)
        return retVal

    def start_service(self, context_handle, arguments):
        starts = SVCCTLStartServiceHeader()
        starts.set_arguments( arguments )
        starts.set_context_handle(context_handle)
        self._dcerpc.send(starts)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespStartServiceHeader(data)
        return retVal
