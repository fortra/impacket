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
# Author: Alberto Solino
#
# Description:
#   WinReg (Windows Registry) interface implementation.
#
# ToDo:
# [ ] Port all this to structure. Check svcctl.py

import array
import struct

from impacket import dcerpc
from impacket.dcerpc import ndrutils
from impacket import ImpactPacket
from impacket.uuid import uuidtup_to_bin


MSRPC_UUID_WINREG = uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0'))

# Registry Security Access Mask values
KEY_CREATE_LINK         = 0x20
KEY_CREATE_SUB_KEY      = 0x04
KEY_ENUMERATE_SUB_KEYS  = 0x08
KEY_EXECUTE             = 0x20019
KEY_NOTIFY              = 0x10
KEY_QUERY_VALUE         = 0x01
KEY_SET_VALUE           = 0x02
KEY_ALL_ACCESS          = 0xF003F
KEY_READ                = 0x20019
KEY_WRITE               = 0x20006

# Registry Data types
REG_NONE                = 0    # No value type
REG_SZ                  = 1    # Unico nul terminated string
REG_EXPAND_SZ           = 2    # Unicode nul terminated string
                               # (with environment variable references)
REG_BINARY              = 3 #   // Free form binary
REG_DWORD                =    4 #   // 32-bit number
REG_DWORD_LITTLE_ENDIAN =   4 #   // 32-bit number (same as REG_DWORD)
REG_DWORD_BIG_ENDIAN    =    5 #   // 32-bit number
REG_LINK                =     6 #   // Symbolic Link (unicode)
REG_MULTI_SZ            =     7 #   // Multiple Unicode strings
REG_RESOURCE_LIST       =     8 #   // Resource list in the resource map
REG_FULL_RESOURCE_DESCRIPTOR  = 9   # Resource list in the hardware description
REG_RESOURCE_REQUIREMENTS_LIST  = 10

class WINREGQueryInfoKey(ImpactPacket.Header):
# Just the class info stuff for now
    OP_NUM = 16
    __SIZE = 40

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGQueryInfoKey.__SIZE)
        self.set_word(20, 0, '<')
        self.set_word(22, 520, '<')
        self.set_long(24,0x2,'<')
        self.set_long(28, 260, '<')
        self.set_long(32, 0, '<')
        self.set_long(34, 0, '<')
        self.set_word(36, 0, '<')

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]

    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGQueryInfoKey.__SIZE
        assert var_size > 0
        return WINREGQueryInfoKey.__SIZE + var_size

class WINREGRespQueryInfoKey(ImpactPacket.Header):
    OP_NUM = 16
    __SIZE = 0

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespQueryInfoKey.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_class_data(self):
        length = self.get_word(0, '<')
        return unicode(self.get_bytes().tostring()[20:20+length], 'utf-16le')

    def get_return_code(self):
        return self.get_long(-4, '<')

    def set_return_code(self, code):
        self.set_long(-4, code, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGRespQueryInfoKey.__SIZE
        assert var_size > 0
        return WINREGRespQueryInfoKey.__SIZE + var_size


class WINREGSaveKey(ImpactPacket.Header):
    OP_NUM = 20
    __SIZE = 72

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGSaveKey.__SIZE)

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]

    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_file_name(self):
        return unicode(self.get_bytes().tostring()[40:-4], 'utf-16le')

    def set_file_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        wlen = 2 * namelen
        if (wlen % 4):
            pad = ('\x00' * (4 - (wlen % 4)))
        else:
            pad = ''

        self.set_word(20, 2 * namelen, '<')
        self.set_word(22, 2 * namelen, '<')
        self.set_long(24, 0x2, '<')
        self.set_long(28, namelen, '<')
        self.set_long(36, namelen, '<')
        self.get_bytes()[40:] = array.array('B', name.encode('utf-16le') + pad + '\x00'*4)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGSaveKey.__SIZE
        assert var_size > 0
        return WINREGSaveKey.__SIZE + var_size


class WINREGRespSaveKey(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespSaveKey.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return WINREGRespSaveKey.__SIZE



class WINREGCloseKey(ImpactPacket.Header):
    OP_NUM = 5

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGCloseKey.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_header_size(self):
        return WINREGCloseKey.__SIZE


class WINREGRespCloseKey(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespCloseKey.__SIZE)
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
        return WINREGRespCloseKey.__SIZE


class WINREGDeleteValue(ImpactPacket.Header):
    OP_NUM = 8

    __SIZE = 40

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGDeleteValue.__SIZE)

        # Write some unknown fluff.
        self.get_bytes()[22:36] = array.array('B', '\x0a\x02\x00\xEC\xfd\x7f\x05\x01' + (6 * '\x00'))

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_name(self):
        return unicode(self.get_bytes().tostring()[40:], 'utf-16le')
    def set_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        wlen = 2 * namelen
        if (wlen % 4):
            pad = ('\x00' * (4 - (wlen % 4)))
        else:
            pad = ''

        self.set_word(20, 2 * namelen, '<')
        self.set_long(36, namelen, '<')
        self.get_bytes()[40:] = array.array('B', name.encode('utf-16le') + pad)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGDeleteValue.__SIZE
        assert var_size > 0
        return WINREGDeleteValue.__SIZE + var_size


class WINREGRespDeleteValue(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespDeleteValue.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return WINREGRespDeleteValue.__SIZE


class WINREGDeleteKey(ImpactPacket.Header):
    OP_NUM = 7

    __SIZE = 40

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGDeleteKey.__SIZE)

        # Write some unknown fluff.
        self.get_bytes()[22:36] = array.array('B', '\x0a\x02\x00\xEC\xfd\x7f\x05\x01' + (6 * '\x00'))

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_key_name(self):
        return unicode(self.get_bytes().tostring()[40:], 'utf-16le')
    def set_key_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        wlen = 2 * namelen
        if (wlen % 4):
            pad = ('\x00' * (4 - (wlen % 4)))
        else:
            pad = ''

        self.set_word(20, 2 * namelen, '<')
        self.set_long(36, namelen, '<')
        self.get_bytes()[40:] = array.array('B', name.encode('utf-16le') + pad)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGDeleteKey.__SIZE
        assert var_size > 0
        return WINREGDeleteKey.__SIZE + var_size


class WINREGRespDeleteKey(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespDeleteKey.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return WINREGRespDeleteKey.__SIZE


class WINREGCreateKey(ImpactPacket.Header):
    OP_NUM = 6

    __SIZE = 64

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGCreateKey.__SIZE)

        # Write some unknown fluff.
        self.get_bytes()[22:36] = array.array('B', '\x0a\x02\x00\xEC\xfd\x7f\x05\x01' + (6 * '\x00'))
        self.get_bytes()[-24:] = array.array('B', 15 * '\x00' + '\x02' + 8 * '\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_key_name(self):
        return unicode(self.get_bytes().tostring()[40:-24], 'utf-16le')
    def set_key_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        wlen = 2 * namelen
        if (wlen % 4):
            pad = ('\x00' * (4 - (wlen % 4)))
        else:
            pad = ''

        self.set_word(20, 2 * namelen, '<')
        self.set_long(36, namelen, '<')
        self.get_bytes()[40:-24] = array.array('B', name.encode('utf-16le') + pad)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGCreateKey.__SIZE
        assert var_size > 0
        return WINREGCreateKey.__SIZE + var_size


class WINREGRespCreateKey(ImpactPacket.Header):
    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespCreateKey.__SIZE)
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
        return WINREGRespCreateKey.__SIZE


#context handle
# WORD LEN (counting the 0s)
# DWORD LEN (in unicode, that is without counting the 0s)
# KEYNAME in UNICODE
# 6 bytes UNKNOWN (all 0s)
# DWORD ACCESS_MASK

class WINREGOpenKey(ImpactPacket.Header):
    OP_NUM = 15

    __SIZE = 44

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGOpenKey.__SIZE)

        self.set_access_mask(KEY_READ)

        # Write some unknown fluff.
        self.get_bytes()[24:28] = array.array('B', '\x00\xEC\xfd\x7f')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_key_name(self):
        return unicode(self.get_bytes().tostring()[40:-4], 'utf-16le')
    def set_key_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        ndrStr = ndrutils.NDRStringW()
        ndrStr['Data'] = name.encode('utf-16le')
        self.set_word(20, 2 * namelen, '<')
        self.set_word(22, 2 * namelen, '<')
        self.get_bytes()[28:-4] = array.array('B',str(ndrStr) + '\x00' * 4)

    def get_access_mask(self):
        return self.get_long(-4, '<')
    def set_access_mask(self, mask):
        self.set_long(-4, mask, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGOpenKey.__SIZE
        assert var_size > 0
        return WINREGOpenKey.__SIZE + var_size


class WINREGRespOpenKey(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespOpenKey.__SIZE)
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
        return WINREGRespOpenKey.__SIZE


class WINREGSetValue(ImpactPacket.Header):
    OP_NUM = 22

    __SIZE = 52

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGSetValue.__SIZE)

        # Write some unknown fluff.
        self.get_bytes()[24:28] = array.array('B', '\x00\xEC\xfd\x7f')
        self.namelen = 0

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_name(self):
        return unicode(self.get_bytes().tostring()[40:40+self.namelen], 'utf-16le')
    def set_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        if namelen & 0x01:
            pad = '\x00\x00'
        else:
            pad = ''

        self.set_word(20, 2 * namelen, '<')
        self.set_word(22, 2 * namelen, '<')
        self.set_long(28, namelen, '<')
        self.set_long(36, namelen, '<')
        padded_name = array.array('B', name.encode('utf-16le') + pad)
        self.get_bytes()[40:40+self.namelen] = padded_name
        self.namelen = len(padded_name)

    def get_data_type(self):
        return self.get_long(40+self.namelen, '<')
    def set_data_type(self, type):
        self.set_long(40+self.namelen, type, '<')

    def get_data(self):
        data_type = self.get_data_type()
        data = self.get_bytes().tostring()[40+self.namelen+8:-4]
        if data_type == REG_DWORD:
            data = struct.unpack('<L', data)[0]
        elif data_type == REG_SZ:
            data = unicode(data, 'utf-16le')
        return data

    def set_data(self, data):
        data_type = self.get_data_type()
        pad = ''
        if data_type == REG_DWORD:
            data = struct.pack('<L', data)
        elif data_type == REG_SZ:
            if not data.endswith('\0'):
                data += '\0'
            if len(data) & 0x01:
                pad = '\x00\x00'
            data = data.encode('utf-16le')
        elif data_type == REG_BINARY:
            if len(data) & 0x01:
                pad = '\x00\x00'

        datalen = len(data)
        self.set_long(40+self.namelen+4, datalen, '<')
        self.set_long(-4, datalen, '<')
        self.get_bytes()[40+self.namelen+8:-4] = array.array('B', data + pad)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGSetValue.__SIZE
        assert var_size > 0
        return WINREGSetValue.__SIZE + var_size


class WINREGRespSetValue(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespSetValue.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return WINREGRespSetValue.__SIZE


# context_handle
# len
# \x0a\x02\x00\xec\xfd\x7f\x05\x01 \x00 * 6
# len /2
# valuename

class WINREGQueryValue(ImpactPacket.Header):
    OP_NUM = 17

    __SIZE = 80

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGQueryValue.__SIZE)

        self.set_data_len(0xC8)

        # Write some unknown fluff.
        self.get_bytes()[24:28] = array.array('B', '\x00\xEC\xfd\x7f')
        self.get_bytes()[-40:-28] = array.array('B', '\x8c\xfe\x12\x00\x69\x45\x13\x00\x69\x45\x13\x00')
        self.get_bytes()[-16:-12] = array.array('B', '\x94\xfe\x12\x00')
        self.get_bytes()[-8:-4] = array.array('B', '\x80\xfe\x12\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_name(self):
        return unicode(self.get_bytes().tostring()[40:-40], 'utf-16le')
    def set_name(self, name):
        if not name.endswith('\0'):
            name += '\0'
        namelen = len(name)
        if namelen & 0x01:
            pad = '\x00\x00'
        else:
            pad = ''

        self.set_word(20, 2 * namelen, '<')
        self.set_word(22, 2 * namelen, '<')
        self.set_long(28, namelen, '<')
        self.set_long(36, namelen, '<')
        self.get_bytes()[40:-40] = array.array('B', name.encode('utf-16le') + pad)

    def get_data_len(self):
        return self.get_long(-28, '<')
    def set_data_len(self, len):
        self.set_long(-28, len, '<')
        self.set_long(-12, len, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGQueryValue.__SIZE
        assert var_size > 0
        return WINREGQueryValue.__SIZE + var_size


class WINREGRespQueryValue(ImpactPacket.Header):
    __SIZE = 44

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespQueryValue.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_data_type(self):
        return self.get_long(4, '<')
    def set_data_type(self, type):
        self.set_long(4, type, '<')

    def get_data_len(self):
        return self.get_long(20, '<')
    def set_data_len(self, len):
        self.set_long(20, len, '<')
        self.set_long(28, len, '<')

    def get_data(self):
        data_type = self.get_data_type()
        data = self.get_bytes().tostring()[24:24+self.get_data_len()]
        if data_type == REG_DWORD:
            data = struct.unpack('<L', data)[0]
        elif data_type == REG_SZ:
            data = unicode(data, 'utf-16le')

        return data

    def set_data(self, len):
        raise Exception, "method not implemented"

    def get_return_code(self):
        return self.get_long(-4, '<')
    def set_return_code(self, code):
        self.set_long(-4, code, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - WINREGRespQueryValue.__SIZE
        assert var_size > 0
        return WINREGRespQueryValue.__SIZE + var_size


class WINREGOpenHK(ImpactPacket.Header):
    # OP_NUM is a "virtual" field.

    __SIZE = 12

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGOpenHK.__SIZE)

        self.set_long(0, 0x06f7c0, '<') # magic, apparently always the same
        self.set_long(4, 0x019b58, '<') # don't know exactly, can be almost anything so far
        self.set_access_mask(0x2000000)

        if aBuffer: self.load_header(aBuffer)

    def get_access_mask(self):
        return self.get_long(8, '<')
    def set_access_mask(self, mask):
        self.set_long(8, mask, '<')


    def get_header_size(self):
        return WINREGOpenHK.__SIZE


class WINREGRespOpenHK(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, WINREGRespOpenHK.__SIZE)
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
        return WINREGRespOpenHK.__SIZE


class WINREGOpenHKCR(WINREGOpenHK):
    OP_NUM = 0

class WINREGOpenHKLM(WINREGOpenHK):
    OP_NUM = 2

class WINREGOpenHKU(WINREGOpenHK):
    OP_NUM = 4


class DCERPCWinReg:
    def __init__(self, dce):
        self._dce = dce

    def openHKCR(self):
        winregopen = WINREGOpenHKCR()
        self._dce.send(winregopen)
        data = self._dce.recv()
        retVal = WINREGRespOpenHK(data)
        return retVal

    def openHKU(self):
        winregopen = WINREGOpenHKU()
        self._dce.send(winregopen)
        data = self._dce.recv()
        retVal = WINREGRespOpenHK(data)
        return retVal

    def regCloseKey(self, context_handle):
        wreg_closekey = WINREGCloseKey()
        wreg_closekey.set_context_handle( context_handle )
        self._dce.send(wreg_closekey)
        data = self._dce.recv()
        retVal = WINREGRespCloseKey(data)
        return retVal

    def regOpenKey(self, context_handle, aKeyname, anAccessMask):
        wreg_openkey = WINREGOpenKey()
        wreg_openkey.set_context_handle( context_handle )
        wreg_openkey.set_key_name( aKeyname )
        wreg_openkey.set_access_mask( anAccessMask )
        self._dce.send(wreg_openkey)
        data = self._dce.recv()
        retVal = WINREGRespOpenKey(data)
        return retVal

    def regCreateKey(self, context_handle, aKeyname):
        wreg_createkey = WINREGCreateKey()
        wreg_createkey.set_context_handle( context_handle )
        wreg_createkey.set_key_name( aKeyname )
        self._dce.send(wreg_createkey)
        data = self._dce.recv()
        retVal = WINREGRespCreateKey(data)
        return retVal

    def regDeleteKey(self, context_handle, aKeyname):
        wreg_deletekey = WINREGDeleteKey()
        wreg_deletekey.set_context_handle( context_handle )
        wreg_deletekey.set_key_name( aKeyname )
        self._dce.send(wreg_deletekey)
        data = self._dce.recv()
        retVal = WINREGRespDeleteKey(data)
        return retVal

    def regDeleteValue(self, context_handle, aValuename):
        wreg_deletevalue = WINREGDeleteValue()
        wreg_deletevalue.set_context_handle( context_handle )
        wreg_deletevalue.set_name( aValuename )
        self._dce.send(wreg_deletevalue)
        data = self._dce.recv()
        retVal = WINREGRespDeleteValue(data)
        return retVal

    def regQueryValue(self, context_handle, aValueName, aDataLen):
        wreg_queryval = WINREGQueryValue()
        wreg_queryval.set_context_handle( context_handle )
        wreg_queryval.set_name( aValueName )
        wreg_queryval.set_data_len( aDataLen )
        self._dce.send(wreg_queryval)
        data = self._dce.recv()
        retVal = WINREGRespQueryValue(data)
        return retVal

    def regSetValue(self, context_handle, aValueType, aValueName, aData):
        wreg_setval = WINREGSetValue()
        wreg_setval.set_context_handle( context_handle )
        wreg_setval.set_data_type(aValueType)
        wreg_setval.set_name(aValueName)
        wreg_setval.set_data(aData)
        self._dce.send(wreg_setval)
        data = self._dce.recv()
        retVal = WINREGRespSetValue(data)
        return retVal

    def regSaveKey(self, context_handle, fileName):
        wreg_savekey = WINREGSaveKey()
        wreg_savekey.set_context_handle( context_handle )
        wreg_savekey.set_file_name(fileName)
        self._dce.send(wreg_savekey)
        data = self._dce.recv()
        retVal = WINREGRespSaveKey(data)
        return retVal

    def regGetClassInfo(self, context_handle):
        query_key = WINREGQueryInfoKey()
        query_key.set_context_handle(context_handle)
        self._dce.send(query_key)
        data = self._dce.recv()
        retVal = WINREGRespQueryInfoKey(data)
        return retVal

    def openHKLM(self):
        winregopen = WINREGOpenHKLM()
        self._dce.send(winregopen)
        data = self._dce.recv()
        retVal = WINREGRespOpenHK(data)
        return retVal

