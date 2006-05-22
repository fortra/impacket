# ---
# $Id$
#
# Description:
#   SRVSVC interface implementation.
#
# Author:
#   Javier Burroni (javier)
#
# Copyright (c) 2001-2004 CORE Security Technologies, CORE SDI Inc.
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
import exceptions

from impacket import ImpactPacket
import dcerpc
import ndrutils

MSRPC_UUID_SRVSVC = '\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x03\x00\x00\x00'

class SRVSVCNetShareGetInfoHeader(ImpactPacket.Header):
    OP_NUM = 0x10
    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SRVSVCNetShareGetInfoHeader.__SIZE)

        self._set_shalen(0)
        self._set_serlen(0)

        self.set_server_referent_id(0x0011bf74)
        self.set_server_max_count(0)
        self.set_server_offset(0)
        self.set_server_actual_count(0)
        self.set_server('')
        self.set_share_max_count(0)
        self.set_share_offset(0)        
        self.set_share_actual_count(0)
        self.set_share('')
        self.set_info_level(0)

        if aBuffer: self.load_header(aBuffer)

    def get_server_referent_id(self):
        return self.get_long(0, '<')
    
    def set_server_referent_id(self, id):
        self.set_long(0, id, '<')

    def get_server_max_count(self):
        return self.get_long(4, '<')

    def set_server_max_count(self, count):
        self.set_long(4, count, '<')

    def get_server_offset(self):
        return self.get_long(8, '<')

    def set_server_offset(self, offset):
        self.set_long(8, offset, '<')

    def get_server_actual_count(self):
        return self.get_long(12, '<')

    def set_server_actual_count(self, count):
        self.set_long(12, count, '<')

    def set_server(self, name):
        pad = ''
        if len(name) % 4:
            pad = '\0' * (4 - len(name) % 4)
        name = name + pad
        ## 4 bytes congruency
        self.get_bytes()[16:16 + len(name)] = array.array('B', name)
        self._set_serlen(len(name))

    def _set_serlen(self, len):
        self._serlen = len

    def _get_serlen(self):
        return self._serlen

    def _set_shalen(self, len):
        self._shalen = len

    def _get_shalen(self):
        return self._shalen

    def get_share_max_count(self):
        server_max_count = self._get_serlen()
        return self.get_long(16 + server_max_count, '<')
    
    def set_share_max_count(self, count):
        server_max_count = self._get_serlen()
        self.set_long(16 + server_max_count, count, '<')

    def get_share_offset(self):
        server_max_count = self._get_serlen()
        return self.get_long(20 + server_max_count, '<')

    def set_share_offset(self, offset):
        server_max_count = self._get_serlen()
        self.set_long(20 + server_max_count, offset, '<')

    def get_share_actual_count(self):
        server_max_count = self._get_serlen()
        return self.get_long(24 + server_max_count, '<')

    def set_share_actual_count(self, count):
        server_max_count = self._get_serlen()
        self.set_long(24 + server_max_count, count, '<')

    def set_share(self, share):
        server_max_count = self._get_serlen()
        pad = ''
        if len(share) % 4:
           pad = '\0' * (4 - len(share) % 4) 
        share = share + pad
        self.get_bytes()[28 + server_max_count:28 + len(share)] = array.array('B', share)
        self._set_shalen(len(share))

    def get_info_level(self):
        server_max_count = self._get_serlen()
        share_max_count = self._get_shalen()
        return self.get_long(28 + server_max_count + share_max_count, '<')

    def set_info_level(self, level):
        server_max_count = self._get_serlen()
        share_max_count = self._get_shalen()
        self.set_long(28 + server_max_count + share_max_count, level, '<')

    def get_header_size(self):
        server_max_count = self._get_serlen()
        share_max_count = self._get_shalen()
        return SRVSVCNetShareGetInfoHeader.__SIZE + server_max_count + share_max_count
    

class SRVSVCRespNetShareGetInfoHeader(ImpactPacket.Header):
    __SIZE = 8

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SRVSVCRespNetShareGetInfoHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_info_level(self):
        return self.get_long(0, '<')

    def set_info_level(self, level):
        self.set_long(0, level, '<')

    def set_share_info(self, info):
        raise exceptions.Exception, "method not implemented"

    def get_share_info(self):
        level = self.get_info_level()
        if level == 2:
            return ndrutils.NDRPointer(self.get_bytes()[4:-4].tostring(), ShareInfoLevel2Entry)
        else:
            raise exceptions.Exception, "Share Info level not supported"

    def get_return_code(self):
        return self.get_long(len(self.get_bytes())-4, '<')

    def get_header_size(self):
        return len(self.get_bytes())

class ShareInfoLevel2Entry:
    def __init__(self, data = ''):
        self.set_netname(0)
        self.set_remark(0)
        self.set_path(0)
        self.set_passwd(0)
        if data:
            p_netname, self._type, p_remark, self._permissions, self._max_uses, \
                       self._current_uses, p_path, p_passwd = unpack('<LLLLLLLL', data[: 8 * 4])
            data = data[8 * 4:]
            if p_netname:
                self.set_netname(ndrutils.NDRString(data))
                dlen = self.get_netname().get_max_len() * 2
                pad = 0
                if dlen % 4:
                    pad = 4 - dlen % 4
                data = data[12 + dlen + pad:]
            if p_remark:
                self.set_remark(ndrutils.NDRString(data))
                dlen = self.get_remark().get_max_len() * 2
                pad = 0
                if dlen % 4:
                    pad = 4 - dlen % 4
                data = data[12 + dlen + pad:]                
            if p_path:
                self.set_path(ndrutils.NDRString(data))
                dlen = self.get_path().get_max_len() * 2
                pad = 0
                if dlen % 4:
                    pad = 4 - dlen % 4
                data = data[12 + dlen + pad:]                
            if p_passwd:
                self.set_passwd(ndrutils.NDRString(data))
                dlen = self.get_passwd().get_max_len() * 2
                pad = 0
                if dlen % 4:
                    pad = 4 - dlen % 4
                data = data[12 + dlen + pad:]

    def set_netname(self, netname):
        self._netname = netname

    def get_netname(self):
        return self._netname

    def set_remark(self, remark):
        self._remark = remark

    def get_remark(self):
        return self._remark

    def set_path(self, path):
        self._path = path

    def get_path(self):
        return self._path

    def set_passwd(self, passwd):
        self._passwd = passwd

    def get_passwd(self):
        return self._passwd

    def get_type(self):
        return self._type

    def get_permissions(self):
        return self._permissions

    def get_max_uses(self):
        return self._max_uses

    def get_current_uses(self):
        return self._current_uses
    
        

class DCERPCSrvSvc:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def get_share_info(self, server, share, level):
        server += '\0'
        share += '\0'
        server = server.encode('utf-16le')
        share = share.encode('utf-16le')
        info = SRVSVCNetShareGetInfoHeader()
        server_len = len(server)
        share_len = len(share)
        info.set_server_max_count(server_len / 2)
        info.set_server_actual_count(server_len / 2)
        info.set_server(server)
        info.set_share_max_count(share_len / 2)
        info.set_share_actual_count(share_len / 2)
        info.set_share(share)
        info.set_info_level(2)
        self._dcerpc.send(info)
        data = self._dcerpc.recv()
        retVal = SRVSVCRespNetShareGetInfoHeader(data)
        return retVal

    

        
