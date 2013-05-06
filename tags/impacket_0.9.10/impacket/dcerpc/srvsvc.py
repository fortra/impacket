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
#   SRVSVC interface implementation.
#
# TODO: NetServerEnum2 

import array
from struct import *
import exceptions

from impacket import ImpactPacket
from impacket.structure import Structure
from impacket import dcerpc
from impacket.dcerpc import ndrutils
from impacket.uuid import uuidtup_to_bin


MSRPC_UUID_SRVSVC = uuidtup_to_bin(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'))

# We should move this to ndrutils.py once we port it to structure
class NDRString(Structure):
    alignment = 4
    structure = (
    ('sName','w'),
    )

class SRVSVCShareEnumStruct(Structure):
    alignment = 4
    structure = (
	('Level','<L'),
	('pCount','<L=1'),
	('Count','<L'),
	('pMaxCount','<L&MaxCount'),
	('MaxCount','<L'),
    )

class SRVSVCShareInfo1(Structure):
    alignment = 4
    structure = (
	('pNetName','<L'),
	('Type','<L'),
	('pRemark','<L'),
   )

class SRVSVCShareInfo2(Structure):
    alignment = 4
    structure = (
	('pNetName','<L&NetName'),
	('Type','<L'),
	('pRemark','<L&Remark'),
	('Permissions','<L'),
	('Max_Uses','<L'),
	('Current_Uses','<L'),
	('pPath','<L&Path'),
	('pPassword','<L&Password'),
	('NetName','w'),
	('Remark','w'),
	('Path','w'),
	('Password','w'),
)

class SRVSVCSwitchpShareInfo2(Structure):
    alignment = 4
    structure = (
	('Level','<L'),
	('pInfo','<L&InfoStruct'),
	('InfoStruct',':',SRVSVCShareInfo2),
    )

class SRVSVCServerInfo102(Structure):
    alignment = 4
    structure = (
       ('PlatFormID','<L'),
       ('pName','<L=&Name'),
       ('VersionMajor','<L'),
       ('VersionMinor','<L'),
       ('Type','<L'),
       ('pComment','<L=&Commet'),
       ('Users','<L'),
       ('DisconnectTime','<L'),
       ('IsHidden','<I'),
       ('Announce','<L'),
       ('AnnounceDelta','<L'),
       ('Licenses','<L'),
       ('pUserPath','<L=&Path'),
       ('Name','w'),
       ('Comment','w'),
       ('UserPath','w'),
    )

class SRVSVCServerpInfo102(Structure):
    alignment = 4
    structure = (
       ('Level','<L'),
       ('pInfo','<L&ServerInfo'),
       ('ServerInfo',':',SRVSVCServerInfo102),
    )


class SRVSVCServerInfo101(Structure):
    alignment = 4
    structure = (
       ('PlatFormID','<L=500'),
       ('pName','<L&Name'),
       ('VersionMajor','<L=5'),
       ('VersionMinor','<L=0'),
       ('Type','<L=1'),
       ('pComment','<L&Comment'),
       ('Name','w'),
       ('Comment','w'),
    )

class SRVSVCServerpInfo101(Structure):
    alignment = 4
    structure = (
       ('Level','<L=101'),
       ('pInfo','<L&ServerInfo'),
       ('ServerInfo',':',SRVSVCServerInfo101),
    )
 

class SRVSVCTimeOfDayInfo(Structure):
    alignment = 4
    structure = (
       ('Elapsedt','<H'),
       ('MSecs','<H'),
       ('Hours','<H'),
       ('Mins','<H'),
       ('Secs','<H'),
       ('Hunds','<H'),
       ('TimeZone','<L'),
       ('TInterval','<H'),
       ('Day','<H'),
       ('Month','<H'),
       ('Year','<H'),
       ('Weekday','<H'),
    )
class SRVSVCpTimeOfDayInfo(Structure):
    alignment = 4
    structure = (
       ('pData','<L=&Data'),
       ('Data',':',SRVSVCTimeOfDayInfo),
    )

######### FUNCTIONS ###########

class SRVSVCNetrShareGetInfo(Structure):
    opnum = 16
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('NetName','w'),
       ('Level','<L=2'),
    )

class SRVSVCNetrServerGetInfo(Structure):
    opnum = 21
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('Level','<L=102'),
    )

class SRVSVCNetrShareEnum(Structure):
    opnum = 15
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('Level','<L=0x1'),
       ('pShareEnum','<L=0x1'),
       ('p2','<L=0x5678'),
       ('count','<L=0'),
       ('NullP','<L=0'),
       ('PreferedMaximumLength','<L=0xffffffff'),
       ('pResumeHandler',':'),
    )

    def getData(self):
       self['pResumeHandler'] = '\xbc\x9a\x00\x00\x00\x00\x00\x00'
       return Structure.getData(self)

class SRVSVCNetrShareEnum1_answer(Structure):
    alignment = 4
    structure = (
	('pLevel','<L=1'),
	('Info',':',SRVSVCShareEnumStruct),
# Not catched by the unpacker - just for doc purposed.
#	('pTotalEntries','<L=&TotalEntries'),
#	('TotalEntries','<L'),
#	('pResumeHandler','<L=&ResumeHandler'),
#	('ResumeHandler','<L'),
    )

class SRVSVCNetrRemoteTOD(Structure):
    opnum = 28
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w')
    )

class SRVSVCNetprNameCanonicalize(Structure):
    opnum = 34
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('Name','w'),
       ('OutbufLen','<H'),
       ('NameType','<H'),
       ('Flags','<H')
    )

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

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                raise Exception, 'DCE-RPC call returned an error.'
            return answer

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

#NetrShareEnum() with Level1 Info
    def get_share_enum_1(self,server):
    	shareEnum = SRVSVCNetrShareEnum()
    	shareEnum['ServerName'] = (server+'\x00').encode('utf-16le')
    	data = self.doRequest(shareEnum, checkReturn = 1)
        b = SRVSVCNetrShareEnum1_answer().fromString(data)
        shareInfoList = []
        index = len(b)
        for i in range(b['Info']['Count']):
            tmp_dict = {}
            shareInfo = SRVSVCShareInfo1().fromString(data[index:])
            tmp_dict['Type']=shareInfo['Type']
            shareInfoList.append(tmp_dict)
            index += len(shareInfo)
        for i in range(b['Info']['Count']):
            ndr_str = NDRString().fromString(data[index:])
            shareInfoList[i]['NetName'] = ndr_str['sName']
            index += len(ndr_str)
            ndr_str = NDRString().fromString(data[index:])
            shareInfoList[i]['Remark'] = ndr_str['sName']
            index += len(ndr_str)
    	return shareInfoList

#NetrShareGetInfo() with Level2 Info
    def get_share_info_2(self, server, share):
    	shareInfoReq = SRVSVCNetrShareGetInfo()
    	shareInfoReq['Level'] = 2
    	shareInfoReq['ServerName'] = (server+'\x00').encode('utf-16le')
    	shareInfoReq['NetName'] = (share+'\x00').encode('utf-16le')
    	ans = self.doRequest(shareInfoReq, checkReturn = 1)
    	return SRVSVCSwitchpShareInfo2(ans)    

#NetrServerGetInfo() with Level 102 Info
    def get_server_info_102(self, server):
      serverInfoReq = SRVSVCNetrServerGetInfo()
      serverInfoReq['ServerName'] = (server+'\x00').encode('utf-16le')
      data = self.doRequest(serverInfoReq, checkReturn = 1)  
      return SRVSVCServerpInfo102(data)['ServerInfo']

#NetrRemoteTOD()
    def NetrRemoteTOD(self, server):
      remoteTODReq = SRVSVCNetrRemoteTOD()
      remoteTODReq['ServerName'] = (server+'\x00').encode('utf-16le')
      data = self.doRequest(remoteTODReq, checkReturn = 1)
      return SRVSVCpTimeOfDayInfo(data)

#NetprNameCanonicalize
    def NetprNameCanonicalize( self, serverName, name, bufLen, nameType ):
      NameCReq = SRVSVCNetprNameCanonicalize()
      NameCReq['ServerName'] = (serverName+'\x00').encode('utf-16le')
      NameCReq['Name'] = (name+'\x00').encode('utf-16le')
      NameCReq['OutbufLen'] = bufLen
      NameCReq['NameType'] = nameType
      NameCReq['Flags'] = 0x0
      data = self.doRequest(NameCReq, checkReturn = 1)
      return data

