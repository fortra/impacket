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
#   [MS-SRVS] interface implementation.
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

# Error Codes
ERROR_ACCESS_DENIED             = 0x00000005
ERROR_INVALID_LEVEL             = 0x0000007C
ERROR_INVALID_PARAMETER         = 0x00000057
ERROR_MORE_DATA                 = 0x000000EA
ERROR_NOT_ENOUGH_MEMORY         = 0x00000000
ERROR_FILE_NOT_FOUND            = 0x00000002
ERROR_DUP_NAME                  = 0x00000034
ERROR_INVALID_DOMAINNAME        = 0x000004BC
ERROR_NOT_SUPPORTED             = 0x00000032
ERROR_SERVICE_DOES_NOT_EXIST    = 0x00000424
NERR_BufTooSmall                = 0x0000084B
NERR_ClientNameNotFound         = 0x00000908
NERR_InvalidComputer            = 0x0000092F
NERR_UserNotFound               = 0x000008AD
NERR_DuplicateShare             = 0x00000846
NERR_RedirectedPath             = 0x00000845
NERR_UnknownDevDir              = 0x00000844
NERR_NetNameNotFound            = 0x00000906
NERR_DeviceNotShared            = 0x00000907
NERR_DuplicateShare             = 0x00000846

class SRVSVCSessionError(Exception):
    error_messages = {
 ERROR_ACCESS_DENIED          : ("ERROR_ACCESS_DENIED", "The user does not have access to the requested information."),          
 ERROR_INVALID_LEVEL          : ("ERROR_INVALID_LEVEL", "The value that is specified for the level parameter is invalid."),          
 ERROR_INVALID_PARAMETER      : ("ERROR_INVALID_PARAMETER", "One or more of the specified parameters is invalid."),          
 ERROR_MORE_DATA              : ("ERROR_MORE_DATA", "More entries are available. Specify a large enough buffer to receive all entries."),          
 ERROR_NOT_ENOUGH_MEMORY      : ("ERROR_NOT_ENOUGH_MEMORY", "Not enough storage is available to process this command."),          
 ERROR_FILE_NOT_FOUND         : ("ERROR_FILE_NOT_FOUND", "The system cannot find the file specified."),          
 ERROR_DUP_NAME               : ("ERROR_DUP_NAME", "A duplicate name exists on the network."),          
 ERROR_INVALID_DOMAINNAME     : ("ERROR_INVALID_DOMAINNAME", "The format of the specified NetBIOS name of a domain is invalid."),          
 ERROR_NOT_SUPPORTED          : ("ERROR_NOT_SUPPORTED", "The server does not support branch cache."),          
 ERROR_SERVICE_DOES_NOT_EXIST : ("ERROR_SERVICE_DOES_NOT_EXIST", "The branch cache component does not exist as an installed service."),          
 NERR_BufTooSmall             : ("NERR_BufTooSmall", "The client request succeeded. More entries are available. The buffer size that is specified by PreferedMaximumLength was too small to fit even a single entry."),          
 NERR_ClientNameNotFound      : ("NERR_ClientNameNotFound", "A session does not exist with the computer name."),          
 NERR_InvalidComputer         : ("NERR_InvalidComputer", "The computer name is not valid."), NERR_UserNotFound            : ("NERR_UserNotFound", "The user name could not be found."),
 NERR_DuplicateShare          : ("NERR_DuplicateShare", "The operation is not valid for a redirected resource. The specified device name is assigned to a shared resource."),          
 NERR_RedirectedPath          : ("NERR_RedirectedPath", "The device or directory does not exist."),          
 NERR_UnknownDevDir           : ("NERR_UnknownDevDir", "The share name does not exist."),
 NERR_NetNameNotFound         : ("NERR_NetNameNotFound", "The device is not shared."),     
 NERR_DeviceNotShared         : ("NERR_DeviceNotShared", "The system cannot find the path specified."),          
 NERR_DuplicateShare          : ("NERR_DuplicateShare", "The alias already exists."),          
    }    

    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        key = self.error_code
        if (SRVSVCSessionError.error_messages.has_key(key)):
            error_msg_short = SRVSVCSessionError.error_messages[key][0]
            error_msg_verbose = SRVSVCSessionError.error_messages[key][1] 
            return 'SRVSVC SessionError: code: %s - %s - %s' % (str(self.error_code), error_msg_short, error_msg_verbose)
        else:
            return 'SRVSVC SessionError: unknown error code: %s' % (str(self.error_code))
        

# Structures
# We should move this to ndrutils.py once we port it to structure
class NDRString(Structure):
    alignment = 4
    structure = (
    ('sName','w'),
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

class SESSION_INFO_502(Structure):
    class nonDeferred(Structure):
        structure = (
            ('sesi502_cname',':',ndrutils.NDRPointerNew),
            ('sesi502_username',':',ndrutils.NDRPointerNew),
            ('sesi502_num_opens','<L=0'),
            ('sesi502_time','<L=0'),
            ('sesi502_idle_time','<L=0'),
            ('sesi502_user_flags','<L=0'),
            ('sesi502_cltype_name',':', ndrutils.NDRPointerNew),
            ('sesi502_transport',':', ndrutils.NDRPointerNew),
        )

    class deferred(Structure):
        structure = (
            ('cname',':',ndrutils.NDRStringW),
            ('username',':',ndrutils.NDRStringW),
            ('cltype_name',':',ndrutils.NDRStringW),
            ('transport',':',ndrutils.NDRStringW),
        )
        def __init__(self, data = None, alignment = 0):
            Structure.__init__(self, data, alignment)
            if data is None:
                self['cname'] = ''
                self['username'] = ''
                self['cltype_name'] = ''
                self['transport'] = ''
            return 
            
    def __init__(self, data = None, alignment = 0):
        self.__deferred = self.deferred()
        self.__nonDeferred = self.nonDeferred(data, alignment)

    def fromStringDeferred(self, data):
        self.__deferred.fromString(data)

    def dumpDeferred(self):
        self.__deferred.dump()

    def dump(self, msg = None, indent = 0):
        self.__nonDeferred.dump(msg, indent)
        self.__deferred.dump('', indent)

    def __len__(self):
        return len(self.__deferred) + len(self.__nonDeferred)

    def __str__(self):
        return str(self.__nonDeferred)

    def __getitem__(self, key):
        if self.__nonDeferred.fields.has_key(key):
            return self.__nonDeferred[key]
        else:
            return self.__deferred[key]
        
class SESSION_INFO_502_CONTAINER(Structure):
    structure = (
       ('EntriesRead','<L=0'),
       ('pBuffer',':', ndrutils.NDRPointerNew),
       ('Buffer',':'),
    )
    def __init__(self, data=None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data:
            self.__array = ndrutils.NDRArray(data = self['Buffer'], itemClass = SESSION_INFO_502)
            self['Buffer'] = self.__array
        return 

    def __len__(self):
        return len(self.__array) + 4 + 4

class SESSION_ENUM_STRUCT(Structure):
    structure = (
        ('Level','<L=0'),
        ('SwitchIs','<L=0', "self['Level']"),
        ('pContainer',':', ndrutils.NDRPointerNew),
        ('SessionInfo',':',SESSION_INFO_502_CONTAINER),
    )

class SHARE_INFO_1(Structure):
    class nonDeferred(Structure):
        structure = (
            ('shi1_netname',':',ndrutils.NDRPointerNew),
            ('shi1_type','<L=0'),
            ('shi1_remark',':', ndrutils.NDRPointerNew),
        )

    class deferred(Structure):
        structure = (
            ('netname',':',ndrutils.NDRStringW),
            ('remark',':',ndrutils.NDRStringW),
        )
        def __init__(self, data = None, alignment = 0):
            Structure.__init__(self, data, alignment)
            if data is None:
                self['netname'] = ''
                self['remark'] = ''
            return 
            
    def __init__(self, data = None, alignment = 0):
        self.__deferred = self.deferred()
        self.__nonDeferred = self.nonDeferred(data, alignment)

    def fromStringDeferred(self, data):
        self.__deferred.fromString(data)

    def dumpDeferred(self):
        self.__deferred.dump()

    def dump(self, msg = None, indent = 0):
        self.__nonDeferred.dump(msg, indent)
        self.__deferred.dump('', indent)

    def __len__(self):
        return len(self.__deferred) + len(self.__nonDeferred)

    def __str__(self):
        return str(self.__nonDeferred)

    def __getitem__(self, key):
        if self.__nonDeferred.fields.has_key(key):
            return self.__nonDeferred[key]
        else:
            return self.__deferred[key]

class SHARE_INFO_1_CONTAINER(Structure):
    structure = (
       ('EntriesRead','<L=0'),
       ('pBuffer',':', ndrutils.NDRPointerNew),
       ('Buffer',':'),
    )
    def __init__(self, data=None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data:
            self.__array = ndrutils.NDRArray(data = self['Buffer'], itemClass = SHARE_INFO_1)
            self['Buffer'] = self.__array

        return 

    def __len__(self):
        return len(self.__array) + 4 + 4

class SHARE_ENUM_STRUCT(Structure):
    structure = (
        ('Level','<L=0'),
        ('SwitchIs','<L=0', "self['Level']"),
        ('pContainer',':', ndrutils.NDRPointerNew),
        ('ShareInfo',':',SHARE_INFO_1_CONTAINER),
    )

class SHARE_INFO_2(Structure):
    structure = (
        ('shi2_netname',':', ndrutils.NDRPointerNew),
        ('shi2_type','<L=0'),
        ('shi2_remark',':', ndrutils.NDRPointerNew),
        ('shi2_permissions','<L=0'),
        ('shi2_max_uses','<L=0'),
        ('shi2_current_uses','<L=0'),
        ('shi2_path',':', ndrutils.NDRPointerNew),
        ('shi2_passwd',':', ndrutils.NDRPointerNew),
        ('netname',':', ndrutils.NDRStringW),
        ('remark',':', ndrutils.NDRStringW),
        ('path',':', ndrutils.NDRStringW),
        # Password is not used/set
        ('passwd','s="'),
    )

class SHARE_INFO(Structure):
    structure = (
        ('SwitchIs','<L=0'),
        ('pInfo',':', ndrutils.NDRPointerNew),
        ('ShareInfo2',':', SHARE_INFO_2)
    )

######### FUNCTIONS ###########

class SRVSVCShareGetInfo(Structure):
    opnum = 16
    alignment = 4
    structure = (
       ('ServerName',':', ndrutils.NDRUniqueStringW),
       ('NetName',':', ndrutils.NDRStringW),
       ('Level','<L=2'),
    )

class SRVSVCShareGetInfoResponse(Structure):
    structure = (
        ('InfoStruct',':', SHARE_INFO),
    )

class SRVSVCShareEnum(Structure):
    opnum = 15
    alignment = 4
    structure = (
       ('ServerName',':', ndrutils.NDRUniqueStringW),
       ('InfoStruct',':', SHARE_ENUM_STRUCT),
       ('PreferedMaximumLength','<L=0'),
       ('pResumeHandle', ':', ndrutils.NDRPointerNew),
       ('ResumeHandle', '<L=0'),
    )

class SRVSVCShareEnumResponse(Structure):
    structure = (
        ('InfoStruct',':', SHARE_ENUM_STRUCT),
        ('TotalEntries','<L=0'),
        ('pResumeHandle',':', ndrutils.NDRPointerNew),
        ('ResumeHandle','<L=0'),
    )

class SRVSVCSessionEnum(Structure):
    opnum = 12
    structure = (
        ('ServerName',':', ndrutils.NDRUniqueStringW),
        ('ClientName',':', ndrutils.NDRUniqueStringW),
        ('UserName',':', ndrutils.NDRUniqueStringW),
        ('InfoStruct',':',SESSION_ENUM_STRUCT),
        ('PreferedMaximumLength', '<L=0xffffffff'),
        ('pResumeHandle', ':', ndrutils.NDRPointerNew),
        ('ResumeHandle', '<L=0'),
    )

class SRVSVCSessionEnumResponse(Structure):
    structure = (
        ('InfoStruct',':', SESSION_ENUM_STRUCT),
        ('TotalEntries','<L=0'),
        ('pResumeHandle',':', ndrutils.NDRPointerNew),
        ('ResumeHandle','<L=0'),
    )

class SRVSVCServerGetInfo(Structure):
    opnum = 21
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('Level','<L=102'),
    )

class SRVSVCRemoteTOD(Structure):
    opnum = 28
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w')
    )

class SRVSVCNameCanonicalize(Structure):
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
                error_code = unpack("<L", answer[-4:])[0]
                raise SRVSVCSessionError(error_code)  
            return answer

    def NetrShareEnum(self, serverName='', preferedMaximumLength=0xffffffff, resumeHandle=0):
        """
        retrieves information about each shared resource on a server (only level1 supported)

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param INT preferedMaximumLength: specifies the preferred maximum length, in bytes, of the returned data. Default value is MAX_PREFERRED_LENGTH
        :param INT resumeHandle: a value that contains a handle, which is used to continue an existing share search. First time it should be 0

        :return: returns a list of dictionaries for each shares returned (strings in UNICODE). print the response to see its contents. On error it raises an exception
        """
        shareEnum = SRVSVCShareEnum()
        shareEnum['ServerName'] = ndrutils.NDRUniqueStringW()
        shareEnum['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        shareEnum['ServerName'].alignment = 4
        shareEnum['InfoStruct'] = SHARE_ENUM_STRUCT()
        shareEnum['InfoStruct']['Level'] = 1
        shareEnum['InfoStruct']['SwitchIs'] = 1
        shareEnum['InfoStruct']['pContainer'] =  ndrutils.NDRPointerNew()
        shareEnum['InfoStruct']['ShareInfo'] = SHARE_INFO_1_CONTAINER()
        shareEnum['InfoStruct']['ShareInfo']['pBuffer'] = ndrutils.NDRPointerNew()
        shareEnum['InfoStruct']['ShareInfo']['pBuffer']['RefId'] = 0
        shareEnum['InfoStruct']['ShareInfo']['Buffer'] = ''
        shareEnum['PreferedMaximumLength'] = preferedMaximumLength
        shareEnum['pResumeHandle'] = ndrutils.NDRPointerNew()
        shareEnum['ResumeHandle'] = resumeHandle

        data = self.doRequest(shareEnum, checkReturn = 1)
        ans = SRVSVCShareEnumResponse(data)
        # Now let's return something useful
        shareList = []
        for i in range(ans['InfoStruct']['ShareInfo']['EntriesRead']):
            item = ans['InfoStruct']['ShareInfo']['Buffer']['Item_%d'%i] 
            entry = {}
            entry['Type'] = item['shi1_type']
            entry['NetName'] = item['netname']['Data']
            entry['Remark'] = item['remark']['Data']
            shareList.append(entry)
      
        return shareList

    def NetrSessionEnum(self, serverName='', clientName='', userName='', preferedMaximumLength=0xffffffff, resumeHandle=0): 
        """
        returns information about sessions that are established on a server (info struct 502 only supported)

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE clientName: Unicode string that specifies the client machine users are connected from. Default value means all users will be returned instead of the client machine they are connecting from.
        :param UNICODE userName: Unicode string that specifies the specific username to check for connectivity. Default value means all users will be returned.
        :param INT preferedMaximumLength: specifies the preferred maximum length, in bytes, of the returned data. Default value is MAX_PREFERRED_LENGTH
        :param INT resumeHandle: a value that contains a handle, which is used to continue an existing share search. First time it should be 0

        :return: returns a list of dictionaries for each session returned (strings in UNICODE). print the response to see its contents. On error it raises an exception
        """
        sessionEnum = SRVSVCSessionEnum()
        sessionEnum['ServerName'] = ndrutils.NDRUniqueStringW()
        sessionEnum['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        sessionEnum['ServerName'].alignment = 4
        sessionEnum['ClientName'] = ndrutils.NDRUniqueStringW()
        sessionEnum['ClientName']['Data'] = clientName+'\x00'.encode('utf-16le')
        sessionEnum['ClientName'].alignment = 4
        sessionEnum['UserName'] = ndrutils.NDRUniqueStringW()
        sessionEnum['UserName']['Data'] = userName+'\x00'.encode('utf-16le')
        sessionEnum['UserName'].alignment = 4
        sessionEnum['InfoStruct'] = SESSION_ENUM_STRUCT()
        sessionEnum['InfoStruct']['Level'] = 502
        sessionEnum['InfoStruct']['SwitchIs'] = 502
        sessionEnum['InfoStruct']['pContainer'] =  ndrutils.NDRPointerNew()
        sessionEnum['InfoStruct']['SessionInfo'] = SESSION_INFO_502_CONTAINER()
        sessionEnum['InfoStruct']['SessionInfo']['pBuffer'] = ndrutils.NDRPointerNew()
        sessionEnum['InfoStruct']['SessionInfo']['pBuffer']['RefId'] = 0
        sessionEnum['InfoStruct']['SessionInfo']['Buffer'] = ''
        sessionEnum['PreferedMaximumLength'] = preferedMaximumLength
        sessionEnum['pResumeHandle'] = ndrutils.NDRPointerNew()
        sessionEnum['ResumeHandle'] = resumeHandle

        data = self.doRequest(sessionEnum, checkReturn = 1)
        ans = SRVSVCSessionEnumResponse(data)
        # Now let's return something useful
        sessionList = []
        for i in range(ans['InfoStruct']['SessionInfo']['EntriesRead']):
            item = ans['InfoStruct']['SessionInfo']['Buffer']['Item_%d'%i] 
            entry = {}
            entry['Active'] = item['sesi502_time']
            entry['IDLE']   = item['sesi502_idle_time']
            entry['Type'] = item['cltype_name']['Data']
            entry['Transport'] = item['transport']['Data']
            entry['HostName'] = item['cname']['Data']
            entry['UserName'] = item['username']['Data']
            sessionList.append(entry)
      
        return sessionList


    def NetrShareGetInfo(self, serverName, netName):
        """
        retrieves information about a particular shared resource on the server (info struct level 2 only supported)

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE netName: Unicode string that specifies the name of the share to return information for

        :return: a SHARE_INFO_2 like structure (strings in UNICODE). For the meaning of each field see [MS-SRVS] Section 2.2.4.24

        """
        shareGetInfo = SRVSVCShareGetInfo() 
        shareGetInfo['ServerName'] = ndrutils.NDRUniqueStringW()
        shareGetInfo['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        shareGetInfo['ServerName'].alignment = 4
        shareGetInfo['NetName'] = ndrutils.NDRStringW()
        shareGetInfo['NetName']['Data'] = netName+'\x00'.encode('utf-16le')
        shareGetInfo['NetName'].alignment = 4
        shareGetInfo['Level'] = 2

        data = self.doRequest(shareGetInfo, checkReturn = 1)
        ans = SRVSVCShareGetInfoResponse(data)

        entry = {}
        entry['Type'] = ans['InfoStruct']['ShareInfo2']['shi2_type']
        entry['NetName'] = ans['InfoStruct']['ShareInfo2']['netname']['Data']
        entry['Remark'] =ans['InfoStruct']['ShareInfo2']['remark']['Data']
        entry['Permissions'] =ans['InfoStruct']['ShareInfo2']['shi2_permissions'] 
        entry['MaxUses'] =ans['InfoStruct']['ShareInfo2']['shi2_max_uses'] 
        entry['CurrentUses'] =ans['InfoStruct']['ShareInfo2']['shi2_current_uses'] 
        entry['Path'] =ans['InfoStruct']['ShareInfo2']['path']['Data']

        return entry

    ################################################################################### 
    # Old functions, mantained just for compatibility reasons. Might be taken out soon

    #NetrShareEnum() with Level1 Info. Going away soon
    def get_share_enum_1(self,server):
        return self.NetrShareEnum(server.encode('utf-16le'))

    def NetrRemoteTOD(self, server):
      remoteTODReq = SRVSVCRemoteTOD()
      remoteTODReq['ServerName'] = (server+'\x00').encode('utf-16le')
      data = self.doRequest(remoteTODReq, checkReturn = 1)
      return SRVSVCpTimeOfDayInfo(data)

    def NetprNameCanonicalize(self, serverName, name, bufLen, nameType):
      NameCReq = SRVSVCNameCanonicalize()
      NameCReq['ServerName'] = (serverName+'\x00').encode('utf-16le')
      NameCReq['Name'] = (name+'\x00').encode('utf-16le')
      NameCReq['OutbufLen'] = bufLen
      NameCReq['NameType'] = nameType
      NameCReq['Flags'] = 0x0
      data = self.doRequest(NameCReq, checkReturn = 1)
      return data

    def get_server_info_102(self, server):
      #NetrServerGetInfo() with Level 102 Info
      serverInfoReq = SRVSVCServerGetInfo()
      serverInfoReq['ServerName'] = (server+'\x00').encode('utf-16le')
      data = self.doRequest(serverInfoReq, checkReturn = 1)  
      return SRVSVCServerpInfo102(data)['ServerInfo']

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


