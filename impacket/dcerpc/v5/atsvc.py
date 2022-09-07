# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-TSCH] ATSVC Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file.
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too.
#
# Author:
#   Alberto Solino (@agsolino)
#

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, UCHAR, ULONG, LPDWORD, NULL
from impacket import hresult_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_ATSVC  = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B','1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'TSCH SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
ATSVC_HANDLE = LPWSTR
# 2.3.1 Constant Values
CNLEN = 15
DNLEN = CNLEN
UNLEN = 256
MAX_BUFFER_SIZE = (DNLEN+UNLEN+1+1)

# 2.3.7 Flags
TASK_FLAG_INTERACTIVE                  = 0x1
TASK_FLAG_DELETE_WHEN_DONE             = 0x2
TASK_FLAG_DISABLED                     = 0x4
TASK_FLAG_START_ONLY_IF_IDLE           = 0x10
TASK_FLAG_KILL_ON_IDLE_END             = 0x20
TASK_FLAG_DONT_START_IF_ON_BATTERIES   = 0x40
TASK_FLAG_KILL_IF_GOING_ON_BATTERIES   = 0x80
TASK_FLAG_RUN_ONLY_IF_DOCKED           = 0x100
TASK_FLAG_HIDDEN                       = 0x200
TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET = 0x400
TASK_FLAG_RESTART_ON_IDLE_RESUME       = 0x800
TASK_FLAG_SYSTEM_REQUIRED              = 0x1000
TASK_FLAG_RUN_ONLY_IF_LOGGED_ON        = 0x2000

################################################################################
# STRUCTURES
################################################################################
# 2.3.4 AT_INFO
class AT_INFO(NDRSTRUCT):
    structure =  (
        ('JobTime',DWORD),
        ('DaysOfMonth',DWORD),
        ('DaysOfWeek',UCHAR),
        ('Flags',UCHAR),
        ('Command',LPWSTR),
    )

class LPAT_INFO(NDRPOINTER):
    referent = (
        ('Data',AT_INFO),
    )

# 2.3.6 AT_ENUM
class AT_ENUM(NDRSTRUCT):
    structure =  (
        ('JobId',DWORD),
        ('JobTime',DWORD),
        ('DaysOfMonth',DWORD),
        ('DaysOfWeek',UCHAR),
        ('Flags',UCHAR),
        ('Command',LPWSTR),
    )

class AT_ENUM_ARRAY(NDRUniConformantArray):
    item = AT_ENUM

class LPAT_ENUM_ARRAY(NDRPOINTER):
    referent = (
        ('Data',AT_ENUM_ARRAY),
    )

# 2.3.5 AT_ENUM_CONTAINER
class AT_ENUM_CONTAINER(NDRSTRUCT):
    structure =  (
        ('EntriesRead',DWORD),
        ('Buffer',LPAT_ENUM_ARRAY),
    )

################################################################################
# RPC CALLS
################################################################################
# 3.2.5.2.1 NetrJobAdd (Opnum 0)
class NetrJobAdd(NDRCALL):
    opnum = 0
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('pAtInfo', AT_INFO),
    )

class NetrJobAddResponse(NDRCALL):
    structure = (
        ('pJobId',DWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.2.2 NetrJobDel (Opnum 1)
class NetrJobDel(NDRCALL):
    opnum = 1
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('MinJobId', DWORD),
        ('MaxJobId', DWORD),
    )

class NetrJobDelResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.2.3 NetrJobEnum (Opnum 2)
class NetrJobEnum(NDRCALL):
    opnum = 2
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('pEnumContainer', AT_ENUM_CONTAINER),
        ('PreferedMaximumLength', DWORD),
        ('pResumeHandle', LPDWORD),
    )

class NetrJobEnumResponse(NDRCALL):
    structure = (
        ('pEnumContainer', AT_ENUM_CONTAINER),
        ('pTotalEntries', DWORD),
        ('pResumeHandle',LPDWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.2.4 NetrJobGetInfo (Opnum 3)
class NetrJobGetInfo(NDRCALL):
    opnum = 3
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('JobId', DWORD),
    )

class NetrJobGetInfoResponse(NDRCALL):
    structure = (
        ('ppAtInfo', LPAT_INFO),
        ('ErrorCode',ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (NetrJobAdd,NetrJobAddResponse ),
 1 : (NetrJobDel,NetrJobDelResponse ),
 2 : (NetrJobEnum,NetrJobEnumResponse ),
 3 : (NetrJobGetInfo,NetrJobGetInfoResponse ),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hNetrJobAdd(dce, serverName = NULL, atInfo = NULL):
    netrJobAdd = NetrJobAdd()
    netrJobAdd['ServerName'] = serverName
    netrJobAdd['pAtInfo'] = atInfo
    return dce.request(netrJobAdd)

def hNetrJobDel(dce, serverName = NULL, minJobId = 0, maxJobId = 0):
    netrJobDel = NetrJobDel()
    netrJobDel['ServerName'] = serverName
    netrJobDel['MinJobId'] = minJobId
    netrJobDel['MaxJobId'] = maxJobId
    return dce.request(netrJobDel)

def hNetrJobEnum(dce, serverName = NULL, pEnumContainer = NULL, preferedMaximumLength = 0xffffffff):
    netrJobEnum = NetrJobEnum()
    netrJobEnum['ServerName'] = serverName
    netrJobEnum['pEnumContainer']['Buffer'] = pEnumContainer
    netrJobEnum['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(netrJobEnum)

def hNetrJobGetInfo(dce, serverName = NULL, jobId = 0):
    netrJobGetInfo = NetrJobGetInfo()
    netrJobGetInfo['ServerName'] = serverName
    netrJobGetInfo['JobId'] = jobId
    return dce.request(netrJobGetInfo)
