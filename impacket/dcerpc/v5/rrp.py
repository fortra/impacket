# Copyright (c) 2003-2014 CORE Security Technologies
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
#   [MS-RRP] Interface implementation
#

from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.ndr import NDRCALL, NDR, NDRSTRUCT, NDRPOINTER, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dtypes import *
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum

MSRPC_UUID_RRP = uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0'))

class DCERPCSessionError(Exception):
    def __init__( self, packet = None, error_code = None):
        Exception.__init__(self)
        self.packet = packet
        if packet is not None:
            self.error_code = packet['ErrorCode']
        else:
            self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code
 
    def get_packet( self ):
        return self.packet

    def __str__( self ):
        key = self.error_code
        if (system_errors.ERROR_MESSAGES.has_key(key)):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'RRP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'RRP SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# CONSTANTS
################################################################################

################################################################################
# STRUCTURES
################################################################################
# 2.2.1 RPC_HKEY
class RPC_HKEY(NDRSTRUCT):
    structure =  (
        ('context_handle_attributes',ULONG),
        ('context_handle_uuid',UUID),
    )
    def __init__(self, data = None,isNDR64 = False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        self['context_handle_uuid'] = '\x00'*20

# 2.2.2 PREGISTRY_SERVER_NAME
PREGISTRY_SERVER_NAME = PWCHAR

# 2.2.3 error_status_t
error_status_t = ULONG

# 2.2.4 REGSAM
REGSAM = ULONG

KEY_QUERY_VALUE        = 0x00000001
KEY_SET_VALUE          = 0x00000002
KEY_CREATE_SUB_KEY     = 0x00000004
KEY_ENUMERATE_SUB_KEYS = 0x00000008
KEY_CREATE_LINK        = 0x00000020
KEY_WOW64_64KEY        = 0x00000100
KEY_WOW64_32KEY        = 0x00000200

# 2.2.5 RRP_UNICODE_STRING
RRP_UNICODE_STRING = RPC_UNICODE_STRING
PRRP_UNICODE_STRING = PRPC_UNICODE_STRING

# 2.2.6 RVALENT
class RVALENT(NDRSTRUCT):
    structure =  (
        ('ve_valuename',PRRP_UNICODE_STRING),
        ('ve_valuelen',DWORD),
        ('ve_valueptr',LPDWORD),
        ('ve_type',DWORD),
    )

REG_BINARY              = 3
REG_DWORD               = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN    = 5
REG_EXPAND_SZ           = 2
REG_LINK                = 6
REG_MULTI_SZ            = 7
REG_NONE                = 0
REG_QWORD               = 11
REG_QWORD_LITTLE_ENDIAN = 11
REG_SZ                  = 1 

# 2.2.9 RPC_SECURITY_DESCRIPTOR
class BYTE_ARRAY(NDRUniConformantVaryingArray):
    pass

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class RPC_SECURITY_DESCRIPTOR(NDRSTRUCT):
    structure =  (
        ('lpSecurityDescriptor',PBYTE_ARRAY),
        ('cbInSecurityDescriptor',DWORD),
        ('cbOutSecurityDescriptor',DWORD),
    )

# 2.2.8 RPC_SECURITY_ATTRIBUTES
class RPC_SECURITY_ATTRIBUTES(NDRSTRUCT):
    structure =  (
        ('nLength',DWORD),
        ('RpcSecurityDescriptor',RPC_SECURITY_DESCRIPTOR),
        ('bInheritHandle',BOOLEAN),
    )

class PRPC_SECURITY_ATTRIBUTES(NDRPOINTER):
    referent = (
        ('Data', RPC_SECURITY_ATTRIBUTES),
    )

# 3.1.5.7 BaseRegCreateKey (Opnum 6)
REG_CREATED_NEW_KEY     = 0x00000001
REG_OPENED_EXISTING_KEY = 0x00000002

# 3.1.5.19 BaseRegRestoreKey (Opnum 19)
# Flags
REG_WHOLE_HIVE_VOLATILE = 0x00000001
REG_REFRESH_HIVE        = 0x00000002
REG_NO_LAZY_FLUSH       = 0x00000004
REG_FORCE_RESTORE       = 0x00000008

################################################################################
# RPC CALLS
################################################################################
# 3.1.5.1 OpenClassesRoot (Opnum 0)
class OpenClassesRoot(NDRCALL):
    opnum = 0
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenClassesRootResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.2 OpenCurrentUser (Opnum 1)
class OpenCurrentUser(NDRCALL):
    opnum = 1
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenCurrentUserResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.3 OpenLocalMachine (Opnum 2)
class OpenLocalMachine(NDRCALL):
    opnum = 2
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenLocalMachineResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.4 OpenPerformanceData (Opnum 3)
class OpenPerformanceData(NDRCALL):
    opnum = 3
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenPerformanceDataResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.5 OpenUsers (Opnum 4)
class OpenUsers(NDRCALL):
    opnum = 4
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenUsersResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.6 BaseRegCloseKey (Opnum 5)
class BaseRegCloseKey(NDRCALL):
    opnum = 5
    structure = (
       ('hKey', RPC_HKEY),
    )

class BaseRegCloseKeyResponse(NDRCALL):
    structure = (
       ('hKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.7 BaseRegCreateKey (Opnum 6)
class BaseRegCreateKey(NDRCALL):
    opnum = 6
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
       ('lpClass', RRP_UNICODE_STRING),
       ('dwOptions', DWORD),
       ('samDesired', REGSAM),
       ('lpSecurityAttributes', PRPC_SECURITY_ATTRIBUTES),
       ('lpdwDisposition', LPULONG),
    )

class BaseRegCreateKeyResponse(NDRCALL):
    structure = (
       ('phkResult', RPC_HKEY),
       ('lpdwDisposition', LPULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.8 BaseRegDeleteKey (Opnum 7)
class BaseRegDeleteKey(NDRCALL):
    opnum = 7
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
    )

class BaseRegDeleteKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.9 BaseRegDeleteValue (Opnum 8)
class BaseRegDeleteValue(NDRCALL):
    opnum = 8
    structure = (
       ('hKey', RPC_HKEY),
       ('lpValueName', RRP_UNICODE_STRING),
    )

class BaseRegDeleteValueResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.10 BaseRegEnumKey (Opnum 9)
class BaseRegEnumKey(NDRCALL):
    opnum = 9
    structure = (
       ('hKey', RPC_HKEY),
       ('dwIndex', DWORD),
       ('lpNameIn', RRP_UNICODE_STRING),
       ('lpClassIn', PRRP_UNICODE_STRING),
       ('lpftLastWriteTime', PFILETIME),
    )

class BaseRegEnumKeyResponse(NDRCALL):
    structure = (
       ('lpNameOut', RRP_UNICODE_STRING),
       ('lplpClassOut', PRRP_UNICODE_STRING),
       ('lpftLastWriteTime', PFILETIME),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.11 BaseRegEnumValue (Opnum 10)
class BaseRegEnumValue(NDRCALL):
    opnum = 10
    structure = (
       ('hKey', RPC_HKEY),
       ('dwIndex', DWORD),
       ('lpValueNameIn', RRP_UNICODE_STRING),
       ('lpType', LPULONG),
       ('lpData', PBYTE_ARRAY),
       ('lpcbData', LPULONG),
       ('lpcbLen', LPULONG),
    )

class BaseRegEnumValueResponse(NDRCALL):
    structure = (
       ('lpValueNameOut', RRP_UNICODE_STRING),
       ('lpType', LPULONG),
       ('lpData', PBYTE_ARRAY),
       ('lpcbData', LPULONG),
       ('lpcbLen', LPULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.12 BaseRegFlushKey (Opnum 11)
class BaseRegFlushKey(NDRCALL):
    opnum = 11
    structure = (
       ('hKey', RPC_HKEY),
    )

class BaseRegFlushKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.13 BaseRegGetKeySecurity (Opnum 12)
class BaseRegGetKeySecurity(NDRCALL):
    opnum = 12
    structure = (
       ('hKey', RPC_HKEY),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('pRpcSecurityDescriptorIn', RPC_SECURITY_DESCRIPTOR),
    )

class BaseRegGetKeySecurityResponse(NDRCALL):
    structure = (
       ('pRpcSecurityDescriptorOut', RPC_SECURITY_DESCRIPTOR),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.14 BaseRegLoadKey (Opnum 13)
class BaseRegLoadKey(NDRCALL):
    opnum = 13
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
       ('lpFile', RRP_UNICODE_STRING),
    )

class BaseRegLoadKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.15 BaseRegOpenKey (Opnum 15)
class BaseRegOpenKey(NDRCALL):
    opnum = 15
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
       ('dwOptions', DWORD),
       ('samDesired', REGSAM),
    )

class BaseRegOpenKeyResponse(NDRCALL):
    structure = (
       ('phkResult', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.16 BaseRegQueryInfoKey (Opnum 16)
class BaseRegQueryInfoKey(NDRCALL):
    opnum = 16
    structure = (
       ('hKey', RPC_HKEY),
       ('lpClassIn', RRP_UNICODE_STRING),
    )

class BaseRegQueryInfoKeyResponse(NDRCALL):
    structure = (
       ('lpClassOut', RPC_UNICODE_STRING),
       ('lpcSubKeys', DWORD),
       ('lpcbMaxSubKeyLen', DWORD),
       ('lpcbMaxClassLen', DWORD),
       ('lpcValues', DWORD),
       ('lpcbMaxValueNameLen', DWORD),
       ('lpcbMaxValueLen', DWORD),
       ('lpcbSecurityDescriptor', DWORD),
       ('lpftLastWriteTime', FILETIME),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.17 BaseRegQueryValue (Opnum 17)
class BaseRegQueryValue(NDRCALL):
    opnum = 17
    structure = (
       ('hKey', RPC_HKEY),
       ('lpValueName', RRP_UNICODE_STRING),
       ('lpType', LPULONG),
       ('lpData', PBYTE_ARRAY),
       ('lpcbData', LPULONG),
       ('lpcbLen', LPULONG),
    )

class BaseRegQueryValueResponse(NDRCALL):
    structure = (
       ('lpType', LPULONG),
       ('lpData', PBYTE_ARRAY),
       ('lpcbData', LPULONG),
       ('lpcbLen', LPULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.18 BaseRegReplaceKey (Opnum 18)
class BaseRegReplaceKey(NDRCALL):
    opnum = 18
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
       ('lpNewFile', RRP_UNICODE_STRING),
       ('lpOldFile', RRP_UNICODE_STRING),
    )

class BaseRegReplaceKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.19 BaseRegRestoreKey (Opnum 19)
class BaseRegRestoreKey(NDRCALL):
    opnum = 19
    structure = (
       ('hKey', RPC_HKEY),
       ('lpFile', RRP_UNICODE_STRING),
       ('Flags', DWORD),
    )

class BaseRegRestoreKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.20 BaseRegSaveKey (Opnum 20)
class BaseRegSaveKey(NDRCALL):
    opnum = 20
    structure = (
       ('hKey', RPC_HKEY),
       ('lpFile', RRP_UNICODE_STRING),
       ('pSecurityAttributes', PRPC_SECURITY_ATTRIBUTES),
    )

class BaseRegSaveKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.21 BaseRegSetKeySecurity (Opnum 21)
class BaseRegSetKeySecurity(NDRCALL):
    opnum = 21
    structure = (
       ('hKey', RPC_HKEY),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('pRpcSecurityDescriptor', RPC_SECURITY_DESCRIPTOR),
    )

class BaseRegSetKeySecurityResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.22 BaseRegSetValue (Opnum 22)
class BaseRegSetValue(NDRCALL):
    opnum = 22
    structure = (
       ('hKey', RPC_HKEY),
       ('lpValueName', RRP_UNICODE_STRING),
       ('dwType', DWORD),
       ('lpData', NDRUniConformantArray),
       ('cbData', DWORD),
    )

class BaseRegSetValueResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )



################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (OpenClassesRoot, OpenClassesRootResponse),
 1 : (OpenCurrentUser, OpenCurrentUserResponse),
 2 : (OpenLocalMachine, OpenLocalMachineResponse),
 3 : (OpenPerformanceData, OpenPerformanceDataResponse),
 4 : (OpenUsers, OpenUsersResponse),
 5 : (BaseRegCloseKey, BaseRegCloseKeyResponse),
 6 : (BaseRegCreateKey, BaseRegCreateKeyResponse),
 7 : (BaseRegDeleteKey, BaseRegDeleteKeyResponse),
 8 : (BaseRegDeleteValue, BaseRegDeleteValueResponse),
 9 : (BaseRegEnumKey, BaseRegEnumKeyResponse),
10 : (BaseRegEnumValue, BaseRegEnumValueResponse),
11 : (BaseRegFlushKey, BaseRegFlushKeyResponse),
12 : (BaseRegGetKeySecurity, BaseRegGetKeySecurityResponse),
13 : (BaseRegLoadKey, BaseRegLoadKeyResponse),
15 : (BaseRegOpenKey, BaseRegOpenKeyResponse),
16 : (BaseRegQueryInfoKey, BaseRegQueryInfoKeyResponse),
17 : (BaseRegQueryValue, BaseRegQueryValueResponse),
18 : (BaseRegReplaceKey, BaseRegReplaceKeyResponse),
19 : (BaseRegRestoreKey, BaseRegRestoreKeyResponse),
20 : (BaseRegSaveKey, BaseRegSaveKeyResponse),
21 : (BaseRegSetKeySecurity, BaseRegSetKeySecurityResponse),
#22 : (BaseRegSetValue, BaseRegSetValueResponse),
#23 : (BaseRegUnLoadKey, BaseRegUnLoadKeyResponse),
#26 : (BaseRegGetVersion, BaseRegGetVersionResponse),
#27 : (OpenCurrentConfig, OpenCurrentConfigResponse),
#29 : (BaseRegQueryMultipleValues, BaseRegQueryMultipleValuesResponse),
#31 : (BaseRegSaveKeyEx, BaseRegSaveKeyExResponse),
#32 : (OpenPerformanceText, OpenPerformanceTextResponse),
#33 : (OpenPerformanceNlsText, OpenPerformanceNlsTextResponse),
#34 : (BaseRegQueryMultipleValues2, BaseRegQueryMultipleValues2Response),
#35 : (BaseRegDeleteKeyEx, BaseRegDeleteKeyExResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

