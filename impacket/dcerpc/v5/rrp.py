# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-RRP] Interface implementation
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
from struct import unpack, pack

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantVaryingArray, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, UUID, ULONG, LPULONG, BOOLEAN, SECURITY_INFORMATION, PFILETIME, \
    RPC_UNICODE_STRING, FILETIME, NULL, MAXIMUM_ALLOWED, OWNER_SECURITY_INFORMATION, PWCHAR, PRPC_UNICODE_STRING
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import system_errors, LOG
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_RRP = uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'RRP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'RRP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 2.2.2 PREGISTRY_SERVER_NAME
PREGISTRY_SERVER_NAME = PWCHAR

# 2.2.3 error_status_t
error_status_t = ULONG

# 2.2.5 RRP_UNICODE_STRING
RRP_UNICODE_STRING = RPC_UNICODE_STRING
PRRP_UNICODE_STRING = PRPC_UNICODE_STRING

# 2.2.4 REGSAM
REGSAM = ULONG

KEY_QUERY_VALUE        = 0x00000001
KEY_SET_VALUE          = 0x00000002
KEY_CREATE_SUB_KEY     = 0x00000004
KEY_ENUMERATE_SUB_KEYS = 0x00000008
KEY_CREATE_LINK        = 0x00000020
KEY_WOW64_64KEY        = 0x00000100
KEY_WOW64_32KEY        = 0x00000200

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

# 2.2.6 RVALENT
class RVALENT(NDRSTRUCT):
    structure =  (
        ('ve_valuename',PRRP_UNICODE_STRING),
        ('ve_valuelen',DWORD),
        ('ve_valueptr',DWORD),
        ('ve_type',DWORD),
    )

class RVALENT_ARRAY(NDRUniConformantVaryingArray):
    item = RVALENT

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

# 3.1.5.23 BaseRegUnLoadKey (Opnum 23)
class BaseRegUnLoadKey(NDRCALL):
    opnum = 23
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
    )

class BaseRegUnLoadKeyResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.24 BaseRegGetVersion (Opnum 26)
class BaseRegGetVersion(NDRCALL):
    opnum = 26
    structure = (
       ('hKey', RPC_HKEY),
    )

class BaseRegGetVersionResponse(NDRCALL):
    structure = (
       ('lpdwVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.25 OpenCurrentConfig (Opnum 27)
class OpenCurrentConfig(NDRCALL):
    opnum = 27
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenCurrentConfigResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.26 BaseRegQueryMultipleValues (Opnum 29)
class BaseRegQueryMultipleValues(NDRCALL):
    opnum = 29
    structure = (
       ('hKey', RPC_HKEY),
       ('val_listIn', RVALENT_ARRAY),
       ('num_vals', DWORD),
       ('lpvalueBuf', PBYTE_ARRAY),
       ('ldwTotsize', DWORD),
    )

class BaseRegQueryMultipleValuesResponse(NDRCALL):
    structure = (
       ('val_listOut', RVALENT_ARRAY),
       ('lpvalueBuf', PBYTE_ARRAY),
       ('ldwTotsize', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.27 BaseRegSaveKeyEx (Opnum 31)
class BaseRegSaveKeyEx(NDRCALL):
    opnum = 31
    structure = (
       ('hKey', RPC_HKEY),
       ('lpFile', RRP_UNICODE_STRING),
       ('pSecurityAttributes', PRPC_SECURITY_ATTRIBUTES),
       ('Flags', DWORD),
    )

class BaseRegSaveKeyExResponse(NDRCALL):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.5.28 OpenPerformanceText (Opnum 32)
class OpenPerformanceText(NDRCALL):
    opnum = 32
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenPerformanceTextResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.29 OpenPerformanceNlsText (Opnum 33)
class OpenPerformanceNlsText(NDRCALL):
    opnum = 33
    structure = (
       ('ServerName', PREGISTRY_SERVER_NAME),
       ('samDesired', REGSAM),
    )

class OpenPerformanceNlsTextResponse(NDRCALL):
    structure = (
       ('phKey', RPC_HKEY),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.30 BaseRegQueryMultipleValues2 (Opnum 34)
class BaseRegQueryMultipleValues2(NDRCALL):
    opnum = 34
    structure = (
       ('hKey', RPC_HKEY),
       ('val_listIn', RVALENT_ARRAY),
       ('num_vals', DWORD),
       ('lpvalueBuf', PBYTE_ARRAY),
       ('ldwTotsize', DWORD),
    )

class BaseRegQueryMultipleValues2Response(NDRCALL):
    structure = (
       ('val_listOut', RVALENT_ARRAY),
       ('lpvalueBuf', PBYTE_ARRAY),
       ('ldwRequiredSize', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.5.31 BaseRegDeleteKeyEx (Opnum 35)
class BaseRegDeleteKeyEx(NDRCALL):
    opnum = 35
    structure = (
       ('hKey', RPC_HKEY),
       ('lpSubKey', RRP_UNICODE_STRING),
       ('AccessMask', REGSAM),
       ('Reserved', DWORD),
    )

class BaseRegDeleteKeyExResponse(NDRCALL):
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
22 : (BaseRegSetValue, BaseRegSetValueResponse),
23 : (BaseRegUnLoadKey, BaseRegUnLoadKeyResponse),
26 : (BaseRegGetVersion, BaseRegGetVersionResponse),
27 : (OpenCurrentConfig, OpenCurrentConfigResponse),
29 : (BaseRegQueryMultipleValues, BaseRegQueryMultipleValuesResponse),
31 : (BaseRegSaveKeyEx, BaseRegSaveKeyExResponse),
32 : (OpenPerformanceText, OpenPerformanceTextResponse),
33 : (OpenPerformanceNlsText, OpenPerformanceNlsTextResponse),
34 : (BaseRegQueryMultipleValues2, BaseRegQueryMultipleValues2Response),
35 : (BaseRegDeleteKeyEx, BaseRegDeleteKeyExResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def packValue(valueType, value):
    if valueType == REG_DWORD:
        retData = pack('<L', value)
    elif valueType == REG_DWORD_BIG_ENDIAN:
        retData = pack('>L', value)
    elif valueType == REG_EXPAND_SZ:
        try:
            retData = value.encode('utf-16le')
        except UnicodeDecodeError:
            import sys
            retData = value.decode(sys.getfilesystemencoding()).encode('utf-16le')
    elif valueType == REG_MULTI_SZ:
        try:
            retData = value.encode('utf-16le')
        except UnicodeDecodeError:
            import sys
            retData = value.decode(sys.getfilesystemencoding()).encode('utf-16le')
    elif valueType == REG_QWORD:
        retData = pack('<Q', value)
    elif valueType == REG_QWORD_LITTLE_ENDIAN:
        retData = pack('>Q', value)
    elif valueType == REG_SZ:
        try:
            retData = value.encode('utf-16le')
        except UnicodeDecodeError:
            import sys
            retData = value.decode(sys.getfilesystemencoding()).encode('utf-16le')
    else:
        retData = value

    return retData

def unpackValue(valueType, value):
    if valueType == REG_DWORD:
        retData = unpack('<L', ''.join(value))[0]
    elif valueType == REG_DWORD_BIG_ENDIAN:
        retData = unpack('>L', ''.join(value))[0]
    elif valueType == REG_EXPAND_SZ:
        retData = ''.join(value).decode('utf-16le')
    elif valueType == REG_MULTI_SZ:
        retData = ''.join(value).decode('utf-16le')
    elif valueType == REG_QWORD:
        retData = unpack('<Q', ''.join(value))[0]
    elif valueType == REG_QWORD_LITTLE_ENDIAN:
        retData = unpack('>Q', ''.join(value))[0]
    elif valueType == REG_SZ:
        retData = ''.join(value).decode('utf-16le')
    else:
        retData = ''.join(value)

    return retData

def hOpenClassesRoot(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenClassesRoot()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hOpenCurrentUser(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenCurrentUser()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hOpenLocalMachine(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenLocalMachine()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hOpenPerformanceData(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenPerformanceData()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hOpenUsers(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenUsers()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hBaseRegCloseKey(dce, hKey):
    request = BaseRegCloseKey()
    request['hKey'] = hKey
    return dce.request(request)

def hBaseRegCreateKey(dce, hKey, lpSubKey, lpClass = NULL, dwOptions = 0x00000001, samDesired = MAXIMUM_ALLOWED, lpSecurityAttributes = NULL, lpdwDisposition = REG_CREATED_NEW_KEY):
    request = BaseRegCreateKey()
    request['hKey'] = hKey
    request['lpSubKey'] = checkNullString(lpSubKey)
    request['lpClass'] = checkNullString(lpClass)
    request['dwOptions'] = dwOptions
    request['samDesired'] = samDesired
    if lpSecurityAttributes == NULL:
        request['lpSecurityAttributes']['RpcSecurityDescriptor']['lpSecurityDescriptor'] = NULL
    else:
        request['lpSecurityAttributes'] = lpSecurityAttributes
    request['lpdwDisposition'] = lpdwDisposition

    return dce.request(request)

def hBaseRegDeleteKey(dce, hKey, lpSubKey):
    request = BaseRegDeleteKey()
    request['hKey'] = hKey
    request['lpSubKey'] = checkNullString(lpSubKey)
    return dce.request(request)

def hBaseRegEnumKey(dce, hKey, dwIndex, lpftLastWriteTime = NULL):
    request = BaseRegEnumKey()
    request['hKey'] = hKey
    request['dwIndex'] = dwIndex
    request.fields['lpNameIn'].fields['MaximumLength'] = 1024
    request.fields['lpNameIn'].fields['Data'].fields['Data'].fields['MaximumCount'] = 1024/2
    request['lpClassIn'] = ' '* 64
    request['lpftLastWriteTime'] = lpftLastWriteTime

    return dce.request(request)

def hBaseRegEnumValue(dce, hKey, dwIndex, dataLen=256):
    request = BaseRegEnumValue()
    request['hKey'] = hKey
    request['dwIndex'] = dwIndex
    retries = 1

    # We need to be aware the size might not be enough, so let's catch ERROR_MORE_DATA exception
    while True:
        try:
            # Only the maximum length field of the lpValueNameIn is used to determine the buffer length to be allocated
            # by the service. Specify a string with a zero length but maximum length set to the largest buffer size
            # needed to hold the value names.
            request.fields['lpValueNameIn'].fields['MaximumLength'] = dataLen*2
            request.fields['lpValueNameIn'].fields['Data'].fields['Data'].fields['MaximumCount'] = dataLen

            request['lpData'] = ' ' * dataLen
            request['lpcbData'] = dataLen
            request['lpcbLen'] = dataLen
            resp = dce.request(request)
        except DCERPCSessionError, e:
            if retries > 1:
                LOG.debug('Too many retries when calling hBaseRegEnumValue, aborting')
                raise
            if e.get_error_code() == system_errors.ERROR_MORE_DATA:
                # We need to adjust the size
                retries +=1
                dataLen = e.get_packet()['lpcbData']
                continue
            else:
                raise
        else:
            break

    return resp

def hBaseRegFlushKey(dce, hKey):
    request = BaseRegFlushKey()
    request['hKey'] = hKey
    return dce.request(request)

def hBaseRegGetKeySecurity(dce, hKey, securityInformation = OWNER_SECURITY_INFORMATION ):
    request = BaseRegGetKeySecurity()
    request['hKey'] = hKey
    request['SecurityInformation'] = securityInformation
    request['pRpcSecurityDescriptorIn']['lpSecurityDescriptor'] = NULL
    request['pRpcSecurityDescriptorIn']['cbInSecurityDescriptor'] = 1024

    return dce.request(request)

def hBaseRegLoadKey(dce, hKey, lpSubKey, lpFile):
    request = BaseRegLoadKey()
    request['hKey'] = hKey
    request['lpSubKey'] = checkNullString(lpSubKey)
    request['lpFile'] = checkNullString(lpFile)
    return dce.request(request)

def hBaseRegUnLoadKey(dce, hKey, lpSubKey):
    request = BaseRegUnLoadKey()
    request['hKey'] = hKey
    request['lpSubKey'] = checkNullString(lpSubKey)
    return dce.request(request)

def hBaseRegOpenKey(dce, hKey, lpSubKey, dwOptions=0x00000001, samDesired = MAXIMUM_ALLOWED):
    request = BaseRegOpenKey()
    request['hKey'] = hKey
    request['lpSubKey'] = checkNullString(lpSubKey)
    request['dwOptions'] = dwOptions
    request['samDesired'] = samDesired 
    return dce.request(request)

def hBaseRegQueryInfoKey(dce, hKey):
    request = BaseRegQueryInfoKey()
    request['hKey'] = hKey
    # Not the cleanest way, but oh well
    # Plus, Windows XP needs MaximumCount also set
    request.fields['lpClassIn'].fields['MaximumLength'] = 1024
    request.fields['lpClassIn'].fields['Data'].fields['Data'].fields['MaximumCount'] = 1024/2
    return dce.request(request)

def hBaseRegQueryValue(dce, hKey, lpValueName, dataLen=512):
    request = BaseRegQueryValue()
    request['hKey'] = hKey
    request['lpValueName'] = checkNullString(lpValueName)
    retries = 1

    # We need to be aware the size might not be enough, so let's catch ERROR_MORE_DATA exception
    while True:
        try:
            request['lpData'] = ' ' * dataLen
            request['lpcbData'] = dataLen
            request['lpcbLen'] = dataLen
            resp = dce.request(request)
        except DCERPCSessionError, e:
            if retries > 1:
                LOG.debug('Too many retries when calling hBaseRegQueryValue, aborting')
                raise
            if e.get_error_code() == system_errors.ERROR_MORE_DATA:
                # We need to adjust the size
                dataLen = e.get_packet()['lpcbData']
                continue
            else:
                raise
        else:
            break

    # Returns
    # ( dataType, data )
    return resp['lpType'], unpackValue(resp['lpType'], resp['lpData'])

def hBaseRegReplaceKey(dce, hKey, lpSubKey, lpNewFile, lpOldFile):
    request = BaseRegReplaceKey()
    request['hKey'] = hKey
    request['lpSubKey'] = checkNullString(lpSubKey)
    request['lpNewFile'] = checkNullString(lpNewFile)
    request['lpOldFile'] = checkNullString(lpOldFile)
    return dce.request(request)

def hBaseRegRestoreKey(dce, hKey, lpFile, flags=REG_REFRESH_HIVE):
    request = BaseRegRestoreKey()
    request['hKey'] = hKey
    request['lpFile'] = checkNullString(lpFile)
    request['Flags'] = flags
    return dce.request(request)

def hBaseRegSaveKey(dce, hKey, lpFile, pSecurityAttributes = NULL):
    request = BaseRegSaveKey()
    request['hKey'] = hKey
    request['lpFile'] = checkNullString(lpFile)
    request['pSecurityAttributes'] = pSecurityAttributes
    return dce.request(request)

def hBaseRegSetValue(dce, hKey, lpValueName, dwType, lpData):
    request = BaseRegSetValue()
    request['hKey'] = hKey
    request['lpValueName'] = checkNullString(lpValueName)
    request['dwType'] = dwType
    request['lpData'] = packValue(dwType,lpData)
    request['cbData'] = len(request['lpData'])
    return dce.request(request)

def hBaseRegGetVersion(dce, hKey):
    request = BaseRegGetVersion()
    request['hKey'] = hKey
    return dce.request(request)

def hOpenCurrentConfig(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenCurrentConfig()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hBaseRegQueryMultipleValues(dce, hKey, val_listIn):
    # ToDo, check the result to see whether we need to 
    # have a bigger buffer for the data to receive
    request = BaseRegQueryMultipleValues()
    request['hKey'] = hKey

    for item in  val_listIn:
        itemn = RVALENT() 
        itemn['ve_valuename'] = checkNullString(item['ValueName'])
        itemn['ve_valuelen'] = len(itemn['ve_valuename'])
        itemn['ve_valueptr'] = NULL
        itemn['ve_type'] = item['ValueType']
        request['val_listIn'].append(itemn)

    request['num_vals'] = len(request['val_listIn'])
    request['lpvalueBuf'] = list(' '*128)
    request['ldwTotsize'] = 128

    resp = dce.request(request)
    retVal = list()
    for item in resp['val_listOut']:
        itemn = dict()
        itemn['ValueName'] = item['ve_valuename'] 
        itemn['ValueData'] = unpackValue(item['ve_type'], resp['lpvalueBuf'][item['ve_valueptr'] : item['ve_valueptr']+item['ve_valuelen']])
        retVal.append(itemn)
 
    return retVal

def hBaseRegSaveKeyEx(dce, hKey, lpFile, pSecurityAttributes = NULL, flags=1):
    request = BaseRegSaveKeyEx()
    request['hKey'] = hKey
    request['lpFile'] = checkNullString(lpFile)
    request['pSecurityAttributes'] = pSecurityAttributes
    request['Flags'] = flags
    return dce.request(request)

def hOpenPerformanceText(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenPerformanceText()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hOpenPerformanceNlsText(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenPerformanceNlsText()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

def hBaseRegDeleteValue(dce, hKey, lpValueName):
    request = BaseRegDeleteValue()
    request['hKey'] = hKey
    request['lpValueName'] = checkNullString(lpValueName)
    return dce.request(request)

