# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-RPRN] Interface implementation
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

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantVaryingArray, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import ULONGLONG, UINT, USHORT, LPWSTR, DWORD, UUID, ULONG, LPULONG, BOOLEAN, SECURITY_INFORMATION, PFILETIME, \
    RPC_UNICODE_STRING, FILETIME, NULL, MAXIMUM_ALLOWED, OWNER_SECURITY_INFORMATION, PWCHAR, PRPC_UNICODE_STRING
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import system_errors, LOG
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_RPRN = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'RPRN SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'RPRN SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 2.2.1.1.7 STRING_HANDLE
STRING_HANDLE = LPWSTR
class PSTRING_HANDLE(NDRPOINTER):
    referent = (
        ('Data', STRING_HANDLE),
    )

# 2.2.3.1 Access Values
JOB_ACCESS_ADMINISTER         = 0x00000010
JOB_ACCESS_READ               = 0x00000020
JOB_EXECUTE                   = 0x00020010
JOB_READ                      = 0x00020020
JOB_WRITE                     = 0x00020010
JOB_ALL_ACCESS                = 0x000F0030
PRINTER_ACCESS_ADMINISTER     = 0x00000004
PRINTER_ACCESS_USE            = 0x00000008
PRINTER_ACCESS_MANAGE_LIMITED = 0x00000040
PRINTER_ALL_ACCESS            = 0x000F000C
PRINTER_EXECUTE               = 0x00020008
PRINTER_READ                  = 0x00020008
PRINTER_WRITE                 = 0x00020008
SERVER_ACCESS_ADMINISTER      = 0x00000001
SERVER_ACCESS_ENUMERATE       = 0x00000002
SERVER_ALL_ACCESS             = 0x000F0003
SERVER_EXECUTE                = 0x00020002
SERVER_READ                   = 0x00020002
SERVER_WRITE                  = 0x00020003
SPECIFIC_RIGHTS_ALL           = 0x0000FFFF
STANDARD_RIGHTS_ALL           = 0x001F0000
STANDARD_RIGHTS_EXECUTE       = 0x00020000
STANDARD_RIGHTS_READ          = 0x00020000
STANDARD_RIGHTS_REQUIRED      = 0x000F0000
STANDARD_RIGHTS_WRITE         = 0x00020000
SYNCHRONIZE                   = 0x00100000
DELETE                        = 0x00010000
READ_CONTROL                  = 0x00020000
WRITE_DAC                     = 0x00040000
WRITE_OWNER                   = 0x00080000
GENERIC_READ                  = 0x80000000
GENERIC_WRITE                 = 0x40000000
GENERIC_EXECUTE               = 0x20000000
GENERIC_ALL                   = 0x10000000

# 2.2.3.6.1 Printer Change Flags for Use with a Printer Handle
PRINTER_CHANGE_SET_PRINTER        = 0x00000002
PRINTER_CHANGE_DELETE_PRINTER     = 0x00000004
PRINTER_CHANGE_PRINTER            = 0x000000FF
PRINTER_CHANGE_ADD_JOB            = 0x00000100
PRINTER_CHANGE_SET_JOB            = 0x00000200
PRINTER_CHANGE_DELETE_JOB         = 0x00000400
PRINTER_CHANGE_WRITE_JOB          = 0x00000800
PRINTER_CHANGE_JOB                = 0x0000FF00
PRINTER_CHANGE_SET_PRINTER_DRIVER = 0x20000000
PRINTER_CHANGE_TIMEOUT            = 0x80000000
PRINTER_CHANGE_ALL                = 0x7777FFFF
PRINTER_CHANGE_ALL_2              = 0x7F77FFFF

# 2.2.3.6.2 Printer Change Flags for Use with a Server Handle
PRINTER_CHANGE_ADD_PRINTER_DRIVER        = 0x10000000
PRINTER_CHANGE_DELETE_PRINTER_DRIVER     = 0x40000000
PRINTER_CHANGE_PRINTER_DRIVER            = 0x70000000
PRINTER_CHANGE_ADD_FORM                  = 0x00010000
PRINTER_CHANGE_DELETE_FORM               = 0x00040000
PRINTER_CHANGE_SET_FORM                  = 0x00020000
PRINTER_CHANGE_FORM                      = 0x00070000
PRINTER_CHANGE_ADD_PORT                  = 0x00100000
PRINTER_CHANGE_CONFIGURE_PORT            = 0x00200000
PRINTER_CHANGE_DELETE_PORT               = 0x00400000
PRINTER_CHANGE_PORT                      = 0x00700000
PRINTER_CHANGE_ADD_PRINT_PROCESSOR       = 0x01000000
PRINTER_CHANGE_DELETE_PRINT_PROCESSOR    = 0x04000000
PRINTER_CHANGE_PRINT_PROCESSOR           = 0x07000000
PRINTER_CHANGE_ADD_PRINTER               = 0x00000001
PRINTER_CHANGE_FAILED_CONNECTION_PRINTER = 0x00000008
PRINTER_CHANGE_SERVER                    = 0x08000000

# 2.2.3.8 Printer Notification Values
PRINTER_NOTIFY_CATEGORY_2D  = 0x00000000
PRINTER_NOTIFY_CATEGORY_ALL = 0x00010000
PRINTER_NOTIFY_CATEGORY_3D  = 0x00020000


################################################################################
# STRUCTURES
################################################################################
# 2.2.1.1.4 PRINTER_HANDLE
class PRINTER_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=b""'),
    )
    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4

# 2.2.1.2.1 DEVMODE_CONTAINER
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class DEVMODE_CONTAINER(NDRSTRUCT):
    structure =  (
        ('cbBuf',DWORD),
        ('pDevMode',PBYTE_ARRAY),
    )

# 2.2.1.11.1 SPLCLIENT_INFO_1
class SPLCLIENT_INFO_1(NDRSTRUCT):
    structure =  (
        ('dwSize',DWORD),
        ('pMachineName',LPWSTR),
        ('pUserName',LPWSTR),
        ('dwBuildNum',DWORD),
        ('dwMajorVersion',DWORD),
        ('dwMinorVersion',DWORD),
        ('wProcessorArchitecture',USHORT),
    )

class PSPLCLIENT_INFO_1(NDRPOINTER):
    referent = (
        ('Data', SPLCLIENT_INFO_1),
    )

# 2.2.1.11.2 SPLCLIENT_INFO_2
class SPLCLIENT_INFO_2(NDRSTRUCT):
    structure =  (
        ('notUsed',ULONGLONG),
    )

class PSPLCLIENT_INFO_2(NDRPOINTER):
    referent = (
        ('Data', SPLCLIENT_INFO_2),
    )
# 2.2.1.11.3 SPLCLIENT_INFO_3
class SPLCLIENT_INFO_3(NDRSTRUCT):
    structure =  (
        ('cbSize',UINT),
        ('dwFlags',DWORD),
        ('dwFlags',DWORD),
        ('pMachineName',LPWSTR),
        ('pUserName',LPWSTR),
        ('dwBuildNum',DWORD),
        ('dwMajorVersion',DWORD),
        ('dwMinorVersion',DWORD),
        ('wProcessorArchitecture',USHORT),
        ('hSplPrinter',ULONGLONG),
    )

class PSPLCLIENT_INFO_3(NDRPOINTER):
    referent = (
        ('Data', SPLCLIENT_INFO_3),
    )
# 2.2.1.2.14 SPLCLIENT_CONTAINER
class CLIENT_INFO_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        1 : ('pClientInfo1', PSPLCLIENT_INFO_1),
        2 : ('pNotUsed1', PSPLCLIENT_INFO_2),
        3 : ('pNotUsed2', PSPLCLIENT_INFO_3),
    }

class SPLCLIENT_CONTAINER(NDRSTRUCT):
    structure =  (
        ('Level',DWORD),
        ('ClientInfo',CLIENT_INFO_UNION),
    )


# 2.2.1.13.2 RPC_V2_NOTIFY_OPTIONS_TYPE
class USHORT_ARRAY(NDRUniConformantArray):
    item = '<H'

class PUSHORT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', USHORT_ARRAY),
    )

class RPC_V2_NOTIFY_OPTIONS_TYPE(NDRSTRUCT):
    structure =  (
        ('Type',USHORT),
        ('Reserved0',USHORT),
        ('Reserved1',DWORD),
        ('Reserved2',DWORD),
        ('Count',DWORD),
        ('pFields',PUSHORT_ARRAY),
    )

class PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', RPC_V2_NOTIFY_OPTIONS_TYPE),
    )

# 2.2.1.13.1 RPC_V2_NOTIFY_OPTIONS
class RPC_V2_NOTIFY_OPTIONS(NDRSTRUCT):
    structure =  (
        ('Version',DWORD),
        ('Reserved',DWORD),
        ('Count',DWORD),
        ('pTypes',PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY),
    )

class PRPC_V2_NOTIFY_OPTIONS(NDRPOINTER):
    referent = (
        ('Data', RPC_V2_NOTIFY_OPTIONS),
    )


################################################################################
# RPC CALLS
################################################################################
# 3.1.4.2.2 RpcOpenPrinter (Opnum 1)
class RpcOpenPrinter(NDRCALL):
    opnum = 1
    structure = (
       ('pPrinterName', STRING_HANDLE),
       ('pDatatype', LPWSTR),
       ('pDevModeContainer', DEVMODE_CONTAINER),
       ('AccessRequired', DWORD),
    )

class RpcOpenPrinterResponse(NDRCALL):
    structure = (
       ('pHandle', PRINTER_HANDLE),
       ('ErrorCode', ULONG),
    )

# 3.1.4.10.4 RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)
class RpcRemoteFindFirstPrinterChangeNotificationEx(NDRCALL):
    opnum = 65
    structure = (
       ('hPrinter', PRINTER_HANDLE),
       ('fdwFlags', DWORD),
       ('fdwOptions', DWORD),
       ('pszLocalMachine', LPWSTR),
       ('dwPrinterLocal', DWORD),
       ('pOptions', PRPC_V2_NOTIFY_OPTIONS),
    )

class RpcRemoteFindFirstPrinterChangeNotificationExResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

# 3.1.4.2.14 RpcOpenPrinterEx (Opnum 69)
class RpcOpenPrinterEx(NDRCALL):
    opnum = 69
    structure = (
       ('pPrinterName', STRING_HANDLE),
       ('pDatatype', LPWSTR),
       ('pDevModeContainer', DEVMODE_CONTAINER),
       ('AccessRequired', DWORD),
       ('pClientInfo', SPLCLIENT_CONTAINER),
    )

class RpcOpenPrinterExResponse(NDRCALL):
    structure = (
       ('pHandle', PRINTER_HANDLE),
       ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 69 : (RpcOpenPrinterEx, RpcOpenPrinterExResponse),
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

def hOpenClassesRoot(dce, samDesired = MAXIMUM_ALLOWED):
    request = OpenClassesRoot()
    request['ServerName'] = NULL
    request['samDesired'] = samDesired
    return dce.request(request)

