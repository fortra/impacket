# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-PAR] Interface implementation
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/fortra/impacket/tree/master/tests/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file.
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too.
#
# Author:
#   Adam (@cube0x0)
#
from impacket import system_errors
from impacket.dcerpc.v5.dtypes import ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG, NULL
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin, string_to_bin

MSRPC_UUID_PAR = uuidtup_to_bin(('76F03F96-CDFD-44FC-A22C-64950A001209', '1.0'))
MSRPC_UUID_WINSPOOL = string_to_bin('9940CA8E-512F-4C58-88A9-61098D6896BD')

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

# 2.2.3.7 Printer Enumeration Flags
PRINTER_ENUM_LOCAL       = 0x00000002
PRINTER_ENUM_CONNECTIONS = 0x00000004
PRINTER_ENUM_NAME        = 0x00000008
PRINTER_ENUM_REMOTE      = 0x00000010
PRINTER_ENUM_SHARED      = 0x00000020
PRINTER_ENUM_NETWORK     = 0x00000040
PRINTER_ENUM_EXPAND      = 0x00004000
PRINTER_ENUM_CONTAINER   = 0x00008000
PRINTER_ENUM_ICON1       = 0x00010000
PRINTER_ENUM_ICON2       = 0x00020000
PRINTER_ENUM_ICON3       = 0x00040000
PRINTER_ENUM_ICON8       = 0x00800000
PRINTER_ENUM_HIDE        = 0x01000000


# 2.2.3.8 Printer Notification Values
PRINTER_NOTIFY_CATEGORY_2D  = 0x00000000
PRINTER_NOTIFY_CATEGORY_ALL = 0x00010000
PRINTER_NOTIFY_CATEGORY_3D  = 0x00020000


# 3.1.4.4.8 RpcAddPrinterDriverEx Values
APD_STRICT_UPGRADE              = 0x00000001
APD_STRICT_DOWNGRADE            = 0x00000002
APD_COPY_ALL_FILES              = 0x00000004
APD_COPY_NEW_FILES              = 0x00000008
APD_COPY_FROM_DIRECTORY         = 0x00000010
APD_DONT_COPY_FILES_TO_CLUSTER  = 0x00001000
APD_COPY_TO_ALL_SPOOLERS        = 0x00002000
APD_INSTALL_WARNED_DRIVER       = 0x00008000
APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000

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

# 2.2.1.5.1 DRIVER_INFO_1
class DRIVER_INFO_1(NDRSTRUCT):
    structure = (
        ('pName', STRING_HANDLE ),
    )
class PDRIVER_INFO_1(NDRPOINTER):
    referent = (
        ('Data', DRIVER_INFO_1),
    )

# 2.2.1.5.2 DRIVER_INFO_2
class DRIVER_INFO_2(NDRSTRUCT):
    structure = (
        ('cVersion',DWORD),
        ('pName', LPWSTR),
        ('pEnvironment', LPWSTR),
        ('pDriverPath', LPWSTR),
        ('pDataFile', LPWSTR),
        ('pConfigFile', LPWSTR),
    )
class PDRIVER_INFO_2(NDRPOINTER):
    referent = (
        ('Data', DRIVER_INFO_2),
    )

# 2.2.1.2.3 DRIVER_CONTAINER
class DRIVER_INFO_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        1 : ('pNotUsed', PDRIVER_INFO_1),
        2 : ('Level2', PDRIVER_INFO_2),
    }

class DRIVER_CONTAINER(NDRSTRUCT):
    structure =  (
        ('Level', DWORD),
        ('DriverInfo', DRIVER_INFO_UNION),
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

class RpcAsync_V2_NOTIFY_OPTIONS_TYPE(NDRSTRUCT):
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
        ('Data', RpcAsync_V2_NOTIFY_OPTIONS_TYPE),
    )

# 2.2.1.13.1 RPC_V2_NOTIFY_OPTIONS
class RpcAsync_V2_NOTIFY_OPTIONS(NDRSTRUCT):
    structure =  (
        ('Version',DWORD),
        ('Reserved',DWORD),
        ('Count',DWORD),
        ('pTypes',PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY),
    )

class PRPC_V2_NOTIFY_OPTIONS(NDRPOINTER):
    referent = (
        ('Data', RpcAsync_V2_NOTIFY_OPTIONS),
    )


################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1.21 RpcAsyncEnumPrinters (Opnum 38)
class RpcAsyncEnumPrinters(NDRCALL):
    opnum = 38
    structure = (
       ('Flags', DWORD),
       ('Name', STRING_HANDLE),
       ('Level', DWORD),
       ('pPrinterEnum', PBYTE_ARRAY),
       ('cbBuf', DWORD),
    )

class RpcAsyncEnumPrintersResponse(NDRCALL):
    structure = (
       ('pPrinterEnum', PBYTE_ARRAY),
       ('pcbNeeded', DWORD),
       ('pcReturned', DWORD),
       ('ErrorCode', ULONG),
    )

# 3.1.4.1.1 RpcAsyncOpenPrinter (Opnum 0)
class RpcAsyncOpenPrinter(NDRCALL):
    opnum = 0
    structure = (
       ('pPrinterName', STRING_HANDLE),
       ('pDatatype', LPWSTR),
       ('pDevModeContainer', DEVMODE_CONTAINER),
       ('AccessRequired', DWORD),
       ('pClientInfo', SPLCLIENT_CONTAINER),
    )

class RpcAsyncOpenPrinterResponse(NDRCALL):
    structure = (
       ('pHandle', PRINTER_HANDLE),
       ('ErrorCode', ULONG),
    )

# 3.1.4.1.10 RpcAsyncClosePrinter (Opnum 20)
class RpcAsyncClosePrinter(NDRCALL):
    opnum = 20
    structure = (
       ('phPrinter', PRINTER_HANDLE),
    )

class RpcAsyncClosePrinterResponse(NDRCALL):
    structure = (
       ('phPrinter', PRINTER_HANDLE),
       ('ErrorCode', ULONG),
    )

# 3.1.4.2.3 RpcAsyncEnumPrinterDrivers (Opnum 40)
class RpcAsyncEnumPrinterDrivers(NDRCALL):
    opnum = 40
    structure = (
       ('pName', STRING_HANDLE),
       ('pEnvironment', LPWSTR),
       ('Level', DWORD),
       ('pDrivers', PBYTE_ARRAY),
       ('cbBuf', DWORD),
    )

class RpcAsyncEnumPrinterDriversResponse(NDRCALL):
    structure = (
       ('pDrivers', PBYTE_ARRAY),
       ('pcbNeeded', DWORD),
       ('pcReturned', DWORD),
       ('ErrorCode', ULONG),
    )

# 3.1.4.2.4 RpcAsyncGetPrinterDriverDirectory (Opnum 41)
class RpcAsyncGetPrinterDriverDirectory(NDRCALL):
   opnum = 41
   structure = (
       ('pName', STRING_HANDLE),
       ('pEnvironment', LPWSTR),
       ('Level', DWORD),
       ('pDriverDirectory', PBYTE_ARRAY),
       ('cbBuf', DWORD)
   )
   
class RpcAsyncGetPrinterDriverDirectoryResponse(NDRCALL):
    structure = (
       ('pDriverDirectory', PBYTE_ARRAY),
       ('pcbNeeded', DWORD),
       ('ErrorCode', ULONG)
    )

# 3.1.4.2.2 RpcAsyncAddPrinterDriver (Opnum 39)
class RpcAsyncAddPrinterDriver(NDRCALL):
    opnum = 39
    structure = (
       ('pName', STRING_HANDLE),
       ('pDriverContainer', DRIVER_CONTAINER),
       ('dwFileCopyFlags', DWORD),
    )

class RpcAsyncAddPrinterDriverResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0  : (RpcAsyncOpenPrinter, RpcAsyncOpenPrinterResponse),
    #1  : (RpcAsyncAddPrinter, RpcAsyncAddPrinterResponse),
    20 : (RpcAsyncClosePrinter, RpcAsyncClosePrinterResponse),
    38 : (RpcAsyncEnumPrinters, RpcAsyncEnumPrintersResponse),
    39 : (RpcAsyncAddPrinterDriver, RpcAsyncAddPrinterDriver),
    40 : (RpcAsyncEnumPrinterDrivers, RpcAsyncEnumPrinterDriversResponse),
    41 : (RpcAsyncGetPrinterDriverDirectory, RpcAsyncGetPrinterDriverDirectoryResponse)
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

def hRpcAsyncClosePrinter(dce, phPrinter):
    """
    RpcClosePrinter closes a handle to a printer object, server object, job object, or port object.
    Full Documentation: https://msdn.microsoft.com/en-us/library/cc244768.aspx

    :param DCERPC_v5 dce: a connected DCE instance.
    :param PRINTER_HANDLE phPrinter: A handle to a printer object, server object, job object, or port object.

    :return: a RpcClosePrinterResponse instance, raises DCERPCSessionError on error.
    """
    request = RpcAsyncClosePrinter()
    request['phPrinter'] = phPrinter
    return dce.request(request, MSRPC_UUID_WINSPOOL)


def hRpcAsyncOpenPrinter(dce, printerName, pDatatype=NULL, pDevModeContainer=NULL, accessRequired=SERVER_READ,
                      pClientInfo=NULL):
    """
    RpcOpenPrinterEx retrieves a handle for a printer, port, port monitor, print job, or print server
    Full Documentation: https://msdn.microsoft.com/en-us/library/cc244809.aspx

    :param DCERPC_v5 dce: a connected DCE instance.
    :param string printerName: A string for a printer connection, printer object, server object, job object, port
    object, or port monitor object. This MUST be a Domain Name System (DNS), NetBIOS, Internet Protocol version 4
    (IPv4), Internet Protocol version 6 (IPv6), or Universal Naming Convention (UNC) name that remote procedure
    call (RpcAsync) binds to, and it MUST uniquely identify a print server on the network.
    :param string pDatatype: A string that specifies the data type to be associated with the printer handle.
    :param DEVMODE_CONTAINER pDevModeContainer: A DEVMODE_CONTAINER structure. This parameter MUST adhere to the specification in
    DEVMODE_CONTAINER Parameters (section 3.1.4.1.8.1).
    :param int accessRequired: The access level that the client requires for interacting with the object to which a
    handle is being opened.
    :param SPLCLIENT_CONTAINER pClientInfo: This parameter MUST adhere to the specification in SPLCLIENT_CONTAINER Parameters.

    :return: a RpcOpenPrinterExResponse instance, raises DCERPCSessionError on error.
    """
    request = RpcAsyncOpenPrinter()
    request['pPrinterName'] = checkNullString(printerName)
    request['pDatatype'] = pDatatype
    if pDevModeContainer is NULL:
        request['pDevModeContainer']['pDevMode'] = NULL
    else:
        request['pDevModeContainer'] = pDevModeContainer

    request['AccessRequired'] = accessRequired
    if pClientInfo is NULL:
        raise Exception('pClientInfo cannot be NULL')

    request['pClientInfo'] = pClientInfo
    return dce.request(request, MSRPC_UUID_WINSPOOL)


def hRpcAsyncEnumPrinters(dce, flags, name = NULL, level = 1):
    """
    RpcEnumPrinters enumerates available printers, print servers, domains, or print providers.
    Full Documentation: https://msdn.microsoft.com/en-us/library/cc244794.aspx

    :param DCERPC_v5 dce: a connected DCE instance.
    :param int flags: The types of print objects that this method enumerates. The value of this parameter is the
    result of a bitwise OR of one or more of the Printer Enumeration Flags (section 2.2.3.7).
    :param string name: NULL or a server name parameter as specified in Printer Server Name Parameters (section 3.1.4.1.4).
    :param level: The level of printer information structure.

    :return: a RpcEnumPrintersResponse instance, raises DCERPCSessionError on error.
    """
    request = RpcAsyncEnumPrinters()
    request['Flags'] = flags
    request['Name'] = name
    request['pPrinterEnum'] = NULL
    request['Level'] = level
    bytesNeeded = 0
    try:
        dce.request(request, MSRPC_UUID_WINSPOOL)
    except DCERPCSessionError as e:
        if str(e).find('ERROR_INSUFFICIENT_BUFFER') < 0:
            raise
        bytesNeeded = e.get_packet()['pcbNeeded']

    request = RpcAsyncEnumPrinters()
    request['Flags'] = flags
    request['Name'] = name
    request['Level'] = level

    request['cbBuf'] = bytesNeeded
    request['pPrinterEnum'] = b'a' * bytesNeeded
    return dce.request(request, MSRPC_UUID_WINSPOOL)


def hRpcAsyncAddPrinterDriver(dce, pName, pDriverContainer, dwFileCopyFlags):
    """
    RpcAddPrinterDriverEx installs a printer driver on the print server
    Full Documentation: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b

    :param DCERPC_v5 dce: a connected DCE instance.
    :param pName
    :param pDriverContainer
    :param dwFileCopyFlags

    :return: raises DCERPCSessionError on error.
    """
    request = RpcAsyncAddPrinterDriver()
    request['pName'] = checkNullString(pName)
    request['pDriverContainer'] = pDriverContainer
    request['dwFileCopyFlags'] = dwFileCopyFlags

    #return request
    return dce.request(request, MSRPC_UUID_WINSPOOL)


def hRpcAsyncEnumPrinterDrivers(dce, pName, pEnvironment, Level):
    """
    RpcEnumPrinterDrivers enumerates the printer drivers installed on a specified print server.
    Full Documentation: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/857d00ac-3682-4a0d-86ca-3d3c372e5e4a

    :param DCERPC_v5 dce: a connected DCE instance.
    :param pName
    :param pEnvironment
    :param Level
    :param pDrivers
    :param cbBuf
    :param pcbNeeded
    :param pcReturned

    :return: raises DCERPCSessionError on error.
    """
    # get value for cbBuf
    request = RpcAsyncEnumPrinterDrivers()
    request['pName']        = checkNullString(pName)
    request['pEnvironment'] = pEnvironment
    request['Level']        = Level
    request['pDrivers']     = NULL
    request['cbBuf']        = 0
    try:
        dce.request(request, MSRPC_UUID_WINSPOOL)
    except DCERPCSessionError as e:
        if str(e).find('ERROR_INSUFFICIENT_BUFFER') < 0:
            raise
        bytesNeeded = e.get_packet()['pcbNeeded']

    # now do RpcEnumPrinterDrivers again
    request = RpcAsyncEnumPrinterDrivers()
    request['pName']        = checkNullString(pName)
    request['pEnvironment'] = pEnvironment
    request['Level']        = Level
    request['pDrivers']     = b'a' * bytesNeeded
    request['cbBuf']        = bytesNeeded

    #return request
    return dce.request(request, MSRPC_UUID_WINSPOOL)

def hRpcAsyncGetPrinterDriverDirectory(dce, pName, pEnvironment, Level):
    """
    RpcAsyncGetPrinterDriverDirectory retrieves the path of the printer driver directory.
    Full Documentation: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/92206fb2-dd31-47f4-8d12-4cd239b71d78

    :param DCERPC_v5 dce: a connected DCE instance.
    :param pName
    :param pEnvironment
    :param Level
    :param pDriverDirectory
    :param cbBuf
    :param pcbNeeded

    :return: raises DCERPCSessionError on error.
    """
    # get value for cbBuf
    request = RpcAsyncGetPrinterDriverDirectory()
    request['pName']            = checkNullString(pName)
    request['pEnvironment']     = pEnvironment
    request['Level']            = Level
    request['pDriverDirectory'] = NULL
    request['cbBuf']            = 0
    try:
        dce.request(request, MSRPC_UUID_WINSPOOL)
    except DCERPCSessionError as e:
        if str(e).find('ERROR_INSUFFICIENT_BUFFER') < 0:
            raise
        bytesNeeded = e.get_packet()['pcbNeeded']
    
    # now do RpcGetPrinterDriverDirectory again
    request = RpcAsyncGetPrinterDriverDirectory()
    request['pName']            = checkNullString(pName)
    request['pEnvironment']     = pEnvironment
    request['Level']            = Level
    request['pDriverDirectory'] = b'a' * bytesNeeded
    request['cbBuf']            = bytesNeeded
    
    return dce.request(request, MSRPC_UUID_WINSPOOL)
