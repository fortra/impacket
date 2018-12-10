# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Itamar (@MrAnde7son)
#
# Description:
#   [MS-EVEN] Interface implementation
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
from impacket import system_errors
from impacket.dcerpc.v5.dtypes import NULL, WSTR, LPWSTR, ULONG, RPC_UNICODE_STRING, NTSTATUS, \
    RPC_SID, USHORT, PRPC_UNICODE_STRING
from impacket.dcerpc.v5.ndr import NDRCALL, NDRArray, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_EVEN = uuidtup_to_bin(('82273FDC-E32A-18C3-3F78-827929DC23EA', '0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EVEN SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EVEN SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

# 2.2.2 EventType
EVENTLOG_SUCCESS            = 0x0000
EVENTLOG_ERROR_TYPE         = 0x0001
EVENTLOG_WARNING_TYPE       = 0x0002
EVENTLOG_INFORMATION_TYPE   = 0x0004
EVENTLOG_AUDIT_SUCCESS      = 0x0008
EVENTLOG_AUDIT_FAILURE      = 0x0010

# Read Flags
EVENTLOG_SEQUENTIAL_READ = 0x00000001
EVENTLOG_SEEK_READ = 0x00000002
EVENTLOG_FORWARDS_READ = 0x00000004
EVENTLOG_BACKWARDS_READ = 0x00000008

# 2.2.9 Constants Used in Method Definitions
MAX_STRINGS         = 0x00000100
MAX_SINGLE_EVENT    = 0x0003FFFF
MAX_BATCH_BUFF      = 0x0007FFFF

################################################################################
# STRUCTURES
################################################################################

EVENTLOG_HANDLE_W = LPWSTR

# 2.2.3 EVENTLOGRECORD
class EVENTLOGRECORD(NDRSTRUCT):
    structure =  (
        ('Length', '<L=0'),
        ('Reserved', '<L=0'),
        ('RecordName', '<L=0'),
        ('TimeGenerated', '<L=0'),
        ('TimeWritten', '<L=0'),
        ('EventID', '<L=0'),
        ('EventType', '<H=0'),
        ('NumStrings', '<H=0'),
        ('EventCategory', '<H=0'),
        ('ReservedFlags', '<H=0'),
        ('ClosingRecordNumber', '<L=0'),
        ('StringOffset', '<L=0'),
        ('UserSidLength', '<L=0'),
        ('UserSidOffset', '<L=0'),
        ('DataLength', '<L=0'),
        ('DataOffset', '<L=0'),
        ('SourceName', WSTR),
        ('ComputerName', WSTR),
        ('UserSidPadding', ':'),
        ('UserSid', RPC_SID),
        ('Strings', ':'),
        ('_Data', '_-Data', 'self["DataLength"]'),
        ('Data', ':'),
        ('Padding', ':'),
        ('Length2', '<L=0'),
    )

# 2.2.6 IELF_HANDLE
class IELF_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4

class EVENTLOG_READ_BUFFER(NDRArray):
    item = 'c'

    structure = (
        ('Len', '<L'),
        ('Data', '*Len'),
    )

class STRINGS_ARRAY(NDRArray):
    item = RPC_UNICODE_STRING

    structure = (
        ('Len', '<L'),
        ('Data', '*Len'),
    )
################################################################################
# RPC CALLS
################################################################################

class ElfrClearELFW(NDRCALL):
    opnum = 0
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('BackupFileName', RPC_UNICODE_STRING),
    )

class ElfrClearELFWResponse(NDRCALL):
    structure = (
        ('ErrorCode', NTSTATUS),
    )

class ElfrBackupELFW(NDRCALL):
    opnum = 1
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('BackupFileName', RPC_UNICODE_STRING),
    )

class ElfrBackupELFWResponse(NDRCALL):
    structure = (
        ('ErrorCode', NTSTATUS),
    )

class ElfrCloseEL(NDRCALL):
    opnum = 2
    structure = (
        ('LogHandle', IELF_HANDLE),
    )

class ElfrCloseELResponse(NDRCALL):
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', NTSTATUS),
    )

class ElfrNumberOfRecords(NDRCALL):
    opnum = 4
    structure = (
        ('LogHandle', IELF_HANDLE),
    )

class ElfrNumberOfRecordsResponse(NDRCALL):
    structure = (
        ('NumberOfRecords', ULONG),
        ('ErrorCode', NTSTATUS),
    )

class ElfrOpenELW(NDRCALL):
    opnum = 7
    structure = (
        ('UNCServerName', EVENTLOG_HANDLE_W),
        ('ModuleName', RPC_UNICODE_STRING),
        ('RegModuleName', RPC_UNICODE_STRING),
        ('MajorVersion', ULONG),
        ('MinorVersion', ULONG),
    )

class ElfrOpenELWResponse(NDRCALL):
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', NTSTATUS),
    )

class ElfrRegisterEventSourceW(NDRCALL):
    opnum = 8
    structure = (
        ('UNCServerName', EVENTLOG_HANDLE_W),
        ('ModuleName', RPC_UNICODE_STRING),
        ('RegModuleName', RPC_UNICODE_STRING),
        ('MajorVersion', ULONG),
        ('MinorVersion', ULONG),
    )

class ElfrRegisterEventSourceWResponse(NDRCALL):
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', NTSTATUS),
    )

class ElfrOpenBELW(NDRCALL):
    opnum = 9
    structure = (
        ('UNCServerName', EVENTLOG_HANDLE_W),
        ('BackupFileName', RPC_UNICODE_STRING),
        ('MajorVersion', ULONG),
        ('MinorVersion', ULONG),
    )

class ElfrOpenBELWResponse(NDRCALL):
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', NTSTATUS),
    )

class ElfrReadELW(NDRCALL):
    opnum = 10
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ReadFlags', ULONG),
        ('RecordOffset', ULONG),
        ('NumberOfBytesToRead', ULONG),
    )

class ElfrReadELWResponse(NDRCALL):
    structure = (
        ('Buffer', EVENTLOG_READ_BUFFER),
        ('NumberOfBytesRead', ULONG),
        ('NumberOfBytesNeeded', ULONG),
        ('ErrorCode', NTSTATUS),
    )

class ElfrReportEventW(NDRCALL):
    opnum = 11
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('Time', ULONG),
        ('EventType', USHORT),
        ('EventCategory', USHORT),
        ('EventID', ULONG),
        ('NumStrings', USHORT),
        ('DataSize', ULONG),
        ('ComputerName', PRPC_UNICODE_STRING),
        ('UserSID', RPC_SID),
        ('Strings', STRINGS_ARRAY),
        ('_Data', '_-Data', 'self["DataSize"]'),
        ('Data', ':'),
        ('Flags', USHORT),
    )

class ElfrReportEventWResponse(NDRCALL):
    structure = (
        ('RecordNumber', ULONG),
        ('TimeWritten', ULONG),
        ('ErrorCode', NTSTATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################

OPNUMS = {
    0   : (ElfrClearELFW, ElfrClearELFWResponse),
    1   : (ElfrBackupELFW, ElfrBackupELFWResponse),
    2   : (ElfrCloseEL, ElfrCloseELResponse),
    4   : (ElfrNumberOfRecords, ElfrNumberOfRecordsResponse),
    7   : (ElfrOpenELW, ElfrOpenELWResponse),
    8   : (ElfrRegisterEventSourceW, ElfrRegisterEventSourceWResponse),
    9   : (ElfrOpenBELW, ElfrOpenBELWResponse),
    10  : (ElfrReadELW, ElfrReadELWResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def hElfrOpenELW(dce, module_name, reg_module=''):
    request = ElfrOpenELW()

    request['UNCServerName'] = NULL
    request['ModuleName'] = module_name
    request['RegModuleName'] = reg_module
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    resp = dce.request(request)
    return resp

def hElfrOpenBELW(dce, backup_file):
    request = ElfrOpenBELW()

    request['UNCServerName'] = NULL
    request['BackupFileName'] = backup_file
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    resp = dce.request(request)
    return resp

def hElfrRegisterEventSourceW(dce, module_name, reg_module=''):
    request = ElfrRegisterEventSourceW()

    request['UNCServerName'] = NULL
    request['ModuleName'] = module_name
    request['RegModuleName'] = reg_module
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    resp = dce.request(request)
    return resp

def hElfrCloseEL(dce, log_handle):
    request = ElfrCloseEL()

    request['LogHandle'] = log_handle
    resp = dce.request(request)
    return resp

def hElfrClearELFW(dce, log_handle, backup_file):
    request = ElfrClearELFW()

    request['LogHandle'] = log_handle
    request['BackupFileName'] = backup_file
    resp = dce.request(request)
    return resp

def hElfrBackupELFW(dce, log_handle, backup_file):
    request = ElfrBackupELFW()

    request['LogHandle'] = log_handle
    request['BackupFileName'] = backup_file
    resp = dce.request(request)
    return resp

def hElfrNumberOfRecords(dce, log_handle):
    request = ElfrNumberOfRecords()

    request['LogHandle'] = log_handle
    resp = dce.request(request)
    return resp

def hElfrReadELW(dce, log_handle, flags=EVENTLOG_SEQUENTIAL_READ|EVENTLOG_FORWARDS_READ,
                 record_offset=0, bytes=MAX_SINGLE_EVENT):
    request = ElfrReadELW()

    request['LogHandle'] = log_handle
    request['ReadFlags'] = flags
    request['RecordOffset'] = record_offset
    request['NumberOfBytesToRead'] = bytes
    resp = dce.request(request)
    return resp
