from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray, NDRUniVaryingArray, NDRUNION, \
    NDRSTRUCT
from impacket.dcerpc.v5.dtypes import WSTR, DWORD, LPWSTR, USHORT, UCHAR, ULONGLONG, ULONG, LARGE_INTEGER, GUID, \
    LPDWORD
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_EVENTLOG = uuidtup_to_bin(('F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EVENTLOG SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EVENTLOG SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

# Evt Path Flags
EvtQueryChannelName = 0x00000001
EvtQueryFilePath = 0x00000002
EvtReadNewestToLowest = 0x00000100
EvtReadLowestToNewest = 0x00000200

################################################################################
# STRUCTURES
################################################################################

class CONTEXT_HANDLE_LOG_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s=""'),
    )

class PCONTEXT_HANDLE_LOG_HANDLE(NDRPOINTER):
    referent = (
        ('Data', CONTEXT_HANDLE_LOG_HANDLE),
    )

class CONTEXT_HANDLE_LOG_QUERY(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s=""'),
    )

class PCONTEXT_HANDLE_LOG_QUERY(NDRPOINTER):
    referent = (
        ('Data', CONTEXT_HANDLE_LOG_QUERY),
    )

class LPPCONTEXT_HANDLE_LOG_QUERY(NDRPOINTER):
    referent = (
        ('Data', PCONTEXT_HANDLE_LOG_QUERY),
    )

class CONTEXT_HANDLE_OPERATION_CONTROL(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s=""'),
    )

class PCONTEXT_HANDLE_OPERATION_CONTROL(NDRPOINTER):
    referent = (
        ('Data', CONTEXT_HANDLE_OPERATION_CONTROL),
    )

class LPPCONTEXT_HANDLE_OPERATION_CONTROL(NDRPOINTER):
    referent = (
        ('Data', PCONTEXT_HANDLE_OPERATION_CONTROL),
    )

# 2.2.11 EvtRpcQueryChannelInfo
class EvtRpcQueryChannelInfo(NDRSTRUCT):
    structure = (
        ('Name', LPWSTR),
        ('Status', DWORD),
    )

class EvtRpcQueryChannelInfoArray(NDRUniVaryingArray):
    item = EvtRpcQueryChannelInfo

class LPEvtRpcQueryChannelInfoArray(NDRPOINTER):
    referent = (
        ('Data', EvtRpcQueryChannelInfoArray)
    )

class RPC_INFO(NDRSTRUCT):
    structure = (
        ('Error', DWORD),
        ('SubError', DWORD),
        ('SubErrorParam', DWORD),
    )

class PRPC_INFO(NDRPOINTER):
    referent = (
        ('Data', RPC_INFO)
    )

class WSTR_ARRAY(NDRUniVaryingArray):
    item = WSTR

class LPWSTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WSTR_ARRAY)
    )

class DWORD_ARRAY(NDRUniVaryingArray):
    item = DWORD

class LPDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY)
    )

class BYTE_ARRAY(NDRUniVaryingArray):
    item = 'c'

class LPBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY)
    )

class ULONG_ARRAY(NDRUniConformantArray):
    item = ULONG

# 2.3.1 EVENT_DESCRIPTOR
class EVENT_DESCRIPTOR(NDRSTRUCT):
    structure = (
        ('Id', USHORT),
        ('Version', UCHAR),
        ('Channel', UCHAR),
        ('Level', UCHAR),
        ('Opcode', UCHAR),
        ('Task', USHORT),
        ('Keyword', ULONGLONG),
    )

class PROCESSOR_TIME(NDRUNION):
    commonHdr = (
        ('ProcessorTime', ULONGLONG),
    )
    structure = (
        ('KernelTime', ULONG),
        ('UserTime', ULONG),
    )

# 2.3.2 EVENT_HEADER
class EVENT_HEADER(NDRSTRUCT):
    structure = (
        ('Size', USHORT),
        ('HeaderType', USHORT),
        ('Flags', USHORT),
        ('EventProperty', USHORT),
        ('ThreadId', ULONG),
        ('TimeStamp', LARGE_INTEGER),
        ('ProviderId', GUID),
        ('EventDescriptor', EVENT_DESCRIPTOR),
        ('ProcessorTime', PROCESSOR_TIME),
        ('ActivityId', GUID),
    )

#2.2.17 RESULT_SET
class RESULT_SET(NDRSTRUCT):
    structure = (
        ('TotalSize', DWORD),
        ('HeaderSize', '<L=0x10'),
        ('EventOffset', '<L=0x10'),
        ('BookmarkOffset', DWORD),
        ('BinXmlSize', DWORD),
        ('EventData', BYTE_ARRAY),
        ('NumberOfSubqueryIDs', DWORD),
        ('SubqueryIDs', DWORD),
        ('BookMarkData', BYTE_ARRAY),
        ('BookmarkSize', DWORD),
        ('HeaderSize', '<L=0x18'),
        ('ChannelSize', DWORD),
        ('ReadDirection', DWORD),
        ('RecordIdsOffset', DWORD),
        ('LogRecordNumbers', ULONG_ARRAY),
    )

#2.2.18 BinXmlVariant
class BinXmlVariant(NDRSTRUCT):
    structure = (
        ('Union', BYTE_ARRAY),
        ('Count', DWORD),
        ('Type', DWORD),
    )

################################################################################
# RPC CALLS
################################################################################

class EvtRpcRegisterLogQuery(NDRCALL):
    opnum = 5
    structure = (
        ('Path', LPWSTR),
        ('Query', WSTR),
        ('Flags', DWORD),
    )

class EvtRpcRegisterLogQueryResponse(NDRCALL):
    structure = (
        ('Handle', CONTEXT_HANDLE_LOG_QUERY),
        ('OpControl', CONTEXT_HANDLE_OPERATION_CONTROL),
        ('QueryChannelInfoSize', DWORD),
        ('QueryChannelInfo', EvtRpcQueryChannelInfoArray),
        ('Error', RPC_INFO),
        )

class EvtRpcQueryNext(NDRCALL):
    opnum = 11
    structure = (
        ('LogQuery', CONTEXT_HANDLE_LOG_QUERY),
        ('NumRequestedRecords', DWORD),
        ('TimeOutEnd', DWORD),
        ('Flags', DWORD),
    )

class EvtRpcQueryNextResponse(NDRCALL):
    structure = (
        ('NumActualRecords', DWORD),
        ('EventDataIndices', DWORD_ARRAY),
        ('EventDataSizes', DWORD_ARRAY),
        ('ResultBufferSize', DWORD),
        ('ResultBuffer', BYTE_ARRAY),
        ('ErrorCode', ULONG),
    )

class EvtRpcQuerySeek(NDRCALL):
    opnum = 12
    structure = (
        ('LogQuery', CONTEXT_HANDLE_LOG_QUERY),
        ('Pos', LARGE_INTEGER),
        ('BookmarkXML', LPWSTR),
        ('Flags', DWORD),
    )

class EvtRpcQuerySeekResponse(NDRCALL):
    structure = (
        ('Error', RPC_INFO),
    )

class EvtRpcClose(NDRCALL):
    opnum = 13
    structure = (
        ("Handle", CONTEXT_HANDLE_LOG_HANDLE),
    )

class EvtRpcCloseResponse(NDRCALL):
    structure = (
        ("Handle", PCONTEXT_HANDLE_LOG_HANDLE),
        ('ErrorCode', ULONG),
    )

class EvtRpcOpenLogHandle(NDRCALL):
    opnum = 17
    structure = (
        ('Channel', WSTR),
        ('Flags', DWORD),
    )

class EvtRpcOpenLogHandleResponse(NDRCALL):
    structure = (
        ('Handle', PCONTEXT_HANDLE_LOG_HANDLE),
        ('Error', RPC_INFO),
    )

class EvtRpcGetChannelList(NDRCALL):
    opnum = 19
    structure = (
        ('Flags', DWORD),
    )

class EvtRpcGetChannelListResponse(NDRCALL):
    structure = (
        ('NumChannelPaths', DWORD),
        ('ChannelPaths', WSTR_ARRAY),
        ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################

OPNUMS = {
    5   : (EvtRpcRegisterLogQuery, EvtRpcRegisterLogQueryResponse),
    11  : (EvtRpcQueryNext,  EvtRpcQueryNextResponse),
    12  : (EvtRpcQuerySeek, EvtRpcQuerySeekResponse),
    13  : (EvtRpcClose, EvtRpcCloseResponse),
    17  : (EvtRpcOpenLogHandle, EvtRpcOpenLogHandle),
    19  : (EvtRpcGetChannelList, EvtRpcGetChannelListResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def hEvtRpcRegisterLogQuery(dce, path, flags, query='*\x00'):
    request = EvtRpcRegisterLogQuery()

    request['Path'] = path
    request['Query'] = query
    request['Flags'] = flags
    resp = dce.request(request)
    return resp

def hEvtRpcQueryNext(dce, handle, numRequestedRecords, timeOutEnd=1000):
    request = EvtRpcQueryNext()

    request['LogQuery'] = handle
    request['NumRequestedRecords'] = numRequestedRecords
    request['TimeOutEnd'] = timeOutEnd
    request['Flags'] = 0
    status = system_errors.ERROR_MORE_DATA
    resp = dce.request(request)
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp

def hEvtRpcClose(dce, handle):
    request = EvtRpcClose()
    request['Handle'] = handle
    resp = dce.request(request)
    return resp

def hEvtRpcOpenLogHandle(dce, channel, flags):
    request = EvtRpcOpenLogHandle()

    request['Channel'] = channel
    request['Flags'] = flags
    return dce.request(request)

def hEvtRpcGetChannelList(dce):
    request = EvtRpcGetChannelList()

    request['Flags'] = 0
    resp = dce.request(request)
    return resp
