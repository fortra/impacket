# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-TSCH] ITaskSchedulerService Interface implementation
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
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, WSTR, NULL, GUID, PSYSTEMTIME, SYSTEMTIME
from impacket.structure import Structure
from impacket import hresult_errors, system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_TSCHS  = uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C','1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif key & 0xffff in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key & 0xffff][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key & 0xffff][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'TSCH SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
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

# 2.3.9 TASK_LOGON_TYPE
TASK_LOGON_NONE                          = 0
TASK_LOGON_PASSWORD                      = 1
TASK_LOGON_S4U                           = 2
TASK_LOGON_INTERACTIVE_TOKEN             = 3
TASK_LOGON_GROUP                         = 4
TASK_LOGON_SERVICE_ACCOUNT               = 5
TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6

# 2.3.13 TASK_STATE
TASK_STATE_UNKNOWN  = 0
TASK_STATE_DISABLED = 1
TASK_STATE_QUEUED   = 2
TASK_STATE_READY    = 3
TASK_STATE_RUNNING  = 4

# 2.4.1 FIXDLEN_DATA
SCHED_S_TASK_READY         = 0x00041300
SCHED_S_TASK_RUNNING       = 0x00041301
SCHED_S_TASK_NOT_SCHEDULED = 0x00041301

# 2.4.2.11 Triggers
TASK_TRIGGER_FLAG_HAS_END_DATE         = 0
TASK_TRIGGER_FLAG_KILL_AT_DURATION_END = 0
TASK_TRIGGER_FLAG_DISABLED             = 0

# ToDo: Change this to enums
ONCE                 = 0
DAILY                = 1
WEEKLY               = 2
MONTHLYDATE          = 3
MONTHLYDOW           = 4
EVENT_ON_IDLE        = 5
EVENT_AT_SYSTEMSTART = 6
EVENT_AT_LOGON       = 7

SUNDAY    = 0
MONDAY    = 1
TUESDAY   = 2
WEDNESDAY = 3
THURSDAY  = 4
FRIDAY    = 5
SATURDAY  = 6

JANUARY   = 1
FEBRUARY  = 2
MARCH     = 3
APRIL     = 4
MAY       = 5
JUNE      = 6
JULY      = 7
AUGUST    = 8
SEPTEMBER = 9
OCTOBER   = 10
NOVEMBER  = 11
DECEMBER  = 12

# 2.4.2.11.8 MONTHLYDOW Trigger
FIRST_WEEK  = 1
SECOND_WEEK = 2
THIRD_WEEK  = 3
FOURTH_WEEK = 4
LAST_WEEK   = 5

# 2.3.12 TASK_NAMES
TASK_NAMES = LPWSTR

# 3.2.5.4.2 SchRpcRegisterTask (Opnum 1)
TASK_VALIDATE_ONLY                = 1<<(31-31)
TASK_CREATE                       = 1<<(31-30)
TASK_UPDATE                       = 1<<(31-29)
TASK_DISABLE                      = 1<<(31-28)
TASK_DON_ADD_PRINCIPAL_ACE        = 1<<(31-27)
TASK_IGNORE_REGISTRATION_TRIGGERS = 1<<(31-26)

# 3.2.5.4.5 SchRpcSetSecurity (Opnum 4)
TASK_DONT_ADD_PRINCIPAL_ACE = 1<<(31-27)
SCH_FLAG_FOLDER             = 1<<(31-2)
SCH_FLAG_TASK               = 1<<(31-1) 

# 3.2.5.4.7 SchRpcEnumFolders (Opnum 6)
TASK_ENUM_HIDDEN = 1

# 3.2.5.4.13 SchRpcRun (Opnum 12)
TASK_RUN_AS_SELF            = 1<<(31-31)
TASK_RUN_IGNORE_CONSTRAINTS = 1<<(31-30)
TASK_RUN_USE_SESSION_ID     = 1<<(31-29)
TASK_RUN_USER_SID           = 1<<(31-28)

# 3.2.5.4.18 SchRpcGetTaskInfo (Opnum 17)
SCH_FLAG_STATE            = 1<<(31-3)

################################################################################
# STRUCTURES
################################################################################
# 2.3.12 TASK_NAMES
class TASK_NAMES_ARRAY(NDRUniConformantArray):
    item = TASK_NAMES

class PTASK_NAMES_ARRAY(NDRPOINTER):
    referent = (
        ('Data',TASK_NAMES_ARRAY),
    )

class WSTR_ARRAY(NDRUniConformantArray):
    item = WSTR

class PWSTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data',WSTR_ARRAY),
    )

class GUID_ARRAY(NDRUniConformantArray):
    item = GUID

class PGUID_ARRAY(NDRPOINTER):
    referent = (
        ('Data',GUID_ARRAY),
    )

# 3.2.5.4.13 SchRpcRun (Opnum 12)
class SYSTEMTIME_ARRAY(NDRUniConformantArray):
    item = SYSTEMTIME

class PSYSTEMTIME_ARRAY(NDRPOINTER):
    referent = (
        ('Data',SYSTEMTIME_ARRAY),
    )

# 2.3.8 TASK_USER_CRED
class TASK_USER_CRED(NDRSTRUCT):
    structure =  (
        ('userId',LPWSTR),
        ('password',LPWSTR),
        ('flags',DWORD),
    )

class TASK_USER_CRED_ARRAY(NDRUniConformantArray):
    item = TASK_USER_CRED

class LPTASK_USER_CRED_ARRAY(NDRPOINTER):
    referent = (
        ('Data',TASK_USER_CRED_ARRAY),
    )

# 2.3.10 TASK_XML_ERROR_INFO
class TASK_XML_ERROR_INFO(NDRSTRUCT):
    structure =  (
        ('line',DWORD),
        ('column',DWORD),
        ('node',LPWSTR),
        ('value',LPWSTR),
    )

class PTASK_XML_ERROR_INFO(NDRPOINTER):
    referent = (
        ('Data',TASK_XML_ERROR_INFO),
    )

# 2.4.1 FIXDLEN_DATA
class FIXDLEN_DATA(Structure):
    structure = (
        ('Product Version','<H=0'),
        ('File Version','<H=0'),
        ('Job uuid','16s="'),
        ('App Name Len Offset','<H=0'),
        ('Trigger Offset','<H=0'),
        ('Error Retry Count','<H=0'),
        ('Error Retry Interval','<H=0'),
        ('Idle Deadline','<H=0'),
        ('Idle Wait','<H=0'),
        ('Priority','<L=0'),
        ('Maximum Run Time','<L=0'),
        ('Exit Code','<L=0'),
        ('Status','<L=0'),
        ('Flags','<L=0'),
    )

# 2.4.2.11 Triggers
class TRIGGERS(Structure):
    structure = (
        ('Trigger Size','<H=0'),
        ('Reserved1','<H=0'),
        ('Begin Year','<H=0'),
        ('Begin Month','<H=0'),
        ('Begin Day','<H=0'),
        ('End Year','<H=0'),
        ('End Month','<H=0'),
        ('End Day','<H=0'),
        ('Start Hour','<H=0'),
        ('Start Minute','<H=0'),
        ('Minutes Duration','<L=0'),
        ('Minutes Interval','<L=0'),
        ('Flags','<L=0'),
        ('Trigger Type','<L=0'),
        ('TriggerSpecific0','<H=0'),
        ('TriggerSpecific1','<H=0'),
        ('TriggerSpecific2','<H=0'),
        ('Padding','<H=0'),
        ('Reserved2','<H=0'),
        ('Reserved3','<H=0'),
    )

# 2.4.2.11.6 WEEKLY Trigger
class WEEKLY(Structure):
    structure = (
        ('Trigger Type','<L=0'),
        ('Weeks Interval','<H=0'),
        ('DaysOfTheWeek','<H=0'),
        ('Unused','<H=0'),
        ('Padding','<H=0'),
    )

# 2.4.2.11.7 MONTHLYDATE Trigger
class MONTHLYDATE(Structure):
    structure = (
        ('Trigger Type','<L=0'),
        ('Days','<L=0'),
        ('Months','<H=0'),
        ('Padding','<H=0'),
    )

# 2.4.2.11.8 MONTHLYDOW Trigger
class MONTHLYDOW(Structure):
    structure = (
        ('Trigger Type','<L=0'),
        ('WhichWeek','<H=0'),
        ('DaysOfTheWeek','<H=0'),
        ('Months','<H=0'),
        ('Padding','<H=0'),
        ('Reserved2','<H=0'),
        ('Reserved3','<H=0'),
    )

# 2.4.2.12 Job Signature
class JOB_SIGNATURE(Structure):
    structure = (
        ('SignatureVersion','<HH0'),
        ('MinClientVersion','<H=0'),
        ('Signature','64s="'),
    )

################################################################################
# RPC CALLS
################################################################################
# 3.2.5.4.1 SchRpcHighestVersion (Opnum 0)
class SchRpcHighestVersion(NDRCALL):
    opnum = 0
    structure = (
    )

class SchRpcHighestVersionResponse(NDRCALL):
    structure = (
        ('pVersion', DWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.2 SchRpcRegisterTask (Opnum 1)
class SchRpcRegisterTask(NDRCALL):
    opnum = 1
    structure = (
        ('path', LPWSTR),
        ('xml', WSTR),
        ('flags', DWORD),
        ('sddl', LPWSTR),
        ('logonType', DWORD),
        ('cCreds', DWORD),
        ('pCreds', LPTASK_USER_CRED_ARRAY),
    )

class SchRpcRegisterTaskResponse(NDRCALL):
    structure = (
        ('pActualPath', LPWSTR),
        ('pErrorInfo', PTASK_XML_ERROR_INFO),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.3 SchRpcRetrieveTask (Opnum 2)
class SchRpcRetrieveTask(NDRCALL):
    opnum = 2
    structure = (
        ('path', WSTR),
        ('lpcwszLanguagesBuffer', WSTR),
        ('pulNumLanguages', DWORD),
    )

class SchRpcRetrieveTaskResponse(NDRCALL):
    structure = (
        ('pXml', LPWSTR),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.4 SchRpcCreateFolder (Opnum 3)
class SchRpcCreateFolder(NDRCALL):
    opnum = 3
    structure = (
        ('path', WSTR),
        ('sddl', LPWSTR),
        ('flags', DWORD),
    )

class SchRpcCreateFolderResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.5 SchRpcSetSecurity (Opnum 4)
class SchRpcSetSecurity(NDRCALL):
    opnum = 4
    structure = (
        ('path', WSTR),
        ('sddl', WSTR),
        ('flags', DWORD),
    )

class SchRpcSetSecurityResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.6 SchRpcGetSecurity (Opnum 5)
class SchRpcGetSecurity(NDRCALL):
    opnum = 5
    structure = (
        ('path', WSTR),
        ('securityInformation', DWORD),
    )

class SchRpcGetSecurityResponse(NDRCALL):
    structure = (
        ('sddl',LPWSTR),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.7 SchRpcEnumFolders (Opnum 6)
class SchRpcEnumFolders(NDRCALL):
    opnum = 6
    structure = (
        ('path', WSTR),
        ('flags', DWORD),
        ('startIndex', DWORD),
        ('cRequested', DWORD),
    )

class SchRpcEnumFoldersResponse(NDRCALL):
    structure = (
        ('startIndex', DWORD),
        ('pcNames', DWORD),
        ('pNames', PTASK_NAMES_ARRAY),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.8 SchRpcEnumTasks (Opnum 7)
class SchRpcEnumTasks(NDRCALL):
    opnum = 7
    structure = (
        ('path', WSTR),
        ('flags', DWORD),
        ('startIndex', DWORD),
        ('cRequested', DWORD),
    )

class SchRpcEnumTasksResponse(NDRCALL):
    structure = (
        ('startIndex', DWORD),
        ('pcNames', DWORD),
        ('pNames', PTASK_NAMES_ARRAY),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.9 SchRpcEnumInstances (Opnum 8)
class SchRpcEnumInstances(NDRCALL):
    opnum = 8
    structure = (
        ('path', LPWSTR),
        ('flags', DWORD),
    )

class SchRpcEnumInstancesResponse(NDRCALL):
    structure = (
        ('pcGuids', DWORD),
        ('pGuids', PGUID_ARRAY),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.10 SchRpcGetInstanceInfo (Opnum 9)
class SchRpcGetInstanceInfo(NDRCALL):
    opnum = 9
    structure = (
        ('guid', GUID),
    )

class SchRpcGetInstanceInfoResponse(NDRCALL):
    structure = (
        ('pPath', LPWSTR),
        ('pState', DWORD),
        ('pCurrentAction', LPWSTR),
        ('pInfo', LPWSTR),
        ('pcGroupInstances', DWORD),
        ('pGroupInstances', PGUID_ARRAY),
        ('pEnginePID', DWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.11 SchRpcStopInstance (Opnum 10)
class SchRpcStopInstance(NDRCALL):
    opnum = 10
    structure = (
        ('guid', GUID),
        ('flags', DWORD),
    )

class SchRpcStopInstanceResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.12 SchRpcStop (Opnum 11)
class SchRpcStop(NDRCALL):
    opnum = 11
    structure = (
        ('path', LPWSTR),
        ('flags', DWORD),
    )

class SchRpcStopResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.13 SchRpcRun (Opnum 12)
class SchRpcRun(NDRCALL):
    opnum = 12
    structure = (
        ('path', WSTR),
        ('cArgs', DWORD),
        ('pArgs', PWSTR_ARRAY),
        ('flags', DWORD),
        ('sessionId', DWORD),
        ('user', LPWSTR),
    )

class SchRpcRunResponse(NDRCALL):
    structure = (
        ('pGuid', GUID),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.14 SchRpcDelete (Opnum 13)
class SchRpcDelete(NDRCALL):
    opnum = 13
    structure = (
        ('path', WSTR),
        ('flags', DWORD),
    )

class SchRpcDeleteResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.15 SchRpcRename (Opnum 14)
class SchRpcRename(NDRCALL):
    opnum = 14
    structure = (
        ('path', WSTR),
        ('newName', WSTR),
        ('flags', DWORD),
    )

class SchRpcRenameResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.16 SchRpcScheduledRuntimes (Opnum 15)
class SchRpcScheduledRuntimes(NDRCALL):
    opnum = 15
    structure = (
        ('path', WSTR),
        ('start', PSYSTEMTIME),
        ('end', PSYSTEMTIME),
        ('flags', DWORD),
        ('cRequested', DWORD),
    )

class SchRpcScheduledRuntimesResponse(NDRCALL):
    structure = (
        ('pcRuntimes',DWORD),
        ('pRuntimes',PSYSTEMTIME_ARRAY),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.17 SchRpcGetLastRunInfo (Opnum 16)
class SchRpcGetLastRunInfo(NDRCALL):
    opnum = 16
    structure = (
        ('path', WSTR),
    )

class SchRpcGetLastRunInfoResponse(NDRCALL):
    structure = (
        ('pLastRuntime',SYSTEMTIME),
        ('pLastReturnCode',DWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.18 SchRpcGetTaskInfo (Opnum 17)
class SchRpcGetTaskInfo(NDRCALL):
    opnum = 17
    structure = (
        ('path', WSTR),
        ('flags', DWORD),
    )

class SchRpcGetTaskInfoResponse(NDRCALL):
    structure = (
        ('pEnabled',DWORD),
        ('pState',DWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.19 SchRpcGetNumberOfMissedRuns (Opnum 18)
class SchRpcGetNumberOfMissedRuns(NDRCALL):
    opnum = 18
    structure = (
        ('path', WSTR),
    )

class SchRpcGetNumberOfMissedRunsResponse(NDRCALL):
    structure = (
        ('pNumberOfMissedRuns',DWORD),
        ('ErrorCode',ULONG),
    )

# 3.2.5.4.20 SchRpcEnableTask (Opnum 19)
class SchRpcEnableTask(NDRCALL):
    opnum = 19
    structure = (
        ('path', WSTR),
        ('enabled', DWORD),
    )

class SchRpcEnableTaskResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (SchRpcHighestVersion,SchRpcHighestVersionResponse ),
 1 : (SchRpcRegisterTask,SchRpcRegisterTaskResponse ),
 2 : (SchRpcRetrieveTask,SchRpcRetrieveTaskResponse ),
 3 : (SchRpcCreateFolder,SchRpcCreateFolderResponse ),
 4 : (SchRpcSetSecurity,SchRpcSetSecurityResponse ),
 5 : (SchRpcGetSecurity,SchRpcGetSecurityResponse ),
 6 : (SchRpcEnumFolders,SchRpcEnumFoldersResponse ),
 7 : (SchRpcEnumTasks,SchRpcEnumTasksResponse ),
 8 : (SchRpcEnumInstances,SchRpcEnumInstancesResponse ),
 9 : (SchRpcGetInstanceInfo,SchRpcGetInstanceInfoResponse ),
 10 : (SchRpcStopInstance,SchRpcStopInstanceResponse ),
 11 : (SchRpcStop,SchRpcStopResponse ),
 12 : (SchRpcRun,SchRpcRunResponse ),
 13 : (SchRpcDelete,SchRpcDeleteResponse ),
 14 : (SchRpcRename,SchRpcRenameResponse ),
 15 : (SchRpcScheduledRuntimes,SchRpcScheduledRuntimesResponse ),
 16 : (SchRpcGetLastRunInfo,SchRpcGetLastRunInfoResponse ),
 17 : (SchRpcGetTaskInfo,SchRpcGetTaskInfoResponse ),
 18 : (SchRpcGetNumberOfMissedRuns,SchRpcGetNumberOfMissedRunsResponse),
 19 : (SchRpcEnableTask,SchRpcEnableTaskResponse),
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

def hSchRpcHighestVersion(dce):
    return dce.request(SchRpcHighestVersion())

def hSchRpcRegisterTask(dce, path, xml, flags, sddl, logonType, pCreds = ()):
    request = SchRpcRegisterTask()
    request['path'] = checkNullString(path)
    request['xml'] = checkNullString(xml)
    request['flags'] = flags
    request['sddl'] = sddl
    request['logonType'] = logonType
    request['cCreds'] = len(pCreds)
    if len(pCreds) == 0:
        request['pCreds'] = NULL
    else:
        for cred in pCreds:
            request['pCreds'].append(cred)
    return dce.request(request)

def hSchRpcRetrieveTask(dce, path, lpcwszLanguagesBuffer = '\x00', pulNumLanguages=0 ):
    schRpcRetrieveTask = SchRpcRetrieveTask()
    schRpcRetrieveTask['path'] = checkNullString(path)
    schRpcRetrieveTask['lpcwszLanguagesBuffer'] = lpcwszLanguagesBuffer
    schRpcRetrieveTask['pulNumLanguages'] = pulNumLanguages
    return dce.request(schRpcRetrieveTask)

def hSchRpcCreateFolder(dce, path, sddl = NULL):
    schRpcCreateFolder = SchRpcCreateFolder()
    schRpcCreateFolder['path'] = checkNullString(path)
    schRpcCreateFolder['sddl'] = sddl
    schRpcCreateFolder['flags'] = 0
    return dce.request(schRpcCreateFolder)

def hSchRpcSetSecurity(dce, path, sddl, flags):
    schRpcSetSecurity = SchRpcSetSecurity()
    schRpcSetSecurity['path'] = checkNullString(path)
    schRpcSetSecurity['sddl'] = checkNullString(sddl)
    schRpcSetSecurity['flags'] = flags
    return dce.request(schRpcSetSecurity)

def hSchRpcGetSecurity(dce, path, securityInformation=0xffffffff):
    schRpcGetSecurity = SchRpcGetSecurity()
    schRpcGetSecurity['path'] = checkNullString(path)
    schRpcGetSecurity['securityInformation'] = securityInformation
    return dce.request(schRpcGetSecurity)

def hSchRpcEnumFolders(dce, path, flags=TASK_ENUM_HIDDEN, startIndex=0, cRequested=0xffffffff):
    schRpcEnumFolders = SchRpcEnumFolders()
    schRpcEnumFolders['path'] = checkNullString(path)
    schRpcEnumFolders['flags'] = flags
    schRpcEnumFolders['startIndex'] = startIndex
    schRpcEnumFolders['cRequested'] = cRequested
    return dce.request(schRpcEnumFolders)

def hSchRpcEnumTasks(dce, path, flags=TASK_ENUM_HIDDEN, startIndex=0, cRequested=0xffffffff):
    schRpcEnumTasks = SchRpcEnumTasks()
    schRpcEnumTasks['path'] = checkNullString(path)
    schRpcEnumTasks['flags'] = flags
    schRpcEnumTasks['startIndex'] = startIndex
    schRpcEnumTasks['cRequested'] = cRequested
    return dce.request(schRpcEnumTasks)

def hSchRpcEnumInstances(dce, path, flags=TASK_ENUM_HIDDEN):
    schRpcEnumInstances = SchRpcEnumInstances()
    schRpcEnumInstances['path'] = checkNullString(path)
    schRpcEnumInstances['flags'] = flags
    return dce.request(schRpcEnumInstances)

def hSchRpcGetInstanceInfo(dce, guid):
    schRpcGetInstanceInfo = SchRpcGetInstanceInfo()
    schRpcGetInstanceInfo['guid'] = guid
    return dce.request(schRpcGetInstanceInfo)

def hSchRpcStopInstance(dce, guid, flags = 0):
    schRpcStopInstance = SchRpcStopInstance()
    schRpcStopInstance['guid'] = guid
    schRpcStopInstance['flags'] = flags
    return dce.request(schRpcStopInstance)

def hSchRpcStop(dce, path, flags = 0):
    schRpcStop= SchRpcStop()
    schRpcStop['path'] = checkNullString(path)
    schRpcStop['flags'] = flags
    return dce.request(schRpcStop)

def hSchRpcRun(dce, path, pArgs=(), flags=0, sessionId=0, user = NULL):
    schRpcRun = SchRpcRun()
    schRpcRun['path'] = checkNullString(path)
    schRpcRun['cArgs'] = len(pArgs)
    for arg in pArgs:
        argn = LPWSTR()
        argn['Data'] = checkNullString(arg)
        schRpcRun['pArgs'].append(argn)
    schRpcRun['flags'] = flags
    schRpcRun['sessionId'] = sessionId
    schRpcRun['user'] = user
    return dce.request(schRpcRun)

def hSchRpcDelete(dce, path, flags = 0):
    schRpcDelete = SchRpcDelete()
    schRpcDelete['path'] = checkNullString(path)
    schRpcDelete['flags'] = flags
    return dce.request(schRpcDelete)

def hSchRpcRename(dce, path, newName, flags = 0):
    schRpcRename = SchRpcRename()
    schRpcRename['path'] = checkNullString(path)
    schRpcRename['newName'] = checkNullString(newName)
    schRpcRename['flags'] = flags
    return dce.request(schRpcRename)

def hSchRpcScheduledRuntimes(dce, path, start = NULL, end = NULL, flags = 0, cRequested = 10):
    schRpcScheduledRuntimes = SchRpcScheduledRuntimes()
    schRpcScheduledRuntimes['path'] = checkNullString(path)
    schRpcScheduledRuntimes['start'] = start
    schRpcScheduledRuntimes['end'] = end
    schRpcScheduledRuntimes['flags'] = flags
    schRpcScheduledRuntimes['cRequested'] = cRequested
    return dce.request(schRpcScheduledRuntimes)

def hSchRpcGetLastRunInfo(dce, path):
    schRpcGetLastRunInfo = SchRpcGetLastRunInfo()
    schRpcGetLastRunInfo['path'] = checkNullString(path)
    return dce.request(schRpcGetLastRunInfo)

def hSchRpcGetTaskInfo(dce, path, flags = 0):
    schRpcGetTaskInfo = SchRpcGetTaskInfo()
    schRpcGetTaskInfo['path'] = checkNullString(path)
    schRpcGetTaskInfo['flags'] = flags
    return dce.request(schRpcGetTaskInfo)

def hSchRpcGetNumberOfMissedRuns(dce, path):
    schRpcGetNumberOfMissedRuns = SchRpcGetNumberOfMissedRuns()
    schRpcGetNumberOfMissedRuns['path'] = checkNullString(path)
    return dce.request(schRpcGetNumberOfMissedRuns)

def hSchRpcEnableTask(dce, path, enabled = True):
    schRpcEnableTask = SchRpcEnableTask()
    schRpcEnableTask['path'] = checkNullString(path)
    if enabled is True:
        schRpcEnableTask['enabled'] = 1
    else:
        schRpcEnableTask['enabled'] = 0
    return dce.request(schRpcEnableTask)
