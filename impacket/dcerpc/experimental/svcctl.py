# Copyright (c) 2003-2013 CORE Security Technologies
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
#   [MS-SCMR] Interface implementation
#

import array
import random
from struct import *
from impacket import ImpactPacket
from impacket import dcerpc
from impacket.dcerpc import ndrutils, dcerpc
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc import ndr
from impacket.dcerpc.ndr import NDRCall, NDR, NDRPointer, UNIQUE_RPC_UNICODE_STRING, NDRLONG, WSTR, LPWSTR, RPC_UNICODE_STRING, PRPC_UNICODE_STRING, NDRPointerNULL, NDRUniConformantArray
from impacket.dcerpc.dtypes import *

MSRPC_UUID_SVCCTL = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))

# Error Codes 
ERROR_PATH_NOT_FOUND             = 3
ERROR_ACCESS_DENIED              = 5
ERROR_INVALID_HANDLE             = 6
ERROR_INVALID_DATA               = 13
ERROR_INVALID_PARAMETER          = 87
ERROR_INSUFICIENT_BUFFER         = 122
ERROR_INVALID_NAME               = 123
ERROR_INVALID_LEVEL              = 124
ERROR_MORE_DATA                  = 234
ERROR_DEPENDENT_SERVICES_RUNNING = 1051
ERROR_INVALID_SERVICE_CONTROL    = 1052
ERROR_SERVICE_REQUEST_TIMEOUT    = 1053
ERROR_SERVICE_ALREADY_RUNNING    = 1056
ERROR_INVALID_SERVICE_ACCOUNT    = 1057
ERROR_SERVICE_DISABLED           = 1058
ERROR_CIRCULAR_DEPENDENCY        = 1059
ERROR_SERVICE_DOES_NOT_EXISTS    = 1060
ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061
ERROR_SERVICE_NOT_ACTIVE         = 1062
ERROR_DATABASE_DOES_NOT_EXIST    = 1065
ERROR_SERVICE_LOGON_FAILURE      = 1069
ERROR_SERVICE_MARKED_FOR_DELETE  = 1072
ERROR_SERVICE_EXISTS             = 1073
ERROR_ALREADY_RUNNING_LKG        = 1074
ERROR_BOOT_ALREADY_ACCEPTED      = 1076
ERROR_DUPLICATE_SERVICE_NAME     = 1078
ERROR_SHUTDOWN_IN_PROGRESS       = 1115

# Access codes
SERVICE_ALL_ACCESS            = 0X000F01FF
SERVICE_CHANGE_CONFIG         = 0X00000002
SERVICE_ENUMERATE_DEPENDENTS  = 0X00000008
SERVICE_INTERROGATE           = 0X00000080
SERVICE_PAUSE_CONTINUE        = 0X00000040
SERVICE_QUERY_CONFIG          = 0X00000001
SERVICE_QUERY_STATUS          = 0X00000004
SERVICE_START                 = 0X00000010
SERVICE_STOP                  = 0X00000020
SERVICE_USER_DEFINED_CTRL     = 0X00000100
SERVICE_SET_STATUS            = 0X00008000

# Service Types
SERVICE_KERNEL_DRIVER         = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER    = 0x00000002
SERVICE_WIN32_OWN_PROCESS     = 0x00000010
SERVICE_WIN32_SHARE_PROCESS   = 0x00000020
SERVICE_INTERACTIVE_PROCESS   = 0x00000100
SERVICE_NO_CHANGE             = 0xffffffff

# Start Types
SERVICE_BOOT_START            = 0x00000000
SERVICE_SYSTEM_START          = 0x00000001
SERVICE_AUTO_START            = 0x00000002
SERVICE_DEMAND_START          = 0x00000003
SERVICE_DISABLED              = 0x00000004
SERVICE_NO_CHANGE             = 0xffffffff

# Error Control 
SERVICE_ERROR_IGNORE          = 0x00000000
SERVICE_ERROR_NORMAL          = 0x00000001
SERVICE_ERROR_SEVERE          = 0x00000002
SERVICE_ERROR_CRITICAL        = 0x00000003
SERVICE_NO_CHANGE             = 0xffffffff

# Service Control Codes
SERVICE_CONTROL_CONTINUE      = 0x00000003
SERVICE_CONTROL_INTERROGATE   = 0x00000004
SERVICE_CONTROL_PARAMCHANGE   = 0x00000006
SERVICE_CONTROL_PAUSE         = 0x00000002
SERVICE_CONTROL_STOP          = 0x00000001

# Service State
SERVICE_ACTIVE                = 0x00000001
SERVICE_INACTIVE              = 0x00000002
SERVICE_STATE_ALL             = 0x00000003

# Current State
SERVICE_CONTINUE_PENDING      = 0x00000005
SERVICE_PAUSE_PENDING         = 0x00000006
SERVICE_PAUSED                = 0x00000007
SERVICE_RUNNING               = 0x00000004
SERVICE_START_PENDING         = 0x00000002
SERVICE_STOP_PENDING          = 0x00000003
SERVICE_STOPPED               = 0x00000001

# Security Information
DACL_SECURITY_INFORMATION     = 0x4
GROUP_SECURITY_INFORMATION    = 0x2
OWNER_SECURITY_INFORMATION    = 0x1
SACL_SECURITY_INFORMATION     = 0x8

class SVCCTLSessionError(Exception):
    
    error_messages = {
 ERROR_PATH_NOT_FOUND            : ("ERROR_PATH_NOT_FOUND", "The system cannot find the path specified."),          
 ERROR_ACCESS_DENIED             : ("ERROR_ACCESS_DENIED", "Access is denied."),
 ERROR_INVALID_HANDLE            : ("ERROR_INVALID_HANDLE", "The handle is invalid."),
 ERROR_INVALID_DATA              : ("ERROR_INVALID_DATA", "The data is invalid."),
 ERROR_INVALID_PARAMETER         : ("ERROR_INVALID_PARAMETER", "The parameter is incorrect."),
 ERROR_INSUFICIENT_BUFFER        : ("ERROR_INSUFICIENT_BUFFER", "The data area passed to a system call is too small."), 
 ERROR_INVALID_NAME              : ("ERROR_INVALID_NAME", "The specified name is invalid."),
 ERROR_INVALID_LEVEL             : ("ERROR_INVALID_LEVEL", "The level specified contains an unsupported value."),           
 ERROR_MORE_DATA                 : ("ERROR_MORE_DATA", "More data is available."),
 ERROR_DEPENDENT_SERVICES_RUNNING: ("ERROR_DEPENDENT_SERVICES_RUNNING", "The service cannot be stopped because other running services are dependent on it."),
 ERROR_INVALID_SERVICE_CONTROL   : ("ERROR_INVALID_SERVICE_CONTROL", "The requested control code is not valid, or it is unacceptable to the service."),
 ERROR_SERVICE_REQUEST_TIMEOUT   : ("ERROR_SERVICE_REQUEST_TIMEOUT", "The request timed out."), 
 ERROR_SERVICE_ALREADY_RUNNING   : ("ERROR_SERVICE_ALREADY_RUNNING", "The target service is already running."),
 ERROR_INVALID_SERVICE_ACCOUNT   : ("ERROR_INVALID_SERVICE_ACCOUNT", "The service account specified does not exist."),   
 ERROR_SERVICE_DISABLED          : ("ERROR_SERVICE_DISABLED", "The service is disabled."),          
 ERROR_CIRCULAR_DEPENDENCY       : ("ERROR_CIRCULAR_DEPENDENCY", "A circular dependency was specified."), 
 ERROR_SERVICE_DOES_NOT_EXISTS   : ("ERROR_SERVICE_DOES_NOT_EXISTS", "The service does not exist in the SCM database."), 
 ERROR_SERVICE_CANNOT_ACCEPT_CTRL: ("ERROR_SERVICE_CANNOT_ACCEPT_CTRL", "The requested control code cannot be sent to the service."),
 ERROR_SERVICE_NOT_ACTIVE        : ("ERROR_SERVICE_NOT_ACTIVE", "The service has not been started."), 
 ERROR_DATABASE_DOES_NOT_EXIST   : ("ERROR_DATABASE_DOES_NOT_EXIST", "The database specified does not exists."), 
 ERROR_SERVICE_LOGON_FAILURE     : ("ERROR_SERVICE_LOGON_FAILURE", "The service did not start due to a logon failure."), 
 ERROR_SERVICE_MARKED_FOR_DELETE : ("ERROR_SERVICE_MARKED_FOR_DELETE", "The service has been marked for deletion."), 
 ERROR_SERVICE_EXISTS            : ("ERROR_SERVICE_EXISTS", "The service already exists."), 
 ERROR_DUPLICATE_SERVICE_NAME    : ("ERROR_DUPLICATE_SERVICE_NAME", "The service already exists."), 
 ERROR_SHUTDOWN_IN_PROGRESS      : ("ERROR_SHUTDOWN_IN_PROGRESS", "The system is shutting down."), 
 ERROR_ALREADY_RUNNING_LKG       : ("ERROR_ALREADY_RUNNING_LKG", "The system is currently running with the last-known-good configuration."),
 ERROR_BOOT_ALREADY_ACCEPTED     : ("ERROR_BOOT_ALREADY_ACCEPTED", "The BootAccepted field of the SCM on the target machine indicated that a successful call to RNotifyBootConfigStatus has already been made."),
    }    

    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        key = self.error_code
        if (SVCCTLSessionError.error_messages.has_key(key)):
            error_msg_short = SVCCTLSessionError.error_messages[key][0]
            error_msg_verbose = SVCCTLSessionError.error_messages[key][1] 
            return 'SVCCTL SessionError: code: %s - %s - %s' % (str(self.error_code), error_msg_short, error_msg_verbose)
        else:
            return 'SVCCTL SessionError: unknown error code: %s' % (str(self.error_code))
# RPC Structures
    
class SC_RPC_HANDLE(NDR):
    structure =  (
        ('Data','20s=""'),
    )

LPSC_RPC_HANDLE = SC_RPC_HANDLE

class SERVICE_STATUS(NDR):
    structure =  (
        ('dwServiceType',DWORD),
        ('dwCurrentState',DWORD),
        ('dwControlsAccepted',DWORD),
        ('dwWin32ExitCode',DWORD),
        ('dwServiceSpecificExitCode',DWORD),
        ('dwCheckPoint',DWORD),
        ('dwWaitHint',DWORD),
    )

class QUERY_SERVICE_CONFIGW(NDR):
    structure = (
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName',PRPC_UNICODE_STRING),
        ('lpLoadOrderGroup',PRPC_UNICODE_STRING),
        ('dwTagId',DWORD),
        ('lpDependencies',PRPC_UNICODE_STRING),
        ('lpServiceStartName',PRPC_UNICODE_STRING),
        ('lpDisplayName',PRPC_UNICODE_STRING),
    )

class SC_RPC_LOCK(NDR):
    structure =  (
        ('Data','20s=""'),
    )

LPSC_RPC_LOCK = SC_RPC_LOCK

class LPSERVICE_STATUS(NDRPointer):
    referent = (
        ('Data',SERVICE_STATUS),
    )

SECURITY_INFORMATION = NDRLONG

BOUNDED_DWORD_256K = DWORD

class LPBOUNDED_DWORD_256K(NDRPointer):
    referent = (
        ('Data', BOUNDED_DWORD_256K),
    )

# ToDo NOSE!
SVCCTL_HANDLEW = PRPC_UNICODE_STRING

class ENUM_SERVICE_STATUSW(NDR):
    structure = (
        ('lpServiceName',LPWSTR),
        ('lpDisplayName',LPWSTR),
        ('ServiceStatus',SERVICE_STATUS),
    )

class LPQUERY_SERVICE_CONFIGW(NDRPointer):
    referent = (
        ('Data', QUERY_SERVICE_CONFIGW),
    )

BOUNDED_DWORD_8K = DWORD

# RPC Calls
class RCloseServiceHandleCall(NDRCall):
    opnum = 0
    structure = (
        ('hSCObject',LPSC_RPC_HANDLE),
    )

class RCloseServiceHandleResponse(NDRCall):
    structure = (
        ('hSCObject',LPSC_RPC_HANDLE),
    )

class RControlServiceCall(NDRCall):
    opnum = 1
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwControl',DWORD),
    )

class RControlServiceResponse(NDRCall):
    structure = (
        ('lpServiceStatus',SERVICE_STATUS),
    )

class RDeleteServiceCall(NDRCall):
    opnum = 2
    structure = (
        ('hService',LPSC_RPC_HANDLE),
    )

class RDeleteServiceResponse(NDRCall):
    structure = (
    )

class RLockServiceDatabaseCall(NDRCall):
    opnum = 3
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
    )

class RLockServiceDatabaseResponse(NDRCall):
    structure = (
        ('lpLock',LPSC_RPC_LOCK),
    )

class RQueryServiceObjectSecurityCall(NDRCall):
    opnum = 4
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwSecurityInformation',SECURITY_INFORMATION),
        ('cbBufSize',DWORD),
    )

class RQueryServiceObjectSecurityResponse(NDRCall):
    structure = (
        ('lpSecurityDescriptor',LPBYTE),
        ('pcbBytesNeeded',LPBOUNDED_DWORD_256K),
    )

class RSetServiceObjectSecurityCall(NDRCall):
    opnum = 5
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwSecurityInformation',SECURITY_INFORMATION),
        ('lpSecurityDescriptor',LPBYTE),
        ('cbBufSize',DWORD),
    )

class RSetServiceObjectSecurityResponse(NDRCall):
    structure = (
    )

class RQueryServiceStatusCall(NDRCall):
    opnum = 6
    structure = (
        ('hService',SC_RPC_HANDLE),
    )

class RQueryServiceStatusResponse(NDRCall):
    structure = (
        ('lpServiceStatus',SERVICE_STATUS),
    )

class RSetServiceStatusCall(NDRCall):
    opnum = 7
    structure = (
        ('hServiceStatus',SC_RPC_HANDLE),
        ('lpServiceStatus',SERVICE_STATUS),
    )

class RSetServiceStatusResponse(NDRCall):
    structure = (
    )

class RUnlockServiceDatabaseCall(NDRCall):
    opnum = 8
    structure = (
        ('Lock',LPSC_RPC_LOCK),
    )

class RUnlockServiceDatabaseResponse(NDRCall):
    structure = (
        ('Lock',LPSC_RPC_LOCK),
    )

class RNotifyBootConfigStatusCall(NDRCall):
    opnum = 9
    structure = (
        ('lpMachineName',SVCCTL_HANDLEW),
        ('BootAcceptable',DWORD),
    )

class RNotifyBootConfigStatusResponse(NDRCall):
    structure = (
    )

class RChangeServiceConfigWCall(NDRCall):
    opnum = 11
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName',UNIQUE_RPC_UNICODE_STRING),
        ('lpLoadOrderGroup',UNIQUE_RPC_UNICODE_STRING),
        ('lpdwTagId',LPDWORD),
        ('lpDependencies',LPBYTE),
        ('dwDependSize',DWORD),
        ('lpServiceStartName',UNIQUE_RPC_UNICODE_STRING),
        ('lpPassword',LPBYTE),
        ('dwPwSize',DWORD),
        ('lpDisplayName',UNIQUE_RPC_UNICODE_STRING),
    )

class RChangeServiceConfigWResponse(NDRCall):
    structure = (
        ('lpdwTagId',LPDWORD),
    )

class RCreateServiceWCall(NDRCall):
    opnum = 12
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',RPC_UNICODE_STRING),
        ('lpDisplayName',UNIQUE_RPC_UNICODE_STRING),
        ('dwDesiredAccess',DWORD),
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName',RPC_UNICODE_STRING),
        ('lpLoadOrderGroup',UNIQUE_RPC_UNICODE_STRING),
        ('lpdwTagId',LPDWORD),
        ('lpDependencies',LPBYTE),
        ('dwDependSize',DWORD),
        ('lpServiceStartName',UNIQUE_RPC_UNICODE_STRING),
        ('lpPassword',LPBYTE),
        ('dwPwSize',DWORD),
    )

class RCreateServiceWResponse(NDRCall):
    structure = (
        ('lpdwTagId',UNIQUE_RPC_UNICODE_STRING),
        ('lpServiceHandle',LPSC_RPC_HANDLE)
    )

class REnumDependentServicesWCall(NDRCall):
    opnum = 13
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
    )

class REnumDependentServicesWResponse(NDRCall):
    structure = (
        ('lpServices',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
    )

class REnumServicesStatusWCall(NDRCall):
    opnum = 14
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('dwServiceType',DWORD),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
        ('lpResumeIndex',LPBOUNDED_DWORD_256K),
    )

class REnumServicesStatusWResponse(NDRCall):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
    )

class ROpenSCManagerWCall(NDRCall):
    opnum = 15
    structure = (
        ('lpMachineName',SVCCTL_HANDLEW),
        ('lpDatabaseName',UNIQUE_RPC_UNICODE_STRING),
        ('dwDesiredAccess',DWORD),
    )

class ROpenSCManagerWResponse(NDRCall):
    structure = (
        ('lpScHandle',LPSC_RPC_HANDLE),
    )

class ROpenServiceWCall(NDRCall):
    opnum = 16
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',RPC_UNICODE_STRING),
        ('dwDesiredAccess',DWORD),
    )

class ROpenServiceWResponse(NDRCall):
    structure = (
        ('lpServiceHandle',LPSC_RPC_HANDLE),
    )

class RQueryServiceConfigWCall(NDRCall):
    opnum = 17
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('cbBufSize',DWORD),
    )

class RQueryServiceConfigWResponse(NDRCall):
    structure = (
        ('lpServiceConfig',QUERY_SERVICE_CONFIGW),
        ('pcbBytesNeeded',BOUNDED_DWORD_8K),
    )


class DCERPCSvcCtl:
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
                raise SVCCTLSessionError(error_code)  
        return answer

    def RCloseServiceHandle(self, hSCObject):
        closeService = RCloseServiceHandleCall()
        closeService['hSCObject']['Data'] = hSCObject
        ans = self.doRequest(closeService)
        resp = RCloseServiceHandleResponse(ans)
        return resp

    def RControlService(self, hService, dwControl):
        controlService = RControlServiceCall()
        controlService['hService']['Data'] = hService
        controlService['dwControl']['Data'] = dwControl
        ans = self.doRequest(controlService)
        resp = RControlServiceResponse(ans)
        return resp

    def RDeleteService(self, hService):
        deleteService = RDeleteServiceCall()
        deleteService['hService']['Data'] = hService
        ans = self.doRequest(deleteService)
        resp = RDeleteServiceResponse(ans)
        return resp
    
    def RLockServiceDatabase(self, hSCManager):
        lockServiceDatabase = RLockServiceDatabaseCall()
        lockServiceDatabase['hSCManager']['Data'] = hSCManager
        ans = self.doRequest(lockServiceDatabase)
        resp = RLockServiceDatabaseResponse(ans)
        return resp

    def RQueryServiceObjectSecurity(self, hService, dwSecurityInformation, cbBufSize ):
        queryServiceObjectSecurity = RQueryServiceObjectSecurityCall()
        queryServiceObjectSecurity['hService']['Data'] = hService
        queryServiceObjectSecurity['dwSecurityInformation']['Data'] = dwSecurityInformation
        queryServiceObjectSecurity['cbBufSize']['Data'] = cbBufSize
        ans = self.doRequest(queryServiceObjectSecurity)
        resp = RQueryServiceObjectSecurityResponse(ans)
        return resp

    def RSetServiceObjectSecurity(self, hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize ):
        setServiceObjectSecurity = RSetServiceObjectSecurityCall()
        setServiceObjectSecurity['hService']['Data'] = hService
        setServiceObjectSecurity['dwSecurityInformation']['Data'] = dwSecurityInformation
        setServiceObjectSecurity['cbBufSize']['Data'] = cbBufSize
        ans = self.doRequest(setServiceObjectSecurity)
        resp = RSetServiceObjectSecurityResponse(ans)
        return resp

    def RQueryServiceStatus(self, hService ):
        queryServiceStatus = RQueryServiceStatusCall()
        queryServiceStatus['hService']['Data'] = hService
        ans = self.doRequest(queryServiceStatus)
        resp = RQueryServiceStatusResponse(ans)
        return resp

    def RSetServiceStatus(self, hServiceStatus, lpServiceStatus ):
        setServiceStatus = RSetServiceStatusCall()
        setServiceStatus['hServiceStatus']['Data'] = hServiceStatus
        setServiceStatus['lpServiceStatus']['Data'] = lpServiceStatus
        ans = self.doRequest(setServiceStatus)
        resp = RSetServiceStatusResponse(ans)
        return resp

    def RUnlockServiceDatabase(self, Lock ):
        unlockServiceDatabase = RUnlockServiceDatabaseCall()
        unlockServiceDatabase['Lock']['Data'] = Lock
        ans = self.doRequest(unlockServiceDatabase)
        resp = RUnlockServiceDatabaseResponse(ans)
        return resp

    def RNotifyBootConfigStatus(self, lpMachineName, BootAcceptable ):
        notifyBootConfigStatus = RNotifyBootConfigStatusCall()
        notifyBootConfigStatus['lpMachineName']['Data']['Data'] = lpMachineName
        notifyBootConfigStatus['BootAcceptable']['Data'] = BootAcceptable
        ans = self.doRequest(notifyBootConfigStatus)
        resp = RNotifyBootConfigStatusResponse(ans)
        return resp

    def RChangeServiceConfigW(self, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName):
        changeServiceConfig = RChangeServiceConfigWCall()
        changeServiceConfig['hService']['Data'] = hService
        changeServiceConfig['dwServiceType']['Data'] = dwServiceType
        changeServiceConfig['dwStartType']['Data'] = dwStartType
        changeServiceConfig['dwErrorControl']['Data'] = dwErrorControl
        if lpBinaryPathName == '':
            changeServiceConfig['lpBinaryPathName'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpBinaryPathName']['Data'] = lpBinaryPathName
        if lpLoadOrderGroup == '':
            changeServiceConfig['lpLoadOrderGroup'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpLoadOrderGroup']['Data'] = lpLoadOrderGroup

        if lpdwTagId == '':
            changeServiceConfig['lpdwTagId'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpdwTagId']['Data'] = lpdwTagId
        if lpDependencies == '':
            changeServiceConfig['lpDependencies'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpDependencies']['Data'] = lpDependencies
        if lpServiceStartName == '':
            changeServiceConfig['lpServiceStartName'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpServiceStartName']['Data'] = lpServiceStartName
        if lpPassword == '':
            changeServiceConfig['lpPassword'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpPassword']['Data'] = lpPassword
        changeServiceConfig['dwPwSize']['Data'] = dwPwSize
        if lpDisplayName == '':
            changeServiceConfig['lpDisplayName'] = NDRPointerNULL()
        else:
            changeServiceConfig['lpDisplayName']['Data'] = lpDisplayName
        ans = self.doRequest(changeServiceConfig)
        resp = RChangeServiceConfigWResponse(ans)
        return resp

    def RCreateServiceW(self, hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize):
        createService = RCreateServiceWCall()
        createService['hSCManager']['Data'] = hSCManager
        createService['lpServiceName']['Data'] = lpServiceName
        createService['lpDisplayName']['Data']['Data'] = lpDisplayName
        createService['dwDesiredAccess']['Data'] = dwDesiredAccess
        createService['dwServiceType']['Data'] = dwServiceType
        createService['dwStartType']['Data'] = dwStartType
        createService['dwErrorControl']['Data'] = dwErrorControl
        createService['lpBinaryPathName']['Data'] = lpBinaryPathName
        if lpLoadOrderGroup == '':
            createService['lpLoadOrderGroup'] = NDRPointerNULL() 
        else:
            createService['lpLoadOrderGroup']['Data']['Data'] = lpLoadOrderGroup
        if lpdwTagId == '':
            createService['lpdwTagId'] = NDRPointerNULL()
        else: 
            createService['lpdwTagId']['Data']['Data'] = lpdwTagId
        if lpDependencies == '':
            createService['lpDependencies'] = NDRPointerNULL()
        else:
            createService['lpDependencies']['Data']['Data'] = lpDependencies
        createService['dwDependSize']['Data'] = dwDependSize
        if lpServiceStartName == '':
            createService['lpServiceStartName'] = NDRPointerNULL()
        else:
            createService['lpServiceStartName']['Data']['Data'] = lpServiceStartName
        if lpPassword == '':
            createService['lpPassword'] = NDRPointerNULL()
        else:
            createService['lpPassword']['Data']['Data'] = lpPassword
        createService['dwPwSize']['Data'] = dwPwSize
        ans = self.doRequest(createService)
        resp = RCreateServiceWResponse(ans)
        return resp

    def REnumDependentServicesW(self, hService, dwServiceState, cbBufSize ):
        enumDependentServices = REnumDependentServicesWCall()
        enumDependentServices['hService']['Data'] = hService
        enumDependentServices['dwServiceState']['Data'] = dwServiceState
        enumDependentServices['cbBufSize']['Data'] = cbBufSize
        ans = self.doRequest(enumDependentServices, checkReturn = 0)
        resp = REnumDependentServicesWResponse(ans)
        return resp

    def REnumServicesStatusW(self, hSCManager, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex ):
        enumServicesStatus = REnumServicesStatusWCall()
        enumServicesStatus['hSCManager']['Data'] = hSCManager
        enumServicesStatus['dwServiceType']['Data'] = dwServiceType
        enumServicesStatus['dwServiceState']['Data'] = dwServiceState
        enumServicesStatus['cbBufSize']['Data'] = cbBufSize
        if lpResumeIndex == '':
            enumServicesStatus['lpResumeIndex'] = NDRPointerNULL()
        else:
            enumServicesStatus['lpResumeIndex']['Data'] = lpResumeIndex
        ans = self.doRequest(enumServicesStatus, checkReturn = 0)
        resp = REnumServicesStatusWResponse(ans)
        return resp

    def ROpenSCManagerW(self, lpMachineName, lpDatabaseName, dwDesiredAccess):
        openSCManager = ROpenSCManagerWCall()
        openSCManager['lpMachineName']['Data']['Data'] = lpMachineName
        if lpDatabaseName == '':
            openSCManager['lpDatabaseName'] = NDRPointerNULL()
        else:
            openSCManager['lpDatabaseName']['Data']['Data'] = lpDatabaseName
        openSCManager['dwDesiredAccess']['Data'] = dwDesiredAccess
        ans = self.doRequest(openSCManager)
        resp = ROpenSCManagerWResponse(ans)
        return resp

    def ROpenServiceW(self, hSCManager, lpServiceName, dwDesiredAccess):
        openService = ROpenServiceWCall()
        openService['hSCManager']['Data'] = hSCManager
        openService['lpServiceName']['Data'] = lpServiceName
        openService['dwDesiredAccess']['Data'] = dwDesiredAccess
        ans = self.doRequest(openService)
        resp = ROpenServiceWResponse(ans)
        return resp

    def RQueryServiceConfigW(self, hService, cbBufSize ):
        queryService = RQueryServiceConfigWCall()
        queryService['hService']['Data'] = hService
        queryService['cbBufSize']['Data'] = cbBufSize
        ans = self.doRequest(queryService, checkReturn = 0)
        resp = RQueryServiceConfigWResponse(ans)
        return resp

