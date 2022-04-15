# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-SCMR] Interface implementation
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

from impacket import system_errors
from impacket.dcerpc.v5.dtypes import NULL, DWORD, LPWSTR, ULONG, BOOL, LPBYTE, ULONGLONG, PGUID, USHORT, LPDWORD, WSTR, \
    GUID, PBOOL, WIDESTR
from impacket.dcerpc.v5.ndr import NDRCALL, NDR, NDRSTRUCT, NDRPOINTER, NDRPOINTERNULL, NDRUniConformantArray, NDRUNION
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_SCMR = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'SCMR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SCMR SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

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

# Specific Access for SCM
SC_MANAGER_LOCK               = 0x00000008
SC_MANAGER_CREATE_SERVICE     = 0x00000002
SC_MANAGER_ENUMERATE_SERVICE  = 0x00000004
SC_MANAGER_CONNECT            = 0x00000001
SC_MANAGER_QUERY_LOCK_STATUS  = 0x00000010
SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020

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
SERVICE_CONTROL_NETBINDADD    = 0x00000007
SERVICE_CONTROL_NETBINDREMOVE = 0x00000008
SERVICE_CONTROL_NETBINDENABLE = 0x00000009
SERVICE_CONTROL_NETBINDDISABLE= 0x0000000A

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

# Controls Accepted
SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
SERVICE_ACCEPT_STOP                  = 0x00000001
SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
SERVICE_ACCEPT_POWEREVENT            = 0x00000040
SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100
SERVICE_ACCEPT_TIMECHANGE            = 0x00000200
ERVICE_ACCEPT_TRIGGEREVENT           = 0x00000400

# Security Information
DACL_SECURITY_INFORMATION     = 0x4
GROUP_SECURITY_INFORMATION    = 0x2
OWNER_SECURITY_INFORMATION    = 0x1
SACL_SECURITY_INFORMATION     = 0x8

# Service Config2 Info Levels
SERVICE_CONFIG_DESCRIPTION              = 0x00000001
SERVICE_CONFIG_FAILURE_ACTIONS          = 0x00000002
SERVICE_CONFIG_DELAYED_AUTO_START_INFO  = 0x00000003
SERVICE_CONFIG_FAILURE_ACTIONS_FLAG     = 0x00000004
SERVICE_CONFIG_SERVICE_SID_INFO         = 0x00000005
SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 0x00000006
SERVICE_CONFIG_PRESHUTDOWN_INFO         = 0x00000007
SERVICE_CONFIG_PREFERRED_NODE           = 0x00000009
SERVICE_CONFIG_RUNLEVEL_INFO            = 0x0000000A

# SC_ACTIONS Types
SC_ACTION_NONE        = 0
SC_ACTION_RESTART     = 1
SC_ACTION_REBOOT      = 2
SC_ACTION_RUN_COMMAND = 3

# SERVICE_SID_INFO types
SERVICE_SID_TYPE_NONE         = 0x00000000
SERVICE_SID_TYPE_RESTRICTED   = 0x00000003
SERVICE_SID_TYPE_UNRESTRICTED = 0x00000001

# SC_STATUS_TYPE types
SC_STATUS_PROCESS_INFO = 0

# Notify Mask
SERVICE_NOTIFY_CREATED          = 0x00000080
SERVICE_NOTIFY_CONTINUE_PENDING = 0x00000010
SERVICE_NOTIFY_DELETE_PENDING   = 0x00000200
SERVICE_NOTIFY_DELETED          = 0x00000100
SERVICE_NOTIFY_PAUSE_PENDING    = 0x00000020
SERVICE_NOTIFY_PAUSED           = 0x00000040
SERVICE_NOTIFY_RUNNING          = 0x00000008
SERVICE_NOTIFY_START_PENDING    = 0x00000002
SERVICE_NOTIFY_STOP_PENDING     = 0x00000004
SERVICE_NOTIFY_STOPPED          = 0x00000001

# SERVICE_CONTROL_STATUS_REASON_IN_PARAMSW Reasons
SERVICE_STOP_CUSTOM    =  0x20000000
SERVICE_STOP_PLANNED   =  0x40000000
SERVICE_STOP_UNPLANNED =  0x10000000

# SERVICE_TRIGGER triggers
SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL  = 0x00000001
SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY   = 0x00000002
SERVICE_TRIGGER_TYPE_DOMAIN_JOIN               = 0x00000003
SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT       = 0x00000004
SERVICE_TRIGGER_TYPE_GROUP_POLICY              = 0x00000005
SERVICE_TRIGGER_TYPE_CUSTOM                    = 0x00000020

# SERVICE_TRIGGER actions
SERVICE_TRIGGER_ACTION_SERVICE_START = 0x00000001
SERVICE_TRIGGER_ACTION_SERVICE_STOP  = 0x00000002

# SERVICE_TRIGGER subTypes
DOMAIN_JOIN_GUID                                = '1ce20aba-9851-4421-9430-1ddeb766e809' 
DOMAIN_LEAVE_GUID                               = 'ddaf516e-58c2-4866-9574-c3b615d42ea1'
FIREWALL_PORT_OPEN_GUID                         = 'b7569e07-8421-4ee0-ad10-86915afdad09'
FIREWALL_PORT_CLOSE_GUID                        = 'a144ed38-8e12-4de4-9d96-e64740b1a524'
MACHINE_POLICY_PRESENT_GUID                     = '659FCAE6-5BDB-4DA9-B1FF-CA2A178D46E0'
NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID   = '4f27f2de-14e2-430b-a549-7cd48cbc8245'
NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID    = 'cc4ba62a-162e-4648-847a-b6bdf993e335'
USER_POLICY_PRESENT_GUID                        = '54FB46C8-F089-464C-B1FD-59D1B62C3B50'

# SERVICE_TRIGGER_SPECIFIC_DATA_ITEM dataTypes
SERVICE_TRIGGER_DATA_TYPE_BINARY = 0x00000001
SERVICE_TRIGGER_DATA_TYPE_STRING = 0x00000002

################################################################################
# STRUCTURES
################################################################################

class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class SC_RPC_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        return 1

SC_NOTIFY_RPC_HANDLE = SC_RPC_HANDLE

class SERVICE_STATUS(NDRSTRUCT):
    structure =  (
        ('dwServiceType',DWORD),
        ('dwCurrentState',DWORD),
        ('dwControlsAccepted',DWORD),
        ('dwWin32ExitCode',DWORD),
        ('dwServiceSpecificExitCode',DWORD),
        ('dwCheckPoint',DWORD),
        ('dwWaitHint',DWORD),
    )

class QUERY_SERVICE_CONFIGW(NDRSTRUCT):
    structure = (
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName', LPWSTR),
        ('lpLoadOrderGroup',LPWSTR),
        ('dwTagId',DWORD),
        ('lpDependencies',LPWSTR),
        ('lpServiceStartName',LPWSTR),
        ('lpDisplayName',LPWSTR),
    )

class SC_RPC_LOCK(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        return 1

class LPSERVICE_STATUS(NDRPOINTER):
    referent = (
        ('Data',SERVICE_STATUS),
    )

SECURITY_INFORMATION = ULONG

BOUNDED_DWORD_256K = DWORD

class LPBOUNDED_DWORD_256K(NDRPOINTER):
    referent = (
        ('Data', BOUNDED_DWORD_256K),
    )

SVCCTL_HANDLEW = LPWSTR

class ENUM_SERVICE_STATUSW(NDRSTRUCT):
    structure = (
        ('lpServiceName',LPWSTR),
        ('lpDisplayName',LPWSTR),
        ('ServiceStatus',SERVICE_STATUS),
    )

class LPQUERY_SERVICE_CONFIGW(NDRPOINTER):
    referent = (
        ('Data', QUERY_SERVICE_CONFIGW),
    )

BOUNDED_DWORD_8K = DWORD
BOUNDED_DWORD_4K = DWORD

class STRING_PTRSW(NDRSTRUCT):
    structure = (
        ('Data',NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = LPWSTR
        if data is not None:
            self.fromString(data)

class UNIQUE_STRING_PTRSW(NDRPOINTER):
    referent = (
        ('Data', STRING_PTRSW),
    )

class QUERY_SERVICE_LOCK_STATUSW(NDRSTRUCT):
    structure = (
        ('fIsLocked',DWORD),
        ('lpLockOwner',LPWSTR),
        ('dwLockDuration',DWORD),
    )

class SERVICE_DESCRIPTION_WOW64(NDRSTRUCT):
    structure = (
        ('dwDescriptionOffset', DWORD),
    )

class SERVICE_DESCRIPTIONW(NDRSTRUCT):
    structure = (
        ('lpDescription', LPWSTR),
    )

class LPSERVICE_DESCRIPTIONW(NDRPOINTER):
    referent = (
        ('Data', SERVICE_DESCRIPTIONW),
    )

class SERVICE_FAILURE_ACTIONS_WOW64(NDRSTRUCT):
    structure = (
        ('dwResetPeriod', DWORD),
        ('dwRebootMsgOffset', DWORD),
        ('dwCommandOffset', DWORD),
        ('cActions', DWORD),
        ('dwsaActionsOffset', DWORD),
    )

class SC_ACTION(NDRSTRUCT):
    structure = (
        ('Type', DWORD), 
        ('Delay', DWORD) , 
    )

class SC_ACTIONS(NDRSTRUCT):
    structure = (
       ('Data', NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = SC_ACTION
        if data is not None:
            self.fromString(data)

class SERVICE_FAILURE_ACTIONSW(NDRSTRUCT):
    structure = (
        ('dwResetPeriod', DWORD), 
        ('lpRebootMsg', LPWSTR) , 
        ('lpCommand', LPWSTR) , 
        ('cActions', DWORD) , 
        ('lpsaActions', SC_ACTIONS) , 
    )

class LPSERVICE_FAILURE_ACTIONSW(NDRPOINTER):
    referent = (
        ('Data', SERVICE_FAILURE_ACTIONSW),
    )

class SERVICE_FAILURE_ACTIONS_FLAG(NDRSTRUCT):
    structure = (
        ('fFailureActionsOnNonCrashFailures', BOOL),
    )

class LPSERVICE_FAILURE_ACTIONS_FLAG(NDRPOINTER):
    referent = (
        ('Data', SERVICE_FAILURE_ACTIONS_FLAG),
    )

class SERVICE_DELAYED_AUTO_START_INFO(NDRSTRUCT):
    structure = (
        ('fDelayedAutostart', BOOL),
    )

class LPSERVICE_DELAYED_AUTO_START_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_DELAYED_AUTO_START_INFO),
    )

class SERVICE_SID_INFO(NDRSTRUCT):
    structure = (
        ('dwServiceSidType', DWORD),
    )

class LPSERVICE_SID_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_SID_INFO),
    )


class SERVICE_RPC_REQUIRED_PRIVILEGES_INFO(NDRSTRUCT):
    structure = (
        ('cbRequiredPrivileges',DWORD),
        ('pRequiredPrivileges',LPBYTE),
    )
    def getData(self, soFar = 0):
        self['cbRequiredPrivileges'] = len(self['pRequiredPrivileges'])
        return NDR.getData(self, soFar = 0)


class LPSERVICE_RPC_REQUIRED_PRIVILEGES_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_RPC_REQUIRED_PRIVILEGES_INFO),
    )

class SERVICE_REQUIRED_PRIVILEGES_INFO_WOW64(NDRSTRUCT):
    structure = (
        ('dwRequiredPrivilegesOffset', DWORD),
    )

class SERVICE_PRESHUTDOWN_INFO(NDRSTRUCT):
    structure = (
        ('dwPreshutdownTimeout', DWORD),
    )

class LPSERVICE_PRESHUTDOWN_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_PRESHUTDOWN_INFO),
    )

class SERVICE_STATUS_PROCESS(NDRSTRUCT):
    structure = (
        ('dwServiceType', DWORD),
        ('dwCurrentState', DWORD),
        ('dwControlsAccepted', DWORD),
        ('dwWin32ExitCode', DWORD),
        ('dwServiceSpecificExitCode', DWORD),
        ('dwCheckPoint', DWORD),
        ('dwWaitHint', DWORD),
        ('dwProcessId', DWORD),
        ('dwServiceFlags', DWORD),
    )

class UCHAR_16(NDRSTRUCT):
    structure = (
        ('Data', '16s=""'),
    )
    def getAlignment(self):
        return 1

class SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1(NDRSTRUCT):
    structure = (
        ('ullThreadId',ULONGLONG),
        ('dwNotifyMask',DWORD),
        ('CallbackAddressArray',UCHAR_16),
        ('CallbackParamAddressArray',UCHAR_16),
        ('ServiceStatus', SERVICE_STATUS_PROCESS),
        ('dwNotificationStatus',DWORD),
        ('dwSequence',DWORD),
    )

class SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2(NDRSTRUCT):
    structure = (
        ('ullThreadId',ULONGLONG),
        ('dwNotifyMask',DWORD),
        ('CallbackAddressArray',UCHAR_16),
        ('CallbackParamAddressArray',UCHAR_16),
        ('ServiceStatus',SERVICE_STATUS_PROCESS),
        ('dwNotificationStatus',DWORD),
        ('dwSequence',DWORD),
        ('dwNotificationTriggered',DWORD),
        ('pszServiceNames',LPWSTR),
    )

class PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1(NDRPOINTER):
    referent = (
        ('Data', SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1),
    )

class PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2(NDRPOINTER):
    referent = (
        ('Data', SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2),
    )

class SC_RPC_NOTIFY_PARAMS(NDRUNION):
    union = {
        1: ('pStatusChangeParam1', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1),
        2: ('pStatusChangeParams', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2),
    }

class SC_RPC_NOTIFY_PARAMS_ARRAY(NDRUniConformantArray):
     item = SC_RPC_NOTIFY_PARAMS

class PSC_RPC_NOTIFY_PARAMS_LIST(NDRSTRUCT):
    structure = (
        ('cElements',BOUNDED_DWORD_4K),
        ('NotifyParamsArray', SC_RPC_NOTIFY_PARAMS_ARRAY),
    )

class SERVICE_CONTROL_STATUS_REASON_IN_PARAMSW(NDRSTRUCT):
    structure = (
        ('dwReason', DWORD),
        ('pszComment', LPWSTR),
    )

class SERVICE_TRIGGER_SPECIFIC_DATA_ITEM(NDRSTRUCT):
    structure = (
        ('dwDataType',DWORD ),
        ('cbData',DWORD),
        ('pData', LPBYTE),
    )
    def getData(self, soFar = 0):
        if self['pData'] != 0:
            self['cbData'] = len(self['pData'])
        return NDR.getData(self, soFar)

class SERVICE_TRIGGER_SPECIFIC_DATA_ITEM_ARRAY(NDRUniConformantArray):
    item = SERVICE_TRIGGER_SPECIFIC_DATA_ITEM

class PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM(NDRPOINTER):
    referent = (
        ('Data', SERVICE_TRIGGER_SPECIFIC_DATA_ITEM_ARRAY),
    )

class SERVICE_TRIGGER(NDRSTRUCT):
    structure = (
        ('dwTriggerType', DWORD),
        ('dwAction', DWORD),
        ('pTriggerSubtype', PGUID),
        ('cDataItems', DWORD),
        ('pDataItems', PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM),
    )
    def getData(self, soFar = 0):
        if self['pDataItems'] != 0:
            self['cDataItems'] = len(self['pDataItems'])
        return NDR.getData(self, soFar)

class SERVICE_TRIGGER_ARRAY(NDRUniConformantArray):
    item = SERVICE_TRIGGER

class PSERVICE_TRIGGER(NDRPOINTER):
    referent = (
        ('Data', SERVICE_TRIGGER_ARRAY),
    )

class SERVICE_CONTROL_STATUS_REASON_OUT_PARAMS(NDRSTRUCT):
    structure = (
       ('ServiceStatus', SERVICE_STATUS_PROCESS),
    )

class SERVICE_TRIGGER_INFO(NDRSTRUCT):
    structure = (
        ('cTriggers', DWORD),
        ('pTriggers', PSERVICE_TRIGGER),
        ('pReserved', NDRPOINTERNULL ),
    )
    def getData(self, soFar = 0):
        if self['pTriggers'] != 0:
            self['cTriggers'] = len(self['pTriggers'])
        return NDR.getData(self, soFar)
    
class PSERVICE_TRIGGER_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_TRIGGER_INFO),
    )

class SERVICE_PREFERRED_NODE_INFO(NDRSTRUCT):
    structure = (
        ('usPreferredNode', USHORT),
        ('fDelete', BOOL),
    )

class LPSERVICE_PREFERRED_NODE_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_PREFERRED_NODE_INFO),
    )

class SERVICE_RUNLEVEL_INFO(NDRSTRUCT):
    structure = (
        ('eLowestRunLevel', DWORD),
    )

class PSERVICE_RUNLEVEL_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_RUNLEVEL_INFO),
    )

class SERVICE_MANAGEDACCOUNT_INFO(NDRSTRUCT):
    structure = (
        ('fIsManagedAccount', DWORD),
    )

class PSERVICE_MANAGEDACCOUNT_INFO(NDRPOINTER):
    referent = (
        ('Data', SERVICE_MANAGEDACCOUNT_INFO),
    )

class SC_RPC_CONFIG_INFOW_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        1: ('psd', LPSERVICE_DESCRIPTIONW),
        2: ('psfa',LPSERVICE_FAILURE_ACTIONSW ),
        3: ('psda',LPSERVICE_DELAYED_AUTO_START_INFO),
        4: ('psfaf',LPSERVICE_FAILURE_ACTIONS_FLAG),
        5: ('pssid',LPSERVICE_SID_INFO),
        6: ('psrp',LPSERVICE_RPC_REQUIRED_PRIVILEGES_INFO),
        7: ('psps',LPSERVICE_PRESHUTDOWN_INFO),
        8: ('psti',PSERVICE_TRIGGER_INFO),
        9: ('pspn',LPSERVICE_PREFERRED_NODE_INFO),
        10: ('psri',PSERVICE_RUNLEVEL_INFO),
        11: ('psma',PSERVICE_MANAGEDACCOUNT_INFO),
    }

class SC_RPC_CONFIG_INFOW(NDRSTRUCT):
    structure = (
        ('dwInfoLevel', DWORD),
        ('Union', SC_RPC_CONFIG_INFOW_UNION),
    )

################################################################################
# RPC CALLS
################################################################################

class RCloseServiceHandle(NDRCALL):
    opnum = 0
    structure = (
        ('hSCObject',SC_RPC_HANDLE),
    )

class RCloseServiceHandleResponse(NDRCALL):
    structure = (
        ('hSCObject',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

class RControlService(NDRCALL):
    opnum = 1
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwControl',DWORD),
    )

class RControlServiceResponse(NDRCALL):
    structure = (
        ('lpServiceStatus',SERVICE_STATUS),
        ('ErrorCode', DWORD),
    )

class RDeleteService(NDRCALL):
    opnum = 2
    structure = (
        ('hService',SC_RPC_HANDLE),
    )

class RDeleteServiceResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

class RLockServiceDatabase(NDRCALL):
    opnum = 3
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
    )

class RLockServiceDatabaseResponse(NDRCALL):
    structure = (
        ('lpLock',SC_RPC_LOCK),
        ('ErrorCode', DWORD),
    )

class RQueryServiceObjectSecurity(NDRCALL):
    opnum = 4
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwSecurityInformation',SECURITY_INFORMATION),
        ('cbBufSize',DWORD),
    )

class RQueryServiceObjectSecurityResponse(NDRCALL):
    structure = (
        ('lpSecurityDescriptor', BYTE_ARRAY),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class RSetServiceObjectSecurity(NDRCALL):
    opnum = 5
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwSecurityInformation',SECURITY_INFORMATION),
        ('lpSecurityDescriptor',LPBYTE),
        ('cbBufSize',DWORD),
    )

class RSetServiceObjectSecurityResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

class RQueryServiceStatus(NDRCALL):
    opnum = 6
    structure = (
        ('hService',SC_RPC_HANDLE),
    )

class RQueryServiceStatusResponse(NDRCALL):
    structure = (
        ('lpServiceStatus',SERVICE_STATUS),
        ('ErrorCode', DWORD),
    )

class RSetServiceStatus(NDRCALL):
    opnum = 7
    structure = (
        ('hServiceStatus',SC_RPC_HANDLE),
        ('lpServiceStatus',SERVICE_STATUS),
    )

class RSetServiceStatusResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

class RUnlockServiceDatabase(NDRCALL):
    opnum = 8
    structure = (
        ('Lock',SC_RPC_LOCK),
    )

class RUnlockServiceDatabaseResponse(NDRCALL):
    structure = (
        ('Lock',SC_RPC_LOCK),
        ('ErrorCode', DWORD),
    )

class RNotifyBootConfigStatus(NDRCALL):
    opnum = 9
    structure = (
        ('lpMachineName',SVCCTL_HANDLEW),
        ('BootAcceptable',DWORD),
    )

class RNotifyBootConfigStatusResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

class RChangeServiceConfigW(NDRCALL):
    opnum = 11
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName',LPWSTR),
        ('lpLoadOrderGroup',LPWSTR),
        ('lpdwTagId',LPDWORD),
        ('lpDependencies',LPBYTE),
        ('dwDependSize',DWORD),
        ('lpServiceStartName',LPWSTR),
        ('lpPassword',LPBYTE),
        ('dwPwSize',DWORD),
        ('lpDisplayName',LPWSTR),
    )

class RChangeServiceConfigWResponse(NDRCALL):
    structure = (
        ('lpdwTagId',LPDWORD),
        ('ErrorCode', DWORD),
    )

class RCreateServiceW(NDRCALL):
    opnum = 12
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',WSTR),
        ('lpDisplayName',LPWSTR),
        ('dwDesiredAccess',DWORD),
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName',WSTR),
        ('lpLoadOrderGroup',LPWSTR),
        ('lpdwTagId',LPDWORD),
        ('lpDependencies',LPBYTE),
        ('dwDependSize',DWORD),
        ('lpServiceStartName',LPWSTR),
        ('lpPassword',LPBYTE),
        ('dwPwSize',DWORD),
    )

class RCreateServiceWResponse(NDRCALL):
    structure = (
        ('lpdwTagId',LPWSTR),
        ('lpServiceHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

class REnumDependentServicesW(NDRCALL):
    opnum = 13
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
    )

class REnumDependentServicesWResponse(NDRCALL):
    structure = (
        ('lpServices',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class REnumServicesStatusW(NDRCALL):
    opnum = 14
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('dwServiceType',DWORD),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
        ('lpResumeIndex',LPBOUNDED_DWORD_256K),
    )

class REnumServicesStatusWResponse(NDRCALL):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
        ('lpResumeIndex',LPBOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class ROpenSCManagerW(NDRCALL):
    opnum = 15
    structure = (
        ('lpMachineName',SVCCTL_HANDLEW),
        ('lpDatabaseName',LPWSTR),
        ('dwDesiredAccess',DWORD),
    )

class ROpenSCManagerWResponse(NDRCALL):
    structure = (
        ('lpScHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

class ROpenServiceW(NDRCALL):
    opnum = 16
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',WSTR),
        ('dwDesiredAccess',DWORD),
    )

class ROpenServiceWResponse(NDRCALL):
    structure = (
        ('lpServiceHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

class RQueryServiceConfigW(NDRCALL):
    opnum = 17
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('cbBufSize',DWORD),
    )

class RQueryServiceConfigWResponse(NDRCALL):
    structure = (
        ('lpServiceConfig',QUERY_SERVICE_CONFIGW),
        ('pcbBytesNeeded',BOUNDED_DWORD_8K),
        ('ErrorCode', DWORD),
    )

class RQueryServiceLockStatusW(NDRCALL):
    opnum = 18
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('cbBufSize',DWORD),
    )

class RQueryServiceLockStatusWResponse(NDRCALL):
    structure = (
        ('lpLockStatus',QUERY_SERVICE_LOCK_STATUSW),
        ('pcbBytesNeeded',BOUNDED_DWORD_4K),
        ('ErrorCode', DWORD),
    )

class RStartServiceW(NDRCALL):
    opnum = 19
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('argc',DWORD),
        ('argv',UNIQUE_STRING_PTRSW),
    )

class RStartServiceWResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

class RGetServiceDisplayNameW(NDRCALL):
    opnum = 20
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',WSTR),
        ('lpcchBuffer',DWORD),
    )

class RGetServiceDisplayNameWResponse(NDRCALL):
    structure = (
        ('lpDisplayName',WSTR),
        ('lpcchBuffer',DWORD),
        ('ErrorCode', DWORD),
    )

class RGetServiceKeyNameW(NDRCALL):
    opnum = 21
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpDisplayName',WSTR),
        ('lpcchBuffer',DWORD),
    )

class RGetServiceKeyNameWResponse(NDRCALL):
    structure = (
        ('lpDisplayName',WSTR),
        ('lpcchBuffer',DWORD),
        ('ErrorCode', DWORD),
    )

class REnumServiceGroupW(NDRCALL):
    opnum = 35
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('dwServiceType',DWORD),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
        ('lpResumeIndex',LPBOUNDED_DWORD_256K),
        ('pszGroupName',LPWSTR),
    )

class REnumServiceGroupWResponse(NDRCALL):
    structure = (
        ('lpBuffer',LPBYTE),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
        ('lpResumeIndex',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class RChangeServiceConfig2W(NDRCALL):
    opnum = 37
    structure = (
       ('hService',SC_RPC_HANDLE),
       ('Info',SC_RPC_CONFIG_INFOW),
    )

class RChangeServiceConfig2WResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

class RQueryServiceConfig2W(NDRCALL):
    opnum = 39
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwInfoLevel',DWORD),
        ('cbBufSize',DWORD),
    )

class RQueryServiceConfig2WResponse(NDRCALL):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_8K),
        ('ErrorCode', DWORD),
    )

class RQueryServiceStatusEx(NDRCALL):
    opnum = 40
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('InfoLevel',DWORD),
        ('cbBufSize',DWORD),
    )

class RQueryServiceStatusExResponse(NDRCALL):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_8K),
        ('ErrorCode', DWORD),
    )

class REnumServicesStatusExW(NDRCALL):
    opnum = 42
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('InfoLevel',DWORD),
        ('dwServiceType',DWORD),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
        ('lpResumeIndex',LPBOUNDED_DWORD_256K),
        ('pszGroupName',LPWSTR),
    )

class REnumServicesStatusExWResponse(NDRCALL):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
        ('lpResumeIndex',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class RCreateServiceWOW64W(NDRCALL):
    opnum = 45
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',WSTR),
        ('lpDisplayName',LPWSTR),
        ('dwDesiredAccess',DWORD),
        ('dwServiceType',DWORD),
        ('dwStartType',DWORD),
        ('dwErrorControl',DWORD),
        ('lpBinaryPathName',WSTR),
        ('lpLoadOrderGroup',LPWSTR),
        ('lpdwTagId',LPDWORD),
        ('lpDependencies',LPBYTE),
        ('dwDependSize',DWORD),
        ('lpServiceStartName',LPWSTR),
        ('lpPassword',LPBYTE),
        ('dwPwSize',DWORD),
    )

class RCreateServiceWOW64WResponse(NDRCALL):
    structure = (
        ('lpdwTagId',LPWSTR),
        ('lpServiceHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

# Still not working, for some reason something changes in the way the pointer inside SC_RPC_NOTIFY_PARAMS is marshalled here
class RNotifyServiceStatusChange(NDRCALL):
    opnum = 47
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('NotifyParams',SC_RPC_NOTIFY_PARAMS),
        ('pClientProcessGuid',GUID),
    )

class RNotifyServiceStatusChangeResponse(NDRCALL):
    structure = (
        ('pSCMProcessGuid',GUID),
        ('pfCreateRemoteQueue',PBOOL),
        ('phNotify',SC_NOTIFY_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

# Not working, until I don't fix the previous one
class RGetNotifyResults(NDRCALL):
    opnum = 48
    structure = (
        ('hNotify',SC_NOTIFY_RPC_HANDLE),
    )

class RGetNotifyResultsResponse(NDRCALL):
    structure = (
        ('ppNotifyParams',PSC_RPC_NOTIFY_PARAMS_LIST),
        ('ErrorCode', DWORD),
    )

# Not working, until I don't fix the previous ones
class RCloseNotifyHandle(NDRCALL):
    opnum = 49
    structure = (
        ('phNotify',SC_NOTIFY_RPC_HANDLE),
    )

class RCloseNotifyHandleResponse(NDRCALL):
    structure = (
        ('phNotify',SC_NOTIFY_RPC_HANDLE),
        ('pfApcFired',PBOOL),
        ('ErrorCode', DWORD),
    )

# Not working, returning bad_stub_data
class RControlServiceExW(NDRCALL):
    opnum = 51
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwControl',DWORD),
        ('dwInfoLevel',DWORD),
        ('pControlInParams',SERVICE_CONTROL_STATUS_REASON_IN_PARAMSW),
    )

class RControlServiceExWResponse(NDRCALL):
    structure = (
        ('pControlOutParams',SERVICE_CONTROL_STATUS_REASON_OUT_PARAMS),
        ('ErrorCode', DWORD),
    )

class RQueryServiceConfigEx(NDRCALL):
    opnum = 56
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwInfoLevel',DWORD),
    )

class RQueryServiceConfigExResponse(NDRCALL):
    structure = (
        ('pInfo',SC_RPC_CONFIG_INFOW),
        ('ErrorCode', DWORD),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (RCloseServiceHandle, RCloseServiceHandleResponse),
 1 : (RControlService, RControlServiceResponse),
 2 : (RDeleteService, RDeleteServiceResponse),
 3 : (RLockServiceDatabase, RLockServiceDatabaseResponse),
 4 : (RQueryServiceObjectSecurity, RQueryServiceObjectSecurityResponse),
 5 : (RSetServiceObjectSecurity, RSetServiceObjectSecurityResponse),
 6 : (RQueryServiceStatus, RQueryServiceStatusResponse),
 7 : (RSetServiceStatus, RSetServiceStatusResponse),
 8 : (RUnlockServiceDatabase, RUnlockServiceDatabaseResponse),
 9 : (RNotifyBootConfigStatus, RNotifyBootConfigStatusResponse),
11 : (RChangeServiceConfigW, RChangeServiceConfigWResponse),
12 : (RCreateServiceW, RCreateServiceWResponse),
13 : (REnumDependentServicesW, REnumDependentServicesWResponse),
14 : (REnumServicesStatusW, REnumServicesStatusWResponse),
15 : (ROpenSCManagerW, ROpenSCManagerWResponse),
16 : (ROpenServiceW, ROpenServiceWResponse),
17 : (RQueryServiceConfigW, RQueryServiceConfigWResponse),
18 : (RQueryServiceLockStatusW, RQueryServiceLockStatusWResponse),
19 : (RStartServiceW, RStartServiceWResponse),
20 : (RGetServiceDisplayNameW, RGetServiceDisplayNameWResponse),
21 : (RGetServiceKeyNameW, RGetServiceKeyNameWResponse),
35 : (REnumServiceGroupW, REnumServiceGroupWResponse),
37 : (RChangeServiceConfig2W, RChangeServiceConfig2WResponse),
39 : (RQueryServiceConfig2W, RQueryServiceConfig2WResponse),
40 : (RQueryServiceStatusEx, RQueryServiceStatusExResponse),
42 : (REnumServicesStatusExW, REnumServicesStatusExWResponse),
45 : (RCreateServiceWOW64W, RCreateServiceWOW64WResponse),
47 : (RNotifyServiceStatusChange, RNotifyServiceStatusChangeResponse),
48 : (RGetNotifyResults, RGetNotifyResultsResponse),
49 : (RCloseNotifyHandle, RCloseNotifyHandleResponse),
51 : (RControlServiceExW, RControlServiceExWResponse),
56 : (RQueryServiceConfigEx, RQueryServiceConfigExResponse),
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

def hRCloseServiceHandle(dce, hSCObject):
    request = RCloseServiceHandle()
    request['hSCObject'] = hSCObject
    return dce.request(request)

def hRControlService(dce, hService, dwControl):
    request = RControlService()
    request['hService'] = hService
    request['dwControl'] = dwControl
    return dce.request(request)

def hRDeleteService(dce, hService):
    request = RDeleteService()
    request ['hService'] = hService
    return dce.request(request)

def hRLockServiceDatabase(dce, hSCManager):
    request = RLockServiceDatabase()
    request['hSCManager'] = hSCManager
    return dce.request(request)


def hRQueryServiceObjectSecurity(dce, hService, dwSecurityInformation, cbBufSize=0):
    request = RQueryServiceObjectSecurity()
    request['hService'] = hService
    request['dwSecurityInformation'] = dwSecurityInformation
    request['cbBufSize'] = cbBufSize
    try:
        resp = dce.request(request)
    except DCERPCSessionError as e:
        if e.get_error_code() == system_errors.ERROR_INSUFFICIENT_BUFFER:
            resp = e.get_packet()
            request['cbBufSize'] = resp['pcbBytesNeeded']
            resp = dce.request(request)
        else:
            raise
    return resp

def hRSetServiceObjectSecurity(dce, hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize ):
    request = RSetServiceObjectSecurity()
    request['hService'] = hService
    request['dwSecurityInformation'] = dwSecurityInformation
    request['cbBufSize'] = cbBufSize
    return dce.request(request)

def hRQueryServiceStatus(dce, hService ):
    request = RQueryServiceStatus()
    request['hService'] = hService
    return dce.request(request)

def hRSetServiceStatus(dce, hServiceStatus, lpServiceStatus ):
    request = RSetServiceStatus()
    request['hServiceStatus'] = hServiceStatus
    request['lpServiceStatus'] = lpServiceStatus
    return dce.request(request)

def hRUnlockServiceDatabase(dce, Lock ):
    request = RUnlockServiceDatabase()
    request['Lock'] = Lock
    return dce.request(request)

def hRNotifyBootConfigStatus(dce, lpMachineName, BootAcceptable ):
    request = RNotifyBootConfigStatus()
    request['lpMachineName'] = lpMachineName
    request['BootAcceptable'] = BootAcceptable
    return dce.request(request)

def hRChangeServiceConfigW(dce, hService, dwServiceType=SERVICE_NO_CHANGE, dwStartType=SERVICE_NO_CHANGE, dwErrorControl=SERVICE_NO_CHANGE, lpBinaryPathName=NULL, lpLoadOrderGroup=NULL, lpdwTagId=NULL, lpDependencies=NULL, dwDependSize=0, lpServiceStartName=NULL, lpPassword=NULL, dwPwSize=0, lpDisplayName=NULL):
    changeServiceConfig = RChangeServiceConfigW()
    changeServiceConfig['hService'] = hService
    changeServiceConfig['dwServiceType'] = dwServiceType
    changeServiceConfig['dwStartType'] = dwStartType
    changeServiceConfig['dwErrorControl'] = dwErrorControl
    changeServiceConfig['lpBinaryPathName'] = checkNullString(lpBinaryPathName)
    changeServiceConfig['lpLoadOrderGroup'] = checkNullString(lpLoadOrderGroup)
    changeServiceConfig['lpdwTagId'] = lpdwTagId
    changeServiceConfig['lpDependencies'] = lpDependencies
    # Strings MUST be NULL terminated for lpDependencies
    changeServiceConfig['dwDependSize'] = dwDependSize
    changeServiceConfig['lpServiceStartName'] = checkNullString(lpServiceStartName)
    changeServiceConfig['lpPassword'] = lpPassword
    changeServiceConfig['dwPwSize'] = dwPwSize
    changeServiceConfig['lpDisplayName'] = checkNullString(lpDisplayName)
    return dce.request(changeServiceConfig)

def hRCreateServiceW(dce, hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess=SERVICE_ALL_ACCESS, dwServiceType=SERVICE_WIN32_OWN_PROCESS, dwStartType=SERVICE_AUTO_START, dwErrorControl=SERVICE_ERROR_IGNORE, lpBinaryPathName=NULL, lpLoadOrderGroup=NULL, lpdwTagId=NULL, lpDependencies=NULL, dwDependSize=0, lpServiceStartName=NULL, lpPassword=NULL, dwPwSize=0):
    createService = RCreateServiceW()
    createService['hSCManager'] = hSCManager
    createService['lpServiceName'] = checkNullString(lpServiceName)
    createService['lpDisplayName'] = checkNullString(lpDisplayName)
    createService['dwDesiredAccess'] = dwDesiredAccess
    createService['dwServiceType'] = dwServiceType
    createService['dwStartType'] = dwStartType
    createService['dwErrorControl'] = dwErrorControl
    createService['lpBinaryPathName'] = checkNullString(lpBinaryPathName)
    createService['lpLoadOrderGroup'] = checkNullString(lpLoadOrderGroup)
    createService['lpdwTagId'] = lpdwTagId
    # Strings MUST be NULL terminated for lpDependencies
    createService['lpDependencies'] = lpDependencies
    createService['dwDependSize'] = dwDependSize
    createService['lpServiceStartName'] = checkNullString(lpServiceStartName)
    createService['lpPassword'] = lpPassword
    createService['dwPwSize'] = dwPwSize
    return dce.request(createService)

def hREnumDependentServicesW(dce, hService, dwServiceState, cbBufSize ):
    enumDependentServices = REnumDependentServicesW()
    enumDependentServices['hService'] = hService
    enumDependentServices['dwServiceState'] = dwServiceState
    enumDependentServices['cbBufSize'] = cbBufSize
    return dce.request(enumDependentServices)

def hREnumServicesStatusW(dce, hSCManager, dwServiceType=SERVICE_WIN32_OWN_PROCESS|SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER|SERVICE_WIN32_SHARE_PROCESS|SERVICE_INTERACTIVE_PROCESS, dwServiceState=SERVICE_STATE_ALL):
    class ENUM_SERVICE_STATUSW2(NDRSTRUCT):
        # This is a little trick, since the original structure is slightly different
        # but instead of parsing the LPBYTE buffer at hand, we just do it with the aid
        # of the NDR library, although the pointers are swapped from the original specification.
        # Why is this? Well.. since we're getting an LPBYTE back, it's just a copy of the remote's memory
        # where the pointers are actually POINTING to the data.
        # Sadly, the pointers are not aligned based on the services records, so we gotta do this
        # It should be easier in C of course.
        class STR(NDRPOINTER):
            referent = (
                ('Data', WIDESTR),
            )
        structure = (
            ('lpServiceName',STR),
            ('lpDisplayName',STR),
            ('ServiceStatus',SERVICE_STATUS),
        )

    enumServicesStatus = REnumServicesStatusW()
    enumServicesStatus['hSCManager'] = hSCManager
    enumServicesStatus['dwServiceType'] = dwServiceType
    enumServicesStatus['dwServiceState'] = dwServiceState
    enumServicesStatus['cbBufSize'] = 0
    enumServicesStatus['lpResumeIndex'] = NULL

    try:
        resp = dce.request(enumServicesStatus)
    except DCERPCSessionError as e:
        if e.get_error_code() == system_errors.ERROR_MORE_DATA:
            resp = e.get_packet()
            enumServicesStatus['cbBufSize'] = resp['pcbBytesNeeded']
            resp = dce.request(enumServicesStatus)
        else:
            raise
    
    # Now we're supposed to have all services returned. Now we gotta parse them

    enumArray = NDRUniConformantArray()
    enumArray.item = ENUM_SERVICE_STATUSW2

    enumArray.setArraySize(resp['lpServicesReturned'])

    data = b''.join(resp['lpBuffer'])
    enumArray.fromString(data)
    data = data[4:]
    # Since the pointers here are pointing to the actual data, we have to reparse
    # the referents
    for record in enumArray['Data']:
        offset =  record.fields['lpDisplayName'].fields['ReferentID']-4
        name = WIDESTR(data[offset:])
        record['lpDisplayName'] = name['Data']
        offset =  record.fields['lpServiceName'].fields['ReferentID']-4
        name = WIDESTR(data[offset:])
        record['lpServiceName'] = name['Data']

    return enumArray['Data']

def hROpenSCManagerW(dce, lpMachineName='DUMMY\x00', lpDatabaseName='ServicesActive\x00', dwDesiredAccess=SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SC_MANAGER_ENUMERATE_SERVICE):
    openSCManager = ROpenSCManagerW()
    openSCManager['lpMachineName'] = checkNullString(lpMachineName)
    openSCManager['lpDatabaseName'] = checkNullString(lpDatabaseName)
    openSCManager['dwDesiredAccess'] = dwDesiredAccess
    return dce.request(openSCManager)

def hROpenServiceW(dce, hSCManager, lpServiceName, dwDesiredAccess= SERVICE_ALL_ACCESS):
    openService = ROpenServiceW()
    openService['hSCManager'] = hSCManager
    openService['lpServiceName'] = checkNullString(lpServiceName)
    openService['dwDesiredAccess'] = dwDesiredAccess
    return dce.request(openService)

def hRQueryServiceConfigW(dce, hService):
    queryService = RQueryServiceConfigW()
    queryService['hService'] = hService
    queryService['cbBufSize'] = 0
    try:
        resp = dce.request(queryService)
    except DCERPCSessionError as e:
        if e.get_error_code() == system_errors.ERROR_INSUFFICIENT_BUFFER:
            resp = e.get_packet()
            queryService['cbBufSize'] = resp['pcbBytesNeeded']
            resp = dce.request(queryService)
        else:
            raise

    return resp

def hRQueryServiceLockStatusW(dce, hSCManager, cbBufSize ):
    queryServiceLock = RQueryServiceLockStatusW()
    queryServiceLock['hSCManager'] = hSCManager
    queryServiceLock['cbBufSize'] = cbBufSize
    return dce.request(queryServiceLock)

def hRStartServiceW(dce, hService, argc=0, argv=NULL ):
    startService = RStartServiceW()
    startService['hService'] = hService
    startService['argc'] = argc
    if argc == 0:
        startService['argv'] = NULL
    else:
        for item in argv:
            itemn = LPWSTR()
            itemn['Data'] = checkNullString(item)
            startService['argv'].append(itemn)
    return dce.request(startService)

def hRGetServiceDisplayNameW(dce, hSCManager, lpServiceName, lpcchBuffer ):
    getServiceDisplay = RGetServiceDisplayNameW()
    getServiceDisplay['hSCManager'] = hSCManager
    getServiceDisplay['lpServiceName'] = checkNullString(lpServiceName)
    getServiceDisplay['lpcchBuffer'] = lpcchBuffer
    return dce.request(getServiceDisplay)

def hRGetServiceKeyNameW(dce, hSCManager, lpDisplayName, lpcchBuffer ):
    getServiceKeyName = RGetServiceKeyNameW()
    getServiceKeyName['hSCManager'] = hSCManager
    getServiceKeyName['lpDisplayName'] = checkNullString(lpDisplayName)
    getServiceKeyName['lpcchBuffer'] = lpcchBuffer
    return dce.request(getServiceKeyName)

def hREnumServiceGroupW(dce, hSCManager, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex = NULL, pszGroupName = NULL ):
    enumServiceGroup = REnumServiceGroupW()
    enumServiceGroup['hSCManager'] = hSCManager
    enumServiceGroup['dwServiceType'] = dwServiceType
    enumServiceGroup['dwServiceState'] = dwServiceState
    enumServiceGroup['cbBufSize'] = cbBufSize
    enumServiceGroup['lpResumeIndex'] = lpResumeIndex
    enumServiceGroup['pszGroupName'] = pszGroupName
    return dce.request(enumServiceGroup)
