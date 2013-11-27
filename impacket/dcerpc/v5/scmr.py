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

from struct import unpack
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.ndr import NDRCall, NDR, NDRPointer, UNIQUE_RPC_UNICODE_STRING, NDRLONG, WSTR, RPC_UNICODE_STRING, NDRPointerNULL, NDRUniConformantArray, PNDRUniConformantArray, NDRBOOLEAN, NDRSHORT, NDRUniFixedArray, NDRUnion, NULL
from impacket.dcerpc.v5.dtypes import *

MSRPC_UUID_SVCCTL = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))

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

# Error Codes 
ERROR_FILE_NOT_FOUND             = 2
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
ERROR_CANNOT_DETECT_DRIVER_FAILURE = 1080
ERROR_SHUTDOWN_IN_PROGRESS       = 1115
ERROR_REQUEST_ABORTED            = 1235

class SCMRSessionError(Exception):
    
    error_messages = {
 ERROR_FILE_NOT_FOUND            : ("ERROR_FILE_NOT_FOUND", "he system cannot find the file specified."),          
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
 ERROR_REQUEST_ABORTED           : ("ERROR_REQUEST_ABORTED", "The request was aborted."),
 ERROR_CANNOT_DETECT_DRIVER_FAILURE: ("SERVICE_CONFIG_FAILURE_ACTIONS cannot be used as a dwInfoLevel in the Info parameter for service records with a Type value defined for drivers."),
    }    

    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        key = self.error_code
        if (SCMRSessionError.error_messages.has_key(key)):
            error_msg_short = SCMRSessionError.error_messages[key][0]
            error_msg_verbose = SCMRSessionError.error_messages[key][1] 
            return 'SVCCTL SessionError: code: %s - %s - %s' % (str(self.error_code), error_msg_short, error_msg_verbose)
        else:
            return 'SVCCTL SessionError: unknown error code: %s' % (str(self.error_code))

# SCMR Structures
class SC_RPC_HANDLE(NDR):
    structure =  (
        ('Data','20s=""'),
    )

SC_NOTIFY_RPC_HANDLE = SC_RPC_HANDLE

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
        ('lpBinaryPathName', LPWSTR),
        ('lpLoadOrderGroup',LPWSTR),
        ('dwTagId',DWORD),
        ('lpDependencies',LPWSTR),
        ('lpServiceStartName',LPWSTR),
        ('lpDisplayName',LPWSTR),
    )

class SC_RPC_LOCK(NDR):
    structure =  (
        ('Data','20s=""'),
    )

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

SVCCTL_HANDLEW = LPWSTR

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
BOUNDED_DWORD_4K = DWORD

class STRING_PTRSW(NDR):
    structure = (
        ('Data',NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = LPWSTR
        if data is not None:
            self.fromString(data)

class UNIQUE_STRING_PTRSW(NDRPointer):
    referent = (
        ('Data', STRING_PTRSW),
    )

class QUERY_SERVICE_LOCK_STATUSW(NDR):
    structure = (
        ('fIsLocked',DWORD),
        ('lpLockOwner',LPWSTR),
        ('dwLockDuration',DWORD),
    )

class SERVICE_DESCRIPTION_WOW64(NDR):
    structure = (
        ('dwDescriptionOffset', DWORD),
    )

class SERVICE_DESCRIPTIONW(NDR):
    structure = (
        ('lpDescription', LPWSTR),
    )

class LPSERVICE_DESCRIPTIONW(NDRPointer):
    referent = (
        ('Data', SERVICE_DESCRIPTIONW),
    )

class SERVICE_FAILURE_ACTIONS_WOW64(NDR):
    structure = (
        ('dwResetPeriod', DWORD),
        ('dwRebootMsgOffset', DWORD),
        ('dwCommandOffset', DWORD),
        ('cActions', DWORD),
        ('dwsaActionsOffset', DWORD),
    )

class SC_ACTION(NDR):
    structure = (
        ('Type', DWORD), 
        ('Delay', DWORD) , 
    )

class SC_ACTIONS(NDR):
    structure = (
       ('Data', NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = SC_ACTION
        if data is not None:
            self.fromString(data)

class SERVICE_FAILURE_ACTIONSW(NDR):
    structure = (
        ('dwResetPeriod', DWORD), 
        ('lpRebootMsg', LPWSTR) , 
        ('lpCommand', LPWSTR) , 
        ('cActions', DWORD) , 
        ('lpsaActions', SC_ACTIONS) , 
    )

class LPSERVICE_FAILURE_ACTIONSW(NDRPointer):
    referent = (
        ('Data', SERVICE_FAILURE_ACTIONSW),
    )

class SERVICE_FAILURE_ACTIONS_FLAG(NDR):
    structure = (
        ('fFailureActionsOnNonCrashFailures', BOOL),
    )

class LPSERVICE_FAILURE_ACTIONS_FLAG(NDRPointer):
    referent = (
        ('Data', SERVICE_FAILURE_ACTIONS_FLAG),
    )

class SERVICE_DELAYED_AUTO_START_INFO(NDR):
    structure = (
        ('fDelayedAutostart', BOOL),
    )

class LPSERVICE_DELAYED_AUTO_START_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_DELAYED_AUTO_START_INFO),
    )

class SERVICE_SID_INFO(NDR):
    structure = (
        ('dwServiceSidType', DWORD),
    )

class LPSERVICE_SID_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_SID_INFO),
    )


class SERVICE_RPC_REQUIRED_PRIVILEGES_INFO(NDR):
    structure = (
        ('cbRequiredPrivileges',DWORD),
        ('pRequiredPrivileges',LPBYTE),
    )
    def getData(self):
        self['cbRequiredPrivileges'] = len(self['pRequiredPrivileges'])
        return NDR.getData(self)


class LPSERVICE_RPC_REQUIRED_PRIVILEGES_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_RPC_REQUIRED_PRIVILEGES_INFO),
    )

class SERVICE_REQUIRED_PRIVILEGES_INFO_WOW64(NDR):
    structure = (
        ('dwRequiredPrivilegesOffset', DWORD),
    )

class SERVICE_PRESHUTDOWN_INFO(NDR):
    structure = (
        ('dwPreshutdownTimeout', DWORD),
    )

class LPSERVICE_PRESHUTDOWN_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_PRESHUTDOWN_INFO),
    )

class SERVICE_STATUS_PROCESS(NDR):
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

class UCHAR_16(NDR):
    structure = (
        ('Data', '16s=""'),
    )

class SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1(NDR):
    structure = (
        ('ullThreadId',ULONGLONG),
        ('dwNotifyMask',DWORD),
        ('CallbackAddressArray',UCHAR_16),
        ('CallbackParamAddressArray',UCHAR_16),
        ('ServiceStatus', SERVICE_STATUS_PROCESS),
        ('dwNotificationStatus',DWORD),
        ('dwSequence',DWORD),
    )

class SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2(NDR):
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

class PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1(NDRPointer):
    referent = (
        ('Data', SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1),
    )

class PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2(NDRPointer):
    referent = (
        ('Data', SERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2),
    )

class SC_RPC_NOTIFY_PARAMS(NDRUnion):
    union = {
        1: ('pStatusChangeParam1', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1),
        2: ('pStatusChangeParams', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2),
    }

class SC_RPC_NOTIFY_PARAMS_ARRAY(NDR):
    structure = (
        ('Data',NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = SC_RPC_NOTIFY_PARAMS
        if data is not None:
            self.fromString(data)

class PSC_RPC_NOTIFY_PARAMS_LIST(NDR):
    structure = (
        ('cElements',BOUNDED_DWORD_4K),
        ('NotifyParamsArray', SC_RPC_NOTIFY_PARAMS_ARRAY),
    )

class SERVICE_CONTROL_STATUS_REASON_IN_PARAMSW(NDR):
    structure = (
        ('dwReason', DWORD),
        ('pszComment', LPWSTR),
    )

class SERVICE_TRIGGER_SPECIFIC_DATA_ITEM(NDR):
    structure = (
        ('dwDataType',DWORD ),
        ('cbData',DWORD),
        ('pData', LPBYTE),
    )
    def getData(self):
        if self['pData'] != 0:
            self['cbData'] = len(self['pData'])
        return NDR.getData(self)

class SERVICE_TRIGGER_SPECIFIC_DATA_ITEM_ARRAY(NDR):
    structure = (
        ('Data',NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = SERVICE_TRIGGER_SPECIFIC_DATA_ITEM
        if data is not None:
            self.fromString(data)

class PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM(NDRPointer):
    referent = (
        ('Data', SERVICE_TRIGGER_SPECIFIC_DATA_ITEM_ARRAY),
    )

class SERVICE_TRIGGER(NDR):
    structure = (
        ('dwTriggerType', DWORD),
        ('dwAction', DWORD),
        ('pTriggerSubtype', PGUID),
        ('cDataItems', DWORD),
        ('pDataItems', PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM),
    )
    def getData(self):
        if self['pDataItems'] != 0:
            self['cDataItems'] = len(self['pDataItems'])
        return NDR.getData(self)

class SERVICE_TRIGGER_ARRAY(NDR):
    structure = (
        ('Data',NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False):
        NDR.__init__(self,None,isNDR64)
        self.fields['Data'].item = SERVICE_TRIGGER
        if data is not None:
            self.fromString(data)

class PSERVICE_TRIGGER(NDRPointer):
    referent = (
        ('Data', SERVICE_TRIGGER_ARRAY),
    )

class SERVICE_CONTROL_STATUS_REASON_OUT_PARAMS(NDR):
    structure = (
       ('ServiceStatus', SERVICE_STATUS_PROCESS),
    )

class SERVICE_TRIGGER_INFO(NDR):
    structure = (
        ('cTriggers', DWORD),
        ('pTriggers', PSERVICE_TRIGGER),
        ('pReserved', NDRPointerNULL ),
    )
    def getData(self):
        if self['pTriggers'] != 0:
            self['cTriggers'] = len(self['pTriggers'])
        return NDR.getData(self)
    
class PSERVICE_TRIGGER_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_TRIGGER_INFO),
    )

class SERVICE_PREFERRED_NODE_INFO(NDR):
    structure = (
        ('usPreferredNode', NDRSHORT),
        ('fDelete', BOOL),
    )

class LPSERVICE_PREFERRED_NODE_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_PREFERRED_NODE_INFO),
    )

class SERVICE_RUNLEVEL_INFO(NDR):
    structure = (
        ('eLowestRunLevel', DWORD),
    )

class PSERVICE_RUNLEVEL_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_RUNLEVEL_INFO),
    )

class SERVICE_MANAGEDACCOUNT_INFO(NDR):
    structure = (
        ('fIsManagedAccount', DWORD),
    )

class PSERVICE_MANAGEDACCOUNT_INFO(NDRPointer):
    referent = (
        ('Data', SERVICE_MANAGEDACCOUNT_INFO),
    )

class SC_RPC_CONFIG_INFOW2(NDR):
    structure= (
        ('psd', LPSERVICE_DESCRIPTIONW),
    )

class SC_RPC_CONFIG_INFOW(NDRUnion):
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

# RPC Calls
class RCloseServiceHandleCall(NDRCall):
    opnum = 0
    structure = (
        ('hSCObject',SC_RPC_HANDLE),
    )

class RCloseServiceHandleResponse(NDRCall):
    structure = (
        ('hSCObject',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
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
        ('ErrorCode', DWORD),
    )

class RDeleteServiceCall(NDRCall):
    opnum = 2
    structure = (
        ('hService',SC_RPC_HANDLE),
    )

class RDeleteServiceResponse(NDRCall):
    structure = (
        ('ErrorCode', DWORD),
    )

class RLockServiceDatabaseCall(NDRCall):
    opnum = 3
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
    )

class RLockServiceDatabaseResponse(NDRCall):
    structure = (
        ('lpLock',SC_RPC_LOCK),
        ('ErrorCode', DWORD),
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
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
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
        ('ErrorCode', DWORD),
    )

class RQueryServiceStatusCall(NDRCall):
    opnum = 6
    structure = (
        ('hService',SC_RPC_HANDLE),
    )

class RQueryServiceStatusResponse(NDRCall):
    structure = (
        ('lpServiceStatus',SERVICE_STATUS),
        ('ErrorCode', DWORD),
    )

class RSetServiceStatusCall(NDRCall):
    opnum = 7
    structure = (
        ('hServiceStatus',SC_RPC_HANDLE),
        ('lpServiceStatus',SERVICE_STATUS),
    )

class RSetServiceStatusResponse(NDRCall):
    structure = (
        ('ErrorCode', DWORD),
    )

class RUnlockServiceDatabaseCall(NDRCall):
    opnum = 8
    structure = (
        ('Lock',SC_RPC_LOCK),
    )

class RUnlockServiceDatabaseResponse(NDRCall):
    structure = (
        ('Lock',SC_RPC_LOCK),
        ('ErrorCode', DWORD),
    )

class RNotifyBootConfigStatusCall(NDRCall):
    opnum = 9
    structure = (
        ('lpMachineName',SVCCTL_HANDLEW),
        ('BootAcceptable',DWORD),
    )

class RNotifyBootConfigStatusResponse(NDRCall):
    structure = (
        ('ErrorCode', DWORD),
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
        ('ErrorCode', DWORD),
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
        ('lpServiceHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
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
        ('ErrorCode', DWORD),
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
        ('ErrorCode', DWORD),
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
        ('lpScHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
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
        ('lpServiceHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
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
        ('ErrorCode', DWORD),
    )

class RQueryServiceLockStatusWCall(NDRCall):
    opnum = 18
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('cbBufSize',DWORD),
    )

class RQueryServiceLockStatusWResponse(NDRCall):
    structure = (
        ('lpLockStatus',QUERY_SERVICE_LOCK_STATUSW),
        ('pcbBytesNeeded',BOUNDED_DWORD_4K),
        ('ErrorCode', DWORD),
    )

class RStartServiceWCall(NDRCall):
    opnum = 19
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('argc',DWORD),
        ('argv',UNIQUE_STRING_PTRSW),
    )

class RStartServiceWResponse(NDRCall):
    structure = (
        ('ErrorCode', DWORD),
    )

class RGetServiceDisplayNameWCall(NDRCall):
    opnum = 20
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpServiceName',RPC_UNICODE_STRING),
        ('lpcchBuffer',DWORD),
    )

class RGetServiceDisplayNameWResponse(NDRCall):
    structure = (
        ('lpDisplayName',RPC_UNICODE_STRING),
        ('lpcchBuffer',DWORD),
        ('ErrorCode', DWORD),
    )

class RGetServiceKeyNameWCall(NDRCall):
    opnum = 21
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('lpDisplayName',RPC_UNICODE_STRING),
        ('lpcchBuffer',DWORD),
    )

class RGetServiceKeyNameWResponse(NDRCall):
    structure = (
        ('lpDisplayName',RPC_UNICODE_STRING),
        ('lpcchBuffer',DWORD),
        ('ErrorCode', DWORD),
    )


class REnumServiceGroupWCall(NDRCall):
    opnum = 35
    structure = (
        ('hSCManager',SC_RPC_HANDLE),
        ('dwServiceType',DWORD),
        ('dwServiceState',DWORD),
        ('cbBufSize',DWORD),
        ('lpResumeIndex',LPBOUNDED_DWORD_256K),
        ('pszGroupName',LPWSTR),
    )

class REnumServiceGroupWResponse(NDRCall):
    structure = (
        ('lpBuffer',LPBYTE),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
        ('lpResumeIndex',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class RChangeServiceConfig2W(NDRCall):
    opnum = 37
    structure = (
       ('hService',SC_RPC_HANDLE),
       ('Info',SC_RPC_CONFIG_INFOW),
    )

class RChangeServiceConfig2WResponse(NDRCall):
    structure = (
        ('ErrorCode', DWORD),
    )

class RQueryServiceConfig2W(NDRCall):
    opnum = 39
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwInfoLevel',DWORD),
        ('cbBufSize',DWORD),
    )

class RQueryServiceConfig2WResponse(NDRCall):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_8K),
        ('ErrorCode', DWORD),
    )

class RQueryServiceStatusEx(NDRCall):
    opnum = 40
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('InfoLevel',DWORD),
        ('cbBufSize',DWORD),
    )

class RQueryServiceStatusExResponse(NDRCall):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_8K),
        ('ErrorCode', DWORD),
    )

class REnumServicesStatusExW(NDRCall):
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

class REnumServicesStatusExWResponse(NDRCall):
    structure = (
        ('lpBuffer',NDRUniConformantArray),
        ('pcbBytesNeeded',BOUNDED_DWORD_256K),
        ('lpServicesReturned',BOUNDED_DWORD_256K),
        ('lpResumeIndex',BOUNDED_DWORD_256K),
        ('ErrorCode', DWORD),
    )

class RCreateServiceWOW64W(NDRCall):
    opnum = 45
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

class RCreateServiceWOW64WResponse(NDRCall):
    structure = (
        ('lpdwTagId',UNIQUE_RPC_UNICODE_STRING),
        ('lpServiceHandle',SC_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

# Still not working, for some reason something changes in the way the pointer inside SC_RPC_NOTIFY_PARAMS is marshalled here
class RNotifyServiceStatusChange(NDRCall):
    opnum = 47
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('NotifyParams',SC_RPC_NOTIFY_PARAMS),
        ('pClientProcessGuid',GUID),
    )

class RNotifyServiceStatusChangeResponse(NDRCall):
    structure = (
        ('pSCMProcessGuid',GUID),
        ('pfCreateRemoteQueue',PBOOL),
        ('phNotify',SC_NOTIFY_RPC_HANDLE),
        ('ErrorCode', DWORD),
    )

# Not working, until I don't fix the previous one
class RGetNotifyResults(NDRCall):
    opnum = 48
    structure = (
        ('hNotify',SC_NOTIFY_RPC_HANDLE),
    )

class RGetNotifyResultsResponse(NDRCall):
    structure = (
        ('ppNotifyParams',PSC_RPC_NOTIFY_PARAMS_LIST),
        ('ErrorCode', DWORD),
    )

# Not working, until I don't fix the previous ones
class RCloseNotifyHandle(NDRCall):
    opnum = 49
    structure = (
        ('phNotify',SC_NOTIFY_RPC_HANDLE),
    )

class RCloseNotifyHandleResponse(NDRCall):
    structure = (
        ('phNotify',SC_NOTIFY_RPC_HANDLE),
        ('pfApcFired',PBOOL),
        ('ErrorCode', DWORD),
    )

# Not working, returning bad_stub_data
class RControlServiceExW(NDRCall):
    opnum = 51
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwControl',DWORD),
        ('dwInfoLevel',DWORD),
        ('pControlInParams',SERVICE_CONTROL_STATUS_REASON_IN_PARAMSW),
    )

class RControlServiceExWResponse(NDRCall):
    structure = (
        ('pControlOutParams',SERVICE_CONTROL_STATUS_REASON_OUT_PARAMS),
        ('ErrorCode', DWORD),
    )

class RQueryServiceConfigEx(NDRCall):
    opnum = 56
    structure = (
        ('hService',SC_RPC_HANDLE),
        ('dwInfoLevel',DWORD),
    )

class RQueryServiceConfigExResponse(NDRCall):
    structure = (
        ('pInfo',SC_RPC_CONFIG_INFOW),
        ('ErrorCode', DWORD),
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
                raise SCMRSessionError(error_code)  
        return answer

    def request(self, request):
        self._dcerpc.call(request.opnum, request)
        answer = self._dcerpc.recv()
        resp = request.__class__.__name__ + 'Response'
        return eval(resp)(answer)

    def RCloseServiceHandle(self, hSCObject):
        closeService = RCloseServiceHandleCall()
        closeService['hSCObject'] = hSCObject
        ans = self.doRequest(closeService)
        resp = RCloseServiceHandleResponse(ans)
        return resp

    def RControlService(self, hService, dwControl):
        controlService = RControlServiceCall()
        controlService['hService'] = hService
        controlService['dwControl'] = dwControl
        ans = self.doRequest(controlService)
        resp = RControlServiceResponse(ans)
        return resp

    def RDeleteService(self, hService):
        deleteService = RDeleteServiceCall()
        deleteService['hService'] = hService
        ans = self.doRequest(deleteService)
        resp = RDeleteServiceResponse(ans)
        return resp
    
    def RLockServiceDatabase(self, hSCManager):
        lockServiceDatabase = RLockServiceDatabaseCall()
        lockServiceDatabase['hSCManager'] = hSCManager
        ans = self.doRequest(lockServiceDatabase)
        resp = RLockServiceDatabaseResponse(ans)
        return resp

    def RQueryServiceObjectSecurity(self, hService, dwSecurityInformation, cbBufSize ):
        queryServiceObjectSecurity = RQueryServiceObjectSecurityCall()
        queryServiceObjectSecurity['hService'] = hService
        queryServiceObjectSecurity['dwSecurityInformation'] = dwSecurityInformation
        queryServiceObjectSecurity['cbBufSize'] = cbBufSize
        ans = self.doRequest(queryServiceObjectSecurity)
        resp = RQueryServiceObjectSecurityResponse(ans)
        return resp

    def RSetServiceObjectSecurity(self, hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize ):
        setServiceObjectSecurity = RSetServiceObjectSecurityCall()
        setServiceObjectSecurity['hService'] = hService
        setServiceObjectSecurity['dwSecurityInformation'] = dwSecurityInformation
        setServiceObjectSecurity['cbBufSize'] = cbBufSize
        ans = self.doRequest(setServiceObjectSecurity)
        resp = RSetServiceObjectSecurityResponse(ans)
        return resp

    def RQueryServiceStatus(self, hService ):
        queryServiceStatus = RQueryServiceStatusCall()
        queryServiceStatus['hService'] = hService
        ans = self.doRequest(queryServiceStatus)
        resp = RQueryServiceStatusResponse(ans)
        return resp

    def RSetServiceStatus(self, hServiceStatus, lpServiceStatus ):
        setServiceStatus = RSetServiceStatusCall()
        setServiceStatus['hServiceStatus'] = hServiceStatus
        setServiceStatus['lpServiceStatus'] = lpServiceStatus
        ans = self.doRequest(setServiceStatus)
        resp = RSetServiceStatusResponse(ans)
        return resp

    def RUnlockServiceDatabase(self, Lock ):
        unlockServiceDatabase = RUnlockServiceDatabaseCall()
        unlockServiceDatabase['Lock'] = Lock
        ans = self.doRequest(unlockServiceDatabase)
        resp = RUnlockServiceDatabaseResponse(ans)
        return resp

    def RNotifyBootConfigStatus(self, lpMachineName, BootAcceptable ):
        notifyBootConfigStatus = RNotifyBootConfigStatusCall()
        notifyBootConfigStatus['lpMachineName'] = lpMachineName
        notifyBootConfigStatus['BootAcceptable'] = BootAcceptable
        ans = self.doRequest(notifyBootConfigStatus)
        resp = RNotifyBootConfigStatusResponse(ans)
        return resp

    def RChangeServiceConfigW(self, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName):
        changeServiceConfig = RChangeServiceConfigWCall()
        changeServiceConfig['hService'] = hService
        changeServiceConfig['dwServiceType'] = dwServiceType
        changeServiceConfig['dwStartType'] = dwStartType
        changeServiceConfig['dwErrorControl'] = dwErrorControl
        if lpBinaryPathName == '':
            changeServiceConfig['lpBinaryPathName'] = NULL
        else:
            changeServiceConfig['lpBinaryPathName'] = lpBinaryPathName
        if lpLoadOrderGroup == '':
            changeServiceConfig['lpLoadOrderGroup'] = NULL
        else:
            changeServiceConfig['lpLoadOrderGroup'] = lpLoadOrderGroup
        if lpdwTagId == '':
            changeServiceConfig['lpdwTagId'] = NULL
        else:
            changeServiceConfig['lpdwTagId'] = lpdwTagId
        if lpDependencies == '':
            changeServiceConfig['lpDependencies'] = NULL
        else:
            changeServiceConfig['lpDependencies'] = lpDependencies
        changeServiceConfig['dwDependSize'] = dwDependSize
        if lpServiceStartName == '':
            changeServiceConfig['lpServiceStartName'] = NULL
        else:
            changeServiceConfig['lpServiceStartName'] = lpServiceStartName
        if lpPassword == '':
            changeServiceConfig['lpPassword'] = NULL
        else:
            changeServiceConfig['lpPassword'] = lpPassword
        changeServiceConfig['dwPwSize'] = dwPwSize
        if lpDisplayName == '':
            changeServiceConfig['lpDisplayName'] = NULL
        else:
            changeServiceConfig['lpDisplayName'] = lpDisplayName
        ans = self.doRequest(changeServiceConfig)
        resp = RChangeServiceConfigWResponse(ans)
        return resp

    def RCreateServiceW(self, hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize):
        createService = RCreateServiceWCall()
        createService['hSCManager'] = hSCManager
        createService['lpServiceName'] = lpServiceName
        createService['lpDisplayName'] = lpDisplayName
        createService['dwDesiredAccess'] = dwDesiredAccess
        createService['dwServiceType'] = dwServiceType
        createService['dwStartType'] = dwStartType
        createService['dwErrorControl'] = dwErrorControl
        createService['lpBinaryPathName'] = lpBinaryPathName
        if lpLoadOrderGroup == '':
            createService['lpLoadOrderGroup'] = NULL
        else:
            createService['lpLoadOrderGroup'] = lpLoadOrderGroup
        if lpdwTagId == '':
            createService['lpdwTagId'] = NULL
        else: 
            createService['lpdwTagId'] = lpdwTagId
        if lpDependencies == '':
            createService['lpDependencies'] = NULL
        else:
            createService['lpDependencies'] = lpDependencies
        createService['dwDependSize'] = dwDependSize
        if lpServiceStartName == '':
            createService['lpServiceStartName'] = NULL
        else:
            createService['lpServiceStartName'] = lpServiceStartName
        if lpPassword == '':
            createService['lpPassword'] = NULL
        else:
            createService['lpPassword'] = lpPassword
        createService['dwPwSize'] = dwPwSize
        ans = self.doRequest(createService)
        resp = RCreateServiceWResponse(ans)
        return resp

    def REnumDependentServicesW(self, hService, dwServiceState, cbBufSize ):
        enumDependentServices = REnumDependentServicesWCall()
        enumDependentServices['hService'] = hService
        enumDependentServices['dwServiceState'] = dwServiceState
        enumDependentServices['cbBufSize'] = cbBufSize
        ans = self.doRequest(enumDependentServices, checkReturn = 0)
        resp = REnumDependentServicesWResponse(ans)
        return resp

    def REnumServicesStatusW(self, hSCManager, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex ):
        enumServicesStatus = REnumServicesStatusWCall()
        enumServicesStatus['hSCManager'] = hSCManager
        enumServicesStatus['dwServiceType'] = dwServiceType
        enumServicesStatus['dwServiceState'] = dwServiceState
        enumServicesStatus['cbBufSize'] = cbBufSize
        if lpResumeIndex == 0:
            enumServicesStatus['lpResumeIndex'] = NULL
        else:
            enumServicesStatus['lpResumeIndex'] = lpResumeIndex
        ans = self.doRequest(enumServicesStatus, checkReturn = 0)
        resp = REnumServicesStatusWResponse(ans)
        return resp

    def ROpenSCManagerW(self, lpMachineName, lpDatabaseName, dwDesiredAccess):
        openSCManager = ROpenSCManagerWCall()
        openSCManager['lpMachineName'] = lpMachineName
        if lpDatabaseName == '':
            openSCManager['lpDatabaseName'] = NULL
        else:
            openSCManager['lpDatabaseName'] = lpDatabaseName
        openSCManager['dwDesiredAccess'] = dwDesiredAccess
        ans = self.doRequest(openSCManager)
        resp = ROpenSCManagerWResponse(ans)
        return resp

    def ROpenServiceW(self, hSCManager, lpServiceName, dwDesiredAccess):
        openService = ROpenServiceWCall()
        openService['hSCManager'] = hSCManager
        openService['lpServiceName'] = lpServiceName
        openService['dwDesiredAccess'] = dwDesiredAccess
        ans = self.doRequest(openService)
        resp = ROpenServiceWResponse(ans)
        return resp

    def RQueryServiceConfigW(self, hService, cbBufSize ):
        queryService = RQueryServiceConfigWCall()
        queryService['hService'] = hService
        queryService['cbBufSize'] = cbBufSize
        ans = self.doRequest(queryService, checkReturn = 0)
        resp = RQueryServiceConfigWResponse(ans)
        return resp

    def RQueryServiceLockStatusW(self, hSCManager, cbBufSize ):
        queryServiceLock = RQueryServiceLockStatusWCall()
        queryServiceLock['hSCManager'] = hSCManager
        queryServiceLock['cbBufSize'] = cbBufSize
        ans = self.doRequest(queryServiceLock, checkReturn = 0)
        resp = RQueryServiceLockStatusWResponse(ans)
        return resp

    def RStartServiceW(self, hService, argc, argv ):
        startService = RStartServiceWCall()
        startService['hService'] = hService
        startService['argc'] = argc
        if argc == 0:
            startService['argv'] = NULL
        else:
            items = []
            for item in argv:
                itemn = LPWSTR()
                itemn['Data'] = item
                startService['argv'].append(itemn)
        ans = self.doRequest(startService)
        resp = RStartServiceWResponse(ans)
        return resp

    def RGetServiceDisplayNameW(self, hSCManager, lpServiceName, lpcchBuffer ):
        getServiceDisplay = RGetServiceDisplayNameWCall()
        getServiceDisplay['hSCManager'] = hSCManager
        getServiceDisplay['lpServiceName'] = lpServiceName
        getServiceDisplay['lpcchBuffer'] = lpcchBuffer
        ans = self.doRequest(getServiceDisplay)
        resp = RGetServiceDisplayNameWResponse(ans)
        return resp

    def RGetServiceKeyNameW(self, hSCManager, lpDisplayName, lpcchBuffer ):
        getServiceKeyName = RGetServiceKeyNameWCall()
        getServiceKeyName['hSCManager'] = hSCManager
        getServiceKeyName['lpDisplayName'] = lpDisplayName
        getServiceKeyName['lpcchBuffer'] = lpcchBuffer
        ans = self.doRequest(getServiceKeyName)
        resp = RGetServiceKeyNameWResponse(ans)
        return resp

    def REnumServiceGroupW(self, hSCManager, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex, pszGroupName ):
        enumServiceGroup = REnumServiceGroupWCall()
        enumServiceGroup['hSCManager'] = hSCManager
        enumServiceGroup['dwServiceType'] = dwServiceType
        enumServiceGroup['dwServiceState'] = dwServiceState
        enumServiceGroup['cbBufSize'] = cbBufSize
        if lpResumeIndex == 0:
            enumServiceGroup['lpResumeIndex'] = NULL
        else:
            enumServiceGroup['lpResumeIndex'] = lpResumeIndex
        enumServiceGroup['pszGroupName'] = pszGroupName
        ans = self.doRequest(enumServiceGroup)
        resp = REnumServiceGroupWResponse(ans)
        return resp

