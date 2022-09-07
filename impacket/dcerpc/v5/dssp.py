# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-DSSP] Interface implementation
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dssp
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
#   Simon Decosse (@simondotsh)
#

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRENUM
from impacket.dcerpc.v5.dtypes import UINT, LPWSTR, GUID
from impacket import system_errors
from impacket.dcerpc.v5.enum import Enum
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_DSSP = uuidtup_to_bin(('3919286A-B10C-11D0-9BA8-00C04FD92EF5', '0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'DSSP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DSSP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 2.2.1 DSROLER_PRIMARY_DOMAIN_INFO_BASIC
DSROLE_PRIMARY_DS_RUNNING          = 0x00000001
DSROLE_PRIMARY_DS_MIXED_MODE       = 0x00000002
DSROLE_PRIMARY_DS_READONLY         = 0x00000008
DSROLE_PRIMARY_DOMAIN_GUID_PRESENT = 0x01000000

#2.2.5 DSROLE_UPGRADE_STATUS_INFO
DSROLE_UPGRADE_IN_PROGRESS = 0x00000004

################################################################################
# STRUCTURES
################################################################################
#2.2.2 DSROLE_MACHINE_ROLE
class DSROLE_MACHINE_ROLE(NDRENUM):
    class enumItems(Enum):
        DsRole_RoleStandaloneWorkstation   = 0
        DsRole_RoleMemberWorkstation       = 1
        DsRole_RoleStandaloneServer        = 2
        DsRole_RoleMemberServer            = 3
        DsRole_RoleBackupDomainController  = 4
        DsRole_RolePrimaryDomainController = 5
        
# 2.2.1 DSROLER_PRIMARY_DOMAIN_INFO_BASIC
class DSROLER_PRIMARY_DOMAIN_INFO_BASIC(NDRSTRUCT):
    structure = (
        ('MachineRole', DSROLE_MACHINE_ROLE),
        ('Flags', UINT),
        ('DomainNameFlat', LPWSTR),
        ('DomainNameDns', LPWSTR),
        ('DomainForestName', LPWSTR),
        ('DomainGuid', GUID),
    )

class PDSROLER_PRIMARY_DOMAIN_INFO_BASIC(NDRPOINTER):
    referent = (
        ('Data', DSROLER_PRIMARY_DOMAIN_INFO_BASIC),
    )

# 2.2.4 DSROLE_OPERATION_STATE
class DSROLE_OPERATION_STATE(NDRENUM):
    class enumItems(Enum):
        DsRoleOperationIdle       = 0
        DsRoleOperationActive     = 1
        DsRoleOperationNeedReboot = 2

# 2.2.3 DSROLE_OPERATION_STATE_INFO
class DSROLE_OPERATION_STATE_INFO(NDRSTRUCT):
    structure = (
        ('OperationState', DSROLE_OPERATION_STATE),
    )

class PDSROLE_OPERATION_STATE_INFO(NDRPOINTER):
    referent = (
        ('Data', DSROLE_OPERATION_STATE_INFO),
    )

# 2.2.6 DSROLE_SERVER_STATE
class DSROLE_SERVER_STATE(NDRENUM):
    class enumItems(Enum):
        DsRoleServerUnknown = 0
        DsRoleServerPrimary = 1
        DsRoleServerBackup  = 2

class PDSROLE_SERVER_STATE(NDRPOINTER):
    referent = (
        ('Data', DSROLE_SERVER_STATE),
    )

# 2.2.5 DSROLE_UPGRADE_STATUS_INFO
class DSROLE_UPGRADE_STATUS_INFO(NDRSTRUCT):
    structure = (
        ('OperationState', UINT),
        ('PreviousServerState', DSROLE_SERVER_STATE),
    )

class PDSROLE_UPGRADE_STATUS_INFO(NDRPOINTER):
    referent = (
        ('Data', DSROLE_UPGRADE_STATUS_INFO),
    )

# 2.2.7 DSROLE_PRIMARY_DOMAIN_INFO_LEVEL
class DSROLE_PRIMARY_DOMAIN_INFO_LEVEL(NDRENUM):
    class enumItems(Enum):
        DsRolePrimaryDomainInfoBasic = 1
        DsRoleUpgradeStatus          = 2
        DsRoleOperationState         = 3

# 2.2.8 DSROLER_PRIMARY_DOMAIN_INFORMATION
class DSROLER_PRIMARY_DOMAIN_INFORMATION(NDRUNION):
    commonHdr = (
        ('tag', DSROLE_PRIMARY_DOMAIN_INFO_LEVEL),
    )
    
    union = {
        DSROLE_PRIMARY_DOMAIN_INFO_LEVEL.DsRolePrimaryDomainInfoBasic : ('DomainInfoBasic', DSROLER_PRIMARY_DOMAIN_INFO_BASIC),
        DSROLE_PRIMARY_DOMAIN_INFO_LEVEL.DsRoleUpgradeStatus          : ('UpgradStatusInfo', DSROLE_UPGRADE_STATUS_INFO),
        DSROLE_PRIMARY_DOMAIN_INFO_LEVEL.DsRoleOperationState         : ('OperationStateInfo', DSROLE_OPERATION_STATE_INFO),
    }

class PDSROLER_PRIMARY_DOMAIN_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', DSROLER_PRIMARY_DOMAIN_INFORMATION),
    )

################################################################################
# RPC CALLS
################################################################################
# 3.2.5.1 DsRolerGetPrimaryDomainInformation (Opnum 0)
class DsRolerGetPrimaryDomainInformation(NDRCALL):
    opnum = 0
    structure = (
       ('InfoLevel', DSROLE_PRIMARY_DOMAIN_INFO_LEVEL),
    )

class DsRolerGetPrimaryDomainInformationResponse(NDRCALL):
    structure = (
       ('DomainInfo', PDSROLER_PRIMARY_DOMAIN_INFORMATION),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (DsRolerGetPrimaryDomainInformation, DsRolerGetPrimaryDomainInformationResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hDsRolerGetPrimaryDomainInformation(dce, infoLevel):
    request = DsRolerGetPrimaryDomainInformation()
    request['InfoLevel'] = infoLevel
    return dce.request(request)
