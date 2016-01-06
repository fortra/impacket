# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-LSAD] Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/CoreSecurity/impacket/tree/master/impacket/testcases/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#
from impacket.dcerpc.v5.ndr import NDRCALL, NDRENUM, NDRUNION, NDRUniConformantVaryingArray, NDRPOINTER, NDR, NDRSTRUCT, \
    NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, STR, LUID, LONG, ULONG, RPC_UNICODE_STRING, PRPC_SID, LPBYTE, \
    LARGE_INTEGER, NTSTATUS, RPC_SID, ACCESS_MASK, UCHAR, PRPC_UNICODE_STRING, PLARGE_INTEGER, USHORT, \
    SECURITY_INFORMATION, NULL, MAXIMUM_ALLOWED, GUID, SECURITY_DESCRIPTOR, OWNER_SECURITY_INFORMATION
from impacket import nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_LSAD  = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if nt_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'LSAD SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'LSAD SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 2.2.1.1.2 ACCESS_MASK for Policy Objects
POLICY_VIEW_LOCAL_INFORMATION   = 0x00000001
POLICY_VIEW_AUDIT_INFORMATION   = 0x00000002
POLICY_GET_PRIVATE_INFORMATION  = 0x00000004
POLICY_TRUST_ADMIN              = 0x00000008
POLICY_CREATE_ACCOUNT           = 0x00000010
POLICY_CREATE_SECRET            = 0x00000020
POLICY_CREATE_PRIVILEGE         = 0x00000040
POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080
POLICY_SET_AUDIT_REQUIREMENTS   = 0x00000100
POLICY_AUDIT_LOG_ADMIN          = 0x00000200
POLICY_SERVER_ADMIN             = 0x00000400
POLICY_LOOKUP_NAMES             = 0x00000800
POLICY_NOTIFICATION             = 0x00001000

# 2.2.1.1.3 ACCESS_MASK for Account Objects
ACCOUNT_VIEW                 = 0x00000001
ACCOUNT_ADJUST_PRIVILEGES    = 0x00000002
ACCOUNT_ADJUST_QUOTAS        = 0x00000004
ACCOUNT_ADJUST_SYSTEM_ACCESS = 0x00000008

# 2.2.1.1.4 ACCESS_MASK for Secret Objects
SECRET_SET_VALUE   = 0x00000001
SECRET_QUERY_VALUE = 0x00000002

# 2.2.1.1.5 ACCESS_MASK for Trusted Domain Objects
TRUSTED_QUERY_DOMAIN_NAME = 0x00000001
TRUSTED_QUERY_CONTROLLERS = 0x00000002
TRUSTED_SET_CONTROLLERS   = 0x00000004
TRUSTED_QUERY_POSIX       = 0x00000008
TRUSTED_SET_POSIX         = 0x00000010
TRUSTED_SET_AUTH          = 0x00000020
TRUSTED_QUERY_AUTH        = 0x00000040

# 2.2.1.2 POLICY_SYSTEM_ACCESS_MODE
POLICY_MODE_INTERACTIVE             = 0x00000001
POLICY_MODE_NETWORK                 = 0x00000002
POLICY_MODE_BATCH                   = 0x00000004
POLICY_MODE_SERVICE                 = 0x00000010
POLICY_MODE_DENY_INTERACTIVE        = 0x00000040
POLICY_MODE_DENY_NETWORK            = 0x00000080
POLICY_MODE_DENY_BATCH              = 0x00000100
POLICY_MODE_DENY_SERVICE            = 0x00000200
POLICY_MODE_REMOTE_INTERACTIVE      = 0x00000400
POLICY_MODE_DENY_REMOTE_INTERACTIVE = 0x00000800
POLICY_MODE_ALL                     = 0x00000FF7
POLICY_MODE_ALL_NT4                 = 0x00000037

# 2.2.4.4 LSAPR_POLICY_AUDIT_EVENTS_INFO
# EventAuditingOptions
POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000
POLICY_AUDIT_EVENT_NONE      = 0x00000004
POLICY_AUDIT_EVENT_SUCCESS   = 0x00000001
POLICY_AUDIT_EVENT_FAILURE   = 0x00000002

# 2.2.4.19 POLICY_DOMAIN_KERBEROS_TICKET_INFO
# AuthenticationOptions
POLICY_KERBEROS_VALIDATE_CLIENT = 0x00000080

# 2.2.7.21 LSA_FOREST_TRUST_RECORD
# Flags
LSA_TLN_DISABLED_NEW          = 0x00000001
LSA_TLN_DISABLED_ADMIN        = 0x00000002
LSA_TLN_DISABLED_CONFLICT     = 0x00000004
LSA_SID_DISABLED_ADMIN        = 0x00000001
LSA_SID_DISABLED_CONFLICT     = 0x00000002
LSA_NB_DISABLED_ADMIN         = 0x00000004
LSA_NB_DISABLED_CONFLICT      = 0x00000008
LSA_FTRECORD_DISABLED_REASONS = 0x0000FFFF

################################################################################
# STRUCTURES
################################################################################
# 2.2.2.1 LSAPR_HANDLE
class LSAPR_HANDLE(NDRSTRUCT):
    align = 1
    structure =  (
        ('Data','20s=""'),
    )

# 2.2.2.3 LSA_UNICODE_STRING
LSA_UNICODE_STRING = RPC_UNICODE_STRING

# 2.2.3.1 STRING
class STRING(NDRSTRUCT):
    commonHdr = (
        ('MaximumLength','<H=len(Data)-12'),
        ('Length','<H=len(Data)-12'),
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('MaximumLength','<H=len(Data)-24'),
        ('Length','<H=len(Data)-24'),
        ('ReferentID','<Q=0xff'),
    )

    referent = (
        ('Data',STR),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here just print the data
        print " %r" % (self['Data']),

    def __setitem__(self, key, value):
        if key == 'Data':
            self.fields['MaximumLength'] = None
            self.fields['Length'] = None
            self.data = None        # force recompute
        return NDR.__setitem__(self, key, value)

# 2.2.3.2 LSAPR_ACL
class LSAPR_ACL(NDRSTRUCT):
    structure =  (
        ('AclRevision', UCHAR),
        ('Sbz1', UCHAR),
        ('AclSize', USHORT),
        ('Dummy1',NDRUniConformantArray),
    )

# 2.2.3.4 LSAPR_SECURITY_DESCRIPTOR
LSAPR_SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR

class PLSAPR_SECURITY_DESCRIPTOR(NDRPOINTER):
    referent = (
        ('Data', LSAPR_SECURITY_DESCRIPTOR),
    )

# 2.2.3.5 SECURITY_IMPERSONATION_LEVEL
class SECURITY_IMPERSONATION_LEVEL(NDRENUM):
    class enumItems(Enum):
        SecurityAnonymous      = 0
        SecurityIdentification = 1
        SecurityImpersonation  = 2
        SecurityDelegation     = 3

# 2.2.3.6 SECURITY_CONTEXT_TRACKING_MODE
SECURITY_CONTEXT_TRACKING_MODE = UCHAR

# 2.2.3.7 SECURITY_QUALITY_OF_SERVICE
class SECURITY_QUALITY_OF_SERVICE(NDRSTRUCT):
    structure = (
        ('Length', DWORD), 
        ('ImpersonationLevel', SECURITY_IMPERSONATION_LEVEL), 
        ('ContextTrackingMode', SECURITY_CONTEXT_TRACKING_MODE), 
        ('EffectiveOnly', UCHAR), 
    )

class PSECURITY_QUALITY_OF_SERVICE(NDRPOINTER):
    referent = (
        ('Data', SECURITY_QUALITY_OF_SERVICE),
    )

# 2.2.2.4 LSAPR_OBJECT_ATTRIBUTES
class LSAPR_OBJECT_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Length', DWORD), 
        ('RootDirectory', LPWSTR), 
        ('ObjectName', LPWSTR), 
        ('Attributes', DWORD), 
        ('SecurityDescriptor', PLSAPR_SECURITY_DESCRIPTOR), 
        ('SecurityQualityOfService', PSECURITY_QUALITY_OF_SERVICE), 
    )

# 2.2.2.5 LSAPR_SR_SECURITY_DESCRIPTOR
class LSAPR_SR_SECURITY_DESCRIPTOR(NDRSTRUCT):
    structure = (
        ('Length', DWORD), 
        ('SecurityDescriptor', LPBYTE), 
    )

class PLSAPR_SR_SECURITY_DESCRIPTOR(NDRPOINTER):
    referent = (
        ('Data', LSAPR_SR_SECURITY_DESCRIPTOR),
    )

# 2.2.3.3 SECURITY_DESCRIPTOR_CONTROL
SECURITY_DESCRIPTOR_CONTROL = ULONG

# 2.2.4.1 POLICY_INFORMATION_CLASS
class POLICY_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        PolicyAuditLogInformation           = 1
        PolicyAuditEventsInformation        = 2
        PolicyPrimaryDomainInformation      = 3
        PolicyPdAccountInformation          = 4
        PolicyAccountDomainInformation      = 5
        PolicyLsaServerRoleInformation      = 6
        PolicyReplicaSourceInformation      = 7
        PolicyInformationNotUsedOnWire      = 8
        PolicyModificationInformation       = 9
        PolicyAuditFullSetInformation       = 10
        PolicyAuditFullQueryInformation     = 11
        PolicyDnsDomainInformation          = 12
        PolicyDnsDomainInformationInt       = 13
        PolicyLocalAccountDomainInformation = 14
        PolicyLastEntry                     = 15

# 2.2.4.3 POLICY_AUDIT_LOG_INFO
class POLICY_AUDIT_LOG_INFO(NDRSTRUCT):
    structure = (
        ('AuditLogPercentFull', DWORD), 
        ('MaximumLogSize', DWORD), 
        ('AuditRetentionPeriod', LARGE_INTEGER), 
        ('AuditLogFullShutdownInProgress', UCHAR), 
        ('TimeToShutdown', LARGE_INTEGER), 
        ('NextAuditRecordId', DWORD), 
    )

# 2.2.4.4 LSAPR_POLICY_AUDIT_EVENTS_INFO
class DWORD_ARRAY(NDRUniConformantArray):
    item = DWORD

class PDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY),
    )

class LSAPR_POLICY_AUDIT_EVENTS_INFO(NDRSTRUCT):
    structure = (
        ('AuditingMode', UCHAR), 
        ('EventAuditingOptions', PDWORD_ARRAY), 
        ('MaximumAuditEventCount', DWORD), 
    )

# 2.2.4.5 LSAPR_POLICY_PRIMARY_DOM_INFO
class LSAPR_POLICY_PRIMARY_DOM_INFO(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
    )

# 2.2.4.6 LSAPR_POLICY_ACCOUNT_DOM_INFO
class LSAPR_POLICY_ACCOUNT_DOM_INFO(NDRSTRUCT):
    structure = (
        ('DomainName', RPC_UNICODE_STRING), 
        ('DomainSid', PRPC_SID), 
    )

# 2.2.4.7 LSAPR_POLICY_PD_ACCOUNT_INFO
class LSAPR_POLICY_PD_ACCOUNT_INFO(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
    )

# 2.2.4.8 POLICY_LSA_SERVER_ROLE
class POLICY_LSA_SERVER_ROLE(NDRENUM):
    class enumItems(Enum):
        PolicyServerRoleBackup   = 2
        PolicyServerRolePrimary  = 3

# 2.2.4.9 POLICY_LSA_SERVER_ROLE_INFO
class POLICY_LSA_SERVER_ROLE_INFO(NDRSTRUCT):
    structure = (
        ('LsaServerRole', POLICY_LSA_SERVER_ROLE), 
    )

# 2.2.4.10 LSAPR_POLICY_REPLICA_SRCE_INFO
class LSAPR_POLICY_REPLICA_SRCE_INFO(NDRSTRUCT):
    structure = (
        ('ReplicaSource', RPC_UNICODE_STRING), 
        ('ReplicaAccountName', RPC_UNICODE_STRING), 
    )

# 2.2.4.11 POLICY_MODIFICATION_INFO
class POLICY_MODIFICATION_INFO(NDRSTRUCT):
    structure = (
        ('ModifiedId', LARGE_INTEGER), 
        ('DatabaseCreationTime', LARGE_INTEGER), 
    )

# 2.2.4.12 POLICY_AUDIT_FULL_SET_INFO
class POLICY_AUDIT_FULL_SET_INFO(NDRSTRUCT):
    structure = (
        ('ShutDownOnFull', UCHAR), 
    )

# 2.2.4.13 POLICY_AUDIT_FULL_QUERY_INFO
class POLICY_AUDIT_FULL_QUERY_INFO(NDRSTRUCT):
    structure = (
        ('ShutDownOnFull', UCHAR), 
        ('LogIsFull', UCHAR), 
    )

# 2.2.4.14 LSAPR_POLICY_DNS_DOMAIN_INFO
class LSAPR_POLICY_DNS_DOMAIN_INFO(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
        ('DnsDomainName', RPC_UNICODE_STRING), 
        ('DnsForestName', RPC_UNICODE_STRING), 
        ('DomainGuid', GUID), 
        ('Sid', PRPC_SID), 
    )

# 2.2.4.2 LSAPR_POLICY_INFORMATION
class LSAPR_POLICY_INFORMATION(NDRUNION):
    union = {
        POLICY_INFORMATION_CLASS.PolicyAuditLogInformation          : ('PolicyAuditLogInfo', POLICY_AUDIT_LOG_INFO),
        POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation       : ('PolicyAuditEventsInfo', LSAPR_POLICY_AUDIT_EVENTS_INFO),
        POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation     : ('PolicyPrimaryDomainInfo', LSAPR_POLICY_PRIMARY_DOM_INFO),
        POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation     : ('PolicyAccountDomainInfo', LSAPR_POLICY_ACCOUNT_DOM_INFO),
        POLICY_INFORMATION_CLASS.PolicyPdAccountInformation         : ('PolicyPdAccountInfo', LSAPR_POLICY_PD_ACCOUNT_INFO),
        POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation     : ('PolicyServerRoleInfo', POLICY_LSA_SERVER_ROLE_INFO),
        POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation     : ('PolicyReplicaSourceInfo', LSAPR_POLICY_REPLICA_SRCE_INFO),
        POLICY_INFORMATION_CLASS.PolicyModificationInformation      : ('PolicyModificationInfo', POLICY_MODIFICATION_INFO),
        POLICY_INFORMATION_CLASS.PolicyAuditFullSetInformation      : ('PolicyAuditFullSetInfo', POLICY_AUDIT_FULL_SET_INFO),
        POLICY_INFORMATION_CLASS.PolicyAuditFullQueryInformation    : ('PolicyAuditFullQueryInfo', POLICY_AUDIT_FULL_QUERY_INFO),
        POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation         : ('PolicyDnsDomainInfo', LSAPR_POLICY_DNS_DOMAIN_INFO),
        POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt      : ('PolicyDnsDomainInfoInt', LSAPR_POLICY_DNS_DOMAIN_INFO),
        POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation: ('PolicyLocalAccountDomainInfo', LSAPR_POLICY_ACCOUNT_DOM_INFO),
    }

class PLSAPR_POLICY_INFORMATION(NDRPOINTER):
    referent = (
       ('Data', LSAPR_POLICY_INFORMATION),
    )

# 2.2.4.15 POLICY_DOMAIN_INFORMATION_CLASS
class POLICY_DOMAIN_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        PolicyDomainQualityOfServiceInformation = 1
        PolicyDomainEfsInformation              = 2
        PolicyDomainKerberosTicketInformation   = 3

# 2.2.4.17 POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO
class POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO(NDRSTRUCT):
    structure = (
        ('QualityOfService', DWORD), 
    )

# 2.2.4.18 LSAPR_POLICY_DOMAIN_EFS_INFO
class LSAPR_POLICY_DOMAIN_EFS_INFO(NDRSTRUCT):
    structure = (
        ('InfoLength', DWORD), 
        ('EfsBlob', LPBYTE), 
    )

# 2.2.4.19 POLICY_DOMAIN_KERBEROS_TICKET_INFO
class POLICY_DOMAIN_KERBEROS_TICKET_INFO(NDRSTRUCT):
    structure = (
        ('AuthenticationOptions', DWORD), 
        ('MaxServiceTicketAge', LARGE_INTEGER), 
        ('MaxTicketAge', LARGE_INTEGER), 
        ('MaxRenewAge', LARGE_INTEGER), 
        ('MaxClockSkew', LARGE_INTEGER), 
        ('Reserved', LARGE_INTEGER), 
    )

# 2.2.4.16 LSAPR_POLICY_DOMAIN_INFORMATION
class LSAPR_POLICY_DOMAIN_INFORMATION(NDRUNION):
    union = {
        POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainQualityOfServiceInformation : ('PolicyDomainQualityOfServiceInfo', POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO ),
        POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainEfsInformation              : ('PolicyDomainEfsInfo', LSAPR_POLICY_DOMAIN_EFS_INFO),
        POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainKerberosTicketInformation   : ('PolicyDomainKerbTicketInfo', POLICY_DOMAIN_KERBEROS_TICKET_INFO),
    }

class PLSAPR_POLICY_DOMAIN_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', LSAPR_POLICY_DOMAIN_INFORMATION),
    )

# 2.2.4.20 POLICY_AUDIT_EVENT_TYPE
class POLICY_AUDIT_EVENT_TYPE(NDRENUM):
    class enumItems(Enum):
        AuditCategorySystem                 = 0
        AuditCategoryLogon                  = 1
        AuditCategoryObjectAccess           = 2
        AuditCategoryPrivilegeUse           = 3
        AuditCategoryDetailedTracking       = 4
        AuditCategoryPolicyChange           = 5
        AuditCategoryAccountManagement      = 6
        AuditCategoryDirectoryServiceAccess = 7
        AuditCategoryAccountLogon           = 8

# 2.2.5.1 LSAPR_ACCOUNT_INFORMATION
class LSAPR_ACCOUNT_INFORMATION(NDRSTRUCT):
    structure = (
        ('Sid', PRPC_SID), 
    )

# 2.2.5.2 LSAPR_ACCOUNT_ENUM_BUFFER
class LSAPR_ACCOUNT_INFORMATION_ARRAY(NDRUniConformantArray):
    item = LSAPR_ACCOUNT_INFORMATION

class PLSAPR_ACCOUNT_INFORMATION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_ACCOUNT_INFORMATION_ARRAY),
    )

class LSAPR_ACCOUNT_ENUM_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG), 
        ('Information', PLSAPR_ACCOUNT_INFORMATION_ARRAY), 
    )

# 2.2.5.3 LSAPR_USER_RIGHT_SET
class RPC_UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

class PRPC_UNICODE_STRING_ARRAY(NDRPOINTER):
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    )

class LSAPR_USER_RIGHT_SET(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG), 
        ('UserRights', PRPC_UNICODE_STRING_ARRAY), 
    )

# 2.2.5.4 LSAPR_LUID_AND_ATTRIBUTES
class LSAPR_LUID_AND_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Luid', LUID), 
        ('Attributes', ULONG), 
    )

# 2.2.5.5 LSAPR_PRIVILEGE_SET
class LSAPR_LUID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
    item = LSAPR_LUID_AND_ATTRIBUTES

class LSAPR_PRIVILEGE_SET(NDRSTRUCT):
    structure = (
        ('PrivilegeCount', ULONG), 
        ('Control', ULONG), 
        ('Privilege', LSAPR_LUID_AND_ATTRIBUTES_ARRAY), 
    )

class PLSAPR_PRIVILEGE_SET(NDRPOINTER):
    referent = (
        ('Data', LSAPR_PRIVILEGE_SET),
    )

# 2.2.6.1 LSAPR_CR_CIPHER_VALUE
class PCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantVaryingArray),
    )

class LSAPR_CR_CIPHER_VALUE(NDRSTRUCT):
    structure = (
        ('Length', LONG), 
        ('MaximumLength', LONG), 
        ('Buffer', PCHAR_ARRAY), 
    )

class PLSAPR_CR_CIPHER_VALUE(NDRPOINTER):
    referent = (
        ('Data', LSAPR_CR_CIPHER_VALUE), 
    )

class PPLSAPR_CR_CIPHER_VALUE(NDRPOINTER):
    referent = (
        ('Data', PLSAPR_CR_CIPHER_VALUE),
    )

# 2.2.7.1 LSAPR_TRUST_INFORMATION
class LSAPR_TRUST_INFORMATION(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
    )

# 2.2.7.2 TRUSTED_INFORMATION_CLASS
class TRUSTED_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        TrustedDomainNameInformation          = 1
        TrustedControllersInformation         = 2
        TrustedPosixOffsetInformation         = 3
        TrustedPasswordInformation            = 4
        TrustedDomainInformationBasic         = 5
        TrustedDomainInformationEx            = 6
        TrustedDomainAuthInformation          = 7
        TrustedDomainFullInformation          = 8
        TrustedDomainAuthInformationInternal  = 9
        TrustedDomainFullInformationInternal  = 10
        TrustedDomainInformationEx2Internal   = 11
        TrustedDomainFullInformation2Internal = 12
        TrustedDomainSupportedEncryptionTypes = 13

# 2.2.7.4 LSAPR_TRUSTED_DOMAIN_NAME_INFO
class LSAPR_TRUSTED_DOMAIN_NAME_INFO(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
    )

# 2.2.7.5 LSAPR_TRUSTED_CONTROLLERS_INFO
class LSAPR_TRUSTED_CONTROLLERS_INFO(NDRSTRUCT):
    structure = (
        ('Entries', ULONG), 
        ('Names', PRPC_UNICODE_STRING_ARRAY), 
    )

# 2.2.7.6 TRUSTED_POSIX_OFFSET_INFO
class TRUSTED_POSIX_OFFSET_INFO(NDRSTRUCT):
    structure = (
        ('Offset', ULONG), 
    )

# 2.2.7.7 LSAPR_TRUSTED_PASSWORD_INFO
class LSAPR_TRUSTED_PASSWORD_INFO(NDRSTRUCT):
    structure = (
        ('Password', PLSAPR_CR_CIPHER_VALUE), 
        ('OldPassword', PLSAPR_CR_CIPHER_VALUE), 
    )

# 2.2.7.8 LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC
LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC = LSAPR_TRUST_INFORMATION

# 2.2.7.9 LSAPR_TRUSTED_DOMAIN_INFORMATION_EX
class LSAPR_TRUSTED_DOMAIN_INFORMATION_EX(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
        ('FlatName', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
        ('TrustDirection', ULONG), 
        ('TrustType', ULONG), 
        ('TrustAttributes', ULONG), 
    )

# 2.2.7.10 LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2
class LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
        ('FlatName', RPC_UNICODE_STRING), 
        ('Sid', PRPC_SID), 
        ('TrustDirection', ULONG), 
        ('TrustType', ULONG), 
        ('TrustAttributes', ULONG), 
        ('ForestTrustLength', ULONG), 
        ('ForestTrustInfo', LPBYTE), 
    )

# 2.2.7.17 LSAPR_AUTH_INFORMATION
class LSAPR_AUTH_INFORMATION(NDRSTRUCT):
    structure = (
        ('LastUpdateTime', LARGE_INTEGER), 
        ('AuthType', ULONG), 
        ('AuthInfoLength', ULONG), 
        ('AuthInfo', LPBYTE), 
    )

class PLSAPR_AUTH_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', LSAPR_AUTH_INFORMATION),
    )

# 2.2.7.11 LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION
class LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION(NDRSTRUCT):
    structure = (
        ('IncomingAuthInfos', ULONG), 
        ('IncomingAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
        ('IncomingPreviousAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
        ('OutgoingAuthInfos', ULONG), 
        ('OutgoingAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
        ('OutgoingPreviousAuthenticationInformation', PLSAPR_AUTH_INFORMATION), 
    )

# 2.2.7.16 LSAPR_TRUSTED_DOMAIN_AUTH_BLOB
class LSAPR_TRUSTED_DOMAIN_AUTH_BLOB(NDRSTRUCT):
    structure = (
        ('AuthSize', ULONG), 
        ('AuthBlob', LPBYTE), 
    )

# 2.2.7.12 LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL
class LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL(NDRSTRUCT):
    structure = (
        ('AuthBlob', LSAPR_TRUSTED_DOMAIN_AUTH_BLOB), 
    )

# 2.2.7.13 LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION
class LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION(NDRSTRUCT):
    structure = (
        ('Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX), 
        ('PosixOffset', TRUSTED_POSIX_OFFSET_INFO), 
        ('AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION), 
    )

# 2.2.7.14 LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL
class LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL(NDRSTRUCT):
    structure = (
        ('Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX), 
        ('PosixOffset', TRUSTED_POSIX_OFFSET_INFO), 
        ('AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL), 
    )

# 2.2.7.15 LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2
class LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2(NDRSTRUCT):
    structure = (
        ('Information', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX), 
        ('PosixOffset', TRUSTED_POSIX_OFFSET_INFO), 
        ('AuthInformation', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION), 
    )

# 2.2.7.18 TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES
class TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES(NDRSTRUCT):
    structure = (
        ('SupportedEncryptionTypes', ULONG), 
    )

# 2.2.7.3 LSAPR_TRUSTED_DOMAIN_INFO
class LSAPR_TRUSTED_DOMAIN_INFO(NDRUNION):
    union = {
        TRUSTED_INFORMATION_CLASS.TrustedDomainNameInformation          : ('TrustedDomainNameInfo', LSAPR_TRUSTED_DOMAIN_NAME_INFO ),
        TRUSTED_INFORMATION_CLASS.TrustedControllersInformation         : ('TrustedControllersInfo', LSAPR_TRUSTED_CONTROLLERS_INFO),
        TRUSTED_INFORMATION_CLASS.TrustedPosixOffsetInformation         : ('TrustedPosixOffsetInfo', TRUSTED_POSIX_OFFSET_INFO),
        TRUSTED_INFORMATION_CLASS.TrustedPasswordInformation            : ('TrustedPasswordInfo', LSAPR_TRUSTED_PASSWORD_INFO ),
        TRUSTED_INFORMATION_CLASS.TrustedDomainInformationBasic         : ('TrustedDomainInfoBasic', LSAPR_TRUSTED_DOMAIN_INFORMATION_BASIC),
        TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx            : ('TrustedDomainInfoEx', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX),
        TRUSTED_INFORMATION_CLASS.TrustedDomainAuthInformation          : ('TrustedAuthInfo', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION),
        TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation          : ('TrustedFullInfo', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION),
        TRUSTED_INFORMATION_CLASS.TrustedDomainAuthInformationInternal  : ('TrustedAuthInfoInternal', LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION_INTERNAL),
        TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformationInternal  : ('TrustedFullInfoInternal', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION_INTERNAL),
        TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx2Internal   : ('TrustedDomainInfoEx2', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX2),
        TRUSTED_INFORMATION_CLASS.TrustedDomainFullInformation2Internal : ('TrustedFullInfo2', LSAPR_TRUSTED_DOMAIN_FULL_INFORMATION2),
        TRUSTED_INFORMATION_CLASS.TrustedDomainSupportedEncryptionTypes : ('TrustedDomainSETs', TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES),
    }

# 2.2.7.19 LSAPR_TRUSTED_ENUM_BUFFER
class LSAPR_TRUST_INFORMATION_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRUST_INFORMATION

class PLSAPR_TRUST_INFORMATION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_TRUST_INFORMATION_ARRAY),
    )

class LSAPR_TRUSTED_ENUM_BUFFER(NDRSTRUCT):
    structure = (
        ('Entries', ULONG), 
        ('Information', PLSAPR_TRUST_INFORMATION_ARRAY), 
    )

# 2.2.7.20 LSAPR_TRUSTED_ENUM_BUFFER_EX
class LSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRUSTED_DOMAIN_INFORMATION_EX

class PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY),
    )

class LSAPR_TRUSTED_ENUM_BUFFER_EX(NDRSTRUCT):
    structure = (
        ('Entries', ULONG), 
        ('EnumerationBuffer', PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX_ARRAY), 
    )

# 2.2.7.22 LSA_FOREST_TRUST_RECORD_TYPE
class LSA_FOREST_TRUST_RECORD_TYPE(NDRENUM):
    class enumItems(Enum):
        ForestTrustTopLevelName   = 0
        ForestTrustTopLevelNameEx = 1
        ForestTrustDomainInfo     = 2

# 2.2.7.24 LSA_FOREST_TRUST_DOMAIN_INFO
class LSA_FOREST_TRUST_DOMAIN_INFO(NDRSTRUCT):
    structure = (
        ('Sid', PRPC_SID), 
        ('DnsName', LSA_UNICODE_STRING), 
        ('NetbiosName', LSA_UNICODE_STRING), 
    )

# 2.2.7.21 LSA_FOREST_TRUST_RECORD
class LSA_FOREST_TRUST_DATA_UNION(NDRUNION):
    union = {
        LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelName   : ('TopLevelName', LSA_UNICODE_STRING ),
        LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelNameEx : ('TopLevelName', LSA_UNICODE_STRING),
        LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustDomainInfo     : ('DomainInfo', LSA_FOREST_TRUST_DOMAIN_INFO),
    }

class LSA_FOREST_TRUST_RECORD(NDRSTRUCT):
    structure = (
        ('Flags', ULONG), 
        ('ForestTrustType', LSA_FOREST_TRUST_RECORD_TYPE), 
        ('Time', LARGE_INTEGER), 
        ('ForestTrustData', LSA_FOREST_TRUST_DATA_UNION), 
    )

class PLSA_FOREST_TRUST_RECORD(NDRPOINTER):
    referent = (
        ('Data', LSA_FOREST_TRUST_RECORD),
    )

# 2.2.7.23 LSA_FOREST_TRUST_BINARY_DATA
class LSA_FOREST_TRUST_BINARY_DATA(NDRSTRUCT):
    structure = (
        ('Length', ULONG), 
        ('Buffer', LPBYTE), 
    )

# 2.2.7.25 LSA_FOREST_TRUST_INFORMATION
class LSA_FOREST_TRUST_RECORD_ARRAY(NDRUniConformantArray):
    item = PLSA_FOREST_TRUST_RECORD

class PLSA_FOREST_TRUST_RECORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSA_FOREST_TRUST_RECORD_ARRAY),
    )

class LSA_FOREST_TRUST_INFORMATION(NDRSTRUCT):
    structure = (
        ('RecordCount', ULONG), 
        ('Entries', PLSA_FOREST_TRUST_RECORD_ARRAY), 
    )

class PLSA_FOREST_TRUST_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', LSA_FOREST_TRUST_INFORMATION),
    )

# 2.2.7.26 LSA_FOREST_TRUST_COLLISION_RECORD_TYPE
class LSA_FOREST_TRUST_COLLISION_RECORD_TYPE(NDRENUM):
    class enumItems(Enum):
        CollisionTdo   = 0
        CollisionXref  = 1
        CollisionOther = 2

# 2.2.7.27 LSA_FOREST_TRUST_COLLISION_RECORD
class LSA_FOREST_TRUST_COLLISION_RECORD(NDRSTRUCT):
    structure = (
        ('Index', ULONG), 
        ('Type', LSA_FOREST_TRUST_COLLISION_RECORD_TYPE), 
        ('Flags', ULONG), 
        ('Name', LSA_UNICODE_STRING), 
    )

# 2.2.8.1 LSAPR_POLICY_PRIVILEGE_DEF
class LSAPR_POLICY_PRIVILEGE_DEF(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING), 
        ('LocalValue', LUID), 
    )

# 2.2.8.2 LSAPR_PRIVILEGE_ENUM_BUFFER
class LSAPR_POLICY_PRIVILEGE_DEF_ARRAY(NDRUniConformantArray):
    item = LSAPR_POLICY_PRIVILEGE_DEF

class PLSAPR_POLICY_PRIVILEGE_DEF_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_POLICY_PRIVILEGE_DEF_ARRAY),
    )

class LSAPR_PRIVILEGE_ENUM_BUFFER(NDRSTRUCT):
    structure = (
        ('Entries', ULONG), 
        ('Privileges', PLSAPR_POLICY_PRIVILEGE_DEF_ARRAY), 
    )


################################################################################
# RPC CALLS
################################################################################
# 3.1.4.4.1 LsarOpenPolicy2 (Opnum 44)
class LsarOpenPolicy2(NDRCALL):
    opnum = 44
    structure = (
       ('SystemName', LPWSTR),
       ('ObjectAttributes',LSAPR_OBJECT_ATTRIBUTES),
       ('DesiredAccess',ACCESS_MASK),
    )

class LsarOpenPolicy2Response(NDRCALL):
    structure = (
       ('PolicyHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.2 LsarOpenPolicy (Opnum 6)
class LsarOpenPolicy(NDRCALL):
    opnum = 6
    structure = (
       ('SystemName', LPWSTR),
       ('ObjectAttributes',LSAPR_OBJECT_ATTRIBUTES),
       ('DesiredAccess',ACCESS_MASK),
    )

class LsarOpenPolicyResponse(NDRCALL):
    structure = (
       ('PolicyHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.3 LsarQueryInformationPolicy2 (Opnum 46)
class LsarQueryInformationPolicy2(NDRCALL):
    opnum = 46
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
    )

class LsarQueryInformationPolicy2Response(NDRCALL):
    structure = (
       ('PolicyInformation',PLSAPR_POLICY_INFORMATION),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.4 LsarQueryInformationPolicy (Opnum 7)
class LsarQueryInformationPolicy(NDRCALL):
    opnum = 7
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
    )

class LsarQueryInformationPolicyResponse(NDRCALL):
    structure = (
       ('PolicyInformation',PLSAPR_POLICY_INFORMATION),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.5 LsarSetInformationPolicy2 (Opnum 47)
class LsarSetInformationPolicy2(NDRCALL):
    opnum = 47
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
       ('PolicyInformation',LSAPR_POLICY_INFORMATION),
    )

class LsarSetInformationPolicy2Response(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.6 LsarSetInformationPolicy (Opnum 8)
class LsarSetInformationPolicy(NDRCALL):
    opnum = 8
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_INFORMATION_CLASS),
       ('PolicyInformation',LSAPR_POLICY_INFORMATION),
    )

class LsarSetInformationPolicyResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.7 LsarQueryDomainInformationPolicy (Opnum 53)
class LsarQueryDomainInformationPolicy(NDRCALL):
    opnum = 53
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('InformationClass',POLICY_DOMAIN_INFORMATION_CLASS),
    )

class LsarQueryDomainInformationPolicyResponse(NDRCALL):
    structure = (
       ('PolicyDomainInformation',PLSAPR_POLICY_DOMAIN_INFORMATION),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.4.8 LsarSetDomainInformationPolicy (Opnum 54)
# 3.1.4.5.1 LsarCreateAccount (Opnum 10)
class LsarCreateAccount(NDRCALL):
    opnum = 10
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid',RPC_SID),
       ('DesiredAccess',ACCESS_MASK),
    )

class LsarCreateAccountResponse(NDRCALL):
    structure = (
       ('AccountHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.2 LsarEnumerateAccounts (Opnum 11)
class LsarEnumerateAccounts(NDRCALL):
    opnum = 11
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext',ULONG),
       ('PreferedMaximumLength',ULONG),
    )

class LsarEnumerateAccountsResponse(NDRCALL):
    structure = (
       ('EnumerationContext',ULONG),
       ('EnumerationBuffer',LSAPR_ACCOUNT_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.3 LsarOpenAccount (Opnum 17)
class LsarOpenAccount(NDRCALL):
    opnum = 17
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid',RPC_SID),
       ('DesiredAccess',ACCESS_MASK),
    )

class LsarOpenAccountResponse(NDRCALL):
    structure = (
       ('AccountHandle',LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.4 LsarEnumeratePrivilegesAccount (Opnum 18)
class LsarEnumeratePrivilegesAccount(NDRCALL):
    opnum = 18
    structure = (
       ('AccountHandle', LSAPR_HANDLE),
    )

class LsarEnumeratePrivilegesAccountResponse(NDRCALL):
    structure = (
       ('Privileges',PLSAPR_PRIVILEGE_SET),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.5 LsarAddPrivilegesToAccount (Opnum 19)
class LsarAddPrivilegesToAccount(NDRCALL):
    opnum = 19
    structure = (
       ('AccountHandle', LSAPR_HANDLE),
       ('Privileges', LSAPR_PRIVILEGE_SET),
    )

class LsarAddPrivilegesToAccountResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.6 LsarRemovePrivilegesFromAccount (Opnum 20)
class LsarRemovePrivilegesFromAccount(NDRCALL):
    opnum = 20
    structure = (
       ('AccountHandle', LSAPR_HANDLE),
       ('AllPrivileges', UCHAR),
       ('Privileges', PLSAPR_PRIVILEGE_SET),
    )

class LsarRemovePrivilegesFromAccountResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.7 LsarGetSystemAccessAccount (Opnum 23)
class LsarGetSystemAccessAccount(NDRCALL):
    opnum = 23
    structure = (
       ('AccountHandle', LSAPR_HANDLE),
    )

class LsarGetSystemAccessAccountResponse(NDRCALL):
    structure = (
       ('SystemAccess', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.8 LsarSetSystemAccessAccount (Opnum 24)
class LsarSetSystemAccessAccount(NDRCALL):
    opnum = 24
    structure = (
       ('AccountHandle', LSAPR_HANDLE),
       ('SystemAccess', ULONG),
    )

class LsarSetSystemAccessAccountResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.9 LsarEnumerateAccountsWithUserRight (Opnum 35)
class LsarEnumerateAccountsWithUserRight(NDRCALL):
    opnum = 35
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('UserRight', PRPC_UNICODE_STRING),
    )

class LsarEnumerateAccountsWithUserRightResponse(NDRCALL):
    structure = (
       ('EnumerationBuffer',LSAPR_ACCOUNT_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.10 LsarEnumerateAccountRights (Opnum 36)
class LsarEnumerateAccountRights(NDRCALL):
    opnum = 36
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid', RPC_SID),
    )

class LsarEnumerateAccountRightsResponse(NDRCALL):
    structure = (
       ('UserRights',LSAPR_USER_RIGHT_SET),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.11 LsarAddAccountRights (Opnum 37)
class LsarAddAccountRights(NDRCALL):
    opnum = 37
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid', RPC_SID),
       ('UserRights',LSAPR_USER_RIGHT_SET),
    )

class LsarAddAccountRightsResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5.12 LsarRemoveAccountRights (Opnum 38)
class LsarRemoveAccountRights(NDRCALL):
    opnum = 38
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('AccountSid', RPC_SID),
       ('AllRights', UCHAR),
       ('UserRights',LSAPR_USER_RIGHT_SET),
    )

class LsarRemoveAccountRightsResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6.1 LsarCreateSecret (Opnum 16)
class LsarCreateSecret(NDRCALL):
    opnum = 16
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecretName', RPC_UNICODE_STRING),
       ('DesiredAccess', ACCESS_MASK),
    )

class LsarCreateSecretResponse(NDRCALL):
    structure = (
       ('SecretHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6.2 LsarOpenSecret (Opnum 28)
class LsarOpenSecret(NDRCALL):
    opnum = 28
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecretName', RPC_UNICODE_STRING),
       ('DesiredAccess', ACCESS_MASK),
    )

class LsarOpenSecretResponse(NDRCALL):
    structure = (
       ('SecretHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6.3 LsarSetSecret (Opnum 29)
class LsarSetSecret(NDRCALL):
    opnum = 29
    structure = (
       ('SecretHandle', LSAPR_HANDLE),
       ('EncryptedCurrentValue', PLSAPR_CR_CIPHER_VALUE),
       ('EncryptedOldValue', PLSAPR_CR_CIPHER_VALUE),
    )

class LsarSetSecretResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6.4 LsarQuerySecret (Opnum 30)
class LsarQuerySecret(NDRCALL):
    opnum = 30
    structure = (
       ('SecretHandle', LSAPR_HANDLE),
       ('EncryptedCurrentValue', PPLSAPR_CR_CIPHER_VALUE),
       ('CurrentValueSetTime', PLARGE_INTEGER),
       ('EncryptedOldValue', PPLSAPR_CR_CIPHER_VALUE),
       ('OldValueSetTime', PLARGE_INTEGER),
    )

class LsarQuerySecretResponse(NDRCALL):
    structure = (
       ('EncryptedCurrentValue', PPLSAPR_CR_CIPHER_VALUE),
       ('CurrentValueSetTime', PLARGE_INTEGER),
       ('EncryptedOldValue', PPLSAPR_CR_CIPHER_VALUE),
       ('OldValueSetTime', PLARGE_INTEGER),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6.5 LsarStorePrivateData (Opnum 42)
class LsarStorePrivateData(NDRCALL):
    opnum = 42
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('KeyName', RPC_UNICODE_STRING),
       ('EncryptedData', PLSAPR_CR_CIPHER_VALUE),
    )

class LsarStorePrivateDataResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6.6 LsarRetrievePrivateData (Opnum 43)
class LsarRetrievePrivateData(NDRCALL):
    opnum = 43
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('KeyName', RPC_UNICODE_STRING),
       ('EncryptedData', PLSAPR_CR_CIPHER_VALUE),
    )

class LsarRetrievePrivateDataResponse(NDRCALL):
    structure = (
       ('EncryptedData', PLSAPR_CR_CIPHER_VALUE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.7.1 LsarOpenTrustedDomain (Opnum 25)
# 3.1.4.7.1 LsarQueryInfoTrustedDomain (Opnum 26)
# 3.1.4.7.2 LsarQueryTrustedDomainInfo (Opnum 39)
# 3.1.4.7.3 LsarSetTrustedDomainInfo (Opnum 40)
# 3.1.4.7.4 LsarDeleteTrustedDomain (Opnum 41)
# 3.1.4.7.5 LsarQueryTrustedDomainInfoByName (Opnum 48)
# 3.1.4.7.6 LsarSetTrustedDomainInfoByName (Opnum 49)
# 3.1.4.7.7 LsarEnumerateTrustedDomainsEx (Opnum 50)
class LsarEnumerateTrustedDomainsEx(NDRCALL):
    opnum = 50
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class LsarEnumerateTrustedDomainsExResponse(NDRCALL):
    structure = (
       ('EnumerationContext', ULONG),
       ('EnumerationBuffer',LSAPR_TRUSTED_ENUM_BUFFER_EX),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.7.8 LsarEnumerateTrustedDomains (Opnum 13)
class LsarEnumerateTrustedDomains(NDRCALL):
    opnum = 13
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class LsarEnumerateTrustedDomainsResponse(NDRCALL):
    structure = (
       ('EnumerationContext', ULONG),
       ('EnumerationBuffer',LSAPR_TRUSTED_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.7.9 LsarOpenTrustedDomainByName (Opnum 55)
# 3.1.4.7.10 LsarCreateTrustedDomainEx2 (Opnum 59)
# 3.1.4.7.11 LsarCreateTrustedDomainEx (Opnum 51)
# 3.1.4.7.12 LsarCreateTrustedDomain (Opnum 12)
# 3.1.4.7.14 LsarSetInformationTrustedDomain (Opnum 27)
# 3.1.4.7.15 LsarQueryForestTrustInformation (Opnum 73)
class LsarQueryForestTrustInformation(NDRCALL):
    opnum = 73
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('TrustedDomainName', LSA_UNICODE_STRING),
       ('HighestRecordType', LSA_FOREST_TRUST_RECORD_TYPE),
    )

class LsarQueryForestTrustInformationResponse(NDRCALL):
    structure = (
       ('ForestTrustInfo', PLSA_FOREST_TRUST_INFORMATION),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.7.16 LsarSetForestTrustInformation (Opnum 74)

# 3.1.4.8.1 LsarEnumeratePrivileges (Opnum 2)
class LsarEnumeratePrivileges(NDRCALL):
    opnum = 2
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class LsarEnumeratePrivilegesResponse(NDRCALL):
    structure = (
       ('EnumerationContext', ULONG),
       ('EnumerationBuffer', LSAPR_PRIVILEGE_ENUM_BUFFER),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.8.2 LsarLookupPrivilegeValue (Opnum 31)
class LsarLookupPrivilegeValue(NDRCALL):
    opnum = 31
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
    )

class LsarLookupPrivilegeValueResponse(NDRCALL):
    structure = (
       ('Value', LUID),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.8.3 LsarLookupPrivilegeName (Opnum 32)
class LsarLookupPrivilegeName(NDRCALL):
    opnum = 32
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Value', LUID),
    )

class LsarLookupPrivilegeNameResponse(NDRCALL):
    structure = (
       ('Name', PRPC_UNICODE_STRING),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.8.4 LsarLookupPrivilegeDisplayName (Opnum 33)
class LsarLookupPrivilegeDisplayName(NDRCALL):
    opnum = 33
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('ClientLanguage', USHORT),
       ('ClientSystemDefaultLanguage', USHORT),
    )

class LsarLookupPrivilegeDisplayNameResponse(NDRCALL):
    structure = (
       ('Name', PRPC_UNICODE_STRING),
       ('LanguageReturned', UCHAR),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.9.1 LsarQuerySecurityObject (Opnum 3)
class LsarQuerySecurityObject(NDRCALL):
    opnum = 3
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
    )

class LsarQuerySecurityObjectResponse(NDRCALL):
    structure = (
       ('SecurityDescriptor', PLSAPR_SR_SECURITY_DESCRIPTOR),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.9.2 LsarSetSecurityObject (Opnum 4)
class LsarSetSecurityObject(NDRCALL):
    opnum = 4
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('SecurityDescriptor', LSAPR_SR_SECURITY_DESCRIPTOR),
    )

class LsarSetSecurityObjectResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.9.3 LsarDeleteObject (Opnum 34)
class LsarDeleteObject(NDRCALL):
    opnum = 34
    structure = (
       ('ObjectHandle', LSAPR_HANDLE),
    )

class LsarDeleteObjectResponse(NDRCALL):
    structure = (
       ('ObjectHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.9.4 LsarClose (Opnum 0)
class LsarClose(NDRCALL):
    opnum = 0
    structure = (
       ('ObjectHandle', LSAPR_HANDLE),
    )

class LsarCloseResponse(NDRCALL):
    structure = (
       ('ObjectHandle', LSAPR_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (LsarClose, LsarCloseResponse),
 2 : (LsarEnumeratePrivileges, LsarEnumeratePrivilegesResponse),
 3 : (LsarQuerySecurityObject, LsarQuerySecurityObjectResponse),
 4 : (LsarSetSecurityObject, LsarSetSecurityObjectResponse),
 6 : (LsarOpenPolicy, LsarOpenPolicyResponse),
 7 : (LsarQueryInformationPolicy, LsarQueryInformationPolicyResponse),
 8 : (LsarSetInformationPolicy, LsarSetInformationPolicyResponse),
10 : (LsarCreateAccount, LsarCreateAccountResponse),
11 : (LsarEnumerateAccounts, LsarEnumerateAccountsResponse),
#12 : (LsarCreateTrustedDomain, LsarCreateTrustedDomainResponse),
13 : (LsarEnumerateTrustedDomains, LsarEnumerateTrustedDomainsResponse),
16 : (LsarCreateSecret, LsarCreateSecretResponse),
17 : (LsarOpenAccount, LsarOpenAccountResponse),
18 : (LsarEnumeratePrivilegesAccount, LsarEnumeratePrivilegesAccountResponse),
19 : (LsarAddPrivilegesToAccount, LsarAddPrivilegesToAccountResponse),
20 : (LsarRemovePrivilegesFromAccount, LsarRemovePrivilegesFromAccountResponse),
23 : (LsarGetSystemAccessAccount, LsarGetSystemAccessAccountResponse),
24 : (LsarSetSystemAccessAccount, LsarSetSystemAccessAccountResponse),
#25 : (LsarOpenTrustedDomain, LsarOpenTrustedDomainResponse),
#26 : (LsarQueryInfoTrustedDomain, LsarQueryInfoTrustedDomainResponse),
#27 : (LsarSetInformationTrustedDomain, LsarSetInformationTrustedDomainResponse),
28 : (LsarOpenSecret, LsarOpenSecretResponse),
29 : (LsarSetSecret, LsarSetSecretResponse),
30 : (LsarQuerySecret, LsarQuerySecretResponse),
31 : (LsarLookupPrivilegeValue, LsarLookupPrivilegeValueResponse),
32 : (LsarLookupPrivilegeName, LsarLookupPrivilegeNameResponse),
33 : (LsarLookupPrivilegeDisplayName, LsarLookupPrivilegeDisplayNameResponse),
34 : (LsarDeleteObject, LsarDeleteObjectResponse),
35 : (LsarEnumerateAccountsWithUserRight, LsarEnumerateAccountsWithUserRightResponse),
36 : (LsarEnumerateAccountRights, LsarEnumerateAccountRightsResponse),
37 : (LsarAddAccountRights, LsarAddAccountRightsResponse),
38 : (LsarRemoveAccountRights, LsarRemoveAccountRightsResponse),
#39 : (LsarQueryTrustedDomainInfo, LsarQueryTrustedDomainInfoResponse),
#40 : (LsarSetTrustedDomainInfo, LsarSetTrustedDomainInfoResponse),
#41 : (LsarDeleteTrustedDomain, LsarDeleteTrustedDomainResponse),
42 : (LsarStorePrivateData, LsarStorePrivateDataResponse),
43 : (LsarRetrievePrivateData, LsarRetrievePrivateDataResponse),
44 : (LsarOpenPolicy2, LsarOpenPolicy2Response),
46 : (LsarQueryInformationPolicy2, LsarQueryInformationPolicy2Response),
47 : (LsarSetInformationPolicy2, LsarSetInformationPolicy2Response),
#48 : (LsarQueryTrustedDomainInfoByName, LsarQueryTrustedDomainInfoByNameResponse),
#49 : (LsarSetTrustedDomainInfoByName, LsarSetTrustedDomainInfoByNameResponse),
50 : (LsarEnumerateTrustedDomainsEx, LsarEnumerateTrustedDomainsExResponse),
#51 : (LsarCreateTrustedDomainEx, LsarCreateTrustedDomainExResponse),
53 : (LsarQueryDomainInformationPolicy, LsarQueryDomainInformationPolicyResponse),
#54 : (LsarSetDomainInformationPolicy, LsarSetDomainInformationPolicyResponse),
#55 : (LsarOpenTrustedDomainByName, LsarOpenTrustedDomainByNameResponse),
#59 : (LsarCreateTrustedDomainEx2, LsarCreateTrustedDomainEx2Response),
#73 : (LsarQueryForestTrustInformation, LsarQueryForestTrustInformationResponse),
#74 : (LsarSetForestTrustInformation, LsarSetForestTrustInformationResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hLsarOpenPolicy2(dce, desiredAccess = MAXIMUM_ALLOWED):
    request = LsarOpenPolicy2()
    request['SystemName'] = NULL
    request['ObjectAttributes']['RootDirectory'] = NULL
    request['ObjectAttributes']['ObjectName'] = NULL
    request['ObjectAttributes']['SecurityDescriptor'] = NULL
    request['ObjectAttributes']['SecurityQualityOfService'] = NULL
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hLsarOpenPolicy(dce, desiredAccess = MAXIMUM_ALLOWED):
    request = LsarOpenPolicy()
    request['SystemName'] = NULL
    request['ObjectAttributes']['RootDirectory'] = NULL
    request['ObjectAttributes']['ObjectName'] = NULL
    request['ObjectAttributes']['SecurityDescriptor'] = NULL
    request['ObjectAttributes']['SecurityQualityOfService'] = NULL
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hLsarQueryInformationPolicy2(dce, policyHandle, informationClass):
    request = LsarQueryInformationPolicy2()
    request['PolicyHandle'] = policyHandle
    request['InformationClass'] = informationClass
    return dce.request(request)

def hLsarQueryInformationPolicy(dce, policyHandle, informationClass):
    request = LsarQueryInformationPolicy()
    request['PolicyHandle'] = policyHandle
    request['InformationClass'] = informationClass
    return dce.request(request)

def hLsarQueryDomainInformationPolicy(dce, policyHandle, informationClass):
    request = LsarQueryInformationPolicy()
    request['PolicyHandle'] = policyHandle
    request['InformationClass'] = informationClass
    return dce.request(request)

def hLsarEnumerateAccounts(dce, policyHandle, preferedMaximumLength=0xffffffff):
    request = LsarEnumerateAccounts()
    request['PolicyHandle'] = policyHandle
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hLsarEnumerateAccountsWithUserRight(dce, policyHandle, UserRight):
    request = LsarEnumerateAccountsWithUserRight()
    request['PolicyHandle'] = policyHandle
    request['UserRight'] = UserRight
    return dce.request(request)

def hLsarEnumerateTrustedDomainsEx(dce, policyHandle, enumerationContext=0, preferedMaximumLength=0xffffffff):
    request = LsarEnumerateTrustedDomainsEx()
    request['PolicyHandle'] = policyHandle
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hLsarEnumerateTrustedDomains(dce, policyHandle, enumerationContext=0, preferedMaximumLength=0xffffffff):
    request = LsarEnumerateTrustedDomains()
    request['PolicyHandle'] = policyHandle
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hLsarOpenAccount(dce, policyHandle, accountSid, desiredAccess=MAXIMUM_ALLOWED):
    request = LsarOpenAccount()
    request['PolicyHandle'] = policyHandle
    request['AccountSid'].fromCanonical(accountSid)
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hLsarClose(dce, objectHandle):
    request = LsarClose()
    request['ObjectHandle'] = objectHandle
    return dce.request(request)

def hLsarCreateAccount(dce, policyHandle, accountSid, desiredAccess=MAXIMUM_ALLOWED):
    request = LsarCreateAccount()
    request['PolicyHandle'] = policyHandle
    request['AccountSid'].fromCanonical(accountSid)
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hLsarDeleteObject(dce, objectHandle):
    request = LsarDeleteObject()
    request['ObjectHandle'] = objectHandle
    return dce.request(request)

def hLsarEnumeratePrivilegesAccount(dce, accountHandle):
    request = LsarEnumeratePrivilegesAccount()
    request['AccountHandle'] = accountHandle
    return dce.request(request)

def hLsarGetSystemAccessAccount(dce, accountHandle):
    request = LsarGetSystemAccessAccount()
    request['AccountHandle'] = accountHandle
    return dce.request(request)

def hLsarSetSystemAccessAccount(dce, accountHandle, systemAccess):
    request = LsarSetSystemAccessAccount()
    request['AccountHandle'] = accountHandle
    request['SystemAccess'] = systemAccess
    return dce.request(request)

def hLsarAddPrivilegesToAccount(dce, accountHandle, privileges):
    request = LsarAddPrivilegesToAccount()
    request['AccountHandle'] = accountHandle
    request['Privileges']['PrivilegeCount'] = len(privileges)
    request['Privileges']['Control'] = 0
    for priv in privileges:
        request['Privileges']['Privilege'].append(priv)

    return dce.request(request)

def hLsarRemovePrivilegesFromAccount(dce, accountHandle, privileges, allPrivileges = False):
    request = LsarRemovePrivilegesFromAccount()
    request['AccountHandle'] = accountHandle
    request['Privileges']['Control'] = 0
    if privileges != NULL:
        request['Privileges']['PrivilegeCount'] = len(privileges)
        for priv in privileges:
            request['Privileges']['Privilege'].append(priv)
    else:
        request['Privileges']['PrivilegeCount'] = NULL
    request['AllPrivileges'] = allPrivileges

    return dce.request(request)

def hLsarEnumerateAccountRights(dce, policyHandle, accountSid):
    request = LsarEnumerateAccountRights()
    request['PolicyHandle'] = policyHandle
    request['AccountSid'].fromCanonical(accountSid)
    return dce.request(request)

def hLsarAddAccountRights(dce, policyHandle, accountSid, userRights):
    request = LsarAddAccountRights()
    request['PolicyHandle'] = policyHandle
    request['AccountSid'].fromCanonical(accountSid)
    request['UserRights']['EntriesRead'] = len(userRights)
    for userRight in userRights:
        right = RPC_UNICODE_STRING()
        right['Data'] = userRight
        request['UserRights']['UserRights'].append(right)

    return dce.request(request)

def hLsarRemoveAccountRights(dce, policyHandle, accountSid, userRights):
    request = LsarRemoveAccountRights()
    request['PolicyHandle'] = policyHandle
    request['AccountSid'].fromCanonical(accountSid)
    request['UserRights']['EntriesRead'] = len(userRights)
    for userRight in userRights:
        right = RPC_UNICODE_STRING()
        right['Data'] = userRight
        request['UserRights']['UserRights'].append(right)

    return dce.request(request)

def hLsarCreateSecret(dce, policyHandle, secretName, desiredAccess=MAXIMUM_ALLOWED):
    request = LsarCreateSecret()
    request['PolicyHandle'] = policyHandle
    request['SecretName'] = secretName
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hLsarOpenSecret(dce, policyHandle, secretName, desiredAccess=MAXIMUM_ALLOWED):
    request = LsarOpenSecret()
    request['PolicyHandle'] = policyHandle
    request['SecretName'] = secretName
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hLsarSetSecret(dce, secretHandle, encryptedCurrentValue, encryptedOldValue):
    request = LsarOpenSecret()
    request['SecretHandle'] = secretHandle
    if encryptedCurrentValue != NULL:
        request['EncryptedCurrentValue']['Length'] = len(encryptedCurrentValue)
        request['EncryptedCurrentValue']['MaximumLength'] = len(encryptedCurrentValue)
        request['EncryptedCurrentValue']['Buffer'] = list(encryptedCurrentValue)
    if encryptedOldValue != NULL:
        request['EncryptedOldValue']['Length'] = len(encryptedOldValue)
        request['EncryptedOldValue']['MaximumLength'] = len(encryptedOldValue)
        request['EncryptedOldValue']['Buffer'] = list(encryptedOldValue)
    return dce.request(request)

def hLsarQuerySecret(dce, secretHandle):
    request = LsarQuerySecret()
    request['SecretHandle'] = secretHandle
    request['EncryptedCurrentValue']['Buffer'] = NULL
    request['EncryptedOldValue']['Buffer'] = NULL
    request['OldValueSetTime'] = NULL
    return dce.request(request)

def hLsarRetrievePrivateData(dce, policyHandle, keyName):
    request = LsarRetrievePrivateData()
    request['PolicyHandle'] = policyHandle
    request['KeyName'] = keyName
    retVal = dce.request(request)
    return ''.join(retVal['EncryptedData']['Buffer'])

def hLsarStorePrivateData(dce, policyHandle, keyName, encryptedData):
    request = LsarStorePrivateData()
    request['PolicyHandle'] = policyHandle
    request['KeyName'] = keyName
    if encryptedData != NULL:
        request['EncryptedData']['Length'] = len(encryptedData)
        request['EncryptedData']['MaximumLength'] = len(encryptedData)
        request['EncryptedData']['Buffer'] = list(encryptedData)
    else:
        request['EncryptedData'] = NULL
    return dce.request(request)

def hLsarEnumeratePrivileges(dce, policyHandle, enumerationContext = 0, preferedMaximumLength = 0xffffffff):
    request = LsarEnumeratePrivileges()
    request['PolicyHandle'] = policyHandle
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hLsarLookupPrivilegeValue(dce, policyHandle, name):
    request = LsarLookupPrivilegeValue()
    request['PolicyHandle'] = policyHandle
    request['Name'] = name
    return dce.request(request)

def hLsarLookupPrivilegeName(dce, policyHandle, luid):
    request = LsarLookupPrivilegeName()
    request['PolicyHandle'] = policyHandle
    request['Value'] = luid
    return dce.request(request)

def hLsarQuerySecurityObject(dce, policyHandle, securityInformation = OWNER_SECURITY_INFORMATION):
    request = LsarQuerySecurityObject()
    request['PolicyHandle'] = policyHandle
    request['SecurityInformation'] = securityInformation
    retVal =  dce.request(request)
    return ''.join(retVal['SecurityDescriptor']['SecurityDescriptor'])

def hLsarSetSecurityObject(dce, policyHandle, securityInformation, securityDescriptor):
    request = LsarSetSecurityObject()
    request['PolicyHandle'] = policyHandle
    request['SecurityInformation'] = securityInformation
    request['SecurityDescriptor']['Length'] = len(securityDescriptor)
    request['SecurityDescriptor']['SecurityDescriptor'] = list(securityDescriptor)
    return dce.request(request)

def hLsarSetInformationPolicy2(dce, policyHandle, informationClass, policyInformation):
    request = LsarSetInformationPolicy2()
    request['PolicyHandle'] = policyHandle
    request['InformationClass'] = informationClass
    request['PolicyInformation'] = policyInformation
    return dce.request(request)

def hLsarSetInformationPolicy(dce, policyHandle, informationClass, policyInformation):
    request = LsarSetInformationPolicy()
    request['PolicyHandle'] = policyHandle
    request['InformationClass'] = informationClass
    request['PolicyInformation'] = policyInformation
    return dce.request(request)

