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
#   [MS-SAMR] Interface implementation
#

from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.ndr import NDRCall, NDR, NDRLONG, NDRUnion, NDRPointer, NDRUniConformantArray, NDRUniConformantVaryingArray, NDRENUM, NDRSHORT, NDRSMALL
from impacket.dcerpc.v5.dtypes import *
from impacket import nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum

MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))

class DCERPCSessionError(Exception):
    def __init__( self, packet = None, error_code = None):
        Exception.__init__(self)
        self.packet = packet
        if packet is not None:
            self.error_code = packet['ErrorCode']
        else:
            self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code
 
    def get_packet( self ):
        return self.packet

    def __str__( self ):
        key = self.error_code
        if (nt_errors.ERROR_MESSAGES.has_key(key)):
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'SAMR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SAMR SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# CONSTANTS
################################################################################
PSAMPR_SERVER_NAME = LPWSTR
# 2.2.1.1 Common ACCESS_MASK Values
DELETE                  = 0x00010000
READ_CONTROL            = 0x00020000
WRITE_DAC               = 0x00040000
WRITE_OWNER             = 0x00080000
ACCESS_SYSTEM_SECURITY  = 0x01000000
MAXIMUM_ALLOWED         = 0x02000000

# 2.2.1.2 Generic ACCESS_MASK Values
GENERIC_READ     = 0x80000000
GENERIC_WRITE    = 0x40000000
GENERIC_EXECUTE  = 0x20000000
GENERIC_ALL      = 0x10000000

# 2.2.1.3 Server ACCESS_MASK Values
SAM_SERVER_CONNECT            = 0x00000001
SAM_SERVER_SHUTDOWN           = 0x00000002
SAM_SERVER_INITIALIZE         = 0x00000004
SAM_SERVER_CREATE_DOMAIN      = 0x00000008
SAM_SERVER_ENUMERATE_DOMAINS  = 0x00000010
SAM_SERVER_LOOKUP_DOMAIN      = 0x00000020
SAM_SERVER_ALL_ACCESS         = 0x000F003F
SAM_SERVER_READ               = 0x00020010
SAM_SERVER_WRITE              = 0x0002000E
SAM_SERVER_EXECUTE            = 0x00020021

# 2.2.1.4 Domain ACCESS_MASK Values
DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001
DOMAIN_WRITE_PASSWORD_PARAMS    = 0x00000002
DOMAIN_READ_OTHER_PARAMETERS    = 0x00000004
DOMAIN_WRITE_OTHER_PARAMETERS   = 0x00000008
DOMAIN_CREATE_USER              = 0x00000010
DOMAIN_CREATE_GROUP             = 0x00000020
DOMAIN_CREATE_ALIAS             = 0x00000040
DOMAIN_GET_ALIAS_MEMBERSHIP     = 0x00000080
DOMAIN_LIST_ACCOUNTS            = 0x00000100
DOMAIN_LOOKUP                   = 0x00000200
DOMAIN_ADMINISTER_SERVER        = 0x00000400
DOMAIN_ALL_ACCESS               = 0x000F07FF
DOMAIN_READ                     = 0x00020084
DOMAIN_WRITE                    = 0x0002047A
DOMAIN_EXECUTE                  = 0x00020301

# 2.2.1.5 Group ACCESS_MASK Values
GROUP_READ_INFORMATION  = 0x00000001
GROUP_WRITE_ACCOUNT     = 0x00000002
GROUP_ADD_MEMBER        = 0x00000004
GROUP_REMOVE_MEMBER     = 0x00000008
GROUP_LIST_MEMBERS      = 0x00000010
GROUP_ALL_ACCESS        = 0x000F001F
GROUP_READ              = 0x00020010
GROUP_WRITE             = 0x0002000E
GROUP_EXECUTE           = 0x00020001

# 2.2.1.6 Alias ACCESS_MASK Values
ALIAS_ADD_MEMBER        = 0x00000001
ALIAS_REMOVE_MEMBER     = 0x00000002
ALIAS_LIST_MEMBERS      = 0x00000004
ALIAS_READ_INFORMATION  = 0x00000008
ALIAS_WRITE_ACCOUNT     = 0x00000010
ALIAS_ALL_ACCESS        = 0x000F001F
ALIAS_READ              = 0x00020004
ALIAS_WRITE             = 0x00020013
ALIAS_EXECUTE           = 0x00020008

# 2.2.1.7 User ACCESS_MASK Values
USER_READ_GENERAL            = 0x00000001
USER_READ_PREFERENCES        = 0x00000002
USER_WRITE_PREFERENCES       = 0x00000004
USER_READ_LOGON              = 0x00000008
USER_READ_ACCOUNT            = 0x00000010
USER_WRITE_ACCOUNT           = 0x00000020
USER_CHANGE_PASSWORD         = 0x00000040
USER_FORCE_PASSWORD_CHANGE   = 0x00000080
USER_LIST_GROUPS             = 0x00000100
USER_READ_GROUP_INFORMATION  = 0x00000200
USER_WRITE_GROUP_INFORMATION = 0x00000400
USER_ALL_ACCESS              = 0x000F07FF
USER_READ                    = 0x0002031A
USER_WRITE                   = 0x00020044
USER_EXECUTE                 = 0x00020041

# 2.2.1.8 USER_ALL Values
USER_ALL_USERNAME            = 0x00000001
USER_ALL_FULLNAME            = 0x00000002
USER_ALL_USERID              = 0x00000004
USER_ALL_PRIMARYGROUPID      = 0x00000008
USER_ALL_ADMINCOMMENT        = 0x00000010
USER_ALL_USERCOMMENT         = 0x00000020
USER_ALL_HOMEDIRECTORY       = 0x00000040
USER_ALL_HOMEDIRECTORYDRIVE  = 0x00000080
USER_ALL_SCRIPTPATH          = 0x00000100
USER_ALL_PROFILEPATH         = 0x00000200
USER_ALL_WORKSTATIONS        = 0x00000400
USER_ALL_LASTLOGON           = 0x00000800
USER_ALL_LASTLOGOFF          = 0x00001000
USER_ALL_LOGONHOURS          = 0x00002000
USER_ALL_BADPASSWORDCOUNT    = 0x00004000
USER_ALL_LOGONCOUNT          = 0x00008000
USER_ALL_PASSWORDCANCHANGE   = 0x00010000
USER_ALL_PASSWORDMUSTCHANGE  = 0x00020000
USER_ALL_PASSWORDLASTSET     = 0x00040000
USER_ALL_ACCOUNTEXPIRES      = 0x00080000
USER_ALL_USERACCOUNTCONTROL  = 0x00100000
USER_ALL_PARAMETERS          = 0x00200000
USER_ALL_COUNTRYCODE         = 0x00400000
USER_ALL_CODEPAGE            = 0x00800000
USER_ALL_NTPASSWORDPRESENT   = 0x01000000
USER_ALL_LMPASSWORDPRESENT   = 0x02000000
USER_ALL_PRIVATEDATA         = 0x04000000
USER_ALL_PASSWORDEXPIRED     = 0x08000000
USER_ALL_SECURITYDESCRIPTOR  = 0x10000000
USER_ALL_UNDEFINED_MASK      = 0xC0000000

# 2.2.1.9 ACCOUNT_TYPE Values
SAM_DOMAIN_OBJECT             = 0x00000000
SAM_GROUP_OBJECT              = 0x10000000
SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
SAM_ALIAS_OBJECT              = 0x20000000
SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
SAM_USER_OBJECT               = 0x30000000
SAM_MACHINE_ACCOUNT           = 0x30000001
SAM_TRUST_ACCOUNT             = 0x30000002
SAM_APP_BASIC_GROUP           = 0x40000000
SAM_APP_QUERY_GROUP           = 0x40000001

# 2.2.1.10 SE_GROUP Attributes
SE_GROUP_MANDATORY            = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT   = 0x00000002
SE_GROUP_ENABLED              = 0x00000004

# 2.2.1.11 GROUP_TYPE Codes
GROUP_TYPE_ACCOUNT_GROUP      = 0x00000002
GROUP_TYPE_RESOURCE_GROUP     = 0x00000004
GROUP_TYPE_UNIVERSAL_GROUP    = 0x00000008
GROUP_TYPE_SECURITY_ENABLED   = 0x80000000
GROUP_TYPE_SECURITY_ACCOUNT   = 0x80000002
GROUP_TYPE_SECURITY_RESOURCE  = 0x80000004
GROUP_TYPE_SECURITY_UNIVERSAL = 0x80000008

# 2.2.1.12 USER_ACCOUNT Codes
USER_ACCOUNT_DISABLED                       = 0x00000001
USER_HOME_DIRECTORY_REQUIRED                = 0x00000002
USER_PASSWORD_NOT_REQUIRED                  = 0x00000004
USER_TEMP_DUPLICATE_ACCOUNT                 = 0x00000008
USER_NORMAL_ACCOUNT                         = 0x00000010
USER_MNS_LOGON_ACCOUNT                      = 0x00000020
USER_INTERDOMAIN_TRUST_ACCOUNT              = 0x00000040
USER_WORKSTATION_TRUST_ACCOUNT              = 0x00000080
USER_SERVER_TRUST_ACCOUNT                   = 0x00000100
USER_DONT_EXPIRE_PASSWORD                   = 0x00000200
USER_ACCOUNT_AUTO_LOCKED                    = 0x00000400
USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED        = 0x00000800
USER_SMARTCARD_REQUIRED                     = 0x00001000
USER_TRUSTED_FOR_DELEGATION                 = 0x00002000
USER_NOT_DELEGATED                          = 0x00004000
USER_USE_DES_KEY_ONLY                       = 0x00008000
USER_DONT_REQUIRE_PREAUTH                   = 0x00010000
USER_PASSWORD_EXPIRED                       = 0x00020000
USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000
USER_NO_AUTH_DATA_REQUIRED                  = 0x00080000
USER_PARTIAL_SECRETS_ACCOUNT                = 0x00100000
USER_USE_AES_KEYS                           = 0x00200000

# 2.2.1.13 UF_FLAG Codes
UF_SCRIPT                                 = 0x00000001
UF_ACCOUNTDISABLE                         = 0x00000002
UF_HOMEDIR_REQUIRED                       = 0x00000008
UF_LOCKOUT                                = 0x00000010
UF_PASSWD_NOTREQD                         = 0x00000020
UF_PASSWD_CANT_CHANGE                     = 0x00000040
UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED        = 0x00000080
UF_TEMP_DUPLICATE_ACCOUNT                 = 0x00000100
UF_NORMAL_ACCOUNT                         = 0x00000200
UF_INTERDOMAIN_TRUST_ACCOUNT              = 0x00000800
UF_WORKSTATION_TRUST_ACCOUNT              = 0x00001000
UF_SERVER_TRUST_ACCOUNT                   = 0x00002000
UF_DONT_EXPIRE_PASSWD                     = 0x00010000
UF_MNS_LOGON_ACCOUNT                      = 0x00020000
UF_SMARTCARD_REQUIRED                     = 0x00040000
UF_TRUSTED_FOR_DELEGATION                 = 0x00080000
UF_NOT_DELEGATED                          = 0x00100000
UF_USE_DES_KEY_ONLY                       = 0x00200000
UF_DONT_REQUIRE_PREAUTH                   = 0x00400000
UF_PASSWORD_EXPIRED                       = 0x00800000
UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
UF_NO_AUTH_DATA_REQUIRED                  = 0x02000000
UF_PARTIAL_SECRETS_ACCOUNT                = 0x04000000
UF_USE_AES_KEYS                           = 0x08000000

# 2.2.1.14 Predefined RIDs
DOMAIN_USER_RID_ADMIN                 = 0x000001F4
DOMAIN_USER_RID_GUEST                 = 0x000001F5
DOMAIN_USER_RID_KRBTGT                = 0x000001F6
DOMAIN_GROUP_RID_USERS                = 0x00000201
DOMAIN_GROUP_RID_COMPUTERS            = 0x00000203
DOMAIN_GROUP_RID_CONTROLLERS          = 0x00000203
DOMAIN_ALIAS_RID_ADMINS               = 0x00000220
DOMAIN_GROUP_RID_READONLY_CONTROLLERS = 0x00000209

# 2.2.4.1 Domain Fields
DOMAIN_PASSWORD_COMPLEX         = 0x00000001
DOMAIN_PASSWORD_NO_ANON_CHANGE  = 0x00000002
DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 0x00000004
DOMAIN_LOCKOUT_ADMINS           = 0x00000008
DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x00000010
DOMAIN_REFUSE_PASSWORD_CHANGE   = 0x00000020

# 2.2.9.2 SAM_VALIDATE_PERSISTED_FIELDS PresentFields
SAM_VALIDATE_PASSWORD_LAST_SET       = 0x00000001
SAM_VALIDATE_BAD_PASSWORD_TIME       = 0x00000002
SAM_VALIDATE_LOCKOUT_TIME            = 0x00000004
SAM_VALIDATE_BAD_PASSWORD_COUNT      = 0x00000008
SAM_VALIDATE_PASSWORD_HISTORY_LENGTH = 0x00000010
SAM_VALIDATE_PASSWORD_HISTORY        = 0x00000020

################################################################################
# STRUCTURES
################################################################################

# 2.2.2.1 RPC_STRING, PRPC_STRING
class RPC_STRING(NDR):
    align = 2
    align64 = 2
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

class PRPC_STRING(NDRPointer):
    referent = (
        ('Data', RPC_STRING),
    )
 
# 2.2.2.2 OLD_LARGE_INTEGER
class OLD_LARGE_INTEGER(NDR):
    structure = (
        ('LowPart',NDRLONG),
        ('HighPart',NDRLONG),
    )

# 2.2.2.3 SID_NAME_USE
class SID_NAME_USE(NDRENUM):
    class enumItems(Enum):
        SidTypeUser            = 1
        SidTypeGroup           = 2
        SidTypeDomain          = 3
        SidTypeAlias           = 4
        SidTypeWellKnownGroup  = 5
        SidTypeDeletedAccount  = 6
        SidTypeInvalid         = 7
        SidTypeUnknown         = 8
        SidTypeComputer        = 9
        SidTypeLabel           = 10

# 2.2.2.4 RPC_SHORT_BLOB
class SHORT_ARRAY(NDRUniConformantVaryingArray):
    item = '<H'
    pass

class PSHORT_ARRAY(NDRPointer):
    referent = (
        ('Data', SHORT_ARRAY),
    )

class RPC_SHORT_BLOB(NDR):
    structure = (
        ('Length', NDRSHORT),
        ('MaximumLength', NDRSHORT),
        ('Buffer',PSHORT_ARRAY),
    )

# 2.2.3.2 SAMPR_HANDLE
class SAMPR_HANDLE(NDR):
    structure =  (
        ('Data','20s=""'),
    )

# 2.2.3.3 ENCRYPTED_LM_OWF_PASSWORD, ENCRYPTED_NT_OWF_PASSWORD
class ENCRYPTED_LM_OWF_PASSWORD(NDR):
    structure = (
        ('Data', '16s=""'),
    )

ENCRYPTED_NT_OWF_PASSWORD = ENCRYPTED_LM_OWF_PASSWORD

class PENCRYPTED_LM_OWF_PASSWORD(NDRPointer):
    referent = (
        ('Data', ENCRYPTED_LM_OWF_PASSWORD),
    )

PENCRYPTED_NT_OWF_PASSWORD = PENCRYPTED_LM_OWF_PASSWORD

# 2.2.3.4 SAMPR_ULONG_ARRAY
class SAMPR_ULONG_ARRAY(NDRUniConformantVaryingArray):
    item = '<L'

# 2.2.3.5 SAMPR_SID_INFORMATION
class SAMPR_SID_INFORMATION(NDR):
    structure = (
        ('SidPointer', RPC_SID),
    )

class PSAMPR_SID_INFORMATION(NDRPointer):
    referent = (
        ('Data', SAMPR_SID_INFORMATION),
    )

class SAMPR_SID_INFORMATION_ARRAY(NDRUniConformantArray):
    item = PSAMPR_SID_INFORMATION

class PSAMPR_SID_INFORMATION_ARRAY(NDRPointer):
    referent = (
        ('Data', SAMPR_SID_INFORMATION_ARRAY),
    )

# 2.2.3.6 SAMPR_PSID_ARRAY
class SAMPR_PSID_ARRAY(NDR):
    structure = (
        ('Count', NDRLONG),
        ('Sids', PSAMPR_SID_INFORMATION_ARRAY),
    )

# 2.2.3.7 SAMPR_PSID_ARRAY_OUT
class SAMPR_PSID_ARRAY_OUT(NDR):
    structure = (
        ('Count', NDRLONG),
        ('Sids', PSAMPR_SID_INFORMATION_ARRAY),
    )

# 2.2.3.9 SAMPR_RID_ENUMERATION
class SAMPR_RID_ENUMERATION(NDR):
    structure = (
        ('RelativeId',NDRLONG),
        ('Name',RPC_UNICODE_STRING),
    )

class SAMPR_RID_ENUMERATION_ARRAY(NDRUniConformantArray):
    item = SAMPR_RID_ENUMERATION

class PSAMPR_RID_ENUMERATION_ARRAY(NDRPointer):
    referent = (
        ('Data', SAMPR_RID_ENUMERATION_ARRAY),
    )

# 2.2.3.10 SAMPR_ENUMERATION_BUFFER
class SAMPR_ENUMERATION_BUFFER(NDR):
    structure = (
        ('EntriesRead',NDRLONG ),
        ('Buffer',PSAMPR_RID_ENUMERATION_ARRAY ),
    )

class PSAMPR_ENUMERATION_BUFFER(NDRPointer):
    referent = (
        ('Data',SAMPR_ENUMERATION_BUFFER),
    )

# 2.2.3.11 SAMPR_SR_SECURITY_DESCRIPTOR
class CHAR_ARRAY(NDRUniConformantArray):
    pass

class PCHAR_ARRAY(NDRPointer):
    referent = (
        ('Data', CHAR_ARRAY),
    )

class SAMPR_SR_SECURITY_DESCRIPTOR(NDR):
    structure = (
        ('Length', NDRLONG),
        ('SecurityDescriptor', PCHAR_ARRAY),
    )

class PSAMPR_SR_SECURITY_DESCRIPTOR(NDRPointer):
    referent = (
        ('Data', SAMPR_SR_SECURITY_DESCRIPTOR),
    )

# 2.2.3.12 GROUP_MEMBERSHIP
class GROUP_MEMBERSHIP(NDR):
    structure = (
        ('RelativeId',NDRLONG),
        ('Attributes',NDRLONG),
    )

class GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = GROUP_MEMBERSHIP

class PGROUP_MEMBERSHIP_ARRAY(NDRPointer):
    referent = (
        ('Data',GROUP_MEMBERSHIP_ARRAY),
    ) 

# 2.2.3.13 SAMPR_GET_GROUPS_BUFFER
class SAMPR_GET_GROUPS_BUFFER(NDR):
    structure = (
        ('MembershipCount',NDRLONG),
        ('Groups',PGROUP_MEMBERSHIP_ARRAY),
    )

class PSAMPR_GET_GROUPS_BUFFER(NDRPointer):
    referent = (
        ('Data',SAMPR_GET_GROUPS_BUFFER),
    )

# 2.2.3.14 SAMPR_GET_MEMBERS_BUFFER
class LONG_ARRAY(NDRUniConformantArray):
    item = NDRLONG
    pass

class PLONG_ARRAY(NDRPointer):
    referent = (
        ('Data', LONG_ARRAY),
    )

class SAMPR_GET_MEMBERS_BUFFER(NDR):
    structure = (
        ('MemberCount', NDRLONG),
        ('Members', PLONG_ARRAY),
        ('Attributes', PLONG_ARRAY),
    )

class PSAMPR_GET_MEMBERS_BUFFER(NDRPointer):
    referent = (
        ('Data', SAMPR_GET_MEMBERS_BUFFER),
    )

# 2.2.3.15 SAMPR_REVISION_INFO_V1
class SAMPR_REVISION_INFO_V1(NDR):
    structure = (
       ('Revision',NDRLONG),
       ('SupportedFeatures',NDRLONG),
    )

# 2.2.3.16 SAMPR_REVISION_INFO
class SAMPR_REVISION_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', NDRLONG),
    )

    union = {
        1: ('V1', SAMPR_REVISION_INFO_V1),
    }

# 2.2.3.17 USER_DOMAIN_PASSWORD_INFORMATION
class USER_DOMAIN_PASSWORD_INFORMATION(NDR):
    structure = (
        ('MinPasswordLength', NDRSHORT),
        ('PasswordProperties', NDRLONG),
    )

# 2.2.4.2 DOMAIN_SERVER_ENABLE_STATE
class DOMAIN_SERVER_ENABLE_STATE(NDRENUM):
    class enumItems(Enum):
        DomainServerEnabled  = 1
        DomainServerDisabled = 2

# 2.2.4.3 DOMAIN_STATE_INFORMATION
class DOMAIN_STATE_INFORMATION(NDR):
    structure = (
        ('DomainServerState', DOMAIN_SERVER_ENABLE_STATE),
    )

# 2.2.4.4 DOMAIN_SERVER_ROLE
class DOMAIN_SERVER_ROLE(NDRENUM):
    class enumItems(Enum):
        DomainServerRoleBackup  = 2
        DomainServerRolePrimary = 3

# 2.2.4.5 DOMAIN_PASSWORD_INFORMATION
class DOMAIN_PASSWORD_INFORMATION(NDR):
    structure = (
        ('MinPasswordLength', NDRSHORT),
        ('PasswordHistoryLength', NDRSHORT),
        ('PasswordProperties', NDRLONG),
        ('MaxPasswordAge', OLD_LARGE_INTEGER),
        ('MinPasswordAge', OLD_LARGE_INTEGER),
    )

# 2.2.4.6 DOMAIN_LOGOFF_INFORMATION
class DOMAIN_LOGOFF_INFORMATION(NDR):
    structure = (
        ('ForceLogoff', OLD_LARGE_INTEGER),
    )

# 2.2.4.7 DOMAIN_SERVER_ROLE_INFORMATION
class DOMAIN_SERVER_ROLE_INFORMATION(NDR):
    structure = (
        ('DomainServerRole', DOMAIN_SERVER_ROLE),
    )

# 2.2.4.8 DOMAIN_MODIFIED_INFORMATION
class DOMAIN_MODIFIED_INFORMATION(NDR):
    structure = (
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('CreationTime', OLD_LARGE_INTEGER),
    )

# 2.2.4.9 DOMAIN_MODIFIED_INFORMATION2
class DOMAIN_MODIFIED_INFORMATION2(NDR):
    structure = (
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('CreationTime', OLD_LARGE_INTEGER),
        ('ModifiedCountAtLastPromotion', OLD_LARGE_INTEGER),
    )

# 2.2.4.10 SAMPR_DOMAIN_GENERAL_INFORMATION
class SAMPR_DOMAIN_GENERAL_INFORMATION(NDR):
    structure = (
        ('ForceLogoff', OLD_LARGE_INTEGER),
        ('OemInformation', RPC_UNICODE_STRING),
        ('DomainName', RPC_UNICODE_STRING),
        ('ReplicaSourceNodeName', RPC_UNICODE_STRING),
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('DomainServerState', NDRLONG),
        ('DomainServerRole', NDRLONG),
        ('UasCompatibilityRequired', NDRSMALL),
        ('UserCount', NDRLONG),
        ('GroupCount', NDRLONG),
        ('AliasCount', NDRLONG),
    )

# 2.2.4.11 SAMPR_DOMAIN_GENERAL_INFORMATION2
class SAMPR_DOMAIN_GENERAL_INFORMATION2(NDR):
    structure = (
        ('I1', SAMPR_DOMAIN_GENERAL_INFORMATION),
        ('LockoutDuration', LARGE_INTEGER),
        ('LockoutObservationWindow', LARGE_INTEGER),
        ('LockoutThreshold', NDRSHORT),
    )

# 2.2.4.12 SAMPR_DOMAIN_OEM_INFORMATION
class SAMPR_DOMAIN_OEM_INFORMATION(NDR):
    structure = (
        ('OemInformation', RPC_UNICODE_STRING),
    )

# 2.2.4.13 SAMPR_DOMAIN_NAME_INFORMATION
class SAMPR_DOMAIN_NAME_INFORMATION(NDR):
    structure = (
        ('DomainName', RPC_UNICODE_STRING),
    )

# 2.2.4.14 SAMPR_DOMAIN_REPLICATION_INFORMATION
class SAMPR_DOMAIN_REPLICATION_INFORMATION(NDR):
    structure = (
        ('ReplicaSourceNodeName', RPC_UNICODE_STRING),
    )

# 2.2.4.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION
class SAMPR_DOMAIN_LOCKOUT_INFORMATION(NDR):
    structure = (
        ('LockoutDuration', LARGE_INTEGER),
        ('LockoutObservationWindow', LARGE_INTEGER),
        ('LockoutThreshold', NDRSHORT),
    )

# 2.2.4.16 DOMAIN_INFORMATION_CLASS
class DOMAIN_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        DomainPasswordInformation    = 1
        DomainGeneralInformation     = 2
        DomainLogoffInformation      = 3
        DomainOemInformation         = 4
        DomainNameInformation        = 5
        DomainReplicationInformation = 6
        DomainServerRoleInformation  = 7
        DomainModifiedInformation    = 8
        DomainStateInformation       = 9
        DomainGeneralInformation2    = 11
        DomainLockoutInformation     = 12
        DomainModifiedInformation2   = 13

# 2.2.4.17 SAMPR_DOMAIN_INFO_BUFFER
class SAMPR_DOMAIN_INFO_BUFFER(NDRUnion):
    union = {
        DOMAIN_INFORMATION_CLASS.DomainPasswordInformation    : ('Password', DOMAIN_PASSWORD_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainGeneralInformation     : ('General', SAMPR_DOMAIN_GENERAL_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainLogoffInformation      : ('Logoff', DOMAIN_LOGOFF_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainOemInformation         : ('Oem', SAMPR_DOMAIN_OEM_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainNameInformation        : ('Name', SAMPR_DOMAIN_NAME_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation  : ('Role', DOMAIN_SERVER_ROLE_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainReplicationInformation : ('Replication', SAMPR_DOMAIN_REPLICATION_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainModifiedInformation    : ('Modified', DOMAIN_MODIFIED_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainStateInformation       : ('State', DOMAIN_STATE_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2    : ('General2', SAMPR_DOMAIN_GENERAL_INFORMATION2),
        DOMAIN_INFORMATION_CLASS.DomainLockoutInformation     : ('Lockout', SAMPR_DOMAIN_LOCKOUT_INFORMATION),
        DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2   : ('Modified2', DOMAIN_MODIFIED_INFORMATION2),
    }

class PSAMPR_DOMAIN_INFO_BUFFER(NDRPointer):
    referent = (
        ('Data', SAMPR_DOMAIN_INFO_BUFFER),
    )

# 2.2.4.16 DOMAIN_INFORMATION_CLASS
class DOMAIN_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        DomainPasswordInformation    = 1
        DomainGeneralInformation     = 2
        DomainLogoffInformation      = 3
        DomainOemInformation         = 4
        DomainNameInformation        = 5
        DomainReplicationInformation = 6
        DomainServerRoleInformation  = 7
        DomainModifiedInformation    = 8
        DomainStateInformation       = 9
        DomainGeneralInformation2    = 11
        DomainLockoutInformation     = 12
        DomainModifiedInformation2   = 13

# 2.2.5.2 GROUP_ATTRIBUTE_INFORMATION
class GROUP_ATTRIBUTE_INFORMATION(NDR):
    structure = (
        ('Attributes', NDRLONG),
    )

# 2.2.5.3 SAMPR_GROUP_GENERAL_INFORMATION
class SAMPR_GROUP_GENERAL_INFORMATION(NDR):
    structure = (
        ('Name', RPC_UNICODE_STRING),
        ('Attributes', NDRLONG),
        ('MemberCount', NDRLONG),
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.5.4 SAMPR_GROUP_NAME_INFORMATION
class SAMPR_GROUP_NAME_INFORMATION(NDR):
    structure = (
        ('Name', RPC_UNICODE_STRING),
    )

# 2.2.5.5 SAMPR_GROUP_ADM_COMMENT_INFORMATION
class SAMPR_GROUP_ADM_COMMENT_INFORMATION(NDR):
    structure = (
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.5.6 GROUP_INFORMATION_CLASS
class GROUP_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        GroupGeneralInformation      = 1 
        GroupNameInformation         = 2
        GroupAttributeInformation    = 3
        GroupAdminCommentInformation = 4
        GroupReplicationInformation  = 5

# 2.2.5.7 SAMPR_GROUP_INFO_BUFFER
class SAMPR_GROUP_INFO_BUFFER(NDRUnion):
    union = {
        GROUP_INFORMATION_CLASS.GroupGeneralInformation      : ('General', SAMPR_GROUP_GENERAL_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupNameInformation         : ('Name', SAMPR_GROUP_NAME_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupAttributeInformation    : ('Attribute', GROUP_ATTRIBUTE_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupAdminCommentInformation : ('AdminComment', SAMPR_GROUP_ADM_COMMENT_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupReplicationInformation  : ('DoNotUse', SAMPR_GROUP_GENERAL_INFORMATION),
    }

class PSAMPR_GROUP_INFO_BUFFER(NDRPointer):
    referent = (
        ('Data', SAMPR_GROUP_INFO_BUFFER),
    )

# 2.2.6.2 SAMPR_ALIAS_GENERAL_INFORMATION
class SAMPR_ALIAS_GENERAL_INFORMATION(NDR):
    structure = (
        ('Name', RPC_UNICODE_STRING),
        ('MemberCount', NDRLONG),
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.6.3 SAMPR_ALIAS_NAME_INFORMATION
class SAMPR_ALIAS_NAME_INFORMATION(NDR):
    structure = (
        ('Name', RPC_UNICODE_STRING),
    )

# 2.2.6.4 SAMPR_ALIAS_ADM_COMMENT_INFORMATION
class SAMPR_ALIAS_ADM_COMMENT_INFORMATION(NDR):
    structure = (
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.6.5 ALIAS_INFORMATION_CLASS
class ALIAS_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        AliasGeneralInformation      = 1
        AliasNameInformation         = 2
        AliasAdminCommentInformation = 3

# 2.2.6.6 SAMPR_ALIAS_INFO_BUFFER
class SAMPR_ALIAS_INFO_BUFFER(NDRUnion):
    union = {
        ALIAS_INFORMATION_CLASS.AliasGeneralInformation      : ('General', SAMPR_ALIAS_GENERAL_INFORMATION),
        ALIAS_INFORMATION_CLASS.AliasNameInformation         : ('Name', SAMPR_ALIAS_NAME_INFORMATION),
        ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation : ('AdminComment', SAMPR_ALIAS_ADM_COMMENT_INFORMATION),
    }
 
class PSAMPR_ALIAS_INFO_BUFFER(NDRPointer):
    referent = (
        ('Data', SAMPR_ALIAS_INFO_BUFFER),
    )

# 2.2.7.2 USER_PRIMARY_GROUP_INFORMATION
class USER_PRIMARY_GROUP_INFORMATION(NDR):
    structure = (
        ('PrimaryGroupId', NDRLONG),
    )

# 2.2.7.3 USER_CONTROL_INFORMATION
class USER_CONTROL_INFORMATION(NDR):
    structure = (
        ('UserAccountControl', NDRLONG),
    )

# 2.2.7.4 USER_EXPIRES_INFORMATION
class USER_EXPIRES_INFORMATION(NDR):
    structure = (
        ('AccountExpires', OLD_LARGE_INTEGER),
    )

# 2.2.7.5 SAMPR_LOGON_HOURS
class LOGON_HOURS_ARRAY(NDRUniConformantVaryingArray):
    pass

class PLOGON_HOURS_ARRAY(NDRPointer):
    referent = (
        ('Data', LOGON_HOURS_ARRAY),
    )

class SAMPR_LOGON_HOURS(NDR):
    structure = (
        #('UnitsPerWeek', NDRSHORT),
        ('UnitsPerWeek', NDRLONG),
        ('LogonHours', PLOGON_HOURS_ARRAY),
    )

    def getData(self, soFar = 0):
        self['UnitsPerWeek'] = len(self['LogonHours']) * 8 
        return ndr.NDR.getData(self, soFar)

# 2.2.7.6 SAMPR_USER_ALL_INFORMATION
class SAMPR_USER_ALL_INFORMATION(NDR):
    structure = (
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('UserComment', RPC_UNICODE_STRING),
        ('Parameters', RPC_UNICODE_STRING),

        ('LmOwfPassword', RPC_SHORT_BLOB),
        ('NtOwfPassword', RPC_SHORT_BLOB),
        ('PrivateData', RPC_UNICODE_STRING),

        ('SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR),

        ('UserId', NDRLONG),
        ('PrimaryGroupId', NDRLONG),
        ('UserAccountControl', NDRLONG),
        ('WhichFields', NDRLONG),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', NDRSHORT),
        ('LogonCount', NDRSHORT),
        ('CountryCode', NDRSHORT),
        ('CodePage', NDRSHORT),
        ('LmPasswordPresent', NDRSMALL),
        ('NtPasswordPresent', NDRSMALL),
        ('PasswordExpired', NDRSMALL),
        ('PrivateDataSensitive', NDRSMALL),

    )

# 2.2.7.7 SAMPR_USER_GENERAL_INFORMATION
class SAMPR_USER_GENERAL_INFORMATION(NDR):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('PrimaryGroupId', NDRLONG),
        ('AdminComment', RPC_UNICODE_STRING),
        ('UserComment', RPC_UNICODE_STRING),
    )

# 2.2.7.8 SAMPR_USER_PREFERENCES_INFORMATION
class SAMPR_USER_PREFERENCES_INFORMATION(NDR):
    structure = (
        ('UserComment', RPC_UNICODE_STRING),
        ('Reserved1', RPC_UNICODE_STRING),
        ('CountryCode', NDRSHORT),
        ('CodePage', NDRSHORT),
    )

# 2.2.7.9 SAMPR_USER_PARAMETERS_INFORMATION
class SAMPR_USER_PARAMETERS_INFORMATION(NDR):
    structure = (
        ('Parameters', RPC_UNICODE_STRING),
    )

# 2.2.7.10 SAMPR_USER_LOGON_INFORMATION
class SAMPR_USER_LOGON_INFORMATION(NDR):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', NDRLONG),
        ('PrimaryGroupId', NDRLONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', NDRSHORT),
        ('LogonCount', NDRSHORT),
        ('UserAccountControl', NDRLONG),
    )

# 2.2.7.11 SAMPR_USER_ACCOUNT_INFORMATION
class SAMPR_USER_ACCOUNT_INFORMATION(NDR):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', NDRLONG),
        ('PrimaryGroupId', NDRLONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', NDRSHORT),
        ('LogonCount', NDRSHORT),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('UserAccountControl', NDRLONG)
    )

# 2.2.7.12 SAMPR_USER_A_NAME_INFORMATION
class SAMPR_USER_A_NAME_INFORMATION(NDR):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
    )

# 2.2.7.13 SAMPR_USER_F_NAME_INFORMATION
class SAMPR_USER_F_NAME_INFORMATION(NDR):
    structure = (
        ('FullName', RPC_UNICODE_STRING),
    )

# 2.2.7.14 SAMPR_USER_NAME_INFORMATION
class SAMPR_USER_NAME_INFORMATION(NDR):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
    )

# 2.2.7.15 SAMPR_USER_HOME_INFORMATION
class SAMPR_USER_HOME_INFORMATION(NDR):
    structure = (
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
    )

# 2.2.7.16 SAMPR_USER_SCRIPT_INFORMATION
class SAMPR_USER_SCRIPT_INFORMATION(NDR):
    structure = (
        ('ScriptPath', RPC_UNICODE_STRING),
    )

# 2.2.7.17 SAMPR_USER_PROFILE_INFORMATION
class SAMPR_USER_PROFILE_INFORMATION(NDR):
    structure = (
        ('ProfilePath', RPC_UNICODE_STRING),
    )

# 2.2.7.18 SAMPR_USER_ADMIN_COMMENT_INFORMATION
class SAMPR_USER_ADMIN_COMMENT_INFORMATION(NDR):
    structure = (
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.7.19 SAMPR_USER_WORKSTATIONS_INFORMATION
class SAMPR_USER_WORKSTATIONS_INFORMATION(NDR):
    structure = (
        ('WorkStations', RPC_UNICODE_STRING),
    )

# 2.2.7.20 SAMPR_USER_LOGON_HOURS_INFORMATION
class SAMPR_USER_LOGON_HOURS_INFORMATION(NDR):
    structure = (
        ('LogonHours', SAMPR_LOGON_HOURS),
    )

# 2.2.7.21 SAMPR_ENCRYPTED_USER_PASSWORD
class SAMPR_USER_PASSWORD(NDR):
    structure = (
        ('Buffer', '512s=""'),
        ('Length', NDRLONG),
    )

class SAMPR_ENCRYPTED_USER_PASSWORD(NDR):
    structure = (
        ('Buffer', '516s=""'),
    )

class PSAMPR_ENCRYPTED_USER_PASSWORD(NDRPointer):
    referent = (
        ('Data', SAMPR_ENCRYPTED_USER_PASSWORD),
    )

# 2.2.7.22 SAMPR_ENCRYPTED_USER_PASSWORD_NEW
class SAMPR_ENCRYPTED_USER_PASSWORD_NEW(NDR):
    structure = (
        ('Buffer', '522s=""'),
    )

# 2.2.7.23 SAMPR_USER_INTERNAL1_INFORMATION
class SAMPR_USER_INTERNAL1_INFORMATION(NDR):
    structure = (
        ('EncryptedNtOwfPassword', ENCRYPTED_NT_OWF_PASSWORD),
        ('EncryptedLmOwfPassword', ENCRYPTED_LM_OWF_PASSWORD),
        ('NtPasswordPresent', NDRSMALL),
        ('LmPasswordPresent', NDRSMALL),
        ('PasswordExpired', NDRSMALL),
    )

# 2.2.7.24 SAMPR_USER_INTERNAL4_INFORMATION
class SAMPR_USER_INTERNAL4_INFORMATION(NDR):
    structure = (
        ('I1', SAMPR_USER_ALL_INFORMATION),
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD),
    )

# 2.2.7.25 SAMPR_USER_INTERNAL4_INFORMATION_NEW
class SAMPR_USER_INTERNAL4_INFORMATION_NEW(NDR):
    structure = (
        ('I1', SAMPR_USER_ALL_INFORMATION),
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW),
    )

# 2.2.7.26 SAMPR_USER_INTERNAL5_INFORMATION
class SAMPR_USER_INTERNAL5_INFORMATION(NDR):
    structure = (
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD),
        ('PasswordExpired', NDRSMALL),
    )

# 2.2.7.27 SAMPR_USER_INTERNAL5_INFORMATION_NEW
class SAMPR_USER_INTERNAL5_INFORMATION_NEW(NDR):
    structure = (
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW),
        ('PasswordExpired', NDRSMALL),
    )

# 2.2.7.28 USER_INFORMATION_CLASS
class USER_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        UserGeneralInformation      = 1
        UserPreferencesInformation  = 2
        UserLogonInformation        = 3
        UserLogonHoursInformation   = 4
        UserAccountInformation      = 5
        UserNameInformation         = 6
        UserAccountNameInformation  = 7
        UserFullNameInformation     = 8
        UserPrimaryGroupInformation = 9
        UserHomeInformation         = 10
        UserScriptInformation       = 11
        UserProfileInformation      = 12
        UserAdminCommentInformation = 13
        UserWorkStationsInformation = 14
        UserControlInformation      = 16
        UserExpiresInformation      = 17
        UserInternal1Information    = 18
        UserParametersInformation   = 20
        UserAllInformation          = 21
        UserInternal4Information    = 23
        UserInternal5Information    = 24
        UserInternal4InformationNew = 25
        UserInternal5InformationNew = 26

# 2.2.7.29 SAMPR_USER_INFO_BUFFER
class SAMPR_USER_INFO_BUFFER(NDRUnion):
    union = {
        USER_INFORMATION_CLASS.UserGeneralInformation     : ('General', SAMPR_USER_GENERAL_INFORMATION),
        USER_INFORMATION_CLASS.UserPreferencesInformation : ('Preferences', SAMPR_USER_PREFERENCES_INFORMATION),
        USER_INFORMATION_CLASS.UserLogonInformation       : ('Logon', SAMPR_USER_LOGON_INFORMATION),
        USER_INFORMATION_CLASS.UserLogonHoursInformation  : ('LogonHours', SAMPR_USER_LOGON_HOURS_INFORMATION),
        USER_INFORMATION_CLASS.UserAccountInformation     : ('Account', SAMPR_USER_ACCOUNT_INFORMATION),
        USER_INFORMATION_CLASS.UserNameInformation        : ('Name', SAMPR_USER_NAME_INFORMATION),
        USER_INFORMATION_CLASS.UserAccountNameInformation : ('AccountName', SAMPR_USER_A_NAME_INFORMATION),
        USER_INFORMATION_CLASS.UserFullNameInformation    : ('FullName', SAMPR_USER_F_NAME_INFORMATION),
        USER_INFORMATION_CLASS.UserPrimaryGroupInformation: ('PrimaryGroup', USER_PRIMARY_GROUP_INFORMATION),
        USER_INFORMATION_CLASS.UserHomeInformation        : ('Home', SAMPR_USER_HOME_INFORMATION),
        USER_INFORMATION_CLASS.UserScriptInformation      : ('Script', SAMPR_USER_SCRIPT_INFORMATION),
        USER_INFORMATION_CLASS.UserProfileInformation     : ('Profile', SAMPR_USER_PROFILE_INFORMATION),
        USER_INFORMATION_CLASS.UserAdminCommentInformation: ('AdminComment', SAMPR_USER_ADMIN_COMMENT_INFORMATION),
        USER_INFORMATION_CLASS.UserWorkStationsInformation: ('WorkStations', SAMPR_USER_WORKSTATIONS_INFORMATION),
        USER_INFORMATION_CLASS.UserControlInformation     : ('Control', USER_CONTROL_INFORMATION),
        USER_INFORMATION_CLASS.UserExpiresInformation     : ('Expires', USER_EXPIRES_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal1Information   : ('Internal1', SAMPR_USER_INTERNAL1_INFORMATION),
        USER_INFORMATION_CLASS.UserParametersInformation  : ('Parameters', SAMPR_USER_PARAMETERS_INFORMATION ),
        USER_INFORMATION_CLASS.UserAllInformation         : ('All', SAMPR_USER_ALL_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal4Information   : ('Internal4', SAMPR_USER_INTERNAL4_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal5Information   : ('Internal5', SAMPR_USER_INTERNAL5_INFORMATION),
        USER_INFORMATION_CLASS.UserInternal4InformationNew: ('Internal4New', SAMPR_USER_INTERNAL4_INFORMATION_NEW),
        USER_INFORMATION_CLASS.UserInternal5InformationNew: ('Internal5New', SAMPR_USER_INTERNAL5_INFORMATION_NEW),
    }
 
class PSAMPR_USER_INFO_BUFFER(NDRPointer):
    referent = (
        ('Data', SAMPR_USER_INFO_BUFFER),
    )

class PSAMPR_SERVER_NAME2(NDRPointer):
    align = 0
    referent = (
        ('Data', '4s=""'),
    ) 

# 2.2.8.2 SAMPR_DOMAIN_DISPLAY_USER
class SAMPR_DOMAIN_DISPLAY_USER(NDR):
    structure = (
        ('Index',NDRLONG),
        ('Rid',NDRLONG),
        ('AccountControl',NDRLONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
        ('FullName',RPC_UNICODE_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_USER_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_USER

class PSAMPR_DOMAIN_DISPLAY_USER_ARRAY(NDRPointer):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_USER_ARRAY),
    )

# 2.2.8.3 SAMPR_DOMAIN_DISPLAY_MACHINE
class SAMPR_DOMAIN_DISPLAY_MACHINE(NDR):
    structure = (
        ('Index',NDRLONG),
        ('Rid',NDRLONG),
        ('AccountControl',NDRLONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_MACHINE

class PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY(NDRPointer):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY),
    )

# 2.2.8.4 SAMPR_DOMAIN_DISPLAY_GROUP
class SAMPR_DOMAIN_DISPLAY_GROUP(NDR):
    structure = (
        ('Index',NDRLONG),
        ('Rid',NDRLONG),
        ('AccountControl',NDRLONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_GROUP

class PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY(NDRPointer):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY),
    )

# 2.2.8.5 SAMPR_DOMAIN_DISPLAY_OEM_USER
class SAMPR_DOMAIN_DISPLAY_OEM_USER(NDR):
    structure = (
        ('Index',NDRLONG),
        ('OemAccountName',RPC_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_OEM_USER

class PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY(NDRPointer):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY),
    )

# 2.2.8.6 SAMPR_DOMAIN_DISPLAY_OEM_GROUP
class SAMPR_DOMAIN_DISPLAY_OEM_GROUP(NDR):
    structure = (
        ('Index',NDRLONG),
        ('OemAccountName',RPC_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_OEM_GROUP

class PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY(NDRPointer):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY),
    )

#2.2.8.7 SAMPR_DOMAIN_DISPLAY_USER_BUFFER
class SAMPR_DOMAIN_DISPLAY_USER_BUFFER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_USER_ARRAY),
    )

# 2.2.8.8 SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER
class SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY),
    )
 
# 2.2.8.9 SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER
class SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY),
    )
 
# 2.2.8.10 SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER
class SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY),
    )
 
# 2.2.8.11 SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER
class SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY),
    )

# 2.2.8.12 DOMAIN_DISPLAY_INFORMATION
class DOMAIN_DISPLAY_INFORMATION(NDRENUM):
    class enumItems(Enum):
        DomainDisplayUser     = 1
        DomainDisplayMachine  = 2
        DomainDisplayGroup    = 3
        DomainDisplayOemUser  = 4
        DomainDisplayOemGroup = 5

# 2.2.8.13 SAMPR_DISPLAY_INFO_BUFFER
class SAMPR_DISPLAY_INFO_BUFFER(NDRUnion):
    union = {
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser     : ('UserInformation', SAMPR_DOMAIN_DISPLAY_USER_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine  : ('MachineInformation', SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup    : ('GroupInformation', SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemUser  : ('OemUserInformation', SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup : ('OemGroupInformation', SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER),
    }

# 2.2.9.1 SAM_VALIDATE_PASSWORD_HASH
class SAM_VALIDATE_PASSWORD_HASH(NDR):
    structure = (
        ('Length', NDRLONG),
        ('Hash', LPBYTE),
    )

class PSAM_VALIDATE_PASSWORD_HASH(NDRPointer):
    referent = (
        ('Data', SAM_VALIDATE_PASSWORD_HASH),
    )

# 2.2.9.2 SAM_VALIDATE_PERSISTED_FIELDS
class SAM_VALIDATE_PERSISTED_FIELDS(NDR):
    structure = (
        ('PresentFields', NDRLONG),
        ('PasswordLastSet', LARGE_INTEGER),
        ('BadPasswordTime', LARGE_INTEGER),
        ('LockoutTime', LARGE_INTEGER),
        ('BadPasswordCount', NDRLONG),
        ('PasswordHistoryLength', NDRLONG),
        ('PasswordHistory', PSAM_VALIDATE_PASSWORD_HASH),
    )

# 2.2.9.3 SAM_VALIDATE_VALIDATION_STATUS
class SAM_VALIDATE_VALIDATION_STATUS(NDRENUM):
    class enumItems(Enum):
        SamValidateSuccess                  = 1
        SamValidatePasswordMustChange       = 2
        SamValidateAccountLockedOut         = 3
        SamValidatePasswordExpired          = 3
        SamValidatePasswordIncorrect        = 3
        SamValidatePasswordIsInHistory      = 3
        SamValidatePasswordTooShort         = 3
        SamValidatePasswordTooLong          = 3
        SamValidatePasswordNotComplexEnough = 3
        SamValidatePasswordTooRecent        = 3
        SamValidatePasswordFilterError      = 3

# 2.2.9.4 SAM_VALIDATE_STANDARD_OUTPUT_ARG
class SAM_VALIDATE_STANDARD_OUTPUT_ARG(NDR):
    structure = (
        ('ChangedPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ValidationStatus', SAM_VALIDATE_VALIDATION_STATUS),
    )

class PSAM_VALIDATE_STANDARD_OUTPUT_ARG(NDRPointer):
    referent = (
        ('Data', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
    )

# 2.2.9.5 SAM_VALIDATE_AUTHENTICATION_INPUT_ARG
class SAM_VALIDATE_AUTHENTICATION_INPUT_ARG(NDR):
    align = 8
    structure = (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('PasswordMatched', NDRSMALL),
    )

# 2.2.9.6 SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG
class SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG(NDR):
    align = 8
    structure = (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ClearPassword', RPC_UNICODE_STRING),
        ('UserAccountName', RPC_UNICODE_STRING),
        ('HashedPassword', SAM_VALIDATE_PASSWORD_HASH),
        ('PasswordMatch', NDRSMALL),
    )

# 2.2.9.7 SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG
class SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG(NDR):
    align = 8
    structure = (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ClearPassword', RPC_UNICODE_STRING),
        ('UserAccountName', RPC_UNICODE_STRING),
        ('HashedPassword', SAM_VALIDATE_PASSWORD_HASH),
        ('PasswordMustChangeAtNextLogon', NDRSMALL),
        ('ClearLockout', NDRSMALL),
    )

# 2.2.9.8 PASSWORD_POLICY_VALIDATION_TYPE
class PASSWORD_POLICY_VALIDATION_TYPE(NDRENUM):
    class enumItems(Enum):
        SamValidateAuthentication   = 1
        SamValidatePasswordChange   = 2
        SamValidatePasswordReset    = 3

# 2.2.9.9 SAM_VALIDATE_INPUT_ARG
class SAM_VALIDATE_INPUT_ARG(NDRUnion):
    union = {
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidateAuthentication : ('ValidateAuthenticationInput', SAM_VALIDATE_AUTHENTICATION_INPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordChange : ('ValidatePasswordChangeInput', SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset  : ('ValidatePasswordResetInput', SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG),
    }

# 2.2.9.10 SAM_VALIDATE_OUTPUT_ARG
class SAM_VALIDATE_OUTPUT_ARG(NDRUnion):
    union = {
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidateAuthentication : ('ValidateAuthenticationOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordChange : ('ValidatePasswordChangeOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset  : ('ValidatePasswordResetOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
    }

class PSAM_VALIDATE_OUTPUT_ARG(NDRPointer):
    referent = (
        ('Data', SAM_VALIDATE_OUTPUT_ARG),
    )

class RPC_UNICODE_STRING_ARRAY(ndr.NDRUniConformantVaryingArray):
    item = RPC_UNICODE_STRING

################################################################################
# RPC CALLS
################################################################################

class SamrConnect(NDRCall):
    opnum = 0
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME2),
       ('DesiredAccess', NDRLONG),
    )

class SamrConnectResponse(NDRCall):
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrCloseHandle(NDRCall):
    opnum = 1
    structure = (
       ('SamHandle',SAMPR_HANDLE),
       ('DesiredAccess', NDRLONG),
    )

class SamrCloseHandleResponse(NDRCall):
    structure = (
       ('SamHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrSetSecurityObject(NDRCall):
    opnum = 2
    structure = (
       ('ObjectHandle',SAMPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR),
    )

class SamrSetSecurityObjectResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrQuerySecurityObject(NDRCall):
    opnum = 3
    structure = (
       ('ObjectHandle',SAMPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
    )

class SamrQuerySecurityObjectResponse(NDRCall):
    structure = (
       ('SecurityDescriptor',PSAMPR_SR_SECURITY_DESCRIPTOR),
       ('ErrorCode',NDRLONG),
    )

class SamrLookupDomainInSamServer(NDRCall):
    opnum = 5
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
    )

class SamrLookupDomainInSamServerResponse(NDRCall):
    structure = (
       ('DomainId',PRPC_SID),
       ('ErrorCode',NDRLONG),
    )

class SamrEnumerateDomainsInSamServer(NDRCall):
    opnum = 6
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('EnumerationContext', NDRLONG),
       ('PreferedMaximumLength', NDRLONG),
    )

class SamrEnumerateDomainsInSamServerResponse(NDRCall):
    structure = (
       ('EnumerationContext',NDRLONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrOpenDomain(NDRCall):
    opnum = 7
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('DesiredAccess', NDRLONG),
       ('DomainId', RPC_SID),
    )

class SamrOpenDomainResponse(NDRCall):
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryInformationDomain(NDRCall):
    opnum = 8
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
    )

class SamrQueryInformationDomainResponse(NDRCall):
    structure = (
       ('Buffer',PSAMPR_DOMAIN_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrSetInformationDomain(NDRCall):
    opnum = 9
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
       ('DomainInformation', SAMPR_DOMAIN_INFO_BUFFER),
    )

class SamrSetInformationDomainResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrCreateGroupInDomain(NDRCall):
    opnum = 10
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('DesiredAccess', NDRLONG),
    )

class SamrCreateGroupInDomainResponse(NDRCall):
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('RelativeId',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrEnumerateGroupsInDomain(NDRCall):
    opnum = 11
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', NDRLONG),
       ('PreferedMaximumLength', NDRLONG),
    )

class SamrCreateUserInDomain(NDRCall):
    opnum = 12
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('DesiredAccess', NDRLONG),
    )

class SamrCreateUserInDomainResponse(NDRCall):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('RelativeId',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrEnumerateGroupsInDomainResponse(NDRCall):
    structure = (
       ('EnumerationContext',NDRLONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrEnumerateUsersInDomain(NDRCall):
    opnum = 13
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', NDRLONG),
       ('UserAccountControl', NDRLONG),
       ('PreferedMaximumLength', NDRLONG),
    )

class SamrEnumerateUsersInDomainResponse(NDRCall):
    structure = (
       ('EnumerationContext',NDRLONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrCreateAliasInDomain(NDRCall):
    opnum = 14
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('AccountName', RPC_UNICODE_STRING),
       ('DesiredAccess', NDRLONG),
    )

class SamrCreateAliasInDomainResponse(NDRCall):
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('RelativeId',NDRLONG),
       ('ErrorCode',NDRLONG),
    )


class SamrEnumerateAliasesInDomain(NDRCall):
    opnum = 15
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', NDRLONG),
       ('PreferedMaximumLength', NDRLONG),
    )

class SamrEnumerateAliasesInDomainResponse(NDRCall):
    structure = (
       ('EnumerationContext',NDRLONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrGetAliasMembership(NDRCall):
    opnum = 16
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('SidArray',SAMPR_PSID_ARRAY),
    )

class SamrGetAliasMembershipResponse(NDRCall):
    structure = (
       ('Membership',SAMPR_ULONG_ARRAY),
       ('ErrorCode',NDRLONG),
    )

class SamrLookupNamesInDomain(NDRCall):
    opnum = 17
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Count',NDRLONG),
       ('Names',RPC_UNICODE_STRING_ARRAY),
    )

class SamrLookupNamesInDomainResponse(NDRCall):
    structure = (
       ('RelativeIds',NDRLONG),
       ('Use',SAMPR_ULONG_ARRAY),
       ('ErrorCode',NDRLONG),
    )

class SamrLookupIdsInDomain(NDRCall):
    opnum = 18
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Count',NDRLONG),
       ('RelativeIds',SAMPR_ULONG_ARRAY),
    )

class SamrLookupIdsInDomainResponse(NDRCall):
    structure = (
       #('Names',PSAMPR_RETURNED_USTRING_ARRAY),
       ('Names',RPC_UNICODE_STRING_ARRAY),
       ('Use',SAMPR_ULONG_ARRAY),
       ('ErrorCode',NDRLONG),
    )

class SamrOpenGroup(NDRCall):
    opnum = 19
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', NDRLONG),
       ('GroupId', NDRLONG),
    )

class SamrOpenGroupResponse(NDRCall):
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryInformationGroup(NDRCall):
    opnum = 20
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('GroupInformationClass', GROUP_INFORMATION_CLASS),
    )

class SamrQueryInformationGroupResponse(NDRCall):
    structure = (
       ('Buffer',PSAMPR_GROUP_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrSetInformationGroup(NDRCall):
    opnum = 21
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('GroupInformationClass', GROUP_INFORMATION_CLASS),
       ('Buffer', SAMPR_GROUP_INFO_BUFFER),
    )

class SamrSetInformationGroupResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrAddMemberToGroup(NDRCall):
    opnum = 22
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId', NDRLONG),
       ('Attributes', NDRLONG),
    )

class SamrAddMemberToGroupResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrDeleteGroup(NDRCall):
    opnum = 23
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
    )

class SamrDeleteGroupResponse(NDRCall):
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrRemoveMemberFromGroup(NDRCall):
    opnum = 24
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId', NDRLONG),
    )

class SamrRemoveMemberFromGroupResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrGetMembersInGroup(NDRCall):
    opnum = 25
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
    )

class SamrGetMembersInGroupResponse(NDRCall):
    structure = (
       ('Members',PSAMPR_GET_MEMBERS_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrSetMemberAttributesOfGroup(NDRCall):
    opnum = 26
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId',NDRLONG),
       ('Attributes',NDRLONG),
    )

class SamrSetMemberAttributesOfGroupResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrOpenAlias(NDRCall):
    opnum = 27
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', NDRLONG),
       ('AliasId', NDRLONG),
    )

class SamrOpenAliasResponse(NDRCall):
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryInformationAlias(NDRCall):
    opnum = 28
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('AliasInformationClass', ALIAS_INFORMATION_CLASS),
    )

class SamrQueryInformationAliasResponse(NDRCall):
    structure = (
       ('Buffer',PSAMPR_ALIAS_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrSetInformationAlias(NDRCall):
    opnum = 29
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('AliasInformationClass', ALIAS_INFORMATION_CLASS),
       ('Buffer',SAMPR_ALIAS_INFO_BUFFER),
    )

class SamrSetInformationAliasResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrDeleteAlias(NDRCall):
    opnum = 30
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
    )

class SamrDeleteAliasResponse(NDRCall):
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrAddMemberToAlias(NDRCall):
    opnum = 31
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MemberId', RPC_SID),
    )

class SamrAddMemberToAliasResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrRemoveMemberFromAlias(NDRCall):
    opnum = 32
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MemberId', RPC_SID),
    )

class SamrRemoveMemberFromAliasResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrGetMembersInAlias(NDRCall):
    opnum = 33
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
    )

class SamrGetMembersInAliasResponse(NDRCall):
    structure = (
       ('Members',SAMPR_PSID_ARRAY_OUT),
       ('ErrorCode',NDRLONG),
    )

class SamrOpenUser(NDRCall):
    opnum = 34
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', NDRLONG),
       ('UserId', NDRLONG),
    )

class SamrOpenUserResponse(NDRCall):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrDeleteUser(NDRCall):
    opnum = 35
    structure = (
       ('UserHandle',SAMPR_HANDLE),
    )

class SamrDeleteUserResponse(NDRCall):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryInformationUser(NDRCall):
    opnum = 36
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
    )

class SamrQueryInformationUserResponse(NDRCall):
    structure = (
       ('Buffer',PSAMPR_USER_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrSetInformationUser(NDRCall):
    opnum = 37
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
       ('Buffer',SAMPR_USER_INFO_BUFFER),
    )

class SamrSetInformationUserResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrChangePasswordUser(NDRCall):
    opnum = 38
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('LmPresent', NDRSMALL ),
       ('OldLmEncryptedWithNewLm',PENCRYPTED_LM_OWF_PASSWORD),
       ('NewLmEncryptedWithOldLm',PENCRYPTED_LM_OWF_PASSWORD),
       ('NtPresent',NDRSMALL),
       ('OldNtEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('NewNtEncryptedWithOldNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('NtCrossEncryptionPresent',NDRSMALL),
       ('NewNtEncryptedWithNewLm',PENCRYPTED_NT_OWF_PASSWORD),
       ('LmCrossEncryptionPresent',NDRSMALL),
       ('NewLmEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
    )

class SamrChangePasswordUserResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrGetGroupsForUser(NDRCall):
    opnum = 39
    structure = (
       ('UserHandle',SAMPR_HANDLE),
    )

class SamrGetGroupsForUserResponse(NDRCall):
    structure = (
       ('Groups',PSAMPR_GET_GROUPS_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryDisplayInformation(NDRCall):
    opnum = 40
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', NDRLONG),
       ('EntryCount',NDRLONG),
       ('PreferredMaximumLength',NDRLONG),
    )

class SamrQueryDisplayInformationResponse(NDRCall):
    structure = (
       ('TotalAvailable',NDRLONG),
       ('TotalReturned',NDRLONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrGetDisplayEnumerationIndex(NDRCall):
    opnum = 41
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Prefix', RPC_UNICODE_STRING),
    )

class SamrGetDisplayEnumerationIndexResponse(NDRCall):
    structure = (
       ('Index',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrGetUserDomainPasswordInformation(NDRCall):
    opnum = 44
    structure = (
       ('UserHandle',SAMPR_HANDLE),
    )

class SamrGetUserDomainPasswordInformationResponse(NDRCall):
    structure = (
       ('PasswordInformation',USER_DOMAIN_PASSWORD_INFORMATION),
       ('ErrorCode',NDRLONG),
    )

class SamrRemoveMemberFromForeignDomain(NDRCall):
    opnum = 45
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('MemberSid', RPC_SID),
    )

class SamrRemoveMemberFromForeignDomainResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrQueryInformationDomain2(NDRCall):
    opnum = 46
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
    )

class SamrQueryInformationDomain2Response(NDRCall):
    structure = (
       ('Buffer',PSAMPR_DOMAIN_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryInformationUser2(NDRCall):
    opnum = 47
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
    )

class SamrQueryInformationUser2Response(NDRCall):
    structure = (
       ('Buffer',PSAMPR_USER_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryDisplayInformation2(NDRCall):
    opnum = 48
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', NDRLONG),
       ('EntryCount',NDRLONG),
       ('PreferredMaximumLength',NDRLONG),
    )

class SamrQueryDisplayInformation2Response(NDRCall):
    structure = (
       ('TotalAvailable',NDRLONG),
       ('TotalReturned',NDRLONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrGetDisplayEnumerationIndex2(NDRCall):
    opnum = 49
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Prefix', RPC_UNICODE_STRING),
    )

class SamrGetDisplayEnumerationIndex2Response(NDRCall):
    structure = (
       ('Index',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrCreateUser2InDomain(NDRCall):
    opnum = 50
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('AccountType', NDRLONG),
       ('DesiredAccess', NDRLONG),
    )

class SamrCreateUser2InDomainResponse(NDRCall):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('GrantedAccess',NDRLONG),
       ('RelativeId',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

class SamrQueryDisplayInformation3(NDRCall):
    opnum = 51
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', NDRLONG),
       ('EntryCount',NDRLONG),
       ('PreferredMaximumLength',NDRLONG),
    )

class SamrQueryDisplayInformation3Response(NDRCall):
    structure = (
       ('TotalAvailable',NDRLONG),
       ('TotalReturned',NDRLONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',NDRLONG),
    )

class SamrAddMultipleMembersToAlias(NDRCall):
    opnum = 52
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MembersBuffer', SAMPR_PSID_ARRAY),
    )

class SamrAddMultipleMembersToAliasResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrRemoveMultipleMembersFromAlias(NDRCall):
    opnum = 53
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MembersBuffer', SAMPR_PSID_ARRAY),
    )

class SamrRemoveMultipleMembersFromAliasResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrOemChangePasswordUser2(NDRCall):
    opnum = 54
    structure = (
       ('ServerName', PRPC_STRING),
       ('UserName', RPC_STRING),
       ('NewPasswordEncryptedWithOldLm', PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldLmOwfPasswordEncryptedWithNewLm', PENCRYPTED_LM_OWF_PASSWORD),
    )

class SamrOemChangePasswordUser2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrUnicodeChangePasswordUser2(NDRCall):
    opnum = 55
    structure = (
       ('ServerName', PRPC_UNICODE_STRING),
       ('UserName', RPC_UNICODE_STRING),
       ('NewPasswordEncryptedWithOldNt',PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldNtOwfPasswordEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('LmPresent',NDRSMALL),
       ('NewPasswordEncryptedWithOldLm',PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldLmOwfPasswordEncryptedWithNewNt',PENCRYPTED_LM_OWF_PASSWORD),
    )

class SamrUnicodeChangePasswordUser2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrGetDomainPasswordInformation(NDRCall):
    opnum = 56
    structure = (
       #('BindingHandle',SAMPR_HANDLE),
       ('Unused', UNIQUE_RPC_UNICODE_STRING),
    )

class SamrGetDomainPasswordInformationResponse(NDRCall):
    structure = (
       ('PasswordInformation',USER_DOMAIN_PASSWORD_INFORMATION),
       ('ErrorCode',NDRLONG),
    )

class SamrConnect2(NDRCall):
    opnum = 57
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('DesiredAccess', NDRLONG),
    )

class SamrConnect2Response(NDRCall):
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrSetInformationUser2(NDRCall):
    opnum = 58
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS),
       ('Buffer', SAMPR_USER_INFO_BUFFER),
    )

class SamrSetInformationUser2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrConnect4(NDRCall):
    opnum = 62
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('ClientRevision', NDRLONG),
       ('DesiredAccess', NDRLONG),
    )

class SamrConnect4Response(NDRCall):
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrConnect5(NDRCall):
    opnum = 64
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('DesiredAccess', NDRLONG),
       ('InVersion', NDRLONG),
       ('InRevisionInfo',SAMPR_REVISION_INFO),
    )

class SamrConnect5Response(NDRCall):
    structure = (
       ('OutVersion',NDRLONG),
       ('OutRevisionInfo',SAMPR_REVISION_INFO),
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',NDRLONG),
    )

class SamrRidToSid(NDRCall):
    opnum = 65
    structure = (
       ('ObjectHandle',SAMPR_HANDLE),
       ('Rid', NDRLONG),
    )

class SamrRidToSidResponse(NDRCall):
    structure = (
       ('Sid',PRPC_SID),
       ('ErrorCode',NDRLONG),
    )

class SamrSetDSRMPassword(NDRCall):
    opnum = 66
    structure = (
       ('Unused', UNIQUE_RPC_UNICODE_STRING),
       ('UserId',NDRLONG),
       ('EncryptedNtOwfPassword',PENCRYPTED_NT_OWF_PASSWORD),
    )

class SamrSetDSRMPasswordResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

class SamrValidatePassword(NDRCall):
    opnum = 67
    structure = (
       ('ValidationType', PASSWORD_POLICY_VALIDATION_TYPE),
       ('InputArg',SAM_VALIDATE_INPUT_ARG),
    )

class SamrValidatePasswordResponse(NDRCall):
    structure = (
       ('OutputArg',PSAM_VALIDATE_OUTPUT_ARG),
       ('ErrorCode',NDRLONG),
    )



################################################################################
# HELPER FUNCTIONS
################################################################################

