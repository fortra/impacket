# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-SAMR] Interface implementation
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
from __future__ import division
from __future__ import print_function
from binascii import unhexlify

from impacket.dcerpc.v5.ndr import NDRCALL, NDR, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
    NDRUniConformantVaryingArray, NDRENUM
from impacket.dcerpc.v5.dtypes import NULL, RPC_UNICODE_STRING, ULONG, USHORT, UCHAR, LARGE_INTEGER, RPC_SID, LONG, STR, \
    LPBYTE, SECURITY_INFORMATION, PRPC_SID, PRPC_UNICODE_STRING, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import nt_errors, LOG
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.structure import Structure

import struct
import os
from hashlib import md5
from Cryptodome.Cipher import ARC4

MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES:
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1]
            return 'SAMR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SAMR SessionError: unknown error code: 0x%x' % self.error_code

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
DOMAIN_GROUP_RID_ADMINS               = 0x00000200
DOMAIN_GROUP_RID_USERS                = 0x00000201
DOMAIN_GROUP_RID_COMPUTERS            = 0x00000203
DOMAIN_GROUP_RID_CONTROLLERS          = 0x00000204
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
class RPC_UNICODE_STRING_ARRAY(NDRUniConformantVaryingArray):
    item = RPC_UNICODE_STRING

class RPC_UNICODE_STRING_ARRAY_C(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

class PRPC_UNICODE_STRING_ARRAY(NDRPOINTER):
    referent = (
        ('Data',RPC_UNICODE_STRING_ARRAY_C),
    )

# 2.2.2.1 RPC_STRING, PRPC_STRING
class RPC_STRING(NDRSTRUCT):
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
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
        # Here just print the data
        print(" %r" % (self['Data']), end=' ')

class PRPC_STRING(NDRPOINTER):
    referent = (
        ('Data', RPC_STRING),
    )

# 2.2.2.2 OLD_LARGE_INTEGER
class OLD_LARGE_INTEGER(NDRSTRUCT):
    structure = (
        ('LowPart',ULONG),
        ('HighPart',LONG),
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
class USHORT_ARRAY(NDRUniConformantVaryingArray):
    item = '<H'
    pass

class PUSHORT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', USHORT_ARRAY),
    )

class RPC_SHORT_BLOB(NDRSTRUCT):
    structure = (
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer',PUSHORT_ARRAY),
    )

# 2.2.3.2 SAMPR_HANDLE
class SAMPR_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=b""'),
    )
    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4

# 2.2.3.3 ENCRYPTED_LM_OWF_PASSWORD, ENCRYPTED_NT_OWF_PASSWORD
class ENCRYPTED_LM_OWF_PASSWORD(NDRSTRUCT):
    structure = (
        ('Data', '16s=b""'),
    )
    def getAlignment(self):
        return 1

ENCRYPTED_NT_OWF_PASSWORD = ENCRYPTED_LM_OWF_PASSWORD

class PENCRYPTED_LM_OWF_PASSWORD(NDRPOINTER):
    referent = (
        ('Data', ENCRYPTED_LM_OWF_PASSWORD),
    )

PENCRYPTED_NT_OWF_PASSWORD = PENCRYPTED_LM_OWF_PASSWORD

# 2.2.3.4 SAMPR_ULONG_ARRAY
#class SAMPR_ULONG_ARRAY(NDRUniConformantVaryingArray):
#    item = '<L'
class ULONG_ARRAY(NDRUniConformantArray):
    item = ULONG

class PULONG_ARRAY(NDRPOINTER):
    referent = (
        ('Data', ULONG_ARRAY),
    )

class ULONG_ARRAY_CV(NDRUniConformantVaryingArray):
    item = ULONG

class SAMPR_ULONG_ARRAY(NDRSTRUCT):
    structure = (
        ('Count', ULONG),
        ('Element', PULONG_ARRAY),
    )

# 2.2.3.5 SAMPR_SID_INFORMATION
class SAMPR_SID_INFORMATION(NDRSTRUCT):
    structure = (
        ('SidPointer', RPC_SID),
    )

class PSAMPR_SID_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', SAMPR_SID_INFORMATION),
    )

class SAMPR_SID_INFORMATION_ARRAY(NDRUniConformantArray):
    item = PSAMPR_SID_INFORMATION

class PSAMPR_SID_INFORMATION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', SAMPR_SID_INFORMATION_ARRAY),
    )

# 2.2.3.6 SAMPR_PSID_ARRAY
class SAMPR_PSID_ARRAY(NDRSTRUCT):
    structure = (
        ('Count', ULONG),
        ('Sids', PSAMPR_SID_INFORMATION_ARRAY),
    )

# 2.2.3.7 SAMPR_PSID_ARRAY_OUT
class SAMPR_PSID_ARRAY_OUT(NDRSTRUCT):
    structure = (
        ('Count', ULONG),
        ('Sids', PSAMPR_SID_INFORMATION_ARRAY),
    )

# 2.2.3.8 SAMPR_RETURNED_USTRING_ARRAY
class SAMPR_RETURNED_USTRING_ARRAY(NDRSTRUCT):
    structure = (
        ('Count', ULONG),
        ('Element', PRPC_UNICODE_STRING_ARRAY),
    )

# 2.2.3.9 SAMPR_RID_ENUMERATION
class SAMPR_RID_ENUMERATION(NDRSTRUCT):
    structure = (
        ('RelativeId',ULONG),
        ('Name',RPC_UNICODE_STRING),
    )

class SAMPR_RID_ENUMERATION_ARRAY(NDRUniConformantArray):
    item = SAMPR_RID_ENUMERATION

class PSAMPR_RID_ENUMERATION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', SAMPR_RID_ENUMERATION_ARRAY),
    )

# 2.2.3.10 SAMPR_ENUMERATION_BUFFER
class SAMPR_ENUMERATION_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead',ULONG ),
        ('Buffer',PSAMPR_RID_ENUMERATION_ARRAY ),
    )

class PSAMPR_ENUMERATION_BUFFER(NDRPOINTER):
    referent = (
        ('Data',SAMPR_ENUMERATION_BUFFER),
    )

# 2.2.3.11 SAMPR_SR_SECURITY_DESCRIPTOR
class CHAR_ARRAY(NDRUniConformantArray):
    pass

class PCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', CHAR_ARRAY),
    )

class SAMPR_SR_SECURITY_DESCRIPTOR(NDRSTRUCT):
    structure = (
        ('Length', ULONG),
        ('SecurityDescriptor', PCHAR_ARRAY),
    )

class PSAMPR_SR_SECURITY_DESCRIPTOR(NDRPOINTER):
    referent = (
        ('Data', SAMPR_SR_SECURITY_DESCRIPTOR),
    )

# 2.2.3.12 GROUP_MEMBERSHIP
class GROUP_MEMBERSHIP(NDRSTRUCT):
    structure = (
        ('RelativeId',ULONG),
        ('Attributes',ULONG),
    )

class GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = GROUP_MEMBERSHIP

class PGROUP_MEMBERSHIP_ARRAY(NDRPOINTER):
    referent = (
        ('Data',GROUP_MEMBERSHIP_ARRAY),
    )

# 2.2.3.13 SAMPR_GET_GROUPS_BUFFER
class SAMPR_GET_GROUPS_BUFFER(NDRSTRUCT):
    structure = (
        ('MembershipCount',ULONG),
        ('Groups',PGROUP_MEMBERSHIP_ARRAY),
    )

class PSAMPR_GET_GROUPS_BUFFER(NDRPOINTER):
    referent = (
        ('Data',SAMPR_GET_GROUPS_BUFFER),
    )

# 2.2.3.14 SAMPR_GET_MEMBERS_BUFFER
class SAMPR_GET_MEMBERS_BUFFER(NDRSTRUCT):
    structure = (
        ('MemberCount', ULONG),
        ('Members', PULONG_ARRAY),
        ('Attributes', PULONG_ARRAY),
    )

class PSAMPR_GET_MEMBERS_BUFFER(NDRPOINTER):
    referent = (
        ('Data', SAMPR_GET_MEMBERS_BUFFER),
    )

# 2.2.3.15 SAMPR_REVISION_INFO_V1
class SAMPR_REVISION_INFO_V1(NDRSTRUCT):
    structure = (
       ('Revision',ULONG),
       ('SupportedFeatures',ULONG),
    )

# 2.2.3.16 SAMPR_REVISION_INFO
class SAMPR_REVISION_INFO(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        1: ('V1', SAMPR_REVISION_INFO_V1),
    }

# 2.2.3.17 USER_DOMAIN_PASSWORD_INFORMATION
class USER_DOMAIN_PASSWORD_INFORMATION(NDRSTRUCT):
    structure = (
        ('MinPasswordLength', USHORT),
        ('PasswordProperties', ULONG),
    )

# 2.2.4.2 DOMAIN_SERVER_ENABLE_STATE
class DOMAIN_SERVER_ENABLE_STATE(NDRENUM):
    class enumItems(Enum):
        DomainServerEnabled  = 1
        DomainServerDisabled = 2

# 2.2.4.3 DOMAIN_STATE_INFORMATION
class DOMAIN_STATE_INFORMATION(NDRSTRUCT):
    structure = (
        ('DomainServerState', DOMAIN_SERVER_ENABLE_STATE),
    )

# 2.2.4.4 DOMAIN_SERVER_ROLE
class DOMAIN_SERVER_ROLE(NDRENUM):
    class enumItems(Enum):
        DomainServerRoleBackup  = 2
        DomainServerRolePrimary = 3

# 2.2.4.5 DOMAIN_PASSWORD_INFORMATION
class DOMAIN_PASSWORD_INFORMATION(NDRSTRUCT):
    structure = (
        ('MinPasswordLength', USHORT),
        ('PasswordHistoryLength', USHORT),
        ('PasswordProperties', ULONG),
        ('MaxPasswordAge', OLD_LARGE_INTEGER),
        ('MinPasswordAge', OLD_LARGE_INTEGER),
    )

# 2.2.4.6 DOMAIN_LOGOFF_INFORMATION
class DOMAIN_LOGOFF_INFORMATION(NDRSTRUCT):
    structure = (
        ('ForceLogoff', OLD_LARGE_INTEGER),
    )

# 2.2.4.7 DOMAIN_SERVER_ROLE_INFORMATION
class DOMAIN_SERVER_ROLE_INFORMATION(NDRSTRUCT):
    structure = (
        ('DomainServerRole', DOMAIN_SERVER_ROLE),
    )

# 2.2.4.8 DOMAIN_MODIFIED_INFORMATION
class DOMAIN_MODIFIED_INFORMATION(NDRSTRUCT):
    structure = (
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('CreationTime', OLD_LARGE_INTEGER),
    )

# 2.2.4.9 DOMAIN_MODIFIED_INFORMATION2
class DOMAIN_MODIFIED_INFORMATION2(NDRSTRUCT):
    structure = (
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('CreationTime', OLD_LARGE_INTEGER),
        ('ModifiedCountAtLastPromotion', OLD_LARGE_INTEGER),
    )

# 2.2.4.10 SAMPR_DOMAIN_GENERAL_INFORMATION
class SAMPR_DOMAIN_GENERAL_INFORMATION(NDRSTRUCT):
    structure = (
        ('ForceLogoff', OLD_LARGE_INTEGER),
        ('OemInformation', RPC_UNICODE_STRING),
        ('DomainName', RPC_UNICODE_STRING),
        ('ReplicaSourceNodeName', RPC_UNICODE_STRING),
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('DomainServerState', ULONG),
        ('DomainServerRole', ULONG),
        ('UasCompatibilityRequired', UCHAR),
        ('UserCount', ULONG),
        ('GroupCount', ULONG),
        ('AliasCount', ULONG),
    )

# 2.2.4.11 SAMPR_DOMAIN_GENERAL_INFORMATION2
class SAMPR_DOMAIN_GENERAL_INFORMATION2(NDRSTRUCT):
    structure = (
        ('I1', SAMPR_DOMAIN_GENERAL_INFORMATION),
        ('LockoutDuration', LARGE_INTEGER),
        ('LockoutObservationWindow', LARGE_INTEGER),
        ('LockoutThreshold', USHORT),
    )

# 2.2.4.12 SAMPR_DOMAIN_OEM_INFORMATION
class SAMPR_DOMAIN_OEM_INFORMATION(NDRSTRUCT):
    structure = (
        ('OemInformation', RPC_UNICODE_STRING),
    )

# 2.2.4.13 SAMPR_DOMAIN_NAME_INFORMATION
class SAMPR_DOMAIN_NAME_INFORMATION(NDRSTRUCT):
    structure = (
        ('DomainName', RPC_UNICODE_STRING),
    )

# 2.2.4.14 SAMPR_DOMAIN_REPLICATION_INFORMATION
class SAMPR_DOMAIN_REPLICATION_INFORMATION(NDRSTRUCT):
    structure = (
        ('ReplicaSourceNodeName', RPC_UNICODE_STRING),
    )

# 2.2.4.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION
class SAMPR_DOMAIN_LOCKOUT_INFORMATION(NDRSTRUCT):
    structure = (
        ('LockoutDuration', LARGE_INTEGER),
        ('LockoutObservationWindow', LARGE_INTEGER),
        ('LockoutThreshold', USHORT),
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
class SAMPR_DOMAIN_INFO_BUFFER(NDRUNION):
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

class PSAMPR_DOMAIN_INFO_BUFFER(NDRPOINTER):
    referent = (
        ('Data', SAMPR_DOMAIN_INFO_BUFFER),
    )

# 2.2.5.2 GROUP_ATTRIBUTE_INFORMATION
class GROUP_ATTRIBUTE_INFORMATION(NDRSTRUCT):
    structure = (
        ('Attributes', ULONG),
    )

# 2.2.5.3 SAMPR_GROUP_GENERAL_INFORMATION
class SAMPR_GROUP_GENERAL_INFORMATION(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING),
        ('Attributes', ULONG),
        ('MemberCount', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.5.4 SAMPR_GROUP_NAME_INFORMATION
class SAMPR_GROUP_NAME_INFORMATION(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING),
    )

# 2.2.5.5 SAMPR_GROUP_ADM_COMMENT_INFORMATION
class SAMPR_GROUP_ADM_COMMENT_INFORMATION(NDRSTRUCT):
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
class SAMPR_GROUP_INFO_BUFFER(NDRUNION):
    union = {
        GROUP_INFORMATION_CLASS.GroupGeneralInformation      : ('General', SAMPR_GROUP_GENERAL_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupNameInformation         : ('Name', SAMPR_GROUP_NAME_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupAttributeInformation    : ('Attribute', GROUP_ATTRIBUTE_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupAdminCommentInformation : ('AdminComment', SAMPR_GROUP_ADM_COMMENT_INFORMATION),
        GROUP_INFORMATION_CLASS.GroupReplicationInformation  : ('DoNotUse', SAMPR_GROUP_GENERAL_INFORMATION),
    }

class PSAMPR_GROUP_INFO_BUFFER(NDRPOINTER):
    referent = (
        ('Data', SAMPR_GROUP_INFO_BUFFER),
    )

# 2.2.6.2 SAMPR_ALIAS_GENERAL_INFORMATION
class SAMPR_ALIAS_GENERAL_INFORMATION(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING),
        ('MemberCount', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.6.3 SAMPR_ALIAS_NAME_INFORMATION
class SAMPR_ALIAS_NAME_INFORMATION(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING),
    )

# 2.2.6.4 SAMPR_ALIAS_ADM_COMMENT_INFORMATION
class SAMPR_ALIAS_ADM_COMMENT_INFORMATION(NDRSTRUCT):
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
class SAMPR_ALIAS_INFO_BUFFER(NDRUNION):
    union = {
        ALIAS_INFORMATION_CLASS.AliasGeneralInformation      : ('General', SAMPR_ALIAS_GENERAL_INFORMATION),
        ALIAS_INFORMATION_CLASS.AliasNameInformation         : ('Name', SAMPR_ALIAS_NAME_INFORMATION),
        ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation : ('AdminComment', SAMPR_ALIAS_ADM_COMMENT_INFORMATION),
    }

class PSAMPR_ALIAS_INFO_BUFFER(NDRPOINTER):
    referent = (
        ('Data', SAMPR_ALIAS_INFO_BUFFER),
    )

# 2.2.7.2 USER_PRIMARY_GROUP_INFORMATION
class USER_PRIMARY_GROUP_INFORMATION(NDRSTRUCT):
    structure = (
        ('PrimaryGroupId', ULONG),
    )

# 2.2.7.3 USER_CONTROL_INFORMATION
class USER_CONTROL_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserAccountControl', ULONG),
    )

# 2.2.7.4 USER_EXPIRES_INFORMATION
class USER_EXPIRES_INFORMATION(NDRSTRUCT):
    structure = (
        ('AccountExpires', OLD_LARGE_INTEGER),
    )

# 2.2.7.5 SAMPR_LOGON_HOURS
class LOGON_HOURS_ARRAY(NDRUniConformantVaryingArray):
    pass

class PLOGON_HOURS_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LOGON_HOURS_ARRAY),
    )

class SAMPR_LOGON_HOURS(NDRSTRUCT):
    structure = (
        #('UnitsPerWeek', NDRSHORT),
        ('UnitsPerWeek', ULONG),
        ('LogonHours', PLOGON_HOURS_ARRAY),
    )

    def getData(self, soFar = 0):
        if self['LogonHours'] != 0:
            self['UnitsPerWeek'] = len(self['LogonHours']) * 8
        return NDR.getData(self, soFar)

# 2.2.7.6 SAMPR_USER_ALL_INFORMATION
class SAMPR_USER_ALL_INFORMATION(NDRSTRUCT):
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

        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('UserAccountControl', ULONG),
        ('WhichFields', ULONG),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('CountryCode', USHORT),
        ('CodePage', USHORT),
        ('LmPasswordPresent', UCHAR),
        ('NtPasswordPresent', UCHAR),
        ('PasswordExpired', UCHAR),
        ('PrivateDataSensitive', UCHAR),
    )

# 2.2.7.7 SAMPR_USER_GENERAL_INFORMATION
class SAMPR_USER_GENERAL_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('PrimaryGroupId', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
        ('UserComment', RPC_UNICODE_STRING),
    )

# 2.2.7.8 SAMPR_USER_PREFERENCES_INFORMATION
class SAMPR_USER_PREFERENCES_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserComment', RPC_UNICODE_STRING),
        ('Reserved1', RPC_UNICODE_STRING),
        ('CountryCode', USHORT),
        ('CodePage', USHORT),
    )

# 2.2.7.9 SAMPR_USER_PARAMETERS_INFORMATION
class SAMPR_USER_PARAMETERS_INFORMATION(NDRSTRUCT):
    structure = (
        ('Parameters', RPC_UNICODE_STRING),
    )

# 2.2.7.10 SAMPR_USER_LOGON_INFORMATION
class SAMPR_USER_LOGON_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
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
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('UserAccountControl', ULONG),
    )

# 2.2.7.11 SAMPR_USER_ACCOUNT_INFORMATION
class SAMPR_USER_ACCOUNT_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('LogonHours', SAMPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('UserAccountControl', ULONG)
    )

# 2.2.7.12 SAMPR_USER_A_NAME_INFORMATION
class SAMPR_USER_A_NAME_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
    )

# 2.2.7.13 SAMPR_USER_F_NAME_INFORMATION
class SAMPR_USER_F_NAME_INFORMATION(NDRSTRUCT):
    structure = (
        ('FullName', RPC_UNICODE_STRING),
    )

# 2.2.7.14 SAMPR_USER_NAME_INFORMATION
class SAMPR_USER_NAME_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
    )

# 2.2.7.15 SAMPR_USER_HOME_INFORMATION
class SAMPR_USER_HOME_INFORMATION(NDRSTRUCT):
    structure = (
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
    )

# 2.2.7.16 SAMPR_USER_SCRIPT_INFORMATION
class SAMPR_USER_SCRIPT_INFORMATION(NDRSTRUCT):
    structure = (
        ('ScriptPath', RPC_UNICODE_STRING),
    )

# 2.2.7.17 SAMPR_USER_PROFILE_INFORMATION
class SAMPR_USER_PROFILE_INFORMATION(NDRSTRUCT):
    structure = (
        ('ProfilePath', RPC_UNICODE_STRING),
    )

# 2.2.7.18 SAMPR_USER_ADMIN_COMMENT_INFORMATION
class SAMPR_USER_ADMIN_COMMENT_INFORMATION(NDRSTRUCT):
    structure = (
        ('AdminComment', RPC_UNICODE_STRING),
    )

# 2.2.7.19 SAMPR_USER_WORKSTATIONS_INFORMATION
class SAMPR_USER_WORKSTATIONS_INFORMATION(NDRSTRUCT):
    structure = (
        ('WorkStations', RPC_UNICODE_STRING),
    )

# 2.2.7.20 SAMPR_USER_LOGON_HOURS_INFORMATION
class SAMPR_USER_LOGON_HOURS_INFORMATION(NDRSTRUCT):
    structure = (
        ('LogonHours', SAMPR_LOGON_HOURS),
    )

# 2.2.7.21 SAMPR_ENCRYPTED_USER_PASSWORD
class SAMPR_USER_PASSWORD(NDRSTRUCT):
    structure = (
        ('Buffer', '512s=b""'),
        ('Length', ULONG),
    )
    def getAlignment(self):
        return 4


class SAMPR_ENCRYPTED_USER_PASSWORD(NDRSTRUCT):
    structure = (
        ('Buffer', '516s=b""'),
    )
    def getAlignment(self):
        return 1

class PSAMPR_ENCRYPTED_USER_PASSWORD(NDRPOINTER):
    referent = (
        ('Data', SAMPR_ENCRYPTED_USER_PASSWORD),
    )

# 2.2.7.22 SAMPR_ENCRYPTED_USER_PASSWORD_NEW
class SAMPR_ENCRYPTED_USER_PASSWORD_NEW(NDRSTRUCT):
    structure = (
        ('Buffer', '532s=b""'),
    )
    def getAlignment(self):
        return 1

# 2.2.7.23 SAMPR_USER_INTERNAL1_INFORMATION
class SAMPR_USER_INTERNAL1_INFORMATION(NDRSTRUCT):
    structure = (
        ('EncryptedNtOwfPassword', ENCRYPTED_NT_OWF_PASSWORD),
        ('EncryptedLmOwfPassword', ENCRYPTED_LM_OWF_PASSWORD),
        ('NtPasswordPresent', UCHAR),
        ('LmPasswordPresent', UCHAR),
        ('PasswordExpired', UCHAR),
    )

# 2.2.7.24 SAMPR_USER_INTERNAL4_INFORMATION
class SAMPR_USER_INTERNAL4_INFORMATION(NDRSTRUCT):
    structure = (
        ('I1', SAMPR_USER_ALL_INFORMATION),
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD),
    )

# 2.2.7.25 SAMPR_USER_INTERNAL4_INFORMATION_NEW
class SAMPR_USER_INTERNAL4_INFORMATION_NEW(NDRSTRUCT):
    structure = (
        ('I1', SAMPR_USER_ALL_INFORMATION),
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW),
    )

# 2.2.7.26 SAMPR_USER_INTERNAL5_INFORMATION
class SAMPR_USER_INTERNAL5_INFORMATION(NDRSTRUCT):
    structure = (
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD),
        ('PasswordExpired', UCHAR),
    )

# 2.2.7.27 SAMPR_USER_INTERNAL5_INFORMATION_NEW
class SAMPR_USER_INTERNAL5_INFORMATION_NEW(NDRSTRUCT):
    structure = (
        ('UserPassword', SAMPR_ENCRYPTED_USER_PASSWORD_NEW),
        ('PasswordExpired', UCHAR),
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
class SAMPR_USER_INFO_BUFFER(NDRUNION):
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

class PSAMPR_USER_INFO_BUFFER(NDRPOINTER):
    referent = (
        ('Data', SAMPR_USER_INFO_BUFFER),
    )

class PSAMPR_SERVER_NAME2(NDRPOINTER):
    referent = (
        ('Data', '4s=b""'),
    )

# 2.2.8.2 SAMPR_DOMAIN_DISPLAY_USER
class SAMPR_DOMAIN_DISPLAY_USER(NDRSTRUCT):
    structure = (
        ('Index',ULONG),
        ('Rid',ULONG),
        ('AccountControl',ULONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
        ('FullName',RPC_UNICODE_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_USER_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_USER

class PSAMPR_DOMAIN_DISPLAY_USER_ARRAY(NDRPOINTER):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_USER_ARRAY),
    )

# 2.2.8.3 SAMPR_DOMAIN_DISPLAY_MACHINE
class SAMPR_DOMAIN_DISPLAY_MACHINE(NDRSTRUCT):
    structure = (
        ('Index',ULONG),
        ('Rid',ULONG),
        ('AccountControl',ULONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_MACHINE

class PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY(NDRPOINTER):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY),
    )

# 2.2.8.4 SAMPR_DOMAIN_DISPLAY_GROUP
class SAMPR_DOMAIN_DISPLAY_GROUP(NDRSTRUCT):
    structure = (
        ('Index',ULONG),
        ('Rid',ULONG),
        ('AccountControl',ULONG),
        ('AccountName',RPC_UNICODE_STRING),
        ('AdminComment',RPC_UNICODE_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_GROUP

class PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY(NDRPOINTER):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_GROUP_ARRAY),
    )

# 2.2.8.5 SAMPR_DOMAIN_DISPLAY_OEM_USER
class SAMPR_DOMAIN_DISPLAY_OEM_USER(NDRSTRUCT):
    structure = (
        ('Index',ULONG),
        ('OemAccountName',RPC_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_OEM_USER

class PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY(NDRPOINTER):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY),
    )

# 2.2.8.6 SAMPR_DOMAIN_DISPLAY_OEM_GROUP
class SAMPR_DOMAIN_DISPLAY_OEM_GROUP(NDRSTRUCT):
    structure = (
        ('Index',ULONG),
        ('OemAccountName',RPC_STRING),
    )

class SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY(NDRUniConformantArray):
    item = SAMPR_DOMAIN_DISPLAY_OEM_GROUP

class PSAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY(NDRPOINTER):
    referent = (
        ('Data',SAMPR_DOMAIN_DISPLAY_OEM_GROUP_ARRAY),
    )

#2.2.8.7 SAMPR_DOMAIN_DISPLAY_USER_BUFFER
class SAMPR_DOMAIN_DISPLAY_USER_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_USER_ARRAY),
    )

# 2.2.8.8 SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER
class SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_MACHINE_ARRAY),
    )

# 2.2.8.9 SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER
class SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_GROUP_ARRAY),
    )

# 2.2.8.10 SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER
class SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', PSAMPR_DOMAIN_DISPLAY_OEM_USER_ARRAY),
    )

# 2.2.8.11 SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER
class SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
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
class SAMPR_DISPLAY_INFO_BUFFER(NDRUNION):
    union = {
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser     : ('UserInformation', SAMPR_DOMAIN_DISPLAY_USER_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine  : ('MachineInformation', SAMPR_DOMAIN_DISPLAY_MACHINE_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup    : ('GroupInformation', SAMPR_DOMAIN_DISPLAY_GROUP_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemUser  : ('OemUserInformation', SAMPR_DOMAIN_DISPLAY_OEM_USER_BUFFER),
        DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup : ('OemGroupInformation', SAMPR_DOMAIN_DISPLAY_OEM_GROUP_BUFFER),
    }

# 2.2.9.1 SAM_VALIDATE_PASSWORD_HASH
class SAM_VALIDATE_PASSWORD_HASH(NDRSTRUCT):
    structure = (
        ('Length', ULONG),
        ('Hash', LPBYTE),
    )

class PSAM_VALIDATE_PASSWORD_HASH(NDRPOINTER):
    referent = (
        ('Data', SAM_VALIDATE_PASSWORD_HASH),
    )

# 2.2.9.2 SAM_VALIDATE_PERSISTED_FIELDS
class SAM_VALIDATE_PERSISTED_FIELDS(NDRSTRUCT):
    structure = (
        ('PresentFields', ULONG),
        ('PasswordLastSet', LARGE_INTEGER),
        ('BadPasswordTime', LARGE_INTEGER),
        ('LockoutTime', LARGE_INTEGER),
        ('BadPasswordCount', ULONG),
        ('PasswordHistoryLength', ULONG),
        ('PasswordHistory', PSAM_VALIDATE_PASSWORD_HASH),
    )

# 2.2.9.3 SAM_VALIDATE_VALIDATION_STATUS
class SAM_VALIDATE_VALIDATION_STATUS(NDRENUM):
    class enumItems(Enum):
        SamValidateSuccess                  = 0
        SamValidatePasswordMustChange       = 1
        SamValidateAccountLockedOut         = 2
        SamValidatePasswordExpired          = 3
        SamValidatePasswordIncorrect        = 4
        SamValidatePasswordIsInHistory      = 5
        SamValidatePasswordTooShort         = 6
        SamValidatePasswordTooLong          = 7
        SamValidatePasswordNotComplexEnough = 8
        SamValidatePasswordTooRecent        = 9
        SamValidatePasswordFilterError      = 10

# 2.2.9.4 SAM_VALIDATE_STANDARD_OUTPUT_ARG
class SAM_VALIDATE_STANDARD_OUTPUT_ARG(NDRSTRUCT):
    structure = (
        ('ChangedPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ValidationStatus', SAM_VALIDATE_VALIDATION_STATUS),
    )

class PSAM_VALIDATE_STANDARD_OUTPUT_ARG(NDRPOINTER):
    referent = (
        ('Data', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
    )

# 2.2.9.5 SAM_VALIDATE_AUTHENTICATION_INPUT_ARG
class SAM_VALIDATE_AUTHENTICATION_INPUT_ARG(NDRSTRUCT):
    structure = (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('PasswordMatched', UCHAR),
    )

# 2.2.9.6 SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG
class SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG(NDRSTRUCT):
    structure = (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ClearPassword', RPC_UNICODE_STRING),
        ('UserAccountName', RPC_UNICODE_STRING),
        ('HashedPassword', SAM_VALIDATE_PASSWORD_HASH),
        ('PasswordMatch', UCHAR),
    )

# 2.2.9.7 SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG
class SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG(NDRSTRUCT):
    structure = (
        ('InputPersistedFields', SAM_VALIDATE_PERSISTED_FIELDS),
        ('ClearPassword', RPC_UNICODE_STRING),
        ('UserAccountName', RPC_UNICODE_STRING),
        ('HashedPassword', SAM_VALIDATE_PASSWORD_HASH),
        ('PasswordMustChangeAtNextLogon', UCHAR),
        ('ClearLockout', UCHAR),
    )

# 2.2.9.8 PASSWORD_POLICY_VALIDATION_TYPE
class PASSWORD_POLICY_VALIDATION_TYPE(NDRENUM):
    class enumItems(Enum):
        SamValidateAuthentication   = 1
        SamValidatePasswordChange   = 2
        SamValidatePasswordReset    = 3

# 2.2.9.9 SAM_VALIDATE_INPUT_ARG
class SAM_VALIDATE_INPUT_ARG(NDRUNION):
    union = {
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidateAuthentication : ('ValidateAuthenticationInput', SAM_VALIDATE_AUTHENTICATION_INPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordChange : ('ValidatePasswordChangeInput', SAM_VALIDATE_PASSWORD_CHANGE_INPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset  : ('ValidatePasswordResetInput', SAM_VALIDATE_PASSWORD_RESET_INPUT_ARG),
    }

# 2.2.9.10 SAM_VALIDATE_OUTPUT_ARG
class SAM_VALIDATE_OUTPUT_ARG(NDRUNION):
    union = {
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidateAuthentication : ('ValidateAuthenticationOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordChange : ('ValidatePasswordChangeOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
        PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset  : ('ValidatePasswordResetOutput', SAM_VALIDATE_STANDARD_OUTPUT_ARG),
    }

class PSAM_VALIDATE_OUTPUT_ARG(NDRPOINTER):
    referent = (
        ('Data', SAM_VALIDATE_OUTPUT_ARG),
    )

# 2.2.10 Supplemental Credentials Structures

# 2.2.10.1 USER_PROPERTIES
class USER_PROPERTIES(Structure):
    structure = (
        ('Reserved1','<L=0'),
        ('Length','<L=0'),
        ('Reserved2','<H=0'),
        ('Reserved3','<H=0'),
        ('Reserved4','96s=""'),
        ('PropertySignature','<H=0x50'),
        ('PropertyCount','<H=0'),
        ('UserProperties',':'),
    )

# 2.2.10.2 USER_PROPERTY
class USER_PROPERTY(Structure):
    structure = (
        ('NameLength','<H=0'),
        ('ValueLength','<H=0'),
        ('Reserved','<H=0'),
        ('_PropertyName','_-PropertyName', "self['NameLength']"),
        ('PropertyName',':'),
        ('_PropertyValue','_-PropertyValue', "self['ValueLength']"),
        ('PropertyValue',':'),
    )

# 2.2.10.3 Primary:WDigest - WDIGEST_CREDENTIALS
class WDIGEST_CREDENTIALS(Structure):
    structure = (
        ('Reserved1','B=0'),
        ('Reserved2','B=0'),
        ('Version','B=1'),
        ('NumberOfHashes','B=29'),
        ('Reserved3','12s=""'),
        ('Hash1', '16s=""'),
        ('Hash2', '16s=""'),
        ('Hash3', '16s=""'),
        ('Hash4', '16s=""'),
        ('Hash5', '16s=""'),
        ('Hash6', '16s=""'),
        ('Hash7', '16s=""'),
        ('Hash8', '16s=""'),
        ('Hash9', '16s=""'),
        ('Hash10', '16s=""'),
        ('Hash11', '16s=""'),
        ('Hash12', '16s=""'),
        ('Hash13', '16s=""'),
        ('Hash14', '16s=""'),
        ('Hash15', '16s=""'),
        ('Hash16', '16s=""'),
        ('Hash17', '16s=""'),
        ('Hash18', '16s=""'),
        ('Hash19', '16s=""'),
        ('Hash20', '16s=""'),
        ('Hash21', '16s=""'),
        ('Hash22', '16s=""'),
        ('Hash23', '16s=""'),
        ('Hash24', '16s=""'),
        ('Hash25', '16s=""'),
        ('Hash26', '16s=""'),
        ('Hash27', '16s=""'),
        ('Hash28', '16s=""'),
        ('Hash29', '16s=""'),
    )

# 2.2.10.5 KERB_KEY_DATA
class KERB_KEY_DATA(Structure):
    structure = (
        ('Reserved1','<H=0'),
        ('Reserved2','<H=0'),
        ('Reserved3','<H=0'),
        ('KeyType','<L=0'),
        ('KeyLength','<L=0'),
        ('KeyOffset','<L=0'),
    )

# 2.2.10.4 Primary:Kerberos - KERB_STORED_CREDENTIAL
class KERB_STORED_CREDENTIAL(Structure):
    structure = (
        ('Revision','<H=3'),
        ('Flags','<H=0'),
        ('CredentialCount','<H=0'),
        ('OldCredentialCount','<H=0'),
        ('DefaultSaltLength','<H=0'),
        ('DefaultSaltMaximumLength','<H=0'),
        ('DefaultSaltOffset','<L=0'),
        #('Credentials',':'),
        #('OldCredentials',':'),
        #('DefaultSalt',':'),
        #('KeyValues',':'),
        # All the preceding stuff inside this Buffer
        ('Buffer',':'),
    )

# 2.2.10.7 KERB_KEY_DATA_NEW
class KERB_KEY_DATA_NEW(Structure):
    structure = (
        ('Reserved1','<H=0'),
        ('Reserved2','<H=0'),
        ('Reserved3','<L=0'),
        ('IterationCount','<L=0'),
        ('KeyType','<L=0'),
        ('KeyLength','<L=0'),
        ('KeyOffset','<L=0'),
    )

# 2.2.10.6 Primary:Kerberos-Newer-Keys - KERB_STORED_CREDENTIAL_NEW
class KERB_STORED_CREDENTIAL_NEW(Structure):
    structure = (
        ('Revision','<H=4'),
        ('Flags','<H=0'),
        ('CredentialCount','<H=0'),
        ('ServiceCredentialCount','<H=0'),
        ('OldCredentialCount','<H=0'),
        ('OlderCredentialCount','<H=0'),
        ('DefaultSaltLength','<H=0'),
        ('DefaultSaltMaximumLength','<H=0'),
        ('DefaultSaltOffset','<L=0'),
        ('DefaultIterationCount','<L=0'),
        #('Credentials',':'),
        #('ServiceCredentials',':'),
        #('OldCredentials',':'),
        #('OlderCredentials',':'),
        #('DefaultSalt',':'),
        #('KeyValues',':'),
        # All the preceding stuff inside this Buffer
        ('Buffer',':'),
    )

################################################################################
# RPC CALLS
################################################################################

class SamrConnect(NDRCALL):
    opnum = 0
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME2),
       ('DesiredAccess', ULONG),
    )

class SamrConnectResponse(NDRCALL):
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrCloseHandle(NDRCALL):
    opnum = 1
    structure = (
       ('SamHandle',SAMPR_HANDLE),
       ('DesiredAccess', LONG),
    )

class SamrCloseHandleResponse(NDRCALL):
    structure = (
       ('SamHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrSetSecurityObject(NDRCALL):
    opnum = 2
    structure = (
       ('ObjectHandle',SAMPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
       ('SecurityDescriptor', SAMPR_SR_SECURITY_DESCRIPTOR),
    )

class SamrSetSecurityObjectResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrQuerySecurityObject(NDRCALL):
    opnum = 3
    structure = (
       ('ObjectHandle',SAMPR_HANDLE),
       ('SecurityInformation', SECURITY_INFORMATION),
    )

class SamrQuerySecurityObjectResponse(NDRCALL):
    structure = (
       ('SecurityDescriptor',PSAMPR_SR_SECURITY_DESCRIPTOR),
       ('ErrorCode',ULONG),
    )

class SamrLookupDomainInSamServer(NDRCALL):
    opnum = 5
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
    )

class SamrLookupDomainInSamServerResponse(NDRCALL):
    structure = (
       ('DomainId',PRPC_SID),
       ('ErrorCode',ULONG),
    )

class SamrEnumerateDomainsInSamServer(NDRCALL):
    opnum = 6
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class SamrEnumerateDomainsInSamServerResponse(NDRCALL):
    structure = (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrOpenDomain(NDRCALL):
    opnum = 7
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('DomainId', RPC_SID),
    )

class SamrOpenDomainResponse(NDRCALL):
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrQueryInformationDomain(NDRCALL):
    opnum = 8
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
    )

class SamrQueryInformationDomainResponse(NDRCALL):
    structure = (
       ('Buffer',PSAMPR_DOMAIN_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrSetInformationDomain(NDRCALL):
    opnum = 9
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
       ('DomainInformation', SAMPR_DOMAIN_INFO_BUFFER),
    )

class SamrSetInformationDomainResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrCreateGroupInDomain(NDRCALL):
    opnum = 10
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('DesiredAccess', ULONG),
    )

class SamrCreateGroupInDomainResponse(NDRCALL):
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrEnumerateGroupsInDomain(NDRCALL):
    opnum = 11
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class SamrCreateUserInDomain(NDRCALL):
    opnum = 12
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('DesiredAccess', ULONG),
    )

class SamrCreateUserInDomainResponse(NDRCALL):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrEnumerateGroupsInDomainResponse(NDRCALL):
    structure = (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrEnumerateUsersInDomain(NDRCALL):
    opnum = 13
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('UserAccountControl', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class SamrEnumerateUsersInDomainResponse(NDRCALL):
    structure = (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrCreateAliasInDomain(NDRCALL):
    opnum = 14
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('AccountName', RPC_UNICODE_STRING),
       ('DesiredAccess', ULONG),
    )

class SamrCreateAliasInDomainResponse(NDRCALL):
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    )


class SamrEnumerateAliasesInDomain(NDRCALL):
    opnum = 15
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', ULONG),
       ('PreferedMaximumLength', ULONG),
    )

class SamrEnumerateAliasesInDomainResponse(NDRCALL):
    structure = (
       ('EnumerationContext',ULONG),
       ('Buffer',PSAMPR_ENUMERATION_BUFFER),
       ('CountReturned',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrGetAliasMembership(NDRCALL):
    opnum = 16
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('SidArray',SAMPR_PSID_ARRAY),
    )

class SamrGetAliasMembershipResponse(NDRCALL):
    structure = (
       ('Membership',SAMPR_ULONG_ARRAY),
       ('ErrorCode',ULONG),
    )

class SamrLookupNamesInDomain(NDRCALL):
    opnum = 17
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Count',ULONG),
       ('Names',RPC_UNICODE_STRING_ARRAY),
    )

class SamrLookupNamesInDomainResponse(NDRCALL):
    structure = (
       ('RelativeIds',SAMPR_ULONG_ARRAY),
       ('Use',SAMPR_ULONG_ARRAY),
       ('ErrorCode',ULONG),
    )

class SamrLookupIdsInDomain(NDRCALL):
    opnum = 18
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Count',ULONG),
       ('RelativeIds',ULONG_ARRAY_CV),
    )

class SamrLookupIdsInDomainResponse(NDRCALL):
    structure = (
       ('Names',SAMPR_RETURNED_USTRING_ARRAY),
       ('Use',SAMPR_ULONG_ARRAY),
       ('ErrorCode',ULONG),
    )

class SamrOpenGroup(NDRCALL):
    opnum = 19
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('GroupId', ULONG),
    )

class SamrOpenGroupResponse(NDRCALL):
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrQueryInformationGroup(NDRCALL):
    opnum = 20
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('GroupInformationClass', GROUP_INFORMATION_CLASS),
    )

class SamrQueryInformationGroupResponse(NDRCALL):
    structure = (
       ('Buffer',PSAMPR_GROUP_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrSetInformationGroup(NDRCALL):
    opnum = 21
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('GroupInformationClass', GROUP_INFORMATION_CLASS),
       ('Buffer', SAMPR_GROUP_INFO_BUFFER),
    )

class SamrSetInformationGroupResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrAddMemberToGroup(NDRCALL):
    opnum = 22
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId', ULONG),
       ('Attributes', ULONG),
    )

class SamrAddMemberToGroupResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrDeleteGroup(NDRCALL):
    opnum = 23
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
    )

class SamrDeleteGroupResponse(NDRCALL):
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrRemoveMemberFromGroup(NDRCALL):
    opnum = 24
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId', ULONG),
    )

class SamrRemoveMemberFromGroupResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrGetMembersInGroup(NDRCALL):
    opnum = 25
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
    )

class SamrGetMembersInGroupResponse(NDRCALL):
    structure = (
       ('Members',PSAMPR_GET_MEMBERS_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrSetMemberAttributesOfGroup(NDRCALL):
    opnum = 26
    structure = (
       ('GroupHandle',SAMPR_HANDLE),
       ('MemberId',ULONG),
       ('Attributes',ULONG),
    )

class SamrSetMemberAttributesOfGroupResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrOpenAlias(NDRCALL):
    opnum = 27
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('AliasId', ULONG),
    )

class SamrOpenAliasResponse(NDRCALL):
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrQueryInformationAlias(NDRCALL):
    opnum = 28
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('AliasInformationClass', ALIAS_INFORMATION_CLASS),
    )

class SamrQueryInformationAliasResponse(NDRCALL):
    structure = (
       ('Buffer',PSAMPR_ALIAS_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrSetInformationAlias(NDRCALL):
    opnum = 29
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('AliasInformationClass', ALIAS_INFORMATION_CLASS),
       ('Buffer',SAMPR_ALIAS_INFO_BUFFER),
    )

class SamrSetInformationAliasResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrDeleteAlias(NDRCALL):
    opnum = 30
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
    )

class SamrDeleteAliasResponse(NDRCALL):
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrAddMemberToAlias(NDRCALL):
    opnum = 31
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MemberId', RPC_SID),
    )

class SamrAddMemberToAliasResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrRemoveMemberFromAlias(NDRCALL):
    opnum = 32
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MemberId', RPC_SID),
    )

class SamrRemoveMemberFromAliasResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrGetMembersInAlias(NDRCALL):
    opnum = 33
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
    )

class SamrGetMembersInAliasResponse(NDRCALL):
    structure = (
       ('Members',SAMPR_PSID_ARRAY_OUT),
       ('ErrorCode',ULONG),
    )

class SamrOpenUser(NDRCALL):
    opnum = 34
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DesiredAccess', ULONG),
       ('UserId', ULONG),
    )

class SamrOpenUserResponse(NDRCALL):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrDeleteUser(NDRCALL):
    opnum = 35
    structure = (
       ('UserHandle',SAMPR_HANDLE),
    )

class SamrDeleteUserResponse(NDRCALL):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrQueryInformationUser(NDRCALL):
    opnum = 36
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
    )

class SamrQueryInformationUserResponse(NDRCALL):
    structure = (
       ('Buffer',PSAMPR_USER_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrSetInformationUser(NDRCALL):
    opnum = 37
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
       ('Buffer',SAMPR_USER_INFO_BUFFER),
    )

class SamrSetInformationUserResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrChangePasswordUser(NDRCALL):
    opnum = 38
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('LmPresent', UCHAR ),
       ('OldLmEncryptedWithNewLm',PENCRYPTED_LM_OWF_PASSWORD),
       ('NewLmEncryptedWithOldLm',PENCRYPTED_LM_OWF_PASSWORD),
       ('NtPresent', UCHAR),
       ('OldNtEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('NewNtEncryptedWithOldNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('NtCrossEncryptionPresent',UCHAR),
       ('NewNtEncryptedWithNewLm',PENCRYPTED_NT_OWF_PASSWORD),
       ('LmCrossEncryptionPresent',UCHAR),
       ('NewLmEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
    )

class SamrChangePasswordUserResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrGetGroupsForUser(NDRCALL):
    opnum = 39
    structure = (
       ('UserHandle',SAMPR_HANDLE),
    )

class SamrGetGroupsForUserResponse(NDRCALL):
    structure = (
       ('Groups',PSAMPR_GET_GROUPS_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrQueryDisplayInformation(NDRCALL):
    opnum = 40
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', ULONG),
       ('EntryCount',ULONG),
       ('PreferredMaximumLength',ULONG),
    )

class SamrQueryDisplayInformationResponse(NDRCALL):
    structure = (
       ('TotalAvailable',ULONG),
       ('TotalReturned',ULONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrGetDisplayEnumerationIndex(NDRCALL):
    opnum = 41
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Prefix', RPC_UNICODE_STRING),
    )

class SamrGetDisplayEnumerationIndexResponse(NDRCALL):
    structure = (
       ('Index',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrGetUserDomainPasswordInformation(NDRCALL):
    opnum = 44
    structure = (
       ('UserHandle',SAMPR_HANDLE),
    )

class SamrGetUserDomainPasswordInformationResponse(NDRCALL):
    structure = (
       ('PasswordInformation',USER_DOMAIN_PASSWORD_INFORMATION),
       ('ErrorCode',ULONG),
    )

class SamrRemoveMemberFromForeignDomain(NDRCALL):
    opnum = 45
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('MemberSid', RPC_SID),
    )

class SamrRemoveMemberFromForeignDomainResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrQueryInformationDomain2(NDRCALL):
    opnum = 46
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DomainInformationClass', DOMAIN_INFORMATION_CLASS),
    )

class SamrQueryInformationDomain2Response(NDRCALL):
    structure = (
       ('Buffer',PSAMPR_DOMAIN_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrQueryInformationUser2(NDRCALL):
    opnum = 47
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS ),
    )

class SamrQueryInformationUser2Response(NDRCALL):
    structure = (
       ('Buffer',PSAMPR_USER_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrQueryDisplayInformation2(NDRCALL):
    opnum = 48
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', ULONG),
       ('EntryCount',ULONG),
       ('PreferredMaximumLength',ULONG),
    )

class SamrQueryDisplayInformation2Response(NDRCALL):
    structure = (
       ('TotalAvailable',ULONG),
       ('TotalReturned',ULONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrGetDisplayEnumerationIndex2(NDRCALL):
    opnum = 49
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Prefix', RPC_UNICODE_STRING),
    )

class SamrGetDisplayEnumerationIndex2Response(NDRCALL):
    structure = (
       ('Index',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrCreateUser2InDomain(NDRCALL):
    opnum = 50
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('Name', RPC_UNICODE_STRING),
       ('AccountType', ULONG),
       ('DesiredAccess', ULONG),
    )

class SamrCreateUser2InDomainResponse(NDRCALL):
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('GrantedAccess',ULONG),
       ('RelativeId',ULONG),
       ('ErrorCode',ULONG),
    )

class SamrQueryDisplayInformation3(NDRCALL):
    opnum = 51
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('DisplayInformationClass', DOMAIN_DISPLAY_INFORMATION),
       ('Index', ULONG),
       ('EntryCount',ULONG),
       ('PreferredMaximumLength',ULONG),
    )

class SamrQueryDisplayInformation3Response(NDRCALL):
    structure = (
       ('TotalAvailable',ULONG),
       ('TotalReturned',ULONG),
       ('Buffer',SAMPR_DISPLAY_INFO_BUFFER),
       ('ErrorCode',ULONG),
    )

class SamrAddMultipleMembersToAlias(NDRCALL):
    opnum = 52
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MembersBuffer', SAMPR_PSID_ARRAY),
    )

class SamrAddMultipleMembersToAliasResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrRemoveMultipleMembersFromAlias(NDRCALL):
    opnum = 53
    structure = (
       ('AliasHandle',SAMPR_HANDLE),
       ('MembersBuffer', SAMPR_PSID_ARRAY),
    )

class SamrRemoveMultipleMembersFromAliasResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrOemChangePasswordUser2(NDRCALL):
    opnum = 54
    structure = (
       ('ServerName', PRPC_STRING),
       ('UserName', RPC_STRING),
       ('NewPasswordEncryptedWithOldLm', PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldLmOwfPasswordEncryptedWithNewLm', PENCRYPTED_LM_OWF_PASSWORD),
    )

class SamrOemChangePasswordUser2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrUnicodeChangePasswordUser2(NDRCALL):
    opnum = 55
    structure = (
       ('ServerName', PRPC_UNICODE_STRING),
       ('UserName', RPC_UNICODE_STRING),
       ('NewPasswordEncryptedWithOldNt',PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldNtOwfPasswordEncryptedWithNewNt',PENCRYPTED_NT_OWF_PASSWORD),
       ('LmPresent',UCHAR),
       ('NewPasswordEncryptedWithOldLm',PSAMPR_ENCRYPTED_USER_PASSWORD),
       ('OldLmOwfPasswordEncryptedWithNewNt',PENCRYPTED_LM_OWF_PASSWORD),
    )

class SamrUnicodeChangePasswordUser2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrGetDomainPasswordInformation(NDRCALL):
    opnum = 56
    structure = (
       #('BindingHandle',SAMPR_HANDLE),
       ('Unused', PRPC_UNICODE_STRING),
    )

class SamrGetDomainPasswordInformationResponse(NDRCALL):
    structure = (
       ('PasswordInformation',USER_DOMAIN_PASSWORD_INFORMATION),
       ('ErrorCode',ULONG),
    )

class SamrConnect2(NDRCALL):
    opnum = 57
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('DesiredAccess', ULONG),
    )

class SamrConnect2Response(NDRCALL):
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrSetInformationUser2(NDRCALL):
    opnum = 58
    structure = (
       ('UserHandle',SAMPR_HANDLE),
       ('UserInformationClass', USER_INFORMATION_CLASS),
       ('Buffer', SAMPR_USER_INFO_BUFFER),
    )

class SamrSetInformationUser2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrConnect4(NDRCALL):
    opnum = 62
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('ClientRevision', ULONG),
       ('DesiredAccess', ULONG),
    )

class SamrConnect4Response(NDRCALL):
    structure = (
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrConnect5(NDRCALL):
    opnum = 64
    structure = (
       ('ServerName',PSAMPR_SERVER_NAME),
       ('DesiredAccess', ULONG),
       ('InVersion', ULONG),
       ('InRevisionInfo',SAMPR_REVISION_INFO),
    )

class SamrConnect5Response(NDRCALL):
    structure = (
       ('OutVersion',ULONG),
       ('OutRevisionInfo',SAMPR_REVISION_INFO),
       ('ServerHandle',SAMPR_HANDLE),
       ('ErrorCode',ULONG),
    )

class SamrRidToSid(NDRCALL):
    opnum = 65
    structure = (
       ('ObjectHandle',SAMPR_HANDLE),
       ('Rid', ULONG),
    )

class SamrRidToSidResponse(NDRCALL):
    structure = (
       ('Sid',PRPC_SID),
       ('ErrorCode',ULONG),
    )

class SamrSetDSRMPassword(NDRCALL):
    opnum = 66
    structure = (
       ('Unused', PRPC_UNICODE_STRING),
       ('UserId',ULONG),
       ('EncryptedNtOwfPassword',PENCRYPTED_NT_OWF_PASSWORD),
    )

class SamrSetDSRMPasswordResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

class SamrValidatePassword(NDRCALL):
    opnum = 67
    structure = (
       ('ValidationType', PASSWORD_POLICY_VALIDATION_TYPE),
       ('InputArg',SAM_VALIDATE_INPUT_ARG),
    )

class SamrValidatePasswordResponse(NDRCALL):
    structure = (
       ('OutputArg',PSAM_VALIDATE_OUTPUT_ARG),
       ('ErrorCode',ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (SamrConnect, SamrConnectResponse),
 1 : (SamrCloseHandle, SamrCloseHandleResponse),
 2 : (SamrSetSecurityObject, SamrSetSecurityObjectResponse),
 3 : (SamrQuerySecurityObject, SamrQuerySecurityObjectResponse),
 5 : (SamrLookupDomainInSamServer, SamrLookupDomainInSamServerResponse),
 6 : (SamrEnumerateDomainsInSamServer, SamrEnumerateDomainsInSamServerResponse),
 7 : (SamrOpenDomain, SamrOpenDomainResponse),
 8 : (SamrQueryInformationDomain, SamrQueryInformationDomainResponse),
 9 : (SamrSetInformationDomain, SamrSetInformationDomainResponse),
10 : (SamrCreateGroupInDomain, SamrCreateGroupInDomainResponse),
11 : (SamrEnumerateGroupsInDomain, SamrEnumerateGroupsInDomainResponse),
12 : (SamrCreateUserInDomain, SamrCreateUserInDomainResponse),
13 : (SamrEnumerateUsersInDomain, SamrEnumerateUsersInDomainResponse),
14 : (SamrCreateAliasInDomain, SamrCreateAliasInDomainResponse),
15 : (SamrEnumerateAliasesInDomain, SamrEnumerateAliasesInDomainResponse),
16 : (SamrGetAliasMembership, SamrGetAliasMembershipResponse),
17 : (SamrLookupNamesInDomain, SamrLookupNamesInDomainResponse),
18 : (SamrLookupIdsInDomain, SamrLookupIdsInDomainResponse),
19 : (SamrOpenGroup, SamrOpenGroupResponse),
20 : (SamrQueryInformationGroup, SamrQueryInformationGroupResponse),
21 : (SamrSetInformationGroup, SamrSetInformationGroupResponse),
22 : (SamrAddMemberToGroup, SamrAddMemberToGroupResponse),
23 : (SamrDeleteGroup, SamrDeleteGroupResponse),
24 : (SamrRemoveMemberFromGroup, SamrRemoveMemberFromGroupResponse),
25 : (SamrGetMembersInGroup, SamrGetMembersInGroupResponse),
26 : (SamrSetMemberAttributesOfGroup, SamrSetMemberAttributesOfGroupResponse),
27 : (SamrOpenAlias, SamrOpenAliasResponse),
28 : (SamrQueryInformationAlias, SamrQueryInformationAliasResponse),
29 : (SamrSetInformationAlias, SamrSetInformationAliasResponse),
30 : (SamrDeleteAlias, SamrDeleteAliasResponse),
31 : (SamrAddMemberToAlias, SamrAddMemberToAliasResponse),
32 : (SamrRemoveMemberFromAlias, SamrRemoveMemberFromAliasResponse),
33 : (SamrGetMembersInAlias, SamrGetMembersInAliasResponse),
34 : (SamrOpenUser, SamrOpenUserResponse),
35 : (SamrDeleteUser, SamrDeleteUserResponse),
36 : (SamrQueryInformationUser, SamrQueryInformationUserResponse),
37 : (SamrSetInformationUser, SamrSetInformationUserResponse),
38 : (SamrChangePasswordUser, SamrChangePasswordUserResponse),
39 : (SamrGetGroupsForUser, SamrGetGroupsForUserResponse),
40 : (SamrQueryDisplayInformation, SamrQueryDisplayInformationResponse),
41 : (SamrGetDisplayEnumerationIndex, SamrGetDisplayEnumerationIndexResponse),
44 : (SamrGetUserDomainPasswordInformation, SamrGetUserDomainPasswordInformationResponse),
45 : (SamrRemoveMemberFromForeignDomain, SamrRemoveMemberFromForeignDomainResponse),
46 : (SamrQueryInformationDomain2, SamrQueryInformationDomain2Response),
47 : (SamrQueryInformationUser2, SamrQueryInformationUser2Response),
48 : (SamrQueryDisplayInformation2, SamrQueryDisplayInformation2Response),
49 : (SamrGetDisplayEnumerationIndex2, SamrGetDisplayEnumerationIndex2Response),
50 : (SamrCreateUser2InDomain, SamrCreateUser2InDomainResponse),
51 : (SamrQueryDisplayInformation3, SamrQueryDisplayInformation3Response),
52 : (SamrAddMultipleMembersToAlias, SamrAddMultipleMembersToAliasResponse),
53 : (SamrRemoveMultipleMembersFromAlias, SamrRemoveMultipleMembersFromAliasResponse),
54 : (SamrOemChangePasswordUser2, SamrOemChangePasswordUser2Response),
55 : (SamrUnicodeChangePasswordUser2, SamrUnicodeChangePasswordUser2Response),
56 : (SamrGetDomainPasswordInformation, SamrGetDomainPasswordInformationResponse),
57 : (SamrConnect2, SamrConnect2Response),
58 : (SamrSetInformationUser2, SamrSetInformationUser2Response),
62 : (SamrConnect4, SamrConnect4Response),
64 : (SamrConnect5, SamrConnect5Response),
65 : (SamrRidToSid, SamrRidToSidResponse),
66 : (SamrSetDSRMPassword, SamrSetDSRMPasswordResponse),
67 : (SamrValidatePassword, SamrValidatePasswordResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def hSamrConnect5(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED, inVersion=1, revision=3):
    request = SamrConnect5()
    request['ServerName'] = serverName
    request['DesiredAccess'] = desiredAccess
    request['InVersion'] = inVersion
    request['InRevisionInfo']['tag'] = inVersion
    request['InRevisionInfo']['V1']['Revision'] = revision
    return dce.request(request)

def hSamrConnect4(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED, clientRevision=2):
    request = SamrConnect4()
    request['ServerName'] = serverName
    request['DesiredAccess'] = desiredAccess
    request['ClientRevision'] = clientRevision
    return dce.request(request)

def hSamrConnect2(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED):
    request = SamrConnect2()
    request['ServerName'] = serverName
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hSamrConnect(dce, serverName='\x00', desiredAccess=MAXIMUM_ALLOWED):
    request = SamrConnect()
    request['ServerName'] = serverName
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hSamrOpenDomain(dce, serverHandle, desiredAccess=MAXIMUM_ALLOWED, domainId=NULL):
    request = SamrOpenDomain()
    request['ServerHandle'] = serverHandle
    request['DesiredAccess'] = desiredAccess
    request['DomainId'] = domainId
    return dce.request(request)

def hSamrOpenGroup(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, groupId=0):
    request = SamrOpenGroup()
    request['DomainHandle'] = domainHandle
    request['DesiredAccess'] = desiredAccess
    request['GroupId'] = groupId
    return dce.request(request)

def hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=0):
    request = SamrOpenAlias()
    request['DomainHandle'] = domainHandle
    request['DesiredAccess'] = desiredAccess
    request['AliasId'] = aliasId
    return dce.request(request)

def hSamrOpenUser(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, userId=0):
    request = SamrOpenUser()
    request['DomainHandle'] = domainHandle
    request['DesiredAccess'] = desiredAccess
    request['UserId'] = userId
    return dce.request(request)

def hSamrEnumerateDomainsInSamServer(dce, serverHandle, enumerationContext=0, preferedMaximumLength=0xffffffff):
    request = SamrEnumerateDomainsInSamServer()
    request['ServerHandle'] = serverHandle
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=0, preferedMaximumLength=0xffffffff):
    request = SamrEnumerateGroupsInDomain()
    request['DomainHandle'] = domainHandle
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrEnumerateAliasesInDomain(dce, domainHandle, enumerationContext=0, preferedMaximumLength=0xffffffff):
    request = SamrEnumerateAliasesInDomain()
    request['DomainHandle'] = domainHandle
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrEnumerateUsersInDomain(dce, domainHandle, userAccountControl=USER_NORMAL_ACCOUNT, enumerationContext=0, preferedMaximumLength=0xffffffff):
    request = SamrEnumerateUsersInDomain()
    request['DomainHandle'] = domainHandle
    request['UserAccountControl'] = userAccountControl
    request['EnumerationContext'] = enumerationContext
    request['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrQueryDisplayInformation3(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, index=0, entryCount=0xffffffff, preferedMaximumLength=0xffffffff):
    request = SamrQueryDisplayInformation3()
    request['DomainHandle'] = domainHandle
    request['DisplayInformationClass'] = displayInformationClass
    request['Index'] = index
    request['EntryCount'] = entryCount
    request['PreferredMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrQueryDisplayInformation2(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, index=0, entryCount=0xffffffff, preferedMaximumLength=0xffffffff):
    request = SamrQueryDisplayInformation2()
    request['DomainHandle'] = domainHandle
    request['DisplayInformationClass'] = displayInformationClass
    request['Index'] = index
    request['EntryCount'] = entryCount
    request['PreferredMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrQueryDisplayInformation(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, index=0, entryCount=0xffffffff, preferedMaximumLength=0xffffffff):
    request = SamrQueryDisplayInformation()
    request['DomainHandle'] = domainHandle
    request['DisplayInformationClass'] = displayInformationClass
    request['Index'] = index
    request['EntryCount'] = entryCount
    request['PreferredMaximumLength'] = preferedMaximumLength
    return dce.request(request)

def hSamrGetDisplayEnumerationIndex2(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, prefix=''):
    request = SamrGetDisplayEnumerationIndex2()
    request['DomainHandle'] = domainHandle
    request['DisplayInformationClass'] = displayInformationClass
    request['Prefix'] = prefix
    return dce.request(request)

def hSamrGetDisplayEnumerationIndex(dce, domainHandle, displayInformationClass=DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, prefix=''):
    request = SamrGetDisplayEnumerationIndex()
    request['DomainHandle'] = domainHandle
    request['DisplayInformationClass'] = displayInformationClass
    request['Prefix'] = prefix
    return dce.request(request)

def hSamrCreateGroupInDomain(dce, domainHandle, name, desiredAccess=GROUP_ALL_ACCESS):
    request = SamrCreateGroupInDomain()
    request['DomainHandle'] = domainHandle
    request['Name'] = name
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hSamrCreateAliasInDomain(dce, domainHandle, accountName, desiredAccess=GROUP_ALL_ACCESS):
    request = SamrCreateAliasInDomain()
    request['DomainHandle'] = domainHandle
    request['AccountName'] = accountName
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hSamrCreateUser2InDomain(dce, domainHandle, name, accountType=USER_NORMAL_ACCOUNT, desiredAccess=GROUP_ALL_ACCESS):
    request = SamrCreateUser2InDomain()
    request['DomainHandle'] = domainHandle
    request['Name'] = name
    request['AccountType'] = accountType
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hSamrCreateUserInDomain(dce, domainHandle, name, desiredAccess=GROUP_ALL_ACCESS):
    request = SamrCreateUserInDomain()
    request['DomainHandle'] = domainHandle
    request['Name'] = name
    request['DesiredAccess'] = desiredAccess
    return dce.request(request)

def hSamrQueryInformationDomain(dce, domainHandle, domainInformationClass=DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2):
    request = SamrQueryInformationDomain()
    request['DomainHandle'] = domainHandle
    request['DomainInformationClass'] = domainInformationClass
    return dce.request(request)

def hSamrQueryInformationDomain2(dce, domainHandle, domainInformationClass=DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2):
    request = SamrQueryInformationDomain2()
    request['DomainHandle'] = domainHandle
    request['DomainInformationClass'] = domainInformationClass
    return dce.request(request)

def hSamrQueryInformationGroup(dce, groupHandle, groupInformationClass=GROUP_INFORMATION_CLASS.GroupGeneralInformation):
    request = SamrQueryInformationGroup()
    request['GroupHandle'] = groupHandle
    request['GroupInformationClass'] = groupInformationClass
    return dce.request(request)

def hSamrQueryInformationAlias(dce, aliasHandle, aliasInformationClass=ALIAS_INFORMATION_CLASS.AliasGeneralInformation):
    request = SamrQueryInformationAlias()
    request['AliasHandle'] = aliasHandle
    request['AliasInformationClass'] = aliasInformationClass
    return dce.request(request)

def hSamrQueryInformationUser2(dce, userHandle, userInformationClass=USER_INFORMATION_CLASS.UserGeneralInformation):
    request = SamrQueryInformationUser2()
    request['UserHandle'] = userHandle
    request['UserInformationClass'] = userInformationClass
    return dce.request(request)

def hSamrQueryInformationUser(dce, userHandle, userInformationClass=USER_INFORMATION_CLASS.UserGeneralInformation):
    request = SamrQueryInformationUser()
    request['UserHandle'] = userHandle
    request['UserInformationClass'] = userInformationClass
    return dce.request(request)

def hSamrSetInformationDomain(dce, domainHandle, domainInformation):
    request = SamrSetInformationDomain()
    request['DomainHandle'] = domainHandle
    request['DomainInformationClass'] = domainInformation['tag']
    request['DomainInformation'] = domainInformation
    return dce.request(request)

def hSamrSetInformationGroup(dce, groupHandle, buffer):
    request = SamrSetInformationGroup()
    request['GroupHandle'] = groupHandle
    request['GroupInformationClass'] = buffer['tag']
    request['Buffer'] = buffer
    return dce.request(request)

def hSamrSetInformationAlias(dce, aliasHandle, buffer):
    request = SamrSetInformationAlias()
    request['AliasHandle'] = aliasHandle
    request['AliasInformationClass'] = buffer['tag']
    request['Buffer'] = buffer
    return dce.request(request)

def hSamrSetInformationUser2(dce, userHandle, buffer):
    request = SamrSetInformationUser2()
    request['UserHandle'] = userHandle
    request['UserInformationClass'] = buffer['tag']
    request['Buffer'] = buffer
    return dce.request(request)

def hSamrSetInformationUser(dce, userHandle, buffer):
    request = SamrSetInformationUser()
    request['UserHandle'] = userHandle
    request['UserInformationClass'] = buffer['tag']
    request['Buffer'] = buffer
    return dce.request(request)

def hSamrDeleteGroup(dce, groupHandle):
    request = SamrDeleteGroup()
    request['GroupHandle'] = groupHandle
    return dce.request(request)

def hSamrDeleteAlias(dce, aliasHandle):
    request = SamrDeleteAlias()
    request['AliasHandle'] = aliasHandle
    return dce.request(request)

def hSamrDeleteUser(dce, userHandle):
    request = SamrDeleteUser()
    request['UserHandle'] = userHandle
    return dce.request(request)

def hSamrAddMemberToGroup(dce, groupHandle, memberId, attributes):
    request = SamrAddMemberToGroup()
    request['GroupHandle'] = groupHandle
    request['MemberId'] = memberId
    request['Attributes'] = attributes
    return dce.request(request)

def hSamrRemoveMemberFromGroup(dce, groupHandle, memberId):
    request = SamrRemoveMemberFromGroup()
    request['GroupHandle'] = groupHandle
    request['MemberId'] = memberId
    return dce.request(request)

def hSamrGetMembersInGroup(dce, groupHandle):
    request = SamrGetMembersInGroup()
    request['GroupHandle'] = groupHandle
    return dce.request(request)

def hSamrAddMemberToAlias(dce, aliasHandle, memberId):
    request = SamrAddMemberToAlias()
    request['AliasHandle'] = aliasHandle
    request['MemberId'] = memberId
    return dce.request(request)

def hSamrRemoveMemberFromAlias(dce, aliasHandle, memberId):
    request = SamrRemoveMemberFromAlias()
    request['AliasHandle'] = aliasHandle
    request['MemberId'] = memberId
    return dce.request(request)

def hSamrGetMembersInAlias(dce, aliasHandle):
    request = SamrGetMembersInAlias()
    request['AliasHandle'] = aliasHandle
    return dce.request(request)

def hSamrRemoveMemberFromForeignDomain(dce, domainHandle, memberSid):
    request = SamrRemoveMemberFromForeignDomain()
    request['DomainHandle'] = domainHandle
    request['MemberSid'] = memberSid
    return dce.request(request)

def hSamrAddMultipleMembersToAlias(dce, aliasHandle, membersBuffer):
    request = SamrAddMultipleMembersToAlias()
    request['AliasHandle'] = aliasHandle
    request['MembersBuffer'] = membersBuffer
    request['MembersBuffer']['Count'] = len(membersBuffer['Sids'])
    return dce.request(request)

def hSamrRemoveMultipleMembersFromAlias(dce, aliasHandle, membersBuffer):
    request = SamrRemoveMultipleMembersFromAlias()
    request['AliasHandle'] = aliasHandle
    request['MembersBuffer'] = membersBuffer
    request['MembersBuffer']['Count'] = len(membersBuffer['Sids'])
    return dce.request(request)

def hSamrGetGroupsForUser(dce, userHandle):
    request = SamrGetGroupsForUser()
    request['UserHandle'] = userHandle
    return dce.request(request)

def hSamrGetAliasMembership(dce, domainHandle, sidArray):
    request = SamrGetAliasMembership()
    request['DomainHandle'] = domainHandle
    request['SidArray'] = sidArray
    request['SidArray']['Count'] = len(sidArray['Sids'])
    return dce.request(request)

def hSamrChangePasswordUser(dce, userHandle, oldPassword, newPassword, oldPwdHashNT='', newPwdHashLM='', newPwdHashNT=''):
    request = SamrChangePasswordUser()
    request['UserHandle'] = userHandle

    from impacket import crypto, ntlm

    if oldPwdHashNT == '':
        oldPwdHashNT = ntlm.NTOWFv1(oldPassword)
    else:
        # Let's convert the hashes to binary form, if not yet
        try:
            oldPwdHashNT = unhexlify(oldPwdHashNT)
        except:
            pass

    if newPwdHashLM == '':
        newPwdHashLM = ntlm.LMOWFv1(newPassword)
    else:
        # Let's convert the hashes to binary form, if not yet
        try:
            newPwdHashLM = unhexlify(newPwdHashLM)
        except:
            pass

    if newPwdHashNT == '':
        newPwdHashNT = ntlm.NTOWFv1(newPassword)
    else:
        # Let's convert the hashes to binary form, if not yet
        try:
            newPwdHashNT = unhexlify(newPwdHashNT)
        except:
            pass

    request['LmPresent'] = 0
    request['OldLmEncryptedWithNewLm'] = NULL
    request['NewLmEncryptedWithOldLm'] = NULL
    request['NtPresent'] = 1
    request['OldNtEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
    request['NewNtEncryptedWithOldNt'] = crypto.SamEncryptNTLMHash(newPwdHashNT, oldPwdHashNT)
    request['NtCrossEncryptionPresent'] = 0
    request['NewNtEncryptedWithNewLm'] = NULL
    request['LmCrossEncryptionPresent'] = 1
    request['NewLmEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(newPwdHashLM, newPwdHashNT)

    return dce.request(request)

def hSamrUnicodeChangePasswordUser2(dce, serverName='\x00', userName='', oldPassword='', newPassword='', oldPwdHashLM = '', oldPwdHashNT = ''):
    request = SamrUnicodeChangePasswordUser2()
    request['ServerName'] = serverName
    request['UserName'] = userName

    try:
        from Cryptodome.Cipher import ARC4
    except Exception:
        LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
        LOG.critical("See https://pypi.org/project/pycryptodomex/")
    from impacket import crypto, ntlm

    if oldPwdHashLM == '' and oldPwdHashNT == '':
        oldPwdHashLM = ntlm.LMOWFv1(oldPassword)
        oldPwdHashNT = ntlm.NTOWFv1(oldPassword)
    else:
        # Let's convert the hashes to binary form, if not yet
        try:
            oldPwdHashLM = unhexlify(oldPwdHashLM)
        except:
            pass
        try:
            oldPwdHashNT = unhexlify(oldPwdHashNT)
        except:
            pass

    newPwdHashNT = ntlm.NTOWFv1(newPassword)

    samUser = SAMPR_USER_PASSWORD()
    try:
        samUser['Buffer'] = b'A'*(512-len(newPassword)*2) + newPassword.encode('utf-16le')
    except UnicodeDecodeError:
        import sys
        samUser['Buffer'] = b'A'*(512-len(newPassword)*2) + newPassword.decode(sys.getfilesystemencoding()).encode('utf-16le')

    samUser['Length'] = len(newPassword)*2
    pwdBuff = samUser.getData()

    rc4 = ARC4.new(oldPwdHashNT)
    encBuf = rc4.encrypt(pwdBuff)
    request['NewPasswordEncryptedWithOldNt']['Buffer'] = encBuf
    request['OldNtOwfPasswordEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
    request['LmPresent'] = 0
    request['NewPasswordEncryptedWithOldLm'] = NULL
    request['OldLmOwfPasswordEncryptedWithNewNt'] = NULL

    return dce.request(request)

def hSamrLookupDomainInSamServer(dce, serverHandle, name):
    request = SamrLookupDomainInSamServer()
    request['ServerHandle'] = serverHandle
    request['Name'] = name
    return dce.request(request)

def hSamrSetSecurityObject(dce, objectHandle, securityInformation, securityDescriptor):
    request = SamrSetSecurityObject()
    request['ObjectHandle'] =  objectHandle
    request['SecurityInformation'] =  securityInformation
    request['SecurityDescriptor'] = securityDescriptor
    return dce.request(request)

def hSamrQuerySecurityObject(dce, objectHandle, securityInformation):
    request = SamrQuerySecurityObject()
    request['ObjectHandle'] =  objectHandle
    request['SecurityInformation'] =  securityInformation
    return dce.request(request)

def hSamrCloseHandle(dce, samHandle):
    request = SamrCloseHandle()
    request['SamHandle'] =  samHandle
    return dce.request(request)

def hSamrSetMemberAttributesOfGroup(dce, groupHandle, memberId, attributes):
    request = SamrSetMemberAttributesOfGroup()
    request['GroupHandle'] =  groupHandle
    request['MemberId'] =  memberId
    request['Attributes'] =  attributes
    return dce.request(request)

def hSamrGetUserDomainPasswordInformation(dce, userHandle):
    request = SamrGetUserDomainPasswordInformation()
    request['UserHandle'] =  userHandle
    return dce.request(request)

def hSamrGetDomainPasswordInformation(dce):
    request = SamrGetDomainPasswordInformation()
    request['Unused'] =  NULL
    return dce.request(request)

def hSamrRidToSid(dce, objectHandle, rid):
    request = SamrRidToSid()
    request['ObjectHandle'] = objectHandle
    request['Rid'] =  rid
    return dce.request(request)

def hSamrValidatePassword(dce, inputArg):
    request = SamrValidatePassword()
    request['ValidationType'] =  inputArg['tag']
    request['InputArg'] = inputArg
    return dce.request(request)

def hSamrLookupNamesInDomain(dce, domainHandle, names):
    request = SamrLookupNamesInDomain()
    request['DomainHandle'] =  domainHandle
    request['Count'] = len(names)
    for name in names:
        entry = RPC_UNICODE_STRING()
        entry['Data'] = name
        request['Names'].append(entry)

    request.fields['Names'].fields['MaximumCount'] = 1000

    return dce.request(request)

def hSamrLookupIdsInDomain(dce, domainHandle, ids):
    request = SamrLookupIdsInDomain()
    request['DomainHandle'] =  domainHandle
    request['Count'] = len(ids)
    for dId in ids:
        entry = ULONG()
        entry['Data'] = dId
        request['RelativeIds'].append(entry)

    request.fields['RelativeIds'].fields['MaximumCount'] = 1000

    return dce.request(request)

def hSamrSetPasswordInternal4New(dce, userHandle, password):
    request = SamrSetInformationUser2()
    request['UserHandle'] = userHandle
    request['UserInformationClass'] = USER_INFORMATION_CLASS.UserInternal4InformationNew
    request['Buffer']['tag'] =  USER_INFORMATION_CLASS.UserInternal4InformationNew
    request['Buffer']['Internal4New']['I1']['WhichFields'] = 0x01000000 | 0x08000000

    request['Buffer']['Internal4New']['I1']['UserName'] = NULL
    request['Buffer']['Internal4New']['I1']['FullName'] = NULL
    request['Buffer']['Internal4New']['I1']['HomeDirectory'] = NULL
    request['Buffer']['Internal4New']['I1']['HomeDirectoryDrive'] = NULL
    request['Buffer']['Internal4New']['I1']['ScriptPath'] = NULL
    request['Buffer']['Internal4New']['I1']['ProfilePath'] = NULL
    request['Buffer']['Internal4New']['I1']['AdminComment'] = NULL
    request['Buffer']['Internal4New']['I1']['WorkStations'] = NULL
    request['Buffer']['Internal4New']['I1']['UserComment'] = NULL
    request['Buffer']['Internal4New']['I1']['Parameters'] = NULL
    request['Buffer']['Internal4New']['I1']['LmOwfPassword']['Buffer'] = NULL
    request['Buffer']['Internal4New']['I1']['NtOwfPassword']['Buffer'] = NULL
    request['Buffer']['Internal4New']['I1']['PrivateData'] = NULL
    request['Buffer']['Internal4New']['I1']['SecurityDescriptor']['SecurityDescriptor'] = NULL
    request['Buffer']['Internal4New']['I1']['LogonHours']['LogonHours'] = NULL
    request['Buffer']['Internal4New']['I1']['PasswordExpired'] = 1

    #crypto
    pwdbuff = password.encode("utf-16le")
    bufflen = len(pwdbuff)
    pwdbuff = pwdbuff.rjust(512, b'\0')
    pwdbuff += struct.pack('<I', bufflen)
    salt = os.urandom(16)
    session_key = dce.get_rpc_transport().get_smb_connection().getSessionKey()
    keymd = md5()
    keymd.update(salt)
    keymd.update(session_key)
    key = keymd.digest()

    cipher = ARC4.new(key)
    buffercrypt = cipher.encrypt(pwdbuff) + salt


    request['Buffer']['Internal4New']['UserPassword']['Buffer'] = buffercrypt
    return dce.request(request)
