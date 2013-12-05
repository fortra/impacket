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
from impacket.dcerpc.v5.ndr import NDRCall, NDR, NDRLONG, NDRUnion, NDRPointer, NDRUniConformantArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dtypes import *
from impacket import nt_errors
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))

class DCERPCSessionError(Exception):
    def __init__( self, packet):
        Exception.__init__(self)
        self.packet = packet
        self.error_code = packet['ErrorCode']
       
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

################################################################################
# STRUCTURES
################################################################################
class PSAMPR_SERVER_NAME2(NDRPointer):
    align = 0
    referent = (
        ('Data', '4s=""'),
    ) 

class SAMPR_ULONG_ARRAY(NDRUniConformantVaryingArray):
    item = '<L'

class SAMPR_HANDLE(NDR):
    structure =  (
        ('Data','20s=""'),
    )

class SAMPR_REVISION_INFO_V1(NDR):
    structure = (
       ('Revision',NDRLONG),
       ('SupportedFeatures',NDRLONG),
    )

class SAMPR_REVISION_INFO(NDRUnion):
    union = {
        1: ('V1', SAMPR_REVISION_INFO_V1),
    }

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

class SAMPR_ENUMERATION_BUFFER(NDR):
    structure = (
        ('EntriesRead',NDRLONG ),
        ('Buffer',PSAMPR_RID_ENUMERATION_ARRAY ),
    )

class PSAMPR_ENUMERATION_BUFFER(NDRPointer):
    referent = (
        ('Data',SAMPR_ENUMERATION_BUFFER),
    )

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

class SamrEnumerateGroupsInDomain(NDRCall):
    opnum = 11
    structure = (
       ('DomainHandle',SAMPR_HANDLE),
       ('EnumerationContext', NDRLONG),
       ('PreferedMaximumLength', NDRLONG),
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
       ('ErrorCode',SAMPR_ULONG_ARRAY),
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


################################################################################
# HELPER FUNCTIONS
################################################################################

