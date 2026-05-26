# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-RAA] Remote Authorization API Protocol Interface implementation.
#   Only the client side segment of the protocol has been implemented
#   MS-RAA is pretty neat as it allows us to preform pretty good enumeration to ask the question of what our permissions are
#   and what they can be if we added ourselves to a group or container. Its a rather easy protocol to implement since
#   all we have to do is define mostly structures using the spec and base that off what impacket had implemented in other similar protocols
#
#   Helper functions start with "h"<name of the call>.
#   Test cases have been added and are found in tests/dcerpc/test_raa.py.
#   Author : Abdul Mhanni

from struct import pack, unpack_from

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRENUM, NDRPOINTER, \
    NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, ULONG, USHORT, LONG64, ULONGLONG, LPWSTR, \
    PLARGE_INTEGER, LUID, ACCESS_MASK, OBJECT_TYPE_LIST, RPC_SID, PRPC_SID, NULL

from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin, string_to_bin

MSRPC_UUID_RAA = uuidtup_to_bin(('0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7', '0.0'))

# Object UUIDs (section 2.1). The second one disables the server-side stripping
# of SYSTEM_SCOPED_POLICY_ID_ACEs from the security descriptor in AuthzrAccessCheck.
RAA_OBJECT_UUID_DEFAULT = '9a81c2bd-a525-471d-a4ed-49907c0b23da'
RAA_OBJECT_UUID_NO_SCOPED_POLICY = '5fc860e0-6f6e-4fc2-83cd-46324f25e90b'

# mixed-endian per DCE RFC4122
RAA_OBJECT_UUID_DEFAULT_BIN          = string_to_bin(RAA_OBJECT_UUID_DEFAULT)
RAA_OBJECT_UUID_NO_SCOPED_POLICY_BIN = string_to_bin(RAA_OBJECT_UUID_NO_SCOPED_POLICY)

################################################################################
# CONSTANTS
################################################################################
# 3.1.4.2 AuthzrInitializeContextFromSid Flags
AUTHZ_COMPUTE_PRIVILEGES = 0x00000008

# 2.2.3.5 AUTHZR_SECURITY_ATTRIBUTE_V1 Flags
AUTHZ_SECURITY_ATTRIBUTE_NON_INHERITABLE     = 0x00000001
AUTHZ_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE = 0x00000002

# 2.2.3.6 AUTHZR_SECURITY_ATTRIBUTE_V1_VALUE ValueType
AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64  = 0x0001
AUTHZ_SECURITY_ATTRIBUTE_TYPE_UINT64 = 0x0002
AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING = 0x0003 #this is AUTHZR_SECURITY_ATTRIBUTE_STRING_VALUE structure, as
#specified in section 2.2.3.4 of MS-RAA
AUTHZ_SECURITY_ATTRIBUTE_TYPE_BOOLEAN = 0x0006

################################################################################
# ENUMERATIONS
################################################################################
# 2.2.2.1 AUTHZ_CONTEXT_INFORMATION_CLASS
class AUTHZ_CONTEXT_INFORMATION_CLASS(NDRENUM):
    class enumItems(Enum):
        AuthzContextInfoUserSid         = 1
        AuthzContextInfoGroupsSids      = 2
        AuthzContextInfoRestrictedSids  = 3
        AuthzContextInfoDeviceSids      = 12
        AuthzContextInfoUserClaims      = 13
        AuthzContextInfoDeviceClaims    = 14

# 2.2.2.2 AUTHZ_SECURITY_ATTRIBUTE_OPERATION
class AUTHZ_SECURITY_ATTRIBUTE_OPERATION(NDRENUM):
    class enumItems(Enum):
        AUTHZ_SECURITY_ATTRIBUTE_OPERATION_NONE        = 0
        AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL = 1
        AUTHZ_SECURITY_ATTRIBUTE_OPERATION_ADD         = 2
        AUTHZ_SECURITY_ATTRIBUTE_OPERATION_DELETE      = 3
        AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE     = 4

# 2.2.2.3 AUTHZ_SID_OPERATION
class AUTHZ_SID_OPERATION(NDRENUM):
    class enumItems(Enum):
        AUTHZ_SID_OPERATION_NONE        = 0
        AUTHZ_SID_OPERATION_REPLACE_ALL = 1
        AUTHZ_SID_OPERATION_ADD         = 2
        AUTHZ_SID_OPERATION_DELETE      = 3
        AUTHZ_SID_OPERATION_REPLACE     = 4

################################################################################
# STRUCTURES
################################################################################
# 2.2.1.1 AUTHZR_HANDLE
class AUTHZR_HANDLE(NDRSTRUCT):
    structure = (
        ('Data', '20s=b""'),
    )
    def getAlignment(self):
        return 1

# 2.2.3.11 SR_SD
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class SR_SD(NDRSTRUCT):
    structure = (
        ('dwLength', DWORD),
        ('pSrSd', PBYTE_ARRAY),
    )

class SR_SD_ARRAY(NDRUniConformantArray):
    item = SR_SD

# 2.2.3.2 AUTHZR_ACCESS_REQUEST
class OBJECT_TYPE_LIST_ARRAY(NDRUniConformantArray):
    item = OBJECT_TYPE_LIST

class POBJECT_TYPE_LIST_ARRAY(NDRPOINTER):
    referent = (
        ('Data', OBJECT_TYPE_LIST_ARRAY),
    )

class AUTHZR_ACCESS_REQUEST(NDRSTRUCT):
    structure = (
        ('DesiredAccess', ACCESS_MASK),
        ('PrincipalSelfSid', PRPC_SID),
        ('ObjectTypeListLength', DWORD),
        ('ObjectTypeList', POBJECT_TYPE_LIST_ARRAY),
    )

class PAUTHZR_ACCESS_REQUEST(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_ACCESS_REQUEST),
    )

# 2.2.3.1 AUTHZR_ACCESS_REPLY
class ACCESS_MASK_ARRAY(NDRUniConformantArray):
    item = '<L'

class PACCESS_MASK_ARRAY(NDRPOINTER):
    referent = (
        ('Data', ACCESS_MASK_ARRAY),
    )

class DWORD_ARRAY(NDRUniConformantArray):
    item = '<L'

class PDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY),
    )

class AUTHZR_ACCESS_REPLY(NDRSTRUCT):
    structure = (
        ('ResultListLength', DWORD),
        ('GrantedAccessMask', PACCESS_MASK_ARRAY),
        ('Error', PDWORD_ARRAY),
    )

# 2.2.3.8 AUTHZR_SID_AND_ATTRIBUTES
class AUTHZR_SID_AND_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Sid', PRPC_SID),
        ('Attributes', DWORD),
    )

class AUTHZR_SID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
    item = AUTHZR_SID_AND_ATTRIBUTES

# 2.2.3.10 AUTHZR_TOKEN_USER
class AUTHZR_TOKEN_USER(NDRSTRUCT):
    structure = (
        ('User', AUTHZR_SID_AND_ATTRIBUTES),
    )

class PAUTHZR_TOKEN_USER(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_TOKEN_USER),
    )

class AUTHZR_TOKEN_GROUPS(NDRSTRUCT):
    structure = (
        ('GroupCount', DWORD),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, None, isNDR64=isNDR64)
        self.fields['Groups'] = []
        if data is not None:
            self.fromString(data)

    def __getitem__(self, key):
        if key == 'Groups':
            return self.fields['Groups']
        return NDRSTRUCT.__getitem__(self, key)

    def __setitem__(self, key, value):
        if key == 'Groups':
            self.fields['Groups'] = list(value)
            return
        return NDRSTRUCT.__setitem__(self, key, value)

    def fromString(self, data, offset=0):
        offset0 = offset

        # Windows emits the conformant-array max count for NDR64 here, but
        # omits it in observed NDR32 replies.
        if self._isNDR64:
            offset += (8 - (offset % 8)) % 8
            maxCount = unpack_from('<Q', data, offset)[0]
            offset += 8
        else:
            maxCount = None

        offset += self.unpack('GroupCount', DWORD, data, offset)
        arrayCount = maxCount if maxCount is not None else self['GroupCount']

        entry = AUTHZR_SID_AND_ATTRIBUTES(isNDR64=self._isNDR64)
        entryAlignment = entry.getAlignment()
        if entryAlignment > 0:
            offset += (entryAlignment - (offset % entryAlignment)) % entryAlignment

        self.fields['Groups'] = []
        for _ in range(arrayCount):
            entry = AUTHZR_SID_AND_ATTRIBUTES(isNDR64=self._isNDR64)
            offset += entry.fromString(data, offset)
            self.fields['Groups'].append(entry)

        return offset - offset0

    def fromStringReferents(self, data, offset=0):
        offset0 = offset
        for entry in self.fields['Groups']:
            offset += entry.fromStringReferents(data, offset)
        return offset - offset0

    def getData(self, soFar=0):
        self['GroupCount'] = len(self.fields['Groups'])
        data = b''

        if self._isNDR64:
            pad = (8 - (soFar % 8)) % 8
            data += b'\xee' * pad
            data += pack('<Q', self['GroupCount'])

        data += self.pack('GroupCount', DWORD, soFar + len(data))

        entry = AUTHZR_SID_AND_ATTRIBUTES(isNDR64=self._isNDR64)
        entryAlignment = entry.getAlignment()
        if entryAlignment > 0:
            pad = (entryAlignment - ((soFar + len(data)) % entryAlignment)) % entryAlignment
            data += b'\xab' * pad

        for entry in self.fields['Groups']:
            data += entry.getData(soFar + len(data))
        return data

    def getDataReferents(self, soFar=0):
        data = b''
        for entry in self.fields['Groups']:
            data += entry.getDataReferents(soFar + len(data))
        return data

class PAUTHZR_TOKEN_GROUPS(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_TOKEN_GROUPS),
    )

# 2.2.3.4 AUTHZR_SECURITY_ATTRIBUTE_STRING_VALUE
class AUTHZR_SECURITY_ATTRIBUTE_STRING_VALUE(NDRSTRUCT):
    structure = (
        ('Length', ULONG),
        ('Value', LPWSTR),
    )

# 2.2.3.6 AUTHZR_SECURITY_ATTRIBUTE_V1_VALUE
class AUTHZR_SECURITY_ATTRIBUTE_UNION(NDRUNION):
    union = {
        AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64   : ('Int64', LONG64),
        AUTHZ_SECURITY_ATTRIBUTE_TYPE_UINT64  : ('Uint64', ULONGLONG),
        AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING  : ('String', AUTHZR_SECURITY_ATTRIBUTE_STRING_VALUE),
        AUTHZ_SECURITY_ATTRIBUTE_TYPE_BOOLEAN : ('Uint64', ULONGLONG),
    }

class AUTHZR_SECURITY_ATTRIBUTE_V1_VALUE(NDRSTRUCT):
    structure = (
        ('AttributeUnion', AUTHZR_SECURITY_ATTRIBUTE_UNION),
    )

class AUTHZR_SECURITY_ATTRIBUTE_V1_VALUE_ARRAY(NDRUniConformantArray):
    item = AUTHZR_SECURITY_ATTRIBUTE_V1_VALUE

class PAUTHZR_SECURITY_ATTRIBUTE_V1_VALUE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_SECURITY_ATTRIBUTE_V1_VALUE_ARRAY),
    )

# 2.2.3.5 AUTHZR_SECURITY_ATTRIBUTE_V1
class AUTHZR_SECURITY_ATTRIBUTE_V1(NDRSTRUCT):
    structure = (
        ('Length', ULONG),
        ('Value', LPWSTR),
        ('ValueType', USHORT),
        ('Reserved', USHORT),
        ('Flags', ULONG),
        ('ValueCount', ULONG),
        ('Values', PAUTHZR_SECURITY_ATTRIBUTE_V1_VALUE_ARRAY),
    )

class AUTHZR_SECURITY_ATTRIBUTE_V1_ARRAY(NDRUniConformantArray):
    item = AUTHZR_SECURITY_ATTRIBUTE_V1

class PAUTHZR_SECURITY_ATTRIBUTE_V1_ARRAY(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_SECURITY_ATTRIBUTE_V1_ARRAY),
    )

# 2.2.3.7 AUTHZR_SECURITY_ATTRIBUTES_INFORMATION
class AUTHZR_SECURITY_ATTRIBUTES_INFORMATION(NDRSTRUCT):
    structure = (
        ('Version', USHORT),
        ('Reserved', USHORT),
        ('AttributeCount', ULONG),
        ('Attributes', PAUTHZR_SECURITY_ATTRIBUTE_V1_ARRAY),
    )

class PAUTHZR_SECURITY_ATTRIBUTES_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_SECURITY_ATTRIBUTES_INFORMATION),
    )

# 2.2.3.3 AUTHZR_CONTEXT_INFORMATION
class AUTHZR_CONTEXT_INFORMATION_UNION(NDRUNION):
    union = {
        0x1 : ('pTokenUser',   PAUTHZR_TOKEN_USER),
        0x2 : ('pTokenGroups', PAUTHZR_TOKEN_GROUPS),
        0x3 : ('pTokenGroups', PAUTHZR_TOKEN_GROUPS),
        0xC : ('pTokenGroups', PAUTHZR_TOKEN_GROUPS),
        0xD : ('pTokenClaims', PAUTHZR_SECURITY_ATTRIBUTES_INFORMATION),
        0xE : ('pTokenClaims', PAUTHZR_SECURITY_ATTRIBUTES_INFORMATION),
    }

class AUTHZR_CONTEXT_INFORMATION(NDRSTRUCT):
    structure = (
        ('ContextInfoUnion', AUTHZR_CONTEXT_INFORMATION_UNION),
    )

class PAUTHZR_CONTEXT_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', AUTHZR_CONTEXT_INFORMATION),
    )

class PPAUTHZR_CONTEXT_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', PAUTHZR_CONTEXT_INFORMATION),
    )

# Operation arrays for AuthzrModifyClaims / AuthzrModifySids
class AUTHZ_SECURITY_ATTRIBUTE_OPERATION_ARRAY(NDRUniConformantArray):
    item = AUTHZ_SECURITY_ATTRIBUTE_OPERATION

class AUTHZ_SID_OPERATION_ARRAY(NDRUniConformantArray):
    item = AUTHZ_SID_OPERATION

################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1 AuthzrFreeContext (Opnum 0)
class AuthzrFreeContext(NDRCALL):
    opnum = 0
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
    )

class AuthzrFreeContextResponse(NDRCALL):
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
        ('ErrorCode', DWORD),
    )

# 3.1.4.2 AuthzrInitializeContextFromSid (Opnum 1)
class AuthzrInitializeContextFromSid(NDRCALL):
    opnum = 1
    structure = (
        ('Flags', DWORD),
        ('Sid', RPC_SID),
        ('pExpirationTime', PLARGE_INTEGER),
        ('Identifier', LUID),
    )

class AuthzrInitializeContextFromSidResponse(NDRCALL):
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
        ('ErrorCode', DWORD),
    )

# 3.1.4.3 AuthzrInitializeCompoundContext (Opnum 2)
class AuthzrInitializeCompoundContext(NDRCALL):
    opnum = 2
    structure = (
        ('UserContextHandle', AUTHZR_HANDLE),
        ('DeviceContextHandle', AUTHZR_HANDLE),
    )

class AuthzrInitializeCompoundContextResponse(NDRCALL):
    structure = (
        ('CompoundContextHandle', AUTHZR_HANDLE),
        ('ErrorCode', DWORD),
    )

# 3.1.4.4 AuthzrAccessCheck (Opnum 3)
class AuthzrAccessCheck(NDRCALL):
    opnum = 3
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
        ('Flags', DWORD),
        ('pRequest', AUTHZR_ACCESS_REQUEST),
        ('SecurityDescriptorCount', DWORD),
        ('pSecurityDescriptors', SR_SD_ARRAY),
        ('pReply', AUTHZR_ACCESS_REPLY),
    )

class AuthzrAccessCheckResponse(NDRCALL):
    structure = (
        ('pReply', AUTHZR_ACCESS_REPLY),
        ('ErrorCode', DWORD),
    )

# 3.1.4.5 AuthzGetInformationFromContext (Opnum 4)
class AuthzGetInformationFromContext(NDRCALL):
    opnum = 4
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
        ('InfoClass', AUTHZ_CONTEXT_INFORMATION_CLASS),
    )

class AuthzGetInformationFromContextResponse(NDRCALL):
    structure = (
        ('ppContextInformation', PPAUTHZR_CONTEXT_INFORMATION),
        ('ErrorCode', DWORD),
    )

# 3.1.4.6 AuthzrModifyClaims (Opnum 5)
class AuthzrModifyClaims(NDRCALL):
    opnum = 5
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
        ('ClaimClass', AUTHZ_CONTEXT_INFORMATION_CLASS),
        ('OperationCount', DWORD),
        ('pClaimOperations', AUTHZ_SECURITY_ATTRIBUTE_OPERATION_ARRAY),
        ('pClaims', PAUTHZR_SECURITY_ATTRIBUTES_INFORMATION),
    )

class AuthzrModifyClaimsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

# 3.1.4.7 AuthzrModifySids (Opnum 6)
class AuthzrModifySids(NDRCALL):
    opnum = 6
    structure = (
        ('ContextHandle', AUTHZR_HANDLE),
        ('SidClass', AUTHZ_CONTEXT_INFORMATION_CLASS),
        ('OperationCount', DWORD),
        ('pSidOperations', AUTHZ_SID_OPERATION_ARRAY),
        ('pSids', PAUTHZR_TOKEN_GROUPS),
    )

class AuthzrModifySidsResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0 : (AuthzrFreeContext, AuthzrFreeContextResponse),
    1 : (AuthzrInitializeContextFromSid, AuthzrInitializeContextFromSidResponse),
    2 : (AuthzrInitializeCompoundContext, AuthzrInitializeCompoundContextResponse),
    3 : (AuthzrAccessCheck, AuthzrAccessCheckResponse),
    4 : (AuthzGetInformationFromContext, AuthzGetInformationFromContextResponse),
    5 : (AuthzrModifyClaims, AuthzrModifyClaimsResponse),
    6 : (AuthzrModifySids, AuthzrModifySidsResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hAuthzrFreeContext(dce, contextHandle, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzrFreeContext()
    request['ContextHandle'] = contextHandle
    return dce.request(request, uuid=objectUuid)

def hAuthzrInitializeContextFromSid(dce, sid, flags=AUTHZ_COMPUTE_PRIVILEGES, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzrInitializeContextFromSid()
    request['Flags'] = flags
    sid_object = RPC_SID()
    sid_object.fromCanonical(sid)
    request['Sid'] = sid_object
    request['pExpirationTime'] = NULL
    request['Identifier']['LowPart'] = 0
    request['Identifier']['HighPart'] = 0
    return dce.request(request, uuid=objectUuid)

def hAuthzrInitializeCompoundContext(dce, userContextHandle, deviceContextHandle, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzrInitializeCompoundContext()
    request['UserContextHandle'] = userContextHandle
    request['DeviceContextHandle'] = deviceContextHandle
    return dce.request(request, uuid=objectUuid)

def hAuthzrAccessCheck(dce, contextHandle, securityDescriptor, desiredAccess,
                      principalSelfSid=NULL, objectTypeList=(), resultListLength=1, flags=0, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzrAccessCheck()
    request['ContextHandle'] = contextHandle
    request['Flags'] = flags
    request['pRequest']['DesiredAccess'] = desiredAccess
    request['pRequest']['PrincipalSelfSid'] = principalSelfSid
    request['pRequest']['ObjectTypeListLength'] = len(objectTypeList)
    if len(objectTypeList) == 0:
        request['pRequest']['ObjectTypeList'] = NULL
    else:
        for entry in objectTypeList:
            request['pRequest']['ObjectTypeList'].append(entry)

    if isinstance(securityDescriptor, (list, tuple)):
        sds = list(securityDescriptor)
    else:
        sds = [securityDescriptor]
    request['SecurityDescriptorCount'] = len(sds)
    for sd in sds:
        srSd = SR_SD()
        srSd['dwLength'] = len(sd)
        srSd['pSrSd'] = sd
        request['pSecurityDescriptors'].append(srSd)

    request['pReply']['ResultListLength'] = resultListLength
    request['pReply']['GrantedAccessMask'] = [0] * resultListLength
    request['pReply']['Error'] = [0] * resultListLength
    return dce.request(request, uuid=objectUuid)

def hAuthzGetInformationFromContext(dce, contextHandle, infoClass, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzGetInformationFromContext()
    request['ContextHandle'] = contextHandle
    request['InfoClass'] = infoClass
    return dce.request(request, uuid=objectUuid)

def _enum_operation(enumClass, operation):
    if isinstance(operation, enumClass):
        return operation

    enumOperation = enumClass()
    enumOperation['Data'] = operation
    return enumOperation

def hAuthzrModifyClaims(dce, contextHandle, claimClass, claimOperations, claims=NULL, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzrModifyClaims()
    request['ContextHandle'] = contextHandle
    request['ClaimClass'] = claimClass
    request['OperationCount'] = len(claimOperations)
    for op in claimOperations:
        request['pClaimOperations'].append(_enum_operation(AUTHZ_SECURITY_ATTRIBUTE_OPERATION, op))
    request['pClaims'] = claims
    return dce.request(request, uuid=objectUuid)

def hAuthzrModifySids(dce, contextHandle, sidClass, sidOperations, sids=NULL, objectUuid=RAA_OBJECT_UUID_DEFAULT_BIN):
    request = AuthzrModifySids()
    request['ContextHandle'] = contextHandle
    request['SidClass'] = sidClass
    request['OperationCount'] = len(sidOperations)
    for op in sidOperations:
        request['pSidOperations'].append(_enum_operation(AUTHZ_SID_OPERATION, op))
    request['pSids'] = sids
    return dce.request(request, uuid=objectUuid)

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'RAA SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'RAA SessionError: unknown error code: 0x%x' % self.error_code
