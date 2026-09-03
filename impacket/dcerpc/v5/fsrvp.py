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
#   Implementation of MS-FSRVP: File server remote VSS Protocol.
#
# Authors:
#   Andrei Solodiankin https://github.com/AndreySolod
#


from __future__ import division
from __future__ import print_function
import enum
from typing import Optional, Union

from impacket import nt_errors
from impacket.dcerpc.v5.dtypes import LONG, DWORD, WSTR, LPWSTR, ULONG, GUID, LONGLONG, BOOL
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NULL, NDRUNION
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC_v5
from impacket.uuid import uuidtup_to_bin, string_to_bin

MSRPC_UUID_FSRVP       = uuidtup_to_bin(('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0'))
MSRPC_NAMED_PIPE_FSRVP = "\\pipe\\FssagentRpc"

FSRVP_ERROR_MESSAGES = {
    0x80042301 : ("FSRVP_E_BAD_STATE", "A method call was invalid because of the state of the server. (For example, calling AddToShadowCopySet (Opnum 3) before StartShadowCopySet (Opnum 2).)"),
    0x80042316 : ("FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS", "A call was made to either SetContext (Opnum 1) or StartShadowCopySet (Opnum 2) while the creation of another shadow copy set is in progress."),
    0x8004230C : ("FSRVP_E_NOT_SUPPORTED", "The file store which contains the share to be shadow copied is not supported by the server."),
    0xFFFFFFFF : ("FSRVP_E_WAIT_FAILED", "The wait for a shadow copy commit expose operation has failed."),
    0x8004230D : ("FSRVP_E_OBJECT_ALREADY_EXISTS", "The specified object already exists."),
    0x80042308 : ("FSRVP_E_OBJECT_NOT_FOUND", "The specified object does not exist."),
    0x8004231B : ("FSRVP_E_UNSUPPORTED_CONTEXT", "The specified context value is invalid"),
    0x80042501 : ("FSRVP_E_SHADOWCOPYSET_ID_MISMATCH", "The provided ShadowCopySetId does not exist."),
    0x80070005 : ("E_ACCESSDENIED", "The caller does not have the permissions to perform the operation"),
    0x80070057 : ("E_INVALIDARG", "One or more arguments are invalid.")
}

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in FSRVP_ERROR_MESSAGES:
            error_msg_short = FSRVP_ERROR_MESSAGES[key][0]
            error_msg_verbose = FSRVP_ERROR_MESSAGES[key][1]
            return 'FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        if key in nt_errors.ERROR_MESSAGES:
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'FSRVP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

class ShadowCopyAttributes(enum.IntEnum):
    ATTR_PERSISTENT       = 0x00000001
    ATTR_NO_AUTO_RECOVERY = 0x00000002
    ATTR_NO_AUTO_RELEASE  = 0x00000008
    ATTR_NO_WRITERS       = 0x00000010
    ATTR_AUTO_RECOVERY    = 0x00400000


class ContextValues(enum.IntEnum):
    CTX_BACKUP            = 0x00000000
    CTX_FILE_SHARE_BACKUP = 0x00000010
    CTX_NAS_ROLLBACK      = 0x00000019
    CTX_APP_ROLLBACK      = 0x00000009


class ShadowCopyCompatibilityValues(enum.IntEnum):
    DISABLE_DEFRAG        = 0x00000001
    DISABLE_CONTENTINDEX  = 0x00000002

################################################################################
# STRUCTURES
################################################################################
class FSSAGENT_SHARE_MAPPING_1(NDRSTRUCT):
    structure = (
        ('ShadowCopySetId', GUID),
        ('ShadowCopyId', GUID),
        ('ShareNameUNC', LPWSTR),
        ('ShadowCopyShareName', LPWSTR),
        ('CreationTimestamp', LONGLONG),
    )

class PFSSAGENT_SHARE_MAPPING_1(NDRPOINTER):
    referent = (
        ('Data', FSSAGENT_SHARE_MAPPING_1),
    )

class FSSAGENT_SHARE_MAPPING(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1: ('ShareMapping1', PFSSAGENT_SHARE_MAPPING_1),
    }

class PFSSAGENT_SHARE_MAPPING(NDRPOINTER):
    referent = (
        ('Data', FSSAGENT_SHARE_MAPPING),
    )

################################################################################
# RPC CALLS
################################################################################
class GetSupportedVersion(NDRCALL):
    '''The GetSupportedVersion method is invoked by the client to get the minimum and maximum versions of the protocol that the server supports.'''
    opnum = 0
    structure = tuple()


class GetSupportedVersionResponse(NDRCALL):
    structure = (
        ('MinVersion', DWORD),
        ('MaxVersion', DWORD),
        ('ErrorCode',DWORD),
    )


class SetContext(NDRCALL):
    '''The SetContext method sets the context for the current shadow copy creation process.'''
    opnum = 1
    structure = (
        ('Context', ULONG),
    )


class SetContextResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )


class StartShadowCopySet(NDRCALL):
    '''The StartShadowCopySet method is called by the client to initiate a new shadow copy set for shadow copy creation'''
    opnum = 2
    structure = (
        ('ClientShadowCopySetId', GUID),
    )


class StartShadowCopySetResponse(NDRCALL):
    structure = (
        ('pShadowCopySetId', GUID),
        ('ErrorCode', DWORD)
    )


class AddToShadowCopySet(NDRCALL):
    '''The AddToShadowCopySet method adds a share to an existing shadow copy set.'''
    opnum = 3
    structure = (
        ('ClientShadowCopyId', GUID),
        ('ShadowCopySetId', GUID),
        ('ShareName', WSTR)
    )


class AddToShadowCopySetResponse(NDRCALL):
    structure = (
        ("ShadowCopyId", GUID),
        ("ErrorCode", DWORD)
    )


class CommitShadowCopySet(NDRCALL):
    '''The CommitShadowCopySet method is invoked by the client to commit a given shadow copy set.'''
    opnum = 4
    structure = (
        ('ShadowCopySetId', GUID),
        ('TimeOutInMilliseconds', ULONG)
    )


class CommitShadowCopySetResponse(NDRCALL):
    structure = (
        ("ErrorCode", DWORD),
    )


class ExposeShadowCopySet(NDRCALL):
    '''The ExposeShadowCopySet method exposes all the shadow copies in a shadow copy set as file shares on the file server.'''
    opnum = 5
    structure = (
        ("ShadowCopySetId", GUID),
        ('TimeOutInMilliseconds', ULONG)
    )


class ExposeShadowCopySetResponse(NDRCALL):
    structure = (
        ("ErrorCode", DWORD),
    )


class RecoveryCompleteShadowCopySet(NDRCALL):
    '''The RecoveryCompleteShadowCopySet method is invoked by the client to indicate to the server
    that the data associated with the file shares in a shadow copy set have been recovered by the VSS
    writers.
    '''
    opnum = 6
    structure = (
        ("ShadowCopySetId", GUID),
    )


class RecoveryCompleteShadowCopySetResponse(NDRCALL):
    structure = (
        ("ErrorCode", DWORD),
    )


class AbortShadowCopySet(NDRCALL):
    '''The AbortShadowCopySet method is invoked by the client to delete a given shadow copy set on the server.'''
    opnum = 7
    structure = (
        ("ShadowCopySetId", GUID),
    )


class AbortShadowCopySetResponse(NDRCALL):
    structure = (
        ("ErrorCode", DWORD),
    )


class IsPathSupported(NDRCALL):
    '''The IsPathSupported method is invoked by the client to query if a given share is supported by the server for shadow copy operations.'''
    opnum = 8
    structure = (
        ("ShareName", WSTR),
    )


class IsPathSupportedResponse(NDRCALL):
    structure = (
        ('SupportedByThisProvider', BOOL),
        ('OwnerMachineName', LPWSTR),
        ('ErrorCode', DWORD)
    )

class IsPathShadowCopied(NDRCALL):
    '''The IsPathShadowCopied method is invoked by the client to query if any shadow copy for a share already exists.'''
    opnum = 9
    structure = (
        ("ShareName", WSTR),
    )


class IsPathShadowCopiedResponse(NDRCALL):
    structure = (
        ("ShadowCopyPresent", BOOL),
        ("ShadowCopyCompatibility", LONG),
        ('ErrorCode', DWORD)
    )


class GetShareMapping(NDRCALL):
    '''The GetShareMapping method is invoked by the client to get the shadow copy information on a
    given file share on the server after the shadow copy of the share has been exposed.'''
    opnum = 10
    structure = (
        ("ShadowCopyId", GUID),
        ("ShadowCopySetId", GUID),
        ("ShareName", WSTR),
        ("Level", DWORD)
    )


class GetShareMappingResponse(NDRCALL):
    structure = (
        ('ShareMapping', FSSAGENT_SHARE_MAPPING),
        ('ErrorCode', DWORD),
    )


class DeleteShareMapping(NDRCALL):
    '''The DeleteShareMapping method deletes the mapping of a share's shadow copy from a shadow copy set. '''
    opnum = 11
    structure = (
        ('ShadowCopySetId', GUID),
        ('ShadowCopyId', GUID),
        ('ShareName', WSTR)
    )


class DeleteShareMappingResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )


class PrepareShadowCopySet(NDRCALL):
    '''The PrepareShadowCopySet method is invoked by the client to ensure that the server has
    completed preparation for creating the shadow copy set.'''
    opnum = 12
    structure = (
        ('ShadowCopySetId', GUID),
        ('TimeOutInMilliseconds', ULONG)
    )


class PrepareShadowCopySetResponse(NDRCALL):
    structure = (
        ('ErrorCode', DWORD),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0  : (GetSupportedVersion, GetSupportedVersionResponse),
 1  : (SetContext, SetContextResponse),
 2  : (StartShadowCopySet, StartShadowCopySetResponse),
 3  : (AddToShadowCopySet, AddToShadowCopySetResponse),
 4  : (CommitShadowCopySet, CommitShadowCopySetResponse),
 5  : (ExposeShadowCopySet, ExposeShadowCopySetResponse),
 6  : (RecoveryCompleteShadowCopySet, RecoveryCompleteShadowCopySetResponse),
 7  : (AbortShadowCopySet, AbortShadowCopySetResponse),
 8  : (IsPathSupported, IsPathSupportedResponse),
 9  : (IsPathShadowCopied, IsPathShadowCopiedResponse),
 10 : (GetShareMapping, GetShareMappingResponse),
 11 : (DeleteShareMapping, DeleteShareMappingResponse),
 12 : (PrepareShadowCopySet, PrepareShadowCopySetResponse)
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
    if string == NULL:
        return string

    if string is None:
        return NULL

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string


def hGetSupportedVersion(dce: DCERPC_v5) -> GetSupportedVersionResponse:
    gsv = GetSupportedVersion()
    return dce.request(gsv)


def hSetContext(dce: DCERPC_v5, context: Union[ShadowCopyAttributes, int]) -> SetContextResponse:
    set_context = SetContext()
    ctx = context if isinstance(context, int) else context.value
    set_context['Context'] = ctx
    return dce.request(set_context)


def hStartShadowCopySet(dce: DCERPC_v5, clientShadowCopySetId: bytes) -> StartShadowCopySetResponse:
    start_shadow_copy = StartShadowCopySet()
    start_shadow_copy['ClientShadowCopySetId'] = clientShadowCopySetId
    return dce.request(start_shadow_copy)


def hAddToShadowCopySet(dce: DCERPC_v5, ClientShadowCopyId: bytes, ShadowCopySetId: bytes, ShareName: str) -> AddToShadowCopySetResponse:
    add_to_shadow_copy = AddToShadowCopySet()
    add_to_shadow_copy['ClientShadowCopyId'] = ClientShadowCopyId
    add_to_shadow_copy['ShadowCopySetId'] = ShadowCopySetId
    add_to_shadow_copy['ShareName'] = checkNullString(ShareName)
    return dce.request(add_to_shadow_copy)


def hCommitShadowCopySet(dce: DCERPC_v5, ShadowCopySetId: str, TimeOutInMilliseconds: int) -> CommitShadowCopySetResponse:
    commit_shadow_copy = CommitShadowCopySet()
    commit_shadow_copy['ShadowCopySetId'] = ShadowCopySetId
    commit_shadow_copy['TimeOutInMilliseconds'] = TimeOutInMilliseconds
    return dce.request(commit_shadow_copy)


def hExposeShadowCopySet(dce: DCERPC_v5, ShadowCopySetId: bytes, TimeOutInMilliseconds: int) -> ExposeShadowCopySetResponse:
    expose_shadow_copy = ExposeShadowCopySet()
    expose_shadow_copy['ShadowCopySetId'] = ShadowCopySetId
    expose_shadow_copy['TimeOutInMilliseconds'] = TimeOutInMilliseconds
    return dce.request(expose_shadow_copy)


def hRecoveryCompleteShadowCopySet(dce: DCERPC_v5, ShadowCopySetId: bytes) -> RecoveryCompleteShadowCopySetResponse:
    recovery_complete = RecoveryCompleteShadowCopySet()
    recovery_complete['ShadowCopySetId'] = ShadowCopySetId
    return dce.request(recovery_complete)


def hAbortShadowCopySet(dce: DCERPC_v5, ShadowCopySetId: bytes) -> AbortShadowCopySetResponse:
    request = AbortShadowCopySet()
    request['ShadowCopySetId'] = ShadowCopySetId
    return dce.request(request)


def hIsPathSupported(dce: DCERPC_v5, ShareName: Optional[str]) -> IsPathSupportedResponse:
    request = IsPathSupported()
    request['ShareName'] = checkNullString(ShareName)
    return dce.request(request)


def hIsPathShadowCopied(dce: DCERPC_v5, ShareName: Optional[str]) -> IsPathShadowCopiedResponse:
    request = IsPathShadowCopied()
    request['ShareName'] = checkNullString(ShareName)
    return dce.request(request)


def hGetShareMapping(dce: DCERPC_v5, ShadowCopyId: bytes, ShadowCopySetId: bytes, ShareName: str, Level: int=1) -> GetShareMappingResponse:
    request = GetShareMapping()
    request['ShadowCopyId'] = ShadowCopyId
    request['ShadowCopySetId'] = ShadowCopySetId
    request['ShareName'] = checkNullString(ShareName)
    request['Level'] = Level
    return dce.request(request)


def hDeleteShareMapping(dce: DCERPC_v5, ShadowCopySetId: bytes, ShadowCopyId: bytes, ShareName: str) -> DeleteShareMappingResponse:
    request = DeleteShareMapping()
    request['ShadowCopySetId'] = ShadowCopySetId
    request['ShadowCopyId'] = ShadowCopyId
    request['ShareName'] = checkNullString(ShareName)
    return dce.request(request)


def hPrepareShadowCopySet(dce: DCERPC_v5, ShadowCopySetId: bytes, TimeOutInMilliseconds: int) -> PrepareShadowCopySetResponse:
    request = PrepareShadowCopySet()
    request['ShadowCopySetId'] = ShadowCopySetId
    request['TimeOutInMilliseconds'] = TimeOutInMilliseconds
    return dce.request(request)
