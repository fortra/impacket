# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-LSAT] Interface implementation
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
from impacket import nt_errors
from impacket.dcerpc.v5.dtypes import ULONG, LONG, PRPC_SID, RPC_UNICODE_STRING, LPWSTR, PRPC_UNICODE_STRING, NTSTATUS, \
    NULL
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.lsad import LSAPR_HANDLE, PLSAPR_TRUST_INFORMATION_ARRAY
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_LSAT  = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES:
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'LSAT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'LSAT SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 2.2.10 ACCESS_MASK
POLICY_LOOKUP_NAMES             = 0x00000800

################################################################################
# STRUCTURES
################################################################################
# 2.2.12 LSAPR_REFERENCED_DOMAIN_LIST
class LSAPR_REFERENCED_DOMAIN_LIST(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('Domains', PLSAPR_TRUST_INFORMATION_ARRAY),
        ('MaxEntries', ULONG),
    )

class PLSAPR_REFERENCED_DOMAIN_LIST(NDRPOINTER):
    referent = (
        ('Data', LSAPR_REFERENCED_DOMAIN_LIST),
    )

# 2.2.14 LSA_TRANSLATED_SID
class LSA_TRANSLATED_SID(NDRSTRUCT):
    structure = (
        ('Use', SID_NAME_USE),
        ('RelativeId', ULONG),
        ('DomainIndex', LONG),
    )

# 2.2.15 LSAPR_TRANSLATED_SIDS
class LSA_TRANSLATED_SID_ARRAY(NDRUniConformantArray):
    item = LSA_TRANSLATED_SID

class PLSA_TRANSLATED_SID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSA_TRANSLATED_SID_ARRAY),
    )

class LSAPR_TRANSLATED_SIDS(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('Sids', PLSA_TRANSLATED_SID_ARRAY),
    )

# 2.2.16 LSAP_LOOKUP_LEVEL
class LSAP_LOOKUP_LEVEL(NDRENUM):
    class enumItems(Enum):
        LsapLookupWksta                = 1
        LsapLookupPDC                  = 2
        LsapLookupTDL                  = 3
        LsapLookupGC                   = 4
        LsapLookupXForestReferral      = 5
        LsapLookupXForestResolve       = 6
        LsapLookupRODCReferralToFullDC = 7

# 2.2.17 LSAPR_SID_INFORMATION
class LSAPR_SID_INFORMATION(NDRSTRUCT):
    structure = (
        ('Sid', PRPC_SID),
    )

# 2.2.18 LSAPR_SID_ENUM_BUFFER
class LSAPR_SID_INFORMATION_ARRAY(NDRUniConformantArray):
    item = LSAPR_SID_INFORMATION

class PLSAPR_SID_INFORMATION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_SID_INFORMATION_ARRAY),
    )

class LSAPR_SID_ENUM_BUFFER(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('SidInfo', PLSAPR_SID_INFORMATION_ARRAY),
    )

# 2.2.19 LSAPR_TRANSLATED_NAME
class LSAPR_TRANSLATED_NAME(NDRSTRUCT):
    structure = (
        ('Use', SID_NAME_USE),
        ('Name', RPC_UNICODE_STRING),
        ('DomainIndex', LONG),
    )

# 2.2.20 LSAPR_TRANSLATED_NAMES
class LSAPR_TRANSLATED_NAME_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_NAME

class PLSAPR_TRANSLATED_NAME_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_TRANSLATED_NAME_ARRAY),
    )

class LSAPR_TRANSLATED_NAMES(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('Names', PLSAPR_TRANSLATED_NAME_ARRAY),
    )

# 2.2.21 LSAPR_TRANSLATED_NAME_EX
class LSAPR_TRANSLATED_NAME_EX(NDRSTRUCT):
    structure = (
        ('Use', SID_NAME_USE),
        ('Name', RPC_UNICODE_STRING),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    )

# 2.2.22 LSAPR_TRANSLATED_NAMES_EX
class LSAPR_TRANSLATED_NAME_EX_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_NAME_EX

class PLSAPR_TRANSLATED_NAME_EX_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_TRANSLATED_NAME_EX_ARRAY),
    )

class LSAPR_TRANSLATED_NAMES_EX(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('Names', PLSAPR_TRANSLATED_NAME_EX_ARRAY),
    )

# 2.2.23 LSAPR_TRANSLATED_SID_EX
class LSAPR_TRANSLATED_SID_EX(NDRSTRUCT):
    structure = (
        ('Use', SID_NAME_USE),
        ('RelativeId', ULONG),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    )

# 2.2.24 LSAPR_TRANSLATED_SIDS_EX
class LSAPR_TRANSLATED_SID_EX_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_SID_EX

class PLSAPR_TRANSLATED_SID_EX_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_TRANSLATED_SID_EX_ARRAY),
    )

class LSAPR_TRANSLATED_SIDS_EX(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('Sids', PLSAPR_TRANSLATED_SID_EX_ARRAY),
    )

# 2.2.25 LSAPR_TRANSLATED_SID_EX2
class LSAPR_TRANSLATED_SID_EX2(NDRSTRUCT):
    structure = (
        ('Use', SID_NAME_USE),
        ('Sid', PRPC_SID),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    )

# 2.2.26 LSAPR_TRANSLATED_SIDS_EX2
class LSAPR_TRANSLATED_SID_EX2_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_SID_EX2

class PLSAPR_TRANSLATED_SID_EX2_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LSAPR_TRANSLATED_SID_EX2_ARRAY),
    )

class LSAPR_TRANSLATED_SIDS_EX2(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('Sids', PLSAPR_TRANSLATED_SID_EX2_ARRAY),
    )

class RPC_UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

################################################################################
# RPC CALLS
################################################################################
# 3.1.4.4 LsarGetUserName (Opnum 45)
class LsarGetUserName(NDRCALL):
    opnum = 45
    structure = (
       ('SystemName', LPWSTR),
       ('UserName', PRPC_UNICODE_STRING),
       ('DomainName', PRPC_UNICODE_STRING),
    )

class LsarGetUserNameResponse(NDRCALL):
    structure = (
       ('UserName', PRPC_UNICODE_STRING),
       ('DomainName', PRPC_UNICODE_STRING),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5 LsarLookupNames4 (Opnum 77)
class LsarLookupNames4(NDRCALL):
    opnum = 77
    structure = (
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    )

class LsarLookupNames4Response(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6 LsarLookupNames3 (Opnum 68)
class LsarLookupNames3(NDRCALL):
    opnum = 68
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    )

class LsarLookupNames3Response(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.7 LsarLookupNames2 (Opnum 58)
class LsarLookupNames2(NDRCALL):
    opnum = 58
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    )

class LsarLookupNames2Response(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.8 LsarLookupNames (Opnum 14)
class LsarLookupNames(NDRCALL):
    opnum = 14
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
    )

class LsarLookupNamesResponse(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.9 LsarLookupSids3 (Opnum 76)
class LsarLookupSids3(NDRCALL):
    opnum = 76
    structure = (
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    )

class LsarLookupSids3Response(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.10 LsarLookupSids2 (Opnum 57)
class LsarLookupSids2(NDRCALL):
    opnum = 57
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    )

class LsarLookupSids2Response(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.11 LsarLookupSids (Opnum 15)
class LsarLookupSids(NDRCALL):
    opnum = 15
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
    )

class LsarLookupSidsResponse(NDRCALL):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 14 : (LsarLookupNames, LsarLookupNamesResponse),
 15 : (LsarLookupSids, LsarLookupSidsResponse),
 45 : (LsarGetUserName, LsarGetUserNameResponse),
 57 : (LsarLookupSids2, LsarLookupSids2Response),
 58 : (LsarLookupNames2, LsarLookupNames2Response),
 68 : (LsarLookupNames3, LsarLookupNames3Response),
 76 : (LsarLookupSids3, LsarLookupSids3Response),
 77 : (LsarLookupNames4, LsarLookupNames4Response),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hLsarGetUserName(dce, userName = NULL, domainName = NULL):
    request = LsarGetUserName()
    request['SystemName'] = NULL
    request['UserName'] = userName
    request['DomainName'] = domainName
    return dce.request(request)

def hLsarLookupNames4(dce, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001):
    request = LsarLookupNames4()
    request['Count'] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn['Data'] = name
        request['Names'].append(itemn)
    request['TranslatedSids']['Sids'] = NULL
    request['LookupLevel'] = lookupLevel
    request['LookupOptions'] = lookupOptions
    request['ClientRevision'] = clientRevision

    return dce.request(request)

def hLsarLookupNames3(dce, policyHandle, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001):
    request = LsarLookupNames3()
    request['PolicyHandle'] = policyHandle
    request['Count'] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn['Data'] = name
        request['Names'].append(itemn)
    request['TranslatedSids']['Sids'] = NULL
    request['LookupLevel'] = lookupLevel
    request['LookupOptions'] = lookupOptions
    request['ClientRevision'] = clientRevision

    return dce.request(request)

def hLsarLookupNames2(dce, policyHandle, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001):
    request = LsarLookupNames2()
    request['PolicyHandle'] = policyHandle
    request['Count'] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn['Data'] = name
        request['Names'].append(itemn)
    request['TranslatedSids']['Sids'] = NULL
    request['LookupLevel'] = lookupLevel
    request['LookupOptions'] = lookupOptions
    request['ClientRevision'] = clientRevision

    return dce.request(request)

def hLsarLookupNames(dce, policyHandle, names, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta):
    request = LsarLookupNames()
    request['PolicyHandle'] = policyHandle
    request['Count'] = len(names)
    for name in names:
        itemn = RPC_UNICODE_STRING()
        itemn['Data'] = name
        request['Names'].append(itemn)
    request['TranslatedSids']['Sids'] = NULL
    request['LookupLevel'] = lookupLevel

    return dce.request(request)

def hLsarLookupSids2(dce, policyHandle, sids, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta, lookupOptions=0x00000000, clientRevision=0x00000001):
    request = LsarLookupSids2()
    request['PolicyHandle'] = policyHandle
    request['SidEnumBuffer']['Entries'] = len(sids)
    for sid in sids:
        itemn = LSAPR_SID_INFORMATION()
        itemn['Sid'].fromCanonical(sid)
        request['SidEnumBuffer']['SidInfo'].append(itemn)

    request['TranslatedNames']['Names'] = NULL
    request['LookupLevel'] = lookupLevel
    request['LookupOptions'] = lookupOptions
    request['ClientRevision'] = clientRevision

    return dce.request(request)

def hLsarLookupSids(dce, policyHandle, sids, lookupLevel = LSAP_LOOKUP_LEVEL.LsapLookupWksta):
    request = LsarLookupSids()
    request['PolicyHandle'] = policyHandle
    request['SidEnumBuffer']['Entries'] = len(sids)
    for sid in sids:
        itemn = LSAPR_SID_INFORMATION()
        itemn['Sid'].fromCanonical(sid)
        request['SidEnumBuffer']['SidInfo'].append(itemn)

    request['TranslatedNames']['Names'] = NULL
    request['LookupLevel'] = lookupLevel

    return dce.request(request)
