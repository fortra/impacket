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
#   [MS-LSAT] Interface implementation
#

from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.ndr import NDRCall, NDR, NDRENUM, NDRUnion, NDRPointer, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import *
from impacket import nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.lsad import LSAPR_HANDLE, PSTRING, LSAPR_ACL, SECURITY_DESCRIPTOR_CONTROL, LSAPR_SECURITY_DESCRIPTOR, PLSAPR_SECURITY_DESCRIPTOR, SECURITY_IMPERSONATION_LEVEL, SECURITY_CONTEXT_TRACKING_MODE, SECURITY_QUALITY_OF_SERVICE, LSAPR_OBJECT_ATTRIBUTES, LSAPR_TRUST_INFORMATION, PLSAPR_TRUST_INFORMATION_ARRAY, PRPC_UNICODE_STRING_ARRAY, LsarOpenPolicy2, LsarOpenPolicy, LsarClose
from impacket.dcerpc.v5.samr import SID_NAME_USE

MSRPC_UUID_LSAT  = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))

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
            return 'LSAT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'LSAT SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# CONSTANTS
################################################################################
# 2.2.10 ACCESS_MASK
POLICY_LOOKUP_NAMES             = 0x00000800

################################################################################
# STRUCTURES
################################################################################
# 2.2.12 LSAPR_REFERENCED_DOMAIN_LIST
class LSAPR_REFERENCED_DOMAIN_LIST(NDR):
    structure = (
        ('Entries', ULONG),
        ('Domains', PLSAPR_TRUST_INFORMATION_ARRAY),
        ('MaxEntries', ULONG),
    )

class PLSAPR_REFERENCED_DOMAIN_LIST(NDRPointer):
    referent = (
        ('Data', LSAPR_REFERENCED_DOMAIN_LIST),
    )

# 2.2.14 LSA_TRANSLATED_SID
class LSA_TRANSLATED_SID(NDR):
    structure = (
        ('Use', SID_NAME_USE),
        ('RelativeId', ULONG),
        ('DomainIndex', LONG),
    )

# 2.2.15 LSAPR_TRANSLATED_SIDS
class LSA_TRANSLATED_SID_ARRAY(NDRUniConformantArray):
    item = LSA_TRANSLATED_SID

class PLSA_TRANSLATED_SID_ARRAY(NDRPointer):
    referent = (
        ('Data', LSA_TRANSLATED_SID_ARRAY),
    )

class LSAPR_TRANSLATED_SIDS(NDR):
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
class LSAPR_SID_INFORMATION(NDR):
    structure = (
        ('Sid', PRPC_SID),
    )

# 2.2.18 LSAPR_SID_ENUM_BUFFER
class LSAPR_SID_INFORMATION_ARRAY(NDRUniConformantArray):
    item = LSAPR_SID_INFORMATION

class PLSAPR_SID_INFORMATION_ARRAY(NDRPointer):
    referent = (
        ('Data', LSAPR_SID_INFORMATION_ARRAY),
    )

class LSAPR_SID_ENUM_BUFFER(NDR):
    structure = (
        ('Entries', ULONG),
        ('SidInfo', PLSAPR_SID_INFORMATION_ARRAY),
    )

# 2.2.19 LSAPR_TRANSLATED_NAME
class LSAPR_TRANSLATED_NAME(NDR):
    structure = (
        ('Use', SID_NAME_USE),
        ('Name', RPC_UNICODE_STRING),
        ('DomainIndex', LONG),
    )

# 2.2.20 LSAPR_TRANSLATED_NAMES
class LSAPR_TRANSLATED_NAME_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_NAME

class PLSAPR_TRANSLATED_NAME_ARRAY(NDRPointer):
    referent = (
        ('Data', LSAPR_TRANSLATED_NAME_ARRAY),
    )

class LSAPR_TRANSLATED_NAMES(NDR):
    structure = (
        ('Entries', ULONG),
        ('Names', PLSAPR_TRANSLATED_NAME_ARRAY),
    )

# 2.2.21 LSAPR_TRANSLATED_NAME_EX
class LSAPR_TRANSLATED_NAME_EX(NDR):
    structure = (
        ('Use', SID_NAME_USE),
        ('Name', RPC_UNICODE_STRING),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    )

# 2.2.22 LSAPR_TRANSLATED_NAMES_EX
class LSAPR_TRANSLATED_NAME_EX_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_NAME_EX

class PLSAPR_TRANSLATED_NAME_EX_ARRAY(NDRPointer):
    referent = (
        ('Data', LSAPR_TRANSLATED_NAME_EX_ARRAY),
    )

class LSAPR_TRANSLATED_NAMES_EX(NDR):
    structure = (
        ('Entries', ULONG),
        ('Names', PLSAPR_TRANSLATED_NAME_EX_ARRAY),
    )

# 2.2.23 LSAPR_TRANSLATED_SID_EX
class LSAPR_TRANSLATED_SID_EX(NDR):
    structure = (
        ('Use', SID_NAME_USE),
        ('RelativeId', ULONG),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    )

# 2.2.24 LSAPR_TRANSLATED_SIDS_EX
class LSAPR_TRANSLATED_SID_EX_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_SID_EX

class PLSAPR_TRANSLATED_SID_EX_ARRAY(NDRPointer):
    referent = (
        ('Data', LSAPR_TRANSLATED_SID_EX_ARRAY),
    )

class LSAPR_TRANSLATED_SIDS_EX(NDR):
    structure = (
        ('Entries', ULONG),
        ('Sids', PLSAPR_TRANSLATED_SID_EX_ARRAY),
    )

# 2.2.25 LSAPR_TRANSLATED_SID_EX2
class LSAPR_TRANSLATED_SID_EX2(NDR):
    structure = (
        ('Use', SID_NAME_USE),
        ('Sid', PRPC_SID),
        ('DomainIndex', LONG),
        ('Flags', ULONG),
    )

# 2.2.26 LSAPR_TRANSLATED_SIDS_EX2
class LSAPR_TRANSLATED_SID_EX2_ARRAY(NDRUniConformantArray):
    item = LSAPR_TRANSLATED_SID_EX2

class PLSAPR_TRANSLATED_SID_EX2_ARRAY(NDRPointer):
    referent = (
        ('Data', LSAPR_TRANSLATED_SID_EX2_ARRAY),
    )

class LSAPR_TRANSLATED_SIDS_EX2(NDR):
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
class LsarGetUserName(NDRCall):
    opnum = 45
    structure = (
       ('SystemName', LPWSTR),
       ('UserName', PRPC_UNICODE_STRING),
       ('DomainName', PRPC_UNICODE_STRING),
    )

class LsarGetUserNameResponse(NDRCall):
    structure = (
       ('UserName', PRPC_UNICODE_STRING),
       ('DomainName', PRPC_UNICODE_STRING),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.5 LsarLookupNames4 (Opnum 77)
class LsarLookupNames4(NDRCall):
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

class LsarLookupNames4Response(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.6 LsarLookupNames3 (Opnum 68)
class LsarLookupNames3(NDRCall):
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

class LsarLookupNames3Response(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX2),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.7 LsarLookupNames2 (Opnum 58)
class LsarLookupNames2(NDRCall):
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

class LsarLookupNames2Response(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.8 LsarLookupNames (Opnum 14)
class LsarLookupNames(NDRCall):
    opnum = 14
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('Count', ULONG),
       ('Names', RPC_UNICODE_STRING_ARRAY),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
    )

class LsarLookupNamesResponse(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedSids', LSAPR_TRANSLATED_SIDS),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.9 LsarLookupSids3 (Opnum 76)
class LsarLookupSids3(NDRCall):
    opnum = 76
    structure = (
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
       ('LookupOptions', ULONG),
       ('ClientRevision', ULONG),
    )

class LsarLookupSids3Response(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.10 LsarLookupSids2 (Opnum 57)
class LsarLookupSids2(NDRCall):
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

class LsarLookupSids2Response(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES_EX),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

# 3.1.4.11 LsarLookupSids (Opnum 15)
class LsarLookupSids(NDRCall):
    opnum = 15
    structure = (
       ('PolicyHandle', LSAPR_HANDLE),
       ('SidEnumBuffer', LSAPR_SID_ENUM_BUFFER),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES),
       ('LookupLevel', LSAP_LOOKUP_LEVEL),
       ('MappedCount', ULONG),
    )

class LsarLookupSidsResponse(NDRCall):
    structure = (
       ('ReferencedDomains', PLSAPR_REFERENCED_DOMAIN_LIST),
       ('TranslatedNames', LSAPR_TRANSLATED_NAMES),
       ('MappedCount', ULONG),
       ('ErrorCode', NTSTATUS),
    )

################################################################################
# HELPER FUNCTIONS
################################################################################

