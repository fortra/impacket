# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-DRSR] Directory Replication Service (DRS) DRSUAPI Interface implementation
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
import hashlib
from struct import pack

from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray, NDRUNION, NDR, NDRENUM
from impacket.dcerpc.v5.dtypes import PUUID, DWORD, NULL, GUID, LPWSTR, BOOL, ULONG, UUID, LONGLONG, ULARGE_INTEGER, LARGE_INTEGER
from impacket import hresult_errors, system_errors
from impacket.structure import Structure
from impacket.uuid import uuidtup_to_bin, string_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.krb5 import crypto
from pyasn1.type import univ
from pyasn1.codec.ber import decoder

try:
    from Crypto.Cipher import ARC4, DES
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need PyCrypto")
    LOG.critical("See http://www.pycrypto.org/")

MSRPC_UUID_DRSUAPI = uuidtup_to_bin(('E3514235-4B06-11D1-AB04-00C04FC2DCD2','4.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if hresult_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'DRSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif system_errors.ERROR_MESSAGES.has_key(key & 0xffff):
            error_msg_short = system_errors.ERROR_MESSAGES[key & 0xffff][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key & 0xffff][1]
            return 'DRSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DRSR SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 4.1.10.2.17 EXOP_ERR Codes
class EXOP_ERR(NDRENUM):
    align = 4
    align64 = 4
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        EXOP_ERR_SUCCESS               = 0x00000001
        EXOP_ERR_UNKNOWN_OP            = 0x00000002
        EXOP_ERR_FSMO_NOT_OWNER        = 0x00000003
        EXOP_ERR_UPDATE_ERR            = 0x00000004
        EXOP_ERR_EXCEPTION             = 0x00000005
        EXOP_ERR_UNKNOWN_CALLER        = 0x00000006
        EXOP_ERR_RID_ALLOC             = 0x00000007
        EXOP_ERR_FSMO_OWNER_DELETED    = 0x00000008
        EXOP_ERR_FSMO_PENDING_OP       = 0x00000009
        EXOP_ERR_MISMATCH              = 0x0000000A
        EXOP_ERR_COULDNT_CONTACT       = 0x0000000B
        EXOP_ERR_FSMO_REFUSING_ROLES   = 0x0000000C
        EXOP_ERR_DIR_ERROR             = 0x0000000D
        EXOP_ERR_FSMO_MISSING_SETTINGS = 0x0000000E
        EXOP_ERR_ACCESS_DENIED         = 0x0000000F
        EXOP_ERR_PARAM_ERROR           = 0x00000010

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        if msg != '':
            print msg,

        try:
            print " %s" % self.enumItems(self.fields['Data']).name,
        except ValueError:
            print " %d" % self.fields['Data']

# 4.1.10.2.18 EXOP_REQ Codes
EXOP_FSMO_REQ_ROLE = 0x00000001
EXOP_FSMO_REQ_RID_ALLOC = 0x00000002
EXOP_FSMO_RID_REQ_ROLE = 0x00000003
EXOP_FSMO_REQ_PDC = 0x00000004
EXOP_FSMO_ABANDON_ROLE = 0x00000005
EXOP_REPL_OBJ = 0x00000006
EXOP_REPL_SECRETS = 0x00000007

# 5.14 ATTRTYP
ATTRTYP = ULONG

# 5.51 DSTIME
DSTIME = LONGLONG

# 5.39 DRS_EXTENSIONS_INT
DRS_EXT_BASE = 0x00000001
DRS_EXT_ASYNCREPL = 0x00000002
DRS_EXT_REMOVEAPI = 0x00000004
DRS_EXT_MOVEREQ_V2 = 0x00000008
DRS_EXT_GETCHG_DEFLATE = 0x00000010
DRS_EXT_DCINFO_V1 = 0x00000020
DRS_EXT_RESTORE_USN_OPTIMIZATION = 0x00000040
DRS_EXT_ADDENTRY = 0x00000080
DRS_EXT_KCC_EXECUTE = 0x00000100
DRS_EXT_ADDENTRY_V2 = 0x00000200
DRS_EXT_LINKED_VALUE_REPLICATION = 0x00000400
DRS_EXT_DCINFO_V2 = 0x00000800
DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD = 0x00001000
DRS_EXT_CRYPTO_BIND = 0x00002000
DRS_EXT_GET_REPL_INFO = 0x00004000
DRS_EXT_STRONG_ENCRYPTION = 0x00008000
DRS_EXT_DCINFO_VFFFFFFFF = 0x00010000
DRS_EXT_TRANSITIVE_MEMBERSHIP = 0x00020000
DRS_EXT_ADD_SID_HISTORY = 0x00040000
DRS_EXT_POST_BETA3 = 0x00080000
DRS_EXT_GETCHGREQ_V5 = 0x00100000
DRS_EXT_GETMEMBERSHIPS2 = 0x00200000
DRS_EXT_GETCHGREQ_V6 = 0x00400000
DRS_EXT_NONDOMAIN_NCS = 0x00800000
DRS_EXT_GETCHGREQ_V8 = 0x01000000
DRS_EXT_GETCHGREPLY_V5 = 0x02000000
DRS_EXT_GETCHGREPLY_V6 = 0x04000000
DRS_EXT_GETCHGREPLY_V9 = 0x00000100
DRS_EXT_WHISTLER_BETA3 = 0x08000000
DRS_EXT_W2K3_DEFLATE = 0x10000000
DRS_EXT_GETCHGREQ_V10 = 0x20000000
DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2 = 0x40000000
DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3 = 0x80000000

# dwFlagsExt
DRS_EXT_ADAM = 0x00000001
DRS_EXT_LH_BETA2 = 0x00000002
DRS_EXT_RECYCLE_BIN = 0x00000004

# 5.41 DRS_OPTIONS
DRS_ASYNC_OP = 0x00000001
DRS_GETCHG_CHECK = 0x00000002
DRS_UPDATE_NOTIFICATION = 0x00000002
DRS_ADD_REF = 0x00000004
DRS_SYNC_ALL = 0x00000008
DRS_DEL_REF = 0x00000008
DRS_WRIT_REP = 0x00000010
DRS_INIT_SYNC = 0x00000020
DRS_PER_SYNC = 0x00000040
DRS_MAIL_REP = 0x00000080
DRS_ASYNC_REP = 0x00000100
DRS_IGNORE_ERROR = 0x00000100
DRS_TWOWAY_SYNC = 0x00000200
DRS_CRITICAL_ONLY = 0x00000400
DRS_GET_ANC = 0x00000800
DRS_GET_NC_SIZE = 0x00001000
DRS_LOCAL_ONLY = 0x00001000
DRS_NONGC_RO_REP = 0x00002000
DRS_SYNC_BYNAME = 0x00004000
DRS_REF_OK = 0x00004000
DRS_FULL_SYNC_NOW = 0x00008000
DRS_NO_SOURCE = 0x00008000
DRS_FULL_SYNC_IN_PROGRESS = 0x00010000
DRS_FULL_SYNC_PACKET = 0x00020000
DRS_SYNC_REQUEUE = 0x00040000
DRS_SYNC_URGENT = 0x00080000
DRS_REF_GCSPN = 0x00100000
DRS_NO_DISCARD = 0x00100000
DRS_NEVER_SYNCED = 0x00200000
DRS_SPECIAL_SECRET_PROCESSING = 0x00400000
DRS_INIT_SYNC_NOW = 0x00800000
DRS_PREEMPTED = 0x01000000
DRS_SYNC_FORCED = 0x02000000
DRS_DISABLE_AUTO_SYNC = 0x04000000
DRS_DISABLE_PERIODIC_SYNC = 0x08000000
DRS_USE_COMPRESSION = 0x10000000
DRS_NEVER_NOTIFY = 0x20000000
DRS_SYNC_PAS = 0x40000000
DRS_GET_ALL_GROUP_MEMBERSHIP = 0x80000000


# 5.113 LDAP_CONN_PROPERTIES
BND = 0x00000001
SSL = 0x00000002
UDP = 0x00000004
GC = 0x00000008
GSS = 0x00000010
NGO = 0x00000020
SPL = 0x00000040
MD5 = 0x00000080
SGN = 0x00000100
SL = 0x00000200

# 5.137 NTSAPI_CLIENT_GUID
NTDSAPI_CLIENT_GUID = string_to_bin('e24d201a-4fd6-11d1-a3da-0000f875ae0d')

# 5.139 NULLGUID
NULLGUID = string_to_bin('00000000-0000-0000-0000-000000000000')

# 5.205 USN
USN = LONGLONG

# 4.1.4.1.2 DRS_MSG_CRACKREQ_V1
DS_NAME_FLAG_GCVERIFY = 0x00000004
DS_NAME_FLAG_TRUST_REFERRAL = 0x00000008
DS_NAME_FLAG_PRIVATE_RESOLVE_FPOS = 0x80000000

DS_LIST_SITES = 0xFFFFFFFF
DS_LIST_SERVERS_IN_SITE = 0xFFFFFFFE
DS_LIST_DOMAINS_IN_SITE = 0xFFFFFFFD
DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE = 0xFFFFFFFC
DS_LIST_INFO_FOR_SERVER = 0xFFFFFFFB
DS_LIST_ROLES = 0xFFFFFFFA
DS_NT4_ACCOUNT_NAME_SANS_DOMAIN = 0xFFFFFFF9
DS_MAP_SCHEMA_GUID = 0xFFFFFFF8
DS_LIST_DOMAINS = 0xFFFFFFF7
DS_LIST_NCS = 0xFFFFFFF6
DS_ALT_SECURITY_IDENTITIES_NAME = 0xFFFFFFF5
DS_STRING_SID_NAME = 0xFFFFFFF4
DS_LIST_SERVERS_WITH_DCS_IN_SITE = 0xFFFFFFF3
DS_LIST_GLOBAL_CATALOG_SERVERS = 0xFFFFFFF1
DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX = 0xFFFFFFF0
DS_USER_PRINCIPAL_NAME_AND_ALTSECID = 0xFFFFFFEF

DS_USER_PRINCIPAL_NAME_FOR_LOGON = 0xFFFFFFF2

# 5.53 ENTINF
ENTINF_FROM_MASTER = 0x00000001
ENTINF_DYNAMIC_OBJECT = 0x00000002
ENTINF_REMOTE_MODIFY = 0x00010000

# 4.1.27.1.2 DRS_MSG_VERIFYREQ_V1
DRS_VERIFY_DSNAMES = 0x00000000
DRS_VERIFY_SIDS = 0x00000001
DRS_VERIFY_SAM_ACCOUNT_NAMES = 0x00000002
DRS_VERIFY_FPOS = 0x00000003

# 4.1.11.1.2 DRS_MSG_NT4_CHGLOG_REQ_V1
DRS_NT4_CHGLOG_GET_CHANGE_LOG = 0x00000001
DRS_NT4_CHGLOG_GET_SERIAL_NUMBERS = 0x00000002

# 4.1.10.2.15 DRS_MSG_GETCHGREPLY_NATIVE_VERSION_NUMBER
DRS_MSG_GETCHGREPLY_NATIVE_VERSION_NUMBER = 9
################################################################################
# STRUCTURES
################################################################################
# 4.1.10.2.16 ENCRYPTED_PAYLOAD
class ENCRYPTED_PAYLOAD(Structure):
    structure = (
        ('Salt','16s'),
        ('CheckSum','<L'),
        ('EncryptedData',':'),
    )

# 5.136 NT4SID
class NT4SID(NDRSTRUCT):
    structure =  (
        ('Data','28s=""'),
    )
    def getAlignment(self):
        return 4

# 5.40 DRS_HANDLE
class DRS_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        return 4

class PDRS_HANDLE(NDRPOINTER):
    referent = (
        ('Data',DRS_HANDLE),
    )

# 5.38 DRS_EXTENSIONS
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data',BYTE_ARRAY),
    )

class DRS_EXTENSIONS(NDRSTRUCT):
    structure =  (
        ('cb',DWORD),
        ('rgb',BYTE_ARRAY),
    )

class PDRS_EXTENSIONS(NDRPOINTER):
    referent = (
        ('Data',DRS_EXTENSIONS),
    )

# 5.39 DRS_EXTENSIONS_INT
class DRS_EXTENSIONS_INT(Structure):
    structure =  (
        ('dwFlags','<L=0'),
        ('SiteObjGuid','16s=""'),
        ('Pid','<L=0'),
        ('dwReplEpoch','<L=0'),
        ('dwFlagsExt','<L=0'),
        ('ConfigObjGUID','16s=""'),
        ('dwExtCaps','<L=0'),
    )

# 4.1.5.1.2 DRS_MSG_DCINFOREQ_V1
class DRS_MSG_DCINFOREQ_V1(NDRSTRUCT):
    structure =  (
        ('Domain',LPWSTR),
        ('InfoLevel',DWORD),
    )

# 4.1.5.1.1 DRS_MSG_DCINFOREQ
class DRS_MSG_DCINFOREQ(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_DCINFOREQ_V1),
    }

# 4.1.5.1.8 DS_DOMAIN_CONTROLLER_INFO_1W
class DS_DOMAIN_CONTROLLER_INFO_1W(NDRSTRUCT):
    structure =  (
        ('NetbiosName',LPWSTR),
        ('DnsHostName',LPWSTR),
        ('SiteName',LPWSTR),
        ('ComputerObjectName',LPWSTR),
        ('ServerObjectName',LPWSTR),
        ('fIsPdc',BOOL),
        ('fDsEnabled',BOOL),
    )

class DS_DOMAIN_CONTROLLER_INFO_1W_ARRAY(NDRUniConformantArray):
    item = DS_DOMAIN_CONTROLLER_INFO_1W

class PDS_DOMAIN_CONTROLLER_INFO_1W_ARRAY(NDRPOINTER):
    referent = (
        ('Data',DS_DOMAIN_CONTROLLER_INFO_1W_ARRAY),
    )

# 4.1.5.1.4 DRS_MSG_DCINFOREPLY_V1
class DRS_MSG_DCINFOREPLY_V1(NDRSTRUCT):
    structure =  (
        ('cItems',DWORD),
        ('rItems',PDS_DOMAIN_CONTROLLER_INFO_1W_ARRAY),
    )

# 4.1.5.1.9 DS_DOMAIN_CONTROLLER_INFO_2W
class DS_DOMAIN_CONTROLLER_INFO_2W(NDRSTRUCT):
    structure =  (
        ('NetbiosName',LPWSTR),
        ('DnsHostName',LPWSTR),
        ('SiteName',LPWSTR),
        ('SiteObjectName',LPWSTR),
        ('ComputerObjectName',LPWSTR),
        ('ServerObjectName',LPWSTR),
        ('NtdsDsaObjectName',LPWSTR),
        ('fIsPdc',BOOL),
        ('fDsEnabled',BOOL),
        ('fIsGc',BOOL),
        ('SiteObjectGuid',GUID),
        ('ComputerObjectGuid',GUID),
        ('ServerObjectGuid',GUID),
        ('NtdsDsaObjectGuid',GUID),
    )

class DS_DOMAIN_CONTROLLER_INFO_2W_ARRAY(NDRUniConformantArray):
    item = DS_DOMAIN_CONTROLLER_INFO_2W

class PDS_DOMAIN_CONTROLLER_INFO_2W_ARRAY(NDRPOINTER):
    referent = (
        ('Data',DS_DOMAIN_CONTROLLER_INFO_2W_ARRAY),
    )

# 4.1.5.1.5 DRS_MSG_DCINFOREPLY_V2
class DRS_MSG_DCINFOREPLY_V2(NDRSTRUCT):
    structure =  (
        ('cItems',DWORD),
        ('rItems',PDS_DOMAIN_CONTROLLER_INFO_2W_ARRAY),
    )

# 4.1.5.1.10 DS_DOMAIN_CONTROLLER_INFO_3W
class DS_DOMAIN_CONTROLLER_INFO_3W(NDRSTRUCT):
    structure =  (
        ('NetbiosName',LPWSTR),
        ('DnsHostName',LPWSTR),
        ('SiteName',LPWSTR),
        ('SiteObjectName',LPWSTR),
        ('ComputerObjectName',LPWSTR),
        ('ServerObjectName',LPWSTR),
        ('NtdsDsaObjectName',LPWSTR),
        ('fIsPdc',BOOL),
        ('fDsEnabled',BOOL),
        ('fIsGc',BOOL),
        ('fIsRodc',BOOL),
        ('SiteObjectGuid',GUID),
        ('ComputerObjectGuid',GUID),
        ('ServerObjectGuid',GUID),
        ('NtdsDsaObjectGuid',GUID),
    )

class DS_DOMAIN_CONTROLLER_INFO_3W_ARRAY(NDRUniConformantArray):
    item = DS_DOMAIN_CONTROLLER_INFO_3W

class PDS_DOMAIN_CONTROLLER_INFO_3W_ARRAY(NDRPOINTER):
    referent = (
        ('Data',DS_DOMAIN_CONTROLLER_INFO_3W_ARRAY),
    )

# 4.1.5.1.6 DRS_MSG_DCINFOREPLY_V3
class DRS_MSG_DCINFOREPLY_V3(NDRSTRUCT):
    structure =  (
        ('cItems',DWORD),
        ('rItems',PDS_DOMAIN_CONTROLLER_INFO_3W_ARRAY),
    )

# 4.1.5.1.11 DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW
class DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW(NDRSTRUCT):
    structure =  (
        ('IPAddress',DWORD),
        ('NotificationCount',DWORD),
        ('secTimeConnected',DWORD),
        ('Flags',DWORD),
        ('TotalRequests',DWORD),
        ('Reserved1',DWORD),
        ('UserName',LPWSTR),
    )

class DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY(NDRUniConformantArray):
    item = DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW

class PDS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY(NDRPOINTER):
    referent = (
        ('Data',DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY),
    )

# 4.1.5.1.7 DRS_MSG_DCINFOREPLY_VFFFFFFFF
class DRS_MSG_DCINFOREPLY_VFFFFFFFF(NDRSTRUCT):
    structure =  (
        ('cItems',DWORD),
        ('rItems',PDS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW_ARRAY),
    )

# 4.1.5.1.3 DRS_MSG_DCINFOREPLY
class DRS_MSG_DCINFOREPLY(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_DCINFOREPLY_V1),
        2  : ('V2', DRS_MSG_DCINFOREPLY_V2),
        3  : ('V3', DRS_MSG_DCINFOREPLY_V3),
        0xffffffff  : ('V1', DRS_MSG_DCINFOREPLY_VFFFFFFFF),
    }

# 4.1.4.1.2 DRS_MSG_CRACKREQ_V1
class LPWSTR_ARRAY(NDRUniConformantArray):
    item = LPWSTR

class PLPWSTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data',LPWSTR_ARRAY),
    )

class DRS_MSG_CRACKREQ_V1(NDRSTRUCT):
    structure =  (
        ('CodePage',ULONG),
        ('LocaleId',ULONG),
        ('dwFlags',DWORD),
        ('formatOffered',DWORD),
        ('formatDesired',DWORD),
        ('cNames',DWORD),
        ('rpNames',PLPWSTR_ARRAY),
    )

# 4.1.4.1.1 DRS_MSG_CRACKREQ
class DRS_MSG_CRACKREQ(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_CRACKREQ_V1),
    }

# 4.1.4.1.3 DS_NAME_FORMAT
class DS_NAME_FORMAT(NDRENUM):
    class enumItems(Enum):
        DS_UNKNOWN_NAME            = 0
        DS_FQDN_1779_NAME          = 1
        DS_NT4_ACCOUNT_NAME        = 2
        DS_DISPLAY_NAME            = 3
        DS_UNIQUE_ID_NAME          = 6
        DS_CANONICAL_NAME          = 7
        DS_USER_PRINCIPAL_NAME     = 8
        DS_CANONICAL_NAME_EX       = 9
        DS_SERVICE_PRINCIPAL_NAME  = 10
        DS_SID_OR_SID_HISTORY_NAME = 11
        DS_DNS_DOMAIN_NAME         = 12

# 4.1.4.1.4 DS_NAME_RESULT_ITEMW
class DS_NAME_RESULT_ITEMW(NDRSTRUCT):
    structure =  (
        ('status',DWORD),
        ('pDomain',LPWSTR),
        ('pName',LPWSTR),
    )

class DS_NAME_RESULT_ITEMW_ARRAY(NDRUniConformantArray):
    item = DS_NAME_RESULT_ITEMW

class PDS_NAME_RESULT_ITEMW_ARRAY(NDRPOINTER):
    referent = (
        ('Data',DS_NAME_RESULT_ITEMW_ARRAY),
    )

# 4.1.4.1.5 DS_NAME_RESULTW
class DS_NAME_RESULTW(NDRSTRUCT):
    structure =  (
        ('cItems',DWORD),
        ('rItems',PDS_NAME_RESULT_ITEMW_ARRAY),
    )

class PDS_NAME_RESULTW(NDRPOINTER):
    referent = (
        ('Data',DS_NAME_RESULTW),
    )

# 4.1.4.1.7 DRS_MSG_CRACKREPLY_V1
class DRS_MSG_CRACKREPLY_V1(NDRSTRUCT):
    structure =  (
        ('pResult',PDS_NAME_RESULTW),
    )

# 4.1.4.1.6 DRS_MSG_CRACKREPLY
class DRS_MSG_CRACKREPLY(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_CRACKREPLY_V1),
    }

# 5.198 UPTODATE_CURSOR_V1
class UPTODATE_CURSOR_V1(NDRSTRUCT):
    structure =  (
        ('uuidDsa',UUID),
        ('usnHighPropUpdate',USN),
    )

class UPTODATE_CURSOR_V1_ARRAY(NDRUniConformantArray):
    item = UPTODATE_CURSOR_V1

# 5.200 UPTODATE_VECTOR_V1_EXT
class UPTODATE_VECTOR_V1_EXT(NDRSTRUCT):
    structure =  (
        ('dwVersion',DWORD),
        ('dwReserved1',DWORD),
        ('cNumCursors',DWORD),
        ('dwReserved2',DWORD),
        ('rgCursors',UPTODATE_CURSOR_V1_ARRAY),
    )

class PUPTODATE_VECTOR_V1_EXT(NDRPOINTER):
    referent = (
        ('Data',UPTODATE_VECTOR_V1_EXT),
    )

# 5.206 USN_VECTOR
class USN_VECTOR(NDRSTRUCT):
    structure =  (
        ('usnHighObjUpdate',USN),
        ('usnReserved',USN),
        ('usnHighPropUpdate',USN),
    )

# 5.50 DSNAME
class WCHAR_ARRAY(NDRUniConformantArray):
    item  = 'H'

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        self.data = None        # force recompute
        return NDRUniConformantArray.__setitem__(self, key, [ord(c) for c in value])

    def __getitem__(self, key):
        if key == 'Data':
            return ''.join([chr(i) for i in self.fields[key]])
        else:
            return NDR.__getitem__(self,key)

class DSNAME(NDRSTRUCT):
    structure =  (
        ('structLen',ULONG),
        ('SidLen',ULONG),
        ('Guid',GUID),
        ('Sid',NT4SID),
        ('NameLen',ULONG),
        ('StringName', WCHAR_ARRAY),
    )
    def getDataLen(self, data):
        return self['NameLen']
    def getData(self, soFar = 0):
        return NDRSTRUCT.getData(self, soFar)

class PDSNAME(NDRPOINTER):
    referent = (
        ('Data',DSNAME),
    )

class PDSNAME_ARRAY(NDRUniConformantArray):
    item = PDSNAME

class PPDSNAME_ARRAY(NDRPOINTER):
    referent = (
        ('Data',PDSNAME_ARRAY),
    )

class ATTRTYP_ARRAY(NDRUniConformantArray):
    item = ATTRTYP

# 5.145 PARTIAL_ATTR_VECTOR_V1_EXT
class PARTIAL_ATTR_VECTOR_V1_EXT(NDRSTRUCT):
    structure =  (
        ('dwVersion',DWORD),
        ('dwReserved1',DWORD),
        ('cAttrs',DWORD),
        ('rgPartialAttr',ATTRTYP_ARRAY),
    )

class PPARTIAL_ATTR_VECTOR_V1_EXT(NDRPOINTER):
    referent = (
        ('Data',PARTIAL_ATTR_VECTOR_V1_EXT),
    )

# 5.142 OID_t
class OID_t(NDRSTRUCT):
    structure =  (
        ('length',ULONG),
        ('elements',PBYTE_ARRAY),
    )

# 5.153 PrefixTableEntry
class PrefixTableEntry(NDRSTRUCT):
    structure =  (
        ('ndx',ULONG),
        ('prefix',OID_t),
    )

class PrefixTableEntry_ARRAY(NDRUniConformantArray):
    item = PrefixTableEntry

class PPrefixTableEntry_ARRAY(NDRPOINTER):
    referent = (
        ('Data',PrefixTableEntry_ARRAY),
    )

# 5.177 SCHEMA_PREFIX_TABLE
class SCHEMA_PREFIX_TABLE(NDRSTRUCT):
    structure =  (
        ('PrefixCount',DWORD),
        ('pPrefixEntry',PPrefixTableEntry_ARRAY),
    )

# 4.1.10.2.2 DRS_MSG_GETCHGREQ_V3
class DRS_MSG_GETCHGREQ_V3(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjDest',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('pUpToDateVecDestV1',PUPTODATE_VECTOR_V1_EXT),
        ('pPartialAttrVecDestV1',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('PrefixTableDest',SCHEMA_PREFIX_TABLE),
        ('ulFlags',ULONG),
        ('cMaxObjects',ULONG),
        ('cMaxBytes',ULONG),
        ('ulExtendedOp',ULONG),
    )

# 5.131 MTX_ADDR
class MTX_ADDR(NDRSTRUCT):
    structure =  (
        ('mtx_namelen',ULONG),
        ('mtx_name',PBYTE_ARRAY),
    )

class PMTX_ADDR(NDRPOINTER):
    referent = (
        ('Data',MTX_ADDR),
    )

# 4.1.10.2.3 DRS_MSG_GETCHGREQ_V4
class DRS_MSG_GETCHGREQ_V4(NDRSTRUCT):
    structure =  (
        ('uuidTransportObj',UUID),
        ('pmtxReturnAddress',PMTX_ADDR),
        ('V3',DRS_MSG_GETCHGREQ_V3),
    )

# 4.1.10.2.4 DRS_MSG_GETCHGREQ_V5
class DRS_MSG_GETCHGREQ_V5(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjDest',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('pUpToDateVecDestV1',PUPTODATE_VECTOR_V1_EXT),
        ('ulFlags',ULONG),
        ('cMaxObjects',ULONG),
        ('cMaxBytes',ULONG),
        ('ulExtendedOp',ULONG),
        ('liFsmoInfo',ULARGE_INTEGER),
    )

# 4.1.10.2.5 DRS_MSG_GETCHGREQ_V7
class DRS_MSG_GETCHGREQ_V7(NDRSTRUCT):
    structure =  (
        ('uuidTransportObj',UUID),
        ('pmtxReturnAddress',PMTX_ADDR),
        ('V3',DRS_MSG_GETCHGREQ_V3),
        ('pPartialAttrSet',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('pPartialAttrSetEx1',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('PrefixTableDest',SCHEMA_PREFIX_TABLE),
    )

# 4.1.10.2.6 DRS_MSG_GETCHGREQ_V8
class DRS_MSG_GETCHGREQ_V8(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjDest',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('pUpToDateVecDest',PUPTODATE_VECTOR_V1_EXT),
        ('ulFlags',ULONG),
        ('cMaxObjects',ULONG),
        ('cMaxBytes',ULONG),
        ('ulExtendedOp',ULONG),
        ('liFsmoInfo',ULARGE_INTEGER),
        ('pPartialAttrSet',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('pPartialAttrSetEx1',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('PrefixTableDest',SCHEMA_PREFIX_TABLE),
    )

# 4.1.10.2.7 DRS_MSG_GETCHGREQ_V10
class DRS_MSG_GETCHGREQ_V10(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjDest',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('pUpToDateVecDest',PUPTODATE_VECTOR_V1_EXT),
        ('ulFlags',ULONG),
        ('cMaxObjects',ULONG),
        ('cMaxBytes',ULONG),
        ('ulExtendedOp',ULONG),
        ('liFsmoInfo',ULARGE_INTEGER),
        ('pPartialAttrSet',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('pPartialAttrSetEx1',PPARTIAL_ATTR_VECTOR_V1_EXT),
        ('PrefixTableDest',SCHEMA_PREFIX_TABLE),
        ('ulMoreFlags',ULONG),
    )

# 4.1.10.2.1 DRS_MSG_GETCHGREQ
class DRS_MSG_GETCHGREQ(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        4  : ('V4', DRS_MSG_GETCHGREQ_V4),
        5  : ('V5', DRS_MSG_GETCHGREQ_V5),
        7  : ('V7', DRS_MSG_GETCHGREQ_V7),
        8  : ('V8', DRS_MSG_GETCHGREQ_V8),
        10 : ('V10', DRS_MSG_GETCHGREQ_V10),
    }

# 5.16 ATTRVAL
class ATTRVAL(NDRSTRUCT):
    structure =  (
        ('valLen',ULONG),
        ('pVal',PBYTE_ARRAY),
    )

class ATTRVAL_ARRAY(NDRUniConformantArray):
    item = ATTRVAL

class PATTRVAL_ARRAY(NDRPOINTER):
    referent = (
        ('Data',ATTRVAL_ARRAY),
    )

# 5.17 ATTRVALBLOCK
class ATTRVALBLOCK(NDRSTRUCT):
    structure =  (
        ('valCount',ULONG),
        ('pAVal',PATTRVAL_ARRAY),
    )

# 5.9 ATTR
class ATTR(NDRSTRUCT):
    structure =  (
        ('attrTyp',ATTRTYP),
        ('AttrVal',ATTRVALBLOCK),
    )

class ATTR_ARRAY(NDRUniConformantArray):
    item = ATTR

class PATTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data',ATTR_ARRAY),
    )

# 5.10 ATTRBLOCK
class ATTRBLOCK(NDRSTRUCT):
    structure =  (
        ('attrCount',ULONG),
        ('pAttr',PATTR_ARRAY),
    )

# 5.53 ENTINF
class ENTINF(NDRSTRUCT):
    structure =  (
        ('pName',PDSNAME),
        ('ulFlags',ULONG),
        ('AttrBlock',ATTRBLOCK),
    )

class ENTINF_ARRAY(NDRUniConformantArray):
    item = ENTINF

class PENTINF_ARRAY(NDRPOINTER):
    referent = (
        ('Data',ENTINF_ARRAY),
    )

# 5.154 PROPERTY_META_DATA_EXT
class PROPERTY_META_DATA_EXT(NDRSTRUCT):
    structure =  (
        ('dwVersion',DWORD),
        ('timeChanged',DSTIME),
        ('uuidDsaOriginating',UUID),
        ('usnOriginating',USN),
    )

class PROPERTY_META_DATA_EXT_ARRAY(NDRUniConformantArray):
    item = PROPERTY_META_DATA_EXT

# 5.155 PROPERTY_META_DATA_EXT_VECTOR
class PROPERTY_META_DATA_EXT_VECTOR(NDRSTRUCT):
    structure =  (
        ('cNumProps',DWORD),
        ('rgMetaData',PROPERTY_META_DATA_EXT_ARRAY),
    )

class PPROPERTY_META_DATA_EXT_VECTOR(NDRPOINTER):
    referent = (
        ('Data',PROPERTY_META_DATA_EXT_VECTOR),
    )

# 5.161 REPLENTINFLIST

class REPLENTINFLIST(NDRSTRUCT):
    structure =  (
        ('pNextEntInf',NDRPOINTER),
        ('Entinf',ENTINF),
        ('fIsNCPrefix',BOOL),
        ('pParentGuidm',PUUID),
        ('pMetaDataExt',PPROPERTY_META_DATA_EXT_VECTOR),
    )
    # ToDo: Here we should work with getData and fromString beacuse we're cheating with pNextEntInf
    def fromString(self, data, soFar = 0 ):
        # Here we're changing the struct so we can represent a linked list with NDR
        self.fields['pNextEntInf'] = PREPLENTINFLIST(isNDR64 = self._isNDR64)
        retVal = NDRSTRUCT.fromString(self, data, soFar)
        return retVal

class PREPLENTINFLIST(NDRPOINTER):
    referent = (
        ('Data',REPLENTINFLIST),
    )

# 4.1.10.2.9 DRS_MSG_GETCHGREPLY_V1
class DRS_MSG_GETCHGREPLY_V1(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjSrc',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('usnvecTo',USN_VECTOR),
        ('pUpToDateVecSrcV1',PUPTODATE_VECTOR_V1_EXT),
        ('PrefixTableSrc',SCHEMA_PREFIX_TABLE),
        ('ulExtendedRet',EXOP_ERR),
        ('cNumObjects',ULONG),
        ('cNumBytes',ULONG),
        ('pObjects',PREPLENTINFLIST),
        ('fMoreData',BOOL),
    )

# 4.1.10.2.15 DRS_COMPRESSED_BLOB
class DRS_COMPRESSED_BLOB(NDRSTRUCT):
    structure =  (
        ('cbUncompressedSize',DWORD),
        ('cbCompressedSize',DWORD),
        ('pbCompressedData',BYTE_ARRAY),
    )

# 4.1.10.2.10 DRS_MSG_GETCHGREPLY_V2
class DRS_MSG_GETCHGREPLY_V2(NDRSTRUCT):
    structure =  (
        ('CompressedV1',DRS_COMPRESSED_BLOB),
    )

# 5.199 UPTODATE_CURSOR_V2
class UPTODATE_CURSOR_V2(NDRSTRUCT):
    structure =  (
        ('uuidDsa',UUID),
        ('usnHighPropUpdate',USN),
        ('timeLastSyncSuccess',DSTIME),
    )

class UPTODATE_CURSOR_V2_ARRAY(NDRUniConformantArray):
    item = UPTODATE_CURSOR_V2

# 5.201 UPTODATE_VECTOR_V2_EXT
class UPTODATE_VECTOR_V2_EXT(NDRSTRUCT):
    structure =  (
        ('dwVersion',DWORD),
        ('dwReserved1',DWORD),
        ('cNumCursors',DWORD),
        ('dwReserved2',DWORD),
        ('rgCursors',UPTODATE_CURSOR_V2_ARRAY),
    )

class PUPTODATE_VECTOR_V2_EXT(NDRPOINTER):
    referent = (
        ('Data',UPTODATE_VECTOR_V2_EXT),
    )

# 5.211 VALUE_META_DATA_EXT_V1
class VALUE_META_DATA_EXT_V1(NDRSTRUCT):
    structure =  (
        ('timeCreated',DSTIME),
        ('MetaData',PROPERTY_META_DATA_EXT),
    )

# 5.215 VALUE_META_DATA_EXT_V3
class VALUE_META_DATA_EXT_V3(NDRSTRUCT):
    structure =  (
        ('timeCreated',DSTIME),
        ('MetaData',PROPERTY_META_DATA_EXT),
        ('unused1',DWORD),
        ('unused1',DWORD),
        ('unused1',DWORD),
        ('timeExpired',DSTIME),
    )

# 5.167 REPLVALINF_V1
class REPLVALINF_V1(NDRSTRUCT):
    structure =  (
        ('pObject',PDSNAME),
        ('attrTyp',ATTRTYP),
        ('Aval',ATTRVAL),
        ('fIsPresent',BOOL),
        ('MetaData',VALUE_META_DATA_EXT_V1),
    )

    def fromString(self, data, soFar = 0):
        retVal = NDRSTRUCT.fromString(self, data, soFar)
        #self.dumpRaw()
        return retVal

class REPLVALINF_V1_ARRAY(NDRUniConformantArray):
    item = REPLVALINF_V1

class PREPLVALINF_V1_ARRAY(NDRPOINTER):
    referent = (
        ('Data', REPLVALINF_V1_ARRAY),
    )

# 5.168 REPLVALINF_V3
class REPLVALINF_V3(NDRSTRUCT):
    structure = (
        ('pObject', PDSNAME),
        ('attrTyp', ATTRTYP),
        ('Aval', ATTRVAL),
        ('fIsPresent', BOOL),
        ('MetaData', VALUE_META_DATA_EXT_V3),
    )

    def fromString(self, data, soFar=0):
        retVal = NDRSTRUCT.fromString(self, data, soFar)
        # self.dumpRaw()
        return retVal

class REPLVALINF_V3_ARRAY(NDRUniConformantArray):
    item = REPLVALINF_V3

class PREPLVALINF_V3_ARRAY(NDRPOINTER):
    referent = (
        ('Data', REPLVALINF_V3_ARRAY),
    )

# 5.169 REPLVALINF_NATIVE
REPLVALINF_NATIVE = REPLVALINF_V3

# 4.1.10.2.11 DRS_MSG_GETCHGREPLY_V6
class DRS_MSG_GETCHGREPLY_V6(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjSrc',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('usnvecTo',USN_VECTOR),
        ('pUpToDateVecSrc',PUPTODATE_VECTOR_V2_EXT),
        ('PrefixTableSrc',SCHEMA_PREFIX_TABLE),
        ('ulExtendedRet',EXOP_ERR),
        ('cNumObjects',ULONG),
        ('cNumBytes',ULONG),
        ('pObjects',PREPLENTINFLIST),
        ('fMoreData',BOOL),
        ('cNumNcSizeObjectsc',ULONG),
        ('cNumNcSizeValues',ULONG),
        ('cNumValues',DWORD),
        #('rgValues',PREPLVALINF_V1_ARRAY),
        # ToDo: Once we find out what's going on with PREPLVALINF_ARRAY get it back
        # Seems there's something in there that is not being parsed correctly
        ('rgValues',DWORD),
        ('dwDRSError',DWORD),
    )

# 4.1.10.2.14 DRS_COMP_ALG_TYPE
class DRS_COMP_ALG_TYPE(NDRENUM):
    class enumItems(Enum):
        DRS_COMP_ALG_NONE   = 0
        DRS_COMP_ALG_UNUSED = 1
        DRS_COMP_ALG_MSZIP  = 2
        DRS_COMP_ALG_WIN2K3 = 3

# 4.1.10.2.12 DRS_MSG_GETCHGREPLY_V7
class DRS_MSG_GETCHGREPLY_V7(NDRSTRUCT):
    structure =  (
        ('dwCompressedVersion',DWORD),
        ('CompressionAlg',DRS_COMP_ALG_TYPE),
        ('CompressedAny',DRS_COMPRESSED_BLOB),
    )

# 4.1.10.2.13 DRS_MSG_GETCHGREPLY_V9
class DRS_MSG_GETCHGREPLY_V9(NDRSTRUCT):
    structure =  (
        ('uuidDsaObjSrc',UUID),
        ('uuidInvocIdSrc',UUID),
        ('pNC',PDSNAME),
        ('usnvecFrom',USN_VECTOR),
        ('usnvecTo',USN_VECTOR),
        ('pUpToDateVecSrc',PUPTODATE_VECTOR_V2_EXT),
        ('PrefixTableSrc',SCHEMA_PREFIX_TABLE),
        ('ulExtendedRet',EXOP_ERR),
        ('cNumObjects',ULONG),
        ('cNumBytes',ULONG),
        ('pObjects',PREPLENTINFLIST),
        ('fMoreData',BOOL),
        ('cNumNcSizeObjectsc',ULONG),
        ('cNumNcSizeValues',ULONG),
        ('cNumValues',DWORD),
        #('rgValues',PREPLVALINF_V3_ARRAY),
        # ToDo: Once we find out what's going on with PREPLVALINF_ARRAY get it back
        # Seems there's something in there that is not being parsed correctly
        ('rgValues',DWORD),
        ('dwDRSError',DWORD),
    )

# 4.1.10.2.14 DRS_MSG_GETCHGREPLY_NATIVE
DRS_MSG_GETCHGREPLY_NATIVE = DRS_MSG_GETCHGREPLY_V9

# 4.1.10.2.8 DRS_MSG_GETCHGREPLY
class DRS_MSG_GETCHGREPLY(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_GETCHGREPLY_V1),
        2  : ('V2', DRS_MSG_GETCHGREPLY_V2),
        6  : ('V6', DRS_MSG_GETCHGREPLY_V6),
        7  : ('V7', DRS_MSG_GETCHGREPLY_V7),
        9  : ('V9', DRS_MSG_GETCHGREPLY_V9),
    }

# 4.1.27.1.2 DRS_MSG_VERIFYREQ_V1
class DRS_MSG_VERIFYREQ_V1(NDRSTRUCT):
    structure =  (
        ('dwFlags',DWORD),
        ('cNames',DWORD),
        ('rpNames',PPDSNAME_ARRAY),
        ('RequiredAttrs',ATTRBLOCK),
        ('PrefixTable',SCHEMA_PREFIX_TABLE),
    )

# 4.1.27.1.1 DRS_MSG_VERIFYREQ
class DRS_MSG_VERIFYREQ(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_VERIFYREQ_V1),
    }

# 4.1.27.1.4 DRS_MSG_VERIFYREPLY_V1
class DRS_MSG_VERIFYREPLY_V1(NDRSTRUCT):
    structure =  (
        ('error',DWORD),
        ('cNames',DWORD),
        ('rpEntInf',PENTINF_ARRAY),
        ('PrefixTable',SCHEMA_PREFIX_TABLE),
    )

# 4.1.27.1.3 DRS_MSG_VERIFYREPLY
class DRS_MSG_VERIFYREPLY(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_VERIFYREPLY_V1),
    }

# 4.1.11.1.2 DRS_MSG_NT4_CHGLOG_REQ_V1
class DRS_MSG_NT4_CHGLOG_REQ_V1(NDRSTRUCT):
    structure =  (
        ('dwFlags',DWORD),
        ('PreferredMaximumLength',DWORD),
        ('cbRestart',DWORD),
        ('pRestart',PBYTE_ARRAY),
    )

# 4.1.11.1.1 DRS_MSG_NT4_CHGLOG_REQ
class DRS_MSG_NT4_CHGLOG_REQ(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_NT4_CHGLOG_REQ_V1),
    }

# 4.1.11.1.5 NT4_REPLICATION_STATE
class NT4_REPLICATION_STATE(NDRSTRUCT):
    structure =  (
        ('SamSerialNumber',LARGE_INTEGER),
        ('SamCreationTime',LARGE_INTEGER),
        ('BuiltinSerialNumber',LARGE_INTEGER),
        ('BuiltinCreationTime',LARGE_INTEGER),
        ('LsaSerialNumber',LARGE_INTEGER),
        ('LsaCreationTime',LARGE_INTEGER),
    )

# 4.1.11.1.4 DRS_MSG_NT4_CHGLOG_REPLY_V1
class DRS_MSG_NT4_CHGLOG_REPLY_V1(NDRSTRUCT):
    structure =  (
        ('cbRestart',DWORD),
        ('cbLog',DWORD),
        ('ReplicationState',NT4_REPLICATION_STATE),
        ('ActualNtStatus',DWORD),
        ('pRestart',PBYTE_ARRAY),
        ('pLog',PBYTE_ARRAY),
    )

# 4.1.11.1.3 DRS_MSG_NT4_CHGLOG_REPLY
class DRS_MSG_NT4_CHGLOG_REPLY(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1  : ('V1', DRS_MSG_NT4_CHGLOG_REPLY_V1),
    }

################################################################################
# RPC CALLS
################################################################################
# 4.1.3 IDL_DRSBind (Opnum 0)
class DRSBind(NDRCALL):
    opnum = 0
    structure = (
        ('puuidClientDsa', PUUID),
        ('pextClient', PDRS_EXTENSIONS),
    )

class DRSBindResponse(NDRCALL):
    structure = (
        ('ppextServer', PDRS_EXTENSIONS),
        ('phDrs', DRS_HANDLE),
        ('ErrorCode',DWORD),
    )

# 4.1.10 IDL_DRSGetNCChanges (Opnum 3)
class DRSGetNCChanges(NDRCALL):
    opnum = 3
    structure = (
        ('hDrs', DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_GETCHGREQ),
    )

class DRSGetNCChangesResponse(NDRCALL):
    structure = (
        ('pdwOutVersion', DWORD),
        ('pmsgOut', DRS_MSG_GETCHGREPLY),
        ('ErrorCode',DWORD),
    )

# 4.1.27 IDL_DRSVerifyNames (Opnum 8)
class DRSVerifyNames(NDRCALL):
    opnum = 8
    structure = (
        ('hDrs', DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_VERIFYREQ),
    )

class DRSVerifyNamesResponse(NDRCALL):
    structure = (
        ('pdwOutVersion', DWORD),
        ('pmsgOut', DRS_MSG_VERIFYREPLY),
        ('ErrorCode',DWORD),
    )
# 4.1.11 IDL_DRSGetNT4ChangeLog (Opnum 11)
class DRSGetNT4ChangeLog(NDRCALL):
    opnum = 11
    structure = (
        ('hDrs', DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_NT4_CHGLOG_REQ),
    )

class DRSGetNT4ChangeLogResponse(NDRCALL):
    structure = (
        ('pdwOutVersion', DWORD),
        ('pmsgOut', DRS_MSG_NT4_CHGLOG_REPLY),
        ('ErrorCode',DWORD),
    )

# 4.1.4 IDL_DRSCrackNames (Opnum 12)
class DRSCrackNames(NDRCALL):
    opnum = 12
    structure = (
        ('hDrs', DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_CRACKREQ),
    )

class DRSCrackNamesResponse(NDRCALL):
    structure = (
        ('pdwOutVersion', DWORD),
        ('pmsgOut', DRS_MSG_CRACKREPLY),
        ('ErrorCode',DWORD),
    )

# 4.1.5 IDL_DRSDomainControllerInfo (Opnum 16)
class DRSDomainControllerInfo(NDRCALL):
    opnum = 16
    structure = (
        ('hDrs', DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_DCINFOREQ),
    )

class DRSDomainControllerInfoResponse(NDRCALL):
    structure = (
        ('pdwOutVersion', DWORD),
        ('pmsgOut', DRS_MSG_DCINFOREPLY),
        ('ErrorCode',DWORD),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (DRSBind,DRSBindResponse ),
 3 : (DRSGetNCChanges,DRSGetNCChangesResponse ),
 12: (DRSCrackNames,DRSCrackNamesResponse ),
 16: (DRSDomainControllerInfo,DRSDomainControllerInfoResponse ),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def hDRSDomainControllerInfo(dce, hDrs, domain, infoLevel):
    request = DRSDomainControllerInfo()
    request['hDrs'] = hDrs
    request['dwInVersion'] = 1

    request['pmsgIn']['tag'] = 1
    request['pmsgIn']['V1']['Domain'] = checkNullString(domain)
    request['pmsgIn']['V1']['InfoLevel'] = infoLevel
    return dce.request(request)

def hDRSCrackNames(dce, hDrs, flags, formatOffered, formatDesired, rpNames = ()):
    request = DRSCrackNames()
    request['hDrs'] = hDrs
    request['dwInVersion'] = 1

    request['pmsgIn']['tag'] = 1
    request['pmsgIn']['V1']['CodePage'] = 0
    request['pmsgIn']['V1']['LocaleId'] = 0
    request['pmsgIn']['V1']['dwFlags'] = flags
    request['pmsgIn']['V1']['formatOffered'] = formatOffered
    request['pmsgIn']['V1']['formatDesired'] = formatDesired
    request['pmsgIn']['V1']['cNames'] = len(rpNames)
    for name in rpNames:
        record = LPWSTR()
        record['Data'] = checkNullString(name)
        request['pmsgIn']['V1']['rpNames'].append(record)

    return dce.request(request)

def transformKey(InputKey):
        # Section 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
        OutputKey = []
        OutputKey.append( chr(ord(InputKey[0]) >> 0x01) )
        OutputKey.append( chr(((ord(InputKey[0])&0x01)<<6) | (ord(InputKey[1])>>2)) )
        OutputKey.append( chr(((ord(InputKey[1])&0x03)<<5) | (ord(InputKey[2])>>3)) )
        OutputKey.append( chr(((ord(InputKey[2])&0x07)<<4) | (ord(InputKey[3])>>4)) )
        OutputKey.append( chr(((ord(InputKey[3])&0x0F)<<3) | (ord(InputKey[4])>>5)) )
        OutputKey.append( chr(((ord(InputKey[4])&0x1F)<<2) | (ord(InputKey[5])>>6)) )
        OutputKey.append( chr(((ord(InputKey[5])&0x3F)<<1) | (ord(InputKey[6])>>7)) )
        OutputKey.append( chr(ord(InputKey[6]) & 0x7F) )

        for i in range(8):
            OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

        return "".join(OutputKey)

def deriveKey(baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = key[0] + key[1] + key[2] + key[3] + key[0] + key[1] + key[2]
        key2 = key[3] + key[0] + key[1] + key[2] + key[3] + key[0] + key[1]
        return transformKey(key1),transformKey(key2)

def removeDESLayer(cryptedHash, rid):
        Key1,Key2 = deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

def DecryptAttributeValue(dce, attribute):
    sessionKey = dce.get_session_key()
    # Is it a Kerberos Session Key?
    if isinstance(sessionKey, crypto.Key):
        # Extract its contents and move on
        sessionKey = sessionKey.contents

    encryptedPayload = ENCRYPTED_PAYLOAD(attribute)

    md5 = hashlib.new('md5')
    md5.update(sessionKey)
    md5.update(encryptedPayload['Salt'])
    finalMD5 = md5.digest()

    cipher = ARC4.new(finalMD5)
    plainText = cipher.decrypt(attribute[16:])

    #chkSum = (binascii.crc32(plainText[4:])) & 0xffffffff
    #if unpack('<L',plainText[:4])[0] != chkSum:
    #    print "RECEIVED 0x%x" % unpack('<L',plainText[:4])[0]
    #    print "CALCULATED 0x%x" % chkSum

    return plainText[4:]

# 5.16.4 ATTRTYP-to-OID Conversion
def MakeAttid(prefixTable, oid):
    # get the last value in the original OID: the value * after the last '.'
    lastValue = int(oid.split('.')[-1])

    # convert the dotted form of OID into a BER encoded binary * format.
    # The BER encoding of OID is described in section * 8.19 of [ITUX690]
    from pyasn1.type import univ
    from pyasn1.codec.ber import encoder
    binaryOID = encoder.encode(univ.ObjectIdentifier(oid))[2:]

    # get the prefix of the OID
    if lastValue < 128:
        oidPrefix = list(binaryOID[:-1])
    else:
        oidPrefix = list(binaryOID[:-2])

    # search the prefix in the prefix table, if none found, add
    # one entry for the new prefix.
    fToAdd = True
    pos = len(prefixTable)
    for j, item in enumerate(prefixTable):
        if item['prefix']['elements'] == oidPrefix:
            fToAdd = False
            pos = j
            break

    if fToAdd is True:
        entry = PrefixTableEntry()
        entry['ndx'] = pos
        entry['prefix']['length'] = len(oidPrefix)
        entry['prefix']['elements'] = oidPrefix
        prefixTable.append(entry)

    # compose the attid
    lowerWord = lastValue % 16384
    if lastValue >= 16384:
        # mark it so that it is known to not be the whole lastValue
        lowerWord += 32768

    upperWord = pos

    attrTyp = ATTRTYP()
    attrTyp['Data'] = (upperWord << 16) + lowerWord
    return attrTyp

def OidFromAttid(prefixTable, attr):
    # separate the ATTRTYP into two parts
    upperWord = attr / 65536
    lowerWord = attr % 65536

    # search in the prefix table to find the upperWord, if found,
    # construct the binary OID by appending lowerWord to the end of
    # found prefix.

    binaryOID = None
    for j, item in enumerate(prefixTable):
        if item['ndx'] == upperWord:
            binaryOID = item['prefix']['elements'][:item['prefix']['length']]
            if lowerWord < 128:
                binaryOID.append(chr(lowerWord))
            else:
                if lowerWord >= 32768:
                    lowerWord -= 32768
                binaryOID.append(chr(((lowerWord/128) % 128)+128))
                binaryOID.append(chr(lowerWord%128))
            break

    if binaryOID is None:
        return None

    return str(decoder.decode('\x06' + chr(len(binaryOID)) + ''.join(binaryOID), asn1Spec = univ.ObjectIdentifier())[0])

if __name__ == '__main__':
    prefixTable = []
    oid0 = '1.2.840.113556.1.4.94'
    oid1 = '2.5.6.2'
    oid2 = '1.2.840.113556.1.2.1'
    oid3 = '1.2.840.113556.1.3.223'
    oid4 = '1.2.840.113556.1.5.7000.53'

    o0 = MakeAttid(prefixTable, oid0)
    print hex(o0)
    o1 = MakeAttid(prefixTable, oid1)
    print hex(o1)
    o2 = MakeAttid(prefixTable, oid2)
    print hex(o2)
    o3 = MakeAttid(prefixTable, oid3)
    print hex(o3)
    o4 = MakeAttid(prefixTable, oid4)
    print hex(o4)
    jj = OidFromAttid(prefixTable, o0)
    print jj
    jj = OidFromAttid(prefixTable, o1)
    print jj
    jj = OidFromAttid(prefixTable, o2)
    print jj
    jj = OidFromAttid(prefixTable, o3)
    print jj
    jj = OidFromAttid(prefixTable, o4)
    print jj
