# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-WKST] Interface implementation
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
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRUniConformantArray, NDRUniFixedArray, \
    NDRPOINTER
from impacket.dcerpc.v5.dtypes import NULL, WSTR, ULONG, LPWSTR, LONG, LARGE_INTEGER, WIDESTR, RPC_UNICODE_STRING, \
    LPULONG, LPLONG
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_WKST   = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'WKST SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'WKST SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

# 2.2.1.1 JOIN_MAX_PASSWORD_LENGTH
JOIN_MAX_PASSWORD_LENGTH = 256

# 2.2.1.2 JOIN_OBFUSCATOR_LENGTH
JOIN_OBFUSCATOR_LENGTH = 8

# 2.2.1.3 MAX_PREFERRED_LENGTH
MAX_PREFERRED_LENGTH = 0xffffffff

# 2.2.5.22 USE_INFO_1
USE_OK       = 0x00000000
USE_PAUSED   = 0x00000001
USE_SESSLOST = 0x00000002
USE_NETERR   = 0x00000003
USE_CONN     = 0x00000004
USE_RECONN   = 0x00000005

USE_WILDCARD = 0xFFFFFFFF
USE_DISKDEV  = 0x00000000
USE_SPOOLDEV = 0x00000001
USE_CHARDEV  = 0x00000002
USE_IPC      = 0x00000003

# 3.2.4.9 NetrUseDel (Opnum 10)
# Force Level
USE_NOFORCE       = 0x00000000
USE_FORCE         = 0x00000001
USE_LOTS_OF_FORCE = 0x00000002

# 3.2.4.13 NetrJoinDomain2 (Opnum 22)
# Options
NETSETUP_JOIN_DOMAIN           = 0x00000001
NETSETUP_ACCT_CREATE           = 0x00000002
NETSETUP_ACCT_DELETE           = 0x00000004
NETSETUP_DOMAIN_JOIN_IF_JOINED = 0x00000020
NETSETUP_JOIN_UNSECURE         = 0x00000040
NETSETUP_MACHINE_PWD_PASSED    = 0x00000080
NETSETUP_DEFER_SPN_SET         = 0x00000100
NETSETUP_JOIN_DC_ACCOUNT       = 0x00000200
NETSETUP_JOIN_WITH_NEW_NAME    = 0x00000400
NETSETUP_INSTALL_INVOCATION    = 0x00040000

# 3.2.4.14 NetrUnjoinDomain2 (Opnum 23)
# Options
NETSETUP_ACCT_DELETE              = 0x00000004
NETSETUP_IGNORE_UNSUPPORTED_FLAGS = 0x10000000

# 3.2.4.15 NetrRenameMachineInDomain2 (Opnum 24)
# Options
NETSETUP_ACCT_CREATE           = 0x00000002
NETSETUP_DNS_NAME_CHANGES_ONLY = 0x00001000

################################################################################
# STRUCTURES
################################################################################

# 2.2.2.1 WKSSVC_IDENTIFY_HANDLE
class WKSSVC_IDENTIFY_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data', WSTR),
    )

class LPWKSSVC_IDENTIFY_HANDLE(NDRPOINTER):
    referent = (
        ('Data', WKSSVC_IDENTIFY_HANDLE),
    )

# 2.2.2.2 WKSSVC_IMPERSONATE_HANDLE
class WKSSVC_IMPERSONATE_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data',WSTR),
    )

class LPWKSSVC_IMPERSONATE_HANDLE(NDRPOINTER):
    referent = (
        ('Data', WKSSVC_IMPERSONATE_HANDLE),
    )

# 2.2.3.1 NETSETUP_JOIN_STATUS
class NETSETUP_JOIN_STATUS(NDRENUM):
    class enumItems(Enum):
        NetSetupUnknownStatus = 1
        NetSetupUnjoined      = 2
        NetSetupWorkgroupName = 3
        NetSetupDomainName    = 4

# 2.2.3.2 NETSETUP_NAME_TYPE
class NETSETUP_NAME_TYPE(NDRENUM):
    class enumItems(Enum):
        NetSetupUnknown           = 0
        NetSetupMachine           = 1
        NetSetupWorkgroup         = 2
        NetSetupDomain            = 3
        NetSetupNonExistentDomain = 4
        NetSetupDnsMachine        = 5

# 2.2.3.3 NET_COMPUTER_NAME_TYPE
class NET_COMPUTER_NAME_TYPE(NDRENUM):
    class enumItems(Enum):
        NetPrimaryComputerName    = 0
        NetAlternateComputerNames = 1
        NetAllComputerNames       = 2
        NetComputerNameTypeMax    = 3

# 2.2.5.1 WKSTA_INFO_100
class WKSTA_INFO_100(NDRSTRUCT):
    structure = (
        ('wki100_platform_id', ULONG),
        ('wki100_computername', LPWSTR),
        ('wki100_langroup', LPWSTR),
        ('wki100_ver_major', ULONG),
        ('wki100_ver_minor', ULONG),
    )

class LPWKSTA_INFO_100(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_100),
    )

# 2.2.5.2 WKSTA_INFO_101
class WKSTA_INFO_101(NDRSTRUCT):
    structure = (
        ('wki101_platform_id', ULONG),
        ('wki101_computername', LPWSTR),
        ('wki101_langroup', LPWSTR),
        ('wki101_ver_major', ULONG),
        ('wki101_ver_minor', ULONG),
        ('wki101_lanroot', LPWSTR),
    )

class LPWKSTA_INFO_101(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_101),
    )

# 2.2.5.3 WKSTA_INFO_102
class WKSTA_INFO_102(NDRSTRUCT):
    structure = (
        ('wki102_platform_id', ULONG),
        ('wki102_computername', LPWSTR),
        ('wki102_langroup', LPWSTR),
        ('wki102_ver_major', ULONG),
        ('wki102_ver_minor', ULONG),
        ('wki102_lanroot', LPWSTR),
        ('wki102_logged_on_users', ULONG),
    )

class LPWKSTA_INFO_102(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_102),
    )

# 2.2.5.4 WKSTA_INFO_502
class WKSTA_INFO_502(NDRSTRUCT):
    structure = (
        ('wki502_char_wait', ULONG),
        ('wki502_collection_time', ULONG),
        ('wki502_maximum_collection_count', ULONG),
        ('wki502_keep_conn', ULONG),
        ('wki502_max_cmds', ULONG),
        ('wki502_sess_timeout', ULONG),
        ('wki502_siz_char_buf', ULONG),
        ('wki502_max_threads', ULONG),
        ('wki502_lock_quota', ULONG),
        ('wki502_lock_increment', ULONG),
        ('wki502_lock_maximum', ULONG),
        ('wki502_pipe_increment', ULONG),
        ('wki502_pipe_maximum', ULONG),
        ('wki502_cache_file_timeout', ULONG),
        ('wki502_dormant_file_limit', ULONG),
        ('wki502_read_ahead_throughput', ULONG),
        ('wki502_num_mailslot_buffers', ULONG),
        ('wki502_num_srv_announce_buffers', ULONG),
        ('wki502_max_illegal_datagram_events', ULONG),
        ('wki502_illegal_datagram_event_reset_frequency', ULONG),
        ('wki502_log_election_packets', LONG),
        ('wki502_use_opportunistic_locking', LONG),
        ('wki502_use_unlock_behind', LONG),
        ('wki502_use_close_behind', LONG),
        ('wki502_buf_named_pipes', LONG),
        ('wki502_use_lock_read_unlock', LONG),
        ('wki502_utilize_nt_caching', LONG),
        ('wki502_use_raw_read', LONG),
        ('wki502_use_raw_write', LONG),
        ('wki502_use_write_raw_data', LONG),
        ('wki502_use_encryption', LONG),
        ('wki502_buf_files_deny_write', LONG),
        ('wki502_buf_read_only_files', LONG),
        ('wki502_force_core_create_mode', LONG),
        ('wki502_use_512_byte_max_transfer', LONG),
    )

class LPWKSTA_INFO_502(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_502),
    )

# 2.2.5.5 WKSTA_INFO_1013
class WKSTA_INFO_1013(NDRSTRUCT):
    structure = (
        ('wki1013_keep_conn', ULONG),
    )

class LPWKSTA_INFO_1013(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_1013),
    )

# 2.2.5.6 WKSTA_INFO_1018
class WKSTA_INFO_1018(NDRSTRUCT):
    structure = (
        ('wki1018_sess_timeout', ULONG),
    )

class LPWKSTA_INFO_1018(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_1018),
    )

# 2.2.5.7 WKSTA_INFO_1046
class WKSTA_INFO_1046(NDRSTRUCT):
    structure = (
        ('wki1046_dormant_file_limit', ULONG),
    )

class LPWKSTA_INFO_1046(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO_1046),
    )

# 2.2.4.1 WKSTA_INFO
class WKSTA_INFO(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        100: ('WkstaInfo100', LPWKSTA_INFO_100),
        101: ('WkstaInfo101', LPWKSTA_INFO_101),
        102: ('WkstaInfo102', LPWKSTA_INFO_102),
        502: ('WkstaInfo502', LPWKSTA_INFO_502),
        1013: ('WkstaInfo1013', LPWKSTA_INFO_1013),
        1018: ('WkstaInfo1018', LPWKSTA_INFO_1018),
        1046: ('WkstaInfo1046', LPWKSTA_INFO_1046),
    }

class LPWKSTA_INFO(NDRPOINTER):
    referent = (
        ('Data', WKSTA_INFO),
    )

# 2.2.5.8 WKSTA_TRANSPORT_INFO_0
class WKSTA_TRANSPORT_INFO_0(NDRSTRUCT):
    structure = (
        ('wkti0_quality_of_service', ULONG),
        ('wkti0_number_of_vcs', ULONG),
        ('wkti0_transport_name', LPWSTR),
        ('wkti0_transport_address', LPWSTR),
        ('wkti0_wan_ish', ULONG),
    )

# 2.2.5.9 WKSTA_USER_INFO_0
class WKSTA_USER_INFO_0(NDRSTRUCT):
    structure = (
        ('wkui0_username', LPWSTR),
    )

# 2.2.5.10 WKSTA_USER_INFO_1
class WKSTA_USER_INFO_1(NDRSTRUCT):
    structure = (
        ('wkui1_username', LPWSTR),
        ('wkui1_logon_domain', LPWSTR),
        ('wkui1_oth_domains', LPWSTR),
        ('wkui1_logon_server', LPWSTR),
    )

# 2.2.5.11 STAT_WORKSTATION_0
class STAT_WORKSTATION_0(NDRSTRUCT):
    structure = (
        ('StatisticsStartTime', LARGE_INTEGER),
        ('BytesReceived', LARGE_INTEGER),
        ('SmbsReceived', LARGE_INTEGER),
        ('PagingReadBytesRequested', LARGE_INTEGER),
        ('NonPagingReadBytesRequested', LARGE_INTEGER),
        ('CacheReadBytesRequested', LARGE_INTEGER),
        ('NetworkReadBytesRequested', LARGE_INTEGER),
        ('BytesTransmitted', LARGE_INTEGER),
        ('SmbsTransmitted', LARGE_INTEGER),
        ('PagingWriteBytesRequested', LARGE_INTEGER),
        ('NonPagingWriteBytesRequested', LARGE_INTEGER),
        ('CacheWriteBytesRequested', LARGE_INTEGER),
        ('NetworkWriteBytesRequested', LARGE_INTEGER),
        ('InitiallyFailedOperations', ULONG),
        ('FailedCompletionOperations', ULONG),
        ('ReadOperations', ULONG),
        ('RandomReadOperations', ULONG),
        ('ReadSmbs', ULONG),
        ('LargeReadSmbs', ULONG),
        ('SmallReadSmbs', ULONG),
        ('WriteOperations', ULONG),
        ('RandomWriteOperations', ULONG),
        ('WriteSmbs', ULONG),
        ('LargeWriteSmbs', ULONG),
        ('SmallWriteSmbs', ULONG),
        ('RawReadsDenied', ULONG),
        ('RawWritesDenied', ULONG),
        ('NetworkErrors', ULONG),
        ('Sessions', ULONG),
        ('FailedSessions', ULONG),
        ('Reconnects', ULONG),
        ('CoreConnects', ULONG),
        ('Lanman20Connects', ULONG),
        ('Lanman21Connects', ULONG),
        ('LanmanNtConnects', ULONG),
        ('ServerDisconnects', ULONG),
        ('HungSessions', ULONG),
        ('UseCount', ULONG),
        ('FailedUseCount', ULONG),
        ('CurrentCommands', ULONG),
    )

class LPSTAT_WORKSTATION_0(NDRPOINTER):
    referent = (
        ('Data', STAT_WORKSTATION_0),
    )

# 2.2.5.12 WKSTA_USER_INFO_0_CONTAINER
class WKSTA_USER_INFO_0_ARRAY(NDRUniConformantArray):
    item = WKSTA_USER_INFO_0

class LPWKSTA_USER_INFO_0_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WKSTA_USER_INFO_0_ARRAY),
    )

class WKSTA_USER_INFO_0_CONTAINER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', LPWKSTA_USER_INFO_0_ARRAY),
    )

class LPWKSTA_USER_INFO_0_CONTAINER(NDRPOINTER):
    referent = (
        ('Data', WKSTA_USER_INFO_0_CONTAINER),
    )

# 2.2.5.13 WKSTA_USER_INFO_1_CONTAINER
class WKSTA_USER_INFO_1_ARRAY(NDRUniConformantArray):
    item = WKSTA_USER_INFO_1

class LPWKSTA_USER_INFO_1_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WKSTA_USER_INFO_1_ARRAY),
    )

class WKSTA_USER_INFO_1_CONTAINER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', LPWKSTA_USER_INFO_1_ARRAY),
    )

class LPWKSTA_USER_INFO_1_CONTAINER(NDRPOINTER):
    referent = (
        ('Data', WKSTA_USER_INFO_1_CONTAINER),
    )

# 2.2.5.14 WKSTA_USER_ENUM_STRUCT
class WKSTA_USER_ENUM_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        0: ('Level0', LPWKSTA_USER_INFO_0_CONTAINER),
        1: ('Level1', LPWKSTA_USER_INFO_1_CONTAINER),
    }

class WKSTA_USER_ENUM_STRUCT(NDRSTRUCT):
    structure = (
        ('Level', ULONG),
        ('WkstaUserInfo', WKSTA_USER_ENUM_UNION),
    )


# 2.2.5.15 WKSTA_TRANSPORT_INFO_0_CONTAINER
class WKSTA_TRANSPORT_INFO_0_ARRAY(NDRUniConformantArray):
    item = WKSTA_TRANSPORT_INFO_0

class LPWKSTA_TRANSPORT_INFO_0_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WKSTA_TRANSPORT_INFO_0_ARRAY),
    )

class WKSTA_TRANSPORT_INFO_0_CONTAINER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', LPWKSTA_TRANSPORT_INFO_0_ARRAY),
    )

class LPWKSTA_TRANSPORT_INFO_0_CONTAINER(NDRPOINTER):
    referent = (
        ('Data', WKSTA_TRANSPORT_INFO_0_CONTAINER),
    )

# 2.2.5.16 WKSTA_TRANSPORT_ENUM_STRUCT
class WKSTA_TRANSPORT_ENUM_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        0: ('Level0', LPWKSTA_TRANSPORT_INFO_0_CONTAINER),
    }

class WKSTA_TRANSPORT_ENUM_STRUCT(NDRSTRUCT):
    structure = (
        ('Level', ULONG),
        ('WkstaTransportInfo', WKSTA_TRANSPORT_ENUM_UNION),
    )

# 2.2.5.17 JOINPR_USER_PASSWORD
class WCHAR_ARRAY(WIDESTR):
    def getDataLen(self, data):
        return JOIN_MAX_PASSWORD_LENGTH

class CHAR_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return JOIN_OBFUSCATOR_LENGTH

class JOINPR_USER_PASSWORD(NDRSTRUCT):
    structure = (
        ('Obfuscator', CHAR_ARRAY),
        ('Buffer', WCHAR_ARRAY),
    )

# 2.2.5.18 JOINPR_ENCRYPTED_USER_PASSWORD
class JOINPR_ENCRYPTED_USER_PASSWORD(NDRSTRUCT):
    structure = (
        ('Buffer', '524s=""'),
    )
    def getAlignment(self):
        return 1

class PJOINPR_ENCRYPTED_USER_PASSWORD(NDRPOINTER):
    referent = (
        ('Data', JOINPR_ENCRYPTED_USER_PASSWORD),
    )

# 2.2.5.19 UNICODE_STRING
UNICODE_STRING = WSTR
class PUNICODE_STRING(NDRPOINTER):
    referent = (
        ('Data', UNICODE_STRING),
    )

# 2.2.5.20 NET_COMPUTER_NAME_ARRAY
class UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

class PUNICODE_STRING_ARRAY(NDRPOINTER):
    referent = (
        ('Data', UNICODE_STRING_ARRAY),
    )

class NET_COMPUTER_NAME_ARRAY(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('ComputerNames', PUNICODE_STRING_ARRAY),
    )

class PNET_COMPUTER_NAME_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NET_COMPUTER_NAME_ARRAY), 
    )

# 2.2.5.21 USE_INFO_0
class USE_INFO_0(NDRSTRUCT):
    structure = (
        ('ui0_local', LPWSTR),
        ('ui0_remote', LPWSTR),
    )

class LPUSE_INFO_0(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_0),
    )

# 2.2.5.22 USE_INFO_1
class USE_INFO_1(NDRSTRUCT):
    structure = (
        ('ui1_local', LPWSTR),
        ('ui1_remote', LPWSTR),
        ('ui1_password', LPWSTR),
        ('ui1_status', ULONG),
        ('ui1_asg_type', ULONG),
        ('ui1_refcount', ULONG),
        ('ui1_usecount', ULONG),
    )

class LPUSE_INFO_1(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_1),
    )

# 2.2.5.23 USE_INFO_2
class USE_INFO_2(NDRSTRUCT):
    structure = (
        ('ui2_useinfo', USE_INFO_1),
        ('ui2_username', LPWSTR),
        ('ui2_domainname', LPWSTR),
    )

class LPUSE_INFO_2(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_2),
    )

# 2.2.5.24 USE_INFO_3
class USE_INFO_3(NDRSTRUCT):
    structure = (
        ('ui3_ui2', USE_INFO_2),
        ('ui3_flags', ULONG),
    )

class LPUSE_INFO_3(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_3),
    )

# 2.2.4.2 USE_INFO
class USE_INFO(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        0: ('UseInfo0', LPUSE_INFO_0),
        1: ('UseInfo1', LPUSE_INFO_1),
        2: ('UseInfo2', LPUSE_INFO_2),
        3: ('UseInfo3', LPUSE_INFO_3),
    }

# 2.2.5.25 USE_INFO_0_CONTAINER
class USE_INFO_0_CONTAINER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', LPUSE_INFO_0),
    )

class LPUSE_INFO_0_CONTAINER(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_0_CONTAINER),
    )

# 2.2.5.26 USE_INFO_1_CONTAINER
class USE_INFO_1_CONTAINER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', LPUSE_INFO_1),
    )

class LPUSE_INFO_1_CONTAINER(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_1_CONTAINER),
    )

# 2.2.5.27 USE_INFO_2_CONTAINER
class USE_INFO_2_CONTAINER(NDRSTRUCT):
    structure = (
        ('EntriesRead', ULONG),
        ('Buffer', LPUSE_INFO_2),
    )

class LPUSE_INFO_2_CONTAINER(NDRPOINTER):
    referent = (
        ('Data', USE_INFO_2_CONTAINER),
    )

# 2.2.5.28 USE_ENUM_STRUCT
class USE_ENUM_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )

    union = {
        0: ('Level0', LPUSE_INFO_0_CONTAINER),
        1: ('Level1', LPUSE_INFO_1_CONTAINER),
        2: ('Level2', LPUSE_INFO_2_CONTAINER),
    }

class USE_ENUM_STRUCT(NDRSTRUCT):
    structure = (
        ('Level', ULONG),
        ('UseInfo', USE_ENUM_UNION),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.2.4.1 NetrWkstaGetInfo (Opnum 0)
class NetrWkstaGetInfo(NDRCALL):
    opnum = 0
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', ULONG),
    )

class NetrWkstaGetInfoResponse(NDRCALL):
    structure = (
       ('WkstaInfo',WKSTA_INFO),
       ('ErrorCode',ULONG),
    )

# 3.2.4.2 NetrWkstaSetInfo (Opnum 1)
class NetrWkstaSetInfo(NDRCALL):
    opnum = 1
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', ULONG),
       ('WkstaInfo',WKSTA_INFO),
       ('ErrorParameter',LPULONG),
    )

class NetrWkstaSetInfoResponse(NDRCALL):
    structure = (
       ('ErrorParameter',LPULONG),
       ('ErrorCode',ULONG),
    )

# 3.2.4.3 NetrWkstaUserEnum (Opnum 2)
class NetrWkstaUserEnum(NDRCALL):
    opnum = 2
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('UserInfo', WKSTA_USER_ENUM_STRUCT),
       ('PreferredMaximumLength', ULONG),
       ('ResumeHandle', LPULONG),
    )

class NetrWkstaUserEnumResponse(NDRCALL):
    structure = (
       ('UserInfo',WKSTA_USER_ENUM_STRUCT),
       ('TotalEntries',ULONG),
       ('ResumeHandle',ULONG),
       ('ErrorCode',ULONG),
    )

# 3.2.4.4 NetrWkstaTransportEnum (Opnum 5)
class NetrWkstaTransportEnum(NDRCALL):
    opnum = 5
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('TransportInfo', WKSTA_TRANSPORT_ENUM_STRUCT),
       ('PreferredMaximumLength', ULONG),
       ('ResumeHandle', LPULONG),
    )

class NetrWkstaTransportEnumResponse(NDRCALL):
    structure = (
       ('TransportInfo',WKSTA_TRANSPORT_ENUM_STRUCT),
       ('TotalEntries',ULONG),
       ('ResumeHandle',ULONG),
       ('ErrorCode',ULONG),
    )

# 3.2.4.5 NetrWkstaTransportAdd (Opnum 6)
class NetrWkstaTransportAdd(NDRCALL):
    opnum = 6
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', ULONG),
       ('TransportInfo',WKSTA_TRANSPORT_INFO_0),
       ('ErrorParameter',LPULONG),
    )

class NetrWkstaTransportAddResponse(NDRCALL):
    structure = (
       ('ErrorParameter',LPULONG),
       ('ErrorCode',ULONG),
    )

# 3.2.4.7 NetrUseAdd (Opnum 8)
class NetrUseAdd(NDRCALL):
    opnum = 8
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('Level', ULONG),
       ('InfoStruct',USE_INFO),
       ('ErrorParameter',LPULONG),
    )

class NetrUseAddResponse(NDRCALL):
    structure = (
       ('ErrorParameter',LPULONG),
       ('ErrorCode',ULONG),
    )

# 3.2.4.8 NetrUseGetInfo (Opnum 9)
class NetrUseGetInfo(NDRCALL):
    opnum = 9
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('UseName', WSTR),
       ('Level',ULONG),
    )

class NetrUseGetInfoResponse(NDRCALL):
    structure = (
       ('InfoStruct',USE_INFO),
       ('ErrorCode',ULONG),
    )

# 3.2.4.9 NetrUseDel (Opnum 10)
class NetrUseDel(NDRCALL):
    opnum = 10
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('UseName', WSTR),
       ('ForceLevel',ULONG),
    )

class NetrUseDelResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.10 NetrUseEnum (Opnum 11)
class NetrUseEnum(NDRCALL):
    opnum = 11
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('InfoStruct', USE_ENUM_STRUCT),
       ('PreferredMaximumLength',ULONG),
       ('ResumeHandle',LPULONG),
    )

class NetrUseEnumResponse(NDRCALL):
    structure = (
       ('InfoStruct',USE_ENUM_STRUCT),
       ('TotalEntries',ULONG),
       ('ResumeHandle',LPULONG),
       ('ErrorCode',ULONG),
    )

# 3.2.4.11 NetrWorkstationStatisticsGet (Opnum 13)
class NetrWorkstationStatisticsGet(NDRCALL):
    opnum = 13
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('ServiceName', LPWSTR),
       ('Level',ULONG),
       ('Options',ULONG),
    )

class NetrWorkstationStatisticsGetResponse(NDRCALL):
    structure = (
       ('Buffer',LPSTAT_WORKSTATION_0),
       ('ErrorCode',ULONG),
    )

# 3.2.4.12 NetrGetJoinInformation (Opnum 20)
class NetrGetJoinInformation(NDRCALL):
    opnum = 20
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('NameBuffer', LPWSTR),
    )

class NetrGetJoinInformationResponse(NDRCALL):
    structure = (
       ('NameBuffer',LPWSTR),
       ('BufferType',NETSETUP_JOIN_STATUS),
       ('ErrorCode',ULONG),
    )

# 3.2.4.13 NetrJoinDomain2 (Opnum 22)
class NetrJoinDomain2(NDRCALL):
    opnum = 22
    structure = (
       ('ServerName', LPWSTR),
       ('DomainNameParam', WSTR),
       ('MachineAccountOU', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', ULONG),
    )

class NetrJoinDomain2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.14 NetrUnjoinDomain2 (Opnum 23)
class NetrUnjoinDomain2(NDRCALL):
    opnum = 23
    structure = (
       ('ServerName', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', ULONG),
    )

class NetrUnjoinDomain2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.15 NetrRenameMachineInDomain2 (Opnum 24)
class NetrRenameMachineInDomain2(NDRCALL):
    opnum = 24
    structure = (
       ('ServerName', LPWSTR),
       ('MachineName', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', ULONG),
    )

class NetrRenameMachineInDomain2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.16 NetrValidateName2 (Opnum 25)
class NetrValidateName2(NDRCALL):
    opnum = 25
    structure = (
       ('ServerName', LPWSTR),
       ('NameToValidate', WSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('NameType', NETSETUP_NAME_TYPE),
    )

class NetrValidateName2Response(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.17 NetrGetJoinableOUs2 (Opnum 26)
class NetrGetJoinableOUs2(NDRCALL):
    opnum = 26
    structure = (
       ('ServerName', LPWSTR),
       ('DomainNameParam', WSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('OUCount', ULONG),
    )

class NetrGetJoinableOUs2Response(NDRCALL):
    structure = (
       ('OUCount', LPLONG),
       ('OUs',PUNICODE_STRING_ARRAY),
       ('ErrorCode',ULONG),
    )

# 3.2.4.18 NetrAddAlternateComputerName (Opnum 27)
class NetrAddAlternateComputerName(NDRCALL):
    opnum = 27
    structure = (
       ('ServerName', LPWSTR),
       ('AlternateName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', ULONG),
    )

class NetrAddAlternateComputerNameResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.19 NetrRemoveAlternateComputerName (Opnum 28)
class NetrRemoveAlternateComputerName(NDRCALL):
    opnum = 28
    structure = (
       ('ServerName', LPWSTR),
       ('AlternateName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', ULONG),
    )

class NetrRemoveAlternateComputerNameResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.20 NetrSetPrimaryComputerName (Opnum 29)
class NetrSetPrimaryComputerName(NDRCALL):
    opnum = 29
    structure = (
       ('ServerName', LPWSTR),
       ('PrimaryName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', ULONG),
    )

class NetrSetPrimaryComputerNameResponse(NDRCALL):
    structure = (
       ('ErrorCode',ULONG),
    )

# 3.2.4.21 NetrEnumerateComputerNames (Opnum 30)
class NetrEnumerateComputerNames(NDRCALL):
    opnum = 30
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('NameType', NET_COMPUTER_NAME_TYPE),
       ('Reserved', ULONG),
    )

class NetrEnumerateComputerNamesResponse(NDRCALL):
    structure = (
       ('ComputerNames',PNET_COMPUTER_NAME_ARRAY),
       ('ErrorCode',ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (NetrWkstaGetInfo, NetrWkstaGetInfoResponse),
 1 : (NetrWkstaSetInfo, NetrWkstaSetInfoResponse),
 2 : (NetrWkstaUserEnum, NetrWkstaUserEnumResponse),
 5 : (NetrWkstaTransportEnum, NetrWkstaTransportEnumResponse),
 6 : (NetrWkstaTransportAdd, NetrWkstaTransportAddResponse),
# 7 : (NetrWkstaTransportDel, NetrWkstaTransportDelResponse),
 8 : (NetrUseAdd, NetrUseAddResponse),
 9 : (NetrUseGetInfo, NetrUseGetInfoResponse),
10 : (NetrUseDel, NetrUseDelResponse),
11 : (NetrUseEnum, NetrUseEnumResponse),
13 : (NetrWorkstationStatisticsGet, NetrWorkstationStatisticsGetResponse),
20 : (NetrGetJoinInformation, NetrGetJoinInformationResponse),
22 : (NetrJoinDomain2, NetrJoinDomain2Response),
23 : (NetrUnjoinDomain2, NetrUnjoinDomain2Response),
24 : (NetrRenameMachineInDomain2, NetrRenameMachineInDomain2Response),
25 : (NetrValidateName2, NetrValidateName2Response),
26 : (NetrGetJoinableOUs2, NetrGetJoinableOUs2Response),
27 : (NetrAddAlternateComputerName, NetrAddAlternateComputerNameResponse),
28 : (NetrRemoveAlternateComputerName, NetrRemoveAlternateComputerNameResponse),
29 : (NetrSetPrimaryComputerName, NetrSetPrimaryComputerNameResponse),
30 : (NetrEnumerateComputerNames, NetrEnumerateComputerNamesResponse),
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

def hNetrWkstaGetInfo(dce, level):
    request = NetrWkstaGetInfo()
    request['ServerName'] = '\x00'*10
    request['Level'] = level
    return dce.request(request)

def hNetrWkstaUserEnum(dce, level, preferredMaximumLength=0xffffffff):
    request = NetrWkstaUserEnum()
    request['ServerName'] = '\x00'*10
    request['UserInfo']['Level'] = level
    request['UserInfo']['WkstaUserInfo']['tag'] = level
    request['PreferredMaximumLength'] = preferredMaximumLength
    return dce.request(request)

def hNetrWkstaTransportEnum(dce, level, resumeHandle = 0, preferredMaximumLength = 0xffffffff):
    request = NetrWkstaTransportEnum()
    request['ServerName'] = '\x00'*10
    request['TransportInfo']['Level'] = level
    request['TransportInfo']['WkstaTransportInfo']['tag'] = level
    request['ResumeHandle'] = resumeHandle
    request['PreferredMaximumLength'] = preferredMaximumLength
    return dce.request(request)

def hNetrWkstaSetInfo(dce, level, wkstInfo):
    request = NetrWkstaSetInfo()
    request['ServerName'] = '\x00'*10
    request['Level'] = level
    request['WkstaInfo']['tag'] = level
    request['WkstaInfo']['WkstaInfo%d'% level] = wkstInfo
    return dce.request(request)

def hNetrWorkstationStatisticsGet(dce, serviceName, level, options):
    request = NetrWorkstationStatisticsGet()
    request['ServerName'] = '\x00'*10
    request['ServiceName'] = serviceName
    request['Level'] = level
    request['Options'] = options
    return dce.request(request)

def hNetrGetJoinInformation(dce, nameBuffer):
    request = NetrGetJoinInformation()
    request['ServerName'] = '\x00'*10
    request['NameBuffer'] = nameBuffer
    return dce.request(request)

def hNetrJoinDomain2(dce, domainNameParam, machineAccountOU, accountName, password, options):
    request = NetrJoinDomain2()
    request['ServerName'] = '\x00'*10
    request['DomainNameParam'] = checkNullString(domainNameParam)
    request['MachineAccountOU'] = checkNullString(machineAccountOU)
    request['AccountName'] = checkNullString(accountName)
    if password == NULL:
        request['Password'] = NULL
    else:
        request['Password']['Buffer'] = password
    request['Options'] = options
    return dce.request(request)

def hNetrUnjoinDomain2(dce, accountName, password, options):
    request = NetrUnjoinDomain2()
    request['ServerName'] = '\x00'*10
    request['AccountName'] = checkNullString(accountName)
    if password == NULL:
        request['Password'] = NULL
    else:
        request['Password']['Buffer'] = password
    request['Options'] = options
    return dce.request(request)

def hNetrRenameMachineInDomain2(dce, machineName, accountName, password, options):
    request = NetrRenameMachineInDomain2()
    request['ServerName'] = '\x00'*10
    request['MachineName'] = checkNullString(machineName)
    request['AccountName'] = checkNullString(accountName)
    if password == NULL:
        request['Password'] = NULL
    else:
        request['Password']['Buffer'] = password
    request['Options'] = options
    return dce.request(request)

def hNetrValidateName2(dce, nameToValidate, accountName, password, nameType):
    request = NetrValidateName2()
    request['ServerName'] = '\x00'*10
    request['NameToValidate'] = checkNullString(nameToValidate)
    request['AccountName'] = checkNullString(accountName)
    if password == NULL:
        request['Password'] = NULL
    else:
        request['Password']['Buffer'] = password
    request['NameType'] = nameType
    return dce.request(request)

def hNetrGetJoinableOUs2(dce, domainNameParam, accountName, password, OUCount):
    request = NetrGetJoinableOUs2()
    request['ServerName'] = '\x00'*10
    request['DomainNameParam'] = checkNullString(domainNameParam)
    request['AccountName'] = checkNullString(accountName)
    if password == NULL:
        request['Password'] = NULL
    else:
        request['Password']['Buffer'] = password
    request['OUCount'] = OUCount
    return dce.request(request)

def hNetrAddAlternateComputerName(dce, alternateName, domainAccount, encryptedPassword):
    request = NetrAddAlternateComputerName()
    request['ServerName'] = '\x00'*10
    request['AlternateName'] = checkNullString(alternateName)
    request['DomainAccount'] = checkNullString(domainAccount)
    if encryptedPassword == NULL:
        request['EncryptedPassword'] = NULL
    else:
        request['EncryptedPassword']['Buffer'] = encryptedPassword
    return dce.request(request)

def hNetrRemoveAlternateComputerName(dce, alternateName, domainAccount, encryptedPassword):
    request = NetrRemoveAlternateComputerName()
    request['ServerName'] = '\x00'*10
    request['AlternateName'] = checkNullString(alternateName)
    request['DomainAccount'] = checkNullString(domainAccount)
    if encryptedPassword == NULL:
        request['EncryptedPassword'] = NULL
    else:
        request['EncryptedPassword']['Buffer'] = encryptedPassword
    return dce.request(request)

def hNetrSetPrimaryComputerName(dce, primaryName, domainAccount, encryptedPassword):
    request = NetrSetPrimaryComputerName()
    request['ServerName'] = '\x00'*10
    request['PrimaryName'] = checkNullString(primaryName)
    request['DomainAccount'] = checkNullString(domainAccount)
    if encryptedPassword == NULL:
        request['EncryptedPassword'] = NULL
    else:
        request['EncryptedPassword']['Buffer'] = encryptedPassword
    return dce.request(request)

def hNetrEnumerateComputerNames(dce, nameType):
    request = NetrEnumerateComputerNames()
    request['ServerName'] = '\x00'*10
    request['NameType'] = nameType
    return dce.request(request)

def hNetrUseAdd(dce, level, infoStruct):
    request = NetrUseAdd()
    request['ServerName'] = '\x00'*10
    request['Level'] = level
    request['InfoStruct']['tag'] = level
    request['InfoStruct']['UseInfo%d' % level] = infoStruct
    return dce.request(request)

def hNetrUseEnum(dce, level, resumeHandle = 0, preferredMaximumLength = 0xffffffff):
    request = NetrUseEnum()
    request['ServerName'] = '\x00'*10
    request['InfoStruct']['Level'] = level
    request['InfoStruct']['UseInfo']['tag'] = level
    request['InfoStruct']['UseInfo']['Level%d'%level]['Buffer'] = NULL
    request['PreferredMaximumLength'] = preferredMaximumLength
    request['ResumeHandle'] = resumeHandle
    return dce.request(request)

def hNetrUseGetInfo(dce, useName, level):
    request = NetrUseGetInfo()
    request['ServerName'] = '\x00'*10
    request['UseName'] = checkNullString(useName)
    request['Level'] = level
    return dce.request(request)

def hNetrUseDel(dce, useName, forceLevel=USE_LOTS_OF_FORCE):
    request = NetrUseDel()
    request['ServerName'] = '\x00'*10
    request['UseName'] = checkNullString(useName)
    request['ForceLevel'] = forceLevel
    return dce.request(request)

