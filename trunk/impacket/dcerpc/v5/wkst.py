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
#   [MS-WKST] Interface implementation
#

from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.ndr import NDRCall, NDR, NDRENUM, NDRUnion, NDRLONG, NDRUniConformantArray, NDRUniFixedArray, NDRPointer
from impacket.dcerpc.v5.dtypes import *
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum

MSRPC_UUID_WKST   = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0'))

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
        if (system_errors.ERROR_MESSAGES.has_key(key)):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'WKST SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'WKST SessionError: unknown error code: 0x%x' % (self.error_code)

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
class WKSSVC_IDENTIFY_HANDLE(NDR):
    structure =  (
        ('Data', WSTR),
    )

class LPWKSSVC_IDENTIFY_HANDLE(NDRPointer):
    referent = (
        ('Data', WKSSVC_IDENTIFY_HANDLE),
    )

# 2.2.2.2 WKSSVC_IMPERSONATE_HANDLE
class WKSSVC_IMPERSONATE_HANDLE(NDR):
    structure =  (
        ('Data',WSTR),
    )

class LPWKSSVC_IMPERSONATE_HANDLE(NDRPointer):
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
class WKSTA_INFO_100(NDR):
    structure = (
        ('wki100_platform_id', NDRLONG),
        ('wki100_computername', LPWSTR),
        ('wki100_langroup', LPWSTR),
        ('wki100_ver_major', NDRLONG),
        ('wki100_ver_minor', NDRLONG),
    )

class LPWKSTA_INFO_100(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_100),
    )

# 2.2.5.2 WKSTA_INFO_101
class WKSTA_INFO_101(NDR):
    structure = (
        ('wki101_platform_id', NDRLONG),
        ('wki101_computername', LPWSTR),
        ('wki101_langroup', LPWSTR),
        ('wki101_ver_major', NDRLONG),
        ('wki101_ver_minor', NDRLONG),
        ('wki101_lanroot', LPWSTR),
    )

class LPWKSTA_INFO_101(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_101),
    )

# 2.2.5.3 WKSTA_INFO_102
class WKSTA_INFO_102(NDR):
    structure = (
        ('wki102_platform_id', NDRLONG),
        ('wki102_computername', LPWSTR),
        ('wki102_langroup', LPWSTR),
        ('wki102_ver_major', NDRLONG),
        ('wki102_ver_minor', NDRLONG),
        ('wki102_lanroot', LPWSTR),
        ('wki102_logged_on_users', NDRLONG),
    )

class LPWKSTA_INFO_102(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_102),
    )

# 2.2.5.4 WKSTA_INFO_502
class WKSTA_INFO_502(NDR):
    structure = (
        ('wki502_char_wait', NDRLONG),
        ('wki502_collection_time', NDRLONG),
        ('wki502_maximum_collection_count', NDRLONG),
        ('wki502_keep_conn', NDRLONG),
        ('wki502_max_cmds', NDRLONG),
        ('wki502_sess_timeout', NDRLONG),
        ('wki502_siz_char_buf', NDRLONG),
        ('wki502_max_threads', NDRLONG),
        ('wki502_lock_quota', NDRLONG),
        ('wki502_lock_increment', NDRLONG),
        ('wki502_lock_maximum', NDRLONG),
        ('wki502_pipe_increment', NDRLONG),
        ('wki502_pipe_maximum', NDRLONG),
        ('wki502_cache_file_timeout', NDRLONG),
        ('wki502_dormant_file_limit', NDRLONG),
        ('wki502_read_ahead_throughput', NDRLONG),
        ('wki502_num_mailslot_buffers', NDRLONG),
        ('wki502_num_srv_announce_buffers', NDRLONG),
        ('wki502_max_illegal_datagram_events', NDRLONG),
        ('wki502_illegal_datagram_event_reset_frequency', NDRLONG),
        ('wki502_log_election_packets', NDRLONG),
        ('wki502_use_opportunistic_locking', NDRLONG),
        ('wki502_use_unlock_behind', NDRLONG),
        ('wki502_use_close_behind', NDRLONG),
        ('wki502_buf_named_pipes', NDRLONG),
        ('wki502_use_lock_read_unlock', NDRLONG),
        ('wki502_utilize_nt_caching', NDRLONG),
        ('wki502_use_raw_read', NDRLONG),
        ('wki502_use_raw_write', NDRLONG),
        ('wki502_use_write_raw_data', NDRLONG),
        ('wki502_use_encryption', NDRLONG),
        ('wki502_buf_files_deny_write', NDRLONG),
        ('wki502_buf_read_only_files', NDRLONG),
        ('wki502_force_core_create_mode', NDRLONG),
        ('wki502_use_512_byte_max_transfer', NDRLONG),
    )

class LPWKSTA_INFO_502(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_502),
    )

# 2.2.5.5 WKSTA_INFO_1013
class WKSTA_INFO_1013(NDR):
    structure = (
        ('wki1013_keep_conn', NDRLONG),
    )

class LPWKSTA_INFO_1013(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_1013),
    )

# 2.2.5.6 WKSTA_INFO_1018
class WKSTA_INFO_1018(NDR):
    structure = (
        ('wki1018_sess_timeout', NDRLONG),
    )

class LPWKSTA_INFO_1018(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_1018),
    )

# 2.2.5.7 WKSTA_INFO_1046
class WKSTA_INFO_1046(NDR):
    structure = (
        ('wki1046_dormant_file_limit', NDRLONG),
    )

class LPWKSTA_INFO_1046(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO_1046),
    )

# 2.2.4.1 WKSTA_INFO
class WKSTA_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', NDRLONG),
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

class LPWKSTA_INFO(NDRPointer):
    referent = (
        ('Data', WKSTA_INFO),
    )

# 2.2.5.8 WKSTA_TRANSPORT_INFO_0
class WKSTA_TRANSPORT_INFO_0(NDR):
    structure = (
        ('wkti0_quality_of_service', NDRLONG),
        ('wkti0_number_of_vcs', NDRLONG),
        ('wkti0_transport_name', LPWSTR),
        ('wkti0_transport_address', LPWSTR),
        ('wkti0_wan_ish', NDRLONG),
    )

# 2.2.5.9 WKSTA_USER_INFO_0
class WKSTA_USER_INFO_0(NDR):
    structure = (
        ('wkui0_username', LPWSTR),
    )

# 2.2.5.10 WKSTA_USER_INFO_1
class WKSTA_USER_INFO_1(NDR):
    structure = (
        ('wkui1_username', LPWSTR),
        ('wkui1_logon_domain', LPWSTR),
        ('wkui1_oth_domains', LPWSTR),
        ('wkui1_logon_server', LPWSTR),
    )

# 2.2.5.11 STAT_WORKSTATION_0
class STAT_WORKSTATION_0(NDR):
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
        ('InitiallyFailedOperations', NDRLONG),
        ('FailedCompletionOperations', NDRLONG),
        ('ReadOperations', NDRLONG),
        ('RandomReadOperations', NDRLONG),
        ('ReadSmbs', NDRLONG),
        ('LargeReadSmbs', NDRLONG),
        ('SmallReadSmbs', NDRLONG),
        ('WriteOperations', NDRLONG),
        ('RandomWriteOperations', NDRLONG),
        ('WriteSmbs', NDRLONG),
        ('LargeWriteSmbs', NDRLONG),
        ('SmallWriteSmbs', NDRLONG),
        ('RawReadsDenied', NDRLONG),
        ('RawWritesDenied', NDRLONG),
        ('NetworkErrors', NDRLONG),
        ('Sessions', NDRLONG),
        ('FailedSessions', NDRLONG),
        ('Reconnects', NDRLONG),
        ('CoreConnects', NDRLONG),
        ('Lanman20Connects', NDRLONG),
        ('Lanman21Connects', NDRLONG),
        ('LanmanNtConnects', NDRLONG),
        ('ServerDisconnects', NDRLONG),
        ('HungSessions', NDRLONG),
        ('UseCount', NDRLONG),
        ('FailedUseCount', NDRLONG),
        ('CurrentCommands', NDRLONG),
    )

class LPSTAT_WORKSTATION_0(NDRPointer):
    referent = (
        ('Data', STAT_WORKSTATION_0),
    )

# 2.2.5.12 WKSTA_USER_INFO_0_CONTAINER
class WKSTA_USER_INFO_0_ARRAY(NDRUniConformantArray):
    item = WKSTA_USER_INFO_0

class LPWKSTA_USER_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', WKSTA_USER_INFO_0_ARRAY),
    )

class WKSTA_USER_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', LPWKSTA_USER_INFO_0_ARRAY),
    )

class LPWKSTA_USER_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', WKSTA_USER_INFO_0_CONTAINER),
    )

# 2.2.5.13 WKSTA_USER_INFO_1_CONTAINER
class WKSTA_USER_INFO_1_ARRAY(NDRUniConformantArray):
    item = WKSTA_USER_INFO_1

class LPWKSTA_USER_INFO_1_ARRAY(NDRPointer):
    referent = (
        ('Data', WKSTA_USER_INFO_1_ARRAY),
    )

class WKSTA_USER_INFO_1_CONTAINER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', LPWKSTA_USER_INFO_1_ARRAY),
    )

class LPWKSTA_USER_INFO_1_CONTAINER(NDRPointer):
    referent = (
        ('Data', WKSTA_USER_INFO_1_CONTAINER),
    )

# 2.2.5.14 WKSTA_USER_ENUM_STRUCT
class WKSTA_USER_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', NDRLONG),
    )

    union = {
        0: ('Level0', LPWKSTA_USER_INFO_0_CONTAINER),
        1: ('Level1', LPWKSTA_USER_INFO_1_CONTAINER),
    }

class WKSTA_USER_ENUM_STRUCT(NDR):
    structure = (
        ('Level', NDRLONG),
        ('WkstaUserInfo', WKSTA_USER_ENUM_UNION),
    )


# 2.2.5.15 WKSTA_TRANSPORT_INFO_0_CONTAINER
class WKSTA_TRANSPORT_INFO_0_ARRAY(NDRUniConformantArray):
    item = WKSTA_TRANSPORT_INFO_0

class LPWKSTA_TRANSPORT_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', WKSTA_TRANSPORT_INFO_0_ARRAY),
    )

class WKSTA_TRANSPORT_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', LPWKSTA_TRANSPORT_INFO_0_ARRAY),
    )

class LPWKSTA_TRANSPORT_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', WKSTA_TRANSPORT_INFO_0_CONTAINER),
    )

# 2.2.5.16 WKSTA_TRANSPORT_ENUM_STRUCT
class WKSTA_TRANSPORT_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', NDRLONG),
    )

    union = {
        0: ('Level0', LPWKSTA_TRANSPORT_INFO_0_CONTAINER),
    }

class WKSTA_TRANSPORT_ENUM_STRUCT(NDR):
    structure = (
        ('Level', NDRLONG),
        ('WkstaTransportInfo', WKSTA_TRANSPORT_ENUM_UNION),
    )

# 2.2.5.17 JOINPR_USER_PASSWORD
class WCHAR_ARRAY(WIDESTR):
    def getDataLen(self, data):
        return JOIN_MAX_PASSWORD_LENGTH

class CHAR_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return JOIN_OBFUSCATOR_LENGTH

class JOINPR_USER_PASSWORD(NDR):
    structure = (
        ('Obfuscator', CHAR_ARRAY),
        ('Buffer', WCHAR_ARRAY),
    )

# 2.2.5.18 JOINPR_ENCRYPTED_USER_PASSWORD
class JOINPR_ENCRYPTED_USER_PASSWORD(NDR):
    align = 0
    structure = (
        ('Buffer', '524s=""'),
    )

class PJOINPR_ENCRYPTED_USER_PASSWORD(NDRPointer):
    referent = (
        ('Data', JOINPR_ENCRYPTED_USER_PASSWORD),
    )

# 2.2.5.19 UNICODE_STRING
UNICODE_STRING = WSTR
class PUNICODE_STRING(NDRPointer):
    referent = (
        ('Data', UNICODE_STRING),
    )

# 2.2.5.20 NET_COMPUTER_NAME_ARRAY
class UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = UNICODE_STRING

class PUNICODE_STRING_ARRAY(NDRPointer):
    referent = (
        ('Data', UNICODE_STRING_ARRAY),
    )

class NET_COMPUTER_NAME_ARRAY(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('ComputerNames', PUNICODE_STRING_ARRAY),
    )

class PNET_COMPUTER_NAME_ARRAY(NDRPointer):
    referent = (
        ('Data', NET_COMPUTER_NAME_ARRAY), 
    )

# 2.2.5.21 USE_INFO_0
class USE_INFO_0(NDR):
    structure = (
        ('ui0_local', LPWSTR),
        ('ui0_remote', LPWSTR),
    )

class LPUSE_INFO_0(NDRPointer):
    referent = (
        ('Data', USE_INFO_0),
    )

# 2.2.5.22 USE_INFO_1
class USE_INFO_1(NDR):
    structure = (
        ('ui1_local', LPWSTR),
        ('ui1_remote', LPWSTR),
        ('ui1_password', LPWSTR),
        ('ui1_status', NDRLONG),
        ('ui1_asg_type', NDRLONG),
        ('ui1_refcount', NDRLONG),
        ('ui1_usecount', NDRLONG),
    )

class LPUSE_INFO_1(NDRPointer):
    referent = (
        ('Data', USE_INFO_1),
    )

# 2.2.5.23 USE_INFO_2
class USE_INFO_2(NDR):
    structure = (
        ('ui2_useinfo', USE_INFO_1),
        ('ui2_username', LPWSTR),
        ('ui2_domainname', LPWSTR),
    )

class LPUSE_INFO_2(NDRPointer):
    referent = (
        ('Data', USE_INFO_2),
    )

# 2.2.5.24 USE_INFO_3
class USE_INFO_3(NDR):
    structure = (
        ('ui3_ui2', USE_INFO_2),
        ('ui3_flags', ULONG),
    )

class LPUSE_INFO_3(NDRPointer):
    referent = (
        ('Data', USE_INFO_3),
    )

# 2.2.4.2 USE_INFO
class USE_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', NDRLONG),
    )

    union = {
        0: ('UseInfo0', LPUSE_INFO_0),
        1: ('UseInfo1', LPUSE_INFO_1),
        2: ('UseInfo2', LPUSE_INFO_2),
        3: ('UseInfo3', LPUSE_INFO_3),
    }

# 2.2.5.25 USE_INFO_0_CONTAINER
class USE_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', LPUSE_INFO_0),
    )

# 2.2.5.26 USE_INFO_1_CONTAINER
class USE_INFO_1_CONTAINER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', LPUSE_INFO_1),
    )

# 2.2.5.27 USE_INFO_2_CONTAINER
class USE_INFO_2_CONTAINER(NDR):
    structure = (
        ('EntriesRead', NDRLONG),
        ('Buffer', LPUSE_INFO_2),
    )

# 2.2.5.28 USE_ENUM_STRUCT
class USE_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', NDRLONG),
    )

    union = {
        0: ('Level0', USE_INFO_0_CONTAINER),
        1: ('Level1', USE_INFO_1_CONTAINER),
        2: ('Level2', USE_INFO_2_CONTAINER),
    }

class USE_ENUM_STRUCT(NDR):
    structure = (
        ('Level', NDRLONG),
        ('UseInfo', USE_ENUM_UNION),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.2.4.1 NetrWkstaGetInfo (Opnum 0)
class NetrWkstaGetInfo(NDRCall):
    opnum = 0
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', NDRLONG),
    )

class NetrWkstaGetInfoResponse(NDRCall):
    structure = (
       ('WkstaInfo',WKSTA_INFO),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.2 NetrWkstaSetInfo (Opnum 1)
class NetrWkstaSetInfo(NDRCall):
    opnum = 1
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', NDRLONG),
       ('WkstaInfo',WKSTA_INFO),
       ('ErrorParameter',LPLONG),
    )

class NetrWkstaSetInfoResponse(NDRCall):
    structure = (
       ('ErrorParameter',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.3 NetrWkstaUserEnum (Opnum 2)
class NetrWkstaUserEnum(NDRCall):
    opnum = 2
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('UserInfo', WKSTA_USER_ENUM_STRUCT),
       ('PreferredMaximumLength', NDRLONG),
       ('ResumeHandle', LPLONG),
    )

class NetrWkstaUserEnumResponse(NDRCall):
    structure = (
       ('UserInfo',WKSTA_USER_ENUM_STRUCT),
       ('TotalEntries',NDRLONG),
       ('ResumeHandle',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.4 NetrWkstaTransportEnum (Opnum 5)
class NetrWkstaTransportEnum(NDRCall):
    opnum = 5
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('TransportInfo', WKSTA_TRANSPORT_ENUM_STRUCT),
       ('PreferredMaximumLength', NDRLONG),
       ('ResumeHandle', LPLONG),
    )

class NetrWkstaTransportEnumResponse(NDRCall):
    structure = (
       ('TransportInfo',WKSTA_TRANSPORT_ENUM_STRUCT),
       ('TotalEntries',NDRLONG),
       ('ResumeHandle',NDRLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.5 NetrWkstaTransportAdd (Opnum 6)
class NetrWkstaTransportAdd(NDRCall):
    opnum = 6
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('Level', NDRLONG),
       ('TransportInfo',WKSTA_TRANSPORT_INFO_0),
       ('ErrorParameter',LPLONG),
    )

class NetrWkstaTransportAddResponse(NDRCall):
    structure = (
       ('ErrorParameter',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.7 NetrUseAdd (Opnum 8)
class NetrUseAdd(NDRCall):
    opnum = 8
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('Level', NDRLONG),
       ('InfoStruct',USE_INFO),
       ('ErrorParameter',LPLONG),
    )

class NetrUseAddResponse(NDRCall):
    structure = (
       ('ErrorParameter',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.8 NetrUseGetInfo (Opnum 9)
class NetrUseGetInfo(NDRCall):
    opnum = 9
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('UseName', WSTR),
       ('Level',NDRLONG),
    )

class NetrUseGetInfoResponse(NDRCall):
    structure = (
       ('InfoStruct',USE_INFO),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.9 NetrUseDel (Opnum 10)
class NetrUseDel(NDRCall):
    opnum = 10
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('UseName', WSTR),
       ('ForceLevel',NDRLONG),
    )

class NetrUseDelResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.10 NetrUseEnum (Opnum 11)
class NetrUseEnum(NDRCall):
    opnum = 11
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('InfoStruct', USE_ENUM_STRUCT),
       ('PreferredMaximumLength',NDRLONG),
       ('ResumeHandle',LPLONG),
    )

class NetrUseDelResponse(NDRCall):
    structure = (
       ('TotalEntries',NDRLONG),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.11 NetrWorkstationStatisticsGet (Opnum 13)
class NetrWorkstationStatisticsGet(NDRCall):
    opnum = 13
    structure = (
       ('ServerName', LPWKSSVC_IDENTIFY_HANDLE),
       ('ServiceName', LPWSTR),
       ('Level',NDRLONG),
       ('Options',NDRLONG),
    )

class NetrWorkstationStatisticsGetResponse(NDRCall):
    structure = (
       ('Buffer',LPSTAT_WORKSTATION_0),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.12 NetrGetJoinInformation (Opnum 20)
class NetrGetJoinInformation(NDRCall):
    opnum = 20
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('NameBuffer', LPWSTR),
    )

class NetrGetJoinInformationResponse(NDRCall):
    structure = (
       ('NameBuffer',LPWSTR),
       ('BufferType',NETSETUP_JOIN_STATUS),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.13 NetrJoinDomain2 (Opnum 22)
class NetrJoinDomain2(NDRCall):
    opnum = 22
    structure = (
       ('ServerName', LPWSTR),
       ('DomainNameParam', WSTR),
       ('MachineAccountOU', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', NDRLONG),
    )

class NetrJoinDomain2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.14 NetrUnjoinDomain2 (Opnum 23)
class NetrUnjoinDomain2(NDRCall):
    opnum = 23
    structure = (
       ('ServerName', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', NDRLONG),
    )

class NetrUnjoinDomain2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.15 NetrRenameMachineInDomain2 (Opnum 24)
class NetrRenameMachineInDomain2(NDRCall):
    opnum = 24
    structure = (
       ('ServerName', LPWSTR),
       ('MachineName', LPWSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Options', NDRLONG),
    )

class NetrRenameMachineInDomain2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.16 NetrValidateName2 (Opnum 25)
class NetrValidateName2(NDRCall):
    opnum = 25
    structure = (
       ('ServerName', LPWSTR),
       ('NameToValidate', WSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('NameType', NETSETUP_NAME_TYPE),
    )

class NetrValidateName2Response(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.17 NetrGetJoinableOUs2 (Opnum 26)
class NetrGetJoinableOUs2(NDRCall):
    opnum = 26
    structure = (
       ('ServerName', LPWSTR),
       ('DomainNameParam', WSTR),
       ('AccountName', LPWSTR),
       ('Password', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('OUCount', NDRLONG),
    )

class NetrGetJoinableOUs2Response(NDRCall):
    structure = (
       ('OUCount', LPLONG),
       ('OUs',PUNICODE_STRING_ARRAY),
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.18 NetrAddAlternateComputerName (Opnum 27)
class NetrAddAlternateComputerName(NDRCall):
    opnum = 27
    structure = (
       ('ServerName', LPWSTR),
       ('AlternateName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', NDRLONG),
    )

class NetrAddAlternateComputerNameResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.19 NetrRemoveAlternateComputerName (Opnum 28)
class NetrRemoveAlternateComputerName(NDRCall):
    opnum = 28
    structure = (
       ('ServerName', LPWSTR),
       ('AlternateName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', NDRLONG),
    )

class NetrRemoveAlternateComputerNameResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.20 NetrSetPrimaryComputerName (Opnum 29)
class NetrSetPrimaryComputerName(NDRCall):
    opnum = 29
    structure = (
       ('ServerName', LPWSTR),
       ('PrimaryName', LPWSTR),
       ('DomainAccount', LPWSTR),
       ('EncryptedPassword', PJOINPR_ENCRYPTED_USER_PASSWORD),
       ('Reserved', NDRLONG),
    )

class NetrSetPrimaryComputerNameResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.2.4.21 NetrEnumerateComputerNames (Opnum 30)
class NetrEnumerateComputerNames(NDRCall):
    opnum = 30
    structure = (
       ('ServerName', LPWKSSVC_IMPERSONATE_HANDLE),
       ('NameType', NET_COMPUTER_NAME_TYPE),
       ('Reserved', NDRLONG),
    )

class NetrEnumerateComputerNamesResponse(NDRCall):
    structure = (
       ('ComputerNames',PNET_COMPUTER_NAME_ARRAY),
       ('ErrorCode',NDRLONG),
    )


################################################################################
# HELPER FUNCTIONS
################################################################################

