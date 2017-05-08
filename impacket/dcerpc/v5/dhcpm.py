# Copyright (c) 2003-2017 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-DHCPM] Interface implementation
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

from impacket import system_errors
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, NULL, DWORD, BOOL, BYTE
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray, NDRPOINTER, NDRSTRUCT, NDRENUM, NDRUNION
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.enum import Enum
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_DHCPSRV  = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F874532D', '1.0'))
MSRPC_UUID_DHCPSRV2 = uuidtup_to_bin(('5B821720-F63B-11D0-AAD2-00C04FC324DB', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'DHCPM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DHCPM SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
DHCP_SRV_HANDLE = LPWSTR
DHCP_IP_ADDRESS = DWORD
DHCP_IP_MASK = DWORD

################################################################################
# STRUCTURES
################################################################################

# 2.2.1.1.3 DHCP_SEARCH_INFO_TYPE
class DHCP_SEARCH_INFO_TYPE(NDRENUM):
    class enumItems(Enum):
        DhcpClientIpAddress = 0
        DhcpClientHardwareAddress = 1
        DhcpClientName = 2

# 2.2.1.1.11 QuarantineStatus
class QuarantineStatus(NDRENUM):
    class enumItems(Enum):
        NOQUARANTINE = 0
        RESTRICTEDACCESS = 1
        DROPPACKET = 2
        PROBATION = 3
        EXEMPT = 4
        DEFAULTQUARSETTING = 5
        NOQUARINFO = 6

# 2.2.1.2.7 DHCP_HOST_INFO
class DHCP_HOST_INFO(NDRSTRUCT):
    structure = (
        ('IpAddress', DHCP_IP_ADDRESS),
        ('NetBiosName', LPWSTR),
        ('HostName', LPWSTR),
    )

# 2.2.1.2.9 DHCP_BINARY_DATA
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class DHCP_BINARY_DATA(NDRSTRUCT):
    structure = (
        ('DataLength', DWORD),
        ('Data_', PBYTE_ARRAY),
    )

DHCP_CLIENT_UID = DHCP_BINARY_DATA

class DHCP_CLIENT_SEARCH_UNION(NDRUNION):
    union = {
        DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress       : ('ClientIpAddress', DHCP_IP_ADDRESS),
        DHCP_SEARCH_INFO_TYPE.DhcpClientHardwareAddress : ('ClientHardwareAddress', DHCP_CLIENT_UID),
        DHCP_SEARCH_INFO_TYPE.DhcpClientName            : ('ClientName', LPWSTR),
    }

class DHCP_SEARCH_INFO(NDRSTRUCT):
    structure = (
        ('SearchType', DHCP_SEARCH_INFO_TYPE),
        ('SearchInfo', DHCP_CLIENT_SEARCH_UNION),
    )

# 2.2.1.2.11 DATE_TIME
class DATE_TIME(NDRSTRUCT):
    structure = (
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD),
    )

# 2.2.1.2.14 DHCP_CLIENT_INFO_V4
class DHCP_CLIENT_INFO_V4(NDRSTRUCT):
    structure = (
        ('ClientIpAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('ClientHardwareAddress', DHCP_CLIENT_UID),
        ('ClientName', LPWSTR),
        ('ClientComment', LPWSTR),
        ('ClientLeaseExpires', DATE_TIME),
        ('OwnerHost', DHCP_HOST_INFO),
        ('bClientType', BYTE),
    )

class LPDHCP_CLIENT_INFO_V4(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_V4),
    )

# 2.2.1.2.115 DHCP_CLIENT_INFO_PB
class DHCP_CLIENT_INFO_PB(NDRSTRUCT):
    structure = (
        ('ClientIpAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('ClientHardwareAddress', DHCP_CLIENT_UID),
        ('ClientName', LPWSTR),
        ('ClientComment', LPWSTR),
        ('ClientLeaseExpires', DATE_TIME),
        ('OwnerHost', DHCP_HOST_INFO),
        ('bClientType', BYTE),
        ('AddressState', BYTE),
        ('Status', QuarantineStatus),
        ('ProbationEnds', DATE_TIME),
        ('QuarantineCapable', BOOL),
        ('FilterStatus', DWORD),
        ('PolicyName', LPWSTR),
    )

class LPDHCP_CLIENT_INFO_PB(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_PB),
    )

################################################################################
# RPC CALLS
################################################################################
# Interface dhcpsrv
class DhcpGetClientInfoV4(NDRCALL):
    opnum = 34
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SearchInfo', DHCP_SEARCH_INFO),
    )

class DhcpGetClientInfoV4Response(NDRCALL):
    structure = (
        ('ClientInfo', LPDHCP_CLIENT_INFO_V4),
        ('ErrorCode', ULONG),
    )

# Interface dhcpsrv2
class DhcpV4GetClientInfo(NDRCALL):
    opnum = 123
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SearchInfo', DHCP_SEARCH_INFO),
    )

class DhcpV4GetClientInfoResponse(NDRCALL):
    structure = (
        ('ClientInfo', LPDHCP_CLIENT_INFO_PB),
        ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 34  : (DhcpGetClientInfoV4, DhcpGetClientInfoV4Response),
 123 : (DhcpV4GetClientInfo, DhcpV4GetClientInfoResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hDhcpGetClientInfoV4(dce, searchType, searchValue):
    request = DhcpGetClientInfoV4()

    request['ServerIpAddress'] = NULL
    request['SearchInfo']['SearchType'] = searchType
    request['SearchInfo']['SearchInfo']['tag'] = searchType
    if searchType == DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress:
        request['SearchInfo']['SearchInfo']['ClientIpAddress'] = searchValue
    elif searchType == DHCP_SEARCH_INFO_TYPE.DhcpClientHardwareAddress:
        # This should be a DHCP_BINARY_DATA
        request['SearchInfo']['SearchInfo']['ClientHardwareAddress'] = searchValue
    else:
        request['SearchInfo']['SearchInfo']['ClientName'] = searchValue

    return dce.request(request)

