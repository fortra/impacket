# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
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
#   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file.
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too.
#

from impacket import system_errors
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, NULL, DWORD, BOOL, BYTE, LPDWORD, WORD
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray, NDRPOINTER, NDRSTRUCT, NDRENUM, NDRUNION
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.enum import Enum
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_DHCPSRV = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F874532D', '1.0'))
MSRPC_UUID_DHCPSRV2 = uuidtup_to_bin(('5B821720-F63B-11D0-AAD2-00C04FC324DB', '1.0'))


class DCERPCSessionError(DCERPCException):
    ERROR_MESSAGES = {
        0x00004E2D: ("ERROR_DHCP_JET_ERROR", "An error occurred while accessing the DHCP server database."),
        0x00004E25: ("ERROR_DHCP_SUBNET_NOT_PRESENT", "The specified IPv4 subnet does not exist."),
        0x00004E54: ("ERROR_DHCP_SUBNET_EXISTS", "The IPv4 scope parameters are incorrect. Either the IPv4 scope already"
                                                 " exists, corresponding to the SubnetAddress and SubnetMask members of "
                                                 "the structure DHCP_SUBNET_INFO (section 2.2.1.2.8), or there is a "
                                                 "range overlap of IPv4 addresses between those associated with the "
                                                 "SubnetAddress and SubnetMask fields of the new IPv4 scope and the "
                                                 "subnet address and mask of an already existing IPv4 scope"),

    }
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'DHCPM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif self.ERROR_MESSAGES.has_key(key):
            error_msg_short = self.ERROR_MESSAGES[key][0]
            error_msg_verbose = self.ERROR_MESSAGES[key][1]
            return 'DHCPM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DHCPM SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
DHCP_SRV_HANDLE = LPWSTR
DHCP_IP_ADDRESS = DWORD
DHCP_IP_MASK = DWORD
DHCP_OPTION_ID = DWORD

# DHCP enumeratiom flags
DHCP_FLAGS_OPTION_DEFAULT = 0x00000000
DHCP_FLAGS_OPTION_IS_VENDOR = 0x00000003

# Errors
ERROR_DHCP_JET_ERROR = 0x00004E2D
ERROR_DHCP_SUBNET_NOT_PRESENT = 0x00004E25
ERROR_DHCP_SUBNET_EXISTS = 0x00004E54
################################################################################
# STRUCTURES
################################################################################
# 2.2.1.1.3 DHCP_SEARCH_INFO_TYPE
class DHCP_SEARCH_INFO_TYPE(NDRENUM):
    class enumItems(Enum):
        DhcpClientIpAddress       = 0
        DhcpClientHardwareAddress = 1
        DhcpClientName            = 2

# 2.2.1.1.11 QuarantineStatus
class QuarantineStatus(NDRENUM):
    class enumItems(Enum):
        NOQUARANTINE        = 0
        RESTRICTEDACCESS    = 1
        DROPPACKET          = 2
        PROBATION           = 3
        EXEMPT              = 4
        DEFAULTQUARSETTING  = 5
        NOQUARINFO          = 6

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

# 2.2.1.2.11 DATE_TIME
class DATE_TIME(NDRSTRUCT):
    structure = (
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD),
    )

# 2.2.1.2.19 DHCP_CLIENT_INFO_VQ
class DHCP_CLIENT_INFO_VQ(NDRSTRUCT):
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
    )

class DHCP_CLIENT_SEARCH_UNION(NDRUNION):
    union = {
        DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress:       ('ClientIpAddress', DHCP_IP_ADDRESS),
        DHCP_SEARCH_INFO_TYPE.DhcpClientHardwareAddress: ('ClientHardwareAddress', DHCP_CLIENT_UID),
        DHCP_SEARCH_INFO_TYPE.DhcpClientName:            ('ClientName', LPWSTR),
    }

class DHCP_SEARCH_INFO(NDRSTRUCT):
    structure = (
        ('SearchType', DHCP_SEARCH_INFO_TYPE),
        ('SearchInfo', DHCP_CLIENT_SEARCH_UNION),
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

class DHCP_CLIENT_INFO_V5(NDRSTRUCT):
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
    )

class LPDHCP_CLIENT_INFO_V4(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_V4),
    )

class LPDHCP_CLIENT_INFO_V5(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_V5),
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

class LPDHCP_CLIENT_INFO_VQ(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_VQ),
    )

class DHCP_CLIENT_INFO_VQ_ARRAY(NDRUniConformantArray):
    item = LPDHCP_CLIENT_INFO_VQ

class LPDHCP_CLIENT_INFO_VQ_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_VQ_ARRAY),
    )

class DHCP_CLIENT_INFO_ARRAY_VQ(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Clients', LPDHCP_CLIENT_INFO_VQ_ARRAY),
    )

class LPDHCP_CLIENT_INFO_ARRAY_VQ(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_ARRAY_VQ),
    )

class DHCP_CLIENT_INFO_V4_ARRAY(NDRUniConformantArray):
    item = LPDHCP_CLIENT_INFO_V4

class DHCP_CLIENT_INFO_V5_ARRAY(NDRUniConformantArray):
    item = LPDHCP_CLIENT_INFO_V5

class LPDHCP_CLIENT_INFO_V4_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_V4_ARRAY),
    )

class LPDHCP_CLIENT_INFO_V5_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_V5_ARRAY),
    )

class DHCP_CLIENT_INFO_ARRAY_V4(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Clients', LPDHCP_CLIENT_INFO_V4_ARRAY),
    )

class DHCP_CLIENT_INFO_ARRAY_V5(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Clients', LPDHCP_CLIENT_INFO_V4_ARRAY),
    )

class LPDHCP_CLIENT_INFO_ARRAY_V5(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_ARRAY_V5),
    )

class LPDHCP_CLIENT_INFO_ARRAY_V4(NDRPOINTER):
    referent = (
        ('Data', DHCP_CLIENT_INFO_ARRAY_V4),
    )

class DHCP_IP_ADDRESS_ARRAY(NDRUniConformantArray):
    item = DHCP_IP_ADDRESS

class LPDHCP_IP_ADDRESS_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DHCP_IP_ADDRESS_ARRAY),
    )

class DHCP_IP_ARRAY(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Elements', LPDHCP_IP_ADDRESS_ARRAY),
    )

class DHCP_SUBNET_STATE(NDRENUM):
    class enumItems(Enum):
        DhcpSubnetEnabled           = 0
        DhcpSubnetDisabled          = 1
        DhcpSubnetEnabledSwitched   = 2
        DhcpSubnetDisabledSwitched  = 3
        DhcpSubnetInvalidState      = 4

class DHCP_SUBNET_INFO(NDRSTRUCT):
    structure = (
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('SubnetMask', DHCP_IP_MASK),
        ('SubnetName', LPWSTR),
        ('SubnetComment', LPWSTR),
        ('PrimaryHost', DHCP_HOST_INFO),
        ('SubnetState', DHCP_SUBNET_STATE),
    )

class LPDHCP_SUBNET_INFO(NDRPOINTER):
    referent = (
        ('Data', DHCP_SUBNET_INFO),
    )

class DHCP_OPTION_SCOPE_TYPE(NDRENUM):
    class enumItems(Enum):
        DhcpDefaultOptions  = 0
        DhcpGlobalOptions   = 1
        DhcpSubnetOptions   = 2
        DhcpReservedOptions = 3
        DhcpMScopeOptions   = 4

class DHCP_RESERVED_SCOPE(NDRSTRUCT):
    structure = (
        ('ReservedIpAddress', DHCP_IP_ADDRESS),
        ('ReservedIpSubnetAddress', DHCP_IP_ADDRESS),
    )

class DHCP_OPTION_SCOPE_UNION(NDRUNION):
    union = {
        DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions   : (),
        DHCP_OPTION_SCOPE_TYPE.DhcpGlobalOptions    : (),
        DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions    : ('SubnetScopeInfo', DHCP_IP_ADDRESS),
        DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions  : ('ReservedScopeInfo', DHCP_RESERVED_SCOPE),
        DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions    : ('MScopeInfo', LPWSTR),
    }

class DHCP_OPTION_SCOPE_INFO(NDRSTRUCT):
    structure = (
        ('ScopeType', DHCP_OPTION_SCOPE_TYPE),
        ('ScopeInfo', DHCP_OPTION_SCOPE_UNION),
    )

class LPDHCP_OPTION_SCOPE_INFO(NDRPOINTER):
    referent = (
        ('Data', DHCP_OPTION_SCOPE_INFO)
    )

class DWORD_DWORD(NDRSTRUCT):
    structure = (
        ('DWord1', DWORD),
        ('DWord2', DWORD),
    )

class DHCP_BOOTP_IP_RANGE(NDRSTRUCT):
    structure = (
        ('StartAddress', DHCP_IP_ADDRESS),
        ('EndAddress', DHCP_IP_ADDRESS),
        ('BootpAllocated', ULONG),
        ('MaxBootpAllowed', DHCP_IP_ADDRESS),
        ('MaxBootpAllowed', ULONG ),
    )

class DHCP_IP_RESERVATION_V4(NDRSTRUCT):
    structure = (
        ('ReservedIpAddress', DHCP_IP_ADDRESS),
        ('ReservedForClient', DHCP_CLIENT_UID),
        ('bAllowedClientTypes', BYTE),
    )

class DHCP_IP_RANGE(NDRSTRUCT):
    structure = (
        ('StartAddress', DHCP_IP_ADDRESS),
        ('EndAddress', DHCP_IP_ADDRESS),
    )

class DHCP_IP_CLUSTER(NDRSTRUCT):
    structure = (
        ('ClusterAddress', DHCP_IP_ADDRESS),
        ('ClusterMask', DWORD),
    )

class DHCP_SUBNET_ELEMENT_TYPE(NDRENUM):
    class enumItems(Enum):
        DhcpIpRanges           = 0
        DhcpSecondaryHosts     = 1
        DhcpReservedIps        = 2
        DhcpExcludedIpRanges   = 3
        DhcpIpUsedClusters     = 4
        DhcpIpRangesDhcpOnly   = 5
        DhcpIpRangesDhcpBootp  = 6
        DhcpIpRangesBootpOnly  = 7

class DHCP_SUBNET_ELEMENT_UNION_V5(NDRUNION):
    union = {
        DHCP_SUBNET_ELEMENT_TYPE.DhcpIpRanges           : ('IpRange', DHCP_BOOTP_IP_RANGE),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpSecondaryHosts     : ('SecondaryHost', DHCP_HOST_INFO),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpReservedIps        : ('ReservedIp', DHCP_IP_RESERVATION_V4),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpExcludedIpRanges   : ('ExcludeIpRange', DHCP_IP_RANGE),
        DHCP_SUBNET_ELEMENT_TYPE.DhcpIpUsedClusters     : ('IpUsedCluster', DHCP_IP_CLUSTER),
    }

class DHCP_SUBNET_ELEMENT_DATA_V5(NDRSTRUCT):
    structure = (
        ('ElementType', DHCP_SUBNET_ELEMENT_TYPE),
        ('Element', DHCP_SUBNET_ELEMENT_UNION_V5),
    )

class LPDHCP_SUBNET_ELEMENT_DATA_V5(NDRUniConformantArray):
    item = DHCP_SUBNET_ELEMENT_DATA_V5

class DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Elements', LPDHCP_SUBNET_ELEMENT_DATA_V5),
    )

class LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5(NDRPOINTER):
    referent = (
        ('Data', DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5)
    )

class DHCP_OPTION_DATA_TYPE(NDRENUM):
    class enumItems(Enum):
        DhcpByteOption              = 0
        DhcpWordOption              = 1
        DhcpDWordOption             = 2
        DhcpDWordDWordOption        = 3
        DhcpIpAddressOption         = 4
        DhcpStringDataOption        = 5
        DhcpBinaryDataOption        = 6
        DhcpEncapsulatedDataOption  = 7
        DhcpIpv6AddressOption       = 8

class DHCP_OPTION_ELEMENT_UNION(NDRUNION):
    commonHdr = (
        ('tag', DHCP_OPTION_DATA_TYPE),
    )
    union = {
        DHCP_OPTION_DATA_TYPE.DhcpByteOption            : ('ByteOption', BYTE),
        DHCP_OPTION_DATA_TYPE.DhcpWordOption            : ('WordOption', WORD),
        DHCP_OPTION_DATA_TYPE.DhcpDWordOption           : ('DWordOption', DWORD),
        DHCP_OPTION_DATA_TYPE.DhcpDWordDWordOption      : ('DWordDWordOption', DWORD_DWORD),
        DHCP_OPTION_DATA_TYPE.DhcpIpAddressOption       : ('IpAddressOption', DHCP_IP_ADDRESS),
        DHCP_OPTION_DATA_TYPE.DhcpStringDataOption      : ('StringDataOption', LPWSTR),
        DHCP_OPTION_DATA_TYPE.DhcpBinaryDataOption      : ('BinaryDataOption', DHCP_BINARY_DATA),
        DHCP_OPTION_DATA_TYPE.DhcpEncapsulatedDataOption: ('EncapsulatedDataOption', DHCP_BINARY_DATA),
        DHCP_OPTION_DATA_TYPE.DhcpIpv6AddressOption     : ('Ipv6AddressDataOption', LPWSTR),
    }

class DHCP_OPTION_DATA_ELEMENT(NDRSTRUCT):
    structure = (
        ('OptionType', DHCP_OPTION_DATA_TYPE),
        ('Element', DHCP_OPTION_ELEMENT_UNION),
    )

class DHCP_OPTION_DATA_ELEMENT_ARRAY2(NDRUniConformantArray):
    item = DHCP_OPTION_DATA_ELEMENT

class LPDHCP_OPTION_DATA_ELEMENT(NDRPOINTER):
    referent = (
        ('Data', DHCP_OPTION_DATA_ELEMENT_ARRAY2),
    )

class DHCP_OPTION_DATA(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Elements', LPDHCP_OPTION_DATA_ELEMENT),
    )

class DHCP_OPTION_VALUE(NDRSTRUCT):
    structure = (
        ('OptionID', DHCP_OPTION_ID),
        ('Value', DHCP_OPTION_DATA),
    )

class PDHCP_OPTION_VALUE(NDRPOINTER):
    referent = (
        ('Data', DHCP_OPTION_VALUE),
    )

class DHCP_OPTION_VALUE_ARRAY2(NDRUniConformantArray):
    item = DHCP_OPTION_VALUE

class LPDHCP_OPTION_VALUE(NDRPOINTER):
    referent = (
        ('Data', DHCP_OPTION_VALUE_ARRAY2),
    )

class DHCP_OPTION_VALUE_ARRAY(NDRSTRUCT):
    structure = (
        ('NumElements', DWORD),
        ('Values', LPDHCP_OPTION_VALUE),
    )

class LPDHCP_OPTION_VALUE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DHCP_OPTION_VALUE_ARRAY),
    )

class DHCP_ALL_OPTION_VALUES(NDRSTRUCT):
    structure = (
        ('ClassName', LPWSTR),
        ('VendorName', LPWSTR),
        ('IsVendor', BOOL),
        ('OptionsArray', LPDHCP_OPTION_VALUE_ARRAY),
    )

class OPTION_VALUES_ARRAY(NDRUniConformantArray):
    item = DHCP_ALL_OPTION_VALUES

class LPOPTION_VALUES_ARRAY(NDRPOINTER):
    referent = (
        ('Data', OPTION_VALUES_ARRAY),
    )

class DHCP_ALL_OPTIONS_VALUES(NDRSTRUCT):
    structure = (
        ('Flags', DWORD),
        ('NumElements', DWORD),
        ('Options', LPOPTION_VALUES_ARRAY),
    )

class LPDHCP_ALL_OPTION_VALUES(NDRPOINTER):
    referent = (
        ('Data', DHCP_ALL_OPTIONS_VALUES),
    )

################################################################################
# RPC CALLS
################################################################################
# Interface dhcpsrv
class DhcpGetSubnetInfo(NDRCALL):
    opnum = 2
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
    )

class DhcpGetSubnetInfoResponse(NDRCALL):
    structure = (
        ('SubnetInfo', LPDHCP_SUBNET_INFO),
        ('ErrorCode', ULONG),
    )

class DhcpEnumSubnets(NDRCALL):
    opnum = 3
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumSubnetsResponse(NDRCALL):
    structure = (
        ('ResumeHandle', LPDWORD),
        ('EnumInfo', DHCP_IP_ARRAY),
        ('EnumRead', DWORD),
        ('EnumTotal', DWORD),
        ('ErrorCode', ULONG),
    )

class DhcpGetOptionValue(NDRCALL):
    opnum = 13
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('OptionID', DHCP_OPTION_ID),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
    )

class DhcpGetOptionValueResponse(NDRCALL):
    structure = (
        ('OptionValue', PDHCP_OPTION_VALUE),
        ('ErrorCode', ULONG),
    )

class DhcpEnumOptionValues(NDRCALL):
    opnum = 14
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumOptionValuesResponse(NDRCALL):
    structure = (
        ('ResumeHandle', DWORD),
        ('OptionValues', LPDHCP_OPTION_VALUE_ARRAY),
        ('OptionsRead', DWORD),
        ('OptionsTotal', DWORD),
        ('ErrorCode', ULONG),
    )

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

class DhcpEnumSubnetClientsV4(NDRCALL):
    opnum = 35
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('ResumeHandle', DWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumSubnetClientsV4Response(NDRCALL):
    structure = (
        ('ResumeHandle', LPDWORD),
        ('ClientInfo', LPDHCP_CLIENT_INFO_ARRAY_V4),
        ('ClientsRead', DWORD),
        ('ClientsTotal', DWORD),
        ('ErrorCode', ULONG),
    )

# Interface dhcpsrv2

class DhcpEnumSubnetClientsV5(NDRCALL):
    opnum = 0
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumSubnetClientsV5Response(NDRCALL):
    structure = (
        ('ResumeHandle', DWORD),
        ('ClientsInfo', LPDHCP_CLIENT_INFO_ARRAY_V5),
        ('ClientsRead', DWORD),
        ('ClientsTotal', DWORD),
    )

class DhcpGetOptionValueV5(NDRCALL):
    opnum = 21
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('Flags', DWORD),
        ('OptionID', DHCP_OPTION_ID),
        ('ClassName', LPWSTR),
        ('VendorName', LPWSTR),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
    )

class DhcpGetOptionValueV5Response(NDRCALL):
    structure = (
        ('OptionValue', PDHCP_OPTION_VALUE),
        ('ErrorCode', ULONG),
    )

class DhcpEnumOptionValuesV5(NDRCALL):
    opnum = 22
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('Flags', DWORD),
        ('ClassName', LPWSTR),
        ('VendorName', LPWSTR),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumOptionValuesV5Response(NDRCALL):
    structure = (
        ('ResumeHandle', DWORD),
        ('OptionValues', LPDHCP_OPTION_VALUE_ARRAY),
        ('OptionsRead', DWORD),
        ('OptionsTotal', DWORD),
        ('ErrorCode', ULONG),
    )

class DhcpGetAllOptionValues(NDRCALL):
    opnum = 30
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('Flags', DWORD),
        ('ScopeInfo', DHCP_OPTION_SCOPE_INFO),
    )

class DhcpGetAllOptionValuesResponse(NDRCALL):
    structure = (
        ('Values', LPDHCP_ALL_OPTION_VALUES),
        ('ErrorCode', ULONG),
    )

class DhcpEnumSubnetElementsV5(NDRCALL):
    opnum = 38
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('EnumElementType', DHCP_SUBNET_ELEMENT_TYPE),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumSubnetElementsV5Response(NDRCALL):
    structure = (
        ('ResumeHandle', DWORD),
        ('EnumElementInfo', LPDHCP_SUBNET_ELEMENT_INFO_ARRAY_V5),
        ('ElementsRead', DWORD),
        ('ElementsTotal', DWORD),
        ('ErrorCode', ULONG),
    )

class DhcpEnumSubnetClientsVQ(NDRCALL):
    opnum = 47
    structure = (
        ('ServerIpAddress', DHCP_SRV_HANDLE),
        ('SubnetAddress', DHCP_IP_ADDRESS),
        ('ResumeHandle', LPDWORD),
        ('PreferredMaximum', DWORD),
    )

class DhcpEnumSubnetClientsVQResponse(NDRCALL):
    structure = (
        ('ResumeHandle', LPDWORD),
        ('ClientInfo', LPDHCP_CLIENT_INFO_ARRAY_VQ),
        ('ClientsRead', DWORD),
        ('ClientsTotal', DWORD),
        ('ErrorCode', ULONG),
    )

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
    0: (DhcpEnumSubnetClientsV5, DhcpEnumSubnetClientsV5Response),
    2: (DhcpGetSubnetInfo, DhcpGetSubnetInfoResponse),
    3: (DhcpEnumSubnets, DhcpEnumSubnetsResponse),
    13: (DhcpGetOptionValue, DhcpGetOptionValueResponse),
    14: (DhcpEnumOptionValues, DhcpEnumOptionValuesResponse),
    21: (DhcpGetOptionValueV5, DhcpGetOptionValueV5Response),
    22: (DhcpEnumOptionValuesV5, DhcpEnumOptionValuesV5Response),
    30: (DhcpGetAllOptionValues, DhcpGetAllOptionValuesResponse),
    34: (DhcpGetClientInfoV4, DhcpGetClientInfoV4Response),
    35: (DhcpEnumSubnetClientsV4, DhcpEnumSubnetClientsV4Response),
    38: (DhcpEnumSubnetElementsV5, DhcpEnumSubnetElementsV5Response),
    47: (DhcpEnumSubnetClientsVQ, DhcpEnumSubnetClientsVQResponse),
    123: (DhcpV4GetClientInfo, DhcpV4GetClientInfoResponse),
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

def hDhcpGetSubnetInfo(dce, subnetaddress):
    request = DhcpGetSubnetInfo()

    request['ServerIpAddress'] = NULL
    request['SubnetAddress'] = subnetaddress
    resp = dce.request(request)

    return resp

def hDhcpGetOptionValue(dce, optionID, scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL):
    request = DhcpGetOptionValue()

    request['ServerIpAddress'] = NULL
    request['OptionID'] = optionID
    request['ScopeInfo']['ScopeType'] = scopetype
    if scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions and scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpGlobalOptions:
        request['ScopeInfo']['ScopeInfo']['tag'] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions:
        request['ScopeInfo']['ScopeInfo']['SubnetScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions:
        request['ScopeInfo']['ScopeInfo']['ReservedScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions:
        request['ScopeInfo']['ScopeInfo']['MScopeInfo'] = options

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumOptionValues(dce, scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL,
                          preferredMaximum=0xffffffff):
    request = DhcpEnumOptionValues()

    request['ServerIpAddress'] = NULL
    request['ScopeInfo']['ScopeType'] = scopetype
    if scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions and scopetype != DHCP_OPTION_SCOPE_TYPE.DhcpGlobalOptions:
        request['ScopeInfo']['ScopeInfo']['tag'] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions:
        request['ScopeInfo']['ScopeInfo']['SubnetScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions:
        request['ScopeInfo']['ScopeInfo']['ReservedScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions:
        request['ScopeInfo']['ScopeInfo']['MScopeInfo'] = options
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumOptionValuesV5(dce, flags=DHCP_FLAGS_OPTION_DEFAULT, classname=NULL, vendorname=NULL,
                            scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL,
                            preferredMaximum=0xffffffff):
    request = DhcpEnumOptionValuesV5()

    request['ServerIpAddress'] = NULL
    request['Flags'] = flags
    request['ClassName'] = classname
    request['VendorName'] = vendorname
    request['ScopeInfo']['ScopeType'] = scopetype
    request['ScopeInfo']['ScopeInfo']['tag'] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions:
        request['ScopeInfo']['ScopeInfo']['SubnetScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions:
        request['ScopeInfo']['ScopeInfo']['ReservedScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions:
        request['ScopeInfo']['ScopeInfo']['MScopeInfo'] = options
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpGetOptionValueV5(dce, option_id, flags=DHCP_FLAGS_OPTION_DEFAULT, classname=NULL, vendorname=NULL,
                            scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL):
    request = DhcpGetOptionValueV5()

    request['ServerIpAddress'] = NULL
    request['Flags'] = flags
    request['OptionID'] = option_id
    request['ClassName'] = classname
    request['VendorName'] = vendorname
    request['ScopeInfo']['ScopeType'] = scopetype
    request['ScopeInfo']['ScopeInfo']['tag'] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions:
        request['ScopeInfo']['ScopeInfo']['SubnetScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions:
        request['ScopeInfo']['ScopeInfo']['ReservedScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions:
        request['ScopeInfo']['ScopeInfo']['MScopeInfo'] = options

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpGetAllOptionValues(dce, scopetype=DHCP_OPTION_SCOPE_TYPE.DhcpDefaultOptions, options=NULL):
    request = DhcpGetAllOptionValues()

    request['ServerIpAddress'] = NULL
    request['Flags'] = NULL
    request['ScopeInfo']['ScopeType'] = scopetype
    request['ScopeInfo']['ScopeInfo']['tag'] = scopetype
    if scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions:
        request['ScopeInfo']['ScopeInfo']['SubnetScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpReservedOptions:
        request['ScopeInfo']['ScopeInfo']['ReservedScopeInfo'] = options
    elif scopetype == DHCP_OPTION_SCOPE_TYPE.DhcpMScopeOptions:
        request['ScopeInfo']['ScopeInfo']['MScopeInfo'] = options

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumSubnets(dce, preferredMaximum=0xffffffff):
    request = DhcpEnumSubnets()

    request['ServerIpAddress'] = NULL
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumSubnetClientsVQ(dce, preferredMaximum=0xffffffff):
    request = DhcpEnumSubnetClientsVQ()

    request['ServerIpAddress'] = NULL
    request['SubnetAddress'] = NULL
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumSubnetClientsV4(dce, preferredMaximum=0xffffffff):
    request = DhcpEnumSubnetClientsV4()

    request['ServerIpAddress'] = NULL
    request['SubnetAddress'] = NULL
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumSubnetClientsV5(dce, subnetAddress=0, preferredMaximum=0xffffffff):
    request = DhcpEnumSubnetClientsV5()

    request['ServerIpAddress'] = NULL
    request['SubnetAddress'] = subnetAddress
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum
    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCSessionError, e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            resp = e.get_packet()
        return resp

def hDhcpEnumSubnetElementsV5(dce, subnet_address, element_type=DHCP_SUBNET_ELEMENT_TYPE.DhcpIpRanges, preferredMaximum=0xffffffff):
    request = DhcpEnumSubnetElementsV5()

    request['ServerIpAddress'] = NULL
    request['SubnetAddress'] = subnet_address
    request['EnumElementType'] = element_type
    request['ResumeHandle'] = NULL
    request['PreferredMaximum'] = preferredMaximum

    status = system_errors.ERROR_MORE_DATA
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException, e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            resp = e.get_packet()
        return resp
