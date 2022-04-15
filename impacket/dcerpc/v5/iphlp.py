# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Implementation of iphlpsvc.dll MSRPC calls (Service that offers IPv6 connectivity over an IPv4 network)
#
# Authors:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#

from socket import inet_aton

from impacket import uuid
from impacket import hresult_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.dtypes import BYTE, ULONG, WSTR, GUID, NULL
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_IPHLP_IP_TRANSITION   = uuidtup_to_bin(('552d076a-cb29-4e44-8b6a-d15e59e2c0af', '1.0'))

# RPC_IF_ALLOW_LOCAL_ONLY
MSRPC_UUID_IPHLP_TEREDO          = uuidtup_to_bin(('ecbdb051-f208-46b9-8c8b-648d9d3f3944', '1.0'))
MSRPC_UUID_IPHLP_TEREDO_CONSUMER = uuidtup_to_bin(('1fff8faa-ec23-4e3f-a8ce-4b2f8707e636', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'IPHLP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'IPHLP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

# Notification types
NOTIFICATION_ISATAP_CONFIGURATION_CHANGE               = 0
NOTIFICATION_PROCESS6TO4_CONFIGURATION_CHANGE          = 1
NOTIFICATION_TEREDO_CONFIGURATION_CHANGE               = 2
NOTIFICATION_IP_TLS_CONFIGURATION_CHANGE               = 3
NOTIFICATION_PORT_CONFIGURATION_CHANGE                 = 4
NOTIFICATION_DNS64_CONFIGURATION_CHANGE                = 5
NOTIFICATION_DA_SITE_MGR_LOCAL_CONFIGURATION_CHANGE_EX = 6

################################################################################
# STRUCTURES
################################################################################

class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

################################################################################
# RPC CALLS
################################################################################

# Opnum 0
class IpTransitionProtocolApplyConfigChanges(NDRCALL):
    opnum = 0
    structure = (
       ('NotificationNum', BYTE),
    )

class IpTransitionProtocolApplyConfigChangesResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

# Opnum 1
class IpTransitionProtocolApplyConfigChangesEx(NDRCALL):
    opnum = 1
    structure = (
       ('NotificationNum', BYTE),
       ('DataLength', ULONG),
       ('Data', BYTE_ARRAY),
    )

class IpTransitionProtocolApplyConfigChangesExResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

# Opnum 2
class IpTransitionCreatev6Inv4Tunnel(NDRCALL):
    opnum = 2
    structure = (
       ('LocalAddress', "4s=''"),
       ('RemoteAddress', "4s=''"),
       ('InterfaceName', WSTR),
    )

class IpTransitionCreatev6Inv4TunnelResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

# Opnum 3
class IpTransitionDeletev6Inv4Tunnel(NDRCALL):
    opnum = 3
    structure = (
       ('TunnelGuid', GUID),
    )

class IpTransitionDeletev6Inv4TunnelResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################

OPNUMS = {
 0 : (IpTransitionProtocolApplyConfigChanges, IpTransitionProtocolApplyConfigChangesResponse),
 1 : (IpTransitionProtocolApplyConfigChangesEx, IpTransitionProtocolApplyConfigChangesExResponse),
 2 : (IpTransitionCreatev6Inv4Tunnel, IpTransitionCreatev6Inv4TunnelResponse),
 3 : (IpTransitionDeletev6Inv4Tunnel, IpTransitionDeletev6Inv4TunnelResponse)
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

# For all notifications except EX
def hIpTransitionProtocolApplyConfigChanges(dce, notification_num):
    request = IpTransitionProtocolApplyConfigChanges()
    request['NotificationNum'] = notification_num

    return dce.request(request)

# Only for NOTIFICATION_DA_SITE_MGR_LOCAL_CONFIGURATION_CHANGE_EX
# No admin required
def hIpTransitionProtocolApplyConfigChangesEx(dce, notification_num, notification_data):
    request = IpTransitionProtocolApplyConfigChangesEx()
    request['NotificationNum'] = notification_num
    request['DataLength'] = len(notification_data)
    request['Data'] = notification_data

    return dce.request(request)

# Same as netsh interface ipv6 add v6v4tunnel "Test Tunnel" 192.168.0.1 10.0.0.5
def hIpTransitionCreatev6Inv4Tunnel(dce, local_address, remote_address, interface_name):
    request = IpTransitionCreatev6Inv4Tunnel()
    request['LocalAddress'] = inet_aton(local_address)
    request['RemoteAddress'] = inet_aton(remote_address)

    request['InterfaceName'] = checkNullString(interface_name)
    request.fields['InterfaceName'].fields['MaximumCount'] = 256

    return dce.request(request)

def hIpTransitionDeletev6Inv4Tunnel(dce, tunnel_guid):
    request = IpTransitionDeletev6Inv4Tunnel()
    request['TunnelGuid'] = uuid.string_to_bin(tunnel_guid)

    return dce.request(request)
