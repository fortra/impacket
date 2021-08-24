# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)DhcpGetClientInfoV4
#   DhcpV4GetClientInfo
#   hDhcpEnumSubnetClientsV5
#   hDhcpGetOptionValueV5
#
from __future__ import division
from __future__ import print_function

import socket
import struct
import pytest
import unittest
from six import assertRaisesRegex

from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import dhcpm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException


class DHCPMTests(DCERPCTests):
    string_binding = r"ncacn_np:{0.machine}[\PIPE\dhcpserver]"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class DHCPMv1Tests(DHCPMTests):

    iface_uuid = dhcpm.MSRPC_UUID_DHCPSRV

    def test_DhcpGetClientInfoV4(self):
        dce, rpctransport = self.connect()
        request = dhcpm.DhcpGetClientInfoV4()
        request['ServerIpAddress'] = NULL

        request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        ip = struct.unpack("!I", socket.inet_aton(self.machine))[0]
        request['SearchInfo']['SearchInfo']['ClientIpAddress'] = ip

        request.dump()
        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_JET_ERROR"):
            dce.request(request)

    def test_hDhcpGetClientInfoV4(self):
        dce, rpctransport = self.connect()

        ip = struct.unpack("!I", socket.inet_aton(self.machine))[0]
        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_JET_ERROR"):
            dhcpm.hDhcpGetClientInfoV4(dce, dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress, ip)

        with assertRaisesRegex(self, DCERPCException, "0x4e2d"):
            dhcpm.hDhcpGetClientInfoV4(dce, dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName, 'PEPA\x00')


class DHCPMv2Tests(DHCPMTests):

    iface_uuid = dhcpm.MSRPC_UUID_DHCPSRV2

    def test_DhcpV4GetClientInfo(self):
        dce, rpctransport = self.connect()
        request = dhcpm.DhcpV4GetClientInfo()
        request['ServerIpAddress'] = NULL

        request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        ip = struct.unpack("!I", socket.inet_aton(self.machine))[0]
        request['SearchInfo']['SearchInfo']['ClientIpAddress'] = ip

        #request['SearchInfo']['SearchType'] = 2
        #request['SearchInfo']['SearchInfo']['tag'] = 2
        #ip = netaddr.IPAddress('172.16.123.10')
        #request['SearchInfo']['SearchInfo']['ClientName'] = 'PEPONA\0'
        request.dump()

        # For now we'e failing. This is not supported in W2k8r2
        with assertRaisesRegex(self, DCERPCException, "nca_s_op_rng_error"):
            dce.request(request)

    def test_hDhcpEnumSubnetClientsV5(self):
        dce, rpctransport = self.connect()

        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_MORE_ITEMS"):
            dhcpm.hDhcpEnumSubnetClientsV5(dce)

    def test_hDhcpGetOptionValueV5(self):
        dce, rpctransport = self.connect()
        netId = self.machine.split('.')[:-1]
        netId.append('0')
        subnet_id = struct.unpack("!I", socket.inet_aton('.'.join(netId)))[0]

        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_SUBNET_NOT_PRESENT"):
            dhcpm.hDhcpGetOptionValueV5(dce, 3,
                                        dhcpm.DHCP_FLAGS_OPTION_DEFAULT, NULL, NULL,
                                        dhcpm.DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions,
                                        subnet_id)


@pytest.mark.remote
class DHCPMv1TestsSMBTransport(DHCPMv1Tests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DHCPMv2TestsSMBTransport(DHCPMv2Tests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DHCPMv1TestsSMBTransport64(DHCPMv1Tests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class DHCPMv2TestsSMBTransport64(DHCPMv2Tests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class DHCPMv1TestsTCPTransport(DHCPMv1Tests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DHCPMv2TestsTCPTransport(DHCPMv2Tests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DHCPMv1TestsTCPTransport64(DHCPMv1Tests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class DHCPMv2TestsTCPTransport64(DHCPMv2Tests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
