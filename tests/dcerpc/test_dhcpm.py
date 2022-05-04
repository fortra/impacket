# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
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
# Not yet:
#   DhcpGetSubnetInfo
#   DhcpEnumSubnets
#   DhcpGetOptionValue
#   DhcpEnumOptionValues
#   DhcpGetOptionValueV5
#   DhcpEnumOptionValuesV5
#   DhcpGetAllOptionValues
#   DhcpEnumSubnetClientsV4
#   DhcpEnumSubnetElementsV5
#   DhcpEnumSubnetClientsVQ
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
    iface_uuid_v1 = dhcpm.MSRPC_UUID_DHCPSRV
    iface_uuid_v2 = dhcpm.MSRPC_UUID_DHCPSRV2
    string_binding = r"ncacn_np:{0.machine}[\PIPE\dhcpserver]"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_DhcpGetClientInfoV4(self):
        dce, rpctransport = self.connect(iface_uuid=self.iface_uuid_v1)
        request = dhcpm.DhcpGetClientInfoV4()
        request['ServerIpAddress'] = NULL
        request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName
        request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName
        request['SearchInfo']['SearchInfo']['ClientName'] = self.serverName + "\0"
        request.dump()

        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_JET_ERROR"):
            dce.request(request)

        #request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        #request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        #ip = struct.unpack("!I", socket.inet_aton(self.machine))[0]
        #request['SearchInfo']['SearchInfo']['ClientIpAddress'] = ip
        #request.dump()

        #with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_JET_ERROR"):
        #    dce.request(request)

    def test_hDhcpGetClientInfoV4(self):
        dce, rpctransport = self.connect(iface_uuid=self.iface_uuid_v1)

        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_JET_ERROR"):
            dhcpm.hDhcpGetClientInfoV4(dce, dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName, self.serverName + "\0")

        #ip = struct.unpack("!I", socket.inet_aton(self.machine))[0]
        #with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_JET_ERROR"):
        #    dhcpm.hDhcpGetClientInfoV4(dce, dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress, ip)

    def test_DhcpV4GetClientInfo(self):
        dce, rpctransport = self.connect(iface_uuid=self.iface_uuid_v2)
        request = dhcpm.DhcpV4GetClientInfo()
        request['ServerIpAddress'] = NULL
        request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName
        request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName
        request['SearchInfo']['SearchInfo']['ClientName'] = self.serverName + "\0"
        request.dump()

        # The DHCP client is probably not created but if we received an invalid DHCP client error
        # means the search info had no corresponding IPv4 lease records.
        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_INVALID_DHCP_CLIENT"):
            dce.request(request)

        #request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        #request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
        #ip = struct.unpack("!I", socket.inet_aton(self.machine))[0]
        #request['SearchInfo']['SearchInfo']['ClientIpAddress'] = ip
        #request.dump()

        #with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_INVALID_DHCP_CLIENT"):
        #    dce.request(request)

    def test_hDhcpEnumSubnetClientsV5(self):
        dce, rpctransport = self.connect(iface_uuid=self.iface_uuid_v2)

        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_MORE_ITEMS"):
            dhcpm.hDhcpEnumSubnetClientsV5(dce)

    def test_hDhcpGetOptionValueV5(self):
        dce, rpctransport = self.connect(iface_uuid=self.iface_uuid_v2)
        netId = self.machine.split('.')[:-1]
        netId.append('0')
        subnet_id = struct.unpack("!I", socket.inet_aton('.'.join(netId)))[0]

        with assertRaisesRegex(self, DCERPCException, "ERROR_DHCP_SUBNET_NOT_PRESENT"):
            dhcpm.hDhcpGetOptionValueV5(dce, 3,
                                        dhcpm.DHCP_FLAGS_OPTION_DEFAULT, NULL, NULL,
                                        dhcpm.DHCP_OPTION_SCOPE_TYPE.DhcpSubnetOptions,
                                        subnet_id)


@pytest.mark.remote
@pytest.mark.skip(reason="Disabled in Windows Server 2008 onwards")
class DHCPMTestsSMBTransport(DHCPMTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
@pytest.mark.skip(reason="Disabled in Windows Server 2008 onwards")
class DHCPMTestsSMBTransport64(DHCPMTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class DHCPMTestsTCPTransport(DHCPMTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    iface_uuid = dhcpm.MSRPC_UUID_DHCPSRV2
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DHCPMTestsTCPTransport64(DHCPMTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    iface_uuid = dhcpm.MSRPC_UUID_DHCPSRV2
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64
    
    @pytest.mark.xfail(reason="NDRUNION without fields as in DhcpSubnetOptions is not implemented with NDR64")
    def test_hDhcpGetOptionValueV5(self):
        super(DHCPMTestsTCPTransport64, self).test_hDhcpGetOptionValueV5()


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
