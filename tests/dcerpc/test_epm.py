# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)ept_lookup
#   (h)ept_map
#
from __future__ import division
from __future__ import print_function
import socket
import pytest
import unittest
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import epm
from impacket.dcerpc.v5.ndr import NULL
from impacket.uuid import string_to_bin, uuidtup_to_bin


class EPMTests(DCERPCTests):
    iface_uuid = epm.MSRPC_UUID_PORTMAP
    string_binding = r"ncacn_np:{0.machine}[\pipe\epmapper]"
    authn = True

    def test_lookup(self):
        dce, rpctransport = self.connect()
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
      
        resp = dce.request(request)
        for entry in resp['entries']:
            tower = entry['tower']['tower_octet_string']
            epm.EPMTower(b''.join(tower))

    def test_hlookup(self):
        epm.hept_lookup(self.machine)
        MSRPC_UUID_SAMR = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))
        epm.hept_lookup(self.machine, inquiry_type=epm.RPC_C_EP_MATCH_BY_IF, ifId=MSRPC_UUID_SAMR)
        MSRPC_UUID_ATSVC = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0'))
        epm.hept_lookup(self.machine, inquiry_type=epm.RPC_C_EP_MATCH_BY_IF, ifId=MSRPC_UUID_ATSVC)
        MSRPC_UUID_SCMR = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))
        epm.hept_lookup(self.machine, inquiry_type=epm.RPC_C_EP_MATCH_BY_IF, ifId=MSRPC_UUID_SCMR)

    def test_map(self):
        dce, rpctransport = self.connect()
        tower = epm.EPMTower()
        interface = epm.EPMRPCInterface()
        interface['InterfaceUUID'] = string_to_bin('12345778-1234-ABCD-EF00-0123456789AC')
        interface['MajorVersion'] = 1
        interface['MinorVersion'] = 0

        dataRep = epm.EPMRPCDataRepresentation()
        dataRep['DataRepUuid'] = string_to_bin('8a885d04-1ceb-11c9-9fe8-08002b104860')
        dataRep['MajorVersion'] = 2
        dataRep['MinorVersion'] = 0

        protId = epm.EPMProtocolIdentifier()
        protId['ProtIdentifier'] = 0xb

        pipeName = epm.EPMPipeName()
        pipeName['PipeName'] = b'\x00'

        portAddr = epm.EPMPortAddr()
        portAddr['IpPort'] = 0

        hostAddr = epm.EPMHostAddr()
        hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')

        hostName = epm.EPMHostName()
        hostName['HostName'] = b'\x00'

        tower['NumberOfFloors'] = 5
        tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + portAddr.getData() + hostAddr.getData()
        request = epm.ept_map()
        request['max_towers'] = 4
        request['map_tower']['tower_length'] = len(tower)
        request['map_tower']['tower_octet_string'] = tower.getData()
        resp = dce.request(request)
        resp.dump()

    def test_hept_map(self):
        MSRPC_UUID_SAMR = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))
        epm.hept_map(self.machine, MSRPC_UUID_SAMR)
        epm.hept_map(self.machine, MSRPC_UUID_SAMR, protocol='ncacn_ip_tcp')
        MSRPC_UUID_ATSVC = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0'))
        epm.hept_map(self.machine, MSRPC_UUID_ATSVC)
        MSRPC_UUID_SCMR = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))
        epm.hept_map(self.machine, MSRPC_UUID_SCMR, protocol='ncacn_ip_tcp')


@pytest.mark.remote
class EPMTestsSMBTransport(EPMTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class EPMTestsSMBTransport64(EPMTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class EPMTestsTCPTransport(EPMTests, unittest.TestCase):
    string_binding = r"ncacn_ip_tcp:{0.machine}[135]"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class EPMTestsTCPTransport64(EPMTests, unittest.TestCase):
    string_binding = r"ncacn_ip_tcp:{0.machine}[135]"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
