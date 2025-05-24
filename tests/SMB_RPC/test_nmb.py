# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import pytest
import unittest
from binascii import unhexlify
from tests import RemoteTestCase

from impacket import nmb


@pytest.mark.remote
class NMBTests(RemoteTestCase, unittest.TestCase):

    def setUp(self):
        super(NMBTests, self).setUp()
        self.set_transport_config()

    def create_connection(self):
        pass

    def test_encodedecodename(self):
        name = 'THISISAVERYLONGLONGNAME'
        encoded = nmb.encode_name(name, nmb.TYPE_SERVER, None)
        decoded = nmb.decode_name(encoded)

        self.assertEqual(name[:15], decoded[1].strip())


    def test_getnetbiosname(self):
        # Arrange
        name = 'WIN-VB75FK4K1S0'
        mock = unhexlify('f97384000000000100000000204648454a454f434e46474543444844464547454c4445454c444246444441414100002100010000000000650357494e2d56423735464b344b31533000040057494e2d56423735464b344b315330200400574f524b47524f555020202020202000840000155d01230800000000000000000000000000000000000000000000000000000000000000000000000000000000')
        def send_hook(request, destaddr, timeout):
            return nmb.NAME_SERVICE_PACKET(mock)
        n = nmb.NetBIOS()
        n.send = send_hook

        res = n.getnetbiosname(self.machine) # Act

        self.assertEqual(name, res) # Assert

    def test_getnodestatus(self):
        # Arrange
        name1 = b'WIN-VB75FK4K1S0'
        name2 = b'WIN-VB75FK4K1S0'
        name3 = b'WORKGROUP      '
        mock = unhexlify('f97384000000000100000000204648454a454f434e46474543444844464547454c4445454c444246444441414100002100010000000000650357494e2d56423735464b344b31533000040057494e2d56423735464b344b315330200400574f524b47524f555020202020202000840000155d01230800000000000000000000000000000000000000000000000000000000000000000000000000000000')
        def send_hook(request, destaddr, timeout):
            return nmb.NAME_SERVICE_PACKET(mock)
        n = nmb.NetBIOS()
        n.send = send_hook

        resp = n.getnodestatus(self.serverName.upper(), self.machine) # Act

        # Assert
        self.assertEqual(resp[0]['NAME'], name1)
        self.assertEqual(resp[1]['NAME'], name2)
        self.assertEqual(resp[2]['NAME'], name3)

    def test_gethostbyname(self):
        # Arrange
        addr = '10.0.1.1'
        name = 'WIN-VB75FK4K1S0'
        mock = unhexlify('f97485000000000100000000204648454a454f434e46474543444844464547454c4445454c44424644444141410000200001000493e0000600000a000101')
        def send_hook(request, destaddr, timeout):
            return nmb.NAME_SERVICE_PACKET(mock)
        n = nmb.NetBIOS()
        n.send = send_hook
        n.set_nameserver(name)

        resp = n.gethostbyname(name, nmb.TYPE_SERVER) # Act

        self.assertEqual(addr, str(resp.entries[0])) # Assert

    def test_name_query_request(self):
        # Arrange
        name = "WIN-VB75FK4K1S0"
        addr = "10.0.1.1"
        mock = unhexlify('f97485000000000100000000204648454a454f434e46474543444844464547454c4445454c44424644444141410000200001000493e0000600000a000101')
        def send_hook(request, destaddr, timeout):
            return nmb.NAME_SERVICE_PACKET(mock)
        n = nmb.NetBIOS()
        n.send = send_hook

        resp = n.name_query_request(name, addr) # Act

        self.assertEqual(addr, str(resp.entries[0])) # Assert

    def test_name_registration_request(self):
        n = nmb.NetBIOS()
        try:
            resp = n.name_registration_request('*JSMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None, nmb.NB_FLAGS_ONT_P, '1.1.1.2')
            resp.dump()
        except Exception as e:
            print(str(e))
            if str(e).find('NETBIOS') <= 0:
                raise e


if __name__ == "__main__":
    unittest.main(verbosity=1)
