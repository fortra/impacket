#!/usr/bin/env python
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
import struct
import unittest

from impacket.dhcp import DhcpPacket


def build_packet(options):
    return struct.pack('!L', DhcpPacket.MAGIC_NUMBER) + options


class TestDhcpParameterRequestList(unittest.TestCase):
    """parameter-request-list helpers must work on Python 3 (bytes yield ints).

    Option 55 is present in virtually every real DHCP request. Both
    isAskingForProxyAutodiscovery() and unpackParameterRequestList() used
    ord() on the iterated values, raising TypeError on Python 3.
    """

    def test_is_asking_for_proxy_autodiscovery_true(self):
        # message-type=discover, parameter-request-list=[1,3,6,252], eof
        packet = DhcpPacket(build_packet(bytes([53, 1, 1, 55, 4, 1, 3, 6, 252, 255])))
        self.assertTrue(packet.isAskingForProxyAutodiscovery())

    def test_is_asking_for_proxy_autodiscovery_false(self):
        # parameter-request-list without 252
        packet = DhcpPacket(build_packet(bytes([53, 1, 1, 55, 3, 1, 3, 6, 255])))
        self.assertFalse(packet.isAskingForProxyAutodiscovery())

    def test_is_asking_for_proxy_autodiscovery_no_prl(self):
        packet = DhcpPacket(build_packet(bytes([53, 1, 1, 255])))
        self.assertFalse(packet.isAskingForProxyAutodiscovery())

    def test_unpack_parameter_request_list_names(self):
        packet = DhcpPacket(build_packet(bytes([55, 4, 1, 3, 6, 51, 255])))
        names = packet.unpackParameterRequestList(packet.getOptionValue('parameter-request-list'))
        self.assertEqual(names, ['subnet-mask', 'router', 'domain-name-server', 'lease-time'])

    def test_unpack_parameter_request_list_unknown_code(self):
        packet = DhcpPacket(build_packet(bytes([55, 2, 99, 222, 255])))
        names = packet.unpackParameterRequestList(packet.getOptionValue('parameter-request-list'))
        self.assertEqual(names, [99, 222])


if __name__ == '__main__':
    unittest.main(verbosity=1)
