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
import array
import unittest

from impacket.ImpactPacket import IP, IPOption


class TestIP(unittest.TestCase):

    def test_get_packet_with_options_is_repeatable(self):
        # Issue #504: get_packet() must not append the options to the
        # header buffer, or every call adds them again.
        ip = IP()
        ip.set_ip_src('10.0.0.1')
        ip.set_ip_dst('10.0.0.2')
        ip.add_option(IPOption(IPOption.IPOPT_NOP))
        first = ip.get_packet()
        second = ip.get_packet()
        self.assertEqual(first, second)
        self.assertEqual(len(second), 24)
        self.assertEqual(ip.get_ip_hl(), 6)
        self.assertEqual(ip.get_header_size(), 24)
        self.assertEqual(ip.compute_checksum(array.array('B', second)), 0)

    def test_get_packet_of_decoded_options_is_repeatable(self):
        raw = bytes.fromhex('4600001800000000ff00a5e30a0000010a00000201000000')
        ip = IP(raw)
        self.assertEqual(ip.get_packet(), raw)
        self.assertEqual(ip.get_packet(), raw)

    def test_fragment_by_size_without_payload(self):
        ip = IP()
        fragments = ip.fragment_by_size(8)
        self.assertEqual(fragments, [ip])

    def test_dscp_and_ecn_defaults(self):
        ip = IP()
        self.assertEqual(ip.get_ip_dscp(), 0)
        self.assertEqual(ip.get_ip_ecn(), 0)

    def test_set_dscp_keeps_ecn(self):
        ip = IP()
        ip.set_ip_ecn(3)
        ip.set_ip_dscp(46)  # EF
        self.assertEqual(ip.get_ip_dscp(), 46)
        self.assertEqual(ip.get_ip_ecn(), 3)
        self.assertEqual(ip.get_ip_tos(), (46 << 2) | 3)

    def test_set_ecn_keeps_dscp(self):
        ip = IP()
        ip.set_ip_dscp(46)
        ip.set_ip_ecn(2)
        self.assertEqual(ip.get_ip_dscp(), 46)
        self.assertEqual(ip.get_ip_ecn(), 2)

    def test_dscp_ecn_derived_from_tos(self):
        ip = IP()
        ip.set_ip_tos(0xB9)
        self.assertEqual(ip.get_ip_dscp(), 46)
        self.assertEqual(ip.get_ip_ecn(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=1)
