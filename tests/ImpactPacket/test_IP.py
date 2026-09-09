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
import unittest

from impacket.ImpactPacket import IP


class TestIP(unittest.TestCase):

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
