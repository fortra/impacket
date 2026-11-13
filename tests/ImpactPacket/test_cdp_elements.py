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

from impacket.ImpactPacket import ImpactPacketException
from impacket.cdp import CDP


def build_cdp(elements):
    return bytes([2, 180, 0, 0]) + elements


class TestCDPElements(unittest.TestCase):
    """CDP element parsing must work at all and reject malformed element lengths."""

    def test_parses_well_formed_device_id(self):
        # version=2, ttl=180, checksum=0; element: type=1 (DeviceID), len=7, data 'SW1'
        c = CDP(build_cdp(bytes([0, 1, 0, 7]) + b'SW1'))
        self.assertEqual(len(c.getElements()), 1)

    def test_parses_multiple_elements(self):
        elements = bytes([0, 1, 0, 7]) + b'SW1' + bytes([0, 3, 0, 8]) + b'Eth0'
        c = CDP(build_cdp(elements))
        self.assertEqual(len(c.getElements()), 2)

    def test_parses_unknown_element_type(self):
        c = CDP(build_cdp(bytes([0, 0x7f, 0, 6]) + b'XY'))
        self.assertEqual(len(c.getElements()), 1)

    def test_zero_length_element_rejected(self):
        # element length 0 would loop forever (buffer never advances)
        with self.assertRaises(ImpactPacketException):
            CDP(build_cdp(bytes([0, 1, 0, 0]) + b'JUNK'))

    def test_sub_header_length_element_rejected(self):
        with self.assertRaises(ImpactPacketException):
            CDP(build_cdp(bytes([0, 1, 0, 2])))


if __name__ == '__main__':
    unittest.main(verbosity=1)
