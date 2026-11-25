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
from impacket.ImpactDecoder import IPDecoder
from impacket.ImpactPacket import Data, TCP, UDP


def ip_header(protocol, payload_len, flags_and_offset):
    # IPv4, IHL=5, total length, id 0x1234, TTL 64, checksum 0, 10.0.0.1 -> 10.0.0.2
    return (bytes.fromhex('4500') + (20 + payload_len).to_bytes(2, 'big') + bytes.fromhex('1234') +
            flags_and_offset.to_bytes(2, 'big') + bytes([64, protocol]) + bytes.fromhex('00000a0000010a000002'))


class TestIPFragmentIssue553(unittest.TestCase):
    """A fragment with a non-zero offset carries no upper-layer header."""

    def test_later_udp_fragment_is_data(self):
        payload = b'\x00' * 8 + b'abcdefgh'
        packet = ip_header(UDP.protocol, len(payload), 0x0003) + payload
        ip = IPDecoder().decode(packet)
        self.assertIsInstance(ip.child(), Data)
        self.assertEqual(ip.get_packet(), packet)

    def test_later_tcp_fragment_is_data(self):
        payload = b'\x00' * 24
        packet = ip_header(TCP.protocol, len(payload), 0x2003) + payload
        ip = IPDecoder().decode(packet)
        self.assertIsInstance(ip.child(), Data)
        self.assertEqual(ip.get_packet(), packet)

    def test_first_udp_fragment_is_udp(self):
        payload = bytes.fromhex('0035003500200000') + b'abcdefgh'
        packet = ip_header(UDP.protocol, len(payload), 0x2000) + payload
        ip = IPDecoder().decode(packet)
        self.assertIsInstance(ip.child(), UDP)
        self.assertEqual(ip.child().get_uh_dport(), 53)


if __name__ == '__main__':
    unittest.main(verbosity=1)
