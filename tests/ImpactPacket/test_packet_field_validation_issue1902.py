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

from impacket import ImpactDecoder, dhcp
from impacket.ImpactPacket import ImpactPacketException, TCP
from impacket.IP6 import IP6


class TestPacketFieldValidation(unittest.TestCase):

    @staticmethod
    def _ipv6_header(version=6):
        data = bytearray(IP6.HEADER_SIZE)
        data[0] = version << 4
        data[6] = 59
        return bytes(data)

    @staticmethod
    def _bootp_packet(op=1, htype=1, hlen=6):
        data = bytearray(300)
        data[0] = op
        data[1] = htype
        data[2] = hlen
        return bytes(data)

    @staticmethod
    def _tcp_header(data_offset=5, reserved=0, size=20):
        data = bytearray(size)
        if size > 12:
            data[12] = data_offset << 4 | reserved
        return bytes(data)

    def test_ipv6_decoder_rejects_truncated_header(self):
        for size in (0, IP6.HEADER_SIZE - 1):
            with self.subTest(size=size), self.assertRaisesRegex(
                ImpactPacketException,
                'IPv6 header is truncated',
            ):
                ImpactDecoder.IP6Decoder().decode(
                    self._ipv6_header()[:size]
                )

    def test_ipv6_decoder_rejects_wrong_version(self):
        data = self._ipv6_header(version=5)

        with self.assertRaisesRegex(
            ImpactPacketException,
            'IPv6 version must be 6',
        ):
            ImpactDecoder.IP6Decoder().decode(data)

    def test_ipv6_decoder_accepts_valid_fixed_header(self):
        decoded = ImpactDecoder.IP6Decoder().decode(self._ipv6_header())

        self.assertEqual(decoded.get_ip_v(), 6)

    def test_bootp_decoder_rejects_invalid_operation(self):
        for op in (0, 3):
            with self.subTest(op=op), self.assertRaisesRegex(
                ImpactPacketException,
                'BOOTP op must be 1 or 2',
            ):
                ImpactDecoder.BootpDecoder().decode(
                    self._bootp_packet(op=op)
                )

    def test_bootp_decoder_rejects_zero_hardware_type(self):
        with self.assertRaisesRegex(
            ImpactPacketException,
            'BOOTP hardware type must be positive',
        ):
            ImpactDecoder.BootpDecoder().decode(
                self._bootp_packet(htype=0)
            )

    def test_bootp_decoder_rejects_invalid_hardware_address_length(self):
        for hlen in (0, 17):
            with self.subTest(hlen=hlen), self.assertRaisesRegex(
                ImpactPacketException,
                'BOOTP hardware address length must be between 1 and 16',
            ):
                ImpactDecoder.BootpDecoder().decode(
                    self._bootp_packet(hlen=hlen)
                )

    def test_bootp_decoder_accepts_valid_fixed_fields(self):
        for op in (1, 2):
            with self.subTest(op=op):
                decoded = ImpactDecoder.BootpDecoder().decode(
                    self._bootp_packet(op=op)
                )

                self.assertIsInstance(decoded, dhcp.BootpPacket)

    def test_tcp_decoder_rejects_truncated_fixed_header(self):
        for size in (0, 19):
            with self.subTest(size=size), self.assertRaisesRegex(
                ImpactPacketException,
                'TCP header is truncated',
            ):
                ImpactDecoder.TCPDecoder().decode(
                    self._tcp_header(size=size)
                )

    def test_tcp_decoder_rejects_data_offset_below_minimum(self):
        with self.assertRaisesRegex(
            ImpactPacketException,
            'TCP data offset must be at least 5',
        ):
            ImpactDecoder.TCPDecoder().decode(
                self._tcp_header(data_offset=4)
            )

    def test_tcp_decoder_rejects_header_length_past_input(self):
        with self.assertRaisesRegex(
            ImpactPacketException,
            'TCP header length exceeds available data',
        ):
            ImpactDecoder.TCPDecoder().decode(
                self._tcp_header(data_offset=6)
            )

    def test_tcp_decoder_rejects_reserved_bits(self):
        with self.assertRaisesRegex(
            ImpactPacketException,
            'TCP reserved bits must be zero',
        ):
            ImpactDecoder.TCPDecoder().decode(
                self._tcp_header(reserved=1)
            )

    def test_tcp_decoder_rejects_option_without_length_byte(self):
        data = bytearray(self._tcp_header(data_offset=6, size=24))
        data[20:] = b'\x01\x01\x01\x02'

        with self.assertRaisesRegex(
            ImpactPacketException,
            'TCP option is missing its length byte',
        ):
            ImpactDecoder.TCPDecoder().decode(bytes(data))

    def test_tcp_decoder_accepts_valid_fixed_header(self):
        decoded = ImpactDecoder.TCPDecoder().decode(self._tcp_header())

        self.assertIsInstance(decoded, TCP)

    def test_tcp_decoder_uses_declared_header_length_for_payload(self):
        data = bytearray(self._tcp_header(data_offset=7, size=28))
        data.extend(b'payload')

        decoded = ImpactDecoder.TCPDecoder().decode(bytes(data))

        self.assertEqual(decoded.child().get_packet(), b'payload')


if __name__ == '__main__':
    unittest.main()
