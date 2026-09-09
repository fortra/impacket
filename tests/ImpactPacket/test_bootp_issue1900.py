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
from impacket import ImpactDecoder
from impacket import dhcp


class TestBootpTruncated(unittest.TestCase):
    """Best-effort decoding of truncated BOOTP messages.

    RFC 1542 section 2.1 requires a BOOTP message to be at least 300 octets (the
    236-byte fixed header of RFC 951 plus its 64-byte vend field) and says that
    shorter messages MUST be discarded. Rather than discarding them, the decoder
    deliberately decodes what is present and warns, instead of raising
    struct.error. These are truncated messages, not RFC-valid plain BOOTP.
    """

    def test_incomplete_fixed_header_is_zero_padded(self):
        """The 235-byte message reported in issue #1900 stops one byte inside the
        128-byte 'file' field, so BootpPacket() used to raise struct.error. It
        must now be zero-padded and decoded best-effort, with a warning."""
        packet = b'\x01\x01\x01\x00' + b'\x00' * 231
        self.assertEqual(len(packet), 235)
        with self.assertLogs('impacket', level='WARNING') as logs:
            decoded = ImpactDecoder.BootpDecoder().decode(packet)
        self.assertTrue(any('zero-padding' in message for message in logs.output))
        self.assertIsInstance(decoded, dhcp.BootpPacket)
        # The fields that did arrive are decoded normally.
        self.assertEqual(decoded['op'], 1)
        self.assertEqual(decoded['htype'], 1)
        self.assertEqual(decoded['hlen'], 1)
        self.assertIsNone(decoded.child())

    def test_fixed_header_only_without_cookie(self):
        """A 236-byte message holds the complete fixed header but carries no
        vend/DHCP options area, so there is no magic cookie to read. It must
        decode without raising struct.error, and warn that it is undersized."""
        packet = b'\x01\x01\x01\x00' + b'\x00' * 232
        self.assertEqual(len(packet), 236)
        with self.assertLogs('impacket', level='WARNING') as logs:
            decoded = ImpactDecoder.BootpDecoder().decode(packet)
        self.assertTrue(any('RFC 1542' in message for message in logs.output))
        self.assertIsInstance(decoded, dhcp.BootpPacket)
        # No DHCP child protocol should be attached when there is no cookie.
        self.assertIsNone(decoded.child())

    def test_full_length_bootp_with_dhcp_options_still_decodes(self):
        """A conformant, full-length (300 octet) BOOTP message carrying the DHCP
        magic cookie and a message-type option must still be recognised as
        DHCP."""
        payload = b'\x01\x01\x01\x00' + b'\x00' * 232
        payload += b'\x63\x82\x53\x63'  # DHCP magic cookie
        payload += b'\x35\x01\x01'  # option 53 (message-type) = DHCPDISCOVER
        packet = payload + b'\x00' * (300 - len(payload))  # pad to the RFC 1542 minimum
        self.assertEqual(len(packet), 300)
        decoded = ImpactDecoder.BootpDecoder().decode(packet)
        self.assertIsInstance(decoded, dhcp.BootpPacket)
        self.assertIsInstance(decoded.child(), dhcp.DhcpPacket)


if __name__ == '__main__':
    unittest.main()
