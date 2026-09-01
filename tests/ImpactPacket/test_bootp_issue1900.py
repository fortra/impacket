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
    def test_truncated_bootp_without_cookie(self):
        """A truncated BOOTP message carrying only the 236-byte fixed header is
        shorter than the 300-octet minimum of RFC 1542 section 2.1 and has no
        vend/DHCP options area at all. Decoding it is deliberate best-effort
        behaviour: the fixed fields are returned instead of raising
        struct.error, and a warning reports the undersized message (issue
        #1900)."""
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
