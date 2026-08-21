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


class TestBootpWithoutOptions(unittest.TestCase):
    def test_plain_bootp_no_options(self):
        """A plain BOOTP packet with only the 236-byte fixed header and no
        vendor-specific/DHCP options area must decode without raising
        struct.error (issue #1900)."""
        packet = b'\x01\x01\x01\x00' + b'\x00' * 232
        self.assertEqual(len(packet), 236)
        decoded = ImpactDecoder.BootpDecoder().decode(packet)
        self.assertIsInstance(decoded, dhcp.BootpPacket)
        # No DHCP child protocol should be attached when there is no cookie.
        self.assertIsNone(decoded.child())

    def test_bootp_with_dhcp_options_still_decodes(self):
        """A BOOTP packet followed by the DHCP magic cookie and a message-type
        option must still be recognised as DHCP."""
        packet = (b'\x01\x01\x01\x00' + b'\x00' * 232 +
                  b'\x63\x82\x53\x63' +  # DHCP magic cookie
                  b'\x35\x01\x01')       # option 53 (message-type) = DHCPDISCOVER
        decoded = ImpactDecoder.BootpDecoder().decode(packet)
        self.assertIsInstance(decoded, dhcp.BootpPacket)
        self.assertIsInstance(decoded.child(), dhcp.DhcpPacket)


if __name__ == '__main__':
    unittest.main()
