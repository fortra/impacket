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
from unittest import mock

from impacket import ImpactDecoder
from impacket import dhcp

# 236-byte BOOTP fixed header (op=BOOTREQUEST, htype=Ethernet, hlen=6) followed by the DHCP magic cookie
BOOTP_HEADER = (b'\x01\x01\x06\x00' + b'\x39\x03\xf3\x26' + b'\x00\x00\x80\x00' + b'\x00' * 16 +
                b'\x00\x26\x9e\x04\x0a\x5b' + b'\x00' * 10 + b'\x00' * 64 + b'\x00' * 128)
COOKIE = b'\x63\x82\x53\x63'


def dhcp_packet(options):
    return dhcp.DhcpPacket(COOKIE + options)


class TestDhcpOptions(unittest.TestCase):
    """DHCP options parsing (RFC 2132), see issue #1901.

    Malformed options used to raise struct.error and abort decoding the whole
    packet, and the single-octet pad and end options were read as if they had a
    length octet. Malformed options are now kept as raw bytes, with a warning.
    """

    def test_issue_1901_packet_decodes(self):
        """The packet reported in issue #1901 ends with a truncated subnet-mask
        option (code 1, length 6, no data), which used to raise struct.error."""
        options = (b'\x35\x01\x01'                  # message-type: DHCPDISCOVER
                   b'\x32\x04\xc0\xa8\x01\x64'      # requested-ip: 192.168.1.100
                   b'\x33\x04\x01\xa8\x01\x64'      # lease-time
                   b'\x37\x01\x03'                  # parameter-request-list: router
                   b'\x01\x06')                     # subnet-mask, truncated
        with self.assertLogs('impacket', level='WARNING') as logs:
            decoded = ImpactDecoder.BootpDecoder().decode(BOOTP_HEADER + COOKIE + options)
        # Reported once: the decoder must not parse the options a second time to find the cookie.
        self.assertEqual(sum('declares 6 bytes but only 0 are present' in message for message in logs.output), 1)
        packet = decoded.child()
        self.assertIsInstance(packet, dhcp.DhcpPacket)
        self.assertEqual(packet.getOptionValue('message-type'), dhcp.DhcpPacket.DHCPDISCOVER)
        self.assertEqual(packet.getOptionValue('requested-ip'), 0xc0a80164)
        self.assertEqual(packet.getOptionValue('parameter-request-list'), b'\x03')
        self.assertEqual(packet.getOptionValue('subnet-mask'), b'')

    def test_invalid_length_for_type_keeps_raw_bytes(self):
        """A subnet-mask option carrying 6 bytes instead of 4 is kept as raw bytes,
        and the options after it are still decoded."""
        options = b'\x01\x06\xff\xff\xff\x00\x00\x00' + b'\x35\x01\x01' + b'\xff'
        with self.assertLogs('impacket', level='WARNING') as logs:
            packet = dhcp_packet(options)
        self.assertTrue(any('invalid for its type' in message for message in logs.output))
        self.assertEqual(packet.getOptionValue('subnet-mask'), b'\xff\xff\xff\x00\x00\x00')
        self.assertEqual(packet.getOptionValue('message-type'), dhcp.DhcpPacket.DHCPDISCOVER)

    def test_invalid_length_for_list_type_keeps_raw_bytes(self):
        """A router option (a list of 4-byte addresses) whose length is not a
        multiple of 4 is kept as raw bytes."""
        options = b'\x03\x06\xc0\xa8\x01\x01\xc0\xa8' + b'\xff'
        with self.assertLogs('impacket', level='WARNING'):
            packet = dhcp_packet(options)
        self.assertEqual(packet.getOptionValue('router'), b'\xc0\xa8\x01\x01\xc0\xa8')

    def test_missing_length_octet(self):
        """An option code at the very end of the buffer, without its length octet."""
        with self.assertLogs('impacket', level='WARNING') as logs:
            packet = dhcp_packet(b'\x35\x01\x01' + b'\x33')
        self.assertTrue(any('length octet is missing' in message for message in logs.output))
        self.assertEqual(packet['options'], [('message-type', dhcp.DhcpPacket.DHCPDISCOVER)])

    def test_pad_option_is_a_single_octet(self):
        """RFC 2132 section 3.1: the pad option has no length octet. A single pad
        before an option used to swallow that option."""
        with mock.patch.object(dhcp.LOG, 'warning') as warning:
            packet = dhcp_packet(b'\x00' + b'\x35\x01\x01' + b'\x00\x00\x00' + b'\x33\x04\x00\x00\x0e\x10' + b'\xff')
        warning.assert_not_called()
        self.assertEqual(packet['options'], [('message-type', dhcp.DhcpPacket.DHCPDISCOVER),
                                             ('lease-time', 3600),
                                             ('eof', None)])

    def test_nothing_is_parsed_after_end_option(self):
        """RFC 2132 section 3.2: the end option marks the end of valid information,
        so the padding or garbage after it is not decoded as options."""
        with mock.patch.object(dhcp.LOG, 'warning') as warning:
            packet = dhcp_packet(b'\x35\x01\x01' + b'\xff' + b'\x35\x01\x02' + b'\x01')
        warning.assert_not_called()
        self.assertEqual(packet['options'], [('message-type', dhcp.DhcpPacket.DHCPDISCOVER), ('eof', None)])

    def test_well_formed_options(self):
        """Well-formed options decode as before, without warnings."""
        options = (b'\x35\x01\x01'                  # message-type: DHCPDISCOVER
                   b'\x3d\x07\x01\x00\x26\x9e\x04\x0a\x5b'  # client-id
                   b'\x37\x03\x01\x03\x06'          # parameter-request-list
                   b'\x06\x08\x08\x08\x08\x08\x08\x08\x04\x04'  # domain-name-server: 8.8.8.8, 8.8.4.4
                   b'\xff' + b'\x00' * 4)           # end, then padding
        with mock.patch.object(dhcp.LOG, 'warning') as warning:
            packet = dhcp_packet(options)
        warning.assert_not_called()
        self.assertEqual(packet['options'], [('message-type', dhcp.DhcpPacket.DHCPDISCOVER),
                                             ('client-id', b'\x01\x00\x26\x9e\x04\x0a\x5b'),
                                             ('parameter-request-list', b'\x01\x03\x06'),
                                             ('domain-name-server', [0x08080808, 0x08080404]),
                                             ('eof', None)])


if __name__ == '__main__':
    unittest.main()
