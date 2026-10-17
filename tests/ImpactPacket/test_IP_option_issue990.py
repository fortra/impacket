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
from threading import Thread
from impacket import ImpactDecoder
from impacket.ImpactPacket import IP, ImpactPacketException


# IPv4 header with IHL=6 and a Record Route option whose length octet is zero
MALFORMED_IP = bytes.fromhex('4600001800000000ff0000000a0000010a00000207000000')

# ICMP destination unreachable carrying the malformed header above
MALFORMED_ICMP = bytes.fromhex('0301000000000000') + MALFORMED_IP


class TestIPOptionIssue990(unittest.TestCase):
    """Decoding an IP option with a length below 2 used to loop forever."""

    def decode_with_timeout(self, decode, data):
        errors = []

        def run():
            try:
                decode(data)
            except Exception as e:
                errors.append(e)

        thread = Thread(target=run)
        thread.daemon = True
        thread.start()
        thread.join(1.0)  # 1 second timeout
        self.assertFalse(thread.is_alive(), 'decoding did not finish')
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ImpactPacketException)
        self.assertEqual(str(errors[0]), "'IP Option length is too low'")

    def test_ip_option_length_zero(self):
        self.decode_with_timeout(IP, MALFORMED_IP)

    def test_icmp_unreachable_with_malformed_ip_option(self):
        self.decode_with_timeout(ImpactDecoder.ICMPDecoder().decode, MALFORMED_ICMP)


if __name__ == '__main__':
    unittest.main(verbosity=1)
