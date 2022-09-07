#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import six
import unittest
from binascii import hexlify
from impacket.IP6_Address import IP6_Address


def hexl(b):
    return hexlify(b).decode('ascii')


class IP6AddressTests(unittest.TestCase):
    def test_bin(self):
        tests = (("A:B:C:D:E:F:1:2", '000a000b000c000d000e000f00010002',
                  "A:B:C:D:E:F:1:2"),
                 ("A:B:0:D:E:F:0:2", '000a000b0000000d000e000f00000002',
                  "A:B::D:E:F:0:2"),
                 ("A::BC:E:D", '000a000000000000000000bc000e000d',
                  "A::BC:E:D"),
                 ("A::BCD:EFFF:D", '000a00000000000000000bcdefff000d',
                  "A::BCD:EFFF:D"),
                 ("FE80:0000:0000:0000:020C:29FF:FE26:E251",
                  'fe80000000000000020c29fffe26e251',
                  "FE80::20C:29FF:FE26:E251"),
                 ("::", '00000000000000000000000000000000',
                  "::"),
                 ("1::", '00010000000000000000000000000000',
                  "1::"),
                 ("::2", '00000000000000000000000000000002',
                  "::2"),
                 )
        #    print IP6_Address("A::BC:E:D").as_string(False)
        for torig, thex, texp in tests:
            ip = IP6_Address(torig)
            byt = ip.as_bytes()
            self.assertEqual(hexl(byt), thex)
            self.assertEqual(ip.as_string(), texp)

    def test_malformed(self):
        with six.assertRaisesRegex(self, Exception, r'address size'):
            IP6_Address("ABCD:EFAB:1234:1234:1234:1234:1234:12345")
        with six.assertRaisesRegex(self, Exception, r'triple colon'):
            IP6_Address(":::")
        with six.assertRaisesRegex(self, Exception, r'triple colon'):
            IP6_Address("::::")
        # Could also test other invalid inputs
        # IP6_Address("AB:CD:EF")
        # IP6_Address("12::34::56")
        # IP6_Address("00BCDE::")
        # IP6_Address("DEFG::")
        # and how about these...
        # IP6_Address("A::0XBC:D")
        # IP6_Address("B:-123::")
        # IP6_Address("B:56  ::-0xE")


if __name__ == '__main__':
    unittest.main(verbosity=1)
