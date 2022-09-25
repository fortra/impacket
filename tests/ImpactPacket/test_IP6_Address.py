#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from impacket import IP6_Address


class TestIP6_Address(unittest.TestCase):

    def runTest(self):
        pass

    def test_construction(self):
        """Test IP6 Address construction"""
        normal_text_address = "FE80:1234:5678:ABCD:EF01:2345:6789:ABCD"
        normal_binary_address = [0xFE, 0x80, 0x12, 0x34,
                                 0x56, 0x78, 0xAB, 0xCD,
                                 0xEF, 0x01, 0x23, 0x45,
                                 0x67, 0x89, 0xAB, 0xCD]

        oversized_text_address = "FE80:1234:5678:ABCD:EF01:2345:6789:ABCD:1234"
        oversized_binary_address = [0xFE, 0x80, 0x12, 0x34,
                                    0x56, 0x78, 0xAB, 0xCD,
                                    0xEF, 0x01, 0x23, 0x45,
                                    0x67, 0x89, 0xAB, 0xCD, 0x00]

        subsized_text_address = "FE80:1234:5678:ABCD:EF01:2345:6789"
        subsized_binary_address = [0xFE, 0x80, 0x12, 0x34,
                                   0x56, 0x78, 0xAB, 0xCD,
                                   0xEF, 0x01, 0x23, 0x45,
                                   0x67, 0x89, 0xAB]

        malformed_text_address_1 = "FE80:123456788:ABCD:EF01:2345:6789:ABCD"
        malformed_text_address_2 = "ZXYW:1234:5678:ABCD:EF01:2345:6789:ABCD"
        malformed_text_address_3 = "FFFFFF:1234:5678:ABCD:EF01:2345:67:ABCD"
        empty_text_address = ""
        empty_binary_address = []

        self.assertTrue(IP6_Address.IP6_Address(normal_text_address),
                        "IP6 address construction with normal text address failed")
        self.assertTrue(IP6_Address.IP6_Address(normal_binary_address),
                        "IP6 address construction with normal binary address failed")

        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          oversized_text_address)  # , "IP6 address construction with oversized text address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          oversized_binary_address)  # , "IP6 address construction with oversized binary address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          subsized_text_address)  # , "IP6 address construction with subsized text address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          subsized_binary_address)  # , "IP6 address construction with subsized binary address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          malformed_text_address_1)  # , "IP6 address construction with malformed text address (#1) incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          malformed_text_address_2)  # , "IP6 address construction with malformed text address (#2) incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          malformed_text_address_3)  # , "IP6 address construction with malformed text address (#3) incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          empty_text_address)  # , "IP6 address construction with empty text address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address,
                          empty_binary_address)  # , "IP6 address construction with empty binary address incorrectly succeeded")

    def test_unicode_representation(self):
        """Test IP6 Unicode text representations"""
        unicode_normal_text_address = u'FE80:1234:5678:ABCD:EF01:2345:6789:ABCD'

        self.assertTrue(IP6_Address.IP6_Address(unicode_normal_text_address),
                        "IP6 address construction with UNICODE normal text address failed")

    def test_conversions(self):
        """Test IP6 Address conversions."""
        text_address = "FE80:1234:5678:ABCD:EF01:2345:6789:ABCD"
        binary_address = [0xFE, 0x80, 0x12, 0x34,
                          0x56, 0x78, 0xAB, 0xCD,
                          0xEF, 0x01, 0x23, 0x45,
                          0x67, 0x89, 0xAB, 0xCD]
        self.assertEqual(IP6_Address.IP6_Address(text_address).as_string(), text_address,
                         "IP6 address conversion text -> text failed")
        self.assertEqual(IP6_Address.IP6_Address(binary_address).as_bytes(), binary_address,
                         "IP6 address conversion binary -> binary failed")
        self.assertEqual(IP6_Address.IP6_Address(binary_address).as_string(), text_address,
                         "IP6 address conversion binary -> text failed")
        self.assertEqual(IP6_Address.IP6_Address(text_address).as_bytes().tolist(), binary_address,
                         "IP6 address conversion text -> binary failed")

    def test_compressions(self):
        """Test IP6 Address compressions."""
        compressed_addresses = ["::",
                                "1::",
                                "::1",
                                "1::2",
                                "1::1:2:3",
                                "FE80:234:567:4::1"
                                ]
        full_addresses = ["0000:0000:0000:0000:0000:0000:0000:0000",
                          "0001:0000:0000:0000:0000:0000:0000:0000",
                          "0000:0000:0000:0000:0000:0000:0000:0001",
                          "0001:0000:0000:0000:0000:0000:0000:0002",
                          "0001:0000:0000:0000:0000:0001:0002:0003",
                          "FE80:0234:0567:0004:0000:0000:0000:0001"
                          ]

        for f, c in zip(full_addresses, compressed_addresses):
            self.assertEqual(IP6_Address.IP6_Address(f).as_string(), c,
                             "IP6 address compression failed with full address: " + f)
            self.assertEqual(IP6_Address.IP6_Address(c).as_string(False), f,
                             "IP6 address compression failed with compressed address:" + c)

    def test_scoped_addresses(self):
        """Test scoped addresses."""
        numeric_scoped_address = "FE80::1234:1%12"
        self.assertEqual(IP6_Address.IP6_Address(numeric_scoped_address).as_string(), numeric_scoped_address,
                         "Numeric scoped address conversion failed on address: " + numeric_scoped_address)
        self.assertEqual(IP6_Address.IP6_Address(numeric_scoped_address).get_scope_id(), "12",
                         "Numeric scope ID fetch failed on address: " + numeric_scoped_address)
        self.assertEqual(IP6_Address.IP6_Address(numeric_scoped_address).get_unscoped_address(), "FE80::1234:1",
                         "Get unscoped address failed on address: " + numeric_scoped_address)

        unscoped_address = "1::4:1"
        self.assertEqual(IP6_Address.IP6_Address(unscoped_address).as_string(), unscoped_address,
                         "Unscoped address conversion failed on address: " + unscoped_address)
        self.assertEqual(IP6_Address.IP6_Address(unscoped_address).get_scope_id(), "",
                         "Unscoped address scope ID fetch failed on address: " + unscoped_address)
        self.assertEqual(IP6_Address.IP6_Address(unscoped_address).get_unscoped_address(), unscoped_address,
                         "Get unscoped address failed on address: " + unscoped_address)

        text_scoped_address = "FE80::1234:1%BLAH"
        self.assertEqual(IP6_Address.IP6_Address(text_scoped_address).as_string(), text_scoped_address,
                         "Text scoped address conversion failed on address: " + text_scoped_address)
        self.assertEqual(IP6_Address.IP6_Address(text_scoped_address).get_scope_id(), "BLAH",
                         "Text scope ID fetch failed on address: " + text_scoped_address)
        self.assertEqual(IP6_Address.IP6_Address(text_scoped_address).get_unscoped_address(), "FE80::1234:1",
                         "Get unscoped address failed on address: " + text_scoped_address)

        empty_scoped_address = "FE80::1234:1%"
        self.assertRaises(Exception, IP6_Address.IP6_Address, empty_scoped_address)


if __name__ == '__main__':
    unittest.main(verbosity=1)
