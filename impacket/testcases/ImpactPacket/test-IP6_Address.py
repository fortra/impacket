#!/usr/bin/env python

import sys
sys.path.insert(0,"../..")

import IP6_Address
import unittest

class TestIP6_Address(unittest.TestCase):
        
    def test_construction(self):
        '''Test IP6 Address construction'''
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

        self.assert_(IP6_Address.IP6_Address(normal_text_address), "IP6 address construction with normal text address failed")
        self.assert_(IP6_Address.IP6_Address(normal_binary_address), "IP6 address construction with normal binary address failed")
        
        self.assertRaises(Exception, IP6_Address.IP6_Address, oversized_text_address)#, "IP6 address construction with oversized text address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, oversized_binary_address)#, "IP6 address construction with oversized binary address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, subsized_text_address)#, "IP6 address construction with subsized text address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, subsized_binary_address)#, "IP6 address construction with subsized binary address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, malformed_text_address_1)#, "IP6 address construction with malformed text address (#1) incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, malformed_text_address_2)#, "IP6 address construction with malformed text address (#2) incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, malformed_text_address_3)#, "IP6 address construction with malformed text address (#3) incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, empty_text_address)#, "IP6 address construction with empty text address incorrectly succeeded")
        self.assertRaises(Exception, IP6_Address.IP6_Address, empty_binary_address)#, "IP6 address construction with empty binary address incorrectly succeeded")
        

        
    def test_conversions(self):
        '''Test IP6 Address conversions.'''
        text_address = "FE80:1234:5678:ABCD:EF01:2345:6789:ABCD"
        binary_address = [0xFE, 0x80, 0x12, 0x34,
                          0x56, 0x78, 0xAB, 0xCD, 
                          0xEF, 0x01, 0x23, 0x45,
                          0x67, 0x89, 0xAB, 0xCD]
        self.assert_(IP6_Address.IP6_Address(text_address).as_string() == text_address, "IP6 address conversion text -> text failed")
        self.assert_(IP6_Address.IP6_Address(binary_address).as_bytes() == binary_address, "IP6 address conversion binary -> binary failed")
        self.assert_(IP6_Address.IP6_Address(binary_address).as_string() == text_address, "IP6 address conversion binary -> text failed")
        self.assert_(IP6_Address.IP6_Address(text_address).as_bytes().tolist() == binary_address, "IP6 address conversion text -> binary failed")
        
    def test_compressions(self):
        '''Test IP6 Address compressions.'''
        compressed_addresses = [ "::",
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
            self.assert_(IP6_Address.IP6_Address(f).as_string() == c, "IP6 address compression failed with full address: " + f)
            self.assert_(IP6_Address.IP6_Address(c).as_string(False) == f, "IP6 address compression failed with compressed address:" + c)



suite = unittest.TestLoader().loadTestsFromTestCase(TestIP6_Address)
unittest.TextTestRunner(verbosity=2).run(suite)
