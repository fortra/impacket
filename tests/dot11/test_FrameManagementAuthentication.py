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
from six import PY2
from impacket.dot11 import Dot11Types
from impacket.ImpactDecoder import RadioTapDecoder


class TestDot11ManagementAuthenticationFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawframe=b"\x00\x00\x1c\x00\xef\x18\x00\x00\x39\x55\x6f\x05\x3c\x00\x00\x00\x10\x02\x85\x09\xa0\x00\xb8\x9d\x60\x00\x00\x1b\xb0\x00\x3a\x01\x00\x18\xf8\x6c\x76\x42\x70\x1a\x04\x54\xe3\x86\x00\x18\xf8\x6c\x76\x42\x30\xc8\x00\x00\x01\x00\x00\x00\xdd\x09\x00\x10\x18\x02\x00\x10\x00\x00\x00\x8a\x64\xe9\x3b"
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawframe)

        if PY2:
            self.assertEqual(str(radiotap.__class__), "impacket.dot11.RadioTap")
        else:
            self.assertEqual(str(radiotap.__class__), "<class 'impacket.dot11.RadioTap'>")

        self.dot11=radiotap.child()
        if PY2:
            self.assertEqual(str(self.dot11.__class__), "impacket.dot11.Dot11")
        else:
            self.assertEqual(str(self.dot11.__class__), "<class 'impacket.dot11.Dot11'>")

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_AUTHENTICATION)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_AUTHENTICATION)
        
        self.management_base=self.dot11.child()
        if PY2:
            self.assertEqual(str(self.management_base.__class__), "impacket.dot11.Dot11ManagementFrame")
        else:
            self.assertEqual(str(self.management_base.__class__), "<class 'impacket.dot11.Dot11ManagementFrame'>")
        
        self.management_authentication=self.management_base.child()
        if PY2:
            self.assertEqual(str(self.management_authentication.__class__), "impacket.dot11.Dot11ManagementAuthentication")
        else:
            self.assertEqual(str(self.management_authentication.__class__), "<class 'impacket.dot11.Dot11ManagementAuthentication'>")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_authentication.get_header_size(), 17)
        self.assertEqual(self.management_authentication.get_tail_size(), 0)
        
    def test_02(self):
        'Test Duration field'
        
        self.assertEqual(self.management_base.get_duration(), 0x013a)
        self.management_base.set_duration(0x1234)
        self.assertEqual(self.management_base.get_duration(), 0x1234)
    
    def test_03(self):
        'Test Destination Address field'
        
        addr=self.management_base.get_destination_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0xF8,0x6C,0x76,0x42])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_destination_address(addr)
        self.assertEqual(self.management_base.get_destination_address().tolist(), [0x12,0x18,0xF8,0x6C,0x76,0x34])

    def test_04(self):
        'Test Source Address field'
        
        addr=self.management_base.get_source_address()
        
        self.assertEqual(addr.tolist(), [0x70,0x1A,0x04,0x54,0xE3,0x86])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x1A,0x04,0x54,0xE3,0x34])

    def test_05(self):
        'Test BSSID Address field'
        
        addr=self.management_base.get_bssid()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0xF8,0x6C,0x76,0x42])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_bssid(addr)
        self.assertEqual(self.management_base.get_bssid().tolist(), [0x12,0x18,0xF8,0x6C,0x76,0x34])

    def test_06(self):
        'Test Sequence control field'
        self.assertEqual(self.management_base.get_sequence_control(), 0xc830)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 3203)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body=b"\x00\x00\x01\x00\x00\x00\xdd\x09\x00\x10\x18\x02\x00\x10\x00\x00\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Frame Authentication Algorithm field' 
        self.assertEqual(self.management_authentication.get_authentication_algorithm(), 0x0000)
        self.management_authentication.set_authentication_algorithm(0x8765)
        self.assertEqual(self.management_authentication.get_authentication_algorithm(), 0x8765)

    def test_11(self):
        'Test Management Frame Authentication Sequence field' 
        self.assertEqual(self.management_authentication.get_authentication_sequence(), 0x0001)
        self.management_authentication.set_authentication_sequence(0x8765)
        self.assertEqual(self.management_authentication.get_authentication_sequence(), 0x8765)

    def test_12(self):
        'Test Management Frame Authentication Status field' 
        self.assertEqual(self.management_authentication.get_authentication_status(), 0x0000)
        self.management_authentication.set_authentication_status(0x8765)
        self.assertEqual(self.management_authentication.get_authentication_status(), 0x8765)

    def test_13(self):
        'Test Management Vendor Specific getter/setter methods'
        self.assertEqual(self.management_authentication.get_vendor_specific(), [(b"\x00\x10\x18",b"\x02\x00\x10\x00\x00\x00")])
        self.management_authentication.add_vendor_specific(b"\x00\x00\x40",b"\x04\x04\x04\x04\x04\x04")

        self.assertEqual(self.management_authentication.get_vendor_specific(), 
            [(b"\x00\x10\x18",b"\x02\x00\x10\x00\x00\x00"),
             (b"\x00\x00\x40",b"\x04\x04\x04\x04\x04\x04"),
            ])
        self.assertEqual(self.management_authentication.get_header_size(), 28)


if __name__ == '__main__':
    unittest.main(verbosity=1)
