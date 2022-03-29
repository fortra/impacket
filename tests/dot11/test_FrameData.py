#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from impacket.dot11 import Dot11, Dot11Types, Dot11DataFrame


class TestDot11DataFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Data Frame 
        #
        self.frame_orig=b'\x08\x01\x30\x00\x00\x08\x54\xac\x2f\x85\x00\x23\x4d\x09\x86\xfe\x00\x08\x54\xac\x2f\x85\x40\x44\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x72\x37\x40\x00\x80\x06\x6c\x22\xc0\xa8\x01\x02\xc3\x7a\x97\x51\xd7\xa0\x00\x50\xa5\xa5\xb1\xe0\x12\x1c\xa9\xe1\x50\x10\x4e\x75\x59\x74\x00\x00\xed\x13\x22\x91'
        
        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_DATA)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_DATA)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_DATA_SUBTYPE_DATA)
            
        self.data = Dot11DataFrame(d.get_body_as_string())
            
        d.contains(self.data)
        
    def test_01_HeaderSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.data.get_header_size(), 22)
        self.assertEqual(self.data.get_tail_size(), 0)
        
    def test_02_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.data.get_duration(), 0x30)
        self.data.set_duration(0x1234)
        self.assertEqual(self.data.get_duration(), 0x1234)
    
    def test_03_Address_1(self):
        'Test Address 1 field'
        
        addr=self.data.get_address1()
        
        self.assertEqual(addr.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        addr[0]=0x12
        addr[5]=0x34
        self.data.set_address1(addr)
        self.assertEqual(self.data.get_address1().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])

    def test_04_Address_2(self):
        'Test Address 2 field'
        
        addr=self.data.get_address2()
        
        self.assertEqual(addr.tolist(), [0x00,0x23,0x4d,0x09,0x86,0xfe])
        addr[0]=0x12
        addr[5]=0x34
        self.data.set_address2(addr)
        self.assertEqual(self.data.get_address2().tolist(), [0x12,0x23,0x4d,0x09,0x86,0x34])

    def test_05_Address_3(self):
        'Test Address 3 field'
        
        addr=self.data.get_address3()
    
        self.assertEqual(addr.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        addr[0]=0x12
        addr[5]=0x34
        self.data.set_address3(addr)
        self.assertEqual(self.data.get_address3().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])
    
    def test_06_sequence_control(self):
        'Test Sequence control field'
        self.assertEqual(self.data.get_sequence_control(), 0x4440)
        self.data.set_sequence_control(0x1234)
        self.assertEqual(self.data.get_sequence_control(), 0x1234)

    def test_07_fragment_number(self):
        'Test Fragment number field'
        self.assertEqual(self.data.get_fragment_number(), 0x0000)
        self.data.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.data.get_fragment_number(), 0x01)

    def test_08_sequence_number(self):
        'Test Sequence number field'
        self.assertEqual(self.data.get_sequence_number(), 0x0444)
        self.data.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.data.get_sequence_number(), 0x0234)
        
    def test_09_frame_data(self):
        'Test Frame Data field'
        # Test with packet without addr4
        frame_body=b"\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x72\x37\x40\x00\x80\x06\x6c\x22\xc0\xa8\x01\x02\xc3\x7a\x97\x51\xd7\xa0\x00\x50\xa5\xa5\xb1\xe0\x12\x1c\xa9\xe1\x50\x10\x4e\x75\x59\x74\x00\x00"
        self.assertEqual(self.data.get_frame_body(), frame_body)
      

if __name__ == '__main__':
    unittest.main(verbosity=1)
