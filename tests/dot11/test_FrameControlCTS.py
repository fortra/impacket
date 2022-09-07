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
from impacket.dot11 import Dot11,Dot11Types,Dot11ControlFrameCTS


class TestDot11FrameControlCTS(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame CTS
        self.frame_orig=b'\xc4\x00\x3b\x12\x00\x19\xe0\x98\x04\xd4\x2b\x8a\x65\x17'
        
        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_CONTROL)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_CLEAR_TO_SEND)
            
        self.cts = Dot11ControlFrameCTS(d.get_body_as_string())
            
        d.contains(self.cts)
        
    def test_01_HeaderTailSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.cts.get_header_size(), 8)
        self.assertEqual(self.cts.get_tail_size(), 0)
    
    def test_02_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cts.get_duration(), 4667)
        self.cts.set_duration(0x1234)
        self.assertEqual(self.cts.get_duration(), 0x1234)
    
    def test_03_RA(self):
        'Test RA field'
        
        ra=self.cts.get_ra()
        
        self.assertEqual(ra.tolist(), [0x00,0x19,0xe0,0x98,0x04,0xd4])
        ra[0]=0x12
        ra[5]=0x34
        self.cts.set_ra(ra)
        self.assertEqual(self.cts.get_ra().tolist(), [0x12,0x19,0xe0,0x98,0x04,0x34])
      

if __name__ == '__main__':
    unittest.main(verbosity=1)
