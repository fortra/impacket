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
from impacket.dot11 import Dot11,Dot11Types,Dot11ControlFrameACK


class TestDot11FrameControlACK(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame ACK
        self.frame_orig=b'\xd4\x00\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e'

        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_CONTROL)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_ACKNOWLEDGMENT)
            
        self.ack = Dot11ControlFrameACK(d.get_body_as_string())
            
        d.contains(self.ack)
        
    def test_01_HeaderTailSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.ack.get_header_size(), 8)
        self.assertEqual(self.ack.get_tail_size(), 0)

    def test_02_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.ack.get_duration(), 0)
        self.ack.set_duration(0x1234)
        self.assertEqual(self.ack.get_duration(), 0x1234)
    
    def test_03_RA(self):
        'Test RA field'
        
        ra=self.ack.get_ra()
        self.assertEqual(ra.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        ra[0]=0x12
        ra[5]=0x34
        self.ack.set_ra(ra)
        self.assertEqual(self.ack.get_ra().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])
       

if __name__ == '__main__':
    unittest.main(verbosity=1)
