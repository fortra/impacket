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
from impacket.dot11 import Dot11,Dot11Types,Dot11ControlFrameCFEndCFACK


class TestDot11FrameControlCFEndCFACK(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame CFEndCFACK
        self.frame_orig=b'\xf4\x74\xde\xed\xe5\x56\x85\xf8\xd2\x3b\x96\xae\x0f\xb0\xd9\x8a\x03\x02\x38\x00'

        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_CONTROL)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK)
            
        self.cfendcfack = Dot11ControlFrameCFEndCFACK(d.get_body_as_string())
            
        d.contains(self.cfendcfack)
        
    def test_01_HeaderTailSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.cfendcfack.get_header_size(), 14)
        self.assertEqual(self.cfendcfack.get_tail_size(), 0)
    
    def test_02_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cfendcfack.get_duration(), 0xEDDE)
        self.cfendcfack.set_duration(0x1234)
        self.assertEqual(self.cfendcfack.get_duration(), 0x1234)
    
    def test_03_RA(self):
        'Test RA field'
        
        ra=self.cfendcfack.get_ra()
        self.assertEqual(ra.tolist(), [0xe5,0x56,0x85,0xf8,0xd2,0x3b])
        ra[0]=0x12
        ra[5]=0x34
        self.cfendcfack.set_ra(ra)
        self.assertEqual(self.cfendcfack.get_ra().tolist(), [0x12,0x56,0x85,0xf8,0xd2,0x34])

    def test_04_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.cfendcfack.get_bssid()
        self.assertEqual(bssid.tolist(), [0x96,0xae,0x0f,0xb0,0xd9,0x8a])
        bssid[0]=0x12
        bssid[5]=0x34
        self.cfendcfack.set_bssid(bssid)
        self.assertEqual(self.cfendcfack.get_bssid().tolist(), [0x12,0xae,0x0f,0xb0,0xd9,0x34])
      

if __name__ == '__main__':
    unittest.main(verbosity=1)
