#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11Types,Dot11ControlFrameCFEnd
from binascii import hexlify
import unittest

class TestDot11FrameControlCFEnd(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame CFEnd
        self.frame_orig='\xe4\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x19\xe0\x98\x04\xd4\xad\x9c\x3c\xc0'

        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_CONTROL)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_CONTROL_CF_END)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_CF_END)
            
        self.cfend = Dot11ControlFrameCFEnd(d.get_body_as_string())
            
        d.contains(self.cfend)
        
    def test_01_HeaderTailSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.cfend.get_header_size(), 14)
        self.assertEqual(self.cfend.get_tail_size(), 0)
    
    def test_02_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cfend.get_duration(), 0x00)
        self.cfend.set_duration(0x1234)
        self.assertEqual(self.cfend.get_duration(), 0x1234)
    
    def test_03_RA(self):
        'Test RA field'
        
        ra=self.cfend.get_ra()
        self.assertEqual(ra.tolist(), [0xff,0xff,0xff,0xff,0xff,0xff])
        ra[0]=0x12
        ra[5]=0x34
        self.cfend.set_ra(ra)
        self.assertEqual(self.cfend.get_ra().tolist(), [0x12,0xff,0xff,0xff,0xff,0x34])

    def test_04_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.cfend.get_bssid()
        self.assertEqual(bssid.tolist(), [0x00,0x19,0xe0,0x98,0x04,0xd4])
        bssid[0]=0x12
        bssid[5]=0x34
        self.cfend.set_bssid(bssid)
        self.assertEqual(self.cfend.get_bssid().tolist(), [0x12,0x19,0xe0,0x98,0x04,0x34])
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlCFEnd)
unittest.TextTestRunner(verbosity=2).run(suite)

