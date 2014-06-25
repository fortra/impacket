#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11Types,Dot11ControlFrameRTS
from binascii import hexlify
import unittest

class TestDot11FrameControlRTS(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame RTS
        self.frame_orig='\xb4\x00\x81\x01\x00\x08\x54\xac\x2f\x85\x00\x23\x4d\x09\x86\xfe\x99\x75\x43\x73'
        
        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_CONTROL)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_REQUEST_TO_SEND)
            
        self.rts = Dot11ControlFrameRTS(d.get_body_as_string())
            
        d.contains(self.rts)
        
    def test_01_HeaderTailSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.rts.get_header_size(), 14)
        self.assertEqual(self.rts.get_tail_size(), 0)
    
    def test_02_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.rts.get_duration(), 0x181)
        self.rts.set_duration(0x1234)
        self.assertEqual(self.rts.get_duration(), 0x1234)
    
    def test_03_RA(self):
        'Test RA field'
        
        ra=self.rts.get_ra()
        self.assertEqual(ra.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        ra[0]=0x12
        ra[5]=0x34
        self.rts.set_ra(ra)
        self.assertEqual(self.rts.get_ra().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])

    def test_04_TA(self):
        'Test TA field'
        
        ta=self.rts.get_ta()
        self.assertEqual(ta.tolist(), [0x00,0x23,0x4d,0x09,0x86,0xfe])
        ta[0]=0x12
        ta[5]=0x34
        self.rts.set_ta(ta)
        self.assertEqual(self.rts.get_ta().tolist(), [0x12,0x23,0x4d,0x09,0x86,0x34])
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlRTS)
unittest.TextTestRunner(verbosity=2).run(suite)

