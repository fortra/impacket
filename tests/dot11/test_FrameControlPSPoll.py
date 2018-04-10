#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.dot11 import Dot11,Dot11Types,Dot11ControlFramePSPoll
from binascii import hexlify
import unittest

class TestDot11FrameControlPSPoll(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame PSPoll
        self.frame_orig='\xa6\x73\xf1\xaf\x48\x06\xee\x23\x2b\xc9\xfe\xbe\xe5\x05\x4c\x0a\x04\xa0\x00\x0f'

        d = Dot11(self.frame_orig)
        
        type = d.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_CONTROL)
        
        subtype = d.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL)
        
        typesubtype = d.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)
            
        self.pspoll = Dot11ControlFramePSPoll(d.get_body_as_string())
            
        d.contains(self.pspoll)
        
    def test_01_HeaderTailSize(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.pspoll.get_header_size(), 14)
        self.assertEqual(self.pspoll.get_tail_size(), 0)
    
    def test_02_AID(self):
        'Test AID field'
        
        self.assertEqual(self.pspoll.get_aid(), 0xAFF1)
        self.pspoll.set_aid(0x1234)
        self.assertEqual(self.pspoll.get_aid(), 0x1234)
    
    def test_03_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.pspoll.get_bssid()
        self.assertEqual(bssid.tolist(), [0x48,0x06,0xee,0x23,0x2b,0xc9])
        bssid[0]=0x12
        bssid[5]=0x34
        self.pspoll.set_bssid(bssid)
        self.assertEqual(self.pspoll.get_bssid().tolist(), [0x12,0x06,0xee,0x23,0x2b,0x34])

    def test_04_TA(self):
        'Test TA field'
        
        ta=self.pspoll.get_ta()
        self.assertEqual(ta.tolist(), [0xfe,0xbe,0xe5,0x05,0x4c,0x0a])
        ta[0]=0x12
        ta[5]=0x34
        self.pspoll.set_ta(ta)
        self.assertEqual(self.pspoll.get_ta().tolist(), [0x12,0xbe,0xe5,0x05,0x4c,0x34])
     
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlPSPoll)
unittest.TextTestRunner(verbosity=1).run(suite)

