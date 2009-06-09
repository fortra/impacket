#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11ControlFramePSPoll
from binascii import hexlify
import unittest

class TestDot11FrameControlPSPoll(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame PSPoll
        self.frame_orig='\xb4\x00\x81\x01\x00\x08\x54\xac\x2f\x85\x00\x23\x4d\x09\x86\xfe\x99\x75\x43\x73'
        self.pspoll=Dot11ControlFramePSPoll(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.pspoll.get_type(), Dot11.DOT11_TYPE_CONTROL)
        pspoll=Dot11ControlFramePSPoll()
        self.assertEqual(pspoll.get_type(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'
        self.assertEqual(self.pspoll.get_subtype(), Dot11.DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL)
        pspoll=Dot11ControlFramePSPoll()
        self.assertEqual(pspoll.get_subtype(), Dot11.DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
       
        self.assertEqual(self.pspoll.get_type_n_subtype(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)
        pspoll=Dot11ControlFramePSPoll()
        self.assertEqual(pspoll.get_type_n_subtype(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.pspoll.get_header_size(), 20)
        pspoll=Dot11ControlFramePSPoll()
        self.assertEqual(pspoll.get_header_size(), 20)
    
    def test_05_AID(self):
        'Test AID field'
        
        self.assertEqual(self.pspoll.get_aid(), 0x181)
        self.pspoll.set_aid(0x1234)
        self.assertEqual(self.pspoll.get_aid(), 0x1234)
    
    def test_06_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.pspoll.get_bssid()
        self.assertEqual(bssid.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        bssid[0]=0x12
        bssid[5]=0x34
        self.pspoll.set_bssid(bssid)
        self.assertEqual(self.pspoll.get_bssid().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])

    def test_07_TA(self):
        'Test TA field'
        
        ta=self.pspoll.get_ta()
        self.assertEqual(ta.tolist(), [0x00,0x23,0x4d,0x09,0x86,0xfe])
        ta[0]=0x12
        ta[5]=0x34
        self.pspoll.set_ta(ta)
        self.assertEqual(self.pspoll.get_ta().tolist(), [0x12,0x23,0x4d,0x09,0x86,0x34])

    def test_08_FCS(self):
        'Test FCS field'
        
        fcs=self.pspoll.get_fcs()
        
        self.assertEqual(fcs, 0x99754373)
        self.pspoll.set_fcs(0x44332211)
        self.assertEqual(self.pspoll.get_fcs(), 0x44332211)
        
    def test_09_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.pspoll.get_fcs()
        self.assertEqual(fcs,0x99754373)
        frame=self.pspoll.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_10_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.pspoll.set_aid(0x1234)
        frame=self.pspoll.get_packet()
        fcs=self.pspoll.get_fcs()
        self.assertEqual(fcs,0xB67A88D6)
        newframe='\xb4\x00\x34\x12\x00\x08\x54\xac\x2f\x85\x00\x23\x4d\x09\x86\xfe\xb6\x7a\x88\xd6'
        self.assertEqual(frame  ,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlPSPoll)
unittest.TextTestRunner(verbosity=2).run(suite)

