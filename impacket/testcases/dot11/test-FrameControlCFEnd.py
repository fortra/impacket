#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11ControlFrameCFEnd
from binascii import hexlify
import unittest

class TestDot11FrameControlCFEnd(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame CFEnd
        self.frame_orig='\xe4\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x19\xe0\x98\x04\xd4\xad\x9c\x3c\xc0'
        self.cfend=Dot11ControlFrameCFEnd(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.cfend.get_type(), Dot11.DOT11_TYPE_CONTROL)
        cfend=Dot11ControlFrameCFEnd()
        self.assertEqual(cfend.get_type(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'
        self.assertEqual(self.cfend.get_subtype(), Dot11.DOT11_SUBTYPE_CONTROL_CF_END)
        cfend=Dot11ControlFrameCFEnd()
        self.assertEqual(cfend.get_subtype(), Dot11.DOT11_SUBTYPE_CONTROL_CF_END)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
        self.assertEqual(self.cfend.get_type_n_subtype(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CF_END)
        cfend=Dot11ControlFrameCFEnd()
        self.assertEqual(cfend.get_type_n_subtype(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CF_END)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.cfend.get_header_size(), 20)
        cfend=Dot11ControlFrameCFEnd()
        self.assertEqual(cfend.get_header_size(), 20)
    
    def test_05_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cfend.get_duration(), 0x00)
        self.cfend.set_duration(0x1234)
        self.assertEqual(self.cfend.get_duration(), 0x1234)
    
    def test_06_RA(self):
        'Test RA field'
        
        ra=self.cfend.get_ra()
        self.assertEqual(ra.tolist(), [0xff,0xff,0xff,0xff,0xff,0xff])
        ra[0]=0x12
        ra[5]=0x34
        self.cfend.set_ra(ra)
        self.assertEqual(self.cfend.get_ra().tolist(), [0x12,0xff,0xff,0xff,0xff,0x34])

    def test_07_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.cfend.get_bssid()
        self.assertEqual(bssid.tolist(), [0x00,0x19,0xe0,0x98,0x04,0xd4])
        bssid[0]=0x12
        bssid[5]=0x34
        self.cfend.set_bssid(bssid)
        self.assertEqual(self.cfend.get_bssid().tolist(), [0x12,0x19,0xe0,0x98,0x04,0x34])

    def test_08_FCS(self):
        'Test FCS field'
        
        fcs=self.cfend.get_fcs()

        self.assertEqual(fcs, 0xad9c3cc0)
        self.cfend.set_fcs(0x44332211)
        self.assertEqual(self.cfend.get_fcs(), 0x44332211)
        
    def test_09_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.cfend.get_fcs()
        self.assertEqual(fcs,0xad9c3cc0)
        frame=self.cfend.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_10_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.cfend.set_duration(0x1234)
        frame=self.cfend.get_packet()
        fcs=self.cfend.get_fcs()
        self.assertEqual(fcs,0x93441DA6)

        newframe='\xe4\x00\x34\x12\xff\xff\xff\xff\xff\xff\x00\x19\xe0\x98\x04\xd4\x93\x44\x1d\xa6'
        self.assertEqual(frame,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlCFEnd)
unittest.TextTestRunner(verbosity=2).run(suite)

