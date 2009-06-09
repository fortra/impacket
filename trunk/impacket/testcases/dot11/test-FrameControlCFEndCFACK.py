#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11ControlFrameCFEndCFACK
from binascii import hexlify
import unittest

class TestDot11FrameControlCFEndCFACK(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame CFEndCFACK
        self.frame_orig='\xf4\x74\xde\xed\xe5\x56\x85\xf8\xd2\x3b\x96\xae\x0f\xb0\xd9\x8a\x03\x02\x38\x00'  
        self.cfendcfack=Dot11ControlFrameCFEndCFACK(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.cfendcfack.get_type(), Dot11.DOT11_TYPE_CONTROL)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_type(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'

        self.assertEqual(self.cfendcfack.get_subtype(), Dot11.DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_subtype(), Dot11.DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
        self.assertEqual(self.cfendcfack.get_type_n_subtype(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_type_n_subtype(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.cfendcfack.get_header_size(), 20)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_header_size(), 20)
    
    def test_05_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cfendcfack.get_duration(), 0xEDDE)
        self.cfendcfack.set_duration(0x1234)
        self.assertEqual(self.cfendcfack.get_duration(), 0x1234)
    
    def test_06_RA(self):
        'Test RA field'
        
        ra=self.cfendcfack.get_ra()
        self.assertEqual(ra.tolist(), [0xe5,0x56,0x85,0xf8,0xd2,0x3b])
        ra[0]=0x12
        ra[5]=0x34
        self.cfendcfack.set_ra(ra)
        self.assertEqual(self.cfendcfack.get_ra().tolist(), [0x12,0x56,0x85,0xf8,0xd2,0x34])

    def test_07_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.cfendcfack.get_bssid()
        self.assertEqual(bssid.tolist(), [0x96,0xae,0x0f,0xb0,0xd9,0x8a])
        bssid[0]=0x12
        bssid[5]=0x34
        self.cfendcfack.set_bssid(bssid)
        self.assertEqual(self.cfendcfack.get_bssid().tolist(), [0x12,0xae,0x0f,0xb0,0xd9,0x34])

    def test_08_FCS(self):
        'Test FCS field'
        
        fcs=self.cfendcfack.get_fcs()

        self.assertEqual(fcs, 0x03023800)
        self.cfendcfack.set_fcs(0x44332211)
        self.assertEqual(self.cfendcfack.get_fcs(), 0x44332211)
        
    def test_09_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.cfendcfack.get_fcs()
        self.assertEqual(fcs,0x03023800)
        frame=self.cfendcfack.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_10_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.cfendcfack.set_duration(0x1234)
        frame=self.cfendcfack.get_packet()
        fcs=self.cfendcfack.get_fcs()
        self.assertEqual(fcs,0xD850F116)

        newframe='\xf4\x74\x34\x12\xe5\x56\x85\xf8\xd2\x3b\x96\xae\x0f\xb0\xd9\x8a\xd8\x50\xf1\x16'
        self.assertEqual(frame,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlCFEndCFACK)
unittest.TextTestRunner(verbosity=2).run(suite)
