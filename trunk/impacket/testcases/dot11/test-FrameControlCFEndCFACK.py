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
        self.frame_orig='\xe4\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x19\xe0\x98\x04\xd4\xad\x9c\x3c\xc0'
        #f591c22fb8de09c8f680b7259c24520a0458020f80000000ffffffffffff001b9ece4a18001b9ece4a18e0121c2626182500000064001104000543414d3234010482848b960301010504000100002a010432080c1218243048606c861a84ca        
        self.cfendcfack=Dot11ControlFrameCFEndCFACK(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.cfendcfack.get_type_field(), Dot11.DOT11_TYPE_CONTROL)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_type_field(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'

        self.assertEqual(self.cfendcfack.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
        self.assertEqual(self.cfendcfack.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.cfendcfack.get_header_size(), 20)
        cfendcfack=Dot11ControlFrameCFEndCFACK()
        self.assertEqual(cfendcfack.get_header_size(), 20)
    
    def test_05_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cfendcfack.get_duration_field(), 0x00)
        self.cfendcfack.set_duration_field(0x1234)
        self.assertEqual(self.cfendcfack.get_duration_field(), 0x1234)
    
    def test_06_RA(self):
        'Test RA field'
        
        ra=self.cfendcfack.get_ra_field()
        self.assertEqual(ra.tolist(), [0xff,0xff,0xff,0xff,0xff,0xff])
        ra[0]=0x12
        ra[5]=0x34
        self.cfendcfack.set_ra_field(ra)
        self.assertEqual(self.cfendcfack.get_ra_field().tolist(), [0x12,0xff,0xff,0xff,0xff,0x34])

    def test_07_BSSID(self):
        'Test BSS ID field'
        
        bssid=self.cfendcfack.get_bssid_field()
        self.assertEqual(bssid.tolist(), [0x00,0x19,0xe0,0x98,0x04,0xd4])
        bssid[0]=0x12
        bssid[5]=0x34
        self.cfendcfack.set_bssid_field(bssid)
        self.assertEqual(self.cfendcfack.get_bssid_field().tolist(), [0x12,0x19,0xe0,0x98,0x04,0x34])

    def test_08_FCS(self):
        'Test FCS field'
        
        fcs=self.cfendcfack.get_fcs_field()

        self.assertEqual(fcs, 0xad9c3cc0)
        self.cfendcfack.set_fcs_field(0x44332211)
        self.assertEqual(self.cfendcfack.get_fcs_field(), 0x44332211)
        
    def test_09_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.cfendcfack.get_fcs_field()
        self.assertEqual(fcs,0xad9c3cc0)
        frame=self.cfendcfack.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_10_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.cfendcfack.set_duration_field(0x1234)
        frame=self.cfendcfack.get_packet()
        fcs=self.cfendcfack.get_fcs_field()
        self.assertEqual(fcs,0x93441DA6)

        newframe='\xe4\x00\x34\x12\xff\xff\xff\xff\xff\xff\x00\x19\xe0\x98\x04\xd4\x93\x44\x1d\xa6'
        self.assertEqual(frame,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlCFEndCFACK)
unittest.TextTestRunner(verbosity=2).run(suite)
