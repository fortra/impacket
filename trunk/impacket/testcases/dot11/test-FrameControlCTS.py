#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11ControlFrameCTS
from binascii import hexlify
import unittest

class TestDot11FrameControlCTS(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame CTS
        self.frame_orig='\xc4\x00\x3b\x12\x00\x19\xe0\x98\x04\xd4\x2b\x8a\x65\x17'
        self.cts=Dot11ControlFrameCTS(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.cts.get_type_field(), Dot11.DOT11_TYPE_CONTROL)
        cts=Dot11ControlFrameCTS()
        self.assertEqual(cts.get_type_field(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'
        self.assertEqual(self.cts.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND)
        cts=Dot11ControlFrameCTS()
        self.assertEqual(cts.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
        self.assertEqual(self.cts.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CLEAR_TO_SEND)
        cts=Dot11ControlFrameCTS()
        self.assertEqual(cts.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_CLEAR_TO_SEND)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.cts.get_header_size(), 14)
        cts=Dot11ControlFrameCTS()
        self.assertEqual(cts.get_header_size(), 14)
    
    def test_05_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.cts.get_duration_field(), 4667)
        self.cts.set_duration_field(0x1234)
        self.assertEqual(self.cts.get_duration_field(), 0x1234)
    
    def test_06_RA(self):
        'Test RA field'
        
        ra=self.cts.get_ra_field()
        
        self.assertEqual(ra.tolist(), [0x00,0x19,0xe0,0x98,0x04,0xd4])
        ra[0]=0x12
        ra[5]=0x34
        self.cts.set_ra_field(ra)
        self.assertEqual(self.cts.get_ra_field().tolist(), [0x12,0x19,0xe0,0x98,0x04,0x34])
    
    def test_07_FCS(self):
        'Test FCS field'
        
        fcs=self.cts.get_fcs_field()
        self.assertEqual(fcs,   0x2B8A6517)
        self.cts.set_fcs_field(0x44332211)
        self.assertEqual(self.cts.get_fcs_field(), 0x44332211)
        
    def test_08_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.cts.get_fcs_field()
        self.assertEqual(fcs,0x2B8A6517)
        frame=self.cts.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_09_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.cts.set_duration_field(0x1234)
        frame=self.cts.get_packet()
        fcs=self.cts.get_fcs_field()
        self.assertEqual(fcs,0x879845CE)
        newframe='\xc4\x00\x34\x12\x00\x19\xe0\x98\x04\xd4\x87\x98\x45\xce'
        self.assertEqual(frame  ,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlCTS)
unittest.TextTestRunner(verbosity=2).run(suite)

