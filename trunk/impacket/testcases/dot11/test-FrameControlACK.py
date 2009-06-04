#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11ControlFrameACK
from binascii import hexlify
import unittest

class TestDot11FrameControlACK(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame ACK
        self.frame_orig='\xd4\x00\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e'
        self.ack=Dot11ControlFrameACK(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.ack.get_type_field(), Dot11.DOT11_TYPE_CONTROL)
        ack=Dot11ControlFrameACK()
        self.assertEqual(ack.get_type_field(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'
        self.assertEqual(self.ack.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT)
        ack=Dot11ControlFrameACK()
        self.assertEqual(ack.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
        self.assertEqual(self.ack.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_ACKNOWLEDGMENT)
        ack=Dot11ControlFrameACK()
        self.assertEqual(ack.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_ACKNOWLEDGMENT)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.ack.get_header_size(), 14)
        ack=Dot11ControlFrameACK()
        self.assertEqual(ack.get_header_size(), 14)
    
    def test_05_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.ack.get_duration_field(), 0)
        self.ack.set_duration_field(0x1234)
        self.assertEqual(self.ack.get_duration_field(), 0x1234)
    
    def test_06_RA(self):
        'Test RA field'
        
        ra=self.ack.get_ra_field()
        self.assertEqual(ra.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        ra[0]=0x12
        ra[5]=0x34
        self.ack.set_ra_field(ra)
        self.assertEqual(self.ack.get_ra_field().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])
    
    def test_07_FCS(self):
        'Test FCS field'
        
        fcs=self.ack.get_fcs_field()
        self.assertEqual(fcs,   0xb77fc39e)
        self.ack.set_fcs_field(0x44332211)
        self.assertEqual(self.ack.get_fcs_field(), 0x44332211)
        
    def test_08_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.ack.get_fcs_field()
        self.assertEqual(fcs,0xb77fc39e)
        frame=self.ack.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_09_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.ack.set_duration_field(0x1234)
        frame=self.ack.get_packet()
        fcs=self.ack.get_fcs_field()
        self.assertEqual(fcs,0xD7AF056F)
        newframe='\xd4\x00\x34\x12\x00\x08\x54\xac\x2f\x85\xd7\xaf\x05\x6f'
        self.assertEqual(frame  ,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlACK)
unittest.TextTestRunner(verbosity=2).run(suite)

