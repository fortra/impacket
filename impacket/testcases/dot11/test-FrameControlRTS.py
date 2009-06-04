#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11ControlFrameRTS
from binascii import hexlify
import unittest

#####################
# TODO: Rever, libpcap aparentemente esta dropeando 1 byte de los Control RTS frames
class TestDot11FrameControlRTS(unittest.TestCase):

    def setUp(self):
        # 802.11 Control Frame RTS
        self.frame_orig='\xb4\x00\x81\x01\x00\x08\x54\xac\x2f\x85\x00\x23\x4d\x09\x86\xfe\x99\x75\x43\x73'
        self.rts=Dot11ControlFrameRTS(self.frame_orig)
        
    def test_01_Type(self):
        'Test Type field'
        self.assertEqual(self.rts.get_type_field(), Dot11.DOT11_TYPE_CONTROL)
        rts=Dot11ControlFrameRTS()
        self.assertEqual(rts.get_type_field(), Dot11.DOT11_TYPE_CONTROL)

    def test_02_SubType(self):
        'Test SubType field'
        self.assertEqual(self.rts.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND)
        rts=Dot11ControlFrameRTS()
        self.assertEqual(rts.get_subtype_field(), Dot11.DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND)
    
    def test_03_TypeSubtype(self):
        'Test Type and SubType field'
        self.assertEqual(self.rts.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_REQUEST_TO_SEND)
        rts=Dot11ControlFrameRTS()
        self.assertEqual(rts.get_type_n_subtype_field(), Dot11.DOT11_TYPE_CONTROL_SUBTYPE_REQUEST_TO_SEND)

    def test_04_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.rts.get_header_size(), 20)
        rts=Dot11ControlFrameRTS()
        self.assertEqual(rts.get_header_size(), 20)
    
    def test_05_Duration(self):
        'Test Duration field'
        
        self.assertEqual(self.rts.get_duration_field(), 0x181)
        self.rts.set_duration_field(0x1234)
        self.assertEqual(self.rts.get_duration_field(), 0x1234)
    
    def test_06_RA(self):
        'Test RA field'
        
        ra=self.rts.get_ra_field()
        self.assertEqual(ra.tolist(), [0x00,0x08,0x54,0xac,0x2f,0x85])
        ra[0]=0x12
        ra[5]=0x34
        self.rts.set_ra_field(ra)
        self.assertEqual(self.rts.get_ra_field().tolist(), [0x12,0x08,0x54,0xac,0x2f,0x34])

    def test_07_TA(self):
        'Test TA field'
        
        ta=self.rts.get_ta_field()
        self.assertEqual(ta.tolist(), [0x00,0x23,0x4d,0x09,0x86,0xfe])
        ta[0]=0x12
        ta[5]=0x34
        self.rts.set_ta_field(ta)
        self.assertEqual(self.rts.get_ta_field().tolist(), [0x12,0x23,0x4d,0x09,0x86,0x34])

    def test_08_FCS(self):
        'Test FCS field'
        
        fcs=self.rts.get_fcs_field()
        
        self.assertEqual(fcs, 0x99754373)
        self.rts.set_fcs_field(0x44332211)
        self.assertEqual(self.rts.get_fcs_field(), 0x44332211)
        
    def test_09_GetPacket(self):
        'Test FCS with auto_checksum field'
        
        fcs=self.rts.get_fcs_field()
        self.assertEqual(fcs,0x99754373)
        frame=self.rts.get_packet()
        self.assertEqual(frame,self.frame_orig)

    def test_10_AutoChecksum(self):
        'Test auto_checksum feature'
        
        self.rts.set_duration_field(0x1234)
        frame=self.rts.get_packet()
        fcs=self.rts.get_fcs_field()
        self.assertEqual(fcs,0xB67A88D6)
        newframe='\xb4\x00\x34\x12\x00\x08\x54\xac\x2f\x85\x00\x23\x4d\x09\x86\xfe\xb6\x7a\x88\xd6'
        self.assertEqual(frame  ,newframe)    
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11FrameControlRTS)
unittest.TextTestRunner(verbosity=2).run(suite)

