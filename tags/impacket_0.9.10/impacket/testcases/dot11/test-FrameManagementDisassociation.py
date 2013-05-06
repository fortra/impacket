#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11, Dot11Types, Dot11ManagementFrame,Dot11ManagementDisassociation
from ImpactDecoder import RadioTapDecoder
from binascii import hexlify
import unittest

class TestDot11ManagementDisassociationFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
	self.rawframe="\x00\x00\x1c\x00\xef\x18\x00\x00\xe7\x8a\xec\xb8\x3b\x00\x00\x00\x10\x02\x85\x09\xa0\x00\xb5\x9d\x60\x00\x00\x18\xa0\x00\x3a\x01\x00\x18\xf8\x6c\x76\x42\x70\x1a\x04\x54\xe3\x86\x00\x18\xf8\x6c\x76\x42\x70\x92\x08\x00\xbf\x1b\xa3\xa8"
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawframe)

        self.assertEqual(str(radiotap.__class__), "dot11.RadioTap")

        self.dot11=radiotap.child()
        self.assertEqual(str(self.dot11.__class__), "dot11.Dot11")

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_DISASSOCIATION)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_DISASSOCIATION)
        
        self.management_base=self.dot11.child()
        self.assertEqual(str(self.management_base.__class__), "dot11.Dot11ManagementFrame")
        
        self.management_disassociation=self.management_base.child()
        self.assertEqual(str(self.management_disassociation.__class__), "dot11.Dot11ManagementDisassociation")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_disassociation.get_header_size(), 2)
        self.assertEqual(self.management_disassociation.get_tail_size(), 0)
        
    def test_02(self):
        'Test Duration field'
        
        self.assertEqual(self.management_base.get_duration(), 0x013a)
        self.management_base.set_duration(0x1234)
        self.assertEqual(self.management_base.get_duration(), 0x1234)
    
    def test_03(self):
        'Test Destination Address field'
        
        addr=self.management_base.get_destination_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0xF8,0x6C,0x76,0x42])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_destination_address(addr)
        self.assertEqual(self.management_base.get_destination_address().tolist(), [0x12,0x18,0xF8,0x6C,0x76,0x34])

    def test_04(self):
        'Test Source Address field'
        
        addr=self.management_base.get_source_address()
        
        self.assertEqual(addr.tolist(), [0x70,0x1A,0x04,0x54,0xE3,0x86])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x1A,0x04,0x54,0xE3,0x34])

    def test_05(self):
        'Test BSSID Address field'
        
        addr=self.management_base.get_bssid()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0xF8,0x6C,0x76,0x42])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_bssid(addr)
        self.assertEqual(self.management_base.get_bssid().tolist(), [0x12,0x18,0xF8,0x6C,0x76,0x34])

    def test_06(self):
        'Test Sequence control field'
        self.assertEqual(self.management_base.get_sequence_control(), 0x9270)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 2343)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body="\x08\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Reason Code field' 
        self.assertEqual(self.management_disassociation.get_reason_code(), 0x0008)
        self.management_disassociation.set_reason_code(0x8765)
        self.assertEqual(self.management_disassociation.get_reason_code(), 0x8765)
        
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11ManagementDisassociationFrames)
unittest.TextTestRunner(verbosity=2).run(suite)
