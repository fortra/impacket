#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11, Dot11Types, Dot11ManagementFrame, Dot11ManagementReassociationResponse
from ImpactDecoder import RadioTapDecoder
from binascii import hexlify
import unittest

class TestDot11ManagementReassociationResponseFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawframe="\x00\x00\x1c\x00\xef\x18\x00\x00\xc0\xbb\xbc\xae;\x00\x00\x00\x10\x02\x85\t\xa0\x00\xba\x9ca\x00\x00\x1e0\x08:\x01p\x1a\x04T\xe3\x86\x00\x18\xf8lvB\x00\x18\xf8lvB\xe0g\x11\x04\x00\x00\x04\xc0\x01\x08\x82\x84\x8b\x96$0Hl2\x04\x0c\x12\x18`\xdd\t\x00\x10\x18\x02\x02\xf0\x00\x00\x00\xb3\xff\n\\"
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawframe)

        self.assertEqual(str(radiotap.__class__), "dot11.RadioTap")

        self.dot11=radiotap.child()
        self.assertEqual(str(self.dot11.__class__), "dot11.Dot11")

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype, Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE)
        
        self.management_base=self.dot11.child()
        self.assertEqual(str(self.management_base.__class__), "dot11.Dot11ManagementFrame")
        
        self.management_reassociation_response=self.management_base.child()
        self.assertEqual(str(self.management_reassociation_response.__class__), "dot11.Dot11ManagementReassociationResponse")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_reassociation_response.get_header_size(), 33)
        self.assertEqual(self.management_reassociation_response.get_tail_size(), 0)
        
    def test_02(self):
        'Test Duration field'
        
        self.assertEqual(self.management_base.get_duration(), 0x013a)
        self.management_base.set_duration(0x1234)
        self.assertEqual(self.management_base.get_duration(), 0x1234)
    
    def test_03(self):
        'Test Destination Address field'
        
        addr=self.management_base.get_destination_address()
        
        self.assertEqual(addr.tolist(), [0x70,0x1a,0x04,0x54,0xe3,0x86])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_destination_address(addr)
        self.assertEqual(self.management_base.get_destination_address().tolist(), [0x12,0x1a,0x04,0x54,0xe3,0x34])

    def test_04(self):
        'Test Source Address field'
        
        addr=self.management_base.get_source_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0xF8,0x6C,0x76,0x42])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x18,0xF8,0x6C,0x76,0x34])

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
        self.assertEqual(self.management_base.get_sequence_control(), 0x67e0)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 1662)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body="\x11\x04\x00\x00\x04\xc0\x01\x08\x82\x84\x8b\x96$0Hl2\x04\x0c\x12\x18`\xdd\t\x00\x10\x18\x02\x02\xf0\x00\x00\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Reassociation Response Capabilities field'
        self.assertEqual(self.management_reassociation_response.get_capabilities(), 0x0411)
        self.management_reassociation_response.set_capabilities(0x4321) 
        self.assertEqual(self.management_reassociation_response.get_capabilities(), 0x4321)

    def test_11(self):
        'Test Management Reassociation Response Status Code field' 
        self.assertEqual(self.management_reassociation_response.get_status_code(), 0x0000)
        self.management_reassociation_response.set_status_code(0x4321)
        self.assertEqual(self.management_reassociation_response.get_status_code(), 0x4321)

    def test_12(self):
        'Test Management Reassociation Response Association ID field'
        self.assertEqual(self.management_reassociation_response.get_association_id(), 0xc004)
        self.management_reassociation_response.set_association_id(0x4321)
        self.assertEqual(self.management_reassociation_response.get_association_id(), 0x4321)

    def test_13(self):
        'Test Management Reassociation Response Supported_rates getter/setter methods'
        self.assertEqual(self.management_reassociation_response.get_supported_rates(), (0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c))
        self.assertEqual(self.management_reassociation_response.get_supported_rates(human_readable=True), (1.0, 2.0, 5.5, 11.0, 18.0, 24.0, 36.0, 54.0))
        
        self.management_reassociation_response.set_supported_rates((0x12, 0x98, 0x24, 0xb0, 0x48, 0x60))

        self.assertEqual(self.management_reassociation_response.get_supported_rates(), (0x12, 0x98, 0x24, 0xb0, 0x48, 0x60))
        self.assertEqual(self.management_reassociation_response.get_supported_rates(human_readable=True), (9.0, 12.0, 18.0, 24.0, 36.0, 48.0))
        self.assertEqual(self.management_reassociation_response.get_header_size(), 33-2)

    def test_14(self):
        'Test Management Vendor Specific getter/setter methods'
        self.assertEqual(self.management_reassociation_response.get_vendor_specific(), [("\x00\x10\x18","\x02\x02\xf0\x00\x00\x00")])

        self.management_reassociation_response.add_vendor_specific("\x00\x00\x40", "\x04\x04\x04\x04\x04\x04")

        self.assertEqual(self.management_reassociation_response.get_vendor_specific(), 
            [("\x00\x10\x18", "\x02\x02\xf0\x00\x00\x00"),
             ("\x00\x00\x40", "\x04\x04\x04\x04\x04\x04"),
            ])
        self.assertEqual(self.management_reassociation_response.get_header_size(), 33+11)

suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11ManagementReassociationResponseFrames)
unittest.TextTestRunner(verbosity=2).run(suite)
