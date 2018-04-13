#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.dot11 import Dot11, Dot11Types, Dot11ManagementFrame, Dot11ManagementAssociationRequest
from impacket.ImpactDecoder import RadioTapDecoder
from binascii import hexlify
import unittest

class TestDot11ManagementAssociationRequestFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
	self.rawframe="\x00\x00\x1c\x00\xef\x18\x00\x00jH\xfa\x00<\x00\x00\x00\x10\x02\x85\t\xa0\x00\xb9\x9e_\x00\x00\x1b\x00\x00:\x01\x00\x18\xf8lvBp\x1a\x04T\xe3\x86\x00\x18\xf8lvBP\x8e1\x04\n\x00\x00\x05ddwrt\x01\x08\x82\x84\x8b\x96$0Hl!\x02\n\x11$\x02\x01\x0e0\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x08\x002\x04\x0c\x12\x18`\xdd\t\x00\x10\x18\x02\x00\x10\x00\x00\x00\xbf]o\xce"
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawframe)

        self.assertEqual(str(radiotap.__class__), "impacket.dot11.RadioTap")

        self.dot11=radiotap.child()
        self.assertEqual(str(self.dot11.__class__), "impacket.dot11.Dot11")

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_REQUEST)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST)
        
        self.management_base=self.dot11.child()
        self.assertEqual(str(self.management_base.__class__), "impacket.dot11.Dot11ManagementFrame")
        
        self.management_association_request=self.management_base.child()
        self.assertEqual(str(self.management_association_request.__class__), "impacket.dot11.Dot11ManagementAssociationRequest")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_association_request.get_header_size(), 68)
	self.assertEqual(self.management_association_request.get_tail_size(), 0)
        
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
        self.assertEqual(self.management_base.get_sequence_control(), 0x8e50)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 2277)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body="1\x04\n\x00\x00\x05ddwrt\x01\x08\x82\x84\x8b\x96$0Hl!\x02\n\x11$\x02\x01\x0e0\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x08\x002\x04\x0c\x12\x18`\xdd\t\x00\x10\x18\x02\x00\x10\x00\x00\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Association Request Capabilities field' 
        self.assertEqual(self.management_association_request.get_capabilities(), 0x0431)
        self.management_association_request.set_capabilities(0x4321) 
        self.assertEqual(self.management_association_request.get_capabilities(), 0x4321)

    def test_11(self):
        'Test Management Association Request Listen Interval field' 
        self.assertEqual(self.management_association_request.get_listen_interval(), 0x000a)
        self.management_association_request.set_listen_interval(0x4321) 
        self.assertEqual(self.management_association_request.get_listen_interval(), 0x4321)

    def test_12(self):
        'Test Management Association Request Ssid getter/setter methods'
        act_ssid="ddwrt"
        new_ssid="holala"
        self.assertEqual(self.management_association_request.get_ssid(), act_ssid)
        self.management_association_request.set_ssid(new_ssid)
        self.assertEqual(self.management_association_request.get_ssid(), new_ssid)
        self.assertEqual(self.management_association_request.get_header_size(), 68+1)

    def test_13(self):
        'Test Management Association Request Supported_rates getter/setter methods'
	self.assertEqual(self.management_association_request.get_supported_rates(), (0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c))
        self.assertEqual(self.management_association_request.get_supported_rates(human_readable=True), (1.0, 2.0, 5.5, 11.0, 18.0, 24.0, 36.0, 54.0))
        
        self.management_association_request.set_supported_rates((0x12, 0x98, 0x24, 0xb0, 0x48, 0x60))

        self.assertEqual(self.management_association_request.get_supported_rates(), (0x12, 0x98, 0x24, 0xb0, 0x48, 0x60))
        self.assertEqual(self.management_association_request.get_supported_rates(human_readable=True), (9.0, 12.0, 18.0, 24.0, 36.0, 48.0))
        self.assertEqual(self.management_association_request.get_header_size(), 68-2)

    def test_14(self):
        'Test Management Association Request RSN getter/setter methods'
	self.assertEqual(self.management_association_request.get_rsn(), "\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x08\x00")
        
        self.management_association_request.set_rsn("\xff\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x08\xff")

        self.assertEqual(self.management_association_request.get_rsn(), "\xff\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x08\xff")
        self.assertEqual(self.management_association_request.get_header_size(), 68)

    def test_15(self):
        'Test Management Vendor Specific getter/setter methods'
        self.assertEqual(self.management_association_request.get_vendor_specific(), [("\x00\x10\x18","\x02\x00\x10\x00\x00\x00")])

        self.management_association_request.add_vendor_specific("\x00\x00\x40", "\x04\x04\x04\x04\x04\x04")

        self.assertEqual(self.management_association_request.get_vendor_specific(), 
            [("\x00\x10\x18", "\x02\x00\x10\x00\x00\x00"),
             ("\x00\x00\x40", "\x04\x04\x04\x04\x04\x04"),
            ])
        self.assertEqual(self.management_association_request.get_header_size(), 68+11)
        
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11ManagementAssociationRequestFrames)
unittest.TextTestRunner(verbosity=1).run(suite)
