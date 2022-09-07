#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from six import PY2
from impacket.dot11 import Dot11Types
from impacket.ImpactDecoder import RadioTapDecoder


class TestDot11ManagementAssociationResponseFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawframe=b"\x00\x00\x1c\x00\xef\x18\x00\x00\xc2L\xfa\x00<\x00\x00\x00\x10\x02\x85\t\xa0\x00\xb4\x9e_\x00\x00\x16\x10\x00:\x01p\x1a\x04T\xe3\x86\x00\x18\xf8lvB\x00\x18\xf8lvB\xf0\x02\x11\x04\x00\x00\x04\xc0\x01\x08\x82\x84\x8b\x96$0Hl2\x04\x0c\x12\x18`\xdd\t\x00\x10\x18\x02\x02\xf0\x00\x00\x00f%\xdf7"
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawframe)

        if PY2:
            self.assertEqual(str(radiotap.__class__), "impacket.dot11.RadioTap")
        else:
            self.assertEqual(str(radiotap.__class__), "<class 'impacket.dot11.RadioTap'>")

        self.dot11=radiotap.child()
        if PY2:
            self.assertEqual(str(self.dot11.__class__), "impacket.dot11.Dot11")
        else:
            self.assertEqual(str(self.dot11.__class__), "<class 'impacket.dot11.Dot11'>")

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_RESPONSE)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE)
        
        self.management_base=self.dot11.child()
        if PY2:
            self.assertEqual(str(self.management_base.__class__), "impacket.dot11.Dot11ManagementFrame")
        else:
            self.assertEqual(str(self.management_base.__class__), "<class 'impacket.dot11.Dot11ManagementFrame'>")
        
        self.management_association_response=self.management_base.child()
        if PY2:
            self.assertEqual(str(self.management_association_response.__class__), "impacket.dot11.Dot11ManagementAssociationResponse")
        else:
            self.assertEqual(str(self.management_association_response.__class__), "<class 'impacket.dot11.Dot11ManagementAssociationResponse'>")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_association_response.get_header_size(), 33)
        self.assertEqual(self.management_association_response.get_tail_size(), 0)
        
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
        self.assertEqual(self.management_base.get_sequence_control(), 0x02f0)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 47)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body=b"\x11\x04\x00\x00\x04\xc0\x01\x08\x82\x84\x8b\x96$0Hl2\x04\x0c\x12\x18`\xdd\t\x00\x10\x18\x02\x02\xf0\x00\x00\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Association Response Capabilities field' 
        self.assertEqual(self.management_association_response.get_capabilities(), 0x0411)
        self.management_association_response.set_capabilities(0x4321)
        self.assertEqual(self.management_association_response.get_capabilities(), 0x4321)

    def test_11(self):
        'Test Management Association Response Status Code field' 
        self.assertEqual(self.management_association_response.get_status_code(), 0x0000)
        self.management_association_response.set_status_code(0x4321)
        self.assertEqual(self.management_association_response.get_status_code(), 0x4321)

    def test_12(self):
        'Test Management Association Response Association ID field'
        self.assertEqual(self.management_association_response.get_association_id(), 0xc004)
        self.management_association_response.set_association_id(0x4321)
        self.assertEqual(self.management_association_response.get_association_id(), 0x4321)

    def test_13(self):
        'Test Management Association Response Supported_rates getter/setter methods'
        self.assertEqual(self.management_association_response.get_supported_rates(), (0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c))
        self.assertEqual(self.management_association_response.get_supported_rates(human_readable=True), (1.0, 2.0, 5.5, 11.0, 18.0, 24.0, 36.0, 54.0))
        
        self.management_association_response.set_supported_rates((0x12, 0x98, 0x24, 0xb0, 0x48, 0x60))

        self.assertEqual(self.management_association_response.get_supported_rates(), (0x12, 0x98, 0x24, 0xb0, 0x48, 0x60))
        self.assertEqual(self.management_association_response.get_supported_rates(human_readable=True), (9.0, 12.0, 18.0, 24.0, 36.0, 48.0))
        self.assertEqual(self.management_association_response.get_header_size(), 33-2)

    def test_14(self):
        'Test Management Vendor Specific getter/setter methods'
        self.assertEqual(self.management_association_response.get_vendor_specific(), [(b"\x00\x10\x18",b"\x02\x02\xf0\x00\x00\x00")])

        self.management_association_response.add_vendor_specific(b"\x00\x00\x40", b"\x04\x04\x04\x04\x04\x04")

        self.assertEqual(self.management_association_response.get_vendor_specific(), 
            [(b"\x00\x10\x18", b"\x02\x02\xf0\x00\x00\x00"),
             (b"\x00\x00\x40", b"\x04\x04\x04\x04\x04\x04"),
            ])
        self.assertEqual(self.management_association_response.get_header_size(), 33+11)
        

if __name__ == '__main__':
    unittest.main(verbosity=1)
