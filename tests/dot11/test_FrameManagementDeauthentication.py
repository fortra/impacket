#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from six import PY2
from impacket.dot11 import Dot11Types
from impacket.ImpactDecoder import RadioTapDecoder


class TestDot11ManagementBeaconFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawframe=b'\x00\x00\x10\x00\x6e\x00\x00\x00\x00\x02\x94\x09\xa0\x00\x3a\x00\xc0\x00\x3a\x01\x00\x15\xaf\x64\xac\xbd\x00\x18\x39\xc1\xfc\xe2\x00\x18\x39\xc1\xfc\xe2\x20\x3b\x0f\x00'
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
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_DEAUTHENTICATION)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_DEAUTHENTICATION)
        
        self.management_base=self.dot11.child()
        if PY2:
            self.assertEqual(str(self.management_base.__class__), "impacket.dot11.Dot11ManagementFrame")
        else:
            self.assertEqual(str(self.management_base.__class__), "<class 'impacket.dot11.Dot11ManagementFrame'>")
        
        self.management_deauthentication=self.management_base.child()
        if PY2:
            self.assertEqual(str(self.management_deauthentication.__class__), "impacket.dot11.Dot11ManagementDeauthentication")
        else:
            self.assertEqual(str(self.management_deauthentication.__class__), "<class 'impacket.dot11.Dot11ManagementDeauthentication'>")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_deauthentication.get_header_size(), 2)
        self.assertEqual(self.management_deauthentication.get_tail_size(), 0)
        
    def test_02(self):
        'Test Duration field'
        
        self.assertEqual(self.management_base.get_duration(), 0x013a)
        self.management_base.set_duration(0x1234)
        self.assertEqual(self.management_base.get_duration(), 0x1234)
    
    def test_03(self):
        'Test Destination Address field'
        
        addr=self.management_base.get_destination_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x15,0xAF,0x64,0xAC,0xBD])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_destination_address(addr)
        self.assertEqual(self.management_base.get_destination_address().tolist(), [0x12,0x15,0xAF,0x64,0xAC,0x34])

    def test_04(self):
        'Test Source Address field'
        
        addr=self.management_base.get_source_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0x39,0xC1,0xFC,0xE2])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x18,0x39,0xC1,0xFC,0x34])

    def test_05(self):
        'Test BSSID Address field'
        
        addr=self.management_base.get_bssid()
        
        self.assertEqual(addr.tolist(), [0x00,0x18,0x39,0xC1,0xFC,0xE2])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_bssid(addr)
        self.assertEqual(self.management_base.get_bssid().tolist(), [0x12,0x18,0x39,0xC1,0xFC,0x34])

    def test_06(self):
        'Test Sequence control field'
        self.assertEqual(self.management_base.get_sequence_control(), 0x3b20)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 946)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body=b"\x0f\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Reason Code field' 
        self.assertEqual(self.management_deauthentication.get_reason_code(), 0x000f)
        self.management_deauthentication.set_reason_code(0x8765)
        self.assertEqual(self.management_deauthentication.get_reason_code(), 0x8765)
        

if __name__ == '__main__':
    unittest.main(verbosity=1)
