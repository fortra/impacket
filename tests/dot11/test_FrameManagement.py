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


class TestDot11ManagementBeaconFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawframe=b'\x00\x00\x20\x00\x67\x08\x04\x00\x54\xc6\xb8\x24\x00\x00\x00\x00\x22\x0c\xda\xa0\x02\x00\x00\x00\x40\x01\x00\x00\x3c\x14\x24\x11\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x06\x03\x7f\x07\xa0\x16\x06\x03\x7f\x07\xa0\x16\xb0\x77\x3a\x40\xcb\x26\x00\x00\x00\x00\x64\x00\x01\x05\x00\x0a\x66\x72\x65\x65\x62\x73\x64\x2d\x61\x70\x01\x08\x8c\x12\x98\x24\xb0\x48\x60\x6c\x03\x01\x24\x05\x04\x00\x01\x00\x00\x07\x2a\x55\x53\x20\x24\x01\x11\x28\x01\x11\x2c\x01\x11\x30\x01\x11\x34\x01\x17\x38\x01\x17\x3c\x01\x17\x40\x01\x17\x95\x01\x1e\x99\x01\x1e\x9d\x01\x1e\xa1\x01\x1e\xa5\x01\x1e\x20\x01\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00'
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
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_BEACON)
        
        self.management_base=self.dot11.child()
        if PY2:
            self.assertEqual(str(self.management_base.__class__), "impacket.dot11.Dot11ManagementFrame")
        else:
            self.assertEqual(str(self.management_base.__class__), "<class 'impacket.dot11.Dot11ManagementFrame'>")
        
        self.management_beacon=self.management_base.child()
        if PY2:
            self.assertEqual(str(self.management_beacon.__class__), "impacket.dot11.Dot11ManagementBeacon")
        else:
            self.assertEqual(str(self.management_beacon.__class__), "<class 'impacket.dot11.Dot11ManagementBeacon'>")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_beacon.get_header_size(), 116)
        self.assertEqual(self.management_beacon.get_tail_size(), 0)
        
    def test_02(self):
        'Test Duration field'
        
        self.assertEqual(self.management_base.get_duration(), 0x0000)
        self.management_base.set_duration(0x1234)
        self.assertEqual(self.management_base.get_duration(), 0x1234)
    
    def test_03(self):
        'Test Destination Address field'
        
        addr=self.management_base.get_destination_address()
        
        self.assertEqual(addr.tolist(), [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_destination_address(addr)
        self.assertEqual(self.management_base.get_destination_address().tolist(), [0x12,0xFF,0xFF,0xFF,0xFF,0x34])

    def test_04(self):
        'Test Source Address field'
        
        addr=self.management_base.get_source_address()
        
        self.assertEqual(addr.tolist(), [0x06,0x03,0x7f,0x07,0xa0,0x16])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x03,0x7f,0x07,0xa0,0x34])

    def test_05(self):
        'Test BSSID Address field'
        
        addr=self.management_base.get_bssid()
        
        self.assertEqual(addr.tolist(), [0x06,0x03,0x7f,0x07,0xa0,0x16])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_bssid(addr)
        self.assertEqual(self.management_base.get_bssid().tolist(), [0x12,0x03,0x7f,0x07,0xa0,0x34])

    def test_06(self):
        'Test Sequence control field'
        self.assertEqual(self.management_base.get_sequence_control(), 0x77b0)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 1915)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body=b"\x3a\x40\xcb\x26\x00\x00\x00\x00\x64\x00\x01\x05\x00\x0a\x66\x72\x65\x65\x62\x73\x64\x2d\x61\x70\x01\x08\x8c\x12\x98\x24\xb0\x48\x60\x6c\x03\x01\x24\x05\x04\x00\x01\x00\x00\x07\x2a\x55\x53\x20\x24\x01\x11\x28\x01\x11\x2c\x01\x11\x30\x01\x11\x34\x01\x17\x38\x01\x17\x3c\x01\x17\x40\x01\x17\x95\x01\x1e\x99\x01\x1e\x9d\x01\x1e\xa1\x01\x1e\xa5\x01\x1e\x20\x01\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Beacon Timestamp field' 
        self.assertEqual(self.management_beacon.get_timestamp(), 0x0000000026CB403A)
        self.management_beacon.set_timestamp(0x8765432101234567) 
        self.assertEqual(self.management_beacon.get_timestamp(), 0x8765432101234567)

    def test_11(self):
        'Test Management Beacon Interval field' 
        self.assertEqual(self.management_beacon.get_beacon_interval(), 0x0064)
        self.management_beacon.set_beacon_interval(0x4321) 
        self.assertEqual(self.management_beacon.get_beacon_interval(), 0x4321)

    def test_12(self):
        'Test Management Beacon Capabilities field' 
        self.assertEqual(self.management_beacon.get_capabilities(), 0x0501)
        self.management_beacon.set_capabilities(0x4321) 
        self.assertEqual(self.management_beacon.get_capabilities(), 0x4321)

    def test_13(self):
        'Test Management ssid getter/setter methods'
        act_ssid=b"freebsd-ap"
        new_ssid=b"holala"
        self.assertEqual(self.management_beacon.get_ssid(), act_ssid)
        self.management_beacon.set_ssid(new_ssid)
        self.assertEqual(self.management_beacon.get_ssid(), new_ssid)
        self.assertEqual(self.management_beacon.get_header_size(), 116-4)

    def test_14(self):
        'Test Management supported_rates getter/setter methods'
        self.assertEqual(self.management_beacon.get_supported_rates(), (0x8c,0x12,0x98,0x24,0xb0,0x48,0x60,0x6c) )
        self.assertEqual(self.management_beacon.get_supported_rates(human_readable=True), (6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0) )
        
        self.management_beacon.set_supported_rates((0x12,0x98,0x24,0xb0,0x48,0x60))

        self.assertEqual(self.management_beacon.get_supported_rates(), (0x12,0x98,0x24,0xb0,0x48,0x60) )
        self.assertEqual(self.management_beacon.get_supported_rates(human_readable=True), ( 9.0, 12.0, 18.0, 24.0, 36.0, 48.0) )
        self.assertEqual(self.management_beacon.get_header_size(), 116-2)

    def test_15(self):
        'Test Management DS Parameter Set getter/setter methods'
        self.assertEqual(self.management_beacon.get_ds_parameter_set(), 36 )
        
        self.management_beacon.set_ds_parameter_set(40)

        self.assertEqual(self.management_beacon.get_ds_parameter_set(), 40 )
        self.assertEqual(self.management_beacon.get_header_size(), 116)

    def test_16(self):
        'Test Management Vendor Specific getter/setter methods'
        self.assertEqual(self.management_beacon.get_vendor_specific(), [
            (b"\x00\x50\xf2", b"\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")])

        self.management_beacon.add_vendor_specific(b"\x00\x00\x40",b"\x04\x04\x04\x04\x04\x04")

        self.assertEqual(self.management_beacon.get_vendor_specific(), 
            [(b"\x00\x50\xf2",b"\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"),
             (b"\x00\x00\x40",b"\x04\x04\x04\x04\x04\x04"),
            ])
        self.assertEqual(self.management_beacon.get_header_size(), 127)
        

if __name__ == '__main__':
    unittest.main(verbosity=1)
