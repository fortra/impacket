#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.dot11 import Dot11, Dot11Types, Dot11ManagementFrame,Dot11ManagementProbeResponse
from impacket.ImpactDecoder import RadioTapDecoder
from binascii import hexlify
import unittest

class TestDot11ManagementProbeResponseFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawProbeResponseframe='\x00\x00\x18\x00\x2e\x48\x00\x00\x00\x02\x85\x09\xa0\x00\xb0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00\x3a\x01\x00\x21\xfe\x39\x3f\x77\x00\x1b\x11\x32\x66\x23\x00\x1b\x11\x32\x66\x23\x20\x73\x7f\xa0\x22\xf8\x3f\x01\x00\x00\x64\x00\x11\x04\x00\x07\x66\x72\x65\x65\x62\x73\x64\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x06\x2a\x01\x04\x2f\x01\x04\x32\x04\x0c\x12\x18\x60\xdd\x75\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x41\x00\x01\x00\x10\x3b\x00\x01\x03\x10\x47\x00\x10\x11\x4e\xf7\x46\xa9\xc6\xfb\x1d\x70\x1b\x00\x1b\x11\x32\x66\x23\x10\x21\x00\x06\x44\x2d\x4c\x69\x6e\x6b\x10\x23\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x24\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x42\x00\x08\x30\x30\x30\x30\x30\x30\x30\x30\x10\x54\x00\x08\x00\x06\x00\x50\xf2\x04\x00\x01\x10\x11\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x08\x00\x02\x00\x8e\xdd\x05\x00\x50\xf2\x05\x00\xdd\x09\x00\x10\x18\x02\x01\xf0\x00\x00\x00\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x00\x00'
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawProbeResponseframe)

        self.assertEqual(str(radiotap.__class__), "impacket.dot11.RadioTap")

        self.dot11=radiotap.child()
        self.assertEqual(str(self.dot11.__class__), "impacket.dot11.Dot11")

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_RESPONSE)
        
        self.management_base=self.dot11.child()
        self.assertEqual(str(self.management_base.__class__), "impacket.dot11.Dot11ManagementFrame")
        
        self.management_probe_response=self.management_base.child()
        self.assertEqual(str(self.management_probe_response.__class__), "impacket.dot11.Dot11ManagementProbeResponse")
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_probe_response.get_header_size(), 209)
        self.assertEqual(self.management_probe_response.get_tail_size(), 0)
        
    def test_02(self):
        'Test Duration field'
        
        self.assertEqual(self.management_base.get_duration(), 0x013a)
        self.management_base.set_duration(0x1234)
        self.assertEqual(self.management_base.get_duration(), 0x1234)
    
    def test_03(self):
        'Test Destination Address field'
        
        addr=self.management_base.get_destination_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x21,0xFE,0x39,0x3F,0x77])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_destination_address(addr)
        self.assertEqual(self.management_base.get_destination_address().tolist(), [0x12,0x21,0xFE,0x39,0x3F,0x34])

    def test_04(self):
        'Test Source Address field'
        
        addr=self.management_base.get_source_address()
        
        self.assertEqual(addr.tolist(), [0x00,0x1B,0x11,0x32,0x66,0x23])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x1B,0x11,0x32,0x66,0x34])

    def test_05(self):
        'Test BSSID Address field'
        
        addr=self.management_base.get_bssid()
        
        self.assertEqual(addr.tolist(), [0x00,0x1B,0x11,0x32,0x66,0x23])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_bssid(addr)
        self.assertEqual(self.management_base.get_bssid().tolist(), [0x12,0x1B,0x11,0x32,0x66,0x34])

    def test_06(self):
        'Test Sequence control field'
        self.assertEqual(self.management_base.get_sequence_control(), 0x7320)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # It's 4 bits long
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 1842)
        self.management_base.set_sequence_number(0xF234) # It's 12 bits long
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body="\x7f\xa0\x22\xf8\x3f\x01\x00\x00\x64\x00\x11\x04\x00\x07\x66\x72\x65\x65\x62\x73\x64\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x06\x2a\x01\x04\x2f\x01\x04\x32\x04\x0c\x12\x18\x60\xdd\x75\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x41\x00\x01\x00\x10\x3b\x00\x01\x03\x10\x47\x00\x10\x11\x4e\xf7\x46\xa9\xc6\xfb\x1d\x70\x1b\x00\x1b\x11\x32\x66\x23\x10\x21\x00\x06\x44\x2d\x4c\x69\x6e\x6b\x10\x23\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x24\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x42\x00\x08\x30\x30\x30\x30\x30\x30\x30\x30\x10\x54\x00\x08\x00\x06\x00\x50\xf2\x04\x00\x01\x10\x11\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x08\x00\x02\x00\x8e\xdd\x05\x00\x50\xf2\x05\x00\xdd\x09\x00\x10\x18\x02\x01\xf0\x00\x00\x00\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x00\x00"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management Beacon Timestamp field' 
        self.assertEqual(self.management_probe_response.get_timestamp(), 0x0000013FF822A07F)
        self.management_probe_response.set_timestamp(0x8765432101234567) 
        self.assertEqual(self.management_probe_response.get_timestamp(), 0x8765432101234567)

    def test_11(self):
        'Test Management Beacon Interval field' 
        self.assertEqual(self.management_probe_response.get_beacon_interval(), 0x0064)
        self.management_probe_response.set_beacon_interval(0x4321) 
        self.assertEqual(self.management_probe_response.get_beacon_interval(), 0x4321)

    def test_12(self):
        'Test Management Beacon Capabilities field' 
        self.assertEqual(self.management_probe_response.get_capabilities(), 0x0411)
        self.management_probe_response.set_capabilities(0x4321) 
        self.assertEqual(self.management_probe_response.get_capabilities(), 0x4321)

    def test_13(self):
        'Test Management ssid getter/setter methods'
        act_ssid="freebsd"
        new_ssid="holala"
        self.assertEqual(self.management_probe_response.get_ssid(), act_ssid)
        self.management_probe_response.set_ssid(new_ssid)
        self.assertEqual(self.management_probe_response.get_ssid(), new_ssid)
        self.assertEqual(self.management_probe_response.get_header_size(), 209-1)

    def test_14(self):
        'Test Management supported_rates getter/setter methods'
        self.assertEqual(self.management_probe_response.get_supported_rates(), (0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c) )
        self.assertEqual(self.management_probe_response.get_supported_rates(human_readable=True), (1.0, 2.0, 5.5, 11.0, 18.0, 24.0, 36.0, 54.0 ) )
        
        self.management_probe_response.set_supported_rates((0x84,0x8b,0x96,0x24,0x30,0x48))

        self.assertEqual(self.management_probe_response.get_supported_rates(), (0x84,0x8b,0x96,0x24,0x30,0x48) )
        self.assertEqual(self.management_probe_response.get_supported_rates(human_readable=True), ( 2.0, 5.5, 11.0, 18.0, 24.0, 36.0 ) )
        self.assertEqual(self.management_probe_response.get_header_size(), 209-2)

    def test_15(self):
        'Test Management DS Parameter Set getter/setter methods'
        self.assertEqual(self.management_probe_response.get_ds_parameter_set(), 6 )
        
        self.management_probe_response.set_ds_parameter_set(40)

        self.assertEqual(self.management_probe_response.get_ds_parameter_set(), 40 )
        self.assertEqual(self.management_probe_response.get_header_size(), 209)

    def test_16(self):
        'Test Management Vendor Specific getter/setter methods'
        self.assertEqual(self.management_probe_response.get_vendor_specific(), 
            [("\x00\x50\xf2", "\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x41\x00\x01\x00\x10\x3b\x00\x01\x03\x10\x47\x00\x10\x11\x4e\xf7\x46\xa9\xc6\xfb\x1d\x70\x1b\x00\x1b\x11\x32\x66\x23\x10\x21\x00\x06\x44\x2d\x4c\x69\x6e\x6b\x10\x23\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x24\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x42\x00\x08\x30\x30\x30\x30\x30\x30\x30\x30\x10\x54\x00\x08\x00\x06\x00\x50\xf2\x04\x00\x01\x10\x11\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x08\x00\x02\x00\x8e"),
             ("\x00\x50\xf2", "\x05\x00"),
             ("\x00\x10\x18","\x02\x01\xf0\x00\x00\x00"),
             ("\x00\x50\xf2","\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x00\x00"),
            ])
        
        self.management_probe_response.add_vendor_specific("\x00\x00\x40","\x04\x04\x04\x04\x04\x04")

        self.assertEqual(self.management_probe_response.get_vendor_specific(), 
            [("\x00\x50\xf2","\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x41\x00\x01\x00\x10\x3b\x00\x01\x03\x10\x47\x00\x10\x11\x4e\xf7\x46\xa9\xc6\xfb\x1d\x70\x1b\x00\x1b\x11\x32\x66\x23\x10\x21\x00\x06\x44\x2d\x4c\x69\x6e\x6b\x10\x23\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x24\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x42\x00\x08\x30\x30\x30\x30\x30\x30\x30\x30\x10\x54\x00\x08\x00\x06\x00\x50\xf2\x04\x00\x01\x10\x11\x00\x07\x44\x49\x52\x2d\x33\x32\x30\x10\x08\x00\x02\x00\x8e"),
             ("\x00\x50\xf2","\x05\x00"),
             ("\x00\x10\x18","\x02\x01\xf0\x00\x00\x00"),
             ("\x00\x50\xf2","\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x00\x00"),
             ("\x00\x00\x40","\x04\x04\x04\x04\x04\x04"),
            ])
        self.assertEqual(self.management_probe_response.get_header_size(), 209+6+3+2)
        
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11ManagementProbeResponseFrames)
unittest.TextTestRunner(verbosity=1).run(suite)
