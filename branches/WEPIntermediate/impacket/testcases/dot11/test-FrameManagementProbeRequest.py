#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11, Dot11Types, Dot11ManagementFrame,Dot11ManagementProbeRequest
from ImpactDecoder import RadioTapDecoder
from binascii import hexlify
import unittest

class TestDot11ManagementProbeRequestFrames(unittest.TestCase):

    def setUp(self):
        # 802.11 Management Frame 
        #
        self.rawProbeRequestframe='\x00\x00\x18\x00\x2e\x48\x00\x00\x00\x02\x85\x09\xa0\x00\xda\x01\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x23\x4d\x13\xf9\x1b\xff\xff\xff\xff\xff\xff\x90\x45\x00\x05\x64\x6c\x69\x6e\x6b\x01\x08\x02\x04\x0b\x16\x0c\x12\x18\x24\x32\x04\x30\x48\x60\x6c'
        self.radiotap_decoder = RadioTapDecoder()
        radiotap=self.radiotap_decoder.decode(self.rawProbeRequestframe)
        
        self.assertEqual(str(radiotap.__class__), "dot11.RadioTap")      
                
        self.dot11=radiotap.child()
        self.assertEqual(str(self.dot11.__class__), "dot11.Dot11")   

        type = self.dot11.get_type()
        self.assertEqual(type,Dot11Types.DOT11_TYPE_MANAGEMENT)
        
        subtype = self.dot11.get_subtype()
        self.assertEqual(subtype,Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_REQUEST)
        
        typesubtype = self.dot11.get_type_n_subtype()
        self.assertEqual(typesubtype,Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST)
        
        self.management_base=self.dot11.child()
        self.assertEqual(str(self.management_base.__class__), "dot11.Dot11ManagementFrame")   
        
        self.management_probe_request=self.management_base.child()
        self.assertEqual(str(self.management_probe_request.__class__), "dot11.Dot11ManagementProbeRequest")   
            
        
    def test_01(self):
        'Test Header and Tail Size field'
        self.assertEqual(self.management_base.get_header_size(), 22)
        self.assertEqual(self.management_base.get_tail_size(), 0)
        self.assertEqual(self.management_probe_request.get_header_size(), 23)
        self.assertEqual(self.management_probe_request.get_tail_size(), 0)
        
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
        
        self.assertEqual(addr.tolist(), [0x00,0x23,0x4d,0x13,0xf9,0x1b])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_source_address(addr)
        self.assertEqual(self.management_base.get_source_address().tolist(), [0x12,0x23,0x4d,0x13,0xf9,0x34])

    def test_05(self):
        'Test BSSID Address field'
        
        addr=self.management_base.get_bssid()
        
        self.assertEqual(addr.tolist(), [0xff,0xff,0xff,0xff,0xff,0xff])
        addr[0]=0x12
        addr[5]=0x34
        self.management_base.set_bssid(addr)
        self.assertEqual(self.management_base.get_bssid().tolist(), [0x12,0xff,0xff,0xff,0xff,0x34])

    def test_06(self):
        'Test Sequence control field'
        self.assertEqual(self.management_base.get_sequence_control(), 0x4590)
        self.management_base.set_sequence_control(0x1234)
        self.assertEqual(self.management_base.get_sequence_control(), 0x1234)

    def test_07(self):
        'Test Fragment number field'
        self.assertEqual(self.management_base.get_fragment_number(), 0x00)
        self.management_base.set_fragment_number(0xF1) # Es de 4 bit
        self.assertEqual(self.management_base.get_fragment_number(), 0x01)

    def test_08(self):
        'Test Sequence number field'
        self.assertEqual(self.management_base.get_sequence_number(), 1113)
        self.management_base.set_sequence_number(0xF234) # Es de 12 bit
        self.assertEqual(self.management_base.get_sequence_number(), 0x0234)
        
    def test_09(self):
        'Test Management Frame Data field'
        frame_body="\x00\x05\x64\x6c\x69\x6e\x6b\x01\x08\x02\x04\x0b\x16\x0c\x12\x18\x24\x32\x04\x30\x48\x60\x6c"
        self.assertEqual(self.management_base.get_frame_body(), frame_body)

    def test_10(self):
        'Test Management ssid getter/setter methods'
        act_ssid="dlink"
        new_ssid="holala"
        self.assertEqual(self.management_probe_request.get_ssid(), act_ssid)
        self.management_probe_request.set_ssid(new_ssid)
        self.assertEqual(self.management_probe_request.get_ssid(), new_ssid)
        self.assertEqual(self.management_probe_request.get_header_size(), 23+len(new_ssid)-len(act_ssid))

    def test_11(self):
        'Test Management supported_rates getter/setter methods'
        self.assertEqual(self.management_probe_request.get_supported_rates(), (0x02,0x04,0x0b,0x16,0x0c,0x12,0x18,0x24) )
        self.assertEqual(self.management_probe_request.get_supported_rates(human_readable=True), (1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0) )
        self.management_probe_request.set_supported_rates((0x04,0x0b,0x16,0x0c,0x12,0x18))
        self.assertEqual(self.management_probe_request.get_supported_rates(), (0x04,0x0b,0x16,0x0c,0x12,0x18))
        self.assertEqual(self.management_probe_request.get_supported_rates(human_readable=True), (2.0, 5.5, 11.0, 6.0, 9.0, 12.0) )
        self.assertEqual(self.management_probe_request.get_header_size(), 23-2)

suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11ManagementProbeRequestFrames)
unittest.TextTestRunner(verbosity=2).run(suite)
