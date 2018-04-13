#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.dot11 import Dot11,Dot11Types,Dot11DataFrame,Dot11WPA2,Dot11WPA2Data
from binascii import hexlify
import unittest

class TestDot11WPA2Data(unittest.TestCase):

    def setUp(self):
        # 802.11 Data Frame 
        #
        self.frame_orig='\x08\x49\x24\x00\x00\x21\x29\x68\x33\x5d\x00\x15\xaf\xe4\xf1\x0f\x00\x21\x29\x68\x33\x5b\xe0\x31\x1b\x13\x00\x20\x00\x00\x00\x00\x84\x7d\x6a\x30\x8c\x60\x7e\x3b\x22\xdc\x16\xc1\x4b\x28\xd3\x26\x76\x9d\x2e\x59\x96\x31\x3e\x01\x6f\x61\xa2\x59\xc8\xdc\xd3\xc4\xad\x7c\xcc\x32\xa8\x9f\xf6\x03\x02\xe1\xac\x1d\x1e\x02\x8a\xcd\x5b\x94\x20\x2d\xfc\x6e\x37\x40\x2e\x46\x17\x19\x0c\xc0\x34\x07\xae\xe7\x77\xaf\xf9\x9f\x41\x53'
        d = Dot11(self.frame_orig)
        
        self.assertEqual(d.get_type(),Dot11Types.DOT11_TYPE_DATA)
        self.assertEqual(d.get_subtype(),Dot11Types.DOT11_SUBTYPE_DATA)
        self.assertEqual(d.get_type_n_subtype(),Dot11Types.DOT11_TYPE_DATA_SUBTYPE_DATA)
        
        data = Dot11DataFrame(d.get_body_as_string())
        d.contains(data)
        
        self.wpa2_header = Dot11WPA2(data.body_string)
        data.contains(self.wpa2_header)
        
        self.wpa2_data = Dot11WPA2Data(self.wpa2_header.body_string)
        self.wpa2_header.contains(self.wpa2_data)

    def test_01_is_WPA2(self):
        'Test WPA2Header is_WPA2 method'
        self.assertEqual(self.wpa2_header.is_WPA2(), True)
        
    def test_03_extIV(self):
        'Test WPA2Header extIV getter and setter methods'
        self.assertEqual(self.wpa2_header.get_extIV(), 0x01)
        
        self.wpa2_header.set_extIV(0x00) # Es de 1 bit
        self.assertEqual(self.wpa2_header.get_extIV(), 0x00)
        
    def test_04_keyid(self):
        'Test WPA2Header keyID getter and setter methods'
        self.assertEqual(self.wpa2_header.get_keyid(), 0x00)
        
        self.wpa2_header.set_keyid(0x03) # Es de 2 bits
        self.assertEqual(self.wpa2_header.get_keyid(), 0x03)
    
    #TODO: Test get_decrypted_data
    #def test_05_get_decrypted_data(self):
    
    def test_06_PNs(self):
        'Test WPA2Data PN0 to PN5 getter and setter methods'
        # PN0
        self.assertEqual(self.wpa2_header.get_PN0(), 0x1b)
        self.wpa2_header.set_PN0(0xAB)
        self.assertEqual(self.wpa2_header.get_PN0(), 0xAB)

        # PN1
        self.assertEqual(self.wpa2_header.get_PN1(), 0x13)
        self.wpa2_header.set_PN1(0xAB)
        self.assertEqual(self.wpa2_header.get_PN1(), 0xAB)

        # PN2
        self.assertEqual(self.wpa2_header.get_PN2(), 0x00)
        self.wpa2_header.set_PN2(0xAB)
        self.assertEqual(self.wpa2_header.get_PN2(), 0xAB)

        # PN3
        self.assertEqual(self.wpa2_header.get_PN3(), 0x00)
        self.wpa2_header.set_PN3(0xAB)
        self.assertEqual(self.wpa2_header.get_PN3(), 0xAB)

        # PN4
        self.assertEqual(self.wpa2_header.get_PN4(), 0x00)
        self.wpa2_header.set_PN4(0xAB)
        self.assertEqual(self.wpa2_header.get_PN4(), 0xAB)

        # PN5
        self.assertEqual(self.wpa2_header.get_PN5(), 0x00)
        self.wpa2_header.set_PN5(0xAB)
        self.assertEqual(self.wpa2_header.get_PN5(), 0xAB)

    def test_07_data(self):
        'Test WPA2Data body'
        data='\x84\x7d\x6a\x30\x8c\x60\x7e\x3b\x22\xdc\x16\xc1\x4b\x28\xd3\x26\x76\x9d\x2e\x59\x96\x31\x3e\x01\x6f\x61\xa2\x59\xc8\xdc\xd3\xc4\xad\x7c\xcc\x32\xa8\x9f\xf6\x03\x02\xe1\xac\x1d\x1e\x02\x8a\xcd\x5b\x94\x20\x2d\xfc\x6e\x37\x40\x2e\x46\x17\x19' 
        self.assertEqual(self.wpa2_data.body_string, data)

    def test_08_mic(self):
        'Test WPA2Data MIC field'
        mic='\x0c\xc0\x34\x07\xae\xe7\x77\xaf'
        self.assertEqual(self.wpa2_data.get_MIC(), mic)

        mic='\x01\x02\x03\x04\xff\xfe\xfd\xfc'
        self.wpa2_data.set_MIC(mic)
        self.assertEqual(self.wpa2_data.get_MIC(), mic)
        
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11WPA2Data)
unittest.TextTestRunner(verbosity=1).run(suite)

