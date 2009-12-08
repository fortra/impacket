#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11Types,Dot11DataFrame,Dot11WEP,Dot11WEPData
from binascii import hexlify
import unittest

class TestDot11WEPData(unittest.TestCase):

    def setUp(self):
        # 802.11 Data Frame 
        #
        self.frame_orig='\x08\x41\x3a\x01\x00\x17\x3f\x44\x4f\x96\x00\x13\xce\x67\x0e\x73\x00\x17\x3f\x44\x4f\x96\xb0\x04\xeb\xcd\x8b\x00\x6e\xdf\x93\x36\x39\x5a\x39\x66\x6b\x96\xd1\x7a\xe1\xae\xb6\x11\x22\xfd\xf0\xd4\x0d\x6a\xb8\xb1\xe6\x2e\x1f\x25\x7d\x64\x1a\x07\xd5\x86\xd2\x19\x34\xb5\xf7\x8a\x62\x33\x59\x6e\x89\x01\x73\x50\x12\xbb\xde\x17\xdd\xb5\xd4\x35'
        d = Dot11(self.frame_orig)
        
        self.assertEqual(d.get_type(),Dot11Types.DOT11_TYPE_DATA)
        self.assertEqual(d.get_subtype(),Dot11Types.DOT11_SUBTYPE_DATA)
        self.assertEqual(d.get_type_n_subtype(),Dot11Types.DOT11_TYPE_DATA_SUBTYPE_DATA)
        
        data = Dot11DataFrame(d.get_body_as_string())
        d.contains(data)
        
        self.wep_header = Dot11WEP(data.body_string)
        data.contains(self.wep_header)
        
        self.wep_data = Dot11WEPData(self.wep_header.body_string)
        self.wep_header.contains(self.wep_data)

    def test_01_is_WEP(self):
        'Test WEPHeader is_WEP method'
        self.assertEqual(self.wep_header.is_WEP(), True)
        
    def test_02_get_data(self):
        'Test WEPHeader get_data method'
        data='\xeb\xcd\x8b\x00\x6e\xdf\x93\x36\x39\x5a\x39\x66\x6b\x96\xd1\x7a\xe1\xae\xb6\x11\x22\xfd\xf0\xd4\x0d\x6a\xb8\xb1\xe6\x2e\x1f\x25\x7d\x64\x1a\x07\xd5\x86\xd2\x19\x34\xb5\xf7\x8a\x62\x33\x59\x6e\x89\x01\x73\x50\x12\xbb\xde\x17'
        self.assertEqual(self.wep_header.get_packet(), data)
        
    def test_03_iv(self):
        'Test WEPHeader IV getter and setter methods'
        self.assertEqual(self.wep_header.get_iv(), 0xebcd8b)
        
        self.wep_header.set_iv(0x1e0501) # Es de 24 bit
        self.assertEqual(self.wep_header.get_iv(), 0x1e0501)

    def test_04_keyid(self):
        'Test WEPHeader keyID getter and setter methods'
        self.assertEqual(self.wep_header.get_keyid(), 0x00)
        
        self.wep_header.set_iv(0x03) # Es de 2 bits
        self.assertEqual(self.wep_header.get_iv(), 0x03)
    
    #TODO: Test get_decrypted_data
    #def test_05_get_decrypted_data(self):
    
    def test_06_icv(self):
        'Test WEPData ICV getter and setter methods'
        self.assertEqual(self.wep_data.get_icv(), 0x12bbde17)
        
        self.wep_data.set_icv(0x11223344)
        self.assertEqual(self.wep_data.get_icv(), 0x11223344)

    def test_07_data(self):
        'Test WEPData body'
        self.assertEqual(self.wep_data.body_string, '\x6e\xdf\x93\x36\x39\x5a\x39\x66\x6b\x96\xd1\x7a\xe1\xae\xb6\x11\x22\xfd\xf0\xd4\x0d\x6a\xb8\xb1\xe6\x2e\x1f\x25\x7d\x64\x1a\x07\xd5\x86\xd2\x19\x34\xb5\xf7\x8a\x62\x33\x59\x6e\x89\x01\x73\x50')
        
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11WEPData)
unittest.TextTestRunner(verbosity=2).run(suite)

