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
from impacket.dot11 import Dot11,Dot11Types,Dot11DataFrame,Dot11WPA,Dot11WPAData


class TestDot11WPAData(unittest.TestCase):

    def setUp(self):
        # 802.11 Data Frame 
        #
        self.frame_orig=b'\x08\x42\x00\x00\xff\xff\xff\xff\xff\xff\x00\x21\x29\x68\x33\x5d\x00\x1b\xfc\x1e\xca\x40\xa0\x16\x02\x22\x5a\x60\x00\x00\x00\x00\xa2\x0e\x77\x36\xea\x90\x76\x0f\x7a\x9f\x6e\x6c\x78\xb9\xe0\x3e\xb4\x9d\x09\xca\xde\xef\x95\x58\x28\x97\x17\x46\x53\x43\x41\x2b\x2a\xc6\xbe\xe4\x59\x60\xf0\x17\x1d\x20\x8c\xca\x3c\x26\x0d\x5d\x6b\x10\x81\xbc\xc6\xba\x90\xa5\x77\x0e\x83\xd0\xd0\xb9\xdd\xbf\x80\xbf\x65\x17\xee\xc0\x3a\x52\x32\x34\x75\xac\x0c\xc2\xbb\x25\x28\x8f\x6a\xe6\x96\x7a\x53\x4a\x77\xcc\x2b\xe5\x9a\x9a\x73\xc2\x08\x4c\x42\x15\xe9\x26\xa0\xce\x70\x0e\x50\x9b\x2d\xa2\x6e\xcb\x92\x54\xc0\x6d\xbc\x13\xfe\x4d\xd8\x6b\x8c\x76\x98\x9a\x71\x4d\x51\xb1\xf5\x4f\xe2\x43\x1b\xfa\x6f\x5c\x98\x6a\x3a\x64\x4f\x50\xc4\x09\x7d\x10\x3f\xa2\x64\xd9\xad\x6e\x44\xe3\x84\x3d\x2b\x77\x11\xd8\x04\x9d\x9d\xd4\x32\x35\xe8\x3d\xeb\xd5\x9a\xde\xf3\xb5\x41\x67\x94\xf9\xb1\xe0\x7a\xea\x33\xb2\x00\xef\x6a\x2e\x6c\x3b\xea\x23\x49\x23\xc2\xca\x24\x53\xea\xc0\x7e\x8c\xcf\x73\xcb\x2d\x0c\x8e\xdb\x7b\x9e\x0a\x66\x81\x90'
        d = Dot11(self.frame_orig)
        
        self.assertEqual(d.get_type(),Dot11Types.DOT11_TYPE_DATA)
        self.assertEqual(d.get_subtype(),Dot11Types.DOT11_SUBTYPE_DATA)
        self.assertEqual(d.get_type_n_subtype(),Dot11Types.DOT11_TYPE_DATA_SUBTYPE_DATA)
        
        data = Dot11DataFrame(d.get_body_as_string())
        d.contains(data)
        
        self.wpa_header = Dot11WPA(data.body_string)
        data.contains(self.wpa_header)
        
        self.wpa_data = Dot11WPAData(self.wpa_header.body_string)
        self.wpa_header.contains(self.wpa_data)

    def test_01_is_WPA(self):
        'Test WPAHeader is_WPA method'
        self.assertEqual(self.wpa_header.is_WPA(), True)
        
    def test_03_extIV(self):
        'Test WPAHeader extIV getter and setter methods'
        self.assertEqual(self.wpa_header.get_extIV(), 0x01)
        
        self.wpa_header.set_extIV(0x00) # Es de 1 bit
        self.assertEqual(self.wpa_header.get_extIV(), 0x00)
        
    def test_04_keyid(self):
        'Test WPAHeader keyID getter and setter methods'
        self.assertEqual(self.wpa_header.get_keyid(), 0x01)
        
        self.wpa_header.set_keyid(0x03) # Es de 2 bits
        self.assertEqual(self.wpa_header.get_keyid(), 0x03)
    
    #TODO: Test get_decrypted_data
    #def test_05_get_decrypted_data(self):

    def test_06_WEPSeed(self):
        'Test WPAData WEPSeed getter and setter methods'
        # TSC0
        self.assertEqual(self.wpa_header.get_WEPSeed(), 0x22)
        self.wpa_header.set_WEPSeed(0xAB)
        self.assertEqual(self.wpa_header.get_WEPSeed(), 0xAB)
    
    def test_07_TSCs(self):
        'Test WPAData TSC0 to TSC5 getter and setter methods'
        # TSC0
        self.assertEqual(self.wpa_header.get_TSC0(), 0x5A)
        self.wpa_header.set_TSC0(0xAB)
        self.assertEqual(self.wpa_header.get_TSC0(), 0xAB)

        # TSC1
        self.assertEqual(self.wpa_header.get_TSC1(), 0x02)
        self.wpa_header.set_TSC1(0xAB)
        self.assertEqual(self.wpa_header.get_TSC1(), 0xAB)

        # TSC2
        self.assertEqual(self.wpa_header.get_TSC2(), 0x00)
        self.wpa_header.set_TSC2(0xAB)
        self.assertEqual(self.wpa_header.get_TSC2(), 0xAB)

        # TSC3
        self.assertEqual(self.wpa_header.get_TSC3(), 0x00)
        self.wpa_header.set_TSC3(0xAB)
        self.assertEqual(self.wpa_header.get_TSC3(), 0xAB)

        # TSC4
        self.assertEqual(self.wpa_header.get_TSC4(), 0x00)
        self.wpa_header.set_TSC4(0xAB)
        self.assertEqual(self.wpa_header.get_TSC4(), 0xAB)

        # TSC5
        self.assertEqual(self.wpa_header.get_TSC5(), 0x00)
        self.wpa_header.set_TSC5(0xAB)
        self.assertEqual(self.wpa_header.get_TSC5(), 0xAB)

    def test_08_data(self):
        'Test WPAData body'
        data=b'\xa2\x0e\x77\x36\xea\x90\x76\x0f\x7a\x9f\x6e\x6c\x78\xb9\xe0\x3e\xb4\x9d\x09\xca\xde\xef\x95\x58\x28\x97\x17\x46\x53\x43\x41\x2b\x2a\xc6\xbe\xe4\x59\x60\xf0\x17\x1d\x20\x8c\xca\x3c\x26\x0d\x5d\x6b\x10\x81\xbc\xc6\xba\x90\xa5\x77\x0e\x83\xd0\xd0\xb9\xdd\xbf\x80\xbf\x65\x17\xee\xc0\x3a\x52\x32\x34\x75\xac\x0c\xc2\xbb\x25\x28\x8f\x6a\xe6\x96\x7a\x53\x4a\x77\xcc\x2b\xe5\x9a\x9a\x73\xc2\x08\x4c\x42\x15\xe9\x26\xa0\xce\x70\x0e\x50\x9b\x2d\xa2\x6e\xcb\x92\x54\xc0\x6d\xbc\x13\xfe\x4d\xd8\x6b\x8c\x76\x98\x9a\x71\x4d\x51\xb1\xf5\x4f\xe2\x43\x1b\xfa\x6f\x5c\x98\x6a\x3a\x64\x4f\x50\xc4\x09\x7d\x10\x3f\xa2\x64\xd9\xad\x6e\x44\xe3\x84\x3d\x2b\x77\x11\xd8\x04\x9d\x9d\xd4\x32\x35\xe8\x3d\xeb\xd5\x9a\xde\xf3\xb5\x41\x67\x94\xf9\xb1\xe0\x7a\xea\x33\xb2\x00\xef\x6a\x2e\x6c\x3b\xea\x23\x49\x23\xc2\xca\x24\x53\xea'
        self.assertEqual(self.wpa_data.body_string, data)

    def test_09_mic(self):
        'Test WPAData MIC field'
        mic=b'\xc0\x7e\x8c\xcf\x73\xcb\x2d\x0c'
        #icv=>'\x8e\xdb\x7b\x9e'
        self.assertEqual(self.wpa_data.get_MIC(), mic)

        mic=b'\x01\x02\x03\x04\xff\xfe\xfd\xfc'
        self.wpa_data.set_MIC(mic)
        self.assertEqual(self.wpa_data.get_MIC(), mic)
        self.assertEqual(self.wpa_data.get_icv(), 0x8edb7b9e)
        
    def test_10_get_icv(self):
        'Test WPAData ICV field'
        
        self.assertEqual(self.wpa_data.get_icv(), 0x8edb7b9e)
        

if __name__ == '__main__':
    unittest.main(verbosity=1)
