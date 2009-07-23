#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11,Dot11Types,Dot11DataFrame,RadioTap
from binascii import hexlify
import unittest

class TestRadioTap(unittest.TestCase):

    def setUp(self):
        # Radio Tap(Flags,Rate,Channel,Antenna,DBMAntSignal,_
        #  FCSinHeader)+802.11 Data Frame+LLC SNAP+ARP Reply
        self.frame_orig_1='\x00\x00\x18\x00\x0e\x58\x00\x00\x10\x6c\x6c\x09\x80\x04\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x08\x02\x2c\x00\x00\x1f\xe1\x19\xe4\xe4\x00\x1b\x9e\xce\x54\x09\x00\x1b\x9e\xce\x54\x09\xe0\xac\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x00\x1b\x9e\xce\x54\x09\xc0\xa8\x01\x01\x00\x1f\xe1\x19\xe4\xe4\xc0\xa8\x01\x70\x01\x70\xe0\x00\x00\xfb\x94\x04\x00\x00\x16\x00\x00\x00\xe0\x00\x00\xfb\x17\x5c\xa6\xca'
        self.rt1 = RadioTap(self.frame_orig_1)
        
        # RadioTap(TSTF,Flags,Rate,DBMAntSignal,DBMAntNoise,_
        #  Antenna,XChannel)+802.11 Data Frame+LLC SNAP+ARP Request
        self.frame_orig_2='\x00\x00\x20\x00\x67\x08\x04\x00\x30\x03\x1a\x25\x00\x00\x00\x00\x22\x0c\xd9\xa0\x02\x00\x00\x00\x40\x01\x00\x00\x3c\x14\x24\x11\x08\x02\x00\x00\xff\xff\xff\xff\xff\xff\x06\x03\x7f\x07\xa0\x16\x00\x19\xe3\xd3\x53\x52\x90\x7f\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x19\xe3\xd3\x53\x52\xa9\xfe\xf7\x00\x00\x00\x00\x00\x00\x00\x43\x08\x0e\x36'
        self.rt2 = RadioTap(self.frame_orig_2)

    def test_01_sizes(self):
        'Test RadioTap frame sizes'
        
        self.assertEqual(self.rt1.get_size(), len(self.frame_orig_1))
        self.assertEqual(self.rt1.get_header_size(), 24)
        self.assertEqual(self.rt1.get_body_size(), len(self.frame_orig_1)-24)
        self.assertEqual(self.rt1.get_tail_size(), 0)
        
        self.assertEqual(self.rt2.get_size(), len(self.frame_orig_2))
        self.assertEqual(self.rt2.get_header_size(), 32)
        self.assertEqual(self.rt2.get_body_size(), len(self.frame_orig_2)-32)
        self.assertEqual(self.rt2.get_tail_size(), 0)

    def test_02_version(self):
        'Test RadioTap version getter/setter'
        
        self.assertEqual(self.rt1.get_version(), 0x00)
        self.rt1.set_version(1)
        self.assertEqual(self.rt1.get_version(), 0x01)
        
        self.assertEqual(self.rt2.get_version(), 0x00)
        self.rt2.set_version(1)
        self.assertEqual(self.rt2.get_version(), 0x01)

    def test_03_present(self):
        'Test RadioTap present getter'
        
        self.assertEqual(self.rt1.get_present(), 0x0000580e)

        self.assertEqual(self.rt2.get_present(), 0x00040867)

    def test_04_present_bits(self):
        'Test RadioTap present bits tester'
        
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_TSFT), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_FLAGS), True)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_RATE), True)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_CHANNEL), True)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_FHSS), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DBM_ANTSIGNAL), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DBM_ANTNOISE), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_LOCK_QUALITY), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_TX_ATTENUATION), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DB_TX_ATTENUATION), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DBM_TX_POWER), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_ANTENNA), True)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DB_ANTSIGNAL), True)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DB_ANTNOISE), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_FCS_IN_HEADER), True)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_TX_FLAGS), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_RTS_RETRIES), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_DATA_RETRIES), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_XCHANNEL), False)
        self.assertEqual(self.rt1.get_present_bit(RadioTap.RADIOTAP_EXT), False)

        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_TSFT), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_FLAGS), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_RATE), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_CHANNEL), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_FHSS), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DBM_ANTSIGNAL), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DBM_ANTNOISE), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_LOCK_QUALITY), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_TX_ATTENUATION), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DB_TX_ATTENUATION), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DBM_TX_POWER), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_ANTENNA), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DB_ANTSIGNAL), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DB_ANTNOISE), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_FCS_IN_HEADER), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_TX_FLAGS), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_RTS_RETRIES), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_DATA_RETRIES), False)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_XCHANNEL), True)
        self.assertEqual(self.rt2.get_present_bit(RadioTap.RADIOTAP_EXT), False)

    def test_05_tsft(self):
        'Test RadioTap tstf getter'
        
        self.assertEqual(self.rt1.get_tsft(), None)
        self.assertEqual(self.rt2.get_tsft(), 622461744)

    def test_06_tsft(self):
        'Test RadioTap tstf setter'
        # When the field is new 
        self.assertEqual(self.rt1.get_size(),len(self.frame_orig_1))
        self.assertEqual(self.rt1.get_header_size(),24)
        self.rt1.set_tsft(0x0102030405060708)
        self.assertEqual(self.rt1.get_tsft(),0x0102030405060708)
        self.assertEqual(self.rt1.get_header_size(),24+8)
        
        # When exist the field
        self.rt1.set_tsft(0x0807060504030201)
        self.assertEqual(self.rt1.get_tsft(),0x0807060504030201)
        self.assertEqual(self.rt1.get_header_size(),24+8)

    # Test and conitnue with unset_field


suite = unittest.TestLoader().loadTestsFromTestCase(TestRadioTap)
unittest.TextTestRunner(verbosity=2).run(suite)

