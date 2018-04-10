#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.ImpactDecoder import Dot11Decoder #,Dot11Types
from binascii import hexlify
import unittest

class TestDot11Decoder(unittest.TestCase):

    def setUp(self):
	self.WEPKey=None #Unknown
        self.WEPData='\x08\x41\x3a\x01\x00\x17\x3f\x44\x4f\x96\x00\x13\xce\x67\x0e\x73\x00\x17\x3f\x44\x4f\x96\xb0\x04\xeb\xcd\x8b\x00\x6e\xdf\x93\x36\x39\x5a\x39\x66\x6b\x96\xd1\x7a\xe1\xae\xb6\x11\x22\xfd\xf0\xd4\x0d\x6a\xb8\xb1\xe6\x2e\x1f\x25\x7d\x64\x1a\x07\xd5\x86\xd2\x19\x34\xb5\xf7\x8a\x62\x33\x59\x6e\x89\x01\x73\x50\x12\xbb\xde\x17\xdd\xb5\xd4\x35'
        dot11_decoder = Dot11Decoder()
        self.in0=dot11_decoder.decode(self.WEPData)        
        self.in1=self.in0.child()
        self.in2=self.in1.child()
        self.in3=self.in2.child()
	if self.WEPKey:
		self.in4=self.in3.child()
		self.in5=self.in4.child()
        
    def test_01_Dot11Decoder(self):
        'Test Dot11 decoder'
        self.assertEqual(str(self.in0.__class__), "impacket.dot11.Dot11")
        
    def test_02_Dot11DataFrameDecoder(self):
        'Test Dot11DataFrame decoder'
        self.assertEqual(str(self.in1.__class__), "impacket.dot11.Dot11DataFrame")
    
    def test_03_Dot11WEP(self):
        'Test Dot11WEP decoder'
        self.assertEqual(str(self.in2.__class__), "impacket.dot11.Dot11WEP")

    def test_04_Dot11WEPData(self):
        'Test Dot11WEPData decoder'

        if not self.WEPKey:
            return

        self.assertEqual(str(self.in3.__class__), "impacket.dot11.Dot11WEPData")

        # Test if wep data "get_packet" is correct
        wepdata='\x6e\xdf\x93\x36\x39\x5a\x39\x66\x6b\x96\xd1\x7a\xe1\xae\xb6\x11\x22\xfd\xf0\xd4\x0d\x6a\xb8\xb1\xe6\x2e\x1f\x25\x7d\x64\x1a\x07\xd5\x86\xd2\x19\x34\xb5\xf7\x8a\x62\x33\x59\x6e\x89\x01\x73\x50\x12\xbb\xde\x17'
        self.assertEqual(self.in3.get_packet(),wepdata)

    def test_05_LLC(self):
        'Test LLC decoder'
        if self.WEPKey:
            self.assertEqual(str(self.in4.__class__), "impacket.dot11.LLC")

    def test_06_Data(self):
        'Test LLC Data decoder'

        if self.WEPKey:
            dataclass=self.in4.__class__
        else:
            dataclass=self.in3.__class__

        self.assertTrue(str(dataclass).find('ImpactPacket.Data') > 0)
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11Decoder)
unittest.TextTestRunner(verbosity=1).run(suite)

