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
import impacket.dot11
import impacket.ImpactPacket
from impacket.ImpactDecoder import RadioTapDecoder


class TestRadioTapDecoder(unittest.TestCase):

    def setUp(self):
        self.RadioTapData=b'\x00\x00\x20\x00\x67\x08\x04\x00\x30\x03\x1a\x25\x00\x00\x00\x00\x22\x0c\xd9\xa0\x02\x00\x00\x00\x40\x01\x00\x00\x3c\x14\x24\x11\x08\x02\x00\x00\xff\xff\xff\xff\xff\xff\x06\x03\x7f\x07\xa0\x16\x00\x19\xe3\xd3\x53\x52\x90\x7f\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x19\xe3\xd3\x53\x52\xa9\xfe\xf7\x00\x00\x00\x00\x00\x00\x00\x43\x08\x0e\x36'
        self.radiotap_decoder = RadioTapDecoder()
        self.in0=self.radiotap_decoder.decode(self.RadioTapData)
        self.in1=self.in0.child()
        self.in2=self.in1.child()
        self.in3=self.in2.child()
        self.in4=self.in3.child()
        self.in5=self.in4.child()
        self.in6=self.in5.child()
        
    def test_00(self):
        'Test RadioTap decoder'
        if PY2:
            self.assertEqual(str(self.in0.__class__), "impacket.dot11.RadioTap")
        else:
            self.assertEqual(str(self.in0.__class__), "<class 'impacket.dot11.RadioTap'>")
        
    def test_01(self):
        'Test Dot11 decoder'
        if PY2:
            self.assertEqual(str(self.in1.__class__), "impacket.dot11.Dot11")
        else:
            self.assertEqual(str(self.in1.__class__), "<class 'impacket.dot11.Dot11'>")

    def test_02(self):
        'Test Dot11DataFrame decoder'
        if PY2:
            self.assertEqual(str(self.in2.__class__), "impacket.dot11.Dot11DataFrame")
        else:
            self.assertEqual(str(self.in2.__class__), "<class 'impacket.dot11.Dot11DataFrame'>")
    
    def test_03(self):
        'Test LLC decoder'
        if PY2:
            self.assertEqual(str(self.in3.__class__), "impacket.dot11.LLC")
        else:
            self.assertEqual(str(self.in3.__class__), "<class 'impacket.dot11.LLC'>")

    def test_04(self):
        'Test SNAP decoder'
        if PY2:
            self.assertEqual(str(self.in4.__class__), "impacket.dot11.SNAP")
        else:
            self.assertEqual(str(self.in4.__class__), "<class 'impacket.dot11.SNAP'>")

#    def test_05(self):
#        'Test ARP decoder'
#        self.assertEqual(str(self.in5.__class__), "ImpactPacket.ARP")

#    def test_05(self):
#        'Test Data decoder'
#        self.assertEqual(str(self.in6.__class__), "ImpactPacket.Data")
        
    def test_06(self):
        'Test Protocol Finder'
        p=self.radiotap_decoder.get_protocol(impacket.dot11.RadioTap)
        if PY2:
            self.assertEqual(str(p.__class__), "impacket.dot11.RadioTap")
        else:
            self.assertEqual(str(p.__class__), "<class 'impacket.dot11.RadioTap'>")
                
        p=self.radiotap_decoder.get_protocol(impacket.dot11.Dot11)
        if PY2:
            self.assertEqual(str(p.__class__), "impacket.dot11.Dot11")
        else:
            self.assertEqual(str(p.__class__), "<class 'impacket.dot11.Dot11'>")
        
        p=self.radiotap_decoder.get_protocol(impacket.dot11.Dot11DataFrame)
        if PY2:
            self.assertEqual(str(p.__class__), "impacket.dot11.Dot11DataFrame")
        else:
            self.assertEqual(str(p.__class__), "<class 'impacket.dot11.Dot11DataFrame'>")
        
        p=self.radiotap_decoder.get_protocol(impacket.dot11.LLC)
        if PY2:
            self.assertEqual(str(p.__class__), "impacket.dot11.LLC")
        else:
            self.assertEqual(str(p.__class__), "<class 'impacket.dot11.LLC'>")
        
        p=self.radiotap_decoder.get_protocol(impacket.dot11.SNAP)
        if PY2:
            self.assertEqual(str(p.__class__), "impacket.dot11.SNAP")
        else:
            self.assertEqual(str(p.__class__), "<class 'impacket.dot11.SNAP'>")
        
        #p=self.radiotap_decoder.get_protocol(ImpactPacket.ARP)
        #self.assertEqual(str(p.__class__), "ImpactPacket.ARP")
        
        #p=self.radiotap_decoder.get_protocol(ImpactPacket.Data)
        #self.assertEqual(str(p.__class__), "ImpactPacket.Data")
        
        # When not found, None is returned
        p=self.radiotap_decoder.get_protocol(impacket.dot11.Dot11WPA)
        self.assertEqual(p, None)
      

if __name__ == '__main__':
    unittest.main(verbosity=1)
