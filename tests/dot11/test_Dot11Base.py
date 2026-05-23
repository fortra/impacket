#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from impacket.dot11 import Dot11, Dot11Types


class TestDot11Common(unittest.TestCase):

    def setUp(self):
        # Frame control field 
        a=b'\xd4\x00\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e'
        self.dot11fc=Dot11(a)
        self.newVersion = 3
        
    def test_01_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.dot11fc.get_header_size(), 2)

    def test_01_TailSize(self):
        'Test Tail Size field'
        self.assertEqual(self.dot11fc.get_tail_size(), 4)
  
    def test_02_Version(self):
        'Test Version field'
        new_version = 3
        self.assertEqual(self.dot11fc.get_version(), 0)
        self.dot11fc.set_version(new_version)
        self.assertEqual(self.dot11fc.get_version(), new_version)

    def test_03_Type(self):
        'Test Type field'
        new_type = 3
        self.assertEqual(self.dot11fc.get_type(), 1)
        self.dot11fc.set_type(new_type)
        self.assertEqual(self.dot11fc.get_type(), new_type)
    
    def test_04_SubType(self):
        'Test Subtype field'
        new_subtype = 5
        self.assertEqual(self.dot11fc.get_subtype(),13)
        self.dot11fc.set_subtype(new_subtype)
        self.assertEqual(self.dot11fc.get_subtype(),new_subtype)
        
    def test_05_ToDS(self):
        'Test toDS field'
        new_toDS = 1
        self.assertEqual(self.dot11fc.get_toDS(),0)
        self.dot11fc.set_toDS(new_toDS)
        self.assertEqual(self.dot11fc.get_toDS(),new_toDS)

    def test_06_FromDS(self):
        'Test fromDS field'
        new_fromDS = 1
        self.assertEqual(self.dot11fc.get_fromDS(),0)
        self.dot11fc.set_fromDS(new_fromDS)
        self.assertEqual(self.dot11fc.get_fromDS(),new_fromDS)

    def test_07_MoreFrag(self):
        'Test More Frag field'
        new_moreFrag = 1
        self.assertEqual(self.dot11fc.get_moreFrag(),0)
        self.dot11fc.set_moreFrag(new_moreFrag)
        self.assertEqual(self.dot11fc.get_moreFrag(),new_moreFrag)

    def test_08_Retry(self):
        'Test Retry field'
        new_retry = 1
        self.assertEqual(self.dot11fc.get_retry(),0)
        self.dot11fc.set_retry(new_retry)
        self.assertEqual(self.dot11fc.get_retry(),new_retry)

    def test_09_PowerManagement(self):
        'Test Power Management field'
        new_powerManagement = 1
        self.assertEqual(self.dot11fc.get_powerManagement(),0)
        self.dot11fc.set_powerManagement(new_powerManagement)
        self.assertEqual(self.dot11fc.get_powerManagement(),new_powerManagement)

    def test_10_MoreData(self):
        'Test More Data field'
        new_moreData = 1
        self.assertEqual(self.dot11fc.get_moreData(),0)
        self.dot11fc.set_moreData(new_moreData)
        self.assertEqual(self.dot11fc.get_moreData(),new_moreData)

#   def test_11_WEP(self):
#       'Test WEP field'
#       self.assertEqual(self.dot11fc.get_WEP(),0)
#       self.dot11fc.set_WEP(1)
#       self.assertEqual(self.dot11fc.get_WEP(),1)
        
        
    def test_12_Order(self):
        'Test Order field'
        new_order = 1
        self.assertEqual(self.dot11fc.get_order(),0)
        self.dot11fc.set_order(new_order)
        self.assertEqual(self.dot11fc.get_order(),new_order)

    def test_13_latest(self):
        'Test complete frame hexs'
        self.dot11fc.set_type_n_subtype(Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)
        self.dot11fc.set_order(1)
        self.dot11fc.set_moreData(1)
        self.dot11fc.set_retry(1)
        self.dot11fc.set_fromDS(1)
        
        frame=self.dot11fc.get_packet()
        
        self.assertEqual(frame, b'\xa4\xaa\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e')
    

if __name__ == '__main__':
    unittest.main(verbosity=1)
