#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.dot11 import Dot11, Dot11Types
import unittest

class TestDot11Common(unittest.TestCase):

    def setUp(self):
        # Frame control field 
        a='\xd4\x00\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e'
        self.dot11fc=Dot11(a)
        
    def test_01_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.dot11fc.get_header_size(), 2)

    def test_01_TailSize(self):
        'Test Tail Size field'
        self.assertEqual(self.dot11fc.get_tail_size(), 4)
  
    def test_02_Version(self):
        'Test Version field'
        self.assertEqual(self.dot11fc.get_version(), 0)
        self.dot11fc.set_version(3)
        self.assertEqual(self.dot11fc.get_version(), 3)

    def test_03_Type(self):
        'Test Type field'
        self.assertEqual(self.dot11fc.get_type(), 1)
        self.dot11fc.set_type(3)
        self.assertEqual(self.dot11fc.get_type(), 3)
    
    def test_04_SubType(self):
        'Test Subtype field'
        self.assertEqual(self.dot11fc.get_subtype(),13)
        self.dot11fc.set_subtype(5)
        self.assertEqual(self.dot11fc.get_subtype(),5)
        
    def test_05_ToDS(self):
        'Test toDS field'
        self.assertEqual(self.dot11fc.get_toDS(),0)
        self.dot11fc.set_toDS(1)
        self.assertEqual(self.dot11fc.get_toDS(),1)

    def test_06_FromDS(self):
        'Test fromDS field'
        self.assertEqual(self.dot11fc.get_fromDS(),0)
        self.dot11fc.set_fromDS(1)
        self.assertEqual(self.dot11fc.get_fromDS(),1)

    def test_07_MoreFrag(self):
        'Test More Frag field'
        self.assertEqual(self.dot11fc.get_moreFrag(),0)
        self.dot11fc.set_moreFrag(1)
        self.assertEqual(self.dot11fc.get_moreFrag(),1)

    def test_08_Retry(self):
        'Test Retry field'
        self.assertEqual(self.dot11fc.get_retry(),0)
        self.dot11fc.set_retry(1)
        self.assertEqual(self.dot11fc.get_retry(),1)

    def test_09_PowerManagement(self):
        'Test Power Management field'
        self.assertEqual(self.dot11fc.get_powerManagement(),0)
        self.dot11fc.set_powerManagement(1)
        self.assertEqual(self.dot11fc.get_powerManagement(),1)

    def test_10_MoreData(self):
        'Test More Data field'
        self.assertEqual(self.dot11fc.get_moreData(),0)
        self.dot11fc.set_moreData(1)
        self.assertEqual(self.dot11fc.get_moreData(),1)

#   def test_11_WEP(self):
#       'Test WEP field'
#       self.assertEqual(self.dot11fc.get_WEP(),0)
#       self.dot11fc.set_WEP(1)
#       self.assertEqual(self.dot11fc.get_WEP(),1)
        
        
    def test_12_Order(self):
        'Test Order field'
        self.assertEqual(self.dot11fc.get_order(),0)
        self.dot11fc.set_order(1)
        self.assertEqual(self.dot11fc.get_order(),1)

    def test_13_latest(self):
        'Test complete frame hexs'
        self.dot11fc.set_type_n_subtype(Dot11Types.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)
        self.dot11fc.set_order(1)
        self.dot11fc.set_moreData(1)
        self.dot11fc.set_retry(1)
        self.dot11fc.set_fromDS(1)
        
        frame=self.dot11fc.get_packet()
        
        self.assertEqual(frame, '\xa4\xaa\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e')
    

suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11Common)
unittest.TextTestRunner(verbosity=1).run(suite)
