#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import Dot11
from binascii import hexlify
import unittest

class TestDot11Common(unittest.TestCase):

    def setUp(self):
        # Frame control field 
        a='\xd4\x00\x00\x00\x00\x08\x54\xac\x2f\x85\xb7\x7f\xc3\x9e'
        self.dot11fc=Dot11(a)
        
    def test_01_HeaderSize(self):
        'Test Header Size field'
        self.assertEqual(self.dot11fc.get_header_size(), 2)
  
    def test_02_Version(self):
        'Test Version field'
        self.assertEqual(self.dot11fc.get_version_field(), 0)
        self.dot11fc.set_version_field(3)
        self.assertEqual(self.dot11fc.get_version_field(), 3)

    def test_03_Type(self):
        'Test Type field'
        self.assertEqual(self.dot11fc.get_type_field(), 1)
        self.dot11fc.set_type_field(3)
        self.assertEqual(self.dot11fc.get_type_field(), 3)
    
    def test_04_SubType(self):
        'Test Subtype field'
        self.assertEqual(self.dot11fc.get_subtype_field(),13)
        self.dot11fc.set_subtype_field(5)
        self.assertEqual(self.dot11fc.get_subtype_field(),5)
        
    def test_05_ToDS(self):
        'Test toDS field'
        self.assertEqual(self.dot11fc.get_toDS_field(),0)
        self.dot11fc.set_toDS_field(1)
        self.assertEqual(self.dot11fc.get_toDS_field(),1)

    def test_06_FromDS(self):
        'Test fromDS field'
        self.assertEqual(self.dot11fc.get_fromDS_field(),0)
        self.dot11fc.set_fromDS_field(1)
        self.assertEqual(self.dot11fc.get_fromDS_field(),1)

    def test_07_MoreFrag(self):
        'Test More Frag field'
        self.assertEqual(self.dot11fc.get_moreFrag_field(),0)
        self.dot11fc.set_moreFrag_field(1)
        self.assertEqual(self.dot11fc.get_moreFrag_field(),1)

    def test_08_Retry(self):
        'Test Retry field'
        self.assertEqual(self.dot11fc.get_retry_field(),0)
        self.dot11fc.set_retry_field(1)
        self.assertEqual(self.dot11fc.get_retry_field(),1)

    def test_09_PowerManagement(self):
        'Test Power Management field'
        self.assertEqual(self.dot11fc.get_powerManagement_field(),0)
        self.dot11fc.set_powerManagement_field(1)
        self.assertEqual(self.dot11fc.get_powerManagement_field(),1)

    def test_10_MoreData(self):
        'Test More Data field'
        self.assertEqual(self.dot11fc.get_moreData_field(),0)
        self.dot11fc.set_moreData_field(1)
        self.assertEqual(self.dot11fc.get_moreData_field(),1)

#   def test_11_WEP(self):
#       'Test WEP field'
#       self.assertEqual(self.dot11fc.get_WEP_field(),0)
#       self.dot11fc.set_WEP_field(1)
#       self.assertEqual(self.dot11fc.get_WEP_field(),1)
        
        
    def test_12_Order(self):
        'Test Order field'
        self.assertEqual(self.dot11fc.get_order_field(),0)
        self.dot11fc.set_order_field(1)
        self.assertEqual(self.dot11fc.get_order_field(),1)

    def test_13_latest(self):
        'Test complete frame hexs'
        self.dot11fc.set_type_n_subtype_field(Dot11.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)
        self.dot11fc.set_order_field(1)
        self.dot11fc.set_moreData_field(1)
        self.dot11fc.set_retry_field(1)
        self.dot11fc.set_fromDS_field(1)
        
        frame=self.dot11fc.get_packet()
        self.assertEqual(frame, '\xa4\xaa')


suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11Common)
unittest.TextTestRunner(verbosity=2).run(suite)
