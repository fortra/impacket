#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from dot11 import ProtocolPacket
from ImpactPacket import ProtocolLayer, PacketBuffer
from binascii import hexlify
import unittest
    
class TestPacket(ProtocolPacket):
    def __init__(self, aBuffer = None):
        header_size = 7
        tail_size = 5
        
        ProtocolPacket.__init__(self, header_size,tail_size)
        if(aBuffer):
            self.load_packet(aBuffer)
            
class TestDot11HierarchicalUpdate(unittest.TestCase):

    def setUp(self):
        self.rawpacket1 = "" \
            "Header1"\
            "Body1"\
            "Tail1"

        self.rawpacket2 = "" \
            "Header2"+\
            self.rawpacket1+ \
            "Tail2"

        self.rawpacket3 = "" \
            "Header3"+\
            self.rawpacket2+ \
            "Tail3"

        self.packet1=TestPacket(self.rawpacket1)
        self.packet2=TestPacket(self.rawpacket2)
        self.packet2.contains(self.packet1)
        self.packet3=TestPacket(self.rawpacket3)
        self.packet3.contains(self.packet2)
        
    def test_01_StartupPacketsStringTest(self):
        "ProtocolPacket - get_packet initial string test"
        self.assertEqual(self.packet1.get_packet(), "Header1Body1Tail1")
        self.assertEqual(self.packet2.get_packet(), "Header2Header1Body1Tail1Tail2")
        self.assertEqual(self.packet3.get_packet(), "Header3Header2Header1Body1Tail1Tail2Tail3")        

    def test_02_StartupPacketsSizeTest(self):
        "ProtocolPacket - Initial size getters test"
        
        self.assertEqual(self.packet1.get_size(), 7+5+5)        
        self.assertEqual(self.packet1.get_header_size(), 7)
        self.assertEqual(self.packet1.get_body_size(), 5)
        self.assertEqual(self.packet1.get_tail_size(), 5)
        
        self.assertEqual(self.packet2.get_size(), 7+ (7+5+5) + 5)
        self.assertEqual(self.packet2.get_header_size(), 7)
        self.assertEqual(self.packet2.get_body_size(), 7+5+5)
        self.assertEqual(self.packet2.get_tail_size(), 5)
        
        self.assertEqual(self.packet3.get_size(), 7+ (7+ (7+5+5) +5) +5 )
        self.assertEqual(self.packet3.get_header_size(), 7)
        self.assertEqual(self.packet3.get_body_size(), 7+ 7+5+5 +5)
        self.assertEqual(self.packet3.get_tail_size(), 5)
    
    def test_03_ChildModificationTest(self):
        "ProtocolPacket - get_packet hierarchical update test"
        self.packet1.load_body("**NewBody**")
        self.assertEqual(self.packet1.get_packet(), "Header1**NewBody**Tail1")
        self.assertEqual(self.packet2.get_packet(), "Header2Header1**NewBody**Tail1Tail2")
        self.assertEqual(self.packet3.get_packet(), "Header3Header2Header1**NewBody**Tail1Tail2Tail3")        
        
    def test_04_ChildModificationTest(self):
        "ProtocolPacket - size getters hierarchical update test"
        self.packet1.load_body("**NewBody**")
        #self.packet1 => "Header1**NewBody**Tail1"
        #self.packet2 => "Header2Header1**NewBody**Tail1Tail2"
        #self.packet3 => "Header3Header2Header1**NewBody**Tail1Tail2Tail3"        
        
        self.assertEqual(self.packet1.get_size(), 7+11+5 )
        self.assertEqual(self.packet1.get_header_size(), 7)
        self.assertEqual(self.packet1.get_body_size(), 11)
        self.assertEqual(self.packet1.get_tail_size(), 5)
        
        self.assertEqual(self.packet2.get_size(), 7+ (7+11+5) +5 )        
        self.assertEqual(self.packet2.get_header_size(), 7)
        self.assertEqual(self.packet2.get_body_size(), 7+11+5)
        self.assertEqual(self.packet2.get_tail_size(), 5)
        
        self.assertEqual(self.packet3.get_size(), 7+ (7+ (7+11+5) +5) +5 )        
        self.assertEqual(self.packet3.get_header_size(), 7)
        self.assertEqual(self.packet3.get_body_size(), 7+ (7+11+5) +5)
        self.assertEqual(self.packet3.get_tail_size(), 5)

    def test_05_ChildModificationTest(self):
        "ProtocolPacket - body packet hierarchical update test"
        self.packet1.load_body("**NewBody**")
        self.assertEqual(self.packet1.body.get_buffer_as_string(), "**NewBody**")
        self.assertEqual(self.packet2.body.get_buffer_as_string(), "Header1**NewBody**Tail1")
        self.assertEqual(self.packet3.body.get_buffer_as_string(), "Header2Header1**NewBody**Tail1Tail2")        

    def test_06_ChildModificationTest(self):
        "ProtocolPacket - get_body_as_string packet hierarchical update test"
        self.packet1.load_body("**NewBody**")
        self.assertEqual(self.packet1.get_body_as_string(), "**NewBody**")
        self.assertEqual(self.packet2.get_body_as_string(), "Header1**NewBody**Tail1")
        self.assertEqual(self.packet3.get_body_as_string(), "Header2Header1**NewBody**Tail1Tail2")        

    def test_07_ChildModificationTest(self):
        "ProtocolPacket - load_body child hierarchy update test"
        self.assertEqual(self.packet1.parent(), self.packet2)
        self.assertEqual(self.packet2.parent(), self.packet3)
        
        self.assertEqual(self.packet3.child(), self.packet2)
        self.assertEqual(self.packet2.child(), self.packet1)
        
        self.packet2.load_body("Header1**NewBody**Tail1")

        self.assertEqual(self.packet1.parent(), None)
        self.assertEqual(self.packet2.parent(), self.packet3)
        
        self.assertEqual(self.packet3.child(), self.packet2)
        self.assertEqual(self.packet2.child(), None)
    
        self.assertEqual(self.packet1.body.get_buffer_as_string(), "Body1")
        self.assertEqual(self.packet2.body.get_buffer_as_string(), "Header1**NewBody**Tail1")
        self.assertEqual(self.packet3.body.get_buffer_as_string(), "Header2Header1**NewBody**Tail1Tail2")        
        
suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11HierarchicalUpdate)
unittest.TextTestRunner(verbosity=2).run(suite)
