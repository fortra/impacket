#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Tests for helper used to build ProtocolPackets
#
# Author:
#   Aureliano Calvo
#
import unittest
import impacket.helper as h


class TestHelpers(unittest.TestCase):
    
    def test_well_formed(self):
        class MockPacket(h.ProtocolPacket):
            byte_field = h.Byte(0)
            word_field = h.Word(1, ">")
            three_bytes_field = h.ThreeBytesBigEndian(3)
            long_field = h.Long(6, ">")
            aliased_bit_field = h.Bit(0,0)
            
            header_size = 4
            tail_size = 0
            
        p = MockPacket()
        p.byte_field = 1
        p.word_field = 2
        p.three_bytes_field = 4
        p.long_field = 8
        
        self.assertEqual(p.byte_field, 1)
        self.assertEqual(p.word_field, 2)
        self.assertEqual(p.three_bytes_field, 4)
        self.assertEqual(p.long_field, 8)
        
        self.assertTrue(p.aliased_bit_field)
        
        p.aliased_bit_field = False
        
        self.assertEqual(p.byte_field, 0)
        
        self.assertEqual(p.get_packet(), MockPacket(p.get_packet()).get_packet()) # it is the same packet after reprocessing.
        

if __name__ == '__main__':
    unittest.main(verbosity=1)
