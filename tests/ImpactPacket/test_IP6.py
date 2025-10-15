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
from impacket import IP6, ImpactDecoder


class TestIP6(unittest.TestCase):
        
    def setUp(self):
        #Version 6, traffic class 72, flow label 148997, payload length 1500
        #next header 17 (UDP), hop limit 1
        #source addr FE80::78F8:89D1:30FF:256B
        #dest addr FF02::1:3
        self.binary_packet = [ 
                   0x64, 0x82, 0x46, 0x05, 
                   0x05, 0xdc, 0x11, 0x01, 
                   0xfe, 0x80, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 
                   0x78, 0xf8, 0x89, 0xd1,
                   0x30, 0xff, 0x25, 0x6b, 
                   0xff, 0x02, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x01, 0x00, 0x03]
        
    def test_decoding(self):
        '''Test IP6 Packet decoding.'''
        

        d = ImpactDecoder.IP6Decoder()        
        parsed_packet = d.decode(self.binary_packet)
        
        protocol_version = parsed_packet.get_ip_v()
        traffic_class = parsed_packet.get_traffic_class()
        flow_label = parsed_packet.get_flow_label()
        payload_length = parsed_packet.get_payload_length()
        next_header = parsed_packet.get_next_header()
        hop_limit = parsed_packet.get_hop_limit()
        source_address = parsed_packet.get_ip_src()
        destination_address = parsed_packet.get_ip_dst()
        
        self.assertEqual(protocol_version, 6, "IP6 parsing - Incorrect protocol version")
        self.assertEqual(traffic_class, 72, "IP6 parsing - Incorrect traffic class")
        self.assertEqual(flow_label, 148997, "IP6 parsing - Incorrect flow label")
        self.assertEqual(payload_length, 1500, "IP6 parsing - Incorrect payload length")
        self.assertEqual(next_header, 17, "IP6 parsing - Incorrect next header")
        self.assertEqual(hop_limit, 1, "IP6 parsing - Incorrect hop limit")
        self.assertEqual(source_address.as_string(), "FE80::78F8:89D1:30FF:256B", "IP6 parsing - Incorrect source address")
        self.assertEqual(destination_address.as_string(), "FF02::1:3", "IP6 parsing - Incorrect destination address")
        
    def test_creation(self):
        '''Test IP6 Packet creation.'''
        
        crafted_packet = IP6.IP6()
        crafted_packet.set_traffic_class(72)
        crafted_packet.set_flow_label(148997)
        crafted_packet.set_payload_length(1500)
        crafted_packet.set_next_header(17)
        crafted_packet.set_hop_limit(1)
        crafted_packet.set_ip_src("FE80::78F8:89D1:30FF:256B")
        crafted_packet.set_ip_dst("FF02::1:3")
        crafted_buffer = crafted_packet.get_bytes().tolist()
        self.assertEqual(crafted_buffer, self.binary_packet, "IP6 creation - Buffer mismatch")


if __name__ == '__main__':
    unittest.main(verbosity=1)
