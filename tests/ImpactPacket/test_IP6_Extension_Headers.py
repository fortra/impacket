#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
from __future__ import division
from __future__ import print_function
import unittest
from six import PY2

from impacket import IP6, ImpactDecoder, IP6_Extension_Headers


class TestIP6(unittest.TestCase):
    def string_to_list(self, bytes):
        if PY2:
            return list(map(ord, list(bytes)))
        else:
            return list(bytes)

    def test_create_simple_hop_by_hop(self):
        hop_by_hop_binary_packet = [0x3a, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]

        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop()
        hop_by_hop.set_next_header(58)

        self.assertEqual(
            self.string_to_list(hop_by_hop.get_packet()), hop_by_hop_binary_packet, 
            "Simple Hop By Hop Header creation - Buffer mismatch")
        
        self.assertEqual(
            hop_by_hop.get_size(), len(hop_by_hop_binary_packet),
            "Simple Hop By Hop Header creation - Size mismatch")
    
    def test_simple_hop_by_hop_contained_in_ipv6(self):
        ipv6_binary_packet = [ 
               0x64, 0x82, 0x46, 0x05, 
               0x05, 0xdc, 0x00, 0x01, 
               0xfe, 0x80, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x78, 0xf8, 0x89, 0xd1,
               0x30, 0xff, 0x25, 0x6b, 
               0xff, 0x02, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x00, 0x01, 0x00, 0x03]
        
        hop_by_hop_binary_packet = [
               0x3a, 0x00, 0x01, 0x04,
               0x00, 0x00, 0x00, 0x00]

        binary_packet = ipv6_binary_packet + hop_by_hop_binary_packet
        
        ip6_packet = IP6.IP6()
        ip6_packet.set_traffic_class(72)
        ip6_packet.set_flow_label(148997)
        ip6_packet.set_payload_length(1500)
        ip6_packet.set_next_header(17)
        ip6_packet.set_hop_limit(1)
        ip6_packet.set_ip_src("FE80::78F8:89D1:30FF:256B")
        ip6_packet.set_ip_dst("FF02::1:3")
        
        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop()
        hop_by_hop.set_next_header(58)

        ip6_packet.contains(hop_by_hop)

        self.assertEqual(
            self.string_to_list(ip6_packet.get_packet()), binary_packet, 
            "IP6 Hop By Hop Header contained in IPv6 Header - Buffer mismatch")

        self.assertEqual(
            ip6_packet.get_size(), len(binary_packet),
            "IP6 Hop By Hop Header contained in IPv6 Header - Size mismatch")

    def test_add_option_to_hop_by_hop(self):
        hop_by_hop_binary_packet = [
            0x3a, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]

        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop()
        hop_by_hop.set_next_header(58)
        hop_by_hop.add_option(IP6_Extension_Headers.Option_PADN(14))

        self.assertEqual(
            self.string_to_list(hop_by_hop.get_packet()), hop_by_hop_binary_packet, 
            "Add Option to Hop By Hop Header - Buffer mismatch")

        self.assertEqual(
            hop_by_hop.get_size(), len(hop_by_hop_binary_packet),
            "Add Option to Hop By Hop Header - Size mismatch")

    def test_pad_hop_by_hop_when_adding_option(self):
        hop_by_hop_binary_packet = [
            0x3a, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]

        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop()
        hop_by_hop.set_next_header(58)
        hop_by_hop.add_option(IP6_Extension_Headers.Option_PAD1())

        self.assertEqual(
            self.string_to_list(hop_by_hop.get_packet()), hop_by_hop_binary_packet, 
            "Pad Hop By Hop Header when adding option - Buffer mismatch")

        self.assertEqual(
            hop_by_hop.get_size(), len(hop_by_hop_binary_packet),
            "Pad Hop By Hop Header when adding option - Size mismatch")

    def test_create_simple_dest_opts(self):
        dest_opts_binary_packet = [0x3a, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]

        dest_opts = IP6_Extension_Headers.Destination_Options()
        dest_opts.set_next_header(58)
        
        self.assertEqual(
            self.string_to_list(dest_opts.get_packet()), dest_opts_binary_packet, 
            "Simple Destination Options Header creation - Buffer mismatch")

        self.assertEqual(
            dest_opts.get_size(), len(dest_opts_binary_packet),
            "Simple Destination Options Header creation - Size mismatch")

    def test_simple_dest_opts_contained_in_ipv6(self):
        ipv6_binary_packet = [ 
               0x64, 0x82, 0x46, 0x05, 
               0x05, 0xdc, 0x3c, 0x01, 
               0xfe, 0x80, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x78, 0xf8, 0x89, 0xd1,
               0x30, 0xff, 0x25, 0x6b, 
               0xff, 0x02, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x00, 0x01, 0x00, 0x03]
        
        dest_opts_binary_packet = [
               0x3a, 0x00, 0x01, 0x04,
               0x00, 0x00, 0x00, 0x00]

        binary_packet = ipv6_binary_packet + dest_opts_binary_packet
        
        ip6_packet = IP6.IP6()
        ip6_packet.set_traffic_class(72)
        ip6_packet.set_flow_label(148997)
        ip6_packet.set_payload_length(1500)
        ip6_packet.set_next_header(17)
        ip6_packet.set_hop_limit(1)
        ip6_packet.set_ip_src("FE80::78F8:89D1:30FF:256B")
        ip6_packet.set_ip_dst("FF02::1:3")
        
        dest_opts = IP6_Extension_Headers.Destination_Options()
        dest_opts.set_next_header(58)

        ip6_packet.contains(dest_opts)

        self.assertEqual(
            self.string_to_list(ip6_packet.get_packet()), binary_packet, 
            "IP6 Destination Options Header contained in IPv6 Header - Buffer mismatch")

        self.assertEqual(
            ip6_packet.get_size(), len(binary_packet),
            "IP6 Destination Options Header contained in IPv6 Header - Size mismatch")

    def test_add_option_to_dest_opts(self):
        dest_opts_binary_packet = [
            0x3a, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]

        dest_opts = IP6_Extension_Headers.Destination_Options()
        dest_opts.set_next_header(58)
        dest_opts.add_option(IP6_Extension_Headers.Option_PADN(14))

        self.assertEqual(
            self.string_to_list(dest_opts.get_packet()), dest_opts_binary_packet, 
            "Add Option to Destination Options Header - Buffer mismatch")

        self.assertEqual(
            dest_opts.get_size(), len(dest_opts_binary_packet),
            "Add Option to Destination Options Header - Size mismatch")

    def test_pad_dest_opts_when_adding_option(self):
        dest_opts_binary_packet = [
            0x3a, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]

        dest_opts = IP6_Extension_Headers.Destination_Options()
        dest_opts.set_next_header(58)
        dest_opts.add_option(IP6_Extension_Headers.Option_PAD1())

        self.assertEqual(
            self.string_to_list(dest_opts.get_packet()), dest_opts_binary_packet, 
            "Pad Destination Options Header when adding option - Buffer mismatch")

        self.assertEqual(
            dest_opts.get_size(), len(dest_opts_binary_packet),
            "Pad Destination Options Header when adding option - Size mismatch")

    def test_create_simple_routing_options(self):
        routing_options_binary_packet = [0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

        routing_options = IP6_Extension_Headers.Routing_Options()
        routing_options.set_next_header(58)
        
        self.assertEqual(
            self.string_to_list(routing_options.get_packet()), routing_options_binary_packet, 
            "Simple Routing Options Header creation - Buffer mismatch")
        
        self.assertEqual(
            routing_options.get_size(), len(routing_options_binary_packet),
            "Simple Routing Options Header creation - Size mismatch")
    
    def test_simple_routing_options_contained_in_ipv6(self):
        ipv6_binary_packet = [ 
               0x64, 0x82, 0x46, 0x05, 
               0x05, 0xdc, 0x2b, 0x01, 
               0xfe, 0x80, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x78, 0xf8, 0x89, 0xd1,
               0x30, 0xff, 0x25, 0x6b, 
               0xff, 0x02, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x00, 0x00, 0x00, 0x00, 
               0x00, 0x01, 0x00, 0x03]
        
        routing_options_binary_packet = [
               0x3a, 0x00, 0x00, 0x0a,
               0x00, 0x00, 0x00, 0x00]

        binary_packet = ipv6_binary_packet + routing_options_binary_packet
        
        ip6_packet = IP6.IP6()
        ip6_packet.set_traffic_class(72)
        ip6_packet.set_flow_label(148997)
        ip6_packet.set_payload_length(1500)
        ip6_packet.set_next_header(17)
        ip6_packet.set_hop_limit(1)
        ip6_packet.set_ip_src("FE80::78F8:89D1:30FF:256B")
        ip6_packet.set_ip_dst("FF02::1:3")
        
        routing_options = IP6_Extension_Headers.Routing_Options()
        routing_options.set_next_header(58)
        routing_options.set_routing_type(0)
        routing_options.set_segments_left(10)

        ip6_packet.contains(routing_options)

        self.assertEqual(
            self.string_to_list(ip6_packet.get_packet()), binary_packet, 
            "IP6 Hop By Hop Header contained in IPv6 Header - Buffer mismatch")

        self.assertEqual(
            ip6_packet.get_size(), len(binary_packet),
            "IP6 Hop By Hop Header contained in IPv6 Header - Size mismatch")

    def test_chained_basic_options(self):
        dest_opts_binary_packet = [
            0x2b, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]

        routing_options_binary_packet = [
           0x00, 0x00, 0x00, 0x0a,
           0x00, 0x00, 0x00, 0x00]

        hop_by_hop_binary_packet = [
            0x3a, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]

        binary_packet = dest_opts_binary_packet + routing_options_binary_packet + hop_by_hop_binary_packet

        dest_opts = IP6_Extension_Headers.Destination_Options()
        dest_opts.add_option(IP6_Extension_Headers.Option_PAD1())

        routing_options = IP6_Extension_Headers.Routing_Options()
        routing_options.set_next_header(58)
        routing_options.set_routing_type(0)
        routing_options.set_segments_left(10)

        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop()
        hop_by_hop.add_option(IP6_Extension_Headers.Option_PADN(14))
        
        dest_opts.contains(routing_options)
        routing_options.contains(hop_by_hop)
        hop_by_hop.set_next_header(58)

        self.assertEqual(
            self.string_to_list(dest_opts.get_packet()), binary_packet, 
            "Chained options - Buffer mismatch")

        self.assertEqual(
            dest_opts.get_size(), len(binary_packet),
            "Chained options - Size mismatch")

    def test_chained_basic_options_inside_ipv6_packet(self):
        ipv6_binary_packet = [ 
           0x64, 0x82, 0x46, 0x05, 
           0x05, 0xdc, 0x00, 0x01, 
           0xfe, 0x80, 0x00, 0x00, 
           0x00, 0x00, 0x00, 0x00, 
           0x78, 0xf8, 0x89, 0xd1,
           0x30, 0xff, 0x25, 0x6b, 
           0xff, 0x02, 0x00, 0x00, 
           0x00, 0x00, 0x00, 0x00, 
           0x00, 0x00, 0x00, 0x00, 
           0x00, 0x01, 0x00, 0x03]
        
        hop_by_hop_binary_packet = [
            0x2b, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]

        routing_options_binary_packet = [
           0x3c, 0x00, 0x00, 0x0a,
           0x00, 0x00, 0x00, 0x00]

        dest_opts_binary_packet = [
            0x3a, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]

        binary_packet = ipv6_binary_packet + hop_by_hop_binary_packet + routing_options_binary_packet + dest_opts_binary_packet
        
        ip6_packet = IP6.IP6()
        ip6_packet.set_traffic_class(72)
        ip6_packet.set_flow_label(148997)
        ip6_packet.set_payload_length(1500)
        ip6_packet.set_next_header(17)
        ip6_packet.set_hop_limit(1)
        ip6_packet.set_ip_src("FE80::78F8:89D1:30FF:256B")
        ip6_packet.set_ip_dst("FF02::1:3")
        
        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop()
        hop_by_hop.add_option(IP6_Extension_Headers.Option_PADN(14))
  
        routing_options = IP6_Extension_Headers.Routing_Options()
        routing_options.set_next_header(58)
        routing_options.set_routing_type(0)
        routing_options.set_segments_left(10)
      
        dest_opts = IP6_Extension_Headers.Destination_Options()
        dest_opts.add_option(IP6_Extension_Headers.Option_PAD1())

        ip6_packet.contains(hop_by_hop)
        hop_by_hop.contains(routing_options)
        routing_options.contains(dest_opts)
        dest_opts.set_next_header(58)

        self.assertEqual(
            self.string_to_list(ip6_packet.get_packet()), binary_packet, 
            "Chained options inside an IPv6 packet - Buffer mismatch")

        self.assertEqual(
            ip6_packet.get_size(), len(binary_packet),
            "Chained options inside an IPv6 packet - Size mismatch")

    def test_decoding_simple_hop_by_hop(self):
        hop_by_hop_binary_packet = [
            0x2b, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]
        
        d = ImpactDecoder.HopByHopDecoder()        
        parsed_packet = d.decode(hop_by_hop_binary_packet)
        
        next_header = parsed_packet.get_next_header()
        header_extension_length = parsed_packet.get_header_extension_length()
        options = parsed_packet.get_options()
        
        self.assertEqual(1, len(options), "Simple Hop By Hop Parsing - Wrong Quantity of Options")
        
        padn_option = options[0]
        padn_option_type = padn_option.get_option_type()
        padn_option_length = padn_option.get_option_length()
        
        self.assertEqual(parsed_packet.get_header_type(), 0, "Simple Hop By Hop Parsing - Incorrect packet")
        self.assertEqual(next_header, 43, "Simple Hop By Hop Parsing - Incorrect next header value")
        self.assertEqual(header_extension_length, 1, "Simple Hop By Hop Parsing - Incorrect size")
        self.assertEqual(padn_option_type, 1, "Simple Hop By Hop Parsing - Incorrect option type")
        self.assertEqual(padn_option_length, 12, "Simple Hop By Hop Parsing - Incorrect option size")

    def test_decoding_multi_option_hop_by_hop(self):
        hop_by_hop_binary_packet = [
            0x3a, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]
        
        d = ImpactDecoder.HopByHopDecoder()        
        parsed_packet = d.decode(hop_by_hop_binary_packet)
        
        next_header = parsed_packet.get_next_header()
        header_extension_length = parsed_packet.get_header_extension_length()
        options = parsed_packet.get_options()
        
        self.assertEqual(2, len(options), "Simple Hop By Hop Parsing - Wrong Quantity of Options")
        
        pad1_option = options[0]
        pad1_option_type = pad1_option.get_option_type()
        
        padn_option = options[1]
        padn_option_type = padn_option.get_option_type()
        padn_option_length = padn_option.get_option_length()
        
        self.assertEqual(parsed_packet.get_header_type(), 0, "Hop By Hop with multiple options parsing - Incorrect packet")
        self.assertEqual(next_header, 58, "Hop By Hop with multiple options parsing - Incorrect next header value")
        self.assertEqual(header_extension_length, 0, "Hop By Hop with multiple options parsing - Incorrect size")
        self.assertEqual(pad1_option_type, 0, "Hop By Hop with multiple options parsing - Incorrect option type")
        self.assertEqual(padn_option_type, 1, "Hop By Hop with multiple options parsing - Incorrect option type")
        self.assertEqual(padn_option_length, 3, "Hop By Hop with multiple options parsing - Incorrect option size")

    def test_decoding_simple_destination_options(self):
        destination_options_binary_packet = [
            0x2b, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]
        
        d = ImpactDecoder.DestinationOptionsDecoder()        
        parsed_packet = d.decode(destination_options_binary_packet)
        
        next_header = parsed_packet.get_next_header()
        header_extension_length = parsed_packet.get_header_extension_length()
        options = parsed_packet.get_options()
        
        self.assertEqual(1, len(options), "Simple Destination Options Parsing - Wrong Quantity of Options")
        
        padn_option = options[0]
        padn_option_type = padn_option.get_option_type()
        padn_option_length = padn_option.get_option_length()
        
        self.assertEqual(parsed_packet.get_header_type(), 60, "Simple Destination Options Parsing - Incorrect packet")
        self.assertEqual(next_header, 43, "Simple Destination Options Parsing - Incorrect next header value")
        self.assertEqual(header_extension_length, 1, "Simple Destination Options Parsing - Incorrect size")
        self.assertEqual(padn_option_type, 1, "Simple Destination Options Parsing - Incorrect option type")
        self.assertEqual(padn_option_length, 12, "Simple Destination Options Parsing - Incorrect option size")

    def test_decoding_multi_option_destination_options(self):
        destination_options_binary_packet = [
            0x3a, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]
        
        d = ImpactDecoder.DestinationOptionsDecoder()        
        parsed_packet = d.decode(destination_options_binary_packet)
        
        next_header = parsed_packet.get_next_header()
        header_extension_length = parsed_packet.get_header_extension_length()
        options = parsed_packet.get_options()
        
        self.assertEqual(2, len(options), "Destination Options with multiple options parsing - Wrong Quantity of Options")
        
        pad1_option = options[0]
        pad1_option_type = pad1_option.get_option_type()
        
        padn_option = options[1]
        padn_option_type = padn_option.get_option_type()
        padn_option_length = padn_option.get_option_length()
        
        self.assertEqual(parsed_packet.get_header_type(), 60, "Destination Options with multiple options parsing - Incorrect packet")
        self.assertEqual(next_header, 58, "Destination Options with multiple options parsing - Incorrect next header value")
        self.assertEqual(header_extension_length, 0, "Destination Options with multiple options parsing - Incorrect size")
        self.assertEqual(pad1_option_type, 0, "Destination Options with multiple options parsing - Incorrect option type")
        self.assertEqual(padn_option_type, 1, "Destination Options with multiple options parsing - Incorrect option type")
        self.assertEqual(padn_option_length, 3, "Destination Options with multiple options parsing - Incorrect option size")

    def test_decoding_simple_routing_options(self):
        routing_options_binary_packet = [0x3a, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        
        d = ImpactDecoder.RoutingOptionsDecoder()        
        parsed_packet = d.decode(routing_options_binary_packet)
        
        next_header = parsed_packet.get_next_header()
        header_extension_length = parsed_packet.get_header_extension_length()
        routing_type = parsed_packet.get_routing_type()
        segments_left = parsed_packet.get_segments_left()
        options = parsed_packet.get_options()
        
        self.assertEqual(parsed_packet.get_header_type(), 43, "Simple Routing Options Parsing - Incorrect packet")
        self.assertEqual(next_header, 58, "Simple Routing Options Parsing - Incorrect next header value")
        self.assertEqual(header_extension_length, 0, "Simple Routing Options Parsing - Incorrect size")
        self.assertEqual(routing_type, 0, "Simple Routing Options Parsing - Incorrect routing type")
        self.assertEqual(segments_left, 10, "Simple Routing Options Parsing - Incorrect quantity of segments left size")
        self.assertEqual(0, len(options), "Simple Routing Options Parsing - Wrong Quantity of Options")

    def test_decoding_chained_basic_options_inside_ipv6_packet(self):
        ipv6_binary_packet = [ 
           0x64, 0x82, 0x46, 0x05, 
           0x05, 0xdc, 0x00, 0x01, 
           0xfe, 0x80, 0x00, 0x00, 
           0x00, 0x00, 0x00, 0x00, 
           0x78, 0xf8, 0x89, 0xd1,
           0x30, 0xff, 0x25, 0x6b, 
           0xff, 0x02, 0x00, 0x00, 
           0x00, 0x00, 0x00, 0x00, 
           0x00, 0x00, 0x00, 0x00, 
           0x00, 0x01, 0x00, 0x03]
        
        hop_by_hop_binary_packet = [
            0x2b, 0x01, 0x01, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00]

        routing_options_binary_packet = [
           0x3c, 0x00, 0x00, 0x0a,
           0x00, 0x00, 0x00, 0x00]

        dest_opts_binary_packet = [
            0x3a, 0x00, 0x00, 0x01,
            0x03, 0x00, 0x00, 0x00]

        binary_packet = ipv6_binary_packet + hop_by_hop_binary_packet + routing_options_binary_packet + dest_opts_binary_packet
        
        d = ImpactDecoder.IP6Decoder()        
        parsed_ipv6_packet = d.decode(binary_packet)
        
        # IPv6 Parsing
        ipv6_protocol_version = parsed_ipv6_packet.get_ip_v()
        ipv6_traffic_class = parsed_ipv6_packet.get_traffic_class()
        ipv6_flow_label = parsed_ipv6_packet.get_flow_label()
        ipv6_payload_length = parsed_ipv6_packet.get_payload_length()
        ipv6_next_header = parsed_ipv6_packet.get_next_header()
        ipv6_hop_limit = parsed_ipv6_packet.get_hop_limit()
        ipv6_source_address = parsed_ipv6_packet.get_ip_src()
        ipv6_destination_address = parsed_ipv6_packet.get_ip_dst()
        
        # Hop By Hop Parsing
        hop_by_hop_parsed_packet = parsed_ipv6_packet.child()
        hop_by_hop_next_header = hop_by_hop_parsed_packet.get_next_header()
        hop_by_hop_header_extension_length = hop_by_hop_parsed_packet.get_header_extension_length()
        hop_by_hop_options = hop_by_hop_parsed_packet.get_options()
        self.assertEqual(1, len(hop_by_hop_options), "Hop By Hop Parsing - Wrong Quantity of Options")
        hop_by_hop_padn_option = hop_by_hop_options[0]
        hop_by_hop_padn_option_type = hop_by_hop_padn_option.get_option_type()
        hop_by_hop_padn_option_length = hop_by_hop_padn_option.get_option_length()
        
        # Routing Options Tests
        routing_options_parsed_packet = hop_by_hop_parsed_packet.child()
        routing_options_next_header = routing_options_parsed_packet.get_next_header()
        routing_options_header_extension_length = routing_options_parsed_packet.get_header_extension_length()
        routing_options_routing_type = routing_options_parsed_packet.get_routing_type()
        routing_options_segments_left = routing_options_parsed_packet.get_segments_left()
        routing_options_options = routing_options_parsed_packet.get_options()
        
        # Destination Options Parsing
        destination_options_parsed_packet = routing_options_parsed_packet.child()
        destination_options_next_header = destination_options_parsed_packet.get_next_header()
        destination_options_header_extension_length = destination_options_parsed_packet.get_header_extension_length()
        destination_options_options = destination_options_parsed_packet.get_options()
        self.assertEqual(2, len(destination_options_options), "Destination Options Parsing - Wrong Quantity of Options")
        destination_options_pad1_option = destination_options_options[0]
        destination_options_pad1_option_type = destination_options_pad1_option.get_option_type()
        destination_options_padn_option = destination_options_options[1]
        destination_options_padn_option_type = destination_options_padn_option.get_option_type()
        destination_options_padn_option_length = destination_options_padn_option.get_option_length()
        
        self.assertEqual(ipv6_protocol_version, 6, "IP6 parsing - Incorrect protocol version")
        self.assertEqual(ipv6_traffic_class, 72, "IP6 parsing - Incorrect traffic class")
        self.assertEqual(ipv6_flow_label, 148997, "IP6 parsing - Incorrect flow label")
        self.assertEqual(ipv6_payload_length, 1500, "IP6 parsing - Incorrect payload length")
        self.assertEqual(ipv6_next_header, 0, "IP6 parsing - Incorrect next header")
        self.assertEqual(ipv6_hop_limit, 1, "IP6 parsing - Incorrect hop limit")
        self.assertEqual(ipv6_source_address.as_string(), "FE80::78F8:89D1:30FF:256B", "IP6 parsing - Incorrect source address")
        self.assertEqual(ipv6_destination_address.as_string(), "FF02::1:3", "IP6 parsing - Incorrect destination address")
        self.assertEqual(hop_by_hop_parsed_packet.get_header_type(), 0, "Hop By Hop Parsing - Incorrect packet")
        self.assertEqual(hop_by_hop_next_header, 43, "Hop By Hop Parsing - Incorrect next header value")
        self.assertEqual(hop_by_hop_header_extension_length, 1, "Hop By Hop Parsing - Incorrect size")
        self.assertEqual(hop_by_hop_padn_option_type, 1, "Hop By Hop Parsing - Incorrect option type")
        self.assertEqual(hop_by_hop_padn_option_length, 12, "Hop By Hop Parsing - Incorrect option size")
        self.assertEqual(routing_options_parsed_packet.get_header_type(), 43, "Routing Options Parsing - Incorrect packet")
        self.assertEqual(routing_options_next_header, 60, "Routing Options Parsing - Incorrect next header value")
        self.assertEqual(routing_options_header_extension_length, 0, "Routing Options Parsing - Incorrect size")
        self.assertEqual(routing_options_routing_type, 0, "Routing Options Parsing - Incorrect routing type")
        self.assertEqual(routing_options_segments_left, 10, "Routing Options Parsing - Incorrect quantity of segments left size")
        self.assertEqual(0, len(routing_options_options), "Routing Options Parsing - Wrong Quantity of Options")
        self.assertEqual(destination_options_parsed_packet.get_header_type(), 60, "Destination Options Parsing - Incorrect packet")
        self.assertEqual(destination_options_next_header, 58, "Destination Options Parsing - Incorrect next header value")
        self.assertEqual(destination_options_header_extension_length, 0, "Destination Options Parsing - Incorrect size")
        self.assertEqual(destination_options_pad1_option_type, 0, "Destination Options Parsing - Incorrect option type")
        self.assertEqual(destination_options_padn_option_type, 1, "Destination Options Parsing - Incorrect option type")
        self.assertEqual(destination_options_padn_option_length, 3, "Destination Options Parsing - Incorrect option size")

    def test_decoding_extension_header_from_string(self):
        hop_by_hop_binary_packet = b'\x2b\x01\x01\x0C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        d = ImpactDecoder.HopByHopDecoder()        
        parsed_packet = d.decode(hop_by_hop_binary_packet)
        
        next_header = parsed_packet.get_next_header()
        header_extension_length = parsed_packet.get_header_extension_length()
        options = parsed_packet.get_options()
        
        self.assertEqual(1, len(options), "Simple Hop By Hop Parsing - Wrong Quantity of Options")
        
        padn_option = options[0]
        padn_option_type = padn_option.get_option_type()
        padn_option_length = padn_option.get_option_length()
        
        self.assertEqual(parsed_packet.get_header_type(), 0, "Simple Hop By Hop Parsing - Incorrect packet")
        self.assertEqual(next_header, 43, "Simple Hop By Hop Parsing - Incorrect next header value")
        self.assertEqual(header_extension_length, 1, "Simple Hop By Hop Parsing - Incorrect size")
        self.assertEqual(padn_option_type, 1, "Simple Hop By Hop Parsing - Incorrect option type")
        self.assertEqual(padn_option_length, 12, "Simple Hop By Hop Parsing - Incorrect option size")


if __name__ == '__main__':
    unittest.main(verbosity=1)
