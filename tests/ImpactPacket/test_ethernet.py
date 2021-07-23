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
from array import array
from impacket.ImpactPacket import Ethernet, EthernetTag


class TestEthernet(unittest.TestCase):

    def setUp(self):
        # Ethernet frame with a 802.1Q tag (TPID=0x8100, PCP=5, DEI=0, VID=3315)
        # and ethertype 0x0800 (IPv4)
        self.frame = b'\x54\xab\xa3\xb9\x38\x3d\xe2\xef\x8d\xc7\xa8\x5e\x81\x00\xac\xf3\x08\x00'
        self.eth = Ethernet(self.frame)

    def test_01(self):
        """Test Ethernet getters"""
        self.assertEqual(self.eth.get_packet(), self.frame)
        self.assertEqual(self.eth.get_header_size(), 18)
        self.assertEqual(self.eth.get_ether_type(), 0x0800)

        # Check source and destination MACs
        self.assertEqual(self.eth.get_ether_dhost(), array('B', self.frame[0:6]))
        self.assertEqual(self.eth.get_ether_shost(), array('B', self.frame[6:12]))

    def test_02(self):
        """Test Ethernet setters"""
        self.eth.set_ether_type(0x88cc)
        self.assertEqual(self.eth.get_ether_type(), 0x88cc)

        # Swap source and destination MACs
        dhost = self.eth.get_ether_dhost()
        shost = self.eth.get_ether_shost()
        self.eth.set_ether_dhost(shost)
        self.eth.set_ether_shost(dhost)
        self.assertEqual(self.eth.get_ether_dhost(), array('B', self.frame[6:12]))
        self.assertEqual(self.eth.get_ether_shost(), array('B', self.frame[0:6]))

    def test_03(self):
        """Test EthernetTag getters"""
        tag = self.eth.pop_tag()
        self.assertEqual(tag.get_buffer_as_string(),b'\x81\x00\xac\xf3')
        self.assertEqual(tag.get_tpid(), 0x8100)
        self.assertEqual(tag.get_pcp(), 5)
        self.assertEqual(tag.get_dei(), 0)
        self.assertEqual(tag.get_vid(), 3315)

    def test_04(self):
        """Test EthernetTag setters"""
        tag = self.eth.pop_tag()
        tag.set_tpid(0x88a8)
        tag.set_pcp(2)
        tag.set_dei(1)
        tag.set_vid(876)
        self.assertEqual(tag.get_buffer_as_string(), b'\x88\xa8\x53\x6c')

    def test_05(self):
        """Test manipulation with VLAN tags"""
        def check_tags(*tags):
            self.assertEqual(self.eth.tag_cnt, len(tags))
            self.assertEqual(self.eth.get_header_size(), 14 + 4*len(tags))
            self.assertEqual(self.eth.get_ether_type(), 0x0800)
            for i,tag in enumerate(tags):
                self.assertEqual(self.eth.get_tag(i).get_buffer_as_string(), tag)

        # Add S-tag (outer tag, closest to the Ethernet header)
        self.eth.push_tag(EthernetTag(0x88a85001))
        check_tags(b'\x88\xa8\x50\x01', b'\x81\x00\xac\xf3')

        # Set C-tag (inner tag, closest to the payload) to default
        self.eth.set_tag(1, EthernetTag())
        check_tags(b'\x88\xa8\x50\x01', b'\x81\x00\x00\x00')

        # Insert a deprecated 802.1QinQ header between S-tag and C-tag
        self.eth.push_tag(EthernetTag(0x910054d2), index=1)
        check_tags(b'\x88\xa8\x50\x01', b'\x91\x00\x54\xd2', b'\x81\x00\x00\x00')

        # Test negative indices
        tags = {}
        for i in range(-3,3):
            tags[i] = self.eth.get_tag(i).get_buffer_as_string()

        self.assertEqual(tags[-1], tags[2])
        self.assertEqual(tags[-2], tags[1])
        self.assertEqual(tags[-3], tags[0])

        # Accessing non-existent tags raises IndexError
        self.assertRaises(IndexError, self.eth.get_tag, 3)
        self.assertRaises(IndexError, self.eth.get_tag, -4)
        self.assertRaises(IndexError, self.eth.set_tag, 3, EthernetTag())
        self.assertRaises(IndexError, self.eth.set_tag, -4, EthernetTag())

        # Test Ethernet constructor
        data = self.eth.get_buffer_as_string()
        eth_copy = Ethernet(data)
        self.assertEqual(eth_copy.tag_cnt, 3)
        self.assertEqual(eth_copy.get_header_size(), 26)
        self.assertEqual(eth_copy.get_ether_type(), 0x0800)

        # Remove the deprecated 802.1QinQ header and check resulting frame
        eth_copy.pop_tag(1)
        self.assertEqual(eth_copy.tag_cnt, 2)
        self.assertEqual(eth_copy.get_packet(), self.frame[:12] + tags[0] + tags[2] + self.frame[-2:])


if __name__ == '__main__':
    unittest.main(verbosity=1)
