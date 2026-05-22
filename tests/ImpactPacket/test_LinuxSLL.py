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

from impacket.ImpactPacket import LinuxSLL


class TestLinuxSLL(unittest.TestCase):

    def test_set_arphdr(self):
        sll = LinuxSLL()
        sll.set_arphdr(513)
        self.assertEqual(sll.get_arphdr(), 513)

    def test_set_addr_bytes(self):
        sll = LinuxSLL()
        sll.set_addr(b"ABCDEF")
        self.assertEqual(sll.get_addr(), b"ABCDEF\x00\x00")
        self.assertEqual(len(sll.get_packet()), 16)


if __name__ == '__main__':
    unittest.main(verbosity=1)
