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
from impacket.ImpactPacket import IPOption, ImpactPacketException


class TestIPOptionAccessors(unittest.TestCase):

    def test_append_ip_unsupported_option(self):
        option = IPOption(IPOption.IPOPT_NOP)
        with self.assertRaises(ImpactPacketException):
            option.append_ip("1.2.3.4")

    def test_get_flags_timestamp(self):
        option = IPOption(IPOption.IPOPT_TS)
        option.set_flags(3)
        self.assertEqual(option.get_flags(), 3)

    def test_get_flags_other_option(self):
        with self.assertRaises(ImpactPacketException):
            IPOption(IPOption.IPOPT_NOP).get_flags()


if __name__ == "__main__":
    unittest.main(verbosity=1)
