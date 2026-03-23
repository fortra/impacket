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

from impacket.ImpactPacket import IP


class TestIP(unittest.TestCase):

    def test_fragment_by_size_without_payload(self):
        ip = IP()
        fragments = ip.fragment_by_size(8)
        self.assertEqual(fragments, [ip])


if __name__ == '__main__':
    unittest.main(verbosity=1)
