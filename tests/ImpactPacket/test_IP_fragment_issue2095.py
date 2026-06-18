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
from impacket.ImpactPacket import IP, Data


class TestIPFragmentIssue2095(unittest.TestCase):
    """IP.fragment_by_list() must not crash when payload is Data (protocol is None)."""

    def test_fragment_by_list_with_data_payload(self):
        ip = IP()
        ip.contains(Data(b'HELLO WORLD'))
        fragments = ip.fragment_by_list([8])
        self.assertIsInstance(fragments, list)
        self.assertGreater(len(fragments), 0)


if __name__ == '__main__':
    unittest.main(verbosity=1)
