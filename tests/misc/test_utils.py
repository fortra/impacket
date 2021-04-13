#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Utility and helper functions for the example scripts
#
import unittest
from impacket.examples.utils import parse_target


class UtilsTests(unittest.TestCase):

    def test_parse_target(self):

        # Parse target returns a tuple with: domain, username, password, remote_name/address
        targets = {
            "": ("", "", "", ""),
            "HostName": ("", "", "", "HostName"),
            "UserName@HostName": ("", "UserName", "", "HostName"),
            "UserName:Password@HostName": ("", "UserName", "Password", "HostName"),
            "UserName:Pa$$word1234@HostName": ("", "UserName", "Pa$$word1234", "HostName"),
            "UserName:Password!#$@HostName": ("", "UserName", "Password!#$", "HostName"),
            "DOMAIN/UserName@HostName": ("DOMAIN", "UserName", "", "HostName"),
            "DOMAIN/:Password@HostName": ("DOMAIN", "", "Password", "HostName"),
            "DOMAIN/UserName:Password@HostName": ("DOMAIN", "UserName", "Password", "HostName"),
        }

        for target, result in targets.items():
            self.assertTupleEqual(parse_target(target), result)


if __name__ == "__main__":
    unittest.main(verbosity=1)
