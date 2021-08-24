#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Utility and helper functions for the example scripts
#
import unittest
from impacket.examples.utils import parse_target, parse_credentials


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
            "UserName:Passw@rd!#$@HostName": ("", "UserName", "Passw@rd!#$", "HostName"),
            "UserName:P@ssw@rd@!#$@HostName": ("", "UserName", "P@ssw@rd@!#$", "HostName"),
            "DOMAIN/UserName@HostName": ("DOMAIN", "UserName", "", "HostName"),
            "DOMAIN/:Password@HostName": ("DOMAIN", "", "Password", "HostName"),
            "DOMAIN/UserName:Password@HostName": ("DOMAIN", "UserName", "Password", "HostName"),
            "DOMAIN/UserName:Password/123@HostName": ("DOMAIN", "UserName", "Password/123", "HostName"),
        }

        for target, result in targets.items():
            self.assertTupleEqual(parse_target(target), result)

    def test_parse_credentials(self):
        # Parse credentials returns a tuple with: domain, username, password
        creds = {
            "": ("", "", ""),
            "UserName": ("", "UserName", ""),
            "UserName:Password": ("", "UserName", "Password"),
            "UserName:Password:123": ("", "UserName", "Password:123"),
            "DOMAIN/UserName": ("DOMAIN", "UserName", ""),
            "DOMAIN/UserName:Password": ("DOMAIN", "UserName", "Password"),
            "DOMAIN/UserName:Password/123": ("DOMAIN", "UserName", "Password/123"),
        }

        for cred, result in creds.items():
            self.assertTupleEqual(parse_credentials(cred), result)


if __name__ == "__main__":
    unittest.main(verbosity=1)
