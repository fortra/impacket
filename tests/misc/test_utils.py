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
# Description:
#   Utility and helper functions for the example scripts
#
import unittest
from impacket.examples.utils import parse_target, parse_credentials, parse_identity


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

    def test_parse_identity_with_hashes(self):
        domain, username, password, lmhash, nthash, k = parse_identity(
            'DOMAIN/UserName:Password',
            'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0')
        self.assertTupleEqual((domain, username, password), ('DOMAIN', 'UserName', 'Password'))
        self.assertEqual(lmhash, 'aad3b435b51404eeaad3b435b51404ee')
        self.assertEqual(nthash, '31d6cfe0d16ae931b73c59d7e0c089c0')
        self.assertFalse(k)

    def test_parse_identity_with_empty_lm_hash(self):
        # An empty LM hash is replaced by the well-known empty value
        _, _, _, lmhash, nthash, _ = parse_identity(
            'DOMAIN/UserName:Password', ':31d6cfe0d16ae931b73c59d7e0c089c0')
        self.assertEqual(lmhash, 'AAD3B435B51404EEAAD3B435B51404EE')
        self.assertEqual(nthash, '31d6cfe0d16ae931b73c59d7e0c089c0')

    def test_parse_identity_with_invalid_hashes(self):
        # A value which is not LMHASH:NTHASH must be reported, not unpacked blindly
        for hashes in ('zzz', 'aa:bb:cc'):
            with self.assertRaises(ValueError) as ctx:
                parse_identity('DOMAIN/UserName:Password', hashes)
            self.assertIn('LMHASH:NTHASH', str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=1)
