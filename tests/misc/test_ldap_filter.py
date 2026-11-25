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

from impacket.ldap.ldap import LDAPConnection


class LDAPFilterTests(unittest.TestCase):
    def _parse(self, filterStr):
        return LDAPConnection.__new__(LDAPConnection)._parseFilter(filterStr)

    def test_escaped_binary_value(self):
        searchFilter = self._parse(r'(objectGUID=\a1\00\ff\28)')
        self.assertEqual(bytes(searchFilter['equalityMatch']['assertionValue']), b'\xa1\x00\xff(')

    def test_escaped_utf8_value(self):
        searchFilter = self._parse(r'(cn=Jos\c3\a9)')
        self.assertEqual(bytes(searchFilter['equalityMatch']['assertionValue']), 'José'.encode('utf-8'))

    def test_unescaped_utf8_value(self):
        searchFilter = self._parse('(cn=José)')
        self.assertEqual(bytes(searchFilter['equalityMatch']['assertionValue']), 'José'.encode('utf-8'))

    def test_escaped_substring_value(self):
        searchFilter = self._parse(r'(objectGUID=\a1*\ff\2a*\00)')
        substrings = searchFilter['substrings']['substrings']
        self.assertEqual(bytes(substrings[0]['initial']), b'\xa1')
        self.assertEqual(bytes(substrings[1]['any']), b'\xff*')
        self.assertEqual(bytes(substrings[2]['final']), b'\x00')

    def test_escaped_extensible_match_value(self):
        searchFilter = self._parse(r'(cn:caseExactMatch:=Jos\c3\a9)')
        self.assertEqual(bytes(searchFilter['extensibleMatch']['matchValue']), 'José'.encode('utf-8'))


if __name__ == '__main__':
    unittest.main(verbosity=1)
