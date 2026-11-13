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
# Network-free regression tests for recursive LDAP search filter
# (ldapasn1.Filter) BER decoding - https://github.com/fortra/impacket/issues/273
#
import unittest

from pyasn1.codec.ber import decoder, encoder

from impacket.ldap.ldapasn1 import Filter, LDAPMessage
from impacket.ldap.ldap import LDAPConnection


def _chosen_name(choice):
    return choice.componentType[choice._currentIdx].name


# Wire samples from https://github.com/fortra/impacket/issues/273
# SearchRequest with a plain (non-composite) equalityMatch filter: control.
REQ0 = (b'0z\x02\x01\x03cu\x04\x1bou=groups,DC=example,DC=foo\n\x01\x02\n\x01\x03'
        b'\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa3\x1b\x04\x0bobjectclass\x04\x0cgroupOfNames'
        b'0*\x04\x02cn\x04\x0bdescription\x04\x06member\x04\x0fmodifyTimestamp')

# SearchRequest with a composite and(equalityMatch, not(lessOrEqual)) filter.
REQ1 = (b'0\x81\xa3\x02\x01\x02c\x81\x9d\x04\x1bou=groups,DC=example,DC=foo\n\x01\x02\n\x01\x03'
        b'\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa0C\xa3\x1b\x04\x0bobjectclass\x04\x0cgroupOfNames'
        b'\xa2$\xa6"\x04\x0fmodifyTimestamp\x04\x0f20150302092004Z'
        b'0*\x04\x02cn\x04\x0bdescription\x04\x06member\x04\x0fmodifyTimestamp')


class LDAPFilterTests(unittest.TestCase):

    def test_issue_req0_plain_equality_control(self):
        msg, _ = decoder.decode(REQ0, asn1Spec=LDAPMessage())
        f = msg['protocolOp']['searchRequest']['filter']
        self.assertEqual(_chosen_name(f), 'equalityMatch')
        self.assertEqual(str(f['equalityMatch']['attributeDesc']), 'objectclass')
        self.assertEqual(str(f['equalityMatch']['assertionValue']), 'groupOfNames')

    def test_issue_req1_composite_decodes(self):
        msg, _ = decoder.decode(REQ1, asn1Spec=LDAPMessage())
        f = msg['protocolOp']['searchRequest']['filter']
        self.assertEqual(_chosen_name(f), 'and')
        members = f['and']
        self.assertEqual(len(members), 2)
        self.assertEqual(_chosen_name(members[0]), 'equalityMatch')
        self.assertEqual(_chosen_name(members[1]), 'not')
        inner = members[1]['not'][0]
        self.assertEqual(_chosen_name(inner), 'lessOrEqual')
        self.assertEqual(str(inner['lessOrEqual']['attributeDesc']), 'modifyTimestamp')
        self.assertEqual(str(inner['lessOrEqual']['assertionValue']), '20150302092004Z')

    def test_issue_req1_reencode_byte_identical(self):
        msg, _ = decoder.decode(REQ1, asn1Spec=LDAPMessage())
        self.assertEqual(encoder.encode(msg), REQ1)

    def test_parse_filter_composite_roundtrip(self):
        conn = LDAPConnection.__new__(LDAPConnection)
        for filter_str in ('(&(|(a=b)(c=d))(!(e=f)))',
                           '(&(objectclass=groupOfNames)(!(modifyTimestamp<=20150302092004Z)))'):
            f = conn._parseFilter(filter_str)
            wire = encoder.encode(f)
            f2, rest = decoder.decode(wire, asn1Spec=Filter())
            self.assertEqual(rest, b'')
            self.assertEqual(encoder.encode(f2), wire)

    def test_deeply_nested_composite_roundtrip(self):
        conn = LDAPConnection.__new__(LDAPConnection)
        nested = '(cn=x)'
        for i in range(12):
            nested = ('(!%s)' if i % 2 == 0 else '(&%s(cn=z))') % nested
        f = conn._parseFilter(nested)
        wire = encoder.encode(f)
        f2, rest = decoder.decode(wire, asn1Spec=Filter())
        self.assertEqual(rest, b'')
        self.assertEqual(encoder.encode(f2), wire)

        def depth(cf):
            name = _chosen_name(cf)
            if name in ('and', 'or', 'not'):
                return 1 + max(depth(m) for m in cf[name])
            return 0
        self.assertEqual(depth(f2), 12)

    def test_leaf_alternatives_roundtrip(self):
        conn = LDAPConnection.__new__(LDAPConnection)
        cases = {
            '(a=b)': 'equalityMatch',
            '(a~=b)': 'approxMatch',
            '(a>=b)': 'greaterOrEqual',
            '(a<=b)': 'lessOrEqual',
            '(a=*)': 'present',
            '(a=*b*c*)': 'substrings',
            '(a:dn:caseIgnoreMatch:=b)': 'extensibleMatch',
        }
        for filter_str, expected in cases.items():
            f = conn._parseFilter(filter_str)
            self.assertEqual(_chosen_name(f), expected, filter_str)
            wire = encoder.encode(f)
            f2, rest = decoder.decode(wire, asn1Spec=Filter())
            self.assertEqual(rest, b'')
            self.assertEqual(_chosen_name(f2), expected, filter_str)
            self.assertEqual(encoder.encode(f2), wire, filter_str)

    def test_clone_resolves_final_component_type(self):
        embedded = Filter.componentType['and'][1].componentType
        self.assertEqual(len(Filter.componentType), 10)
        self.assertEqual(len(Filter().clone().componentType), 10)
        self.assertEqual(len(embedded.clone().componentType), 10)
        self.assertEqual(len(embedded.clone().clone().componentType), 10)
        for alt in ('and', 'or', 'not'):
            e = Filter.componentType[alt][1].componentType
            self.assertEqual(len(e.clone().componentType), 10, alt)


if __name__ == '__main__':
    unittest.main()
