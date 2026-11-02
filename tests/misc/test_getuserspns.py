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
#   GetUserSPNs.py unit tests
#
import unittest
from types import SimpleNamespace
from unittest import mock

from examples.GetUserSPNs import GetUserSPNs


class GetUserSPNsTests(unittest.TestCase):
    @staticmethod
    def build_options(dc_ip=None, dc_host=None):
        return SimpleNamespace(
            no_preauth='bootstrap',
            outputfile=None,
            no_rc4=False,
            usersfile='unused',
            aesKey=None,
            k=False,
            request=True,
            dc_ip=dc_ip,
            dc_host=dc_host,
            save=False,
            request_user=None,
            stealth=False,
            machine_only=False,
            request_machine=None,
            ldaps_flag=False,
            hashes=None,
        )

    def assert_kdc_host(self, expected, dc_ip=None, dc_host=None):
        get_user_spns = GetUserSPNs(
            'user', '', 'example.test', 'example.test',
            self.build_options(dc_ip=dc_ip, dc_host=dc_host),
        )

        with mock.patch(
            'examples.GetUserSPNs.getKerberosTGT',
            return_value=(b'ticket', object(), b'old-session-key', b'session-key'),
        ) as get_kerberos_tgt:
            with mock.patch.object(get_user_spns, 'outputTGS'):
                get_user_spns.request_multiple_TGSs(['svc/example.test'])

        get_kerberos_tgt.assert_called_once()
        self.assertEqual(get_kerberos_tgt.call_args.kwargs['kdcHost'], expected)

    def test_no_preauth_uses_dc_ip_when_dc_host_is_not_set(self):
        self.assert_kdc_host('192.0.2.10', dc_ip='192.0.2.10')

    def test_no_preauth_prefers_dc_host_when_both_are_set(self):
        self.assert_kdc_host(
            'dc01.example.test',
            dc_ip='192.0.2.10',
            dc_host='dc01.example.test',
        )

    def test_no_preauth_leaves_kdc_host_unset_without_an_override(self):
        self.assert_kdc_host(None)


if __name__ == '__main__':
    unittest.main(verbosity=1)
