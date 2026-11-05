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
# Remote regression tests for IEnumWbemClassObject.Next(). Run directly:
#   python tests/SMB_RPC/test_wmi_next.py 'domain/user:password@target'
# Omitting the password prompts for it, as in wmiquery.py.
#
import argparse
from getpass import getpass
from pathlib import Path
import sys
import unittest
import uuid

# Direct execution should test the checkout, even if another Impacket version
# is installed. Module execution and pytest already put the checkout on sys.path.
if __name__ == '__main__' and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from tests import RemoteTestCase
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.utils import parse_target


@pytest.mark.remote
class WMIRemoteTests(RemoteTestCase, unittest.TestCase):
    connection_options = None

    def setUp(self):
        super(WMIRemoteTests, self).setUp()
        if self.connection_options is None:
            # Keep the standard remote configuration for pytest users.
            self.set_transport_config()
            connection_options = dict(
                target=self.machine, username=self.username,
                password=self.password, domain=self.domain,
                lmhash=self.lmhash, nthash=self.nthash,
            )
        else:
            connection_options = self.connection_options
            self.machine = connection_options['target']
        dcom = DCOMConnection(**connection_options)
        self.addCleanup(dcom.disconnect)
        interface = dcom.CoCreateInstanceEx(
            wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login,
        )
        login = wmi.IWbemLevel1Login(interface)
        try:
            self.services = login.NTLMLogin(
                r'\\%s\root\cimv2' % self.machine, NULL, NULL,
            )
            self.addCleanup(self.services.RemRelease)
        finally:
            login.RemRelease()


class WMINextTests(WMIRemoteTests):
    def _query(self, query='SELECT * FROM Win32_OperatingSystem'):
        enum = self.services.ExecQuery(query)
        self.addCleanup(enum.RemRelease)
        return enum

    def _assert_operating_system(self, objects):
        # Win32_OperatingSystem has one instance for the running OS, so the
        # result count does not depend on processes or services starting/stopping.
        self.assertEqual(len(objects), 1)
        self.assertIsInstance(objects[0], wmi.IWbemClassObject)
        self.assertEqual(objects[0].getClassName(), 'Win32_OperatingSystem')
        self.assertTrue(objects[0].getProperties()['Name']['value'])

    def _assert_exhausted(self, enum, count):
        with self.assertRaises(wmi.DCERPCSessionError) as ctx:
            enum.Next(0xffffffff, count)
        self.assertEqual(
            ctx.exception.get_error_code(),
            wmi.WBEMSTATUS.enumItems.WBEM_S_FALSE.value,
        )
        packet = ctx.exception.get_packet()
        self.assertIsNotNone(packet)
        self.assertEqual(packet['puReturned'], 0)
        self.assertEqual(len(packet['apObjects']), 0)

    def test_next_returns_all_objects_on_success(self):
        enum = self._query()
        self._assert_operating_system(enum.Next(0xffffffff, 1))

    def test_next_recovers_final_partial_batch(self):
        enum = self._query()
        # Requesting two objects from this singleton class forces the server
        # to return one object together with WBEM_S_FALSE. Before the fix,
        # Next() raised here and lost that object.
        self._assert_operating_system(enum.Next(0xffffffff, 2))
        self._assert_exhausted(enum, 2)

    def test_next_reraises_on_exhaustion(self):
        enum = self._query()
        self._assert_operating_system(enum.Next(0xffffffff, 1))
        self._assert_exhausted(enum, 1)

    def test_next_reraises_for_empty_query(self):
        # Name is a key property, so it cannot be NULL.
        enum = self._query('SELECT * FROM Win32_OperatingSystem WHERE Name IS NULL')
        self._assert_exhausted(enum, 2)

    def test_next_reraises_other_errors(self):
        # Semisynchronous queries report the missing-class error through Next().
        missing_class = 'ImpacketMissingClass_' + uuid.uuid4().hex
        enum = self.services.ExecQuery(
            'SELECT * FROM ' + missing_class, wmi.WBEM_FLAG_RETURN_IMMEDIATELY,
        )
        self.addCleanup(enum.RemRelease)
        with self.assertRaises(wmi.DCERPCSessionError) as ctx:
            enum.Next(0xffffffff, 1)
        self.assertEqual(
            ctx.exception.get_error_code(),
            wmi.WBEMSTATUS.enumItems.WBEM_E_INVALID_CLASS.value,
        )


def main(test_case=WMINextTests):
    parser = argparse.ArgumentParser(description='Run remote WMI regression tests.')
    parser.add_argument('target', help='[[domain/]username[:password]@]<targetName or address>')
    authentication = parser.add_argument_group('authentication')
    authentication.add_argument('-hashes', metavar='LMHASH:NTHASH', help='NTLM hashes')
    authentication.add_argument('-no-pass', action='store_true', help="Don't ask for a password (useful for -k)")
    authentication.add_argument('-k', action='store_true', help='Use Kerberos authentication (KRB5CCNAME cache)')
    authentication.add_argument(
        '-aesKey', metavar='hex key', help='AES key for Kerberos authentication (128 or 256 bits)',
    )
    authentication.add_argument('-dc-ip', metavar='ip address', help='IP address of the domain controller')
    options = parser.parse_args()

    domain, username, password, address = parse_target(options.target)
    if not address:
        parser.error('A target hostname or IP address is required')
    lmhash, nthash = '', ''
    if options.hashes is not None:
        try:
            lmhash, nthash = options.hashes.split(':')
        except ValueError:
            parser.error('-hashes must be in LMHASH:NTHASH format')
    if password == '' and username != '' and options.hashes is None and not options.no_pass and options.aesKey is None:
        password = getpass('Password:')

    test_case.connection_options = dict(
        target=address, username=username, password=password, domain=domain,
        lmhash=lmhash, nthash=nthash, aesKey=options.aesKey,
        doKerberos=options.k or options.aesKey is not None, kdcHost=options.dc_ip,
    )
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_case)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
