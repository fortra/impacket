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
# Remote regression tests for IEnumWbemClassObject.Next(). Configure the target
# using tests/dcetests.cfg or pytest's --remote-config option, as in test_wmi.py.
#
import unittest

import pytest

from tests import RemoteTestCase
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL


@pytest.mark.remote
class WMINextTests(RemoteTestCase, unittest.TestCase):
    def setUp(self):
        super(WMINextTests, self).setUp()
        self.set_transport_config()
        dcom = DCOMConnection(
            self.machine, self.username, self.password, self.domain,
            self.lmhash, self.nthash,
        )
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


if __name__ == '__main__':
    unittest.main(verbosity=1)
