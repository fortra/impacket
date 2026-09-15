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
# Host-free unit tests for IEnumWbemClassObject.Next() partial-batch handling.
#
# Tested so far:
#   IEnumWbemClassObject::Next (final partial batch recovery on WBEM_S_FALSE)
#
# These tests do not require a remote target: the DCERPC request layer and the
# per-object interface construction are mocked, so only Next()'s own decision
# logic is exercised.
#
import unittest
from unittest import mock

from impacket.dcerpc.v5.dcom import wmi

WBEM_S_FALSE = wmi.WBEMSTATUS.enumItems.WBEM_S_FALSE.value
WBEM_E_FAILED = wmi.WBEMSTATUS.enumItems.WBEM_E_FAILED.value


def _make_enum():
    """Build an IEnumWbemClassObject without touching the network."""
    enum = wmi.IEnumWbemClassObject.__new__(wmi.IEnumWbemClassObject)
    enum._iid = wmi.IID_IEnumWbemClassObject
    # Name-mangled attribute set by __init__ in normal operation.
    enum._IEnumWbemClassObject__iWbemServices = None
    # Interface plumbing Next() calls into; irrelevant once IWbemClassObject
    # and INTERFACE are patched out below.
    enum.get_iPid = mock.Mock(return_value=b"")
    enum.get_cinstance = mock.Mock(return_value=object())
    enum.get_ipidRemUnknown = mock.Mock(return_value=b"")
    enum.get_oxid = mock.Mock(return_value=0)
    enum.get_target = mock.Mock(return_value="host")
    return enum


def _fake_response(count):
    """A minimal stand-in for IEnumWbemClassObject_NextResponse."""
    return {
        "ErrorCode": 0,
        "puReturned": count,
        "apObjects": [{"abData": [b""]} for _ in range(count)],
    }


def _false_response(count):
    resp = _fake_response(count)
    resp["ErrorCode"] = WBEM_S_FALSE
    return resp


class WMINextTests(unittest.TestCase):
    def test_next_returns_all_objects_on_success(self):
        enum = _make_enum()
        enum.request = mock.Mock(return_value=_fake_response(3))
        with mock.patch.object(wmi, "IWbemClassObject", side_effect=lambda *a, **k: object()), \
             mock.patch.object(wmi, "INTERFACE", side_effect=lambda *a, **k: object()):
            result = enum.Next(0xffffffff, 5)
        self.assertEqual(len(result), 3)

    def test_next_recovers_final_partial_batch(self):
        # Server returned 2 trailing objects *and* WBEM_S_FALSE in one response.
        # Before the fix these rows were dropped; Next() must now return them.
        enum = _make_enum()
        exc = wmi.DCERPCSessionError(packet=_false_response(2), error_code=WBEM_S_FALSE)
        enum.request = mock.Mock(side_effect=exc)
        with mock.patch.object(wmi, "IWbemClassObject", side_effect=lambda *a, **k: object()), \
             mock.patch.object(wmi, "INTERFACE", side_effect=lambda *a, **k: object()):
            result = enum.Next(0xffffffff, 5)
        self.assertEqual(len(result), 2)

    def test_next_reraises_on_exhaustion(self):
        # WBEM_S_FALSE with no trailing objects is genuine end-of-enumeration;
        # the historical exception must still be raised so existing callers that
        # break on it keep working.
        enum = _make_enum()
        exc = wmi.DCERPCSessionError(packet=_false_response(0), error_code=WBEM_S_FALSE)
        enum.request = mock.Mock(side_effect=exc)
        with self.assertRaises(wmi.DCERPCSessionError) as ctx:
            enum.Next(0xffffffff, 5)
        self.assertEqual(ctx.exception.get_error_code(), WBEM_S_FALSE)
        self.assertIn("S_FALSE", str(ctx.exception))

    def test_next_reraises_other_errors(self):
        enum = _make_enum()
        exc = wmi.DCERPCSessionError(error_code=WBEM_E_FAILED)
        enum.request = mock.Mock(side_effect=exc)
        with self.assertRaises(wmi.DCERPCSessionError) as ctx:
            enum.Next(0xffffffff, 5)
        self.assertEqual(ctx.exception.get_error_code(), WBEM_E_FAILED)


if __name__ == "__main__":
    unittest.main(verbosity=1)
