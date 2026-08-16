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
from types import SimpleNamespace
from unittest import mock

import ldap3
from examples.addcomputer import ADDCOMPUTER


class _FakeLDAPConnection:
    def __init__(self, entries, modify_result=True, result_code=0):
        self.entries = entries
        self._modify_result = modify_result
        self.result = {"result": result_code, "message": "error"}
        self.last_modify_dn = None
        self.last_modify_changes = None

    def search(self, *_args, **_kwargs):
        return True

    def modify(self, dn, changes):
        self.last_modify_dn = dn
        self.last_modify_changes = changes
        return self._modify_result


def _build_options(method, computer_name="TESTPC$", no_add=False, delete=False):
    return SimpleNamespace(
        hashes=None,
        aesKey=None,
        k=False,
        dc_host="dc.test.local",
        computer_name=computer_name,
        computer_pass="Password123!",
        method=method,
        port=None,
        domain_netbios=None,
        no_add=no_add,
        delete=delete,
        dc_ip=None,
        baseDN="dc=test,dc=local",
        computer_group=None,
    )


class AddComputerTests(unittest.TestCase):
    def test_ldap_finalize_only_success(self):
        options = _build_options("LDAP_FINALIZE")
        tool = ADDCOMPUTER("user", "pass", "test.local", options)
        entry = SimpleNamespace(entry_dn="CN=TESTPC,CN=Computers,dc=test,dc=local")
        ldap_conn = _FakeLDAPConnection([entry], modify_result=True)

        with mock.patch("examples.addcomputer.init_ldap_session", return_value=(None, ldap_conn)):
            tool.run()

        self.assertEqual(ldap_conn.last_modify_dn, entry.entry_dn)
        self.assertEqual(
            ldap_conn.last_modify_changes["dnsHostName"][0][1][0],
            "TESTPC.test.local",
        )
        self.assertEqual(
            ldap_conn.last_modify_changes["servicePrincipalName"][0][1],
            [
                "HOST/TESTPC",
                "HOST/TESTPC.test.local",
                "RestrictedKrbHost/TESTPC",
                "RestrictedKrbHost/TESTPC.test.local",
            ],
        )

    def test_ldap_finalize_only_missing_account_raises(self):
        options = _build_options("LDAP_FINALIZE")
        tool = ADDCOMPUTER("user", "pass", "test.local", options)
        ldap_conn = _FakeLDAPConnection([], modify_result=True)

        with mock.patch("examples.addcomputer.init_ldap_session", return_value=(None, ldap_conn)):
            with self.assertRaises(Exception) as cm:
                tool.run()

        self.assertIn("was created over SAMR but was not found over LDAP", str(cm.exception))

    def test_ldap_finalize_only_insufficient_rights_raises(self):
        options = _build_options("LDAP_FINALIZE")
        tool = ADDCOMPUTER("user", "pass", "test.local", options)
        entry = SimpleNamespace(entry_dn="CN=TESTPC,CN=Computers,dc=test,dc=local")
        ldap_conn = _FakeLDAPConnection(
            [entry],
            modify_result=False,
            result_code=ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS,
        )

        with mock.patch("examples.addcomputer.init_ldap_session", return_value=(None, ldap_conn)):
            with self.assertRaises(Exception) as cm:
                tool.run()

        self.assertIn("doesn't have right to finalize LDAP attributes", str(cm.exception))

    def test_samr_mode_does_not_finalize_ldap(self):
        options = _build_options("SAMR")
        tool = ADDCOMPUTER("user", "pass", "test.local", options)

        with mock.patch.object(tool, "run_samr") as run_samr, mock.patch.object(
            tool, "LDAPFinalizeComputerAccount"
        ) as finalize:
            tool.run()

        run_samr.assert_called_once()
        finalize.assert_not_called()

    def test_samr_ldap_calls_finalize_after_add(self):
        options = _build_options("SAMR_LDAP")
        tool = ADDCOMPUTER("user", "pass", "test.local", options)

        class FakeSessionError(Exception):
            def __init__(self, error_code):
                super(FakeSessionError, self).__init__("session error")
                self.error_code = error_code

        class FakeDCE:
            def connect(self):
                return None

            def bind(self, _uuid):
                return None

            def disconnect(self):
                return None

        class FakeRPCTransport:
            def get_dce_rpc(self):
                return FakeDCE()

        with mock.patch.object(tool, "LDAPFinalizeComputerAccount") as finalize, mock.patch(
            "examples.addcomputer.samr.DCERPCSessionError", FakeSessionError
        ), mock.patch(
            "examples.addcomputer.samr.hSamrConnect5", return_value={"ServerHandle": "srv-handle"}
        ), mock.patch(
            "examples.addcomputer.samr.hSamrEnumerateDomainsInSamServer",
            return_value={"Buffer": {"Buffer": [{"Name": "Builtin"}, {"Name": "TESTDOM"}]}},
        ), mock.patch(
            "examples.addcomputer.samr.hSamrLookupDomainInSamServer", return_value={"DomainId": "sid"}
        ), mock.patch(
            "examples.addcomputer.samr.hSamrOpenDomain", return_value={"DomainHandle": "domain-handle"}
        ), mock.patch(
            "examples.addcomputer.samr.hSamrLookupNamesInDomain",
            side_effect=[
                FakeSessionError(0xC0000073),
                {"RelativeIds": {"Element": [1001]}},
            ],
        ), mock.patch(
            "examples.addcomputer.samr.hSamrCreateUser2InDomain", return_value={"UserHandle": "new-user-handle"}
        ), mock.patch(
            "examples.addcomputer.samr.hSamrSetPasswordInternal4New"
        ), mock.patch(
            "examples.addcomputer.samr.hSamrOpenUser", return_value={"UserHandle": "open-user-handle"}
        ), mock.patch(
            "examples.addcomputer.samr.SAMPR_USER_INFO_BUFFER",
            side_effect=lambda: {"Control": {}},
        ), mock.patch(
            "examples.addcomputer.samr.hSamrSetInformationUser2"
        ), mock.patch(
            "examples.addcomputer.samr.hSamrCloseHandle"
        ):
            tool.doSAMRAdd(FakeRPCTransport())

        finalize.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=1)
