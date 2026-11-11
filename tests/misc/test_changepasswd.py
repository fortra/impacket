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
from unittest import mock

from examples import changepasswd
from examples.changepasswd import KPassword, LdapPassword, PasswordHandler, RpcPassword, SmbPassword
from impacket.dcerpc.v5 import epm, samr
from impacket.ldap import ldap


class TimeoutValidationTests(unittest.TestCase):
    def _parse(self, *extra):
        argv = ["changepasswd.py", "dom/user:pass@host", *extra]
        with mock.patch("sys.argv", argv):
            return changepasswd.parse_args()

    def test_cli_rejects_zero_negative_and_non_integer_timeout(self):
        for value in ("0", "-5", "abc"):
            with self.subTest(value=value):
                with mock.patch("sys.stderr"), self.assertRaises(SystemExit) as ctx:
                    self._parse("-timeout", value)
                self.assertEqual(ctx.exception.code, 2)

    def test_cli_accepts_positive_timeout(self):
        self.assertEqual(self._parse("-timeout", "5").timeout, 5)

    def test_cli_timeout_defaults_to_30(self):
        self.assertEqual(self._parse().timeout, 30)

    def test_handler_rejects_zero_and_negative_timeout(self):
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    PasswordHandler("host", timeout=value)

    def test_handler_accepts_none_and_positive_timeout(self):
        self.assertIsNone(PasswordHandler("host").timeout)
        self.assertEqual(PasswordHandler("host", timeout=5).timeout, 5)


class TimeoutPropagationTests(unittest.TestCase):
    """The -timeout value must reach the connection code of every protocol"""

    def test_ldap_passes_timeout_to_connection(self):
        handler = LdapPassword("dc.test.local", "test.local", "user", "pass", timeout=5)
        with mock.patch("examples.changepasswd.ldap.LDAPConnection") as connection:
            self.assertTrue(handler.connect("test.local"))
        self.assertEqual(connection.call_args.kwargs["timeout"], 5)

    def test_ldap_connection_applies_timeout_to_tcp_connect_only(self):
        """Documents the scope of the timeout: the TCP connect, not the TLS handshake or later operations"""
        tcp_socket = mock.MagicMock()
        tls_socket = mock.MagicMock()
        tls_socket.get_peer_certificate.return_value.digest.return_value = b"AA:BB"
        with mock.patch("impacket.ldap.ldap.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.1", 636))]), \
                mock.patch("impacket.ldap.ldap.socket.socket", return_value=tcp_socket), \
                mock.patch("impacket.ldap.ldap.SSL.Connection", return_value=tls_socket), \
                mock.patch.object(ldap.LDAPConnection, "build_tls_context"), \
                mock.patch.object(ldap.LDAPConnection, "compute_channel_binding"):
            ldap.LDAPConnection("ldaps://dc.test.local", timeout=5)
        tcp_socket.settimeout.assert_called_once_with(5)
        self.assertEqual(tls_socket.settimeout.call_args_list, [mock.call(None), mock.call(None)])

    def test_kpasswd_change_passes_timeout(self):
        handler = KPassword("dc.test.local", "test.local", "user", "pass", timeout=5)
        with mock.patch("examples.changepasswd.kpasswd.changePassword") as change:
            self.assertTrue(handler._changePassword("user", "test.local", "old", "new", "", "", "", ""))
        self.assertEqual(change.call_args.kwargs["timeout"], 5)

    def test_kpasswd_set_passes_timeout(self):
        handler = KPassword("dc.test.local", "test.local", "admin", "pass", timeout=5)
        with mock.patch("examples.changepasswd.kpasswd.setPassword") as set_password:
            self.assertTrue(handler._setPassword("user", "test.local", "new", "", ""))
        self.assertEqual(set_password.call_args.kwargs["timeout"], 5)

    def test_smb_samr_sets_connect_timeout_on_transport(self):
        handler = SmbPassword("dc.test.local", "test.local", "user", "pass", timeout=5)
        with mock.patch("examples.changepasswd.transport.SMBTransport") as smb_transport:
            handler.authenticate()
        smb_transport.return_value.set_connect_timeout.assert_called_once_with(5)

    def test_smb_samr_keeps_transport_default_without_timeout(self):
        handler = SmbPassword("dc.test.local", "test.local", "user", "pass")
        with mock.patch("examples.changepasswd.transport.SMBTransport") as smb_transport:
            handler.authenticate()
        smb_transport.return_value.set_connect_timeout.assert_not_called()

    def test_rpc_samr_passes_timeout_to_endpoint_mapper_and_transport(self):
        handler = RpcPassword("dc.test.local", "test.local", "user", "pass", timeout=5)
        with mock.patch("examples.changepasswd.epm.hept_map", return_value="ncacn_ip_tcp:dc[49152]") as hept_map, \
                mock.patch("examples.changepasswd.transport.DCERPCTransportFactory") as factory:
            handler.authenticate()
        self.assertEqual(hept_map.call_args.kwargs["timeout"], 5)
        factory.return_value.set_connect_timeout.assert_called_once_with(5)

    def test_rpc_samr_keeps_transport_default_without_timeout(self):
        handler = RpcPassword("dc.test.local", "test.local", "user", "pass")
        with mock.patch("examples.changepasswd.epm.hept_map", return_value="ncacn_ip_tcp:dc[49152]") as hept_map, \
                mock.patch("examples.changepasswd.transport.DCERPCTransportFactory") as factory:
            handler.authenticate()
        self.assertIsNone(hept_map.call_args.kwargs["timeout"])
        factory.return_value.set_connect_timeout.assert_not_called()


class EndpointMapperTimeoutTests(unittest.TestCase):
    def _hept_map(self, **kwargs):
        """Run hept_map until the connection to the endpoint mapper is attempted, and return the transport used"""
        with mock.patch("impacket.dcerpc.v5.epm.transport.DCERPCTransportFactory") as factory:
            factory.return_value.get_dce_rpc.return_value.connect.side_effect = RuntimeError("stop")
            with self.assertRaises(RuntimeError):
                epm.hept_map("dc.test.local", samr.MSRPC_UUID_SAMR, protocol="ncacn_ip_tcp", **kwargs)
        return factory.return_value

    def test_hept_map_sets_connect_timeout(self):
        self._hept_map(timeout=5).set_connect_timeout.assert_called_once_with(5)

    def test_hept_map_keeps_transport_default_without_timeout(self):
        self._hept_map().set_connect_timeout.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=1)
