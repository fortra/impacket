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

import struct
import socket
import unittest
from unittest import mock

from impacket import tds
from impacket.examples.ntlmrelayx.servers.socksplugins.mssql import MSSQLSocksRelay


class TDSTests(unittest.TestCase):
    @staticmethod
    def _build_tds_packet(packet_type, data, status=tds.TDS_STATUS_EOM):
        packet = tds.TDSPacket()
        packet["Type"] = packet_type
        packet["Status"] = status
        packet["Data"] = data
        return packet.getData()

    def test_prelogin_packs_four_byte_threadid(self):
        token = tds.TDS_PRELOGIN()
        token["Version"] = b"\x0f\x00\x11\x3a\x00\x00"
        token["Encryption"] = tds.TDS_ENCRYPT_NOT_SUP
        token["Instance"] = b"\x00"
        token["ThreadID"] = struct.pack("<L", 1)

        data = token.getData()

        self.assertEqual(struct.unpack_from(">H", data, 18)[0], 4)
        self.assertEqual(data[-4:], struct.pack("<L", 1))

    def test_info_error_length_is_computed_for_legacy_layout(self):
        token = tds.TDS_INFO_ERROR()
        token["TokenType"] = tds.TDS_ERROR_TOKEN
        token["Number"] = 18456
        token["State"] = 1
        token["Class"] = 14
        token["MsgText"] = "Login failed for user ''.".encode("utf-16le")
        token["MsgTextLen"] = len(token["MsgText"]) // 2
        token["ServerName"] = "MSSQLSERVER".encode("utf-16le")
        token["ServerNameLen"] = len(token["ServerName"]) // 2
        token["ProcName"] = b""
        token["ProcNameLen"] = 0
        token["LineNumber"] = 1

        data = token.getData()

        self.assertEqual(struct.unpack_from("<H", data, 1)[0], len(data) - 3)

    def test_info_error_length_is_computed_for_72_plus_layout(self):
        token = tds.TDS_INFO_ERROR72()
        token["TokenType"] = tds.TDS_ERROR_TOKEN
        token["Number"] = 18456
        token["State"] = 1
        token["Class"] = 14
        token["MsgText"] = "Login failed for user ''.".encode("utf-16le")
        token["MsgTextLen"] = len(token["MsgText"]) // 2
        token["ServerName"] = "MSSQLSERVER".encode("utf-16le")
        token["ServerNameLen"] = len(token["ServerName"]) // 2
        token["ProcName"] = b""
        token["ProcNameLen"] = 0
        token["LineNumber"] = 1

        data = token.getData()

        self.assertEqual(struct.unpack_from("<H", data, 1)[0], len(data) - 3)

    def test_login_uses_default_tds_version_when_serializing(self):
        login = tds.TDS_LOGIN()

        data = login.getData()

        self.assertEqual(
            struct.unpack_from(">L", data, 4)[0], tds.TDS_LOGIN7_VERSION_71
        )

    def test_negotiate_encryption_does_not_retry_tds8_on_timeout(self):
        client = tds.MSSQL("server")
        client.preLogin = mock.Mock(side_effect=socket.timeout("timed out"))
        client.disconnect = mock.Mock()
        client.connect = mock.Mock()
        client._setup_tds8 = mock.Mock()
        client.set_tls_context = mock.Mock()

        with self.assertRaises(socket.timeout):
            client._negotiate_encryption()

        client.disconnect.assert_not_called()
        client.connect.assert_not_called()
        client._setup_tds8.assert_not_called()
        client.set_tls_context.assert_not_called()

    def test_negotiate_encryption_retries_tds8_on_connection_close(self):
        client = tds.MSSQL("server")
        response = {"Encryption": tds.TDS_ENCRYPT_OFF}
        client.preLogin = mock.Mock(
            side_effect=[ConnectionError("Server closed connection"), response]
        )
        client.disconnect = mock.Mock()
        client.connect = mock.Mock()
        client._setup_tds8 = mock.Mock()
        client.set_tls_context = mock.Mock()

        result = client._negotiate_encryption()

        self.assertIs(result, response)
        client.disconnect.assert_called_once_with()
        client.connect.assert_called_once_with()
        client._setup_tds8.assert_called_once_with()
        client.set_tls_context.assert_not_called()

    def test_wrap_sql_batch_data_adds_headers_for_tds8_sessions(self):
        client = tds.MSSQL("server")
        client.tds8 = True
        sql_text = "SELECT 1\r\n".encode("utf-16le")

        data = client._wrap_sql_batch_data(sql_text)

        self.assertEqual(data[:4], struct.pack("<I", 22))
        self.assertEqual(data[4:8], struct.pack("<I", 18))
        self.assertEqual(data[8:10], struct.pack("<H", 2))
        self.assertEqual(data[10:18], struct.pack("<Q", 0))
        self.assertEqual(data[18:22], struct.pack("<I", 1))
        self.assertEqual(data[22:], sql_text)

    def test_wrap_sql_batch_data_preserves_legacy_sessions(self):
        client = tds.MSSQL("server")
        sql_text = "SELECT 1\r\n".encode("utf-16le")

        self.assertIs(client._wrap_sql_batch_data(sql_text), sql_text)

    def test_recv_tds_reassembles_partial_tls_reads(self):
        client = tds.MSSQL("server")
        packet = self._build_tds_packet(tds.TDS_PRE_LOGIN, b"partial-header")
        client.socket = mock.Mock()
        client.socket.recv = mock.Mock(
            side_effect=[packet[:3], packet[3:6], packet[6:10], packet[10:]]
        )

        response = client.recvTDS(packetSize=4096)

        self.assertEqual(response["Type"], tds.TDS_PRE_LOGIN)
        self.assertEqual(response["Data"], b"partial-header")

    def test_recv_tds_preserves_buffered_bytes_for_next_packet(self):
        client = tds.MSSQL("server")
        first = self._build_tds_packet(tds.TDS_PRE_LOGIN, b"first")
        second = self._build_tds_packet(tds.TDS_TABULAR, b"second")
        client.socket = mock.Mock()
        client.socket.recv = mock.Mock(side_effect=[first + second[:6], second[6:]])

        first_response = client.recvTDS(packetSize=4096)
        second_response = client.recvTDS(packetSize=4096)

        self.assertEqual(first_response["Type"], tds.TDS_PRE_LOGIN)
        self.assertEqual(first_response["Data"], b"first")
        self.assertEqual(second_response["Type"], tds.TDS_TABULAR)
        self.assertEqual(second_response["Data"], b"second")


class MSSQLSocksRelayTests(unittest.TestCase):
    @staticmethod
    def _build_tds_packet(packet_type, data, status=tds.TDS_STATUS_EOM):
        packet = tds.TDSPacket()
        packet["Type"] = packet_type
        packet["Status"] = status
        packet["Data"] = data
        return packet.getData()

    @staticmethod
    def _build_relay(session_tds8=False):
        session = mock.Mock()
        session.tds8 = session_tds8
        protocol_client = mock.Mock()
        protocol_client.session = session
        active_relays = {
            "data": {},
            "scheme": "MSSQL",
            "DOMAIN/USER": {
                "protocolClient": protocol_client,
                "inUse": False,
                "data": {},
            },
        }
        relay = MSSQLSocksRelay(
            "server", 1433, mock.Mock(spec=socket.socket), active_relays
        )
        relay.session = session
        return relay

    def test_get_prelogin_encryption_is_strict_for_tds8_backends(self):
        relay = self._build_relay(session_tds8=True)

        self.assertEqual(relay._get_prelogin_encryption(), tds.TDS_ENCRYPT_STRICT)

    def test_maybe_switch_client_to_tds8_wraps_tls_first_client(self):
        relay = self._build_relay(session_tds8=True)
        relay.socksSocket.recv.return_value = b"\x16"
        relay._wrap_client_connection_for_tds8 = mock.Mock(
            side_effect=lambda: setattr(relay, "client_tds8", True)
        )

        relay._maybe_switch_client_to_tds8()

        relay._wrap_client_connection_for_tds8.assert_called_once_with()
        self.assertTrue(relay.client_tds8)

    def test_skip_authentication_advertises_strict_before_tls_reconnect(self):
        relay = self._build_relay(session_tds8=True)
        relay.socksSocket.recv.return_value = b"\x12"
        relay.recvTDS = mock.Mock(return_value={"Type": tds.TDS_PRE_LOGIN, "Data": b""})
        relay.sendTDS = mock.Mock()

        result = relay.skipAuthentication()

        self.assertFalse(result)
        args = relay.sendTDS.call_args[0]
        self.assertEqual(args[0], tds.TDS_TABULAR)
        response = tds.TDS_PRELOGIN(args[1])
        self.assertEqual(response["Encryption"], tds.TDS_ENCRYPT_STRICT)

    def test_sql_batch_wrap_only_applies_to_legacy_local_clients(self):
        relay = self._build_relay(session_tds8=True)

        relay.client_tds8 = False
        self.assertTrue(relay._should_wrap_sql_batch_for_backend())

        relay.client_tds8 = True
        self.assertFalse(relay._should_wrap_sql_batch_for_backend())

    def test_recv_tds_reassembles_partial_tls_reads_from_local_client(self):
        relay = self._build_relay(session_tds8=True)
        relay.client_tds8 = True
        packet = self._build_tds_packet(tds.TDS_PRE_LOGIN, b"client-partial")
        relay.socksSocket.recv = mock.Mock(
            side_effect=[packet[:2], packet[2:7], packet[7:9], packet[9:]]
        )

        response = relay.recvTDS(packetSize=4096)

        self.assertEqual(response["Type"], tds.TDS_PRE_LOGIN)
        self.assertEqual(response["Data"], b"client-partial")

if __name__ == "__main__":
    unittest.main(verbosity=1)
