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

import datetime
import struct
import socket
import unittest
from decimal import Decimal
from unittest import mock
from uuid import UUID

from impacket.smbconnection import SessionError

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

    def test_mssql_constructor_preserves_legacy_positional_remote_name(self):
        client = tds.MSSQL("server", 1444, "sql.example.com")

        self.assertEqual(client.port, 1444)
        self.assertEqual(client.remoteName, "sql.example.com")
        self.assertIsNone(client.pipe_name)

    def test_named_pipe_constructor_defaults_remote_host_to_address(self):
        client = tds.MSSQL(
            "10.0.0.5",
            pipe_name=r"MSSQL$SQLEXPRESS\sql\query",
            remoteName="sql.example.com",
        )

        self.assertEqual(client.remoteName, "sql.example.com")
        self.assertEqual(client.remoteHost, "10.0.0.5")

    def test_named_pipe_transport_settimeout_forwards_to_smb(self):
        transport = tds.NamedPipeTransport("sql.example.com", "10.0.0.5", "pipe")
        transport._smb = mock.Mock()

        transport.settimeout(7)

        transport._smb.setTimeout.assert_called_once_with(7)

    def test_named_pipe_transport_uses_timeout_from_connect(self):
        client = tds.MSSQL(
            "10.0.0.5",
            pipe_name=r"MSSQL$SQLEXPRESS\sql\query",
            remoteName="sql.example.com",
        )
        client.connect(timeout=7)

        with mock.patch.object(tds, "NamedPipeTransport") as transport_class:
            client._create_named_pipe_transport("user", "password", "DOMAIN")

        transport_class.return_value.connect.assert_called_once_with(7)

    def test_named_pipe_transport_is_closed_when_authentication_fails(self):
        client = tds.MSSQL(
            "10.0.0.5",
            pipe_name=r"MSSQL$SQLEXPRESS\sql\query",
            remoteName="sql.example.com",
        )

        with mock.patch.object(tds, "NamedPipeTransport") as transport_class:
            transport = transport_class.return_value
            transport.authenticate_ntlm.side_effect = RuntimeError(
                "authentication failed"
            )

            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                client._create_named_pipe_transport(
                    "user", "password", "DOMAIN"
                )

        transport.close.assert_called_once_with()
        self.assertEqual(client.socket, 0)

    def test_named_pipe_disconnect_write_error_is_generic(self):
        transport = tds.NamedPipeTransport("sql.example.com", "10.0.0.5", "pipe")
        transport._smb = mock.Mock()
        transport._smb.writeFile.side_effect = SessionError(tds.STATUS_PIPE_DISCONNECTED)

        with self.assertRaisesRegex(ConnectionError, "while writing") as cm:
            transport.sendall(b"data")

        self.assertNotIn("ENCRYPT_STRICT", str(cm.exception))

    def test_named_pipe_login_can_use_separate_smb_credentials(self):
        client = tds.MSSQL(
            "10.0.0.5",
            pipe_name=r"MSSQL$SQLEXPRESS\sql\query",
            remoteName="sql.example.com",
        )
        response = {"Encryption": tds.TDS_ENCRYPT_REQ}
        client._create_named_pipe_transport = mock.Mock()
        client._negotiate_encryption = mock.Mock(return_value=response)
        client.sendTDS = mock.Mock()
        client.recvTDS = mock.Mock(return_value={"Data": b""})
        client.parseReply = mock.Mock(return_value={tds.TDS_LOGINACK_TOKEN: []})

        result = client.login(
            None,
            "sql_user",
            "sql_pass",
            "",
            useWindowsAuth=False,
            smbUsername="smb_user",
            smbPassword="smb_pass",
            smbDomain="SMBDOM",
        )

        self.assertTrue(result)
        client._create_named_pipe_transport.assert_called_once_with(
            "smb_user",
            "smb_pass",
            "SMBDOM",
            "",
            "",
            kerberos=False,
        )

    def test_named_pipe_kerberos_does_not_reuse_mssql_tgs_for_smb(self):
        client = tds.MSSQL(
            "10.0.0.5",
            pipe_name=r"MSSQL$SQLEXPRESS\sql\query",
            remoteName="sql.example.com",
        )
        sql_tgt = object()
        sql_tgs = object()
        client._create_named_pipe_transport = mock.Mock()
        client._negotiate_encryption = mock.Mock(
            side_effect=RuntimeError("stop after SMB setup")
        )

        with self.assertRaisesRegex(RuntimeError, "stop after SMB setup"):
            client.kerberosLogin(
                None,
                "sql_user",
                "sql_pass",
                "DOMAIN",
                TGT=sql_tgt,
                TGS=sql_tgs,
                useCache=False,
            )

        client._create_named_pipe_transport.assert_called_once_with(
            "sql_user",
            "sql_pass",
            "DOMAIN",
            "",
            "",
            kerberos=True,
            aesKey="",
            kdcHost=None,
            TGT=sql_tgt,
            TGS=None,
            useCache=False,
        )

    def test_named_pipe_kerberos_can_use_separate_smb_credentials(self):
        client = tds.MSSQL(
            "10.0.0.5",
            pipe_name=r"MSSQL$SQLEXPRESS\sql\query",
            remoteName="sql.example.com",
        )
        client._create_named_pipe_transport = mock.Mock()
        client._negotiate_encryption = mock.Mock(
            side_effect=RuntimeError("stop after SMB setup")
        )

        with self.assertRaisesRegex(RuntimeError, "stop after SMB setup"):
            client.kerberosLogin(
                None,
                "sql_user",
                "sql_pass",
                "DOMAIN",
                smbUsername="smb_user",
                smbPassword="smb_pass",
                smbDomain="SMBDOM",
            )

        client._create_named_pipe_transport.assert_called_once_with(
            "smb_user",
            "smb_pass",
            "SMBDOM",
            "",
            "",
            kerberos=False,
        )

    @staticmethod
    def _text_pointer_row_data(payload):
        pointer = b"PTR!"
        return (
            bytes([len(pointer)])
            + pointer
            + (b"\x00" * 8)
            + struct.pack("<L", len(payload))
            + payload
        )

    def _parse_single_column_row(self, col_type, data):
        client = tds.MSSQL("server")
        client.colMeta = [{"Type": col_type, "Name": "value"}]
        consumed = client.parseRow({"TokenType": tds.TDS_ROW_TOKEN, "Data": data})

        self.assertEqual(consumed, len(data))
        return client.rows[-1]["value"]

    def test_parse_row_decodes_big_binary_as_bytes(self):
        value = self._parse_single_column_row(
            tds.TDS_BIGVARBINTYPE,
            struct.pack("<H", 3) + b"\x01\xab\xff",
        )

        self.assertEqual(value, b"\x01\xab\xff")
        self.assertIsInstance(value, bytes)

    def test_parse_row_decodes_image_as_bytes(self):
        value = self._parse_single_column_row(
            tds.TDS_IMAGETYPE,
            self._text_pointer_row_data(b"\x01\xab\xff"),
        )

        self.assertEqual(value, b"\x01\xab\xff")
        self.assertIsInstance(value, bytes)

    def test_parse_row_decodes_text_as_string(self):
        value = self._parse_single_column_row(
            tds.TDS_TEXTTYPE,
            self._text_pointer_row_data(b"caf\xe9"),
        )

        self.assertEqual(value, "caf\xe9")
        self.assertIsInstance(value, str)

    def test_parse_row_decodes_big_char_as_string(self):
        value = self._parse_single_column_row(
            tds.TDS_BIGCHARTYPE,
            struct.pack("<H", 10) + b"7         ",
        )

        self.assertEqual(value, "7         ")
        self.assertIsInstance(value, str)

    def _parse_col(self, col_type, data, **meta):
        client = tds.MSSQL("server")
        client.colMeta = [{"Type": col_type, "Name": "value", **meta}]
        client.parseRow({"TokenType": tds.TDS_ROW_TOKEN, "Data": data})
        return client.rows[-1]["value"]

    # ------------------------------------------------------------------
    # _collation_to_codec
    # ------------------------------------------------------------------

    def test_collation_to_codec_returns_cp1252_for_none(self):
        self.assertEqual(tds.MSSQL._collation_to_codec(None), "cp1252")

    def test_collation_to_codec_returns_cp1252_for_empty_bytes(self):
        self.assertEqual(tds.MSSQL._collation_to_codec(b""), "cp1252")

    def test_collation_to_codec_maps_english_lcid_to_cp1252(self):
        # LCID 0x0409 = English (United States) -> cp1252
        collation = struct.pack("<L", 0x0409) + b"\x00"
        self.assertEqual(tds.MSSQL._collation_to_codec(collation), "cp1252")

    def test_collation_to_codec_falls_back_to_cp1252_for_unknown_lcid(self):
        collation = struct.pack("<L", 0xFFFFF) + b"\x00"
        self.assertEqual(tds.MSSQL._collation_to_codec(collation), "cp1252")

    # ------------------------------------------------------------------
    # _decode_scaled_time
    # ------------------------------------------------------------------

    def test_decode_scaled_time_midnight_scale0(self):
        self.assertEqual(tds.MSSQL._decode_scaled_time(0, 0), (0, 0, 0, 0))

    def test_decode_scaled_time_noon_scale0(self):
        # 12 * 3600 = 43200 seconds since midnight
        self.assertEqual(tds.MSSQL._decode_scaled_time(43200, 0), (12, 0, 0, 0))

    def test_decode_scaled_time_max_scale7(self):
        # 863999999999 * 100ns = 23:59:59.9999999; truncated to microseconds = 999999
        self.assertEqual(tds.MSSQL._decode_scaled_time(863999999999, 7), (23, 59, 59, 999999))

    # ------------------------------------------------------------------
    # _read_plp
    # ------------------------------------------------------------------

    def test_read_plp_null_header_returns_none(self):
        data = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
        value, remaining = tds.MSSQL._read_plp(data)
        self.assertIsNone(value)
        self.assertEqual(remaining, b"")

    def test_read_plp_single_chunk(self):
        payload = b"hello"
        data = (
            struct.pack("<Q", len(payload))
            + struct.pack("<L", len(payload))
            + payload
            + struct.pack("<L", 0)
        )
        value, remaining = tds.MSSQL._read_plp(data)
        self.assertEqual(value, b"hello")
        self.assertEqual(remaining, b"")

    def test_read_plp_multiple_chunks(self):
        data = (
            struct.pack("<Q", 0xFFFFFFFFFFFFFFFE)  # unknown total length
            + struct.pack("<L", 3) + b"hel"
            + struct.pack("<L", 2) + b"lo"
            + struct.pack("<L", 0)
        )
        value, remaining = tds.MSSQL._read_plp(data)
        self.assertEqual(value, b"hello")
        self.assertEqual(remaining, b"")

    # ------------------------------------------------------------------
    # parseRow - fixed-size types
    # ------------------------------------------------------------------

    def test_parse_row_guid_returns_uuid(self):
        guid = UUID("12345678-1234-5678-1234-567812345678")
        data = bytes([16]) + guid.bytes_le
        value = self._parse_single_column_row(tds.TDS_GUIDTYPE, data)
        self.assertIsInstance(value, UUID)
        self.assertEqual(value, guid)

    def test_parse_row_guid_null_returns_none(self):
        value = self._parse_single_column_row(tds.TDS_GUIDTYPE, bytes([0]))
        self.assertIsNone(value)

    def test_parse_row_bittype_true_returns_bool(self):
        value = self._parse_single_column_row(tds.TDS_BITTYPE, b"\x01")
        self.assertIs(value, True)
        self.assertIsInstance(value, bool)

    def test_parse_row_bittype_false_returns_bool(self):
        value = self._parse_single_column_row(tds.TDS_BITTYPE, b"\x00")
        self.assertIs(value, False)
        self.assertIsInstance(value, bool)

    def test_parse_row_int1type_returns_int_not_bool(self):
        # TINYINT 0 must be int(0), not False
        value = self._parse_single_column_row(tds.TDS_INT1TYPE, b"\x00")
        self.assertEqual(value, 0)
        self.assertNotIsInstance(value, bool)

    def test_parse_row_datetimetype_negative_days(self):
        # days=-1 from base 1900-01-01 must give 1899-12-31, not ~1752
        data = struct.pack("<l", -1) + struct.pack("<L", 0)
        value = self._parse_single_column_row(tds.TDS_DATETIMETYPE, data)
        self.assertEqual(value.date(), datetime.date(1899, 12, 31))

    def test_parse_row_datetimetype_epoch(self):
        # days=0 = 1900-01-01
        data = struct.pack("<l", 0) + struct.pack("<L", 0)
        value = self._parse_single_column_row(tds.TDS_DATETIMETYPE, data)
        self.assertEqual(value.date(), datetime.date(1900, 1, 1))

    # ------------------------------------------------------------------
    # parseRow - nullable types
    # ------------------------------------------------------------------

    def test_parse_row_bitntype_null(self):
        value = self._parse_single_column_row(tds.TDS_BITNTYPE, b"\x00")
        self.assertIsNone(value)

    def test_parse_row_bitntype_true(self):
        value = self._parse_single_column_row(tds.TDS_BITNTYPE, b"\x01\x01")
        self.assertIs(value, True)
        self.assertIsInstance(value, bool)

    def test_parse_row_bitntype_false(self):
        value = self._parse_single_column_row(tds.TDS_BITNTYPE, b"\x01\x00")
        self.assertIs(value, False)
        self.assertIsInstance(value, bool)

    def test_parse_row_intntype_4byte(self):
        data = b"\x04" + struct.pack("<l", -42)
        value = self._parse_single_column_row(tds.TDS_INTNTYPE, data)
        self.assertEqual(value, -42)
        self.assertIsInstance(value, int)

    def test_parse_row_intntype_null(self):
        value = self._parse_single_column_row(tds.TDS_INTNTYPE, b"\x00")
        self.assertIsNone(value)

    def test_parse_row_fltntype_null(self):
        value = self._parse_single_column_row(tds.TDS_FLTNTYPE, b"\x00")
        self.assertIsNone(value)

    def test_parse_row_fltntype_4byte(self):
        data = b"\x04" + struct.pack("<f", 1.5)
        value = self._parse_single_column_row(tds.TDS_FLTNTYPE, data)
        self.assertAlmostEqual(value, 1.5, places=5)
        self.assertIsInstance(value, float)

    def test_parse_row_moneyntype_smallmoney(self):
        # 12345 units of 1/10000 = 1.2345
        data = b"\x04" + struct.pack("<l", 12345)
        value = self._parse_single_column_row(tds.TDS_MONEYNTYPE, data)
        self.assertEqual(value, Decimal("1.2345"))
        self.assertIsInstance(value, Decimal)

    def test_parse_row_moneyntype_null(self):
        value = self._parse_single_column_row(tds.TDS_MONEYNTYPE, b"\x00")
        self.assertIsNone(value)

    def test_parse_row_datentype_returns_date(self):
        # datetime.date(2000, 1, 1).toordinal() = 730120 = 0x0B2408
        data = b"\x03" + struct.pack("<L", 730120)[:3]
        value = self._parse_col(tds.TDS_DATENTYPE, data)
        self.assertEqual(value, datetime.date(2000, 1, 1))
        self.assertIsInstance(value, datetime.date)

    def test_parse_row_datentype_null(self):
        value = self._parse_col(tds.TDS_DATENTYPE, b"\x00")
        self.assertIsNone(value)

    def test_parse_row_timentype_noon_scale0(self):
        # scale=0: value in seconds; 43200 = 12:00:00; 3 bytes for scale 0-2
        data = b"\x03" + struct.pack("<L", 43200)[:3]
        value = self._parse_col(tds.TDS_TIMENTYPE, data, TypeData=0)
        self.assertEqual(value, datetime.time(12, 0, 0))
        self.assertIsInstance(value, datetime.time)

    def test_parse_row_timentype_null(self):
        value = self._parse_col(tds.TDS_TIMENTYPE, b"\x00", TypeData=0)
        self.assertIsNone(value)

    # ------------------------------------------------------------------
    # parseRow - decimal / numeric
    # ------------------------------------------------------------------

    def test_parse_row_decimalntype_positive(self):
        # DECIMAL(5,2): 123.45 -> integer 12345, sign=1, 2 bytes
        type_data = b"\x11\x05\x02"  # max_size=17, precision=5, scale=2
        data = b"\x03\x01" + struct.pack("<H", 12345)
        value = self._parse_col(tds.TDS_DECIMALNTYPE, data, TypeData=type_data)
        self.assertEqual(value, Decimal("123.45"))
        self.assertIsInstance(value, Decimal)

    def test_parse_row_decimalntype_negative(self):
        type_data = b"\x11\x05\x02"
        data = b"\x03\x00" + struct.pack("<H", 12345)
        value = self._parse_col(tds.TDS_DECIMALNTYPE, data, TypeData=type_data)
        self.assertEqual(value, Decimal("-123.45"))

    def test_parse_row_decimalntype_null(self):
        type_data = b"\x11\x05\x02"
        value = self._parse_col(tds.TDS_DECIMALNTYPE, b"\x00", TypeData=type_data)
        self.assertIsNone(value)

    # ------------------------------------------------------------------
    # parseRow - char types
    # ------------------------------------------------------------------

    def test_parse_row_nvarchartype_returns_str(self):
        payload = "hello".encode("utf-16le")
        data = struct.pack("<H", len(payload)) + payload
        value = self._parse_col(tds.TDS_NVARCHARTYPE, data, TypeData=20)
        self.assertEqual(value, "hello")
        self.assertIsInstance(value, str)

    def test_parse_row_nvarchartype_null(self):
        value = self._parse_col(tds.TDS_NVARCHARTYPE, struct.pack("<H", 0xFFFF), TypeData=20)
        self.assertIsNone(value)

    def test_parse_row_bigvarchrtype_returns_str(self):
        data = struct.pack("<H", 5) + b"hello"
        value = self._parse_col(tds.TDS_BIGVARCHRTYPE, data, TypeData=100)
        self.assertEqual(value, "hello")
        self.assertIsInstance(value, str)

    def test_parse_row_bigvarchrtype_null(self):
        value = self._parse_col(tds.TDS_BIGVARCHRTYPE, struct.pack("<H", 0xFFFF), TypeData=100)
        self.assertIsNone(value)


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
