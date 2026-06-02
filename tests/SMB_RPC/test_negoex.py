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
import unittest
import uuid

from impacket.negoex import (
    ALERT_HEADER_SIZE,
    AUTH_SCHEME_PKU2U,
    EXCHANGE_HEADER_SIZE,
    HEADER_SIZE,
    MESSAGE_TYPE,
    MESSAGE_SIGNATURE,
    NEGOEX_PROTOCOL_VERSION,
    NEGO_HEADER_SIZE,
    VERIFY_HEADER_SIZE,
    AlertMessage,
    ExchangeMessage,
    MessageHeader,
    NegoExParseError,
    NegoMessage,
    VerifyMessage,
    createAlertMessage,
    createExchangeMessage,
    createNegoMessage,
    createVerifyMessage,
    parseNegoExToken,
)


class NegoExTests(unittest.TestCase):
    TEST_CONVERSATION_ID = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')
    TEST_AUTH_SCHEME = uuid.UUID('00010203-0405-0607-0809-0a0b0c0d0e0f')
    UNKNOWN_MESSAGE_TYPE = 0x1337

    def setUp(self):
        self.conversation_id = self.TEST_CONVERSATION_ID
        self.auth_scheme = self.TEST_AUTH_SCHEME

    @staticmethod
    def _set_u32(data, offset, value):
        out = bytearray(data)
        out[offset:offset + 4] = struct.pack('<I', value)
        return bytes(out)

    @staticmethod
    def _set_u16(data, offset, value):
        out = bytearray(data)
        out[offset:offset + 2] = struct.pack('<H', value)
        return bytes(out)

    @staticmethod
    def _set_u64(data, offset, value):
        out = bytearray(data)
        out[offset:offset + 8] = struct.pack('<Q', value)
        return bytes(out)

    def test_create_nego_message_round_trip_initiator(self):
        data = createNegoMessage(
            MESSAGE_TYPE.INITIATOR_NEGO,
            1,
            self.conversation_id,
            [AUTH_SCHEME_PKU2U, self.auth_scheme],
            extensions=[],
        )

        parsed = parseNegoExToken(data)
        self.assertEqual(1, len(parsed))
        self.assertEqual(0, parsed[0].offset)
        self.assertEqual(data, parsed[0].raw_data)

        msg = parsed[0].message
        self.assertEqual(MESSAGE_TYPE.INITIATOR_NEGO, msg['Header']['MessageType'])
        self.assertEqual([AUTH_SCHEME_PKU2U.bytes_le, self.auth_scheme.bytes_le], msg.getAuthSchemeList())
        self.assertEqual(0, len(msg.getExtensionList()))

    def test_create_nego_message_round_trip_acceptor_with_extensions(self):
        data = createNegoMessage(
            MESSAGE_TYPE.ACCEPTOR_NEGO,
            2,
            self.conversation_id,
            [AUTH_SCHEME_PKU2U],
            extensions=[(1, b''), (2, b'abc')],
        )

        msg = parseNegoExToken(data)[0].message
        self.assertEqual(MESSAGE_TYPE.ACCEPTOR_NEGO, msg['Header']['MessageType'])
        self.assertEqual([AUTH_SCHEME_PKU2U.bytes_le], msg.getAuthSchemeList())

        exts = msg.getExtensionList()
        self.assertEqual(2, len(exts))
        self.assertEqual((1, b''), (exts[0]['ExtensionType'], exts[0].ExtensionValue))
        self.assertEqual((2, b'abc'), (exts[1]['ExtensionType'], exts[1].ExtensionValue))

    def test_create_exchange_message_round_trip_all_types_and_payloads(self):
        payloads = [b'', b'payload']
        message_types = (
            MESSAGE_TYPE.INITIATOR_META_DATA,
            MESSAGE_TYPE.ACCEPTOR_META_DATA,
            MESSAGE_TYPE.CHALLENGE,
            MESSAGE_TYPE.AP_REQUEST,
        )

        for msg_type in message_types:
            for payload in payloads:
                with self.subTest(message_type=msg_type, payload_len=len(payload)):
                    data = createExchangeMessage(
                        msg_type,
                        3,
                        self.conversation_id,
                        self.auth_scheme,
                        payload,
                    )
                    msg = parseNegoExToken(data)[0].message
                    self.assertEqual(msg_type, msg['Header']['MessageType'])
                    self.assertEqual(self.auth_scheme.bytes_le, msg.getAuthScheme())
                    self.assertEqual(payload, msg.getExchangeData())

    def test_parse_negoex_token_single_multiple_and_unknown_message(self):
        first = createNegoMessage(
            MESSAGE_TYPE.INITIATOR_NEGO,
            1,
            self.conversation_id,
            [AUTH_SCHEME_PKU2U],
            extensions=[],
        )
        second = createExchangeMessage(
            MESSAGE_TYPE.CHALLENGE,
            2,
            self.conversation_id,
            self.auth_scheme,
            b'\x01\x02',
        )

        unknown = self._set_u32(second, 8, self.UNKNOWN_MESSAGE_TYPE)
        token = first + second + unknown
        parsed = parseNegoExToken(token)

        self.assertEqual(3, len(parsed))
        self.assertEqual(0, parsed[0].offset)
        self.assertEqual(len(first), parsed[1].offset)
        self.assertEqual(len(first) + len(second), parsed[2].offset)
        self.assertEqual(first, parsed[0].raw_data)
        self.assertEqual(second, parsed[1].raw_data)
        self.assertEqual(unknown, parsed[2].raw_data)
        self.assertEqual(self.UNKNOWN_MESSAGE_TYPE, parsed[2].message_type)
        self.assertIsNone(parsed[2].message)

    def test_error_truncated_header(self):
        with self.assertRaises(NegoExParseError):
            parseNegoExToken(b'\x00' * (HEADER_SIZE - 1))

    def test_error_invalid_signature(self):
        data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        broken = b'BADSIG!!' + data[8:]
        with self.assertRaises(NegoExParseError):
            parseNegoExToken(broken)

    def test_error_invalid_cb_header_length(self):
        data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        bad = self._set_u32(data, 16, NEGO_HEADER_SIZE - 1)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad)

    def test_error_cb_message_length_shorter_than_header(self):
        data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        bad = self._set_u32(data, 20, HEADER_SIZE - 1)
        with self.assertRaises(NegoExParseError):
            parseNegoExToken(bad)

    def test_error_cb_message_length_longer_than_available_data(self):
        data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        bad = self._set_u32(data, 20, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            parseNegoExToken(bad)

    def test_error_bad_auth_scheme_vector_offset_length(self):
        data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        bad_offset = self._set_u32(data, 80, len(data) + 100)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad_offset)

        bad_count = self._set_u16(data, 84, 0x7FFF)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad_count)

    def test_error_bad_extension_vector_offset_length(self):
        data = createNegoMessage(
            MESSAGE_TYPE.INITIATOR_NEGO,
            1,
            self.conversation_id,
            [self.auth_scheme],
            extensions=[(1, b'x')],
        )
        bad_offset = self._set_u32(data, 88, len(data) + 100)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad_offset)

        bad_count = self._set_u16(data, 92, 0x7FFF)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad_count)

    def test_error_bad_extension_value_offset_length(self):
        data = createNegoMessage(
            MESSAGE_TYPE.INITIATOR_NEGO,
            1,
            self.conversation_id,
            [self.auth_scheme],
            extensions=[(1, b'abc')],
        )

        bad_offset = self._set_u32(data, 116, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad_offset)

        bad_length = self._set_u32(data, 120, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad_length)

    def test_error_bad_exchange_offset_length(self):
        data = createExchangeMessage(MESSAGE_TYPE.CHALLENGE, 1, self.conversation_id, self.auth_scheme, b'abc')

        bad_offset = self._set_u32(data, 56, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            ExchangeMessage(bad_offset)

        bad_length = self._set_u32(data, 60, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            ExchangeMessage(bad_length)

    def test_error_bad_checksum_offset_length(self):
        data = createVerifyMessage(1, self.conversation_id, self.auth_scheme, b'abc', 1)

        bad_offset = self._set_u32(data, 68, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            VerifyMessage(bad_offset)

        bad_length = self._set_u32(data, 72, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            VerifyMessage(bad_length)

    def test_error_bad_alert_offset_length(self):
        data = createAlertMessage(1, self.conversation_id, self.auth_scheme)

        bad_offset = self._set_u32(data, 72, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            AlertMessage(bad_offset)

        bad_length = self._set_u32(data, 76, len(data) + 1)
        with self.assertRaises(NegoExParseError):
            AlertMessage(bad_length)

    def test_error_unsupported_protocol_version(self):
        data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        bad = self._set_u64(data, 72, NEGOEX_PROTOCOL_VERSION + 1)
        with self.assertRaises(NegoExParseError):
            NegoMessage(bad)

    def test_error_wrong_message_type_for_each_structure(self):
        nego = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 1, self.conversation_id, [self.auth_scheme], [])
        exchange = createExchangeMessage(MESSAGE_TYPE.CHALLENGE, 1, self.conversation_id, self.auth_scheme, b'x')
        verify = createVerifyMessage(1, self.conversation_id, self.auth_scheme, b'abc', 1)
        alert = createAlertMessage(1, self.conversation_id, self.auth_scheme)

        with self.assertRaises(NegoExParseError):
            NegoMessage(self._set_u32(nego, 8, MESSAGE_TYPE.CHALLENGE))
        with self.assertRaises(NegoExParseError):
            ExchangeMessage(self._set_u32(exchange, 8, MESSAGE_TYPE.VERIFY))
        with self.assertRaises(NegoExParseError):
            VerifyMessage(self._set_u32(verify, 8, MESSAGE_TYPE.ALERT))
        with self.assertRaises(NegoExParseError):
            AlertMessage(self._set_u32(alert, 8, MESSAGE_TYPE.VERIFY))

    def test_serialization_stability_and_guid_little_endian(self):
        self.assertEqual(40, HEADER_SIZE)
        self.assertEqual(96, NEGO_HEADER_SIZE)
        self.assertEqual(64, EXCHANGE_HEADER_SIZE)
        self.assertEqual(80, VERIFY_HEADER_SIZE)
        self.assertEqual(68, ALERT_HEADER_SIZE)

        self.assertEqual(40, len(MessageHeader().getData()))

        nego_data = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 7, self.conversation_id, [self.auth_scheme], [])
        exchange_data = createExchangeMessage(MESSAGE_TYPE.CHALLENGE, 7, self.conversation_id, self.auth_scheme, b'')
        verify_data = createVerifyMessage(7, self.conversation_id, self.auth_scheme, b'', 1)
        alert_data = createAlertMessage(7, self.conversation_id, self.auth_scheme)

        self.assertEqual(NEGO_HEADER_SIZE, NegoMessage(nego_data)['Header']['cbHeaderLength'])
        self.assertEqual(EXCHANGE_HEADER_SIZE, ExchangeMessage(exchange_data)['Header']['cbHeaderLength'])
        self.assertEqual(VERIFY_HEADER_SIZE, VerifyMessage(verify_data)['Header']['cbHeaderLength'])
        self.assertEqual(ALERT_HEADER_SIZE, AlertMessage(alert_data)['Header']['cbHeaderLength'])

        self.assertEqual(self.conversation_id.bytes_le, nego_data[24:40])
        self.assertEqual(self.auth_scheme.bytes_le, nego_data[NEGO_HEADER_SIZE:NEGO_HEADER_SIZE + 16])
        self.assertEqual(self.auth_scheme.bytes_le, exchange_data[40:56])


if __name__ == '__main__':
    unittest.main(verbosity=1)