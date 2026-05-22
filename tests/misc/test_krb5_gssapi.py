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

from impacket.krb5 import constants
from impacket.krb5.gssapi import (
    GSSAPI,
    GSSAPI_AES128,
    GSSAPI_AES256,
    GSSAPI_RC4,
    KRB_OID,
    MechIndepToken,
    _calculateMICPad,
)


class _SessionKey:
    def __init__(self, contents):
        self.contents = contents


class KRB5GSSAPITests(unittest.TestCase):
    def test_mechindep_token_from_bytes_invalid_tag_raises(self):
        with self.assertRaises(Exception):
            MechIndepToken.from_bytes(b"\x61\x00")

    def test_mechindep_token_length_helpers_round_trip(self):
        for length in (0, 1, 127, 128, 255, 256, 4096):
            encoded = MechIndepToken.encode_length(length)
            decoded, remaining = MechIndepToken.get_length(encoded + b"tail")
            self.assertEqual(decoded, length)
            self.assertEqual(remaining, b"tail")

    def test_mechindep_token_from_bytes_short_form_length(self):
        payload = b"A" * 10
        token_data = KRB_OID + payload
        raw = b"\x60" + bytes([len(token_data)]) + token_data

        parsed = MechIndepToken.from_bytes(raw)

        self.assertEqual(parsed.token_oid, KRB_OID)
        self.assertEqual(parsed.data, payload)

    def test_mechindep_token_from_bytes_long_form_length(self):
        payload = b"B" * 140
        token_data = KRB_OID + payload
        raw = b"\x60" + MechIndepToken.encode_length(len(token_data)) + token_data

        parsed = MechIndepToken.from_bytes(raw)

        self.assertEqual(parsed.token_oid, KRB_OID)
        self.assertEqual(parsed.data, payload)

    def test_mechindep_token_to_bytes_round_trip(self):
        payload = b"hello-token"
        token = MechIndepToken(payload, KRB_OID)
        header, body = token.to_bytes()
        parsed = MechIndepToken.from_bytes(header + body)

        self.assertEqual(header + body, b"\x60" + MechIndepToken.encode_length(len(KRB_OID + payload)) + KRB_OID + payload)
        self.assertEqual(parsed.token_oid, KRB_OID)
        self.assertEqual(parsed.data, payload)

    def test_calculate_mic_pad(self):
        self.assertEqual(_calculateMICPad(b""), b"")
        self.assertEqual(_calculateMICPad(b"A"), b"\x03" * 3)
        self.assertEqual(_calculateMICPad(b"AB"), b"\x02" * 2)
        self.assertEqual(_calculateMICPad(b"ABCD"), b"")

    def test_gssapi_factory_returns_expected_impl(self):
        class _Cipher:
            def __init__(self, enctype):
                self.enctype = enctype

        self.assertIsInstance(
            GSSAPI(_Cipher(constants.EncryptionTypes.rc4_hmac.value)),
            GSSAPI_RC4,
        )
        self.assertIsInstance(
            GSSAPI(_Cipher(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)),
            GSSAPI_AES128,
        )
        self.assertIsInstance(
            GSSAPI(_Cipher(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)),
            GSSAPI_AES256,
        )
        with self.assertRaises(Exception):
            GSSAPI(_Cipher(0xFFFF))

    def test_gssapi_rc4_getmic_changes_with_direction(self):
        gssapi = GSSAPI_RC4()
        session_key = _SessionKey(b"\x11" * 16)
        data = b"mic-data"
        sequence_number = 3

        init_mic = gssapi.GSS_GetMIC(session_key, data, sequence_number, direction="init")
        accept_mic = gssapi.GSS_GetMIC(session_key, data, sequence_number, direction="accept")

        self.assertTrue(init_mic.startswith(b"\x60\x23"))
        self.assertTrue(accept_mic.startswith(b"\x60\x23"))
        self.assertNotEqual(init_mic, accept_mic)

    def test_gssapi_rc4_wrap_without_encryption_returns_padded_plaintext(self):
        gssapi = GSSAPI_RC4()
        session_key = _SessionKey(b"\x22" * 16)
        plain_text = b"abc"

        cipher_text, header = gssapi.GSS_Wrap(
            session_key, plain_text, 1, direction="init", encrypt=False
        )

        self.assertEqual(cipher_text, b"abc" + b"\x05" * 5)
        self.assertTrue(header.startswith(b"\x60\x2b"))

    def test_gssapi_rc4_ldap_wrap_unwrap_round_trip(self):
        gssapi = GSSAPI_RC4()
        session_key = _SessionKey(b"\x41" * 16)
        plain_text = b"ldap-sign-and-seal-payload"
        sequence_number = 7

        cipher_text, header = gssapi.GSS_Wrap_LDAP(
            session_key, plain_text, sequence_number, encrypt=True
        )
        unwrapped, _ = gssapi.GSS_Unwrap_LDAP(
            session_key, header + cipher_text, sequence_number
        )

        self.assertEqual(unwrapped, plain_text)

    def test_gssapi_aes_rotate_unrotate_inverse(self):
        gssapi = GSSAPI_AES128()
        data = b"0123456789abcdef"

        for amount in (0, 1, 5, len(data), len(data) + 3):
            rotated = gssapi.rotate(data, amount)
            unrotated = gssapi.unrotate(rotated, amount)
            self.assertEqual(unrotated, data)


if __name__ == "__main__":
    unittest.main(verbosity=1)
