
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

from impacket.krb5.gssapi import GSSAPI_RC4, KRB_OID, MechIndepToken


class _SessionKey:
    def __init__(self, contents):
        self.contents = contents


class KRB5GSSAPITests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
