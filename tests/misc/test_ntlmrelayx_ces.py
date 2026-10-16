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

import base64
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import NameOID

from impacket.examples.ntlmrelayx.utils.ces import (
    ADDR_NS,
    AUTHZ_NS,
    CES_ACTION,
    CESConfigurationError,
    SOAP_NS,
    WSS_NS,
    build_ces_soap,
    decode_certificate,
    decode_pkcs7,
    derive_subject_cn,
    extract_response_tokens,
    target_url,
    validate_ces_target,
)
try:
    from impacket.examples.ntlmrelayx.attacks.httpattacks.cesattack import CESAttack
except ImportError:
    CESAttack = None


class CESHelperTests(unittest.TestCase):
    def test_target_validation_requires_explicit_http_url(self):
        for invalid in ("server", "smb://server/path", "ALL://server/path", "https:///path"):
            with self.subTest(invalid=invalid), self.assertRaises(CESConfigurationError):
                validate_ces_target(invalid)
        self.assertEqual(validate_ces_target("https://server:8443/service.svc/CES").port, 8443)

    def test_subject_common_name_derivation(self):
        self.assertEqual(derive_subject_cn("DOMAIN\\machine$"), "machine$")
        self.assertEqual(derive_subject_cn("DOMAIN/user@example.test"), "user")
        self.assertEqual(derive_subject_cn(""), "CES-Enrollment")

    def test_soap_escapes_values_and_preserves_target(self):
        soap = build_ces_soap(
            "https://DOMAIN%5Cuser@[2001:db8::1]:443/service.svc/CES?a=1&b=2",
            "Y3Ny",
            "Machine&A",
            message_id="urn:uuid:test",
        )
        self.assertIn('xmlns:a="%s"' % ADDR_NS, soap)
        self.assertIn('xmlns:s="%s"' % SOAP_NS, soap)
        self.assertIn(CES_ACTION, soap)
        self.assertIn("Machine&amp;A", soap)
        self.assertIn('<AdditionalContext xmlns="%s"><ContextItem' % AUTHZ_NS, soap)
        self.assertIn("https://[2001:db8::1]:443/service.svc/CES?a=1&amp;b=2", soap)
        self.assertNotIn("DOMAIN%5Cuser@", soap)
        self.assertNotIn("\n        <ContextItem", soap)

    @staticmethod
    def certificate_material():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "machine$")])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        p7b_der = (
            pkcs7.PKCS7SignatureBuilder().set_data(b"test")
            .add_signer(certificate, key, hashes.SHA256())
            .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        )
        return key, certificate, cert_der, p7b_der

    def test_response_token_selection_and_validation(self):
        _, certificate, cert_der, p7b_der = self.certificate_material()
        xml = ('<s:Envelope xmlns:s="%s" xmlns:o="%s"><s:Body>'
               '<o:BinarySecurityToken ValueType="PKCS7">\n%s\n</o:BinarySecurityToken>'
               '<o:BinarySecurityToken ValueType="X509v3">%s</o:BinarySecurityToken>'
               '</s:Body></s:Envelope>') % (
                   SOAP_NS, WSS_NS, base64.b64encode(p7b_der).decode(),
                   base64.b64encode(cert_der).decode())
        cert_tokens, p7b_tokens = extract_response_tokens(xml.encode())
        decoded_der, decoded_cert = decode_certificate(cert_tokens[-1])
        self.assertEqual(decoded_der, cert_der)
        self.assertEqual(decoded_cert.fingerprint(hashes.SHA256()), certificate.fingerprint(hashes.SHA256()))
        self.assertEqual(decode_pkcs7(p7b_tokens[0]), p7b_der)

    def test_fault_and_malformed_response(self):
        fault = ('<s:Envelope xmlns:s="%s"><s:Body><s:Fault><s:Reason>'
                 '<s:Text>denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>') % SOAP_NS
        with self.assertRaisesRegex(RuntimeError, "SOAP fault: denied"):
            extract_response_tokens(fault.encode())
        with self.assertRaisesRegex(RuntimeError, "malformed XML"):
            extract_response_tokens(b"<not-closed")

    def test_target_url_removes_identity_and_keeps_explicit_port(self):
        target = urlparse("https://DOMAIN%5Cuser@[2001:db8::1]:443/service.svc/CES?q=1")
        self.assertEqual(target_url(target), "https://[2001:db8::1]:443/service.svc/CES?q=1")


@unittest.skipIf(CESAttack is None, "optional ntlmrelayx test dependencies are unavailable")
class CESAttackTests(unittest.TestCase):
    class Response:
        status = 200
        reason = "OK"

        def __init__(self, body):
            self.stream = io.BytesIO(body)

        def read(self, size=-1):
            return self.stream.read(size)

    class Connection:
        def __init__(self, response):
            self.response = response
            self.requests = []

        def request(self, method, path, body=None, headers=None):
            self.requests.append((method, path, body, headers))

        def getresponse(self):
            return self.response

    def test_enrollment_uses_authenticated_connection_and_lootdir(self):
        key, certificate, cert_der, p7b_der = CESHelperTests.certificate_material()
        xml = ('<s:Envelope xmlns:s="%s" xmlns:o="%s"><s:Body>'
               '<o:BinarySecurityToken ValueType="PKCS7">%s</o:BinarySecurityToken>'
               '<o:BinarySecurityToken ValueType="X509v3">%s</o:BinarySecurityToken>'
               '</s:Body></s:Envelope>') % (
                   SOAP_NS, WSS_NS, base64.b64encode(p7b_der).decode(),
                   base64.b64encode(cert_der).decode())
        connection = self.Connection(self.Response(xml.encode()))
        with tempfile.TemporaryDirectory() as directory:
            attack = CESAttack()
            attack.domain = "DOMAIN"
            attack.username = "machine$"
            attack.target = urlparse("https://ca.example.test/service.svc/CES?q=1")
            attack.relay_client = SimpleNamespace(path="/service.svc/CES", query="q=1")
            attack.client = connection
            attack.config = SimpleNamespace(template=None, lootdir=directory)
            with patch(
                "impacket.examples.ntlmrelayx.attacks.httpattacks.cesattack.rsa.generate_private_key",
                return_value=key,
            ):
                attack._run()

            self.assertEqual(len(connection.requests), 1)
            method, path, body, headers = connection.requests[0]
            self.assertEqual((method, path), ("POST", "/service.svc/CES?q=1"))
            self.assertEqual(headers["Content-Length"], str(len(body)))
            self.assertIn(b"<Value>Machine</Value>", body)
            self.assertEqual(sorted(os.listdir(directory)), [
                "DOMAIN_machine.cer", "DOMAIN_machine.p7b", "DOMAIN_machine.pfx"
            ])
            with open(os.path.join(directory, "DOMAIN_machine.pfx"), "rb") as pfx_file:
                loaded_key, loaded_cert, chain = pkcs12.load_key_and_certificates(pfx_file.read(), None)
            self.assertIsNotNone(loaded_key)
            self.assertEqual(loaded_cert.fingerprint(hashes.SHA256()), certificate.fingerprint(hashes.SHA256()))
            self.assertEqual(chain, [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
