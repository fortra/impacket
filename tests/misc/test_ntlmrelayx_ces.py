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
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import NameOID

from impacket.examples.ntlmrelayx.utils.ces import (
    ADDR_NS,
    AUTHZ_NS,
    CES_ACTION,
    CESConfigurationError,
    SOAP_NS,
    WSS_NS,
    allocate_artifact_paths,
    build_ces_soap,
    create_encrypted_pfx,
    decode_certificate,
    decode_pkcs7,
    derive_subject_cn,
    extract_response_tokens,
    generate_csr,
    secure_write,
    target_url,
    validate_ces_target,
)
from impacket.examples.ntlmrelayx.utils.targetsutils import CESTargetsProcessor, TargetsProcessor
try:
    from impacket.examples.ntlmrelayx.attacks.httpattacks.cesattack import CESAttack
except ImportError:
    CESAttack = None
try:
    from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient
    from impacket.examples.ntlmrelayx.clients import httprelayclient as http_client_module
except ImportError:
    HTTPRelayClient = None
    http_client_module = None


class CESHelperTests(unittest.TestCase):
    def test_target_validation_requires_explicit_http_url(self):
        for invalid in ("server", "smb://server/path", "ALL://server/path", "https:///path"):
            with self.subTest(invalid=invalid), self.assertRaises(CESConfigurationError):
                validate_ces_target(invalid)
        self.assertEqual(validate_ces_target("https://server:8443/service.svc/CES").port, 8443)

    def test_subject_and_generated_csr(self):
        self.assertEqual(derive_subject_cn("DOMAIN\\machine$"), "machine$")
        self.assertEqual(derive_subject_cn("DOMAIN/user@example.test"), "user")
        self.assertEqual(derive_subject_cn(""), "CES-Enrollment")
        encoded, key = generate_csr("DOMAIN\\machine$")
        request = x509.load_der_x509_csr(base64.b64decode(encoded))
        self.assertEqual(key.key_size, 4096)
        self.assertEqual(request.signature_hash_algorithm.name, "sha256")
        self.assertEqual(request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "machine$")
        self.assertEqual(len(request.extensions), 0)

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

    def _certificate_material(self):
        csr_b64, key = generate_csr("DOMAIN\\machine$")
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

    def test_response_selection_and_encrypted_pfx(self):
        key, certificate, cert_der, p7b_der = self._certificate_material()
        xml = ('<s:Envelope xmlns:s="%s" xmlns:o="%s"><s:Body>'
               '<o:BinarySecurityToken ValueType="PKCS7">\n%s\n</o:BinarySecurityToken>'
               '<o:BinarySecurityToken ValueType="X509v3">%s</o:BinarySecurityToken>'
               '</s:Body></s:Envelope>') % (
                   SOAP_NS, WSS_NS, base64.b64encode(p7b_der).decode(),
                   base64.b64encode(cert_der).decode())
        cert_tokens, p7b_tokens = extract_response_tokens(xml.encode())
        decoded_der, decoded_cert = decode_certificate(cert_tokens[-1])
        self.assertEqual(decoded_der, cert_der)
        self.assertEqual(decode_pkcs7(p7b_tokens[0]), p7b_der)
        pfx, password = create_encrypted_pfx(decoded_cert, key)
        loaded_key, loaded_cert, chain = pkcs12.load_key_and_certificates(pfx, password.encode())
        self.assertIsNotNone(loaded_key)
        self.assertEqual(loaded_cert.fingerprint(hashes.SHA256()), certificate.fingerprint(hashes.SHA256()))
        self.assertEqual(chain, [])
        with self.assertRaises(ValueError):
            pkcs12.load_key_and_certificates(pfx, b"wrong-password")

    def test_fault_and_malformed_response(self):
        fault = ('<s:Envelope xmlns:s="%s"><s:Body><s:Fault><s:Reason>'
                 '<s:Text>denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>') % SOAP_NS
        with self.assertRaisesRegex(RuntimeError, "SOAP fault: denied"):
            extract_response_tokens(fault.encode())
        with self.assertRaisesRegex(RuntimeError, "malformed XML"):
            extract_response_tokens(b"<not-closed")

    def test_unique_private_artifact_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = allocate_artifact_paths(directory, "DOMAIN\\user")
            secure_write(paths["cer"], b"certificate")
            self.assertEqual(os.stat(paths["cer"]).st_mode & 0o777, 0o600)
            second = allocate_artifact_paths(directory, "DOMAIN\\user")
            self.assertNotEqual(paths["cer"], second["cer"])

    def test_target_url_removes_identity_and_keeps_explicit_port(self):
        target = urlparse("https://DOMAIN%5Cuser@[2001:db8::1]:443/service.svc/CES?q=1")
        self.assertEqual(target_url(target), "https://[2001:db8::1]:443/service.svc/CES?q=1")


@unittest.skipIf(HTTPRelayClient is None, "optional ntlmrelayx test dependencies are unavailable")
class CESHTTPClientTests(unittest.TestCase):
    class Headers:
        def __init__(self, values):
            self.values = values

        def get_all(self, name):
            return self.values if name == "WWW-Authenticate" else None

    class Response:
        reason = "test"

        def __init__(self, status, headers=(), body=b""):
            self.status = status
            self.msg = CESHTTPClientTests.Headers(list(headers))
            self.body = body
            self.read_called = False

        def getheader(self, name):
            values = self.msg.get_all(name)
            return ", ".join(values) if values else None

        def read(self):
            self.read_called = True
            return self.body

    class Connection:
        def __init__(self, responses):
            self.responses = list(responses)
            self.requests = []

        def request(self, method, path, body=None, headers=None):
            self.requests.append((method, path, body, headers or {}))

        def getresponse(self):
            return self.responses.pop(0)

    @staticmethod
    def client(is_ces, responses):
        client = HTTPRelayClient.__new__(HTTPRelayClient)
        client.serverConfig = SimpleNamespace(isCESAttack=is_ces, isADCSAttack=False)
        client.targetHost = "ca.example.test"
        client.path = "/service.svc/CES"
        client.query = "q=1"
        client.session = CESHTTPClientTests.Connection(responses)
        client.authenticationMethod = None
        client.lastresult = None
        return client

    def test_ces_handshake_uses_empty_posts_and_drains_responses(self):
        token = base64.b64encode(b"NTLMSSP challenge").decode()
        responses = [
            self.Response(401, ["Negotiate"]),
            self.Response(401, ["Negotiate " + token]),
            self.Response(200, body=b"authenticated"),
        ]
        client = self.client(True, responses)
        with patch.object(http_client_module, "NTLMAuthChallenge") as challenge_class:
            challenge = challenge_class.return_value
            self.assertIs(client.sendNegotiate(b"NTLMSSP negotiate"), challenge)
        _, status = client.sendAuth(b"NTLMSSP authenticate")
        self.assertEqual(status, http_client_module.STATUS_SUCCESS)
        self.assertEqual([request[0] for request in client.session.requests], ["POST", "POST", "POST"])
        self.assertTrue(all(request[1] == "/service.svc/CES?q=1" for request in client.session.requests))
        self.assertTrue(all(response.read_called for response in responses))

    def test_ces_invalid_endpoint_fails_on_first_relay_attempt(self):
        response = self.Response(404)
        client = self.client(True, [response])
        self.assertFalse(client.sendNegotiate(b"negotiate"))
        self.assertEqual(len(client.session.requests), 1)
        self.assertEqual(client.session.requests[0][0], "POST")
        self.assertTrue(response.read_called)

    def test_ces_malformed_challenge_and_final_401_fail_closed(self):
        malformed = self.client(True, [
            self.Response(401, ["Negotiate"]), self.Response(401, ["Negotiate !!!"])
        ])
        self.assertFalse(malformed.sendNegotiate(b"negotiate"))

        rejected_response = self.Response(401, ["Negotiate"])
        rejected = self.client(True, [rejected_response])
        _, status = rejected.sendAuth(b"NTLMSSP authenticate")
        self.assertEqual(status, http_client_module.STATUS_ACCESS_DENIED)
        self.assertTrue(rejected_response.read_called)

    def test_normal_http_handshake_still_uses_get(self):
        token = base64.b64encode(b"NTLMSSP challenge").decode()
        client = self.client(False, [
            self.Response(401, ["NTLM"]), self.Response(401, ["NTLM " + token])
        ])
        with patch.object(http_client_module, "NTLMAuthChallenge"):
            self.assertTrue(client.sendNegotiate(b"NTLMSSP negotiate"))
        self.assertEqual([request[0] for request in client.session.requests], ["GET", "GET"])


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

    def test_enrollment_uses_supplied_authenticated_connection(self):
        helper = CESHelperTests()
        key, certificate, cert_der, p7b_der = helper._certificate_material()
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
            attack.config = SimpleNamespace(template=None, cesOutputDir=directory)
            with patch(
                "impacket.examples.ntlmrelayx.attacks.httpattacks.cesattack.generate_csr",
                return_value=("Y3Ny", key),
            ):
                attack._run()

            self.assertEqual(len(connection.requests), 1)
            method, path, body, headers = connection.requests[0]
            self.assertEqual((method, path), ("POST", "/service.svc/CES?q=1"))
            self.assertEqual(headers["Content-Length"], str(len(body)))
            self.assertEqual(sorted(os.listdir(directory)), [
                "DOMAIN_machine$.cer", "DOMAIN_machine$.p7b", "DOMAIN_machine$.pfx"
            ])
            self.assertFalse(any(name.endswith(".key") or name.endswith(".xml") for name in os.listdir(directory)))


class CESTargetTests(unittest.TestCase):
    def test_failed_target_is_retried_without_clearing_success(self):
        processor = CESTargetsProcessor(
            singleTarget="https://ca.example.test/service.svc/CES",
            protocolClients={"HTTP": object, "HTTPS": object},
        )
        target = processor.getTarget(multiRelay=False)
        processor.registerTarget(target, False, "DOMAIN/user1")
        self.assertEqual(processor.failedAttacks, [])
        self.assertIsNotNone(processor.getTarget(multiRelay=False))

        successful = urlparse("https://DOMAIN%5Cuser2@ca.example.test/service.svc/CES")
        processor.registerTarget(successful, True, "DOMAIN/user2")
        processor.registerTarget(target, False, "DOMAIN/user1")
        self.assertIn(successful, processor.finishedAttacks)

    def test_normal_processor_still_records_failure(self):
        processor = TargetsProcessor(singleTarget="https://ca.example.test/", protocolClients={"HTTPS": object})
        target = processor.getTarget(multiRelay=False)
        processor.registerTarget(target, False, "DOMAIN/user")
        self.assertEqual(len(processor.failedAttacks), 1)


if __name__ == "__main__":
    unittest.main(verbosity=1)
