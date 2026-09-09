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

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID

from impacket.examples.ntlmrelayx.attacks.httpattacks.adcsattack import ADCSAttack


class ADCSCertificateSigningRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_generate_pem_csr_without_subject_or_extensions(self):
        data = ADCSAttack.generate_csr(self.key, None, None)
        request = x509.load_pem_x509_csr(data)

        self.assertTrue(data.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"))
        self.assertEqual(request.subject, x509.Name([]))
        self.assertEqual(len(request.extensions), 0)
        self.assertEqual(request.signature_hash_algorithm.name, "sha256")
        self.assertTrue(request.is_signature_valid)

    def test_generate_pem_csr_with_common_name_and_upn_san(self):
        upn = "alice@example.test"
        data = ADCSAttack.generate_csr(self.key, "alice", upn)
        request = x509.load_pem_x509_csr(data)

        common_names = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertEqual([attribute.value for attribute in common_names], ["alice"])

        extension = request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        other_names = extension.value.get_values_for_type(x509.OtherName)
        self.assertFalse(extension.critical)
        self.assertEqual(len(other_names), 1)
        self.assertEqual(other_names[0].type_id, ADCSAttack.UPN_OID)
        self.assertEqual(other_names[0].value, b"\x0c\x12alice@example.test")
        self.assertEqual(
            extension.value.public_bytes(),
            bytes.fromhex(
                "3024a022060a2b060104018237140203a0140c12"
                "616c696365406578616d706c652e74657374"
            )
        )
        self.assertTrue(request.is_signature_valid)

    def test_generate_der_csr_with_upn_and_sid_extensions(self):
        data = ADCSAttack.generate_csr(
            self.key,
            "alice",
            "alice@example.test",
            csr_type=Encoding.DER,
            altSid="S-1-5-21-1"
        )
        request = x509.load_der_x509_csr(data)

        self.assertFalse(data.startswith(b"-----BEGIN"))
        sid_extension = request.extensions.get_extension_for_oid(
            ADCSAttack.NTDS_CA_SECURITY_EXT_OID
        )
        self.assertFalse(sid_extension.critical)
        self.assertIsInstance(sid_extension.value, x509.UnrecognizedExtension)
        self.assertEqual(
            sid_extension.value.value,
            bytes.fromhex(
                "301ca01a060a2b060104018237190201a00c040a"
                "532d312d352d32312d31"
            )
        )
        self.assertIsNotNone(
            request.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
        )
        self.assertTrue(request.is_signature_valid)

    def test_generate_csr_accepts_legacy_pyopenssl_arguments(self):
        key = crypto.PKey.from_cryptography_key(self.key)
        cases = (
            (crypto.FILETYPE_PEM, x509.load_pem_x509_csr),
            (crypto.FILETYPE_ASN1, x509.load_der_x509_csr),
        )

        for csr_type, loader in cases:
            with self.subTest(csr_type=csr_type):
                data = ADCSAttack.generate_csr(
                    key,
                    "alice",
                    None,
                    csr_type=csr_type
                )
                request = loader(data)

                self.assertTrue(request.is_signature_valid)
                self.assertEqual(
                    request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                    "alice"
                )


if __name__ == '__main__':
    unittest.main(verbosity=1)
