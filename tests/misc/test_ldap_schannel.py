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
# Description:
#   LDAP Schannel (TLS client certificate) loading unit tests
#
import datetime
import os
import shutil
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

from impacket.ldap.ldap import LDAPConnection, LDAPSessionError, certificate_file_type, load_pkcs12


def generate_certificate(commonName):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, commonName)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name)\
        .public_key(key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(now - datetime.timedelta(days=1))\
        .not_valid_after(now + datetime.timedelta(days=1))\
        .sign(key, hashes.SHA256())
    return key, certificate


class LDAPSchannelTests(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.key, self.certificate = generate_certificate('schannel.impacket.local')
        self.otherKey, self.otherCertificate = generate_certificate('other.impacket.local')

        self.pfxfile = self.write_pkcs12('cert.pfx', self.key, self.certificate)
        self.encryptedPfxfile = self.write_pkcs12('encrypted.pfx', self.key, self.certificate, b'Passw0rd!')
        self.certfile = self.write_file('cert.pem', self.certificate.public_bytes(serialization.Encoding.PEM))
        self.keyfile = self.write_file('key.pem', self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.otherKeyfile = self.write_file('other_key.pem', self.otherKey.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.derCertfile = self.write_file('cert.der', self.certificate.public_bytes(serialization.Encoding.DER))
        self.derKeyfile = self.write_file('key.der', self.key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def write_file(self, name, data):
        path = os.path.join(self.directory, name)
        with open(path, 'wb') as fd:
            fd.write(data)
        return path

    def write_pkcs12(self, name, key, certificate, password=None):
        encryption = serialization.NoEncryption() if password is None \
            else serialization.BestAvailableEncryption(password)
        data = serialization.pkcs12.serialize_key_and_certificates(b'test', key, certificate, None, encryption)
        return self.write_file(name, data)

    def build_connection(self, **kwargs):
        """Build an LDAPConnection without touching the network, only the certificate attributes are needed."""
        connection = LDAPConnection.__new__(LDAPConnection)
        connection._certfile = kwargs.get('certfile')
        connection._keyfile = kwargs.get('keyfile')
        connection._pfxfile = kwargs.get('pfxfile')
        connection._pfxpass = kwargs.get('pfxpass')
        connection._client_cert_loaded = False
        return connection

    def test_load_pkcs12(self):
        certificate, privateKey = load_pkcs12(self.pfxfile)
        self.assertEqual(certificate.get_subject().CN, 'schannel.impacket.local')
        self.assertEqual(certificate.get_serial_number(), self.certificate.serial_number)
        self.assertEqual(privateKey.to_cryptography_key().private_numbers(), self.key.private_numbers())

    def test_load_pkcs12_with_password(self):
        for password in ('Passw0rd!', b'Passw0rd!'):
            certificate, _ = load_pkcs12(self.encryptedPfxfile, password)
            self.assertEqual(certificate.get_subject().CN, 'schannel.impacket.local')

    def test_load_pkcs12_wrong_password(self):
        with self.assertRaises(LDAPSessionError):
            load_pkcs12(self.encryptedPfxfile, 'wrong')

    def test_load_pkcs12_missing_file(self):
        with self.assertRaises(LDAPSessionError):
            load_pkcs12(os.path.join(self.directory, 'nonexistent.pfx'))

    def test_load_pkcs12_without_private_key(self):
        data = serialization.pkcs12.serialize_key_and_certificates(
            b'test', None, self.certificate, None, serialization.NoEncryption())
        pfxfile = self.write_file('no_key.pfx', data)
        with self.assertRaises(LDAPSessionError):
            load_pkcs12(pfxfile)

    def test_context_without_certificate(self):
        connection = self.build_connection()
        connection.build_tls_context()
        self.assertFalse(connection._client_cert_loaded)

    def test_context_with_pkcs12(self):
        connection = self.build_connection(pfxfile=self.encryptedPfxfile, pfxpass='Passw0rd!')
        connection.build_tls_context()
        self.assertTrue(connection._client_cert_loaded)

    def test_context_with_pem_pair(self):
        connection = self.build_connection(certfile=self.certfile, keyfile=self.keyfile)
        connection.build_tls_context()
        self.assertTrue(connection._client_cert_loaded)

    def test_certificate_file_type(self):
        self.assertEqual(certificate_file_type(self.certfile), crypto.FILETYPE_PEM)
        self.assertEqual(certificate_file_type(self.keyfile), crypto.FILETYPE_PEM)
        self.assertEqual(certificate_file_type(self.derCertfile), crypto.FILETYPE_ASN1)
        self.assertEqual(certificate_file_type(self.derKeyfile), crypto.FILETYPE_ASN1)
        with self.assertRaises(LDAPSessionError):
            certificate_file_type(os.path.join(self.directory, 'nonexistent.pem'))

    def test_context_with_der_pair(self):
        connection = self.build_connection(certfile=self.derCertfile, keyfile=self.derKeyfile)
        connection.build_tls_context()
        self.assertTrue(connection._client_cert_loaded)

    def test_context_with_mixed_pem_and_der(self):
        connection = self.build_connection(certfile=self.derCertfile, keyfile=self.keyfile)
        connection.build_tls_context()
        self.assertTrue(connection._client_cert_loaded)

    def test_context_requires_both_pem_files(self):
        connection = self.build_connection(certfile=self.certfile)
        with self.assertRaises(LDAPSessionError):
            connection.build_tls_context()
        self.assertFalse(connection._client_cert_loaded)

    def test_context_rejects_mismatched_pair(self):
        connection = self.build_connection(certfile=self.certfile, keyfile=self.otherKeyfile)
        with self.assertRaises(LDAPSessionError):
            connection.build_tls_context()
        self.assertFalse(connection._client_cert_loaded)


if __name__ == '__main__':
    unittest.main(verbosity=1)
