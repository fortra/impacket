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

import hashlib
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes

from impacket.ldap import ldap


class LDAPChannelBindingTests(unittest.TestCase):
    DER_CERTIFICATE = b'deterministic-certificate-der'

    @staticmethod
    def _expected_channel_binding(endpoint_digest):
        application_data = b'tls-server-end-point:' + endpoint_digest
        channel_binding_struct = b'\x00' * 16
        channel_binding_struct += len(application_data).to_bytes(4, byteorder='little')
        channel_binding_struct += application_data
        return hashlib.md5(channel_binding_struct).digest()

    def _create_connection(self, signature_hash_algorithm, use_ssl=True):
        scheme = 'ldaps' if use_ssl else 'ldap'
        port = 636 if use_ssl else 389
        socket_mock = Mock()
        tls_socket_mock = Mock()
        tls_socket_mock.get_peer_certificate.return_value = Mock()
        parsed_certificate = SimpleNamespace(signature_hash_algorithm=signature_hash_algorithm)
        address_info = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', port))
        ]

        with patch.object(ldap.socket, 'getaddrinfo', return_value=address_info), \
             patch.object(ldap.socket, 'socket', return_value=socket_mock), \
             patch.object(ldap.SSL, 'Context', return_value=Mock()), \
             patch.object(ldap.SSL, 'Connection', return_value=tls_socket_mock), \
             patch.object(ldap.crypto, 'dump_certificate', return_value=self.DER_CERTIFICATE), \
             patch('cryptography.x509.load_der_x509_certificate', return_value=parsed_certificate):
            return ldap.LDAPConnection('%s://dc.example.test' % scheme)

    def test_weak_certificate_hashes_use_sha256(self):
        expected = self._expected_channel_binding(hashlib.sha256(self.DER_CERTIFICATE).digest())

        for signature_hash_algorithm in (hashes.MD5(), hashes.SHA1()):
            with self.subTest(signature_hash_algorithm=signature_hash_algorithm.name):
                connection = self._create_connection(signature_hash_algorithm)
                self.assertEqual(connection._get_channel_binding_value(), expected)

    def test_certificate_hash_algorithm_is_used_for_channel_binding(self):
        test_cases = (
            (hashes.SHA256(), hashlib.sha256),
            (hashes.SHA384(), hashlib.sha384),
            (hashes.SHA512(), hashlib.sha512),
        )

        for signature_hash_algorithm, expected_hash in test_cases:
            with self.subTest(signature_hash_algorithm=signature_hash_algorithm.name):
                connection = self._create_connection(signature_hash_algorithm)
                expected = self._expected_channel_binding(
                    expected_hash(self.DER_CERTIFICATE).digest()
                )
                self.assertEqual(connection._get_channel_binding_value(), expected)

    def test_signature_without_hash_fails_closed_when_binding_is_requested(self):
        connection = self._create_connection(None)

        self.assertIsNone(connection.channel_binding_value)
        with self.assertRaisesRegex(
            ldap.LDAPSessionError,
            'certificate signature algorithm does not use a separate hash function',
        ):
            connection._get_channel_binding_value()

    def test_signature_without_hash_allows_simple_bind(self):
        connection = self._create_connection(None)
        connection.sendReceive = Mock(return_value=[{
            'protocolOp': {
                'bindResponse': {
                    'resultCode': ldap.ResultCode('success'),
                },
            },
        }])

        self.assertTrue(connection.login(user='user', password='password', authenticationChoice='simple'))

    def test_plain_ldap_has_no_channel_binding(self):
        connection = self._create_connection(None, use_ssl=False)

        self.assertEqual(connection._get_channel_binding_value(), b'')


if __name__ == '__main__':
    unittest.main(verbosity=1)
