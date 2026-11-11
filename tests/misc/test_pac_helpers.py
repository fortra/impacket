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
from struct import pack, pack_into

from impacket.krb5 import constants, pac


class TestPacHelpers(unittest.TestCase):

    @staticmethod
    def _build_pac_blob(descriptors):
        table_end = 8 + len(descriptors) * 16
        data_end = max(
            [table_end] + [offset + size for _, size, offset in descriptors]
        )
        data = bytearray(data_end)
        pack_into('<II', data, 0, len(descriptors), 0)
        for index, descriptor in enumerate(descriptors):
            pack_into('<IIQ', data, 8 + index * 16, *descriptor)
        return bytes(data)

    @classmethod
    def _build_single_buffer_pac(cls, buffer_type, payload):
        data = bytearray(cls._build_pac_blob([
            (buffer_type, len(payload), 24),
        ]))
        data[24:] = payload
        return bytes(data)

    def test_pac_type_rejects_truncated_buffer_table(self):
        data = pack('<II', 1, 0)

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_truncated_header(self):
        with self.assertRaises(ValueError):
            pac.PACTYPE(b'\x00' * 7)

    def test_pac_type_rejects_unsupported_version(self):
        data = pack('<II', 0, 1)

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_unaligned_buffer_offset(self):
        data = self._build_pac_blob([
            (pac.PAC_LOGON_INFO, 1, 25),
        ])

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_buffer_offset_inside_descriptor_table(self):
        data = self._build_pac_blob([
            (pac.PAC_LOGON_INFO, 1, 16),
        ])

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_buffer_past_input(self):
        data = self._build_pac_blob([
            (pac.PAC_LOGON_INFO, 2, 24),
        ])[:-1]

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_overlapping_buffers(self):
        data = self._build_pac_blob([
            (pac.PAC_LOGON_INFO, 8, 40),
            (pac.PAC_CLIENT_INFO_TYPE, 8, 44),
        ])

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_invalid_attributes_flags_length(self):
        data = self._build_single_buffer_pac(
            pac.PAC_ATTRIBUTES_INFO,
            pack('<II', 3, 1),
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_invalid_attributes_size(self):
        data = self._build_single_buffer_pac(
            pac.PAC_ATTRIBUTES_INFO,
            b'\x00' * 7,
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_unknown_attributes_flags(self):
        data = self._build_single_buffer_pac(
            pac.PAC_ATTRIBUTES_INFO,
            pack('<II', 2, 4),
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_requestor_sid_with_invalid_revision(self):
        data = self._build_single_buffer_pac(
            pac.PAC_REQUESTOR_INFO,
            pack('<BB6s', 2, 0, b'\x00\x00\x00\x00\x00\x05'),
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_truncated_requestor_sid(self):
        data = self._build_single_buffer_pac(
            pac.PAC_REQUESTOR_INFO,
            pack('<BB6s', 1, 1, b'\x00\x00\x00\x00\x00\x05'),
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_requestor_sid_trailing_data(self):
        data = self._build_single_buffer_pac(
            pac.PAC_REQUESTOR_INFO,
            pack('<BB6sB', 1, 0, b'\x00\x00\x00\x00\x00\x05', 0),
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_unsupported_signature_type(self):
        data = self._build_single_buffer_pac(
            pac.PAC_SERVER_CHECKSUM,
            pack('<l', -1) + b'\x00' * 12,
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_signature_without_type(self):
        data = self._build_single_buffer_pac(
            pac.PAC_SERVER_CHECKSUM,
            b'\x00' * 3,
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_truncated_signature(self):
        data = self._build_single_buffer_pac(
            pac.PAC_SERVER_CHECKSUM,
            pack('<l', constants.ChecksumTypes.hmac_sha1_96_aes128.value)
            + b'\x00' * 11,
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_truncated_hmac_md5_signature(self):
        data = self._build_single_buffer_pac(
            pac.PAC_SERVER_CHECKSUM,
            pack('<l', constants.ChecksumTypes.hmac_md5.value)
            + b'\x00' * 15,
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_rejects_signature_trailing_data(self):
        data = self._build_single_buffer_pac(
            pac.PAC_PRIVSVR_CHECKSUM,
            pack('<l', constants.ChecksumTypes.hmac_sha1_96_aes128.value)
            + b'\x00' * 15,
        )

        with self.assertRaises(ValueError):
            pac.PACTYPE(data)

    def test_pac_type_accepts_valid_fixed_buffers(self):
        requestor = pack(
            '<BB6sI',
            1,
            1,
            b'\x00\x00\x00\x00\x00\x05',
            21,
        )
        buffers = [
            (pac.PAC_ATTRIBUTES_INFO, pack('<II', 2, 3)),
            (pac.PAC_REQUESTOR_INFO, requestor),
            (
                pac.PAC_SERVER_CHECKSUM,
                pack('<l', constants.ChecksumTypes.hmac_sha1_96_aes128.value)
                + b'\x00' * 12,
            ),
            (
                pac.PAC_PRIVSVR_CHECKSUM,
                pack('<l', constants.ChecksumTypes.hmac_sha1_96_aes256.value)
                + b'\x00' * 14,
            ),
            (
                pac.PAC_SERVER_CHECKSUM,
                pack('<l', constants.ChecksumTypes.hmac_md5.value)
                + b'\x00' * 16,
            ),
        ]

        for buffer_type, payload in buffers:
            with self.subTest(buffer_type=buffer_type):
                pac.PACTYPE(self._build_single_buffer_pac(buffer_type, payload))

    def test_build_pac_type_uses_explicit_buffer_order(self):
        pac_infos = {
            pac.PAC_SERVER_CHECKSUM: b'server',
            pac.PAC_LOGON_INFO: b'logon',
            pac.PAC_CLIENT_INFO_TYPE: b'client',
            pac.PAC_PRIVSVR_CHECKSUM: b'priv',
        }

        pac_type = pac.build_pac_type(
            pac_infos,
            buffer_order=[
                pac.PAC_LOGON_INFO,
                pac.PAC_CLIENT_INFO_TYPE,
                pac.PAC_SERVER_CHECKSUM,
                pac.PAC_PRIVSVR_CHECKSUM,
            ],
        )

        buffer_blob = pac_type['Buffers']
        offset = 0
        buffer_types = []
        for _ in range(pac_type['cBuffers']):
            info_buffer = pac.PAC_INFO_BUFFER(buffer_blob[offset:])
            buffer_types.append(info_buffer['ulType'])
            offset += len(info_buffer)

        self.assertEqual(buffer_types, [
            pac.PAC_LOGON_INFO,
            pac.PAC_CLIENT_INFO_TYPE,
            pac.PAC_SERVER_CHECKSUM,
            pac.PAC_PRIVSVR_CHECKSUM,
        ])

    def test_sign_pac_infers_aes128_checksum_type_from_key_length(self):
        server_checksum = pac.PAC_SIGNATURE_DATA()
        server_checksum['SignatureType'] = constants.ChecksumTypes.hmac_md5.value
        server_checksum['Signature'] = b'\x00' * 12

        priv_checksum = pac.PAC_SIGNATURE_DATA()
        priv_checksum['SignatureType'] = constants.ChecksumTypes.hmac_md5.value
        priv_checksum['Signature'] = b'\x00' * 12

        pac_infos = {
            pac.PAC_LOGON_INFO: b'logon-info',
            pac.PAC_CLIENT_INFO_TYPE: b'client-info',
            pac.PAC_SERVER_CHECKSUM: server_checksum.getData(),
            pac.PAC_PRIVSVR_CHECKSUM: priv_checksum.getData(),
        }

        pac_type = pac.sign_pac(
            pac_infos,
            aes_key='41' * 16,
            infer_aes_signature_type=True,
        )

        updated_server = pac.PAC_SIGNATURE_DATA(pac_infos[pac.PAC_SERVER_CHECKSUM])
        updated_priv = pac.PAC_SIGNATURE_DATA(pac_infos[pac.PAC_PRIVSVR_CHECKSUM])

        self.assertEqual(updated_server['SignatureType'], constants.ChecksumTypes.hmac_sha1_96_aes128.value)
        self.assertEqual(updated_priv['SignatureType'], constants.ChecksumTypes.hmac_sha1_96_aes128.value)
        self.assertEqual(len(bytes(updated_server['Signature'])), 12)
        self.assertEqual(len(bytes(updated_priv['Signature'])), 12)
        self.assertEqual(pac_type['cBuffers'], 4)


if __name__ == '__main__':
    unittest.main()
