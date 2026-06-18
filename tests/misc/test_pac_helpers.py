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

from impacket.krb5 import constants, pac


class TestPacHelpers(unittest.TestCase):

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
