# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import unittest

from impacket.dcerpc.v5 import fsrvp
from impacket.uuid import string_to_bin


class CaptureDCE(object):
    def request(self, request):
        return request


class FSRVPNDRTests(unittest.TestCase):
    SET_ID = string_to_bin('00112233-4455-6677-8899-aabbccddeeff')
    SHADOW_ID = string_to_bin('10213243-5465-7687-98a9-bacbdcedfe0f')
    SHARE_NAME = r'\\server\share'

    def assert_round_trip(self, value):
        encoded = value.getData()
        decoded = value.__class__(encoded, isNDR64=value._isNDR64)
        self.assertEqual(encoded, decoded.getData())
        return decoded

    def test_all_opnums_are_registered(self):
        self.assertEqual(set(fsrvp.OPNUMS), set(range(13)))
        for opnum, (request_type, response_type) in fsrvp.OPNUMS.items():
            self.assertEqual(request_type.opnum, opnum)
            self.assertTrue(response_type.__name__.endswith('Response'))

    def test_all_helpers_build_serializable_requests(self):
        calls = (
            lambda dce: fsrvp.hGetSupportedVersion(dce),
            lambda dce: fsrvp.hSetContext(dce, fsrvp.ContextValues.CTX_FILE_SHARE_BACKUP),
            lambda dce: fsrvp.hStartShadowCopySet(dce, self.SET_ID),
            lambda dce: fsrvp.hAddToShadowCopySet(dce, self.SHADOW_ID, self.SET_ID, self.SHARE_NAME),
            lambda dce: fsrvp.hCommitShadowCopySet(dce, self.SET_ID, 30000),
            lambda dce: fsrvp.hExposeShadowCopySet(dce, self.SET_ID, 30000),
            lambda dce: fsrvp.hRecoveryCompleteShadowCopySet(dce, self.SET_ID),
            lambda dce: fsrvp.hAbortShadowCopySet(dce, self.SET_ID),
            lambda dce: fsrvp.hIsPathSupported(dce, self.SHARE_NAME),
            lambda dce: fsrvp.hIsPathShadowCopied(dce, self.SHARE_NAME),
            lambda dce: fsrvp.hGetShareMapping(dce, self.SHADOW_ID, self.SET_ID, self.SHARE_NAME),
            lambda dce: fsrvp.hDeleteShareMapping(dce, self.SET_ID, self.SHADOW_ID, self.SHARE_NAME),
            lambda dce: fsrvp.hPrepareShadowCopySet(dce, self.SET_ID, 30000),
        )

        for opnum, call in enumerate(calls):
            with self.subTest(opnum=opnum):
                request = call(CaptureDCE())
                self.assertIsInstance(request, fsrvp.OPNUMS[opnum][0])
                self.assertEqual(request.opnum, opnum)
                self.assert_round_trip(request)

    def build_response(self, opnum, is_ndr64):
        response = fsrvp.OPNUMS[opnum][1](isNDR64=is_ndr64)
        response['ErrorCode'] = 0

        if opnum == 0:
            response['MinVersion'] = 1
            response['MaxVersion'] = 1
        elif opnum == 2:
            response['pShadowCopySetId'] = self.SET_ID
        elif opnum == 3:
            response['ShadowCopyId'] = self.SHADOW_ID
        elif opnum == 8:
            response['SupportedByThisProvider'] = 1
            response['OwnerMachineName'] = 'server\x00'
        elif opnum == 9:
            response['ShadowCopyPresent'] = 1
            response['ShadowCopyCompatibility'] = 0
        elif opnum == 10:
            mapping = response['ShareMapping']
            mapping['tag'] = 1
            mapping['ShareMapping1']['ShadowCopySetId'] = self.SET_ID
            mapping['ShareMapping1']['ShadowCopyId'] = self.SHADOW_ID
            mapping['ShareMapping1']['ShareNameUNC'] = self.SHARE_NAME + '\x00'
            mapping['ShareMapping1']['ShadowCopyShareName'] = r'\\server\shadow' + '\x00'
            mapping['ShareMapping1']['CreationTimestamp'] = 132537600000000000

        return response

    def test_all_responses_round_trip(self):
        for is_ndr64 in (False, True):
            for opnum in fsrvp.OPNUMS:
                with self.subTest(opnum=opnum, isNDR64=is_ndr64):
                    self.assert_round_trip(self.build_response(opnum, is_ndr64))


if __name__ == '__main__':
    unittest.main(verbosity=1)
