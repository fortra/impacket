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

from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.dtypes import LPDWORD, NULL


class CaptureDCE(object):
    def request(self, request):
        return request


class SCMRNDRTests(unittest.TestCase):
    HANDLE = b'H' * 20

    def assert_round_trip(self, value):
        encoded = value.getData()
        decoded = value.__class__(encoded, isNDR64=value._isNDR64)
        self.assertEqual(encoded, decoded.getData())
        return decoded

    def test_new_opnum_mappings(self):
        self.assertEqual(
            scmr.OPNUMS[60],
            (scmr.RCreateWowService, scmr.RCreateWowServiceResponse),
        )
        self.assertEqual(
            scmr.OPNUMS[64],
            (scmr.ROpenSCManager2, scmr.ROpenSCManager2Response),
        )

    def test_create_wow_service_helper_builds_serializable_request(self):
        tag_id = LPDWORD()
        tag_id['Data'] = 0x11223344

        request = scmr.hRCreateWowServiceW(
            CaptureDCE(),
            self.HANDLE,
            'offline-service',
            'Offline Service',
            lpBinaryPathName=r'C:\offline-service.exe',
            lpLoadOrderGroup='System Reserved',
            lpdwTagId=tag_id,
            dwServiceWowType=scmr.IMAGE_FILE_MACHINE_AMD64,
        )

        self.assertIsInstance(request, scmr.RCreateWowService)
        self.assertEqual(request.opnum, 60)
        decoded = self.assert_round_trip(request)
        self.assertEqual(decoded['lpdwTagId'], 0x11223344)
        self.assertEqual(decoded['dwServiceWowType'], scmr.IMAGE_FILE_MACHINE_AMD64)

    def test_open_sc_manager2_helper_builds_serializable_request(self):
        request = scmr.hROpenSCManager2(
            CaptureDCE(),
            lpDatabaseName='ServicesActive',
            dwDesiredAccess=scmr.SC_MANAGER_CONNECT,
        )

        self.assertIsInstance(request, scmr.ROpenSCManager2)
        self.assertEqual(request.opnum, 64)
        decoded = self.assert_round_trip(request)
        self.assertEqual(decoded['dwDesiredAccess'], scmr.SC_MANAGER_CONNECT)

    def test_create_wow_service_response_round_trip(self):
        for is_ndr64 in (False, True):
            with self.subTest(isNDR64=is_ndr64):
                response = scmr.RCreateWowServiceResponse(isNDR64=is_ndr64)
                response['lpdwTagId'] = NULL
                response['lpServiceHandle'] = self.HANDLE
                response['ErrorCode'] = 0

                decoded = self.assert_round_trip(response)
                self.assertEqual(decoded['lpServiceHandle'], self.HANDLE)

    def test_open_sc_manager2_response_round_trip(self):
        for is_ndr64 in (False, True):
            with self.subTest(isNDR64=is_ndr64):
                response = scmr.ROpenSCManager2Response(isNDR64=is_ndr64)
                response['lpScHandle'] = self.HANDLE
                response['ReturnCode'] = 0

                decoded = self.assert_round_trip(response)
                self.assertEqual(decoded['lpScHandle'], self.HANDLE)


if __name__ == '__main__':
    unittest.main(verbosity=1)
