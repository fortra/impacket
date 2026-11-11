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

import struct
import unittest
from unittest.mock import Mock

from impacket.dcerpc.v5 import par
from impacket.dcerpc.v5.dtypes import NULL


class PARTests(unittest.TestCase):
    def test_delete_request_reference_strings(self):
        # IDL: unique pName, followed by two non-null reference strings.
        # The latter carry no pointer referent IDs on the wire.
        for ndr64 in (False, True):
            with self.subTest(ndr64=ndr64):
                request = par.RpcAsyncDeletePrinterDriver(isNDR64=ndr64)
                request['pName'] = NULL
                request['pEnvironment'] = 'e\x00'
                request['pDriverName'] = 'd\x00'
                data = request.getData()
                fmt, width = ('<QQQ', 8) if ndr64 else ('<LLL', 4)
                self.assertEqual(data[:width], b'\x00' * width)
                first = width
                self.assertEqual(struct.unpack_from(fmt, data, first), (2, 0, 2))
                self.assertEqual(data[first + 3 * width:first + 3 * width + 4], b'e\x00\x00\x00')
                second = first + 3 * width + 4
                second += -second % width
                self.assertEqual(struct.unpack_from(fmt, data, second), (2, 0, 2))
                self.assertEqual(data[second + 3 * width:], b'd\x00\x00\x00')
                parsed = par.RpcAsyncDeletePrinterDriver(data, isNDR64=ndr64)
                self.assertEqual(parsed['pEnvironment'], 'e\x00')
                self.assertEqual(parsed['pDriverName'], 'd\x00')

    def test_driver_status_responses(self):
        for opnum in (39, 42):
            request, response = par.OPNUMS[opnum]
            self.assertEqual(request.opnum, opnum)
            self.assertIs(response, getattr(par, request.__name__ + 'Response'))
            for ndr64 in (False, True):
                for status in (0, 5, 124, 1797):
                    with self.subTest(opnum=opnum, ndr64=ndr64, status=status):
                        data = struct.pack('<L', status)
                        parsed = response(data, isNDR64=ndr64)
                        self.assertEqual(parsed['ErrorCode'], status)
                        self.assertEqual(parsed.getData(), data)

    def test_delete_helper_terminates_strings_and_sets_object_uuid(self):
        for terminated in (False, True):
            with self.subTest(terminated=terminated):
                suffix = '\x00' if terminated else ''
                dce = Mock()
                response = par.hRpcAsyncDeletePrinterDriver(
                    dce, NULL, 'Windows x64' + suffix, 'ImpacketTest' + suffix,
                )
                self.assertIs(response, dce.request.return_value)
                request, object_uuid = dce.request.call_args[0]
                self.assertIsInstance(request, par.RpcAsyncDeletePrinterDriver)
                self.assertEqual(request['pEnvironment'], 'Windows x64\x00')
                self.assertEqual(request['pDriverName'], 'ImpacketTest\x00')
                self.assertEqual(object_uuid, par.MSRPC_UUID_WINSPOOL)
                self.assertEqual(request.getData()[:4], b'\x00' * 4)


if __name__ == '__main__':
    unittest.main()
