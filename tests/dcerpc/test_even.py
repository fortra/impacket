# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)ElfrOpenBELW
#   (h)ElfrOpenELW
#   (h)ElfrRegisterEventSourceW
#   (h)ElfrReadELW
#   (h)ElfrClearELFW
#   (h)ElfrBackupELFW
#   ElfrReportEventW
#   hElfrNumberOfRecords
#   hElfrOldestRecordNumber
# Not yet:
#   ElfrCloseEL
#
from __future__ import division
from __future__ import print_function
import pytest
import unittest
from six import assertRaisesRegex

from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException


class RRPTests(DCERPCTests):

    iface_uuid = even.MSRPC_UUID_EVEN
    string_binding = r"ncacn_np:{0.machine}[\PIPE\eventlog]"
    authn = True

    def test_ElfrOpenBELW(self):
        dce, rpctransport = self.connect()
        request = even.ElfrOpenBELW()
        request['UNCServerName'] = NULL
        request['BackupFileName'] = '\\??\\BETO'
        request['MajorVersion'] = 1
        request['MinorVersion'] = 1

        with assertRaisesRegex(self, DCERPCException, "STATUS_OBJECT_NAME_NOT_FOUND"):
            dce.request(request)

    def test_hElfrOpenBELW(self):
        dce, rpctransport = self.connect()

        with assertRaisesRegex(self, DCERPCException, "STATUS_OBJECT_NAME_NOT_FOUND"):
            even.hElfrOpenBELW(dce, '\\??\\BETO')

    def test_ElfrOpenELW(self):
        dce, rpctransport = self.connect()
        request = even.ElfrOpenELW()
        request['UNCServerName'] = NULL
        request['ModuleName'] = 'Security'
        request['RegModuleName'] = ''
        request['MajorVersion'] = 1
        request['MinorVersion'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hElfrOpenELW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()

    def test_ElfrRegisterEventSourceW(self):
        dce, rpctransport = self.connect()
        request = even.ElfrRegisterEventSourceW()
        request['UNCServerName'] = NULL
        request['ModuleName'] = 'Security'
        request['RegModuleName'] = ''
        request['MajorVersion'] = 1
        request['MinorVersion'] = 1

        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            dce.request(request)

    def test_hElfrRegisterEventSourceW(self):
        dce, rpctransport = self.connect()

        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            even.hElfrRegisterEventSourceW(dce, 'Security', '')

    def test_ElfrReadELW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        request = even.ElfrReadELW()
        request['LogHandle'] = resp['LogHandle']
        request['ReadFlags'] = even.EVENTLOG_SEQUENTIAL_READ | even.EVENTLOG_FORWARDS_READ
        request['RecordOffset'] = 0
        request['NumberOfBytesToRead'] = even.MAX_BATCH_BUFF
        resp = dce.request(request)
        resp.dump()

    def test_hElfrReadELW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        resp = even.hElfrReadELW(dce, resp['LogHandle'],
                                 even.EVENTLOG_SEQUENTIAL_READ | even.EVENTLOG_FORWARDS_READ,
                                 0, even.MAX_BATCH_BUFF)
        resp.dump()

    def test_ElfrClearELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        request = even.ElfrClearELFW()
        request['LogHandle'] = resp['LogHandle']
        request['BackupFileName'] = '\\??\\c:\\beto2'

        with assertRaisesRegex(self, DCERPCException, "STATUS_OBJECT_NAME_INVALID"):
            dce.request(request)

    def test_hElfrClearELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()

        with assertRaisesRegex(self, DCERPCException, "STATUS_OBJECT_NAME_INVALID"):
            even.hElfrClearELFW(dce, resp['LogHandle'], '\\??\\c:\\beto2')

    def test_ElfrBackupELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        request = even.ElfrBackupELFW()
        request['LogHandle'] = resp['LogHandle']
        request['BackupFileName'] = '\\??\\c:\\beto2'

        with assertRaisesRegex(self, DCERPCException, "STATUS_OBJECT_NAME_INVALID"):
            dce.request(request)

    def test_hElfrBackupELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()

        with assertRaisesRegex(self, DCERPCException, "STATUS_OBJECT_NAME_INVALID"):
            even.hElfrBackupELFW(dce, resp['LogHandle'], '\\??\\c:\\beto2')

    def test_ElfrReportEventW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        request = even.ElfrReportEventW()
        request['LogHandle'] = resp['LogHandle']
        request['Time'] = 5000000
        request['EventType'] = even.EVENTLOG_ERROR_TYPE
        request['EventCategory'] = 0
        request['EventID'] = 7037
        request['ComputerName'] = 'MYCOMPUTER!'
        request['NumStrings'] = 1
        request['DataSize'] = 0
        request['UserSID'].fromCanonical('S-1-2-5-21')
        nn = even.PRPC_UNICODE_STRING()
        nn['Data'] = 'HOLA BETUSSS'
        request['Strings'].append(nn)
        request['Data'] = NULL
        request['Flags'] = 0
        request['RecordNumber'] = NULL
        request['TimeWritten'] = NULL

        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            dce.request(request)

    def test_hElfrNumberOfRecords(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        resp = even.hElfrNumberOfRecords(dce, resp['LogHandle'])
        resp.dump()

    def test_hElfrOldestRecordNumber(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        resp = even.hElfrOldestRecordNumber(dce, resp['LogHandle'])
        resp.dump()


@pytest.mark.remote
class RRPTestsSMBTransport(RRPTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class RRPTestsSMBTransport64(RRPTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
