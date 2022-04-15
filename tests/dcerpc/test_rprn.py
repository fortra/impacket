# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)RpcEnumPrinters
#   (h)RpcOpenPrinter
#   (h)RpcClosePrinter
#   (h)RpcOpenPrinterEx
#   (h)RpcRemoteFindFirstPrinterChangeNotificationEx
# Not yet
#   RpcEnumPrinterDrivers
#   RpcAddPrinterDriverEx
#
from __future__ import division
from __future__ import print_function

import pytest
import unittest
from six import assertRaisesRegex
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5.dtypes import NULL
from impacket.structure import hexdump


class RPRNTests(DCERPCTests):
    iface_uuid = rprn.MSRPC_UUID_RPRN
    string_binding = r'ncacn_np:{0.machine}[\PIPE\spoolss]'
    authn = True

    def test_RpcEnumPrinters(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcEnumPrinters()
        request['Flags'] = rprn.PRINTER_ENUM_LOCAL
        request['Name'] = NULL
        request['pPrinterEnum'] = NULL
        request['Level'] = 1
        request.dump()

        with assertRaisesRegex(self, rprn.DCERPCSessionError, "ERROR_INSUFFICIENT_BUFFER") as cm:
            dce.request(request)
        bytesNeeded = cm.exception.get_packet()['pcbNeeded']

        request = rprn.RpcEnumPrinters()
        request['Flags'] = rprn.PRINTER_ENUM_LOCAL
        request['Name'] = NULL
        request['Level'] = 1

        request['cbBuf'] = bytesNeeded
        request['pPrinterEnum'] = b'a'*bytesNeeded

        request.dump()
        resp = dce.request(request)
        resp.dump()
        hexdump(b''.join(resp['pPrinterEnum']))

    def test_hRpcEnumPrinters(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcEnumPrinters(dce, rprn.PRINTER_ENUM_LOCAL, NULL, 1)
        hexdump(b''.join(resp['pPrinterEnum']))

    def test_RpcOpenPrinter(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcOpenPrinter()
        request['pPrinterName'] = "\\\\%s\x00" % self.machine
        request['pDatatype'] = NULL
        request['pDevModeContainer']['pDevMode'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hRpcOpenPrinter(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % self.machine)
        resp.dump()

    def test_RpcGetPrinterDriverDirectory(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcGetPrinterDriverDirectory()
        request['pName'] = NULL
        request['pEnvironment'] = NULL
        request['Level'] = 1
        request['pDriverDirectory'] = NULL
        request['cbBuf'] = 0
        request.dump()
        with assertRaisesRegex(self, rprn.DCERPCSessionError, "ERROR_INSUFFICIENT_BUFFER"):
            dce.request(request)

    def test_hRpcGetPrinterDriverDirectory(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcGetPrinterDriverDirectory(dce, NULL, NULL, 1)
        resp.dump()

    def test_RpcClosePrinter(self):
        dce, rpctransport = self.connect()

        request = rprn.RpcOpenPrinter()
        request['pPrinterName'] = "\\\\%s\x00" % self.machine
        request['pDatatype'] = NULL
        request['pDevModeContainer']['pDevMode'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = rprn.RpcClosePrinter()
        request['phPrinter'] = resp['pHandle']
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hRpcClosePrinter(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % self.machine)
        resp.dump()
        resp = rprn.hRpcClosePrinter(dce, resp['pHandle'])
        resp.dump()

    def test_RpcOpenPrinterEx(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcOpenPrinterEx()
        request['pPrinterName'] = "\\\\%s\x00" % self.machine
        request['pDatatype'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ
        request['pDevModeContainer']['pDevMode'] = NULL
        request['pClientInfo']['Level'] = 1
        request['pClientInfo']['ClientInfo']['tag'] = 1
        request['pClientInfo']['ClientInfo']['pClientInfo1']['dwSize'] = 28
        request['pClientInfo']['ClientInfo']['pClientInfo1']['pMachineName'] = "%s\x00" % self.machine
        request['pClientInfo']['ClientInfo']['pClientInfo1']['pUserName'] = "%s\\%s\x00" % (self.domain, self.username)
        request['pClientInfo']['ClientInfo']['pClientInfo1']['dwBuildNum'] = 0x0
        request['pClientInfo']['ClientInfo']['pClientInfo1']['dwMajorVersion'] = 0x00000000
        request['pClientInfo']['ClientInfo']['pClientInfo1']['dwMinorVersion'] = 0x00000000
        request['pClientInfo']['ClientInfo']['pClientInfo1']['wProcessorArchitecture'] = 0x0009
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hRpcOpenPrinterEx(self):
        dce, rpctransport = self.connect()
        clientInfo = rprn.SPLCLIENT_CONTAINER()
        clientInfo['Level'] = 1
        clientInfo['ClientInfo']['tag'] = 1
        clientInfo['ClientInfo']['pClientInfo1']['dwSize'] = 28
        clientInfo['ClientInfo']['pClientInfo1']['pMachineName'] = "%s\x00" % self.machine
        clientInfo['ClientInfo']['pClientInfo1']['pUserName'] = "%s\\%s\x00" % (self.domain, self.username)
        clientInfo['ClientInfo']['pClientInfo1']['dwBuildNum'] = 0x0
        clientInfo['ClientInfo']['pClientInfo1']['dwMajorVersion'] = 0x00000000
        clientInfo['ClientInfo']['pClientInfo1']['dwMinorVersion'] = 0x00000000
        clientInfo['ClientInfo']['pClientInfo1']['wProcessorArchitecture'] = 0x0009

        resp = rprn.hRpcOpenPrinterEx(dce, "\\\\%s\x00" % self.machine, pClientInfo=clientInfo)
        resp.dump()

    def test_RpcRemoteFindFirstPrinterChangeNotificationEx(self):
        dce, rpctransport = self.connect()

        request = rprn.RpcOpenPrinter()
        request['pPrinterName'] = "\\\\%s\x00" % self.machine
        request['pDatatype'] = NULL
        request['pDevModeContainer']['pDevMode'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ | rprn.SERVER_ALL_ACCESS | rprn.SERVER_ACCESS_ADMINISTER
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request['hPrinter'] = resp['pHandle']
        request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
        request['pszLocalMachine'] = "\\\\%s\x00" % self.machine
        request['pOptions'] = NULL
        request.dump()
        with assertRaisesRegex(self, rprn.DCERPCSessionError, "ERROR_INVALID_HANDLE"):
            dce.request(request)

    def test_hRpcRemoteFindFirstPrinterChangeNotificationEx(self):
        dce, rpctransport = self.connect()

        resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % self.machine)

        with assertRaisesRegex(self, rprn.DCERPCSessionError, "ERROR_INVALID_HANDLE"):
            rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(dce, resp['pHandle'],
                                                                rprn.PRINTER_CHANGE_ADD_JOB,
                                                                pszLocalMachine="\\\\%s\x00" % self.machine)


@pytest.mark.remote
class RPRNTestsSMBTransport(RPRNTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class RPRNTestsSMBTransport64(RPRNTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
