# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)RpcAsyncEnumPrinters
#   (h)RpcAsyncEnumPrinterDrivers
#   (h)RpcAsyncGetPrinterDriverDirectory
#
# Not yet:
#   (h)RpcAsyncOpenPrinter
#   (h)RpcAsyncClosePrinter
#   (h)RpcAsyncAddPrinterDriver
#   RpcAsyncAddPrinter
#
import pytest
import unittest
from six import assertRaisesRegex
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import par
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class PARTests(DCERPCTests):
    iface_uuid = par.MSRPC_UUID_PAR
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_RpcAsyncEnumPrinters(self):
        dce, rpc_transport = self.connect()
        request = par.RpcAsyncEnumPrinters()
        request['Flags'] = 0
        request['Name'] = NULL
        request['pPrinterEnum'] = NULL
        request['Level'] = 0
        resp = dce.request(request, par.MSRPC_UUID_WINSPOOL)
        resp.dump()

    def test_hRpcAsyncEnumPrinters(self):
        dce, rpc_transport = self.connect()
        resp = par.hRpcAsyncEnumPrinters(dce, NULL)
        resp.dump()

    def test_RpcAsyncEnumPrinterDrivers(self):
        dce, rpc_transport = self.connect()
        request = par.RpcAsyncEnumPrinterDrivers()
        request['pName'] = NULL
        request['pEnvironment'] = NULL
        request['Level'] = 1
        request['pDrivers'] = NULL
        request['cbBuf'] = 0
        with assertRaisesRegex(self, par.DCERPCException, "ERROR_INSUFFICIENT_BUFFER"):
            dce.request(request, par.MSRPC_UUID_WINSPOOL)

    def test_hRpcAsyncEnumPrinterDrivers(self):
        dce, rpc_transport = self.connect()
        resp = par.hRpcAsyncEnumPrinterDrivers(dce, NULL, NULL, 1)
        resp.dump()

    def test_RpcAsyncGetPrinterDriverDirectory(self):
        dce, rpc_transport = self.connect()
        request = par.RpcAsyncGetPrinterDriverDirectory()
        request['pName'] = NULL
        request['pEnvironment'] = NULL
        request['Level'] = 1
        request['pDriverDirectory'] = NULL
        request['cbBuf'] = 0
        with assertRaisesRegex(self, par.DCERPCException, "ERROR_INSUFFICIENT_BUFFER"):
            dce.request(request, par.MSRPC_UUID_WINSPOOL)

    def test_hRpcAsyncGetPrinterDriverDirectory(self):
        dce, rpc_transport = self.connect()
        resp = par.hRpcAsyncGetPrinterDriverDirectory(dce, NULL, NULL, 1)
        resp.dump()


@pytest.mark.remote
class PARTestsTCPTransport(PARTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class PARTestsTCPTransport64(PARTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
