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
# Tested so far:
#   (h)RpcAsyncEnumPrinters
#   (h)RpcAsyncEnumPrinterDrivers
#   (h)RpcAsyncGetPrinterDriverDirectory
#   (h)RpcAsyncAddPrinterDriver (requires the PAR driver fixture)
#   (h)RpcAsyncDeletePrinterDriver (requires the PAR driver fixture)
#
# Not yet:
#   (h)RpcAsyncOpenPrinter
#   (h)RpcAsyncClosePrinter
#   RpcAsyncAddPrinter
#
import pytest
import unittest
from struct import unpack_from
from uuid import uuid4
from six import assertRaisesRegex
from tests import get_remote_config
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import par
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket import system_errors


class PARTests(DCERPCTests):
    iface_uuid = par.MSRPC_UUID_PAR
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def driver_names(self, dce, environment):
        def enumerate_drivers(size):
            request = par.RpcAsyncEnumPrinterDrivers()
            request['pName'] = NULL
            request['pEnvironment'] = par.checkNullString(environment)
            request['Level'] = 1
            request['pDrivers'] = b'\x00' * size if size else NULL
            request['cbBuf'] = size
            return dce.request(request, par.MSRPC_UUID_WINSPOOL, checkError=False)

        resp = enumerate_drivers(0)
        if resp['ErrorCode'] == system_errors.ERROR_INSUFFICIENT_BUFFER:
            resp = enumerate_drivers(resp['pcbNeeded'])
        self.assertEqual(resp['ErrorCode'], 0)
        data = b''.join(resp['pDrivers']) if resp['pcReturned'] else b''
        names = []
        # DRIVER_INFO_1 uses 32-bit offsets relative to each array entry,
        # independently of the RPC transfer syntax.
        for index in range(resp['pcReturned']):
            base = index * 4
            offset = base + unpack_from('<L', data, base)[0]
            names.append(data[offset:].decode('utf-16le').split('\x00', 1)[0])
        return names

    def add_and_delete_driver(self, use_helper):
        config = get_remote_config()
        if not config.has_section('PAR') or not config.getboolean('PAR', 'driver_lifecycle', fallback=False):
            self.skipTest('Enable [PAR] driver_lifecycle and configure a driver fixture')
        options = ('environment', 'driver_path', 'data_file', 'config_file')
        fixture = {option: config.get('PAR', option) for option in options}
        for option, value in fixture.items():
            self.assertTrue(value.strip(), 'Missing [PAR] %s' % option)

        dce, rpc_transport = self.connect()
        self.addCleanup(dce.disconnect)
        name = 'ImpacketTest_' + uuid4().hex
        environment = fixture['environment']
        self.assertNotIn(name, self.driver_names(dce, environment))

        def cleanup_driver():
            try:
                par.hRpcAsyncDeletePrinterDriver(dce, NULL, environment, name)
            except par.DCERPCSessionError as exc:
                if exc.get_error_code() != system_errors.ERROR_UNKNOWN_PRINTER_DRIVER:
                    raise

        # Register before adding, including for a lost reply or assertion failure.
        self.addCleanup(cleanup_driver)
        container = par.DRIVER_CONTAINER()
        container['Level'] = 2
        container['DriverInfo']['tag'] = 2
        info = container['DriverInfo']['Level2']
        info['cVersion'] = 3
        info['pName'] = par.checkNullString(name)
        for field, option in (('pEnvironment', 'environment'), ('pDriverPath', 'driver_path'),
                              ('pDataFile', 'data_file'), ('pConfigFile', 'config_file')):
            info[field] = par.checkNullString(fixture[option])
        flags = par.APD_COPY_NEW_FILES | par.APD_COPY_FROM_DIRECTORY
        if use_helper:
            resp = par.hRpcAsyncAddPrinterDriver(dce, NULL, container, flags)
        else:
            request = par.RpcAsyncAddPrinterDriver()
            request['pName'] = NULL
            request['pDriverContainer'] = container
            request['dwFileCopyFlags'] = flags
            resp = dce.request(request, par.MSRPC_UUID_WINSPOOL)
        self.assertIsInstance(resp, par.RpcAsyncAddPrinterDriverResponse)
        self.assertEqual(resp['ErrorCode'], 0)
        self.assertIn(name, self.driver_names(dce, environment))

        if use_helper:
            resp = par.hRpcAsyncDeletePrinterDriver(dce, NULL, environment, name)
        else:
            request = par.RpcAsyncDeletePrinterDriver()
            request['pName'] = NULL
            request['pEnvironment'] = par.checkNullString(environment)
            request['pDriverName'] = par.checkNullString(name)
            resp = dce.request(request, par.MSRPC_UUID_WINSPOOL)
        self.assertIsInstance(resp, par.RpcAsyncDeletePrinterDriverResponse)
        self.assertEqual(resp['ErrorCode'], 0)
        self.assertNotIn(name, self.driver_names(dce, environment))

    def test_RpcAsyncAddAndDeletePrinterDriver(self):
        self.add_and_delete_driver(use_helper=False)

    def test_hRpcAsyncAddAndDeletePrinterDriver(self):
        self.add_and_delete_driver(use_helper=True)

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
