###############################################################################
#  Tested so far:
#
#  RpcOpenPrinterEx
#  hRpcOpenPrinterEx
#  RpcOpenPrinter
#  hRpcOpenPrinter
#  RpcRemoteFindFirstPrinterChangeNotificationEx
#  hRpcRemoteFindFirstPrinterChangeNotificationEx
#  hRpcClosePrinter
#  RpcClosePrinter
#  RpcEnumPrinters
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#
################################################################################

from __future__ import division
from __future__ import print_function

import unittest

from six.moves import configparser

from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.structure import hexdump


class RPRNTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN, transfer_syntax = self.ts)
        #resp = rrp.hOpenLocalMachine(dce, MAXIMUM_ALLOWED | rrp.KEY_WOW64_32KEY | rrp.KEY_ENUMERATE_SUB_KEYS)

        return dce, rpctransport#, resp['phKey']

    def test_RpcEnumPrinters(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcEnumPrinters()
        request['Flags'] = rprn.PRINTER_ENUM_LOCAL
        request['Name'] = NULL
        request['pPrinterEnum'] = NULL
        request['Level'] = 1
        request.dump()
        bytesNeeded = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except rprn.DCERPCSessionError as e:
            if str(e).find('ERROR_INSUFFICIENT_BUFFER') < 0:
                raise
            bytesNeeded = e.get_packet()['pcbNeeded']

        request = rprn.RpcEnumPrinters()
        request['Flags'] = rprn.PRINTER_ENUM_LOCAL
        request['Name'] = NULL
        request['Level'] = 1

        request['cbBuf'] = bytesNeeded
        request['pPrinterEnum'] = b'a'*bytesNeeded

        request.dump()
        resp = dce.request(request)
        resp.dump()
        hexdump(resp['pPrinterEnum'])

    def test_hRpcEnumPrinters(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcEnumPrinters(dce, rprn.PRINTER_ENUM_LOCAL, NULL, 1)
        hexdump(resp['pPrinterEnum'])

    def test_RpcOpenPrinter(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcOpenPrinter()
        request['pPrinterName'] = '\\\\%s\x00' % self.machine
        request['pDatatype'] = NULL
        request['pDevModeContainer']['pDevMode'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_RpcClosePrinter(self):
        dce, rpctransport = self.connect()

        request = rprn.RpcOpenPrinter()
        request['pPrinterName'] = '\\\\%s\x00' % self.machine
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

    def test_hRpcOpenPrinter(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % self.machine)
        resp.dump()

    def test_hRpcClosePrinter(self):
        dce, rpctransport = self.connect()
        resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % self.machine)
        resp.dump()
        resp = rprn.hRpcClosePrinter(dce, resp['pHandle'])
        resp.dump()

    def test_RpcOpenPrinterEx(self):
        dce, rpctransport = self.connect()
        request = rprn.RpcOpenPrinterEx()
        request['pPrinterName'] = '\\\\%s\x00' % self.machine
        request['pDatatype'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ
        request['pDevModeContainer']['pDevMode'] = NULL
        request['pClientInfo']['Level'] = 1
        request['pClientInfo']['ClientInfo']['tag'] = 1
        request['pClientInfo']['ClientInfo']['pClientInfo1']['dwSize'] = 28
        request['pClientInfo']['ClientInfo']['pClientInfo1']['pMachineName'] = '%s\x00' % self.machine
        request['pClientInfo']['ClientInfo']['pClientInfo1']['pUserName'] = '%s\\%s\x00' % (self.domain, self.username)
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
        clientInfo['ClientInfo']['pClientInfo1']['pMachineName'] = '%s\x00' % self.machine
        clientInfo['ClientInfo']['pClientInfo1']['pUserName'] = '%s\\%s\x00' % (self.domain, self.username)
        clientInfo['ClientInfo']['pClientInfo1']['dwBuildNum'] = 0x0
        clientInfo['ClientInfo']['pClientInfo1']['dwMajorVersion'] = 0x00000000
        clientInfo['ClientInfo']['pClientInfo1']['dwMinorVersion'] = 0x00000000
        clientInfo['ClientInfo']['pClientInfo1']['wProcessorArchitecture'] = 0x0009

        resp = rprn.hRpcOpenPrinterEx(dce, '\\\\%s\x00' % self.machine, pClientInfo=clientInfo)
        resp.dump()

    def test_RpcRemoteFindFirstPrinterChangeNotificationEx(self):
        dce, rpctransport = self.connect()

        request = rprn.RpcOpenPrinter()
        request['pPrinterName'] = '\\\\%s\x00' % self.machine
        request['pDatatype'] = NULL
        request['pDevModeContainer']['pDevMode'] = NULL
        request['AccessRequired'] = rprn.SERVER_READ | rprn.SERVER_ALL_ACCESS | rprn.SERVER_ACCESS_ADMINISTER
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request['hPrinter'] =  resp['pHandle']
        request['fdwFlags'] =  rprn.PRINTER_CHANGE_ADD_JOB
        request['pszLocalMachine'] =  '\\\\%s\x00' % self.machine
        request['pOptions'] =  NULL
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_INVALID_HANDLE') < 0:
                raise

    def test_hRpcRemoteFindFirstPrinterChangeNotificationEx(self):
        dce, rpctransport = self.connect()

        resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % self.machine)

        try:
            resp = rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(dce, resp['pHandle'], rprn.PRINTER_CHANGE_ADD_JOB, pszLocalMachine = '\\\\%s\x00' % self.machine )
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_INVALID_HANDLE') < 0:
                raise

class SMBTransport(RPRNTests):
    def setUp(self):
        RPRNTests.setUp(self)
        configFile = configparser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\spoolss]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        self.rrpStarted = False

class SMBTransport64(RPRNTests):
    def setUp(self):
        RPRNTests.setUp(self)
        configFile = configparser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\spoolss]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
