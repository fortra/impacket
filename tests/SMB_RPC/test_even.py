###############################################################################
#  Tested so far: 
#
# ElfrOpenBELW
# hElfrOpenBELW
# ElfrOpenELW
# hElfrOpenELW
# ElfrRegisterEventSourceW
# hElfrRegisterEventSourceW
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

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL


class RRPTests(unittest.TestCase):
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
        dce.bind(even.MSRPC_UUID_EVEN, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_ElfrOpenBELW(self):
        dce, rpctransport = self.connect()
        request = even.ElfrOpenBELW()
        request['UNCServerName'] = NULL
        request['BackupFileName'] = '\\??\\BETO'
        request['MajorVersion'] = 1
        request['MinorVersion'] = 1
        try:
            resp = dce.request(request)
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') < 0:
                raise
            resp = e.get_packet()
        resp.dump()

    def test_hElfrOpenBELW(self):
        dce, rpctransport = self.connect()
        try:
            resp = even.hElfrOpenBELW(dce, '\\??\\BETO')
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') < 0:
                raise
            resp = e.get_packet()
        resp.dump()

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
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise

    def test_hElfrRegisterEventSourceW(self):
        dce, rpctransport = self.connect()
        try:
            resp = even.hElfrRegisterEventSourceW(dce, 'Security', '')
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise

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
        resp = even.hElfrReadELW(dce, resp['LogHandle'],even.EVENTLOG_SEQUENTIAL_READ | even.EVENTLOG_FORWARDS_READ,0, even.MAX_BATCH_BUFF )
        resp.dump()

    def test_ElfrClearELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        request = even.ElfrClearELFW()
        request['LogHandle'] = resp['LogHandle']
        request['BackupFileName'] = '\\??\\c:\\beto2'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_INVALID') < 0:
                raise

    def test_hElfrClearELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        try:
            resp = even.hElfrClearELFW(dce, resp['LogHandle'], '\\??\\c:\\beto2')
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_INVALID') < 0:
                raise

    def test_ElfrBackupELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        request = even.ElfrBackupELFW()
        request['LogHandle'] = resp['LogHandle']
        request['BackupFileName'] = '\\??\\c:\\beto2'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_INVALID') < 0:
                raise

    def test_hElfrBackupELFW(self):
        dce, rpctransport = self.connect()
        resp = even.hElfrOpenELW(dce, 'Security', '')
        resp.dump()
        try:
            resp = even.hElfrBackupELFW(dce, resp['LogHandle'], '\\??\\c:\\beto2')
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_INVALID') < 0:
                raise

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
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise

class SMBTransport(RRPTests):
    def setUp(self):
        RRPTests.setUp(self)
        configFile = configparser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\eventlog]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(RRPTests):
    def setUp(self):
        RRPTests.setUp(self)
        configFile = configparser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\eventlog]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
