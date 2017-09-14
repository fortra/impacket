import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from lib.impacket.dcerpc.v5 import epm, eventlog
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
import hexdump


class EVEN6Tests(unittest.TestCase):
    def connect(self, version):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        if version == 1:
            dce.bind(eventlog.MSRPC_UUID_EVENTLOG, transfer_syntax=self.ts)
        else:
            dce.bind(eventlog.MSRPC_UUID_EVENTLOG, transfer_syntax=self.ts)

        return dce, rpctransport

    def test_EvtRpcRegisterLogQuery_EvtRpcQueryNext(self):
        dce, rpctransport = self.connect(2)

        request = eventlog.EvtRpcRegisterLogQuery()
        request['Path'] = 'Security\x00'
        request['Query'] = '*\x00'
        request['Flags'] = eventlog.EvtQueryChannelName | eventlog.EvtReadNewestToLowest

        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            return

        log_handle = resp['Handle']

        request = eventlog.EvtRpcQueryNext()
        request['LogQuery'] = log_handle
        request['NumRequestedRecords'] = 5
        request['TimeOutEnd'] = 1000
        request['Flags'] = 0
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            return

        for i in range(resp['NumActualRecords']):
            event_offset = resp['EventDataIndices'][i]['Data']
            event_size = resp['EventDataSizes'][i]['Data']
            event = resp['ResultBuffer'][event_offset:event_offset + event_size]
            buff = ''.join([x.encode('hex') for x in event]).decode('hex')
            print hexdump.hexdump(buff)

class SMBTransport(EVEN6Tests):
    def setUp(self):
        EVEN6Tests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine = configFile.get('SMBTransport', 'machine')
        self.hashes = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\eventlog]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(EVEN6Tests):
    def setUp(self):
        EVEN6Tests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine = configFile.get('SMBTransport', 'machine')
        self.hashes = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\eventlog]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

class TCPTransport(EVEN6Tests):
    def setUp(self):
        EVEN6Tests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine = configFile.get('TCPTransport', 'machine')
        self.hashes = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, eventlog.MSRPC_UUID_EVENTLOG, protocol='ncacn_ip_tcp')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport64(EVEN6Tests):
    def setUp(self):
        EVEN6Tests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine = configFile.get('TCPTransport', 'machine')
        self.hashes = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, eventlog.MSRPC_UUID_EVENTLOG, protocol='ncacn_ip_tcp')
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        # suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
