###############################################################################
#  Tested so far: 
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#  
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import mgmt


class MGMTTests(unittest.TestCase):
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
        dce.connect()
        dce.bind(mgmt.MSRPC_UUID_MGMT, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_inq_if_ids(self):
        dce, transport = self.connect()

        request = mgmt.inq_if_ids()
        resp = dce.request(request)
        resp.dump()
        #for i in range(resp['if_id_vector']['count']):
        #    print bin_to_uuidtup(resp['if_id_vector']['if_id'][i]['Data'].getData())
        #    print

    def test_hinq_if_ids(self):
        dce, transport = self.connect()

        resp = mgmt.hinq_if_ids(dce)
        resp.dump()

    def test_inq_stats(self):
        dce, transport = self.connect()

        request = mgmt.inq_stats()
        request['count'] = 40
        resp = dce.request(request)
        resp.dump()

    def test_hinq_stats(self):
        dce, transport = self.connect()

        resp = mgmt.hinq_stats(dce)
        resp.dump()

    def test_is_server_listening(self):
        dce, transport = self.connect()

        request = mgmt.is_server_listening()
        resp = dce.request(request, checkError=False)
        resp.dump()

    def test_his_server_listening(self):
        dce, transport = self.connect()

        resp = mgmt.his_server_listening(dce)
        resp.dump()

    def test_stop_server_listening(self):
        dce, transport = self.connect()

        request = mgmt.stop_server_listening()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_hstop_server_listening(self):
        dce, transport = self.connect()

        try:
            resp = mgmt.hstop_server_listening(dce)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_inq_princ_name(self):
        dce, transport = self.connect()

        request = mgmt.inq_princ_name()
        request['authn_proto'] = 0
        request['princ_name_size'] = 32
        resp = dce.request(request, checkError=False)
        resp.dump()

    def test_his_server_listening(self):
        dce, transport = self.connect()

        resp = mgmt.hinq_princ_name(dce)
        resp.dump()


class SMBTransport(MGMTTests):
    def setUp(self):
        MGMTTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport(MGMTTests):
    def setUp(self):
        MGMTTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s[135]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(MGMTTests):
    def setUp(self):
        MGMTTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

class TCPTransport64(MGMTTests):
    def setUp(self):
        MGMTTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s[135]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        #suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport64)
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
