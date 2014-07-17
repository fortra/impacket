import unittest
import ConfigParser
from impacket.dcerpc.v5 import transport, epm, rpcrt

# aimed at testing just the DCERPC engine, not the particular
# endpoints (we should do specific tests for endpoints)
# here we're using EPM just beacuse we need one, and it's the 
# easiest one

class DCERPCTests(unittest.TestCase):

    def test_connection(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        dce.disconnect()

    def test_connectionHashes(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        dce.disconnect()

    def test_dceAuth(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        dce.disconnect()

    def test_dceAuthHasHashes(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        dce.disconnect()

    def test_dceTransportFragmentation(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        rpctransport.set_max_fragment_size(1)
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceFragmentation(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_packetWINNTPacketIntegrity(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_packetHashesWINNTPacketIntegrity(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_packetAnonWINNTPacketIntegrity(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.connect()
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_packetWINNTPacketPrivacy(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_packetHashesWINNTPacketPrivacy(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_packetAnonWINNTPacketPrivacy(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        #dce.set_max_fragment_size(1)
        dce.connect()
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

class TCPTransport(DCERPCTests):
    def setUp(self):
        DCERPCTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine

class SMBTransport(DCERPCTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB_002
        DCERPCTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
