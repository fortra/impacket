import unittest
from impacket.dcerpc import transport, epm, dcerpc

# aimed at testing just the DCERPC engine, not the particular
# endpoints (we should do specific tests for endpoints)
# here we're using EPM just beacuse we need one, and it's the 
# easiest one

class DCERPCTests(unittest.TestCase):

    def test_connection(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        dce.disconnect()

    def test_connectionHashes(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
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
        rpctransport.set_dport(self.dport)
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
        rpctransport.set_dport(self.dport)
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
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        rpctransport.set_max_fragment_size(1)
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_dceFragmentation(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_packetWINNTPacketIntegrity(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(dcerpc.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(dcerpc.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_packetHashesWINNTPacketIntegrity(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(dcerpc.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(dcerpc.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_packetAnonWINNTPacketIntegrity(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.connect()
        dce.set_auth_type(dcerpc.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(dcerpc.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_packetWINNTPacketPrivacy(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(dcerpc.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(dcerpc.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_packetHashesWINNTPacketPrivacy(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, '', self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(1)
        dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(dcerpc.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(dcerpc.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

    def test_packetAnonWINNTPacketPrivacy(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if hasattr(rpctransport, 'set_credentials'):
            lmhash, nthash = self.hashes.split(':')
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        #dce.set_max_fragment_size(1)
        dce.connect()
        dce.set_auth_type(dcerpc.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(dcerpc.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        rpcepm = epm.DCERPCEpm(dce)
        resp = rpcepm.lookup('', inquireType = epm.RPC_C_EP_ALL_ELTS)
        dce.disconnect()

class TCPTransport(DCERPCTests):
    def setUp(self):
        DCERPCTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        self.username = 'Administrator'
        self.domain   = ''
        self.serverName = 'ULTIMATE64'
        self.password = 'Admin123456'
        self.machine  = '192.168.88.109'
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine
        self.dport = 135
        self.hashes   = 'aad3b435b51404eeaad3b435b51404ee:ae4c0d5fb959fda8f4cb1d14a8376af4'
        self.upload   = '../../nt_errors.py'

class SMBTransport(DCERPCTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB_002
        DCERPCTests.setUp(self)
        self.username = 'Administrator'
        self.domain   = ''
        self.serverName = 'ULTIMATE64'
        self.password = 'Admin'
        self.hashes   = 'aad3b435b51404eeaad3b435b51404ee:ae4c0d5fb959fda8f4cb1d14a8376af4'
        self.machine  = '192.168.88.109'
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine
        self.dport = 445

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
