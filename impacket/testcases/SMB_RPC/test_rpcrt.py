import unittest
import ConfigParser

from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5 import transport, epm, samr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, \
    RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_WINNT
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING


# aimed at testing just the DCERPC engine, not the particular
# endpoints (we should do specific tests for endpoints)
# here we're using EPM just beacuse we need one, and it's the 
# easiest one

class DCERPCTests(unittest.TestCase):
    def connectDCE(self, username, password, domain, lm='', nt='', aesKey='', TGT=None, TGS=None, tfragment=0,
                   dceFragment=0,
                   auth_type=RPC_C_AUTHN_WINNT, auth_level=RPC_C_AUTHN_LEVEL_NONE, dceAuth=True, doKerberos=False,
                   bind=epm.MSRPC_UUID_PORTMAP):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(username, password, domain, lm, nt, aesKey, TGT, TGS)
            rpctransport.set_kerberos(doKerberos)

        rpctransport.set_max_fragment_size(tfragment)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(dceFragment)
        if dceAuth is True:
            dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(auth_type)
        dce.set_auth_level(auth_level)
        dce.bind(bind)

        return dce

    def test_connection(self):
        dce = self.connectDCE(self.username, self.password, self.domain, dceAuth=False)
        dce.disconnect()

    def test_connectionHashes(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceAuth=False)
        dce.disconnect()

    def test_dceAuth(self):
        dce = self.connectDCE(self.username, self.password, self.domain, dceAuth=True)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthKerberos(self):
        dce = self.connectDCE(self.username, self.password, self.domain, dceAuth=True, doKerberos=True)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasHashes(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceAuth=True)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasHashesKerberos(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceAuth=True, doKerberos=True)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasAes128Kerberos(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aesKey128, dceAuth=True, doKerberos=True)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasAes256Kerberos(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aesKey256, dceAuth=True, doKerberos=True)
        resp = epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceTransportFragmentation(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, tfragment=1, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_dceFragmentation(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceFragment=1, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_bigRequestMustFragment(self):
        class dummyCall(NDRCALL):
            opnum = 2
            structure = (
                ('Name', RPC_UNICODE_STRING),
            )
        lmhash, nthash = self.hashes.split(':')
        oldBinding = self.stringBinding
        self.stringBinding = epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        print self.stringBinding
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceFragment=0,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              dceAuth=True,
                              doKerberos=True, bind=samr.MSRPC_UUID_SAMR)
        self.stringBinding = oldBinding

        request = samr.SamrConnect()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = samr.DELETE | samr.READ_CONTROL | samr.WRITE_DAC | samr.WRITE_OWNER | samr.ACCESS_SYSTEM_SECURITY | samr.GENERIC_READ | samr.GENERIC_WRITE | samr.GENERIC_EXECUTE | samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_SHUTDOWN | samr.SAM_SERVER_INITIALIZE | samr.SAM_SERVER_CREATE_DOMAIN | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN | samr.SAM_SERVER_READ | samr.SAM_SERVER_WRITE | samr.SAM_SERVER_EXECUTE
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp2 = dce.request(request)
        try:
            request = samr.SamrLookupDomainInSamServer()
            request['ServerHandle'] = resp['ServerHandle']
            request['Name'] = 'A'*4500
            resp = dce.request(request)
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        dce.disconnect()

    def test_dceFragmentationWINNTPacketIntegrity(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceFragment=1,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_dceFragmentationWINNTPacketPrivacy(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceFragment=1,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_dceFragmentationKerberosPacketIntegrity(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceFragment=1,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_dceFragmentationKerberosPacketPrivacy(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, dceFragment=1,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_WINNTPacketIntegrity(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                              dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_KerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_HashesWINNTPacketIntegrity(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_HashesKerberosPacketIntegrity(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes128KerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aesKey128,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes256KerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aesKey256,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_packetAnonWINNTPacketIntegrity(self):
        # With SMB Transport this will fail with STATUS_ACCESS_DENIED
        try:
            dce = self.connectDCE('', '', '', auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,dceAuth=False, doKerberos=False)
            request = epm.ept_lookup()
            request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
            request['object'] = NULL
            request['Ifid'] = NULL
            request['vers_option'] = epm.RPC_C_VERS_ALL
            request['max_ents'] = 499
            resp = dce.request(request)
            dce.disconnect()
        except Exception, e:
            if not (str(e).find('STATUS_ACCESS_DENIED') >=0 and self.stringBinding.find('ncacn_np') >=0):
                raise

    def test_WINNTPacketPrivacy(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        dce.disconnect()

    def test_KerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_HashesWINNTPacketPrivacy(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        dce.disconnect()

    def test_HashesKerberosPacketPrivacy(self):
        lmhash, nthash = self.hashes.split(':')
        dce = self.connectDCE(self.username, '', self.domain, lmhash, nthash, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes128KerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aesKey128,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes256KerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aesKey256,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        resp = dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_AnonWINNTPacketPrivacy(self):
        # With SMB Transport this will fail with STATUS_ACCESS_DENIED
        try:
            dce = self.connectDCE('', '', '', auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,dceAuth=False, doKerberos=False)
            request = epm.ept_lookup()
            request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
            request['object'] = NULL
            request['Ifid'] = NULL
            request['vers_option'] = epm.RPC_C_VERS_ALL
            request['max_ents'] = 499
            resp = dce.request(request)
            dce.disconnect()
        except Exception, e:
            if not (str(e).find('STATUS_ACCESS_DENIED') >=0 and self.stringBinding.find('ncacn_np') >=0):
                raise

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
        self.aesKey256= configFile.get('TCPTransport', 'aesKey256')
        self.aesKey128= configFile.get('TCPTransport', 'aesKey128')
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
        self.aesKey256= configFile.get('SMBTransport', 'aesKey256')
        self.aesKey128= configFile.get('SMBTransport', 'aesKey128')
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
