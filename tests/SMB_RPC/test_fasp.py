###############################################################################
#  Tested so far: 
#
#  FWOpenPolicyStore
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import pytest
from tests import RemoteTestCase

from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


@pytest.mark.skip(reason="fasp module unavailable")
class FASPTests(RemoteTestCase):

    def connect(self):
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
        dce.bind(fasp.MSRPC_UUID_FASP, transfer_syntax=self.ts)

        return dce, rpctransport

    def test_FWOpenPolicyStore(self):
        dce, rpctransport = self.connect()
        request = fasp.FWOpenPolicyStore()
        request['BinaryVersion'] = 0x0200
        request['StoreType'] = fasp.FW_STORE_TYPE.FW_STORE_TYPE_LOCAL
        request['AccessRight'] = fasp.FW_POLICY_ACCESS_RIGHT.FW_POLICY_ACCESS_RIGHT_READ
        request['dwFlags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hFWOpenPolicyStore(self):
        dce, rpctransport = self.connect()
        resp = fasp.hFWOpenPolicyStore(dce)
        resp.dump()

    def test_FWClosePolicyStore(self):
        dce, rpctransport = self.connect()
        resp = fasp.hFWOpenPolicyStore(dce)
        request = fasp.FWClosePolicyStore()
        request['phPolicyStore'] = resp['phPolicyStore']
        resp = dce.request(request)
        resp.dump()

    def test_hFWClosePolicyStore(self):
        dce, rpctransport = self.connect()
        resp = fasp.hFWOpenPolicyStore(dce)
        resp = fasp.hFWClosePolicyStore(dce,resp['phPolicyStore'])
        resp.dump()


@pytest.mark.remote
class TCPTransport(FASPTests, unittest.TestCase):

    def setUp(self):
        super(TCPTransport, self).setUp()
        self.set_tcp_transport_config()
        self.stringBinding = epm.hept_map(self.machine, fasp.MSRPC_UUID_FASP, protocol='ncacn_ip_tcp')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


@pytest.mark.remote
class TCPTransport64(TCPTransport):

    def setUp(self):
        super(TCPTransport64, self).setUp()
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.main(defaultTest='suite')
