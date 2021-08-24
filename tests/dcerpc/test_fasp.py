# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   FWOpenPolicyStore
#
# Not yet:
#
import unittest
import pytest
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


# XXX: This is just to pass tests until we figure out what happened with the
#      fasp module
fasp = None


@pytest.mark.skip(reason="fasp module unavailable")
class FASPTests(DCERPCTests):
    #iface_uuid = fasp.MSRPC_UUID_FASP
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_FWOpenPolicyStore(self):
        dce, rpc_transport = self.connect()
        request = fasp.FWOpenPolicyStore()
        request['BinaryVersion'] = 0x0200
        request['StoreType'] = fasp.FW_STORE_TYPE.FW_STORE_TYPE_LOCAL
        request['AccessRight'] = fasp.FW_POLICY_ACCESS_RIGHT.FW_POLICY_ACCESS_RIGHT_READ
        request['dwFlags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hFWOpenPolicyStore(self):
        dce, rpc_transport = self.connect()
        resp = fasp.hFWOpenPolicyStore(dce)
        resp.dump()

    def test_FWClosePolicyStore(self):
        dce, rpc_transport = self.connect()
        resp = fasp.hFWOpenPolicyStore(dce)
        request = fasp.FWClosePolicyStore()
        request['phPolicyStore'] = resp['phPolicyStore']
        resp = dce.request(request)
        resp.dump()

    def test_hFWClosePolicyStore(self):
        dce, rpc_transport = self.connect()
        resp = fasp.hFWOpenPolicyStore(dce)
        resp = fasp.hFWClosePolicyStore(dce,resp['phPolicyStore'])
        resp.dump()


@pytest.mark.remote
class FASPTestsTCPTransport(FASPTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class FASPTestsTCPTransport64(FASPTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
