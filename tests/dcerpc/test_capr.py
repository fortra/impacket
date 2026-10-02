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
#   (h)LsarGetAvailableCAPIDs Which is the only one 
#
import pytest
import unittest
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import capr


class CAPRTests(DCERPCTests):
    iface_uuid = capr.MSRPC_UUID_LSACAP
    string_binding = r"ncacn_np:{0.machine}[\PIPE\lsarpc]"
    authn = True

    def check_capids(self, resp):
        # CAPIDs are SIDs under SECURITY_SCOPED_POLICY_ID_AUTHORITY (S-1-17-*).
        # A target with no Central Access Policies configured returns an
        # empty set, which is still a valid response.
        self.assertEqual(resp['ErrorCode'], 0)
        wrapped = resp['WrappedCAPIDs']
        self.assertEqual(wrapped['Entries'], len(wrapped['SidInfo']))
        for sidInfo in wrapped['SidInfo']:
            self.assertTrue(sidInfo['Sid'].formatCanonical().startswith('S-1-17-'))

    def test_LsarGetAvailableCAPIDs(self):
        dce, rpctransport = self.connect()
        request = capr.LsarGetAvailableCAPIDs()
        resp = dce.request(request)
        resp.dump()
        self.check_capids(resp)

    def test_hLsarGetAvailableCAPIDs(self):
        dce, rpctransport = self.connect()
        resp = capr.hLsarGetAvailableCAPIDs(dce)
        resp.dump()
        self.check_capids(resp)


@pytest.mark.remote
class CAPRTestsSMBTransport(CAPRTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class CAPRTestsSMBTransport64(CAPRTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64



if __name__ == "__main__":
    unittest.main(verbosity=1)
