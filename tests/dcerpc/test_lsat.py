# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)LsarGetUserName
#   (h)LsarLookupNames
#   (h)LsarLookupNames2
#   (h)LsarLookupNames3
#   (h)LsarLookupNames4
#   (h)LsarLookupSids
#   (h)LsarLookupSids2
#   LsarLookupSids3
#
from __future__ import division
from __future__ import print_function
import pytest
import unittest
from six import assertRaisesRegex
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING


class LSATTests(DCERPCTests):
    iface_uuid = lsat.MSRPC_UUID_LSAT
    string_binding = r"ncacn_np:{0.machine}[\PIPE\lsarpc]"
    authn = True

    def open_policy(self, dce):
        request = lsad.LsarOpenPolicy2()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
        resp = dce.request(request)
        return resp['PolicyHandle']

    def test_LsarGetUserName(self):
        dce, rpctransport = self.connect()
        request = lsat.LsarGetUserName()
        request['SystemName'] = NULL
        request['UserName'] = NULL
        request['DomainName'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hLsarGetUserName(self):
        dce, rpctransport = self.connect()
        resp = lsat.hLsarGetUserName(dce)
        resp.dump()

    def test_LsarLookupNames4(self):
        dce, rpctransport = self.connect()

        request = lsat.LsarLookupNames4()
        request['Count'] = 2
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        name2 = RPC_UNICODE_STRING()
        name2['Data'] = 'Guest'
        request['Names'].append(name1)
        request['Names'].append(name2)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        request['LookupOptions'] = 0x00000000
        request['ClientRevision'] = 0x00000001

        # The RPC server MUST ensure that the RPC_C_AUTHN_NETLOGON security provider
        # (as specified in [MS-RPCE] section 2.2.1.1.7) and at least
        # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY authentication level (as specified in
        # [MS-RPCE] section 2.2.1.1.8) are used in this RPC message.
        # Otherwise, the RPC server MUST return STATUS_ACCESS_DENIED.
        with assertRaisesRegex(self, DCERPCException, 'rpc_s_access_denied'):
            dce.request(request)

    def test_hLsarLookupNames4(self):
        # not working, I need netlogon here
        dce, rpctransport = self.connect()

        # The RPC server MUST ensure that the RPC_C_AUTHN_NETLOGON security provider
        # (as specified in [MS-RPCE] section 2.2.1.1.7) and at least
        # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY authentication level (as specified in
        # [MS-RPCE] section 2.2.1.1.8) are used in this RPC message.
        # Otherwise, the RPC server MUST return STATUS_ACCESS_DENIED.
        with assertRaisesRegex(self, DCERPCException, 'rpc_s_access_denied'):
            lsat.hLsarLookupNames4(dce, ('Administrator', 'Guest'))

    def test_LsarLookupNames3(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        request = lsat.LsarLookupNames3()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 2
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        name2 = RPC_UNICODE_STRING()
        name2['Data'] = 'Guest'
        request['Names'].append(name1)
        request['Names'].append(name2)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        request['LookupOptions'] = 0x00000000
        request['ClientRevision'] = 0x00000001
        resp = dce.request(request)
        resp.dump()

    def test_hLsarLookupNames3(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        resp = lsat.hLsarLookupNames3(dce, policyHandle, ('Administrator', 'Guest'))
        resp.dump()

    def test_LsarLookupNames2(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        request = lsat.LsarLookupNames2()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 2
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        name2 = RPC_UNICODE_STRING()
        name2['Data'] = 'Guest'
        request['Names'].append(name1)
        request['Names'].append(name2)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        request['LookupOptions'] = 0x00000000
        request['ClientRevision'] = 0x00000001
        resp = dce.request(request)
        resp.dump()

    def test_hLsarLookupNames2(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        resp = lsat.hLsarLookupNames2(dce, policyHandle, ('Administrator', 'Guest'))
        resp.dump()

    def test_hLsarLookupNames(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        resp = lsat.hLsarLookupNames(dce, policyHandle, ('Administrator', 'Guest'))
        resp.dump()

    def test_LsarLookupNames(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 2
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        name2 = RPC_UNICODE_STRING()
        name2['Data'] = 'Guest'
        request['Names'].append(name1)
        request['Names'].append(name2)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = dce.request(request)
        resp.dump()

    def test_LsarLookupSids3(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 1
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        request['Names'].append(name1)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = dce.request(request)
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()

        request = lsat.LsarLookupSids3()
        sid1 = lsat.LSAPR_SID_INFORMATION()
        sid1['Sid'].fromCanonical(domainSid + '-500')
        sid2= lsat.LSAPR_SID_INFORMATION()
        sid2['Sid'].fromCanonical(domainSid + '-501')
        request['SidEnumBuffer']['Entries'] = 2
        request['SidEnumBuffer']['SidInfo'].append(sid1)
        request['SidEnumBuffer']['SidInfo'].append(sid2)
        request['TranslatedNames']['Names'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        request['LookupOptions'] = 0x00000000
        request['ClientRevision'] = 0x00000001

        # The RPC server MUST ensure that the RPC_C_AUTHN_NETLOGON security provider
        # (as specified in [MS-RPCE] section 2.2.1.1.7) and at least
        # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY authentication level (as specified in
        # [MS-RPCE] section 2.2.1.1.8) are used in this RPC message.
        # Otherwise, the RPC server MUST return STATUS_ACCESS_DENIED.
        with assertRaisesRegex(self, DCERPCException, 'rpc_s_access_denied'):
            dce.request(request)

    def test_LsarLookupSids2(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 1
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        request['Names'].append(name1)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = dce.request(request)
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()

        request = lsat.LsarLookupSids2()
        request['PolicyHandle'] = policyHandle
        sid1 = lsat.LSAPR_SID_INFORMATION()
        sid1['Sid'].fromCanonical(domainSid + '-500')
        sid2= lsat.LSAPR_SID_INFORMATION()
        sid2['Sid'].fromCanonical(domainSid + '-501')
        request['SidEnumBuffer']['Entries'] = 2
        request['SidEnumBuffer']['SidInfo'].append(sid1)
        request['SidEnumBuffer']['SidInfo'].append(sid2)
        request['TranslatedNames']['Names'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        request['LookupOptions'] = 0x00000000
        request['ClientRevision'] = 0x00000001
        resp = dce.request(request)
        resp.dump()

    def test_hLsarLookupSids2(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        resp = lsat.hLsarLookupNames(dce, policyHandle, ('Administrator',))
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()
        sids = list()
        sids.append(domainSid + '-500')
        sids.append(domainSid + '-501')
        resp = lsat.hLsarLookupSids2(dce, policyHandle, sids)
        resp.dump()

    def test_LsarLookupSids(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 1
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'Administrator'
        request['Names'].append(name1)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = dce.request(request)
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()

        request = lsat.LsarLookupSids()
        request['PolicyHandle'] = policyHandle
        for i in range(1000):
            sid = lsat.LSAPR_SID_INFORMATION()
            sid['Sid'].fromCanonical(domainSid + '-%d' % (500+i))
            request['SidEnumBuffer']['SidInfo'].append(sid)
            request['SidEnumBuffer']['Entries'] += 1
        request['TranslatedNames']['Names'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta

        with assertRaisesRegex(self, DCERPCException, 'STATUS_SOME_NOT_MAPPED'):
            dce.request(request)

    def test_hLsarLookupSids(self):
        dce, rpctransport = self.connect()
        policyHandle = self.open_policy(dce)

        resp = lsat.hLsarLookupNames(dce, policyHandle, ('Administrator',))
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()

        sids = list()
        for i in range(1000):
            sids.append(domainSid + '-%d' % (500+i))

        with assertRaisesRegex(self, DCERPCException, 'STATUS_SOME_NOT_MAPPED'):
            lsat.hLsarLookupSids(dce, policyHandle, sids)


@pytest.mark.remote
class LSATTestsSMBTransport(LSATTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class LSATTestsSMBTransport64(LSATTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
