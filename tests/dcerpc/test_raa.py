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
#   (h)AuthzrInitializeContextFromSid
#   (h)AuthzrFreeContext
#   (h)AuthzrInitializeCompoundContext
#   (h)AuthzrAccessCheck
#   (h)AuthzGetInformationFromContext
#
# Not yet:
#   (h)AuthzrModifyClaims
#   (h)AuthzrModifySids
#
from __future__ import division
from __future__ import print_function
import pytest
import unittest

from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import raa, epm
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, READ_CONTROL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACE, ACCESS_ALLOWED_ACE, ACL, \
    LDAP_SID, ACCESS_MASK


class RAATests(DCERPCTests):
    iface_uuid = raa.MSRPC_UUID_RAA
    protocol = "ncacn_ip_tcp"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    # Well-known SID for BUILTIN\Administrators. Always resolves on any Windows target
    WELL_KNOWN_SID = 'S-1-5-32-544'

    def setUp(self):
        # MS-RAA registers itself in EPM under a non-nil object UUID
        # (see [MS-RAA] section 2.1). 
        from struct import unpack
        super(DCERPCTests, self).setUp()
        self.set_transport_config(machine_account=self.machine_account)

        entries = epm.hept_lookup(self.machine, ifId=raa.MSRPC_UUID_RAA)
        port = None
        for entry in entries:
            for floor in entry['tower']['Floors'][3:]:
                if floor['ProtocolData'] == b'\x07':  # ncacn_ip_tcp port floor
                    port = unpack('!H', floor['RelatedData'])[0]
                    break
            if port is not None:
                break
        if port is None:
            self.skipTest("MS-RAA is not registered over ncacn_ip_tcp on %s" % self.machine)
        self.string_binding = r"ncacn_ip_tcp:%s[%d]" % (self.machine, port)

    def build_security_descriptor(self, sid):
        """Builds a minimal self-relative security descriptor with a single
        ACCESS_ALLOWED ACE granting GENERIC_ALL to the supplied SID. Returned as
        the raw octet stream expected by AUTHZR_ACCESS_REQUEST.
        """
        sd = SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        # SE_DACL_PRESENT | SE_SELF_RELATIVE
        sd['Control'] = 0x8004
        sd['OwnerSid'] = LDAP_SID()
        sd['OwnerSid'].fromCanonical(sid)
        sd['GroupSid'] = b''
        sd['Sacl'] = b''

        mask = ACCESS_MASK()
        mask['Mask'] = ACCESS_MASK.GENERIC_ALL
        allowedAce = ACCESS_ALLOWED_ACE()
        allowedAce['Mask'] = mask
        allowedAce['Sid'] = LDAP_SID()
        allowedAce['Sid'].fromCanonical(sid)

        ace = ACE()
        ace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
        ace['AceFlags'] = 0
        ace['Ace'] = allowedAce

        dacl = ACL()
        dacl['AclRevision'] = 2
        dacl['Sbz1'] = 0
        dacl['Sbz2'] = 0
        dacl.aces = [ace]
        sd['Dacl'] = dacl

        return sd.getData()

    def test_AuthzrInitializeContextFromSid(self):
        dce, rpctransport = self.connect()

        request = raa.AuthzrInitializeContextFromSid()
        request['Flags'] = raa.AUTHZ_COMPUTE_PRIVILEGES
        request['Sid'].fromCanonical(self.WELL_KNOWN_SID)
        request['pExpirationTime'] = NULL
        request['Identifier']['LowPart'] = 0xdead
        request['Identifier']['HighPart'] = 0xbeef
        resp = dce.request(request, uuid=raa.RAA_OBJECT_UUID_DEFAULT_BIN)
        resp.dump()

        request = raa.AuthzrFreeContext()
        request['ContextHandle'] = resp['ContextHandle']
        resp = dce.request(request, uuid=raa.RAA_OBJECT_UUID_DEFAULT_BIN)
        resp.dump()

    def test_hAuthzrInitializeContextFromSid(self):
        dce, rpctransport = self.connect()
        resp = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)
        resp.dump()
        raa.hAuthzrFreeContext(dce, resp['ContextHandle'])

    def test_AuthzrInitializeCompoundContext(self):
        dce, rpctransport = self.connect()
        userCtx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)
        deviceCtx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        request = raa.AuthzrInitializeCompoundContext()
        request['UserContextHandle'] = userCtx['ContextHandle']
        request['DeviceContextHandle'] = deviceCtx['ContextHandle']
        resp = dce.request(request, uuid=raa.RAA_OBJECT_UUID_DEFAULT_BIN)
        resp.dump()

        raa.hAuthzrFreeContext(dce, resp['CompoundContextHandle'])
        raa.hAuthzrFreeContext(dce, userCtx['ContextHandle'])
        raa.hAuthzrFreeContext(dce, deviceCtx['ContextHandle'])

    def test_hAuthzrInitializeCompoundContext(self):
        dce, rpctransport = self.connect()
        userCtx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)
        deviceCtx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        resp = raa.hAuthzrInitializeCompoundContext(dce, userCtx['ContextHandle'],
                                                   deviceCtx['ContextHandle'])
        resp.dump()

        raa.hAuthzrFreeContext(dce, resp['CompoundContextHandle'])
        raa.hAuthzrFreeContext(dce, userCtx['ContextHandle'])
        raa.hAuthzrFreeContext(dce, deviceCtx['ContextHandle'])

    def test_AuthzrAccessCheck(self):
        dce, rpctransport = self.connect()
        ctx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        sd = self.build_security_descriptor(self.WELL_KNOWN_SID)

        request = raa.AuthzrAccessCheck()
        request['ContextHandle'] = ctx['ContextHandle']
        request['Flags'] = 0
        request['pRequest']['DesiredAccess'] = MAXIMUM_ALLOWED
        request['pRequest']['PrincipalSelfSid'] = NULL
        request['pRequest']['ObjectTypeListLength'] = 0
        request['pRequest']['ObjectTypeList'] = NULL
        request['SecurityDescriptorCount'] = 1
        srSd = raa.SR_SD()
        srSd['dwLength'] = len(sd)
        srSd['pSrSd'] = sd
        request['pSecurityDescriptors'].append(srSd)
        request['pReply']['ResultListLength'] = 1
        request['pReply']['GrantedAccessMask'] = [0]
        request['pReply']['Error'] = [0]
        resp = dce.request(request, uuid=raa.RAA_OBJECT_UUID_DEFAULT_BIN)
        resp.dump()

        raa.hAuthzrFreeContext(dce, ctx['ContextHandle'])

    def test_hAuthzrAccessCheck(self):
        dce, rpctransport = self.connect()
        ctx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        sd = self.build_security_descriptor(self.WELL_KNOWN_SID)
        resp = raa.hAuthzrAccessCheck(dce, ctx['ContextHandle'], sd, READ_CONTROL)
        resp.dump()

        raa.hAuthzrFreeContext(dce, ctx['ContextHandle'])

    def test_AuthzGetInformationFromContext_UserSid(self):
        dce, rpctransport = self.connect()
        ctx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        request = raa.AuthzGetInformationFromContext()
        request['ContextHandle'] = ctx['ContextHandle']
        request['InfoClass'] = raa.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoUserSid
        resp = dce.request(request, uuid=raa.RAA_OBJECT_UUID_DEFAULT_BIN)
        resp.dump()

        raa.hAuthzrFreeContext(dce, ctx['ContextHandle'])

    def test_hAuthzGetInformationFromContext_UserSid(self):
        dce, rpctransport = self.connect()
        ctx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        resp = raa.hAuthzGetInformationFromContext(dce, ctx['ContextHandle'],
            raa.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoUserSid)
        resp.dump()

        raa.hAuthzrFreeContext(dce, ctx['ContextHandle'])

    def test_hAuthzGetInformationFromContext_GroupsSids(self):
        dce, rpctransport = self.connect()
        ctx = raa.hAuthzrInitializeContextFromSid(dce, self.WELL_KNOWN_SID)

        resp = raa.hAuthzGetInformationFromContext(dce, ctx['ContextHandle'],
            raa.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoGroupsSids)
        resp.dump()

        raa.hAuthzrFreeContext(dce, ctx['ContextHandle'])


@pytest.mark.remote
class RAATestsTCPTransport(RAATests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class RAATestsTCPTransport64(RAATests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64



if __name__ == "__main__":
    unittest.main(verbosity=1)
