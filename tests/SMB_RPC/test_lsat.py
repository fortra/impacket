###############################################################################
#  Tested so far: 
#
# LsarGetUserName
# LsarLookupNames
# LsarLookupSids
# LsarLookupSids2
# LsarLookupNames3
# LsarLookupNames2
#
#  Not yet:
#
# LsarLookupNames4
# LsarLookupSids3
# 
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import lsat
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING


class LSATTests(unittest.TestCase):
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
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT, transfer_syntax = self.ts)
        request = lsat.LsarOpenPolicy2()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
        resp = dce.request(request)

        return dce, rpctransport, resp['PolicyHandle']

    def test_LsarGetUserName(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsat.LsarGetUserName()
        request['SystemName'] = NULL
        request['UserName'] = NULL
        request['DomainName'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hLsarGetUserName(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsat.hLsarGetUserName(dce)
        resp.dump()

    def test_LsarLookupNames4(self):
        # not working, I need netlogon here
        dce, rpctransport, policyHandle = self.connect()

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
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            # The RPC server MUST ensure that the RPC_C_AUTHN_NETLOGON security provider 
            # (as specified in [MS-RPCE] section 2.2.1.1.7) and at least 
            # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY authentication level (as specified in 
            # [MS-RPCE] section 2.2.1.1.8) are used in this RPC message. 
            # Otherwise, the RPC server MUST return STATUS_ACCESS_DENIED.
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_hLsarLookupNames4(self):
        # not working, I need netlogon here
        dce, rpctransport, policyHandle = self.connect()

        try:
            resp = lsat.hLsarLookupNames4(dce, ('Administrator', 'Guest'))
            resp.dump()
        except Exception, e:
            # The RPC server MUST ensure that the RPC_C_AUTHN_NETLOGON security provider 
            # (as specified in [MS-RPCE] section 2.2.1.1.7) and at least 
            # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY authentication level (as specified in 
            # [MS-RPCE] section 2.2.1.1.8) are used in this RPC message. 
            # Otherwise, the RPC server MUST return STATUS_ACCESS_DENIED.
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_LsarLookupNames3(self):
        dce, rpctransport, policyHandle = self.connect()

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
        dce, rpctransport, policyHandle = self.connect()

        resp = lsat.hLsarLookupNames3(dce, policyHandle, ('Administrator', 'Guest'))
        resp.dump()

    def test_LsarLookupNames2(self):
        dce, rpctransport, policyHandle = self.connect()

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
        dce, rpctransport, policyHandle = self.connect()

        resp = lsat.hLsarLookupNames2(dce, policyHandle, ('Administrator', 'Guest'))
        resp.dump()

    def test_hLsarLookupNames(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsat.hLsarLookupNames(dce, policyHandle, ('Administrator', 'Guest'))
        resp.dump()

    def test_LsarLookupNames(self):
        dce, rpctransport, policyHandle = self.connect()

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
        # not working, I need netlogon here
        dce, rpctransport, policyHandle = self.connect()

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
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            # The RPC server MUST ensure that the RPC_C_AUTHN_NETLOGON security provider 
            # (as specified in [MS-RPCE] section 2.2.1.1.7) and at least 
            # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY authentication level (as specified in 
            # [MS-RPCE] section 2.2.1.1.8) are used in this RPC message. 
            # Otherwise, the RPC server MUST return STATUS_ACCESS_DENIED.
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_LsarLookupSids2(self):
        dce, rpctransport, policyHandle = self.connect()

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
        dce, rpctransport, policyHandle = self.connect()

        resp = lsat.hLsarLookupNames(dce, policyHandle, ('Administrator',))
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()
        sids = list()
        sids.append(domainSid + '-500')
        sids.append(domainSid + '-501')
        resp = lsat.hLsarLookupSids2(dce, policyHandle, sids)
        resp.dump()

    def test_LsarLookupSids(self):
        dce, rpctransport, policyHandle = self.connect()

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
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_SOME_NOT_MAPPED') < 0:
                raise
            else:
                resp = e.get_packet()
                resp.dump()

    def test_hLsarLookupSids(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsat.hLsarLookupNames(dce, policyHandle, ('Administrator',))
        resp.dump()
        domainSid = resp['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()

        sids = list()
        for i in range(1000):
            sids.append(domainSid + '-%d' % (500+i))
        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, sids )
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_SOME_NOT_MAPPED') < 0:
                raise
            else:
                resp = e.get_packet()
                resp.dump()


class SMBTransport(LSATTests):
    def setUp(self):
        LSATTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\lsarpc]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(LSATTests):
    def setUp(self):
        LSATTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\lsarpc]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
