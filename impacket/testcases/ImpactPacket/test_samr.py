###############################################################################
#  Tested so far: 
#  
################################################################################

import sys
import unittest
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import samr
from impacket.winregistry import hexdump
from impacket.dcerpc.v5 import dtypes

class SAMRTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
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
        dce.bind(samr.MSRPC_UUID_SAMR)
        request = samr.SamrConnect()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN | samr.SAM_SERVER_ALL_ACCESS
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp2 = dce.request(request)
        request = samr.SamrLookupDomainInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['Name'] = resp2['Buffer']['Buffer'][0]['Name']
        resp3 = dce.request(request)
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)

        return dce, rpctransport, resp4['DomainHandle']

    def test_SamrConnect5(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect5()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['InVersion'] = 1
        request['InRevisionInfo']['tag'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_SamrConnect4(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect4()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        request['ClientRevision'] = 2
        resp = dce.request(request)
        resp.dump()

    def test_SamrConnect2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect2()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        resp.dump()

    def test_SamrConnect(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_SamrOpenDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        request = samr.SamrOpenDomain()
        SID = 'S-1-5-352321536-2562177771-1589929855-2033349547'
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['DomainId'].fromCanonical(SID)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        
    def test_SamrOpenGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        
    def test_SamrOpenAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = 25
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_ALIAS') < 0:
                raise

    def test_SamrOpenUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_ALL_ACCESS
        request['UserId'] = 500
        resp = dce.request(request)
        resp.dump()

    def test_SamrEnumerateDomainsInSamServer(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp2 = dce.request(request)
        resp2.dump()
        request = samr.SamrLookupDomainInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['Name'] = resp2['Buffer']['Buffer'][0]['Name']
        resp3 = dce.request(request)
        resp3.dump()
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)
        resp4.dump()

    def test_SamrLookupNamesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrLookupNamesInDomain()
        request['DomainHandle'] = domainHandle
        request['Count'] = 2
        entry = dtypes.RPC_UNICODE_STRING()
        entry['Data'] = 'Administrator'
        request['Names'].append(entry)
        entry = dtypes.RPC_UNICODE_STRING()
        entry['Data'] = 'beto'
        request['Names'].append(entry)

        resp5 = dce.request(request)
        resp5.dump()

    def test_SamrLookupIdsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrLookupIdsInDomain()
        request['DomainHandle'] = domainHandle
        request['Count'] = 2
        request['RelativeIds'].append(500)
        request['RelativeIds'].append(501)
        resp5 = dce.request(request)
        resp5.dump()

    def test_SamrEnumerateGroupsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateGroupsInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp4 = dce.request(request)
        resp4.dump()

    def test_SamrEnumerateAliasesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp4 = dce.request(request)
        resp4.dump()

    def test_SamrEnumerateUsersInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateUsersInDomain()
        request['DomainHandle'] = domainHandle
        request['UserAccountControl'] =  samr.USER_NORMAL_ACCOUNT
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 8192
        resp4 = dce.request(request)
        resp4.dump()

class SMBTransport(SAMRTests):
    def setUp(self):
        SAMRTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        self.username = 'test'
        self.domain   = ''
        self.serverName = ''
        self.password = 'test'
        self.machine  = '172.16.123.214'
        self.stringBinding = r'ncacn_np:%s[\pipe\samr]' % self.machine
        self.dport = 445
        self.hashes   = ''


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
