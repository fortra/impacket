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

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, lsat
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.dcerpc.v5.dtypes import *
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import system_errors

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
        dce.bind(lsat.MSRPC_UUID_LSAT)
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
        #resp.dump()

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
        resp = dce.request(request)
        #resp.dump()

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
        #resp.dump()

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
        #resp.dump()

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
        #resp.dump()

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
        #resp.dump()
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
        resp = dce.request(request)
        #resp.dump()

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
        #resp.dump()
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
        #resp.dump()

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
        #resp.dump()
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
            #resp.dump()
        except Exception, e:
            if str(e).find('STATUS_SOME_NOT_MAPPED') < 0:
                raise
            else:
                resp = e.get_packet()
                #resp.dump()



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

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
    unittest.TextTestRunner(verbosity=1).run(suite)
