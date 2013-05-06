'''
Created on Jan 26, 2011

@author: jgermano
'''
import unittest

from impacket import ntlm

class Test(unittest.TestCase):

    def test_dcerpc_ntlnauth_negotiate_includes_domain(self):
        
        ntlm_auth = ntlm.DCERPC_NTLMAuthNegotiate()
        ntlm_auth['auth_level'] = ntlm.NTLM_AUTH_PKT_PRIVACY
        ntlm_auth['data'] = " " * 12
        ntlm_auth['host_name'] = 'foo'
        ntlm_auth['domain_name'] = 'WORKGROUP'
        s = str(ntlm_auth)
        self.assertTrue("WORKGROUP" in s)

    def test_dcerpc_ntlnauth_negotiate_includes_dcerpc_auth_info(self):
        dcerpc_auth_info = ntlm.DCERPC_NTLMAuthHeader()
        dcerpc_auth_info['data'] = ''
        dcerpc_auth_info['auth_level'] = ntlm.NTLM_AUTH_PKT_PRIVACY
        dcerpc_auth_info_str = str(dcerpc_auth_info)
        
        ntlm_auth = ntlm.DCERPC_NTLMAuthNegotiate()
        ntlm_auth['auth_level'] = ntlm.NTLM_AUTH_PKT_PRIVACY
        ntlm_auth['data'] = " " * 12
        ntlm_auth['host_name'] = 'foo'
        ntlm_auth['domain_name'] = 'WORKGROUP'
        s = str(ntlm_auth)
        self.assertEquals(s[:len(dcerpc_auth_info_str)], dcerpc_auth_info_str)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()