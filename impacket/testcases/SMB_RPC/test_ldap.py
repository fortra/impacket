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
import ConfigParser

from impacket.ldap import ldap, ldapasn1

class LDAPTests(unittest.TestCase):
    def dummySearch(self, ldapConnection):
        # Let's do a search just to be sure it's working
        searchFilter = ldapasn1.Filter()
        searchFilter['present'] = ldapasn1.Present('servicePrincipalName')

        resp = ldapConnection.search(searchFilter=searchFilter,
                                     attributes=['servicePrincipalName', 'sAMAccountName', 'userPrincipalName',
                                                 'MemberOf', 'pwdLastSet', 'whenCreated'])
        for item in resp:
            print item.prettyPrint()

    def connect(self):
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.login(self.username, self.password)
        return ldapConnection

    def test_sicily(self):
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.login(authenticationChoice='sicilyPackageDiscovery')

    def test_sicilyNtlm(self):
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.login(user=self.username, password=self.password, domain=self.domain)

        self.dummySearch(ldapConnection)

    def test_kerberosLogin(self):
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.kerberosLogin(self.username, self.password, self.domain)

        self.dummySearch(ldapConnection)

    def test_kerberosLoginHashes(self):
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.kerberosLogin(self.username, '', self.domain, lmhash, nthash, '', None, None)

        self.dummySearch(ldapConnection)

    def test_kerberosLoginKeys(self):
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.kerberosLogin(self.username, '', self.domain, '', '', self.aesKey, None, None)

        self.dummySearch(ldapConnection)

    def test_sicilyNtlmHashes(self):
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        ldapConnection.login(user=self.username, password=self.password, domain=self.domain, lmhash=lmhash, nthash=nthash )

        self.dummySearch(ldapConnection)

    def test_search(self):
        ldapConnection = self.connect()

        self.dummySearch(ldapConnection)

class TCPTransport(LDAPTests):
    def setUp(self):
        LDAPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.aesKey = configFile.get('SMBTransport', 'aesKey128')
        self.url      = 'ldap://%s' % self.serverName
        self.baseDN   = 'dc=%s, dc=%s' % (self.domain.split('.')[0],self.domain.split('.')[1] )

class TCPTransportSSL(LDAPTests):
    def setUp(self):
        LDAPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine = configFile.get('TCPTransport', 'machine')
        self.hashes = configFile.get('TCPTransport', 'hashes')
        self.aesKey = configFile.get('SMBTransport', 'aesKey128')
        self.url      = 'ldaps://%s' % self.serverName
        self.baseDN   = 'dc=%s, dc=%s' % (self.domain.split('.')[0],self.domain.split('.')[1] )

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
    unittest.TextTestRunner(verbosity=1).run(suite)