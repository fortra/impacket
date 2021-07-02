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
from __future__ import division
from __future__ import print_function
import pytest
import unittest
from tests import RemoteTestCase

from impacket.ldap import ldap, ldapasn1
import impacket.ldap.ldaptypes
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR


class LDAPTests(RemoteTestCase):
    def connect(self, login=True):
        self.ldapConnection = ldap.LDAPConnection(self.url, self.baseDN)
        if login:
            self.ldapConnection.login(self.username, self.password)
        return self.ldapConnection

    def tearDown(self):
        if hasattr(self, "ldapConnection") and self.ldapConnection:
            self.ldapConnection.close()

    def dummySearch(self, ldapConnection):
        # Let's do a search just to be sure it's working
        searchFilter = "(servicePrincipalName=*)"

        resp = ldapConnection.search(
            searchFilter=searchFilter,
            attributes=[
                "servicePrincipalName",
                "sAMAccountName",
                "userPrincipalName",
                "MemberOf",
                "pwdLastSet",
                "whenCreated",
            ],
        )
        for item in resp:
            print(item.prettyPrint())

    def test_security_descriptor(self):
        # Comment by @dirkjanm:
        # To prevent false negatives in the test case, impacket.ldap.ldaptypes.RECALC_ACL_SIZE should be set to False
        # in tests, since sometimes Windows has redundant null bytes after an ACE.Stripping those away makes the
        # ACLs not match at a binary level.
        impacket.ldap.ldaptypes.RECALC_ACL_SIZE = False
        ldapConnection = self.connect()
        searchFilter = "(objectCategory=computer)"

        resp = ldapConnection.search(
            searchFilter=searchFilter, attributes=["nTSecurityDescriptor"]
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            for attribute in item["attributes"]:
                if attribute["type"] == "nTSecurityDescriptor":
                    secDesc = str(attribute["vals"][0])
                    # Converting it so we can use it
                    sd = SR_SECURITY_DESCRIPTOR()
                    sd.fromString(secDesc)
                    sd.dump()
                    self.assertTrue(secDesc, sd.getData())

    def test_sicily(self):
        ldapConnection = self.connect(False)
        ldapConnection.login(authenticationChoice="sicilyPackageDiscovery")

    def test_sicilyNtlm(self):
        ldapConnection = self.connect(False)
        ldapConnection.login(
            user=self.username, password=self.password, domain=self.domain
        )

        self.dummySearch(ldapConnection)

    def test_kerberosLogin(self):
        ldapConnection = self.connect(False)
        ldapConnection.kerberosLogin(self.username, self.password, self.domain)

        self.dummySearch(ldapConnection)

    def test_kerberosLoginHashes(self):
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(":")
        else:
            lmhash = ""
            nthash = ""
        ldapConnection = self.connect(False)
        ldapConnection.kerberosLogin(
            self.username, "", self.domain, lmhash, nthash, "", None, None
        )

        self.dummySearch(ldapConnection)

    def test_kerberosLoginKeys(self):
        ldapConnection = self.connect(False)
        ldapConnection.kerberosLogin(
            self.username, "", self.domain, "", "", self.aesKey, None, None
        )

        self.dummySearch(ldapConnection)

    def test_sicilyNtlmHashes(self):
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(":")
        else:
            lmhash = ""
            nthash = ""
        ldapConnection = self.connect(False)
        ldapConnection.login(
            user=self.username,
            password=self.password,
            domain=self.domain,
            lmhash=lmhash,
            nthash=nthash,
        )

        self.dummySearch(ldapConnection)

    def test_search(self):
        ldapConnection = self.connect()

        self.dummySearch(ldapConnection)


@pytest.mark.remote
class TCPTransport(LDAPTests, unittest.TestCase):
    def setUp(self):
        super(TCPTransport, self).setUp()
        self.set_tcp_transport_config()
        self.aesKey = self.config_file.get("SMBTransport", "aesKey128")
        self.url = "ldap://%s" % self.serverName
        self.baseDN = "dc=%s, dc=%s" % (
            self.domain.split(".")[0],
            self.domain.split(".")[1],
        )


@pytest.mark.remote
class TCPTransportSSL(TCPTransport):
    def setUp(self):
        super(TCPTransportSSL, self).setUp()
        self.url = "ldaps://%s" % self.serverName


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
