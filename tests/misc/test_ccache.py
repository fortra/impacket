#!/usr/bin/env python
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
# Description:
#   Kerberos CCACHE unit tests
#
import os
import pytest
import unittest
from six import PY2
if PY2:
    mock = None
    FileNotFoundError = IOError
else:
    from unittest import mock
from impacket.krb5 import types
from impacket.krb5.ccache import AuthData, CCache, CountedOctetString, Credential, Principal
from impacket.krb5.constants import PrincipalNameType


class CCACHETests(unittest.TestCase):

    service = "krbtgt"
    domain = "INNOVATION.ROCKS"
    username = "user01"
    server = "{}/{}@{}".format(service, domain, domain)

    cache_v1_file = "tests/data/ccache-v1"
    cache_v2_file = "tests/data/ccache-v2"
    cache_v3_file = "tests/data/ccache-v3"
    cache_v4_file = "tests/data/ccache-v4"
    cache_v3_kirbi_file = "tests/data/ccache-v3-kirbi"
    cache_v4_kirbi_file = "tests/data/ccache-v4-kirbi"

    def assert_ccache(self, ccache):
        ccache.prettyPrint()
        self.assertIsInstance(ccache, CCache)
        self.assertEqual(len(ccache.credentials), 1)
        for cred in ccache.credentials:
            self.assertIsInstance(cred, Credential)

        self.assertIsNone(ccache.getCredential("krbtgt/UNEXISTENT.COM@UNEXISTENT.COM", True))
        self.assertIsNone(ccache.getCredential("krbtgt/UNEXISTENT.COM@UNEXISTENT.COM", False))
        self.assertIsNotNone(ccache.getCredential(self.server, True))
        self.assertIsNotNone(ccache.getCredential(self.server, False))

    def test_ccache_loadFile(self):
        with self.assertRaises(FileNotFoundError):
            CCache.loadFile("NON_EXISTENT")

        for cache_file in [self.cache_v1_file,
                           self.cache_v2_file]:
            with self.assertRaises(NotImplementedError):
                CCache.loadFile(cache_file)

        for cache_file in [self.cache_v3_file,
                           self.cache_v4_file]:
            ccache = CCache.loadFile(cache_file)
            self.assert_ccache(ccache)

    def test_ccache_fromKirbi(self):
        with self.assertRaises(FileNotFoundError):
            CCache.loadKirbiFile("NON_EXISTENT")

        for kirbi_file in [self.cache_v3_kirbi_file,
                           self.cache_v4_kirbi_file]:
            ccache = CCache.loadKirbiFile(kirbi_file)
            self.assert_ccache(ccache)

    @pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
    def test_ccache_parseFile_no_cache(self):
        if not PY2:
            with mock.patch.dict(os.environ, {}, clear=True):
                domain, username, TGT, TGS = CCache.parseFile(self.domain, self.username)
                self.assertEqual(domain, self.domain)
                self.assertEqual(username, self.username)
                self.assertIsNone(TGT)
                self.assertIsNone(TGS)

    @pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
    def test_ccache_parseFile_unexistent(self):
        if not PY2:
            with mock.patch.dict(os.environ, {"KRB5CCNAME": "ccache-unexistent-file"}):
                with self.assertRaises(FileNotFoundError):
                    CCache.parseFile(self.domain, self.username)

    @pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
    def test_ccache_parseFile(self):
        if not PY2:
            with mock.patch.dict(os.environ, {"KRB5CCNAME": self.cache_v4_file}):
                domain, username, TGT, TGS = CCache.parseFile("")
                self.assertEqual(domain, self.domain)
                self.assertEqual(username, self.username)
                self.assertIsNone(TGS)
                self.assertIsNotNone(TGT)

                domain, username, TGT, TGS = CCache.parseFile("unexistent_domain")
                self.assertIsNone(TGS)
                self.assertIsNone(TGT)

                domain, username, TGT, TGS = CCache.parseFile(self.domain)
                self.assertEqual(domain, self.domain)
                self.assertEqual(username, self.username)
                self.assertIsNone(TGS)
                self.assertIsNotNone(TGT)

                domain, username, TGT, TGS = CCache.parseFile(self.domain, self.username)
                self.assertEqual(domain, self.domain)
                self.assertEqual(username, self.username)
                self.assertIsNone(TGS)
                self.assertIsNotNone(TGT)

    def test_credential_with_authdata_roundtrip(self):
        # Regression test for a credential that carries authorization data.
        # Credential.authData started as a tuple and was never turned into a
        # list, so parsing any credential with auth-data raised
        # AttributeError: 'tuple' object has no attribute 'append'.
        ccache = CCache.loadFile(self.cache_v4_file)
        cred = ccache.credentials[0]

        octet = CountedOctetString()
        octet["data"] = b"\xde\xad\xbe\xef"
        octet["length"] = len(octet["data"])
        ad = AuthData()
        ad["authtype"] = 1
        ad["authdata"] = octet
        cred.authData = [ad]

        reparsed = Credential(cred.getData())

        self.assertEqual(len(reparsed.authData), 1)
        self.assertEqual(reparsed.authData[0]["authtype"], 1)
        self.assertEqual(reparsed.authData[0]["authdata"]["data"], b"\xde\xad\xbe\xef")

    def test_ccache_getCredential_three_part_spn(self):
        # Regression test for the 3-part SPN fix (service/host/domain@REALM),
        # seen in multi domain forests ldap tickets
        realm = "FOREST.LOCAL"
        cached_spn = "LDAP/DC01.CHILD-A.LOCAL/CHILD-A.LOCAL@{}".format(realm)

        ccache = CCache()
        cred = Credential()
        cred["server"] = Principal()
        cred["server"].fromPrincipal(types.Principal(cached_spn, type=PrincipalNameType.NT_SRV_INST.value))
        ccache.credentials.append(cred)

        # Exact same 3-part SPN -> should match
        self.assertIsNotNone(ccache.getCredential(cached_spn))

        # Short hostname request for the same host -> should match
        self.assertIsNotNone(ccache.getCredential("LDAP/DC01/CHILD-A.LOCAL@{}".format(realm)))

        # Same short hostname, different child domain -> must not match
        self.assertIsNone(ccache.getCredential("LDAP/DC01.CHILD-B.LOCAL/CHILD-B.LOCAL@{}".format(realm)))


if __name__ == "__main__":
    unittest.main(verbosity=1)
