#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
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
from impacket.krb5.ccache import CCache, Credential


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


if __name__ == "__main__":
    unittest.main(verbosity=1)
