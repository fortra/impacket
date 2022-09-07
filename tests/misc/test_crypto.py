#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
from __future__ import print_function, division
import unittest
from binascii import hexlify, unhexlify

from impacket.crypto import Generate_Subkey, AES_CMAC, AES_CMAC_PRF_128


def by8(s):
    return [s[i:i + 8] for i in range(0, len(s), 8)]


def hex8(b):
    return ' '.join(by8(hexlify(b).decode('ascii')))


def pp(prev, s):
    print(prev, end=' ')
    for c in by8(s):
        print(c, end=' ')
    #    for i in range((len(s)//8)):
    #        print("%s" % (s[:8]), end = ' ')
    #        s = s[8:]
    print()
    return ''


class CryptoTests(unittest.TestCase):
    def test_subkey(self):
        K = "2b7e151628aed2a6abf7158809cf4f3c"
        M = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"  # noqa

        K1, K2 = Generate_Subkey(unhexlify(K))
        self.assertEqual(hex8(K1), 'fbeed618 35713366 7c85e08f 7236a8de')
        self.assertEqual(hex8(K2), 'f7ddac30 6ae266cc f90bc11e e46d513b')

    def test_AES_CMAC(self):
        K = "2b7e151628aed2a6abf7158809cf4f3c"
        M = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        # Example 1: len = 0
        self.assertEqual(hex8(AES_CMAC(unhexlify(K), unhexlify(M), 0)),
                         'bb1d6929 e9593728 7fa37d12 9b756746')
        # Example 2: len = 16
        self.assertEqual(hex8(AES_CMAC(unhexlify(K), unhexlify(M), 16)),
                         '070a16b4 6b4d4144 f79bdd9d d04a287c')
        # Example 3: len = 40
        self.assertEqual(hex8(AES_CMAC(unhexlify(K), unhexlify(M), 40)),
                         'dfa66747 de9ae630 30ca3261 1497c827')
        # Example 3: len = 64
        self.assertEqual(hex8(AES_CMAC(unhexlify(K), unhexlify(M), 64)),
                         '51f0bebf 7e3b9d92 fc497417 79363cfe')
        M = "eeab9ac8fb19cb012849536168b5d6c7a5e6c5b2fcdc32bc29b0e3654078a5129f6be2562046766f93eebf146b"
        K = "6c3473624099e17ff3a39ff6bdf6cc38"
        # Mac = dbf63fd93c4296609e2d66bf79251cb5
        # Example 4: len = 45
        self.assertEqual(hex8(AES_CMAC(unhexlify(K), unhexlify(M), 45)),
                         'dbf63fd9 3c429660 9e2d66bf 79251cb5')

    def test_AES_CMAC_PRF_128(self):
        K = "000102030405060708090a0b0c0d0e0fedcb"
        M = "000102030405060708090a0b0c0d0e0f10111213"

        # AES-CMAC-PRF-128 Test Vectors
        # Example 1: len = 0, Key Length       18
        self.assertEqual(hex8(AES_CMAC_PRF_128(unhexlify(K), unhexlify(M), 18, len(unhexlify(M)))),
                         '84a348a4 a45d235b abfffc0d 2b4da09a')
        # Example 1: len = 0, Key Length       16
        self.assertEqual(hex8(AES_CMAC_PRF_128(unhexlify(K)[:16], unhexlify(M), 16, len(unhexlify(M)))),
                         '980ae87b 5f4c9c52 14f5b6a8 455e4c2d')
        # Example 1: len = 0, Key Length       10
        self.assertEqual(hex8(AES_CMAC_PRF_128(unhexlify(K)[:10], unhexlify(M), 10, len(unhexlify(M)))),
                         '290d9e11 2edb09ee 141fcf64 c0b72f3d')


if __name__ == "__main__":
    unittest.main(verbosity=1)
