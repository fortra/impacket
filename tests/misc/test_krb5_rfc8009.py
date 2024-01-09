#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Red Hat, Inc. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
#
# This test file implements test vectors from the appendix A of RFC8009
# https://datatracker.ietf.org/doc/html/rfc8009#appendix-A
#
from impacket.krb5.crypto import _AES128_SHA256_CTS, _AES256_SHA384_CTS, _SHA256AES128, _SHA384AES256
from Cryptodome.Hash import HMAC
from struct import pack
import unittest


def encrypt_empty_plaintext(tcase, confounder, ke, ki, exp_ciphertext):
    plaintext = b''
    key = tcase.etype.random_to_key(ke)
    c = tcase.etype.basic_encrypt(key, confounder + plaintext, bytes(tcase.etype.blocksize))
    h = HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize]
    ciphertext = c + h
    tcase.assertEqual(ciphertext, exp_ciphertext)
    c = ciphertext[:-tcase.etype.macsize]
    h = ciphertext[-tcase.etype.macsize:]
    dec_plaintext = tcase.etype.basic_decrypt(key, c, bytes(tcase.etype.blocksize))[len(confounder):]
    tcase.assertEqual(plaintext, dec_plaintext)
    tcase.assertEqual(h, HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize])

    ciphertext = tcase.etype.encrypt(key, 2, plaintext, confounder)
    dec_plaintext = tcase.etype.decrypt(key, 2, ciphertext)
    tcase.assertEqual(plaintext, dec_plaintext)

def encrypt_less_than_block_size(tcase, plaintext, confounder, ke, ki, exp_ciphertext):
    key = tcase.etype.random_to_key(ke)
    c = tcase.etype.basic_encrypt(key, confounder + plaintext, bytes(tcase.etype.blocksize))
    h = HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize]
    ciphertext = c + h
    tcase.assertEqual(ciphertext, exp_ciphertext)
    c = ciphertext[:-tcase.etype.macsize]
    h = ciphertext[-tcase.etype.macsize:]
    dec_plaintext = tcase.etype.basic_decrypt(key, c, bytes(tcase.etype.blocksize))[len(confounder):]
    tcase.assertEqual(plaintext, dec_plaintext)
    tcase.assertEqual(h, HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize])

    ciphertext = tcase.etype.encrypt(key, 2, plaintext, confounder)
    dec_plaintext = tcase.etype.decrypt(key, 2, ciphertext)
    tcase.assertEqual(plaintext, dec_plaintext)

def encrypt_equals_block_size(tcase, plaintext, confounder, ke, ki, exp_ciphertext):
    key = tcase.etype.random_to_key(ke)
    c = tcase.etype.basic_encrypt(key, confounder + plaintext, bytes(tcase.etype.blocksize))
    h = HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize]
    ciphertext = c + h
    tcase.assertEqual(ciphertext, exp_ciphertext)
    c = ciphertext[:-tcase.etype.macsize]
    h = ciphertext[-tcase.etype.macsize:]
    dec_plaintext = tcase.etype.basic_decrypt(key, c, bytes(tcase.etype.blocksize))[len(confounder):]
    tcase.assertEqual(plaintext, dec_plaintext)
    tcase.assertEqual(h, HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize])

    ciphertext = tcase.etype.encrypt(key, 2, plaintext, confounder)
    dec_plaintext = tcase.etype.decrypt(key, 2, ciphertext)
    tcase.assertEqual(plaintext, dec_plaintext)

def encrypt_greater_than_block_size(tcase, plaintext, confounder, ke, ki, exp_ciphertext):
    key = tcase.etype.random_to_key(ke)
    c = tcase.etype.basic_encrypt(key, confounder + plaintext, bytes(tcase.etype.blocksize))
    h = HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize]
    ciphertext = c + h
    tcase.assertEqual(ciphertext, exp_ciphertext)
    c = ciphertext[:-tcase.etype.macsize]
    h = ciphertext[-tcase.etype.macsize:]
    dec_plaintext = tcase.etype.basic_decrypt(key, c, bytes(tcase.etype.blocksize))[len(confounder):]
    tcase.assertEqual(plaintext, dec_plaintext)
    tcase.assertEqual(h, HMAC.new(ki, bytes(tcase.etype.blocksize) + c, tcase.etype.hashmod).digest()[:tcase.etype.macsize])

    ciphertext = tcase.etype.encrypt(key, 2, plaintext, None)
    dec_plaintext = tcase.etype.decrypt(key, 2, ciphertext)
    tcase.assertEqual(plaintext, dec_plaintext)

def prf(tcase, inpt, exp_output, key, message):
    output = tcase.etype.prf(tcase.etype.random_to_key(key), inpt)
    tcase.assertEqual(output, exp_output)

def string_to_key(tcase, iter_count, pw, salt, exp_key):
    key = tcase.etype.string_to_key(pw, salt, None)
    tcase.assertEqual(key.contents, exp_key)

def key_derivation(tcase, keyusage, base_key, exp_ke, exp_ki, exp_kc):
    key = tcase.etype.random_to_key(base_key)
    ke = tcase.etype.random_to_key(tcase.etype.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0xAA), tcase.etype.keysize))
    ki = tcase.etype.random_to_key(tcase.etype.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0x55), tcase.etype.macsize))
    kc = tcase.etype.derive(key, pack('>IB', keyusage, 0x99))
    tcase.assertEqual(exp_ke, ke.contents)
    tcase.assertEqual(exp_ki, ki.contents)
    tcase.assertEqual(exp_kc, kc.contents)

def checksum(tcase, kc, plaintext, exp_checksum):
    checksum = HMAC.new(kc, plaintext, tcase.digest.enc.hashmod).digest()[:tcase.digest.enc.macsize]
    tcase.assertEqual(checksum, exp_checksum)


class Aes128HmacSha256Tests(unittest.TestCase):
    etype = _AES128_SHA256_CTS
    digest = _SHA256AES128

    def test_encrypt_empty_plaintext(self):
        confounder = bytes.fromhex('7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48')
        ke = bytes.fromhex('9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E')
        ki = bytes.fromhex('9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C')
        exp_ciphertext = bytes.fromhex('EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18')
        encrypt_empty_plaintext(self, confounder, ke, ki, exp_ciphertext)

    def test_encrypt_less_than_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05')
        confounder = bytes.fromhex('7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24')
        ke = bytes.fromhex('9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E')
        ki = bytes.fromhex('9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C')
        exp_ciphertext = bytes.fromhex('84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4 42 1D FD F8 97 6C')
        encrypt_less_than_block_size(self, plaintext, confounder, ke, ki, exp_ciphertext)

    def test_encrypt_equals_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F')
        confounder = bytes.fromhex('56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F')
        ke = bytes.fromhex('9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E')
        ki = bytes.fromhex('9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C')
        exp_ciphertext = bytes.fromhex('35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2 95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3')
        encrypt_equals_block_size(self, plaintext, confounder, ke, ki, exp_ciphertext)

    def test_encrypt_greater_than_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
        confounder = bytes.fromhex('A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC')
        ke = bytes.fromhex('9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E')
        ki = bytes.fromhex('9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C')
        exp_ciphertext = bytes.fromhex('72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36 C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC')
        encrypt_greater_than_block_size(self, plaintext, confounder, ke, ki, exp_ciphertext)

    def test_prf(self):
        inpt = b'test'
        exp_output = bytes.fromhex('9D 18 86 16 F6 38 52 FE 86 91 5B B8 40 B4 A8 86 FF 3E 6B B0 F8 19 B4 9B 89 33 93 D3 93 85 42 95')
        key = bytes.fromhex('37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C')
        message = bytes.fromhex('00 00 00 01 70 72 66 00 74 65 73 74 00 00 01 00')
        prf(self, inpt, exp_output, key, message)

    def test_string_to_key(self):
        iter_count = 32768
        pw = b'password'
        salt = bytes.fromhex('10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61') + b'ATHENA.MIT.EDUraeburn'
        exp_key = bytes.fromhex('08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7')
        string_to_key(self, iter_count, pw, salt, exp_key)

    def test_key_derivation(self):
        keyusage = 2
        base_key = bytes.fromhex('37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C')
        exp_ke = bytes.fromhex('9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E')
        exp_ki = bytes.fromhex('9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C')
        exp_kc = bytes.fromhex('B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3')
        key_derivation(self, keyusage, base_key, exp_ke, exp_ki, exp_kc)

    def test_checksum(self):
        kc = bytes.fromhex('B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3')
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
        exp_checksum = bytes.fromhex('D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE')
        checksum(self, kc, plaintext, exp_checksum)


class Aes256HmacSha384Tests(unittest.TestCase):
    etype = _AES256_SHA384_CTS
    digest = _SHA384AES256

    def test_encrypt_empty_plaintext(self):
        confounder = bytes.fromhex('F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4')
        ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C')
        encrypt_empty_plaintext(self, confounder, ke, ki, exp_ciphertext)

    def test_encrypt_less_than_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05')
        confounder = bytes.fromhex('B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A')
        ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2')
        encrypt_less_than_block_size(self, plaintext, confounder, ke, ki, exp_ciphertext)

    def test_encrypt_equals_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F')
        confounder = bytes.fromhex('53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63')
        ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66')
        encrypt_equals_block_size(self, plaintext, confounder, ke, ki, exp_ciphertext)

    def test_encrypt_greater_than_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
        confounder = bytes.fromhex('76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1')
        ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62')
        encrypt_greater_than_block_size(self, plaintext, confounder, ke, ki, exp_ciphertext)

    def test_prf(self):
        inpt = b'test'
        exp_output = bytes.fromhex('98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0 7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2')
        key = bytes.fromhex('6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52')
        message = bytes.fromhex('00 00 00 01 70 72 66 00 74 65 73 74 00 00 01 80')
        prf(self, inpt, exp_output, key, message)

    def test_string_to_key(self):
        iter_count = 32768
        pw = b'password'
        salt = bytes.fromhex('10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61') + b'ATHENA.MIT.EDUraeburn'
        exp_key = bytes.fromhex('45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67')
        string_to_key(self, iter_count, pw, salt, exp_key)

    def test_key_derivation(self):
        keyusage = 2
        base_key = bytes.fromhex('6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52')
        exp_ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        exp_ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_kc = bytes.fromhex('EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D')
        key_derivation(self, keyusage, base_key, exp_ke, exp_ki, exp_kc)

    def test_checksum(self):
        kc = bytes.fromhex('EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D')
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
        exp_checksum = bytes.fromhex('45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A')
        checksum(self, kc, plaintext, exp_checksum)


if __name__ == '__main__':
    unittest.main(verbosity=1)
