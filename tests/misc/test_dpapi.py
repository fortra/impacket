#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   MasterKey
# Not yet:
#
import os
import pytest
import unittest
from binascii import unhexlify

from impacket.dpapi import (DPAPI_SYSTEM, MasterKeyFile, MasterKey, CredentialFile, DPAPI_BLOB,
                            CREDENTIAL_BLOB, VAULT_VPOL, VAULT_VPOL_KEYS, VAULT_VCRD, VAULT_KNOWN_SCHEMAS)
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, MD4, SHA1


def dpapi_protect(blob, entropy=None):
    """Helper function to protect a blob of data using Windows' DPAPI via ctypes."""

    if os.name != "nt":
        raise Exception("DP API functions are only available in Windows")

    blob = bytes(blob)
    entropy = bytes(entropy or b"")

    from ctypes import windll, byref, cdll, Structure, POINTER, c_char, c_buffer
    from ctypes.wintypes import DWORD

    LocalFree = windll.kernel32.LocalFree
    memcpy = cdll.msvcrt.memcpy
    CryptProtectData = windll.crypt32.CryptProtectData
    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    class DATA_BLOB(Structure):
        _fields_ = [('cbData', DWORD),
                    ('pbData', POINTER(c_char))
                    ]

    def parse_data(data):
        cbData = int(data.cbData)
        pbData = data.pbData
        buffer = c_buffer(cbData)
        memcpy(buffer, pbData, cbData)
        LocalFree(pbData)
        return buffer.raw

    buffer_in = c_buffer(blob, len(blob))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(blob), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if CryptProtectData(byref(blob_in), None, byref(blob_entropy), None, None,
                        CRYPTPROTECT_UI_FORBIDDEN, byref(blob_out)):
        return parse_data(blob_out)

    raise Exception("Unable to encrypt blob")


class DPAPITests(unittest.TestCase):

    machineKey = unhexlify('2bb2109db472825bfa7660fdbed62c981f08587b')

    userKey = unhexlify('458dc597034d8801fc6fe3b342817caabb81a0cb')

    sid = "S-1-5-21-1455520393-2011455520393-2019809541-4133251990-500"

    username = "david.bowie\x00"
    password = "Admin456"

    adminMasterKey = unhexlify('4c4a398169cc9ecc6eae0e1a70ba1dc58bfec785c4b35bd1afdf2aeb06753bca0ea3491989cb626990973f8370fd576a46c0ce2a85d995a01af6d727ff41969c')

    adminMasterKeyFile = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00a\x004\x003\x00a\x00c\x007' \
                         b'\x001\x00-\x005\x002\x00d\x001\x00-\x004\x00b\x001\x005\x00-\x008\x004\x00c\x00b' \
                         b'\x00-\x000\x001\x00a\x005\x00e\x007\x00f\x000\x006\x003\x005\x000\x00\x00\x00\x00' \
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00h\x00\x00\x00' \
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00t\x01\x00\x00\x00\x00\x00\x00\x02' \
                         b'\x00\x00\x00\xd7\x086A\xa3\xfc\x10[\x87\x00\xea\xd0\x86S\x042\xc0]\x00\x00\t\x80' \
                         b'\x00\x00\x03f\x00\x00!"}/=B\x08\xf9Q\xffW\xc0\xa0)\x16z\x15l\x1d\xe3\xf9\x17\xcd' \
                         b'\x8elf\x98e\x9a\xcc}\xda\xb0\x11\x7fVWJ\xd3\x02\xael\x08\xf4\xach\x9c\xf9\xbbO' \
                         b'\x13\x17\xe1P\xef\x99\xa8^\xae[8)\x12\x86\xf1B-\xdb\x8c\xaf\xa5@1\x90\xba\x1e' \
                         b'\xd0E\x1b\xd0!C\xca\xcc\xc6h\x9a6\xe4B;\x8cM+\xd3\xd6R\xf5\xb5~\xd9\xc2\n\x9d\x02' \
                         b'\x00\x00\x00\xc2\x9e\x93\xc9\xd7*\xd8\x04\xcd\x8d\xfcUAR\x01\x9d\xc0]\x00\x00\t' \
                         b'\x80\x00\x00\x03f\x00\x00\xc2zU\xa7\'\xc6dj\xd8\x93\xb6\xac\xc0KQ\x8a\xea+>\xe0' \
                         b'SK@\x8b\xcc\x8e-Ua1\x92\x87\x05\x12\x7f\xe4!\xe9\xa2\x01\x89\x91JD$\x9bS\xdd\x02' \
                         b'\xba2%\xef3\t\x19Cu\x12S"\xd8Dr\xf4k\x809\xbc\xbaEJ\x02\x00\x00\x00\x00\x01\x00' \
                         b'\x00X\x00\x00\x00\xe9\x99\xde\xe7\'K\xc0D\xa1\xbe\xf3\xf4=\xc8\xa8\x9f\x9bQ\x1d' \
                         b'\x12I\xfd\xd6_\x8f9t\xc3\xfe<\x82\xa1%\x80\x8e\xaa5&\xd2\xa4\xedW\x8e\x17\x9b\xe0' \
                         b'\xe5$}\x13;\x04\xea\xce\xc2\xd3(\xfa\x8f\x02\xcd\xf2\xfa=\xa2\xf9P\x07\xc6pa\x81' \
                         b'\xd9y\xb1\x07Q\xcf\xb9\x160\x89\xf8\xad\xce\xc11\x10O\x1c\xfc\xd5\xb7.\xcd\x83\xe6' \
                         b'\xb5\xb5:\xf4\xa3(\xd3\xc3\xa3\x1b\x1dU\xec\xd8Y\xdb\xad\xd58\x8b\xf2\xe3\xc7\xd1' \
                         b'\r\xd5\x93\x97\xd4:r\x01\x8e\xf4b\x10\xed\x14h\x81\x9c>\x9b\x99\x1c\x0f\xaar\x05' \
                         b'\xf7f_\x89e\xea\x80j\xcb\x92\xa3\xc3w\xc4\x1a\xed\xe9\xceu\x05\x87\xd2r\xda\xa3' \
                         b'\x86\xd0\x8a\x9f\x81\xcde\xaf\xdc\x9a\x86$\xf7\xd7Eu\xc6W\xdam\x18\x8e\xc7wE4' \
                         b'\x90wx&\x11/\xf3Rh\xf4\xb4=\xdd\xbe\xa4\xcbR\xf9\xf6\x15C\x02\xc90\x931\xefY$' \
                         b'\x9aB\x94h4\x04\t\xb1Y\x83N\xd2\xd3\xa6|h\x04\xa4*sR\x9e\xd2pE\x1e\xc0b">\xdd\xc8' \
                         b'\xef\x9cb\xf0jVP\x9aJA\x9b|\xdbx\xdd\xcbs\xd4\xdd\x95\x88\xd4\x87,LyMf\x9b\xdf' \
                         b'\xb7\xc0\x0cJ52]\x8f=\x8eE\xe7\x93u\xe9\x18\xea%\xd7U\x17(0\xe4\x8c\xcb\xe1Q\xc7' \
                         b'\xfa\xc3qX/.\xf0r\xd2\x9a\xb35\x8e\x18\xdb\x8e\x81\xc7x\xab\x81\xbd\xcf,\x1c\xc8x' \
                         b'\x9d\xf2\x9c;\x01xo\x84\xfdx\xb4\x14G-\xd3o'

    systemMasterKey = unhexlify('682a9b8923ff4ca7ce0ef7e4cee061f0ff942cd31c7703ec60792740b2e7d0b1b5115d1ff77e10b77e189e0d6e99d5b668190ecd44fa84e82e049f406e2c2a59')

    systemMasterKeyFile = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x00a\x009\x005\x00e\x00b\x00a\x008" \
                          b"\x00-\x00b\x00a\x000\x000\x00-\x004\x00e\x001\x00a\x00-\x00b\x004\x003\x00f\x00-\x005" \
                          b"\x001\x00e\x00a\x003\x000\x001\x007\x001\x00d\x001\x001\x00\x00\x00\x00\x00\x00\x00" \
                          b"\x00\x00\x06\x00\x00\x00\xb0\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00" \
                          b"\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00" \
                          b"\xf4/a\xea\x0c\x96G\xbf@8\x19\x89\x84R\x08\x9f\xf8C\x00\x00\x0e\x80\x00\x00\x10f\x00" \
                          b"\x00\xe2D\x1d\xec\x11\xa6\xb6\xf0?\xfe\xbb\xa1\xe7\x14s\xf7\x8d\xa4jR\xb1,\xaf\xf7" \
                          b"\xdf\x99%\xedj\xc8\x9d\x84\x05\n\xd1\\\xfe\x88\xecP\xec\xe2\x01\xe5\xa8\x0e\xb1\x98" \
                          b"\x90\x9f\xf8\xc7\x81Q\x0fx\x85\x9b\x96\xcf\xad\xe43\xc8:\x7f?\xc1\x99&\xb0(\x0ej\x19n" \
                          b"\xf1\xb0\xb5\xe1\xb3\xc1\xabBa \xdaS\xf2NY\x89\xf8\xa7\xd3\xdd\xe8j\xc4D\x90\x14\x01" \
                          b"\xa6\xdfd\x07\xf5P\xd1\x97\xff'\xc9\x1a\xbb\\3\x12P\xb5\xa7\xceX\xc1\xf6\x1f\xd0\xd6V6" \
                          b"\r\xf5\x8eo[_\xaa\xc69f\x1a\xa8\x94\x02\x00\x00\x00\xbd\xc1\xf9Y#W5:*>\xbc\xf8\xce" \
                          b"\xdcr\xbb\xf8C\x00\x00\x0e\x80\x00\x00\x10f\x00\x00\x121\xd6~\xc6\x89\xfe\xa9\xf6" \
                          b"\xdek\xd6j!\xe2\x8dT\x05#-\xf7\x1d\xea\xe5\xbf:\xb6<l\xb2\xca\xc0\x8a\xd1tV\x97\x9dr" \
                          b"\xb7\r\xe1:\xfc+a\xd0T4\x16\x11\x91\xdc\xdf\xb2J\xaa\xc7\xed\x02u\xf7\x1e\xff\x9f" \
                          b"\x93jU\x9a\xffK\xe60\x1b\xa9\x9df\xbd\x8e\x07\xb1\xa3%\xc7<zM\xa9q\x17\xf8\x05Q\xa3" \
                          b"\xf0\xa7]\xa9\xfc\xc3|M+\xb4;Z\x9e\xf1hDF\xae\x03\x00\x00\x00\x00\x00\x00\x00\x00" \
                          b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    credentialFile = b'\x01\x00\x00\x00j\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15' \
                     b'\xd1\x11\x8cz\x00\xc0O\xc2\x97\xeb\x01\x00\x00\x00q\xacC:\xd1R\x15K\x84\xcb\x01\xa5' \
                     b'\xe7\xf0cP\x00\x00\x00 :\x00\x00\x00E\x00n\x00t\x00e\x00r\x00p\x00r\x00i\x00s\x00e' \
                     b'\x00 \x00C\x00r\x00e\x00d\x00e\x00n\x00t\x00i\x00a\x00l\x00 \x00D\x00a\x00t\x00a\x00' \
                     b'\r\x00\n\x00\x00\x00\x03f\x00\x00\xc0\x00\x00\x00\x10\x00\x00\x00X\x87\xdb\xeb\xc07' \
                     b'\xd8\xef\xb5\xa3\x9fi##!L\x00\x00\x00\x00\x04\x80\x00\x00\xa0\x00\x00\x00\x10\x00\x00' \
                     b'\x00\x92\xbe\x1f7\xa5\x80\xe5\x11\ns\x08lr\xec\xf7\xfc\xa8\x00\x00\x00\x92YL\xcd4C\xd8' \
                     b'\xe7[\xd8D}\xac\x9a_\n\xdc\xe7\xf2\x9ar\x84\x1fC\x87\x19\xb9\xe8y\x9c\x07LD>\xf3\xd3' \
                     b'\x97\x01\xb0\xfa\xf2n\xa3\xd9U_\xd3n\xd4\x80\xa5\x13\xb9$\x13\xe2\x02\x97\xb0*\xd6\xcf' \
                     b'\xa1\x1e\x19\xf1\x9c\xea.tq\xf3\xb4\x89*L\xd2\xd5\x91;D7\xbd\xf0\x1eF\x82\x13\xb9e\x9b' \
                     b'\x9a\x86w0\xb2\xb7b\x8f\xb6\t\xbe\xfb>v\x9f\x89S\x10\xe3\xe7\x0f}:\xd3\xdd\xe3B\x18c' \
                     b'\xf7\x85j\xe4\xfb4=\x1e\x18\x97\xa1,+i\xe5\x8b\xdfn8\xc5>\x9eysQe\x85\xfb\x0b\x01' \
                     b'\xd8 \xb2\x81*\x8e\xcd \xafE\x9f\x8c\xcb\x97\x89\x96\x97\xdd\x14\x00\x00\x00\xb7\xe5%' \
                     b'\xfdC*R\xf9\rd\x0b\x7f\xf0G\xe9C\xf3\xd3p\x8c'

    vpolFile = b"\x01\x00\x00\x00B\xc4\xf4K\x8a\x9b\xa0A\xb3\x80\xddJpM\xdb( \x00\x00\x00W\x00e\x00b\x00 " \
               b"\x00C\x00r\x00e\x00d\x00e\x00n\x00t\x00i\x00a\x00l\x00s\x00\x00\x00\x01\x00\x00\x00\x00\x00" \
               b"\x00\x00\x01\x00\x00\x00h\x01\x00\x00\x0b\xdas\xdd\x83\xfd\x12G\xaf\x8b\xd1S\xc7\x10\xc6\xb9" \
               b"\x0b\xdas\xdd\x83\xfd\x12G\xaf\x8b\xd1S\xc7\x10\xc6\xb9D\x01\x00\x00\x01\x00\x00\x00\xd0\x8c" \
               b"\x9d\xdf\x01\x15\xd1\x11\x8cz\x00\xc0O\xc2\x97\xeb\x01\x00\x00\x00Wc\xa0\t\xf5\xf3\xccJ\x9d" \
               b"\x08\xd8\x86Z\xad\xe4\xac\x00\x00\x00 \x00\x00\x00\x00\x10f\x00\x00\x00\x01\x00\x00 \x00\x00" \
               b"\x00\xe5\r@\x973M\xca\xdd\xb1\xca\x0cR\xb6\xaaO\xc5C\x91\x01\xd0l\xd6\x8f\xce1\xaf!\x17$L!" \
               b"\xc8\x00\x00\x00\x00\x0e\x80\x00\x00\x00\x02\x00\x00 \x00\x00\x00\xd2@h\x0e\x8e\xd9$V\xa8y" \
               b"\xf3\xbe\xbd\x85\x98\xb3\x1b&{\xed\xb3xx\xc6\xba\xc9\x8a\xc0s\xd4]\xeap\x00\x00\x00\x88}\x83" \
               b"\x18\xc6\xc6\x00\xbc\xfe\xeb\xc4\xcb\xde\xfei>\xabo\xba\xb8=\\\ns\xb5\xdb\x97\xb9ln8B\xd9" \
               b"\xc9\xd4:\x94\x9b7|\x94^\xda\x06\xe3\xdau\x0c\x02\x0c\x1bh\x8b\xac\xb8W#\x08\x0cm\xd5T+" \
               b"\xc0m!U\xd7f\x9aO\xf1\xc7\x8b\xd1\x9c\x8ak._g\x01P>\xd3\xd7'\xe8j\xc4\xe4\xc7\xe4f`x\xffA" \
               b"\x93#\xb5\x84\xbc\x17\x96\xa5e\xa0k\xd7p\xfc@\x00\x00\x00\xde\xb5&\xf7jZ\xac\x14Z\xd2\xb5" \
               b"\xc3\xc9\x046\xb1\xb9A-~\x17)\xe9\xdcb~\xf7J+\x15\xa8\xe7N\xc5\xe5\x0b\xe3\x86\xf8\x08\\]G" \
               b"\x9e;\x82\x9c\xa2\xf3\xf8s\xd9}\xdd\x00f\x97u\xe3\xeff\x05\xa4\x90\x00\x00\x00\x00"

    vcrdFile = b'\x99T\xcd<\xa8\x87\x10K\xa2\x15`\x88\x88\xdd;U\x04\x00\x00\x00\xa3\xcf\x10\xffWm\xd3\x01\xff' \
               b'\xff\xff\xff\x00\x02\x00\x00$\x00\x00\x00I\x00n\x00t\x00e\x00r\x00n\x00e\x00t\x00 \x00E\x00x' \
               b'\x00p\x00l\x00o\x00r\x00e\x00r\x00\x00\x000\x00\x00\x00\x01\x00\x00\x00\x80\x00\x00\x00M_{' \
               b'\x18\x02\x00\x00\x00\xb5\x00\x00\x00M_{\x18\x03\x00\x00\x00\xea\x00\x00\x00M_{\x18d\x00\x00' \
               b'\x00\x00\x01\x00\x00M_{\x18\x01\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00\n\x00\x00\x00!' \
               b'\x00\x00\x00\x00\x00e\x1c\x90\x18P\xab\xd0 0\xac!\xaf\x10\x81\xfe\xabAN#ga\xa9^I\x0e=\xffW' \
               b'\xd2\xdbt\x02\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00\n\x00\x00\x00!\x00\x00\x00\x00\x99' \
               b'|\xc9\x8b+\xd1\xbfF\xf2\xdd\xdd\xac\xa9\x80\xfd\x08x\x9d\xe6\xbe\x16&\xb0\'\x1ahQ\x08\x86-' \
               b'\xdc~\x03\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x01\x00d' \
               b'\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\xb5\x00\x00\x00' \
               b'\x01\x10\x00\x00\x00)\x87\xe8|\xe62\xc7\xcf\x98\xc9\xbd\xfb}"\xe4]8\x8a\x1cl\xb9\x1dP4\xc8' \
               b'\xdf\xe1\x8e#b\x91\xe3\xbe\xb2bA$,\xe9\xa1\xa6\x93\xff\t\x84+\xda\xff\x9f-\'\x96O\xb9\xe9' \
               b'\x15\x0f\xb8\xd4\xdbs\xa3\xb1Z\xfc\x90\x07\x01?DBQ\xd4\x1d_\x0eo?\xd3Z\xf1Z\xe7\xf8\xe4oL3' \
               b'\x91\xbbB%\xef\x0f\xaf\x03*\x99\xd6\xb6\xc8\xd9\x83+e\x8b\x02l\x9fl IJ\xe2\x89~a)E\x8fL\xe4' \
               b'\xfc\x9dC\x17\xb0\x14\xe9]H\xfd\x0e+:\xc5\xc7\xcb\x87\xd0S\x16\x1bu\xb4\xfc1\xce\xd8\xffb' \
               b'\x0e3\xbe|\xa3\xd7<\xd1:\xf1.PUr\xe8\xfdQ\x16\xe3\xa9\rt\x14\x04\xbb\x01\x00\x00\x00\x00' \
               b'\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'

    def test_DPAPI_SYSTEM(self):
        blob = unhexlify('010000002bb2109db472825bfa7660fdbed62c981f08587b458dc597034d8801fc6fe3b342817caabb81a0cb')
        keys = DPAPI_SYSTEM(blob)
        keys.dump()
        self.assertEqual(self.machineKey, keys['MachineKey'])
        self.assertEqual(self.userKey, keys['UserKey'])

    def test_systemMasterKeyFile(self):
        mkf = MasterKeyFile(self.systemMasterKeyFile)
        mkf.dump()
        data = self.systemMasterKeyFile[len(mkf):]
        mk = MasterKey(data[:mkf['MasterKeyLen']])
        mk.dump()
        decryptedKey = mk.decrypt(self.userKey)
        self.assertEqual(decryptedKey, self.systemMasterKey)

    def deriveKeysFromUser(self, sid, password):
        # Will generate two keys, one with SHA1 and another with MD4
        key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
        key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()

        return key1, key2

    def atest_adminMasterKeyFile(self):
        # ToDo: fix this one..
        mkf = MasterKeyFile(self.adminMasterKeyFile)
        mkf.dump()
        data = self.adminMasterKeyFile[len(mkf):]
        mk = MasterKey(data[:mkf['MasterKeyLen']])
        mk.dump()
        key1, key2 = self.deriveKeysFromUser(self.sid, self.password)
        decryptedKey = mk.decrypt(key1)
        decryptedKey = mk.decrypt(key2)
        self.assertEqual(decryptedKey, self.adminMasterKey)

    def test_decryptCredential(self):
        credFile = CredentialFile(self.credentialFile)
        credFile.dump()
        blob = DPAPI_BLOB(credFile['Data'])
        decrypted = blob.decrypt(self.adminMasterKey)
        creds = CREDENTIAL_BLOB(decrypted)
        creds.dump()
        self.assertEqual(creds['Username'], self.username.encode('utf-16le'))

    @pytest.mark.skipif(os.name != "nt", reason="Only Windows")
    def test_dumpBlobProtectAPI(self):
        """Protect a blob using DPAPI and then parse and dump it. We're not testing the
        correct decryption at this point.

        TODO: It would be great to have a complete functional test to protect using DPAPI and
              then unprotect it but it will require also dumping the master key from the test
              system.
        """
        plain_blob = b"Some test string"
        entropy = b"Some entropy"
        encrypted_blob = dpapi_protect(plain_blob, entropy)
        dpapi_blob = DPAPI_BLOB(encrypted_blob)
        dpapi_blob.dump()

    def test_unprotect_without_entropy(self):
        """Simple test to decrypt a protected blob without providing an entropy string.
        The blob was obtained using the dpapi_protect helper function and key extracted from a
        test system with secretsdump/mimikatz.
        """
        plain_blob = b"Some test string"
        entropy = None
        key = unhexlify("9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3")
        encrypted_blob = unhexlify("01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc6000000000200000000001066000000010000200000000d1af96e5e102266fd36d96ac7d1595552e5a4e972463f77e6e227f22d5fc8df000000000e8000000002000020000000834f3c5710c8a7474f7dbcea8ba28ab8e4d4443f50a0c63ff4eba1cce485295f20000000b61d7576c0c6caf3690edb247bde3f7edaa59580e3b4be1265ea78e8c1b8a61d400000001c03ab807147742649b6bdfd1c1344d178bb163842d70abacfd51233af909cb81a677ec05d8db996f587ef5ac410dc189beda756eb0d1b6ee376823e80968538")
        dpapi_blob = DPAPI_BLOB(encrypted_blob)
        decrypted_blob = dpapi_blob.decrypt(key, entropy)
        self.assertEqual(plain_blob, decrypted_blob)

    def test_unprotect_with_entropy(self):
        """Simple test to decrypt a protected blob providing an entropy string.
        The blob was obtained using the dpapi_protect helper function and key extracted from a
        test system with secretsdump/mimikatz.
        """
        plain_blob = b"Some test string"
        entropy = b"Some entropy"
        key = unhexlify("9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3")
        encrypted_blob = unhexlify("01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc600000000020000000000106600000001000020000000f239c0018e71b33bef9a6299675c7e209eef1f6447bd578d19c7973548737545000000000e80000000020000200000009d9ef33e15ffb1b310a13ecec39b1c02adc39e8d40a7162f9f9bb3170c699a812000000040e820259332c47af42e5f9de629e109d1504641aad853f3818c40ac311cf24a4000000010f01a84a5cc0393d3ea44cc3a8ff00ca4d02fcabc7c353a6823c53e4e719c9b398282a06b8878250205160ed79fef8b026093ad5a467594953d6de28d71f8c9")
        dpapi_blob = DPAPI_BLOB(encrypted_blob)
        decrypted_blob = dpapi_blob.decrypt(key, entropy)
        self.assertEqual(plain_blob, decrypted_blob)

    def test_decryptVpol(self):
        vpol = VAULT_VPOL(self.vpolFile)
        vpol.dump()
        key = unhexlify('dda7cb9077756f4a5ea6291d57d5e3d3e96765885777cd6e8575f337034dfa4e58eb1ec5c97a4d9915b70130b7776aea16dc14a9486319e1849355c097b99272')
        blob = vpol['Blob']
        data = blob.decrypt(key)
        keys = VAULT_VPOL_KEYS(data)
        keys.dump()
        self.assertEqual(keys['Key2']['bKeyBlob']['bKey'],
                         unhexlify('756ff73b0ee4980e2dd722fbcd0badb9a6be89590304eb6d58b6e8ab7aaaec1d'))

    def test_decryptVCrd(self):
        blob = VAULT_VCRD(self.vcrdFile)
        blob.dump()
        key = unhexlify('acf4ff323558de5514be1731598e37c1ae5a6bf9016d5906097aee46712a5fe7')

        cleartext = None
        for i, entry in enumerate(blob.attributesLen):
            if entry > 28:
                attribute = blob.attributes[i]
                if 'IV' in attribute.fields and len(attribute['IV']) == 16:
                    cipher = AES.new(key, AES.MODE_CBC, iv=attribute['IV'])
                else:
                    cipher = AES.new(key, AES.MODE_CBC)
                cleartext = cipher.decrypt(attribute['Data'])

        if cleartext is not None:
            # Lookup schema Friendly Name and print if we find one
            if blob['FriendlyName'].decode('utf-16le')[:-1] in VAULT_KNOWN_SCHEMAS:
                # Found one. Cast it and print
                vault = VAULT_KNOWN_SCHEMAS[blob['FriendlyName'].decode('utf-16le')[:-1]](cleartext)
                vault.dump()
                self.assertEqual(vault['Username'], 'CONTOSO\\Administrator\x00'.encode('utf-16le'))
            else:
                raise Exception('No valid Schema')


# Process command-line arguments.
if __name__ == '__main__':
    unittest.main(verbosity=1)
