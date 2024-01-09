# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Copyright and license note from crypto.py:
#
# Copyright (C) 2013 by the Massachusetts Institute of Technology.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#
from binascii import unhexlify
from functools import reduce
from os import urandom
# XXX current status:
# * Done and tested
#   - AES encryption, checksum, string2key, prf
#   - cf2 (needed for FAST)
# * Still to do:
#   - DES enctypes and cksumtypes
#   - RC4 exported enctype (if we need it for anything)
#   - Unkeyed checksums
#   - Special RC4, raw DES/DES3 operations for GSSAPI
# * Difficult or low priority:
#   - Camellia not supported by PyCrypto
#   - Cipher state only needed for kcmd suite
#   - Nonstandard enctypes and cksumtypes like des-hmac-sha1
from struct import pack, unpack

from Cryptodome.Cipher import AES, DES3, ARC4, DES
from Cryptodome.Hash import HMAC, MD4, MD5, SHA1, SHA256, SHA384
from Cryptodome.Protocol.KDF import PBKDF2, SP800_108_Counter
from Cryptodome.Util.number import GCD as gcd
from six import b, PY3, indexbytes, binary_type

from impacket.krb5 import constants


def get_random_bytes(lenBytes):
    # We don't really need super strong randomness here to use PyCrypto.Random
    return urandom(lenBytes)

class Enctype(object):
    DES_CRC = constants.EncryptionTypes.des_cbc_crc.value
    DES_MD4 = constants.EncryptionTypes.des_cbc_md4.value
    DES_MD5 = constants.EncryptionTypes.des_cbc_md5.value
    DES3 = constants.EncryptionTypes.des3_cbc_sha1_kd.value
    AES128_SHA1 = constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value
    AES256_SHA1 = constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
    AES128_SHA256 = constants.EncryptionTypes.aes128_cts_hmac_sha256_128.value
    AES256_SHA384 = constants.EncryptionTypes.aes256_cts_hmac_sha384_192.value
    RC4 = constants.EncryptionTypes.rc4_hmac.value


class Cksumtype(object):
    CRC32 = 1
    MD4 = 2
    MD4_DES = 3
    MD5 = 7
    MD5_DES = constants.ChecksumTypes.rsa_md5_des.value
    SHA1 = 9
    SHA1_DES3 = constants.ChecksumTypes.hmac_sha1_des3_kd.value
    SHA1_AES128 = constants.ChecksumTypes.hmac_sha1_96_aes128.value
    SHA1_AES256 = constants.ChecksumTypes.hmac_sha1_96_aes256.value
    SHA256_AES128 = constants.ChecksumTypes.hmac_sha256_128_aes128.value
    SHA384_AES256 = constants.ChecksumTypes.hmac_sha384_192_aes256.value
    HMAC_MD5 = constants.ChecksumTypes.hmac_md5.value


class InvalidChecksum(ValueError):
    pass


def _zeropad(s, padsize):
    # Return s padded with 0 bytes to a multiple of padsize.
    padlen = (padsize - (len(s) % padsize)) % padsize
    return s + b'\0'*padlen


def _xorbytes(b1, b2):
    # xor two strings together and return the resulting string.
    assert len(b1) == len(b2)
    return bytearray((x ^ y) for x, y in zip(b1, b2))


def _mac_equal(mac1, mac2):
    # Constant-time comparison function.  (We can't use HMAC.verify
    # since we use truncated macs.)
    assert len(mac1) == len(mac2)
    res = 0
    for x, y in zip(mac1, mac2):
        res |= x ^ y
    return res == 0


def _nfold(ba, nbytes):
    # Convert bytearray to a string of length nbytes using the RFC 3961 nfold
    # operation.

    # Rotate the bytes in ba to the right by nbits bits.
    def rotate_right(ba, nbits):
        ba = bytearray(ba)
        nbytes, remain = (nbits//8) % len(ba), nbits % 8
        return bytearray((ba[i-nbytes] >> remain) | ((ba[i-nbytes-1] << (8-remain)) & 0xff) for i in range(len(ba)))

    # Add equal-length strings together with end-around carry.
    def add_ones_complement(str1, str2):
        n = len(str1)
        v = [a + b for a, b in zip(str1, str2)]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xff for x in v):
            v = [(v[i-n+1]>>8) + (v[i]&0xff) for i in range(n)]
        return bytearray(x for x in v)

    # Concatenate copies of str to produce the least common multiple
    # of len(str) and nbytes, rotating each copy of str to the right
    # by 13 bits times its list position.  Decompose the concatenation
    # into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slen = len(ba)
    lcm = nbytes * slen // gcd(nbytes, slen)
    bigstr = bytearray()
    for i in range(lcm//slen):
        bigstr += rotate_right(ba, 13 * i)
    slices = (bigstr[p:p+nbytes] for p in range(0, lcm, nbytes))
    return bytes(reduce(add_ones_complement, slices))


def _is_weak_des_key(keybytes):
    return keybytes in (b'\x01\x01\x01\x01\x01\x01\x01\x01',
                        b'\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE',
                        b'\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E',
                        b'\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1',
                        b'\x01\xFE\x01\xFE\x01\xFE\x01\xFE',
                        b'\xFE\x01\xFE\x01\xFE\x01\xFE\x01',
                        b'\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1',
                        b'\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E',
                        b'\x01\xE0\x01\xE0\x01\xF1\x01\xF1',
                        b'\xE0\x01\xE0\x01\xF1\x01\xF1\x01',
                        b'\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE',
                        b'\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E',
                        b'\x01\x1F\x01\x1F\x01\x0E\x01\x0E',
                        b'\x1F\x01\x1F\x01\x0E\x01\x0E\x01',
                        b'\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE',
                        b'\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1')


class _EnctypeProfile(object):
    # Base class for enctype profiles.  Usable enctype classes must define:
    #   * enctype: enctype number
    #   * keysize: protocol size of key in bytes
    #   * seedsize: random_to_key input size in bytes
    #   * random_to_key (if the keyspace is not dense)
    #   * string_to_key
    #   * encrypt
    #   * decrypt
    #   * prf

    @classmethod
    def random_to_key(cls, seed):
        if len(seed) != cls.seedsize:
            raise ValueError('Wrong seed length')
        return Key(cls.enctype, seed)


class _SimplifiedEnctype(_EnctypeProfile):
    # Base class for enctypes using the RFC 3961 simplified profile.
    # Defines the encrypt, decrypt, and prf methods.  Subclasses must
    # define:
    #   * blocksize: Underlying cipher block size in bytes
    #   * padsize: Underlying cipher padding multiple (1 or blocksize)
    #   * macsize: Size of integrity MAC in bytes
    #   * hashmod: PyCrypto hash module for underlying hash function
    #   * basic_encrypt, basic_decrypt: Underlying CBC/CTS cipher

    @classmethod
    def derive(cls, key, constant):
        # RFC 3961 only says to n-fold the constant only if it is
        # shorter than the cipher block size.  But all Unix
        # implementations n-fold constants if their length is larger
        # than the block size as well, and n-folding when the length
        # is equal to the block size is a no-op.
        plaintext = _nfold(constant, cls.blocksize)
        rndseed = b''
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        return cls.random_to_key(rndseed[0:cls.seedsize])

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ki = cls.derive(key, pack('>IB', keyusage, 0x55))
        ke = cls.derive(key, pack('>IB', keyusage, 0xAA))
        if confounder is None:
            confounder = get_random_bytes(cls.blocksize)
        basic_plaintext = confounder + _zeropad(plaintext, cls.padsize)
        hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
        return cls.basic_encrypt(ke, basic_plaintext) + hmac[:cls.macsize]

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        ki = cls.derive(key, pack('>IB', keyusage, 0x55))
        ke = cls.derive(key, pack('>IB', keyusage, 0xAA))
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError('ciphertext too short')
        basic_ctext, mac = bytearray(ciphertext[:-cls.macsize]), bytearray(ciphertext[-cls.macsize:])
        if len(basic_ctext) % cls.padsize != 0:
            raise ValueError('ciphertext does not meet padding requirement')
        basic_plaintext = cls.basic_decrypt(ke, bytes(basic_ctext))
        hmac = bytearray(HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest())
        expmac = hmac[:cls.macsize]
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum('ciphertext integrity failure')
        # Discard the confounder.
        return bytes(basic_plaintext[cls.blocksize:])

    @classmethod
    def prf(cls, key, string):
        # Hash the input.  RFC 3961 says to truncate to the padding
        # size, but implementations truncate to the block size.
        hashval = cls.hashmod.new(string).digest()
        truncated = hashval[:-(len(hashval) % cls.blocksize)]
        # Encrypt the hash with a derived key.
        kp = cls.derive(key, b'prf')
        return cls.basic_encrypt(kp, truncated)

class _DESCBC(_SimplifiedEnctype):
    enctype = Enctype.DES_MD5
    keysize = 8
    seedsize = 8
    blocksize = 8
    padsize = 8
    macsize = 16
    hashmod = MD5

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        if confounder is None:
            confounder = get_random_bytes(cls.blocksize)
        basic_plaintext = confounder + b'\x00'*cls.macsize + _zeropad(plaintext, cls.padsize)
        checksum = cls.hashmod.new(basic_plaintext).digest()
        basic_plaintext = basic_plaintext[:len(confounder)] + checksum + basic_plaintext[len(confounder)+len(checksum):]
        return cls.basic_encrypt(key, basic_plaintext)
        
        
    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError('ciphertext too short')
        
        complex_plaintext = cls.basic_decrypt(key, ciphertext)
        cofounder = complex_plaintext[:cls.padsize]
        mac = complex_plaintext[cls.padsize:cls.padsize+cls.macsize]
        message = complex_plaintext[cls.padsize+cls.macsize:]
        
        expmac = cls.hashmod.new(cofounder+b'\x00'*cls.macsize+message).digest()
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum('ciphertext integrity failure')
        return bytes(message)
    
    @classmethod
    def mit_des_string_to_key(cls,string,salt):
    
        def fixparity(deskey):
            temp = b''
            for i in range(len(deskey)):
                t = (bin(indexbytes(deskey,i))[2:]).rjust(8,'0')
                if t[:7].count('1') %2 == 0:
                    temp+= b(chr(int(t[:7]+'1',2)))
                else:
                    temp+= b(chr(int(t[:7]+'0',2)))
            return temp
    
        def addparity(l1):
            temp = list()
            for byte in l1:
                if (bin(byte).count('1') % 2) == 0:
                    byte = (byte << 1)|0b00000001
                else:
                    byte = (byte << 1)&0b11111110
                temp.append(byte)
            return temp
        
        def XOR(l1,l2):
            temp = list()
            for b1,b2 in zip(l1,l2):
                temp.append((b1^b2)&0b01111111)
            
            return temp
        
        odd = True
        tempstring = [0,0,0,0,0,0,0,0]
        s = _zeropad(string + salt, cls.padsize)

        for block in [s[i:i+8] for i in range(0, len(s), 8)]:
            temp56 = list()
            #removeMSBits
            for byte in block:
                if PY3:
                    temp56.append(byte&0b01111111)
                else:
                    temp56.append(ord(byte)&0b01111111)
            
            #reverse
            if odd is False:
                bintemp = b''
                for byte in temp56:
                    bintemp += b(bin(byte)[2:].rjust(7,'0'))
                bintemp = bintemp[::-1]
                
                temp56 = list()
                for bits7 in [bintemp[i:i+7] for i in range(0, len(bintemp), 7)]:
                    temp56.append(int(bits7,2))

            odd = not odd
                
            tempstring = XOR(tempstring,temp56)
        
        tempkey = ''.join(chr(byte) for byte in addparity(tempstring))
        if _is_weak_des_key(tempkey):
            tempkey[7] = chr(ord(tempkey[7]) ^ 0xF0)

        cipher = DES.new(b(tempkey), DES.MODE_CBC, b(tempkey))
        checksumkey = cipher.encrypt(s)[-8:]
        checksumkey = fixparity(checksumkey)
        if _is_weak_des_key(checksumkey):
            checksumkey[7] = chr(ord(checksumkey[7]) ^ 0xF0)
        
        return Key(cls.enctype, checksumkey)

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) % 8 == 0
        des = DES.new(key.contents, DES.MODE_CBC, b'\0' * 8)
        return des.encrypt(bytes(plaintext))

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) % 8 == 0
        des = DES.new(key.contents, DES.MODE_CBC, b'\0' * 8)
        return des.decrypt(bytes(ciphertext))
    
    @classmethod
    def string_to_key(cls, string, salt, params):
        if params is not None and params != b'':
            raise ValueError('Invalid DES string-to-key parameters')
        if not isinstance(string, binary_type):
            string = string.encode("utf-8")
        if not isinstance(salt, binary_type):
            salt = salt.encode("utf-8")

        key = cls.mit_des_string_to_key(string, salt)
        return key
    
    

class _DES3CBC(_SimplifiedEnctype):
    enctype = Enctype.DES3
    keysize = 24
    seedsize = 21
    blocksize = 8
    padsize = 8
    macsize = 20
    hashmod = SHA1

    @classmethod
    def random_to_key(cls, seed):
        # XXX Maybe reframe as _DESEnctype.random_to_key and use that
        # way from DES3 random-to-key when DES is implemented, since
        # MIT does this instead of the RFC 3961 random-to-key.
        def expand(seed):
            def parity(b):
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                return b if bin(b & ~1).count('1') % 2 else b | 1
            assert len(seed) == 7
            firstbytes = [parity(b & ~1) for b in seed]
            lastbyte = parity(sum((seed[i]&1) << i+1 for i in range(7)))
            keybytes= bytearray(firstbytes + [lastbyte])
            if _is_weak_des_key(keybytes):
                keybytes[7] = keybytes[7] ^ 0xF0
            return bytes(keybytes)

        seed = bytearray(seed)
        if len(seed) != 21:
            raise ValueError('Wrong seed length')
        k1, k2, k3 = expand(seed[:7]), expand(seed[7:14]), expand(seed[14:])
        return Key(cls.enctype, k1 + k2 + k3)

    @classmethod
    def string_to_key(cls, string, salt, params):
        if params is not None and params != b'':
            raise ValueError('Invalid DES3 string-to-key parameters')
        if not isinstance(string, binary_type):
            string = string.encode("utf-8")
        if not isinstance(salt, binary_type):
            salt = salt.encode("utf-8")

        k = cls.random_to_key(_nfold(string + salt, 21))
        return cls.derive(k, b'kerberos')

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) % 8 == 0
        des3 = DES3.new(key.contents, AES.MODE_CBC, b'\0' * 8)
        return des3.encrypt(bytes(plaintext))

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) % 8 == 0
        des3 = DES3.new(key.contents, AES.MODE_CBC, b'\0' * 8)
        return des3.decrypt(bytes(ciphertext))


def basic_decrypt_all_aes(cls, key, ciphertext, iv):
    bs = cls.blocksize
    assert len(ciphertext) >= bs
    aes = AES.new(key.contents, AES.MODE_ECB)
    if len(ciphertext) == bs:
        return aes.decrypt(ciphertext)
    # Split the ciphertext into blocks.  The last block may be partial.
    cblocks = [bytearray(ciphertext[p:p+bs]) for p in range(0, len(ciphertext), bs)]
    lastlen = len(cblocks[-1])
    # CBC-decrypt all but the last two blocks.
    prev_cblock = bytearray(iv)
    plaintext = b''
    for bb in cblocks[:-2]:
        plaintext += _xorbytes(bytearray(aes.decrypt(bytes(bb))), prev_cblock)
        prev_cblock = bb
    # Decrypt the second-to-last cipher block.  The left side of
    # the decrypted block will be the final block of plaintext
    # xor'd with the final partial cipher block; the right side
    # will be the omitted bytes of ciphertext from the final
    # block.
    bb = bytearray(aes.decrypt(bytes(cblocks[-2])))
    lastplaintext =_xorbytes(bb[:lastlen], cblocks[-1])
    omitted = bb[lastlen:]
    # Decrypt the final cipher block plus the omitted bytes to get
    # the second-to-last plaintext block.
    plaintext += _xorbytes(bytearray(aes.decrypt(bytes(cblocks[-1]) + bytes(omitted))), prev_cblock)
    return plaintext + lastplaintext

def basic_encrypt_all_aes(cls, key, plaintext, iv):
    bs = cls.blocksize
    assert len(plaintext) >= bs
    aes = AES.new(key.contents, AES.MODE_CBC, iv)
    ctext = aes.encrypt(_zeropad(bytes(plaintext), bs))
    if len(plaintext) > bs:
        # Swap the last two ciphertext blocks and truncate the
        # final block to match the plaintext length.
        lastlen = len(plaintext) % bs or bs
        ctext = ctext[:-(bs*2)] + ctext[-bs:] + ctext[-(bs*2):-bs][:lastlen]
    return ctext


class _AES_SHA1_Enctype(_SimplifiedEnctype):
    # Base class for aes128-cts and aes256-cts.
    blocksize = 16
    padsize = 1
    macsize = 12
    hashmod = SHA1

    @classmethod
    def string_to_key(cls, string, salt, params):
        if not isinstance(string, binary_type):
            string = string.encode("utf-8")
        if not isinstance(salt, binary_type):
            salt = salt.encode("utf-8")

        (iterations,) = unpack('>L', params or b'\x00\x00\x10\x00')
        prf = lambda p, s: HMAC.new(p, s, SHA1).digest()
        seed = PBKDF2(string, salt, cls.seedsize, iterations, prf)
        tkey = cls.random_to_key(seed)
        return cls.derive(tkey, b'kerberos')

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        iv = bytes(cls.blocksize)
        return basic_encrypt_all_aes(cls, key, plaintext, iv)

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        iv = bytes(cls.blocksize)
        return basic_decrypt_all_aes(cls, key, ciphertext, iv)


class _AES128_SHA1_CTS(_AES_SHA1_Enctype):
    enctype = Enctype.AES128_SHA1
    keysize = 16
    seedsize = 16


class _AES256_SHA1_CTS(_AES_SHA1_Enctype):
    enctype = Enctype.AES256_SHA1
    keysize = 32
    seedsize = 32


class _RFC8009_Enctype(_EnctypeProfile):
    # Base class for aes128-cts-hmac-sha256-128 and aes256-cts-hmac-sha384-192.
    blocksize    = 128 // 8  # Cipher block size
    seedsize     = None      # PRF output size
    keysize      = None      # Encryption key size
    macsize      = None      # Integrity key size
    hashmod      = None      # Hash function module
    enctype_name = None      # Encryption type name as byte string

    @classmethod
    def random_to_key(cls, seed):
        return Key(cls.enctype, seed)

    @classmethod
    def basic_encrypt(cls, key, plaintext, iv):
        return basic_encrypt_all_aes(cls, key, plaintext, iv)

    @classmethod
    def basic_decrypt(cls, key, ciphertext, iv):
        return basic_decrypt_all_aes(cls, key, ciphertext, iv)

    @classmethod
    def kdf_hmac_sha2(cls, key, label, k, context=b''):
        hmac_sha2 = lambda p, s: HMAC.new(p, s, cls.hashmod).digest()
        return SP800_108_Counter(master=key, key_len=k, prf=hmac_sha2, label=label, context=context)

    @classmethod
    def derive(cls, key, constant):
        return cls.random_to_key(cls.kdf_hmac_sha2(key=key.contents, label=constant, k=cls.macsize))

    @classmethod
    def prf(cls, input_key, string):
        return cls.kdf_hmac_sha2(key=input_key.contents, label=b'prf',
                                 k=cls.seedsize, context=string)

    @classmethod
    def string_to_key(cls, string, salt, params):
        if not isinstance(string, binary_type):
            string = string.encode("utf-8")
        if not isinstance(salt, binary_type):
            salt = salt.encode("utf-8")

        saltp = cls.enctype_name + b'\0' + salt

        iter_count = unpack('>L', params)[0] if params else 32768
        tkey = PBKDF2(password=string, salt=saltp, count=iter_count, dkLen=cls.keysize, hmac_hash_module=cls.hashmod)
        return cls.random_to_key(cls.kdf_hmac_sha2(key=tkey, label=b'kerberos', k=cls.keysize))


    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ke = cls.random_to_key(cls.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0xAA), cls.keysize))
        ki = cls.random_to_key(cls.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0x55), cls.macsize))
        n = get_random_bytes(cls.blocksize)
        # Initial cipher state is a zeroed buffer
        iv = bytes(cls.blocksize)
        c = cls.basic_encrypt(ke, n + plaintext, iv)
        h = HMAC.new(ki.contents, iv + c, cls.hashmod).digest()
        ciphertext = c + h[:cls.macsize]
        assert(plaintext == cls.decrypt(key, keyusage, ciphertext))
        return ciphertext

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if not isinstance(ciphertext, binary_type):
            ciphertext = bytes(ciphertext)
        ke = cls.random_to_key(cls.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0xAA), cls.keysize))
        ki = cls.random_to_key(cls.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0x55), cls.macsize))
        c = ciphertext[:-cls.macsize]
        h = ciphertext[-cls.macsize:]
        # Initial cipher state is a zeroed buffer
        iv = bytes(cls.blocksize)
        if h != HMAC.new(ki.contents, iv + c, cls.hashmod).digest()[:cls.macsize]:
            raise InvalidChecksum('ciphertext integrity failure')
        plaintext = cls.basic_decrypt(ke, c, iv)[cls.blocksize:]
        return plaintext


class _AES128_SHA256_CTS(_RFC8009_Enctype):
    enctype  = Enctype.AES128_SHA256
    seedsize = 256 // 8
    macsize  = 128 // 8
    keysize  = 128 // 8
    hashmod  = SHA256
    enctype_name = b'aes128-cts-hmac-sha256-128'


class _AES256_SHA384_CTS(_RFC8009_Enctype):
    enctype  = Enctype.AES256_SHA384
    seedsize = 384 // 8
    macsize  = 192 // 8
    keysize  = 256 // 8
    hashmod  = SHA384
    enctype_name = b'aes256-cts-hmac-sha384-192'


class _RC4(_EnctypeProfile):
    enctype = Enctype.RC4
    keysize = 16
    seedsize = 16

    @staticmethod
    def usage_str(keyusage):
        # Return a four-byte string for an RFC 3961 keyusage, using
        # the RFC 4757 rules.  Per the errata, do not map 9 to 8.
        table = {3: 8, 23: 13}
        msusage = table[keyusage] if keyusage in table else keyusage
        return pack('<I', msusage)

    @classmethod
    def string_to_key(cls, string, salt, params):
        utf16string = string.encode('UTF-16LE')
        return Key(cls.enctype, MD4.new(utf16string).digest())

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        if confounder is None:
            confounder = get_random_bytes(8)
        ki = HMAC.new(key.contents, cls.usage_str(keyusage), MD5).digest()
        cksum = HMAC.new(ki, confounder + plaintext, MD5).digest()
        ke = HMAC.new(ki, cksum, MD5).digest()
        return cksum + ARC4.new(ke).encrypt(bytes(confounder + plaintext))

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if len(ciphertext) < 24:
            raise ValueError('ciphertext too short')
        cksum, basic_ctext = bytearray(ciphertext[:16]), bytearray(ciphertext[16:])
        ki = HMAC.new(key.contents, cls.usage_str(keyusage), MD5).digest()
        ke = HMAC.new(ki, cksum, MD5).digest()
        basic_plaintext = bytearray(ARC4.new(ke).decrypt(bytes(basic_ctext)))
        exp_cksum = bytearray(HMAC.new(ki, basic_plaintext, MD5).digest())
        ok = _mac_equal(cksum, exp_cksum)
        if not ok and keyusage == 9:
            # Try again with usage 8, due to RFC 4757 errata.
            ki = HMAC.new(key.contents, pack('<I', 8), MD5).digest()
            exp_cksum = HMAC.new(ki, basic_plaintext, MD5).digest()
            ok = _mac_equal(cksum, exp_cksum)
        if not ok:
            raise InvalidChecksum('ciphertext integrity failure')
        # Discard the confounder.
        return bytes(basic_plaintext[8:])

    @classmethod
    def prf(cls, key, string):
        return HMAC.new(key.contents, bytes(string), SHA1).digest()


class _ChecksumProfile(object):
    # Base class for checksum profiles.  Usable checksum classes must
    # define:
    #   * checksum
    #   * verify (if verification is not just checksum-and-compare)
    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        expected = cls.checksum(key, keyusage, text)
        if not _mac_equal(bytearray(cksum), bytearray(expected)):
            raise InvalidChecksum('checksum verification failure')


class _SimplifiedChecksum(_ChecksumProfile):
    # Base class for checksums using the RFC 3961 simplified profile.
    # Defines the checksum and verify methods.  Subclasses must
    # define:
    #   * macsize: Size of checksum in bytes
    #   * enc: Profile of associated enctype

    @classmethod
    def checksum(cls, key, keyusage, text):
        kc = cls.enc.derive(key, pack('>IB', keyusage, 0x99))
        hmac = HMAC.new(kc.contents, text, cls.enc.hashmod).digest()
        return hmac[:cls.macsize]

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != cls.enc.enctype:
            raise ValueError('Wrong key type for checksum')
        super(_SimplifiedChecksum, cls).verify(key, keyusage, text, cksum)


class _SHA256AES128(_SimplifiedChecksum):
    macsize = _AES128_SHA256_CTS.macsize
    enc = _AES128_SHA256_CTS


class _SHA384AES256(_SimplifiedChecksum):
    macsize = _AES256_SHA384_CTS.macsize
    enc = _AES256_SHA384_CTS


class _SHA1AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128_SHA1_CTS


class _SHA1AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256_SHA1_CTS


class _SHA1DES3(_SimplifiedChecksum):
    macsize = 20
    enc = _DES3CBC


class _HMACMD5(_ChecksumProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        ksign = HMAC.new(key.contents, b'signaturekey\0', MD5).digest()
        md5hash = MD5.new(_RC4.usage_str(keyusage) + text).digest()
        return HMAC.new(ksign, md5hash, MD5).digest()

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != Enctype.RC4:
            raise ValueError('Wrong key type for checksum')
        super(_HMACMD5, cls).verify(key, keyusage, text, cksum)


_enctype_table = {
    Enctype.DES_MD5: _DESCBC,
    Enctype.DES3: _DES3CBC,
    Enctype.AES128_SHA1: _AES128_SHA1_CTS,
    Enctype.AES256_SHA1: _AES256_SHA1_CTS,
    Enctype.RC4: _RC4,
    Enctype.AES128_SHA256: _AES128_SHA256_CTS,
    Enctype.AES256_SHA384: _AES256_SHA384_CTS
}


_checksum_table = {
    Cksumtype.SHA1_DES3: _SHA1DES3,
    Cksumtype.SHA1_AES128: _SHA1AES128,
    Cksumtype.SHA1_AES256: _SHA1AES256,
    Cksumtype.HMAC_MD5: _HMACMD5,
    0xffffff76: _HMACMD5,
    Cksumtype.SHA256_AES128: _SHA256AES128,
    Cksumtype.SHA384_AES256: _SHA384AES256
}


def _get_enctype_profile(enctype):
    if enctype not in _enctype_table:
        raise ValueError('Invalid enctype %d' % enctype)
    return _enctype_table[enctype]


def _get_checksum_profile(cksumtype):
    if cksumtype not in _checksum_table:
        raise ValueError('Invalid cksumtype %d' % cksumtype)
    return _checksum_table[cksumtype]


class Key(object):
    def __init__(self, enctype, contents):
        e = _get_enctype_profile(enctype)
        if len(contents) != e.keysize and len(contents) != e.macsize:
            raise ValueError('Wrong key length')
        self.enctype = enctype
        self.contents = contents


def random_to_key(enctype, seed):
    e = _get_enctype_profile(enctype)
    if len(seed) != e.seedsize:
        raise ValueError('Wrong crypto seed length')
    return e.random_to_key(seed)


def string_to_key(enctype, string, salt, params=None):
    e = _get_enctype_profile(enctype)
    return e.string_to_key(string, salt, params)


def encrypt(key, keyusage, plaintext, confounder=None):
    e = _get_enctype_profile(key.enctype)
    return e.encrypt(key, keyusage, bytes(plaintext), bytes(confounder))


def decrypt(key, keyusage, ciphertext):
    # Throw InvalidChecksum on checksum failure.  Throw ValueError on
    # invalid key enctype or malformed ciphertext.
    e = _get_enctype_profile(key.enctype)
    return e.decrypt(key, keyusage, ciphertext)


def prf(key, string):
    e = _get_enctype_profile(key.enctype)
    return e.prf(key, string)


def make_checksum(cksumtype, key, keyusage, text):
    c = _get_checksum_profile(cksumtype)
    return c.checksum(key, keyusage, text)


def verify_checksum(cksumtype, key, keyusage, text, cksum):
    # Throw InvalidChecksum exception on checksum failure.  Throw
    # ValueError on invalid cksumtype, invalid key enctype, or
    # malformed checksum.
    c = _get_checksum_profile(cksumtype)
    c.verify(key, keyusage, text, cksum)


def cf2(enctype, key1, key2, pepper1, pepper2):
    # Combine two keys and two pepper strings to produce a result key
    # of type enctype, using the RFC 6113 KRB-FX-CF2 function.
    def prfplus(key, pepper, l):
        # Produce l bytes of output using the RFC 6113 PRF+ function.
        out = b''
        count = 1
        while len(out) < l:
            out += prf(key, b(chr(count)) + pepper)
            count += 1
        return out[:l]

    e = _get_enctype_profile(enctype)
    return e.random_to_key(_xorbytes(bytearray(prfplus(key1, pepper1, e.seedsize)),
                                     bytearray(prfplus(key2, pepper2, e.seedsize))))
