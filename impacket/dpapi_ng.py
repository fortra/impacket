# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import math
import struct
from impacket.dcerpc.v5.gkdi import ECDHKey, FFCDHKey, GroupKeyEnvelope
from impacket.ldap.ldaptypes import ACE, ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, SR_SECURITY_DESCRIPTOR, LDAP_SID
from impacket.structure import Structure
from Cryptodome.Hash import SHA512, SHA256, HMAC
from Cryptodome.Util.number import long_to_bytes
from Cryptodome.Util.py3compat import iter_range
from Cryptodome.Cipher import AES

KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")
KEK_PUBLIC_KEY_LABEL = "KDS public key\0".encode("utf-16le")

def SP800_108_Counter(master, key_len, prf, num_keys=None, label=b'', context=b''):
    """Derive one or more keys from a master secret using
    a pseudorandom function in Counter Mode, as specified in
    `NIST SP 800-108r1 <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf>`_.

    Modified version for Impacket, accepting null_bytes

    Args:
     master (byte string):
        The secret value used by the KDF to derive the other keys.
        It must not be a password.
        The length on the secret must be consistent with the input expected by
        the :data:`prf` function.
     key_len (integer):
        The length in bytes of each derived key.
     prf (function):
        A pseudorandom function that takes two byte strings as parameters:
        the secret and an input. It returns another byte string.
     num_keys (integer):
        The number of keys to derive. Every key is :data:`key_len` bytes long.
        By default, only 1 key is derived.
     label (byte string):
        Optional description of the purpose of the derived keys.
        It must not contain zero bytes.
     context (byte string):
        Optional information pertaining to
        the protocol that uses the keys, such as the identity of the
        participants, nonces, session IDs, etc.
        It must not contain zero bytes.

    Return:
        - a byte string (if ``num_keys`` is not specified), or
        - a tuple of byte strings (if ``num_key`` is specified).
    """

    if num_keys is None:
        num_keys = 1

    key_len_enc = long_to_bytes(key_len * num_keys * 8, 4)
    output_len = key_len * num_keys

    i = 1
    dk = b""
    while len(dk) < output_len:
        info = long_to_bytes(i, 4) + label + b'\x00' + context + key_len_enc
        dk += prf(master, info)
        i += 1
        if i > 0xFFFFFFFF:
            raise ValueError("Overflow in SP800 108 counter")

    if num_keys == 1:
        return dk[:key_len]
    else:
        kol = [dk[idx:idx + key_len]
               for idx in iter_range(0, output_len, key_len)]
        return kol

class KeyIdentifier(Structure):
    structure = (
        ('Version', '<L=0'),
        ('Magic', '<L=0'),
        ('Flags', '<L=0'),
        ('L0Index', '<L=0'),
        ('L1Index', '<L=0'),
        ('L2Index', '<L=0'),
        ('RootKeyId', '16s=b'),
        ('UnknownLength', '<L=0'),
        ('DomainLength', '<L=0'),
        ('ForestLength', '<L=0'),
        ('_Unknown','_-Unknown', 'self["UnknownLength"]'),
        ('Unknown',':'),
        ('_Domain','_-Domain', 'self["DomainLength"]'),
        ('Domain',':'),
        ('_Forest','_-Forest', 'self["ForestLength"]'),
        ('Forest',':'),
    )

    def dump(self):
        print("[KEY IDENTIFIER]")
        print("Version:\t\t%s" % (self['Version']))
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("Flags:\t\t%s" % (self['Flags']))
        print("L0Index:\t\t%s" % (self['L0Index']))
        print("L1Index:\t\t%s" % (self['L1Index']))
        print("L2Index:\t\t%s" % (self['L2Index']))
        print("RootKeyId:\t\t%s" % (self['RootKeyId']))
        print("Unknown:\t\t%s" % (self['Unknown']))
        print("Domain:\t\t%s" % (self['Domain'].decode('utf-16le')))
        print("Forest:\t\t%s" % (self['Forest'].decode('utf-16le')))
        print()
    
    def is_public_key(self) -> bool:
        return bool(self['Flags'] & 1)
    
class EncryptedPasswordBlob(Structure):
    structure = (
        ('Timestamp_lower', '<L=0'),
        ('Timestamp_upper', '<L=0'),
        ('Length', '<L=0'),
        ('Flags', '<L=0'),
        ('_Blob','_-Blob', 'self["Length"]'),
        ('Blob',':')
    )

    def dump(self):
        print("[ENCRYPTED PASSWORD BLOB]")
        print("Timestamp_upper:\t\t%s" % (self['Timestamp_upper']))
        print("Timestamp_lower:\t\t%s" % (self['Timestamp_lower']))
        print("Update Timestamp:\t\t%s" % ((int(self['Timestamp_upper']) << 32) | self['Timestamp_lower']))
        print("Length:\t\t%s" % (self['Length']))
        print("Flags:\t\t%s" % (self['Flags']))
        print("Blob:\t\t%s" % (self['Blob']))
        print()

def int_to_u32be(n: int) -> bytes:
    return n.to_bytes(length=4, byteorder="big")

def create_ace(sid, mask):
    nace = ACE()
    nace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = mask
    acedata['Sid'] = LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_sd(sid):
    sd = SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-18')
    sd['GroupSid'] = LDAP_SID()
    sd['GroupSid'].fromCanonical('S-1-5-18')
    sd['Sacl'] = b''

    acl = ACL()
    acl['AclRevision'] = 2
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    acl.aces.append(create_ace(sid, 3))
    acl.aces.append(create_ace('S-1-1-0',2))
    sd['Dacl'] = acl
    return sd

def compute_kdf_hash(length, key_material, otherinfo):
    output = [b""]
    outlen = 0
    counter = 1

    while length > outlen:
        hash_module = SHA256.SHA256Hash()
        hash_module.update(data = int_to_u32be(counter))
        hash_module.update(key_material)
        hash_module.update(otherinfo)
        output.append(hash_module.digest())
        outlen += len(output[-1])
        counter += 1

    return b"".join(output)[:length]

def compute_kdf_context(key_guid, l0, l1, l2):
    return b"".join(
            [
                key_guid,
                l0.to_bytes(4, byteorder="little", signed=True),
                l1.to_bytes(4, byteorder="little", signed=True),
                l2.to_bytes(4, byteorder="little", signed=True),
            ]
        )

def kdf(hash_alg_str, secret, label, context, length):
    hash_alg = SHA512
    if 'SHA512' in hash_alg_str:
        hash_alg = SHA512
    elif 'SHA256' in hash_alg_str:
        hash_alg = SHA256

    def prf(s,x):
        return HMAC.new(s,x,hash_alg).digest()

    return SP800_108_Counter(
        master=secret,
        prf=prf,
        key_len=length,
        label=label,
        context=context
    )

def compute_l2_key(key_id: KeyIdentifier, gke: GroupKeyEnvelope):
    l1 = gke["L1Index"]
    l1_key = gke["L1Key"]
    l2 = gke["L2Index"]
    l2_key = gke["L2Key"]

    reseed_l2 = l2 == 31 or l1 != key_id["L1Index"]

    kdf_param = gke["KdfPara"]["HashName"].decode('utf-16le')

    if l2 != 31 and l1 != key_id["L1Index"]:
        l1 -= 1

    while l1 != key_id["L1Index"]:
        reseed_l2 = True
        l1 -= 1

        l1_key = kdf(
            kdf_param,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                gke["RootKeyId"],
                gke["L0Index"],
                l1,
                -1
            ),
            64
        )
    
    if reseed_l2:
        l2 = 31
        l2_key = kdf(
            kdf_param,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                gke["RootKeyId"],
                gke["L0Index"],
                l1,
                l2,
            ),
            64,
        )
    
    while l2 != key_id["L2Index"]:
        l2 -= 1

        l2_key = kdf(
            kdf_param,
            l2_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                gke["RootKeyId"],
                gke["L0Index"],
                l1,
                l2,
            ),
            64,
        )

    return l2_key

def generate_kek_secret_from_pubkey(gke: GroupKeyEnvelope, key_id: KeyIdentifier,l2_key: bytes):
    private_key = kdf(
        gke["KdfPara"]["HashName"].decode('utf-16le'),
        l2_key,
        KDS_SERVICE_LABEL,
        gke['SecAlgo'],
        math.ceil(gke["PrivKeyLength"] / 8),
    )
    if gke['SecAlgo'].decode('utf-16le').encode() == b"DH\0":
        ffcdh_key = FFCDHKey(key_id["Unknown"])
        shared_secret_int = pow(
            int.from_bytes(ffcdh_key['PubKey'], byteorder="big"),
            int.from_bytes(private_key, byteorder="big"),
            int.from_bytes(ffcdh_key['FieldOrder'], byteorder="big"),
        )
        shared_secret = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder="big")
    elif "ECDH_P" in gke['SecAlgo'].decode('utf-16le'):
        ecdh_key = ECDHKey(key_id["Unknown"])
        # not yet supported
        return
    kek_context = "KDS public key\0".encode("utf-16le")
    otherinfo = "SHA512\0".encode("utf-16le") + kek_context + KDS_SERVICE_LABEL
    return compute_kdf_hash(length=32, otherinfo=otherinfo, key_material=shared_secret), kek_context
    
def compute_kek(gke: GroupKeyEnvelope, key_id: KeyIdentifier):
    kek_context = None
    kek_secret = None

    l2_key = compute_l2_key(key_id, gke)

    if key_id.is_public_key():
        kek_secret, kek_context = generate_kek_secret_from_pubkey(gke=gke, key_id=key_id, l2_key=l2_key)
    else:
        kek_secret = l2_key
        kek_context = key_id["Unknown"]
        
    return kdf(
        gke["KdfPara"]["HashName"].decode('utf-16le'),
        kek_secret,
        KDS_SERVICE_LABEL,
        kek_context,
        32
    )

def aes_unwrap(wrapping_key: bytes, wrapped_key: bytes):
    aiv = b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6"
    r = [wrapped_key[i : i + 8] for i in range(0, len(wrapped_key), 8)]
    a = r.pop(0)
    decryptor = AES.new(wrapping_key, AES.MODE_ECB)
    n = len(r)
    for j in reversed(range(6)):
        for i in reversed(range(n)):
            atr = (
                int.from_bytes(a, byteorder="big") ^ ((n * j) + i + 1)
            ).to_bytes(length=8, byteorder="big") + r[i]
            # every decryption operation is a discrete 16 byte chunk so
            # it is safe to reuse the decryptor for the entire operation
            b = decryptor.decrypt(atr)
            # b = decryptor.update(atr)
            a = b[:8]
            r[i] = b[-8:]
    if a == aiv:
        return b"".join(r)
    else:
        return None

def unwrap_cek(kek, encrypted_cek):
    r = aes_unwrap(kek, encrypted_cek)
    if r is None:
        raise ValueError("Could not unwrap key")
    return r

def decrypt_plaintext(cek, iv, encrypted_blob):
    cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt(encrypted_blob)