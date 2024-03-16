import OpenSSL
from Cryptodome.PublicKey import RSA
import struct
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import hashlib
import base64
import binascii
import random
import datetime
import time
import os

def raw_public_key( modulus,exponent,keySize,prime1,prime2 ):
    b_blobType = b'RSA1'
    b_keySize = struct.pack('<I', keySize)

    b_exponent = long_to_bytes(exponent)
    b_exponentSize = struct.pack('<I', len(b_exponent))

    b_modulus = long_to_bytes(modulus)
    b_modulusSize = struct.pack('<I', len(b_modulus))

    if prime1 == 0:
        b_prime1Size = struct.pack('<I', 0)
    else:
        b_prime1 = long_to_bytes(prime1)
        b_prime1Size = struct.pack('<I', len(b_prime1))

    if prime2 == 0:
        b_prime2Size = struct.pack('<I', 0)
    else:
        b_prime2 = long_to_bytes(prime2)
        b_prime2Size = struct.pack('<I', len(b_prime2))

    # Header
    data = b_blobType
    # Header
    data += b_keySize
    data += b_exponentSize + b_modulusSize + b_prime1Size + b_prime2Size
    # Content
    data += b_exponent + b_modulus
    if prime1 != 0:
        data += b_prime1
    if prime2 != 0:
        data += b_prime2
    return data

def createX509Certificate( subject,keySize,notBefore,notAfter ):
    # create rsa key pair object
    key = OpenSSL.crypto.PKey()
    # generate key pair or 2048 of length
    key.generate_key(OpenSSL.crypto.TYPE_RSA, keySize)
    # create x509 certificate object
    certificate = OpenSSL.crypto.X509()

    # set cert params
    certificate.get_subject().CN = subject
    certificate.set_issuer(certificate.get_subject())
    # Validity
    certificate.gmtime_adj_notBefore(notBefore * 24 * 60 * 60)
    certificate.gmtime_adj_notAfter(notAfter * 24 * 60 * 60)

    certificate.set_pubkey(key)

    # self-sign certificate with SHA256 digest and PKCS1 padding scheme
    certificate.sign(key, "sha256")

    pem_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, key)
    pubkey = RSA.importKey(pem_key)
    publicKey = raw_public_key(
        modulus=pubkey.n,
        exponent=pubkey.e,
        keySize=pubkey.size_in_bits(),
        prime1=0,
        prime2=0
    )
    return certificate,publicKey,key

def getRandomGUID():
    a = sum([random.randint(0, 0xff) << (8*k) for k in range(4)])
    b = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
    c = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
    d = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
    e = sum([random.randint(0, 0xff) << (8*k) for k in range(6)])

    data = b''
    data += struct.pack("<L", a)
    data += struct.pack("<H", b)
    data += struct.pack("<H", c)
    data += struct.pack(">H", d)
    data += binascii.unhexlify(hex(e)[2:].rjust(12, '0'))
    return data

def getTimeTicks():
    Value = datetime.datetime.now()
    # diff 1601 - epoch
    diff = datetime.datetime(1970, 1, 1, 0, 0, 0) - datetime.datetime(1601, 1, 1, 0, 0, 0)
    # nanoseconds between 1601 and epoch
    diff_ns = int(diff.total_seconds()) * 1000000000
    # nanoseconds between epoch and now
    now_ns = time.time_ns()
    # ticks between 1601 and now
    ticks = (diff_ns + now_ns) // 100
    return ticks


def getBinaryTime( timestamp_ticks ):
    return struct.pack('<Q', timestamp_ticks)

def toDNWithBinary2String( binaryData, owner ):
    hexdata = binascii.hexlify(binaryData).decode("UTF-8")
    return "B:%d:%s:%s" % (len(binaryData)*2,hexdata,owner)


def CreateKeyCredentialFromX509Certificate(publicKey,deviceId,owner,currentTime,isComputerKey=False):

    # Process owner DN/UPN
    print("onwer %s" % str(owner))
    assert (len(owner) != 0)
    if type(owner) == str:
        Owner = owner
    elif type(owner) == bytes:
        Owner = owner.decode("UTF-8")

    Version = 0x00000200 #version2

    sha256 = hashlib.sha256(publicKey)

    Identifier = base64.b64encode(sha256.digest()).decode("utf-8")

    KeyHash = None
    if currentTime is not None:
        CreationTime = currentTime

    RawKeyMaterial = publicKey
    Usage = 0x01
    LegacyUsage = None
    Source = 0x00
    DeviceId = deviceId
    computed_hash = "\x00"*16
    # Computer NGC keys have to meet some requirements to pass the validated write
    # The CustomKeyInformation entry is not present.
    # The KeyApproximateLastLogonTimeStamp entry is not present.

    if not isComputerKey:
        LastLogonTime = CreationTime
        CustomKeyInfo = CustomKeyInformation(0x0)

    # Serialize properties 3-9 first, as property 2 must contain their hash:
    binaryData = b""
    binaryProperties = b""

    # Key Material
    _data = RawKeyMaterial
    binaryProperties += struct.pack("<H", len(_data))
    binaryProperties += struct.pack("<B", 0x03)
    binaryProperties += _data

    # Key Usage
    _data = None
    if LegacyUsage is not None and Usage is None:
        _data = LegacyUsage
    elif Usage is not None and LegacyUsage is None:
        _data = struct.pack("<B", Usage)
    binaryProperties += struct.pack("<H", len(_data))
    binaryProperties += struct.pack("<B", 0x04)
    binaryProperties += _data

    # Key Source
    _data = struct.pack("<B", Source)
    binaryProperties += struct.pack("<H", len(_data))
    binaryProperties += struct.pack("<B", 0x05)
    binaryProperties += _data

    # Device ID
    if DeviceId is not None:
        _data = DeviceId
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B",0x06)
        binaryProperties += _data

    # Custom Key Information
    if CustomKeyInfo is not None:
        _data = CustomKeyInfo
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B",0x07)
        binaryProperties += _data

    # Last Logon Time
    if LastLogonTime is not None:
        _data = getBinaryTime(LastLogonTime)
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B",0x08)
        binaryProperties += _data

    # Creation Time
    _data = getBinaryTime(CreationTime)
    binaryProperties += struct.pack("<H", len(_data))
    binaryProperties += struct.pack("<B",0x09)
    binaryProperties += _data

    # Version
    binaryData += struct.pack('<L',0x00000200)

    # Key Identifier
    _data = base64.b64decode( Identifier + "===")
    binaryData += struct.pack("<H", len(_data))
    binaryData += struct.pack("<B",0x01)
    binaryData += _data

    # Key Hash
    computed_hash = hashlib.sha256(_data).digest()
    binaryData += struct.pack("<H", len(computed_hash))
    binaryData += struct.pack("<B",0x02)
    binaryData += computed_hash

    # Append the remaining entries
    binaryData += binaryProperties

    return binaryData



def CustomKeyInformation(flags):
    stream_data = b""
    stream_data += struct.pack("<B",0x1)
    stream_data += struct.pack("<B",flags)

    return stream_data

def exportPFX(certificate,key,path_to_file,password):
    if len(os.path.dirname(path_to_file)) != 0:
        if not os.path.exists(os.path.dirname(path_to_file)):
            os.makedirs(os.path.dirname(path_to_file), exist_ok=True)

    pk = OpenSSL.crypto.PKCS12()
    pk.set_privatekey(key)
    pk.set_certificate(certificate)
    with open(path_to_file+".pfx","wb") as f:
        f.write(pk.export(passphrase=password))


def exportPEM(certificate,key, path_to_files):
    if len(os.path.dirname(path_to_files)) != 0:
        if not os.path.exists(os.path.dirname(path_to_files)):
            os.makedirs(os.path.dirname(path_to_files), exist_ok=True)

        cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        with open(path_to_files + "_cert.pem", "wb") as f:
            f.write(cert)
        privpem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        with open(path_to_files + "_priv.pem", "wb") as f:
            f.write(privpem)

