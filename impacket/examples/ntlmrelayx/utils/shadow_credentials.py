from struct import pack
from Cryptodome.Util.number import long_to_bytes
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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Cryptodome.IO import PEM
from cryptography.hazmat.primitives.serialization import pkcs12

def getTicksNow():
    # https://learn.microsoft.com/en-us/dotnet/api/system.datetime.ticks?view=net-5.0#system-datetime-ticks
    dt_now = datetime.datetime.now(datetime.timezone.utc)
    csharp_epoch = datetime.datetime(year=1601, month=1, day=1,tzinfo=datetime.timezone.utc)
    delta = dt_now - csharp_epoch
    return int(delta.total_seconds() * 10000000) # Convert to microseconds and multiply by 10 for ticks

def getDeviceId():
    return uuid.uuid4().bytes

def createSelfSignedX509Certificate(subject,kSize=2048):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=kSize,
        backend=None  # Use default backend    
    )

    subject_name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    
    cert = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        subject_name
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(days=1)
    ).not_valid_after(
        now + datetime.timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(key, hashes.SHA256()
    )

    return key,cert

class KeyCredential():
    @staticmethod
    def raw_public_key(public_key):

        kSize = pack("<I",public_key.key_size)
        exponent = long_to_bytes(public_key.public_key().public_numbers().e)
        exponentSize = pack("<I",len(exponent))
        modulus = long_to_bytes(public_key.public_key().public_numbers().n)
        modulusSize = pack("<I",len(modulus))

        padding = pack("<I",0)*2

        return b'RSA1' + kSize + exponentSize + modulusSize + padding + exponent + modulus

    def __init__(self,key,deviceId,currentTime):
        self.__publicKey = self.raw_public_key(key)
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

    def __getKeyHash(self,binaryProperties):
        computed_hash = hashlib.sha256(binaryProperties).digest()
        return (0x2,computed_hash)

    def dumpBinary(self):
        version = pack("<L",self.__version)

        binaryProperties = self.__packData( [self.__rawKeyMaterial,
                            self.__usage,
                            self.__source,
                            self.__deviceId,
                            self.__customKeyInfo,
                            self.__lastLogonTime,
                            self.__creationTime,
                         ])

        binaryData = self.__packData( [self.__getKeyIdentifier(),
                                        self.__getKeyHash(binaryProperties),
                                      ])

        return version + binaryData + binaryProperties


def toDNWithBinary2String( binaryData, owner ):
    hexdata = binascii.hexlify(binaryData).decode("UTF-8")
    return "B:%d:%s:%s" % (len(binaryData)*2,hexdata,owner)

def exportPFX(certificate,key,path_to_file,password):
    if len(os.path.dirname(path_to_file)) != 0:
        if not os.path.exists(os.path.dirname(path_to_file)):
            os.makedirs(os.path.dirname(path_to_file), exist_ok=True)

    # Export private key and certificate in PKCS#12 format using cryptography
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"",
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    with open(path_to_file + ".pfx", "wb") as f:
        f.write(pfx_data)


def exportPEM(certificate,key, path_to_files):
    if len(os.path.dirname(path_to_files)) != 0:
        if not os.path.exists(os.path.dirname(path_to_files)):
            os.makedirs(os.path.dirname(path_to_files), exist_ok=True)

    # Export certificate in PEM format 
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    with open(path_to_files + "_cert.pem", "wb") as f:
        f.write(cert_pem)

    # Export private key in PEM format 
    privpem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(path_to_files + "_priv.pem", "wb") as f:
        f.write(privpem)

