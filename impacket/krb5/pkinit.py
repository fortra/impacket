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
#   PKINIT client implementation, as defined by:
#     * RFC 4556 - Public Key Cryptography for Initial Authentication in Kerberos
#     * RFC 5349 - Elliptic Curve Cryptography (ECC) support for PKINIT
#     * RFC 4557 - Online Certificate Status Protocol (OCSP) support for PKINIT
#
#   Both AS reply key delivery methods are implemented: the Diffie-Hellman key
#   agreement method (RFC 4556 3.2.3.1, MODP and, per RFC 5349, ECDH) and the
#   public key encryption method (RFC 4556 3.2.3.2).
#
#   The TGT obtained here is a regular TGT: the reply key is derived from the
#   certificate exchange itself.
#
# Author:
#  Giovanni A. (@azoxlpf)
#
import datetime
import os
from binascii import hexlify
from hashlib import sha1, sha256, sha384, sha512

from Cryptodome.Cipher import AES, DES3
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import tag, univ
from pyasn1_modules import rfc3279, rfc5280, rfc5652

from impacket import LOG
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP, AS_REQ, AuthPack, EncASRepPart, KDCDHKeyInfo, KERB_PA_PAC_REQUEST, \
    KRB5PrincipalName, METHOD_DATA, PA_PK_AS_REP, PA_PK_AS_REQ, PKOcspData, ReplyKeyPack, \
    TD_DH_PARAMETERS, TYPED_DATA, seq_set, seq_set_iter
from impacket.krb5.crypto import Cksumtype, Enctype, InvalidChecksum, Key, _enctype_table, verify_checksum
from impacket.krb5.types import KerberosTime, Principal

# PKINIT object identifiers (RFC 4556, Appendix A)
ID_PKINIT_AUTHDATA = '1.3.6.1.5.2.3.1'
ID_PKINIT_DHKEYDATA = '1.3.6.1.5.2.3.2'
ID_PKINIT_RKEYDATA = '1.3.6.1.5.2.3.3'
ID_PKINIT_KP_CLIENTAUTH = '1.3.6.1.5.2.3.4'
ID_PKINIT_KP_KDC = '1.3.6.1.5.2.3.5'
ID_PKINIT_SAN = '1.3.6.1.5.2.2'

# Microsoft extensions (RFC 4556 Appendix C), what Windows issues instead of the PKINIT EKU and SAN
ID_MS_KP_SC_LOGON = '1.3.6.1.4.1.311.20.2.2'
ID_MS_SAN_SC_LOGON_UPN = '1.3.6.1.4.1.311.20.2.3'
ID_KP_SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
ID_KP_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'

# CMS (RFC 5652) and PKCS#9 object identifiers
ID_DATA = '1.2.840.113549.1.7.1'
ID_SIGNED_DATA = '1.2.840.113549.1.7.2'
ID_ENVELOPED_DATA = '1.2.840.113549.1.7.3'
ID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
ID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'

# Algorithm identifiers (RFC 3279, RFC 5349, RFC 3370)
ID_DH_PUBLIC_NUMBER = '1.2.840.10046.2.1'
ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
ID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
ID_RSAES_OAEP = '1.2.840.113549.1.1.7'
ID_DES_EDE3_CBC = '1.2.840.113549.3.7'
ID_AES128_CBC = '2.16.840.1.101.3.4.1.2'
ID_AES192_CBC = '2.16.840.1.101.3.4.1.22'
ID_AES256_CBC = '2.16.840.1.101.3.4.1.42'

DIGEST_ALGORITHMS = {
    'sha1': ('1.3.14.3.2.26', '1.2.840.113549.1.1.5', '1.2.840.10045.4.1', sha1, hashes.SHA1),
    'sha256': ('2.16.840.1.101.3.4.2.1', '1.2.840.113549.1.1.11', '1.2.840.10045.4.3.2', sha256, hashes.SHA256),
    'sha384': ('2.16.840.1.101.3.4.2.2', '1.2.840.113549.1.1.12', '1.2.840.10045.4.3.3', sha384, hashes.SHA384),
    'sha512': ('2.16.840.1.101.3.4.2.3', '1.2.840.113549.1.1.13', '1.2.840.10045.4.3.4', sha512, hashes.SHA512),
}

DIGEST_OIDS = {values[0]: name for name, values in DIGEST_ALGORITHMS.items()}
SIGNATURE_OIDS = {}
for name, values in DIGEST_ALGORITHMS.items():
    SIGNATURE_OIDS[values[1]] = name
    SIGNATURE_OIDS[values[2]] = name
SIGNATURE_OIDS[ID_RSA_ENCRYPTION] = None  # digest carried by digestAlgorithm

# MODP groups usable for the Diffie-Hellman key agreement method (RFC 4556 3.2.1), as (prime, generator)
DH_GROUPS = {
    2: (int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF', 16), 2),
    5: (int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF', 16), 2),
    14: (int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
        '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16), 2),
    15: (int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
        '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33'
        'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864'
        'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2'
        '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF', 16), 2),
    16: (int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
        '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33'
        'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864'
        'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2'
        '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'
        '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8'
        'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2'
        '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'
        '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF', 16), 2),
}

EC_CURVES = {
    'P-256': ec.SECP256R1,
    'P-384': ec.SECP384R1,
    'P-521': ec.SECP521R1,
}

EC_CURVE_OIDS = {
    '1.2.840.10045.3.1.7': 'P-256',  # secp256r1
    '1.3.132.0.34': 'P-384',  # secp384r1
    '1.3.132.0.35': 'P-521',  # secp521r1
}

# Checksum required for the enctype of the reply key, to verify a ReplyKeyPack asChecksum (RFC 4556 3.2.3.2)
CHECKSUM_FOR_ENCTYPE = {
    Enctype.DES3: Cksumtype.SHA1_DES3,
    Enctype.AES128: Cksumtype.SHA1_AES128,
    Enctype.AES256: Cksumtype.SHA1_AES256,
    Enctype.RC4: Cksumtype.HMAC_MD5,
}

KEY_USAGE_AS_REQ_CHECKSUM = 6


class PKINITError(Exception):
    pass


class KDCCertificateError(PKINITError):
    pass


# Malformed input does not consistently raise PyAsn1Error: pyasn1 lets plain builtin errors through
PARSE_ERRORS = (PyAsn1Error, x509.InvalidVersion, x509.DuplicateExtension, x509.UnsupportedGeneralNameType,
                UnsupportedAlgorithm, KeyError, IndexError, TypeError, ValueError)


def decodeASN1(data, asn1Spec, description):
    try:
        return decoder.decode(data, asn1Spec=asn1Spec)[0]
    except PARSE_ERRORS as e:
        raise PKINITError('Could not parse the %s the KDC sent: %s' % (description, e))


def readCertificateFields(certificate):
    return (certificate.subject.rfc4514_string(), certificate.issuer.public_bytes(), certificate.serial_number,
            certificate.public_key(), certificate.signature_hash_algorithm, len(certificate.extensions),
            getCertificateValidity(certificate))


def loadCertificate(component, description):
    try:
        certificate = x509.load_der_x509_certificate(encoder.encode(component))
        readCertificateFields(certificate)
        return certificate
    except PARSE_ERRORS as e:
        raise PKINITError('Could not parse a certificate of the %s: %s' % (description, e))


def getPublicKey(certificate):
    try:
        return certificate.public_key()
    except PARSE_ERRORS as e:
        raise PKINITError('Could not read the public key of "%s": %s' % (getCertificateName(certificate), e))


def getCipher(enctype, description):
    try:
        return _enctype_table[enctype]
    except KeyError:
        raise PKINITError('The KDC used the unsupported encryption type %d for the %s' % (enctype, description))


def octetstring2key(x, cipher):
    """Derive an AS reply key from an octet string, as defined in RFC 4556 3.2.3.1.

    octetstring2key(x) == random-to-key(K-truncate(SHA1(0x00 | x) | SHA1(0x01 | x) | ...))
    """
    seed = b''
    counter = 0
    while len(seed) < cipher.seedsize:
        seed += sha1(bytes([counter]) + x).digest()
        counter += 1
    return cipher.random_to_key(seed[:cipher.seedsize])


class DiffieHellman:
    """MODP Diffie-Hellman key agreement (RFC 4556 3.2.3.1)."""

    def __init__(self, group=14, prime=None, generator=2):
        if prime is None:
            if group not in DH_GROUPS:
                raise PKINITError('Unsupported Diffie-Hellman group %s' % group)
            prime, generator = DH_GROUPS[group]
        self.group = group
        self.prime = prime
        self.generator = generator
        self.modulusSize = (prime.bit_length() + 7) // 8
        # RFC 4556 3.2.1: the exponent needs at least twice as many bits as the 256 bit reply key
        self.privateKey = int.from_bytes(os.urandom(self.modulusSize), 'big') % (prime - 2) + 1
        self.publicKey = pow(generator, self.privateKey, prime)

    def getSharedSecret(self, peerPublicKey):
        if peerPublicKey <= 1 or peerPublicKey >= self.prime - 1:
            raise PKINITError('KDC returned an invalid Diffie-Hellman public value')
        shared = pow(peerPublicKey, self.privateKey, self.prime)
        if shared <= 1:
            raise PKINITError('Degenerate Diffie-Hellman shared secret')
        # RFC 4556 3.2.3.1: DHSharedSecret is padded with leading zeros up to the modulus size
        return shared.to_bytes(self.modulusSize, 'big')

    def getSubjectPublicKeyInfo(self):
        parameters = rfc3279.DomainParameters()
        parameters['p'] = self.prime
        parameters['g'] = self.generator
        parameters['q'] = (self.prime - 1) // 2  # safe prime

        algorithm = rfc5280.AlgorithmIdentifier()
        algorithm['algorithm'] = univ.ObjectIdentifier(ID_DH_PUBLIC_NUMBER)
        algorithm['parameters'] = univ.Any(encoder.encode(parameters))

        publicKeyInfo = rfc5280.SubjectPublicKeyInfo()
        publicKeyInfo['algorithm'] = algorithm
        # RFC 3279 2.3.3: the public value is the DER encoding of an INTEGER
        publicKeyInfo['subjectPublicKey'] = derToBitString(encoder.encode(univ.Integer(self.publicKey)))
        return publicKeyInfo

    def getPeerPublicKey(self, bitString):
        return int(decodeASN1(bitString.asOctets(), univ.Integer(), 'Diffie-Hellman public value'))


class EllipticCurveDiffieHellman:
    """ECDH key agreement, as defined in RFC 5349 4."""

    def __init__(self, curve='P-256'):
        if curve not in EC_CURVES:
            raise PKINITError('Unsupported elliptic curve %s' % curve)
        self.curve = curve
        self.privateKey = ec.generate_private_key(EC_CURVES[curve]())

    def getSharedSecret(self, peerPublicKey):
        # RFC 5349 4: the shared secret is the x coordinate of the point, which is what exchange() returns
        return self.privateKey.exchange(ec.ECDH(), peerPublicKey)

    def getSubjectPublicKeyInfo(self):
        publicKeyInfo = decoder.decode(
            self.privateKey.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo),
            asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]
        return publicKeyInfo

    def getPeerPublicKey(self, bitString):
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(EC_CURVES[self.curve](), bitString.asOctets())
        except ValueError as e:
            raise PKINITError('The KDC returned an invalid %s public value: %s' % (self.curve, e))


def derToBitString(data):
    return univ.BitString(hexValue=hexlify(data).decode('ascii'))


def getReqBodyBytes(reqBody):
    """Return the DER encoding of the KDC-REQ-BODY itself."""
    encoded = encoder.encode(reqBody)
    lengthOctet = encoded[1]
    if lengthOctet & 0x80:
        return encoded[2 + (lengthOctet & 0x7F):]
    return encoded[2:]


def buildAlgorithmIdentifier(oid, parameters=None):
    algorithm = rfc5280.AlgorithmIdentifier()
    algorithm['algorithm'] = univ.ObjectIdentifier(oid)
    if parameters is not None:
        algorithm['parameters'] = univ.Any(parameters)
    return algorithm


def buildDigestAlgorithm(digest):
    oid = DIGEST_ALGORITHMS[digest][0]
    # RFC 5754 2: SHA-2 identifiers have absent parameters, SHA-1 ones are commonly emitted with a NULL
    if digest == 'sha1':
        return buildAlgorithmIdentifier(oid, encoder.encode(univ.Null('')))
    return buildAlgorithmIdentifier(oid)


def buildAttribute(oid, value):
    attribute = rfc5652.Attribute()
    attribute['attrType'] = univ.ObjectIdentifier(oid)
    seq_set_iter(attribute, 'attrValues', (univ.Any(value),))
    return attribute


def getSignatureAlgorithm(privateKey, digest):
    rsaOid, ecdsaOid = DIGEST_ALGORITHMS[digest][1:3]
    if isinstance(privateKey, rsa.RSAPrivateKey):
        # RFC 3279 2.2.1: the parameters of an RSA signature algorithm are NULL
        return buildAlgorithmIdentifier(rsaOid, encoder.encode(univ.Null('')))
    if isinstance(privateKey, ec.EllipticCurvePrivateKey):
        # RFC 5758 3.2: ECDSA algorithm identifiers have absent parameters
        return buildAlgorithmIdentifier(ecdsaOid)
    raise PKINITError('Unsupported private key type %s' % type(privateKey).__name__)


def signData(privateKey, data, digest):
    hashAlgorithm = DIGEST_ALGORITHMS[digest][4]()
    if isinstance(privateKey, rsa.RSAPrivateKey):
        return privateKey.sign(data, padding.PKCS1v15(), hashAlgorithm)
    if isinstance(privateKey, ec.EllipticCurvePrivateKey):
        return privateKey.sign(data, ec.ECDSA(hashAlgorithm))
    raise PKINITError('Unsupported private key type %s' % type(privateKey).__name__)


def verifySignature(publicKey, signature, data, digest):
    if isinstance(publicKey, ed25519.Ed25519PublicKey):
        publicKey.verify(signature, data)
        return
    verifyRawSignature(publicKey, signature, data, DIGEST_ALGORITHMS[digest][4]())


def verifyRawSignature(publicKey, signature, data, hashAlgorithm):
    if isinstance(publicKey, rsa.RSAPublicKey):
        publicKey.verify(signature, data, padding.PKCS1v15(), hashAlgorithm)
    elif isinstance(publicKey, ec.EllipticCurvePublicKey):
        publicKey.verify(signature, data, ec.ECDSA(hashAlgorithm))
    else:
        raise PKINITError('Unsupported public key type %s' % type(publicKey).__name__)


def buildSignedData(privateKey, certificate, chain, contentType, content, digest):
    """Build the CMS ContentInfo/SignedData wrapping content (RFC 4556 3.2.1)."""
    digestAlgorithm = buildDigestAlgorithm(digest)
    hashFunction = DIGEST_ALGORITHMS[digest][3]

    # Built with the [0] IMPLICIT tag of the SignerInfo, subtyping a filled value would drop its components
    signedAttributes = rfc5652.SignedAttributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    signedAttributes.setComponentByPosition(0, buildAttribute(
        ID_CONTENT_TYPE, encoder.encode(univ.ObjectIdentifier(contentType))))
    signedAttributes.setComponentByPosition(1, buildAttribute(
        ID_MESSAGE_DIGEST, encoder.encode(univ.OctetString(hashFunction(content).digest()))))

    signerInfo = rfc5652.SignerInfo()
    signerInfo['version'] = 1  # issuerAndSerialNumber
    signerInfo['sid'] = buildSignerIdentifier(certificate)
    signerInfo['digestAlgorithm'] = digestAlgorithm
    signerInfo['signedAttrs'] = signedAttributes
    signerInfo['signatureAlgorithm'] = getSignatureAlgorithm(privateKey, digest)
    signerInfo['signature'] = signData(privateKey, getSignedAttributesBytes(signedAttributes), digest)

    signedData = rfc5652.SignedData()
    signedData['version'] = 3
    signedData['digestAlgorithms'].setComponentByPosition(0, digestAlgorithm)
    signedData['encapContentInfo']['eContentType'] = univ.ObjectIdentifier(contentType)
    signedData['encapContentInfo']['eContent'] = content
    signedData['certificates'] = buildCertificateSet([certificate] + list(chain))
    signedData['signerInfos'].setComponentByPosition(0, signerInfo)

    return buildContentInfo(ID_SIGNED_DATA, encoder.encode(signedData))


def buildContentInfo(contentType, content):
    contentInfo = rfc5652.ContentInfo()
    contentInfo['contentType'] = univ.ObjectIdentifier(contentType)
    contentInfo['content'] = univ.Any(content).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    return encoder.encode(contentInfo)


def buildSignerIdentifier(certificate):
    issuerAndSerial = rfc5652.IssuerAndSerialNumber()
    issuerAndSerial['issuer'] = decoder.decode(certificate.issuer.public_bytes(),
                                               asn1Spec=rfc5280.Name())[0]
    issuerAndSerial['serialNumber'] = certificate.serial_number

    signerIdentifier = rfc5652.SignerIdentifier()
    signerIdentifier['issuerAndSerialNumber'] = issuerAndSerial
    return signerIdentifier


def buildCertificateSet(certificates):
    certificateSet = rfc5652.CertificateSet().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    for position, certificate in enumerate(certificates):
        choice = rfc5652.CertificateChoices()
        choice['certificate'] = decoder.decode(certificate.public_bytes(serialization.Encoding.DER),
                                               asn1Spec=rfc5280.Certificate())[0]
        certificateSet.setComponentByPosition(position, choice)
    return certificateSet


def getSignedAttributesBytes(signedAttributes):
    encoded = encoder.encode(signedAttributes)
    # Only the identifier octet differs between the stored [0] IMPLICIT encoding and the signed SET OF
    return b'\x31' + encoded[1:]


def getAttributeValue(signedAttributes, oid):
    for attribute in signedAttributes:
        if str(attribute['attrType']) == oid and len(attribute['attrValues']):
            return attribute['attrValues'][0].asOctets()
    return None


def parseSignedData(data, expectedContentType):
    """Decode a CMS ContentInfo/SignedData and return (content, signerInfo, certificates)."""
    contentInfo = decodeASN1(data, rfc5652.ContentInfo(), 'CMS ContentInfo')
    if str(contentInfo['contentType']) != ID_SIGNED_DATA:
        raise PKINITError('Expected a CMS SignedData, got content type %s' % contentInfo['contentType'])

    signedData = decodeASN1(bytes(contentInfo['content']), rfc5652.SignedData(), 'CMS SignedData')
    contentType = str(signedData['encapContentInfo']['eContentType'])
    if contentType != expectedContentType:
        raise PKINITError('Unexpected eContentType %s, expected %s' % (contentType, expectedContentType))

    if not signedData['encapContentInfo']['eContent'].hasValue():
        raise PKINITError('The SignedData carries no content')
    content = signedData['encapContentInfo']['eContent'].asOctets()

    certificates = []
    if signedData['certificates'].hasValue():
        for choice in signedData['certificates']:
            if choice.getName() != 'certificate':
                continue
            certificates.append(loadCertificate(choice.getComponent(), 'SignedData'))

    if len(signedData['signerInfos']) != 1:
        raise PKINITError('Expected a single signerInfo, got %d' % len(signedData['signerInfos']))

    return content, signedData['signerInfos'][0], certificates


def findSignerCertificate(signerInfo, certificates):
    signerIdentifier = signerInfo['sid']
    if signerIdentifier.getName() == 'issuerAndSerialNumber':
        issuerAndSerial = signerIdentifier.getComponent()
        issuer = encoder.encode(issuerAndSerial['issuer'])
        serialNumber = int(issuerAndSerial['serialNumber'])
        for certificate in certificates:
            if certificate.serial_number == serialNumber and certificate.issuer.public_bytes() == issuer:
                return certificate
        raise PKINITError('The signer certificate is not part of the SignedData')

    keyIdentifier = bytes(signerIdentifier.getComponent())
    for certificate in certificates:
        extension = getExtension(certificate, x509.SubjectKeyIdentifier)
        if extension is not None and extension.digest == keyIdentifier:
            return certificate
    raise PKINITError('The signer certificate is not part of the SignedData')


def verifySignedData(data, expectedContentType):
    """Verify a CMS SignedData signature and return (content, signer certificate, certificates)."""
    content, signerInfo, certificates = parseSignedData(data, expectedContentType)
    certificate = findSignerCertificate(signerInfo, certificates)

    signatureOid = str(signerInfo['signatureAlgorithm']['algorithm'])
    if signatureOid not in SIGNATURE_OIDS:
        raise PKINITError('Unsupported signature algorithm %s' % signatureOid)
    digest = SIGNATURE_OIDS[signatureOid]
    if digest is None:
        digestOid = str(signerInfo['digestAlgorithm']['algorithm'])
        if digestOid not in DIGEST_OIDS:
            raise PKINITError('Unsupported digest algorithm %s' % digestOid)
        digest = DIGEST_OIDS[digestOid]

    # RFC 4556 3.2.3.1: signed attributes are mandatory here, so the signature always covers them
    if not signerInfo['signedAttrs'].hasValue():
        raise PKINITError('The SignedData carries no signed attributes')

    contentTypeAttribute = getAttributeValue(signerInfo['signedAttrs'], ID_CONTENT_TYPE)
    if contentTypeAttribute is None:
        raise PKINITError('The content-type signed attribute is missing')
    contentType = str(decodeASN1(contentTypeAttribute, univ.ObjectIdentifier(), 'content-type attribute'))
    if contentType != expectedContentType:
        raise PKINITError('The content-type signed attribute is %s, expected %s'
                          % (contentType, expectedContentType))

    messageDigest = getAttributeValue(signerInfo['signedAttrs'], ID_MESSAGE_DIGEST)
    if messageDigest is None:
        raise PKINITError('The message-digest signed attribute is missing')
    messageDigest = decodeASN1(messageDigest, univ.OctetString(), 'message-digest attribute').asOctets()
    if messageDigest != DIGEST_ALGORITHMS[digest][3](content).digest():
        raise PKINITError('The message-digest signed attribute does not match the signed content')

    signature = signerInfo['signature'].asOctets()
    try:
        verifySignature(getPublicKey(certificate), signature, getSignedAttributesBytes(signerInfo['signedAttrs']),
                        digest)
    except InvalidSignature:
        raise PKINITError('The signature of "%s" over the SignedData is invalid'
                          % getCertificateName(certificate))
    return content, certificate, certificates


def getCertificateValidity(certificate):
    try:
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    except AttributeError:
        return (certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc),
                certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc))


def getRevocationTime(ocspResponse):
    try:
        return ocspResponse.revocation_time_utc
    except AttributeError:
        return ocspResponse.revocation_time


def getOCSPValidity(ocspResponse):
    try:
        return ocspResponse.this_update_utc, ocspResponse.next_update_utc
    except AttributeError:
        nextUpdate = ocspResponse.next_update
        return (ocspResponse.this_update.replace(tzinfo=datetime.timezone.utc),
                nextUpdate.replace(tzinfo=datetime.timezone.utc) if nextUpdate is not None else None)


def findOCSPResponder(ocspResponse, certificates):
    candidates = list(ocspResponse.certificates) + list(certificates)
    for candidate in candidates:
        if ocspResponse.responder_name is not None and candidate.subject == ocspResponse.responder_name:
            return candidate
        if ocspResponse.responder_key_hash is not None:
            extension = getExtension(candidate, x509.SubjectKeyIdentifier)
            if extension is not None and extension.digest == ocspResponse.responder_key_hash:
                return candidate
    return None


def isSignedBy(certificate, issuer):
    try:
        verifyCertificateSignature(certificate, issuer)
    except KDCCertificateError:
        return False
    return True


def verifyOCSPResponse(ocspResponse, certificate, certificates):
    """Check that an OCSP response is a fresh, authoritative answer about certificate."""
    candidates = list(ocspResponse.certificates) + list(certificates)
    responder = findOCSPResponder(ocspResponse, candidates)
    if responder is None:
        raise PKINITError('The certificate of the OCSP responder is unknown')

    if ID_KP_OCSP_SIGNING in getExtendedKeyUsage(responder):
        authoritative = any(isSignedBy(responder, issuer) and isSignedBy(certificate, issuer)
                            for issuer in candidates)
    else:
        authoritative = isSignedBy(certificate, responder)
    if not authoritative:
        raise PKINITError('The OCSP responder "%s" is not authoritative for "%s"'
                          % (getCertificateName(responder), getCertificateName(certificate)))

    try:
        verifyRawSignature(getPublicKey(responder), ocspResponse.signature, ocspResponse.tbs_response_bytes,
                           ocspResponse.signature_hash_algorithm)
    except (InvalidSignature, PKINITError, ValueError, TypeError) as e:
        raise PKINITError('Invalid signature on the OCSP response: %s' % e)

    now = datetime.datetime.now(datetime.timezone.utc)
    thisUpdate, nextUpdate = getOCSPValidity(ocspResponse)
    if nextUpdate is not None and nextUpdate < now:
        raise PKINITError('The OCSP response expired on %s' % nextUpdate)
    if thisUpdate > now + datetime.timedelta(minutes=5):
        raise PKINITError('The OCSP response is not valid before %s' % thisUpdate)


def getExtension(certificate, extensionClass):
    """Return an extension of a certificate, or None if it has none of that class."""
    try:
        return certificate.extensions.get_extension_for_class(extensionClass).value
    except x509.ExtensionNotFound:
        return None
    except PARSE_ERRORS as e:
        raise PKINITError('Could not read the extensions of a certificate: %s' % e)


def getExtendedKeyUsage(certificate):
    extension = getExtension(certificate, x509.ExtendedKeyUsage)
    if extension is None:
        return []
    return [usage.dotted_string for usage in extension]


def getKeyUsage(certificate):
    return getExtension(certificate, x509.KeyUsage)


def getOtherNames(certificate, oid):
    extension = getExtension(certificate, x509.SubjectAlternativeName)
    if extension is None:
        return []
    return [name.value for name in extension.get_values_for_type(x509.OtherName)
            if name.type_id.dotted_string == oid]


def getDNSNames(certificate):
    extension = getExtension(certificate, x509.SubjectAlternativeName)
    if extension is None:
        return []
    return extension.get_values_for_type(x509.DNSName)


def getKerberosPrincipals(certificate):
    principals = []
    for value in getOtherNames(certificate, ID_PKINIT_SAN):
        principalName = decodeASN1(value, KRB5PrincipalName(), 'id-pkinit-san of a certificate')
        components = [str(component) for component in principalName['principalName']['name-string']]
        principals.append('%s@%s' % ('/'.join(components), principalName['realm']))
    return principals


def getUPNs(certificate):
    upns = []
    for value in getOtherNames(certificate, ID_MS_SAN_SC_LOGON_UPN):
        upns.append(str(decodeASN1(value, None, 'UPN of a certificate')))
    return upns


def getCertificateName(certificate):
    subject = certificate.subject.rfc4514_string()
    if subject:
        return subject
    for name in getKerberosPrincipals(certificate) + getDNSNames(certificate) + getUPNs(certificate):
        return name
    return 'serial number %d' % certificate.serial_number


def verifyCertificateAuthority(certificate, pathLength):
    """Check the RFC 5280 6.1.4 constraints an issuing certificate must satisfy."""
    constraints = getExtension(certificate, x509.BasicConstraints)
    if constraints is None:
        raise KDCCertificateError('Certificate "%s" signed another certificate without a basicConstraints extension'
                                  % getCertificateName(certificate))
    if not constraints.ca:
        raise KDCCertificateError('Certificate "%s" is not a CA but signed another certificate'
                                  % getCertificateName(certificate))
    if constraints.path_length is not None and constraints.path_length < pathLength:
        raise KDCCertificateError('Certificate "%s" allows %d intermediate certificates below it, the path has %d'
                                  % (getCertificateName(certificate), constraints.path_length, pathLength))
    keyUsage = getKeyUsage(certificate)
    if keyUsage is not None and not keyUsage.key_cert_sign:
        raise KDCCertificateError('Certificate "%s" is not allowed to sign certificates by its key usage'
                                  % getCertificateName(certificate))


def verifyCertificateChain(certificate, intermediates, anchors):
    """Walk the certification path from certificate up to one of the trust anchors."""
    now = datetime.datetime.now(datetime.timezone.utc)
    current = certificate
    pathLength = 0
    for _ in range(len(intermediates) + len(anchors) + 1):
        notBefore, notAfter = getCertificateValidity(current)
        if not notBefore <= now <= notAfter:
            raise KDCCertificateError('Certificate "%s" is not valid at this time' % getCertificateName(current))

        issuers = [anchor for anchor in anchors if anchor.subject == current.issuer]
        if issuers:
            verifyCertificateAuthority(issuers[0], pathLength)
            verifyCertificateSignature(current, issuers[0])
            return
        issuers = [intermediate for intermediate in intermediates if intermediate.subject == current.issuer]
        if not issuers:
            raise KDCCertificateError('Cannot build a certification path for "%s", issuer "%s" is unknown'
                                      % (getCertificateName(current), current.issuer.rfc4514_string()))
        verifyCertificateAuthority(issuers[0], pathLength)
        verifyCertificateSignature(current, issuers[0])
        current = issuers[0]
        pathLength += 1
    raise KDCCertificateError('Certification path for "%s" is looping' % getCertificateName(certificate))


def verifyCertificateSignature(certificate, issuer):
    try:
        verifyRawSignature(getPublicKey(issuer), certificate.signature, certificate.tbs_certificate_bytes,
                           certificate.signature_hash_algorithm)
    except (InvalidSignature, PKINITError, ValueError, TypeError) as e:
        raise KDCCertificateError('Invalid signature on certificate "%s": %s'
                                  % (getCertificateName(certificate), e))


def verifyKDCCertificate(certificate, certificates, realm, anchors=None):
    """Apply the KDC certificate checks of RFC 4556 3.2.4."""
    
    # RFC 4556 3.2.4: digitalSignature must be asserted, this certificate is what signs the reply
    keyUsage = getKeyUsage(certificate)
    if keyUsage is not None and not keyUsage.digital_signature:
        raise KDCCertificateError('The KDC certificate is not allowed to sign by its key usage')

    expected = 'krbtgt/%s@%s' % (realm.upper(), realm.upper())
    principals = getKerberosPrincipals(certificate)
    if principals:
        if expected not in principals:
            raise KDCCertificateError('The KDC certificate is bound to %s, expected %s'
                                      % (', '.join(principals), expected))
    else:
        usages = getExtendedKeyUsage(certificate)
        if ID_PKINIT_KP_KDC not in usages and ID_MS_KP_SC_LOGON not in usages and ID_KP_SERVER_AUTH not in usages:
            raise KDCCertificateError('The KDC certificate has neither an id-pkinit-san SAN nor a KDC extended key '
                                      'usage, it cannot be verified to belong to a KDC of %s' % realm.upper())
        LOG.debug('KDC certificate has no id-pkinit-san SAN, accepted on its extended key usage (%s)'
                  % ', '.join(usages))

    if not anchors:
        # Without an anchor only the binding between the signature and the reply key is verified
        LOG.debug('No trusted CA certificate given, skipping the KDC certification path validation')
        return

    intermediates = [candidate for candidate in certificates if candidate != certificate]
    verifyCertificateChain(certificate, intermediates, anchors)


def decryptEnvelopedData(data, privateKey):
    """Decrypt a CMS EnvelopedData addressed to privateKey (RFC 4556 3.2.3.2)."""
    contentInfo = decodeASN1(data, rfc5652.ContentInfo(), 'CMS ContentInfo')
    if str(contentInfo['contentType']) != ID_ENVELOPED_DATA:
        raise PKINITError('Expected a CMS EnvelopedData, got content type %s' % contentInfo['contentType'])

    envelopedData = decodeASN1(bytes(contentInfo['content']), rfc5652.EnvelopedData(), 'CMS EnvelopedData')
    if len(envelopedData['recipientInfos']) != 1:
        raise PKINITError('Expected a single recipientInfo, got %d' % len(envelopedData['recipientInfos']))
    if envelopedData['recipientInfos'][0].getName() != 'ktri':
        raise PKINITError('The EnvelopedData does not hold a KeyTransRecipientInfo')
    recipientInfo = envelopedData['recipientInfos'][0].getComponent()

    if not isinstance(privateKey, rsa.RSAPrivateKey):
        raise PKINITError('The public key encryption method requires an RSA private key')

    keyEncryptionOid = str(recipientInfo['keyEncryptionAlgorithm']['algorithm'])
    if keyEncryptionOid == ID_RSA_ENCRYPTION:
        keyPadding = padding.PKCS1v15()
    elif keyEncryptionOid == ID_RSAES_OAEP:
        keyPadding = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    else:
        raise PKINITError('Unsupported key transport algorithm %s' % keyEncryptionOid)

    try:
        contentEncryptionKey = privateKey.decrypt(recipientInfo['encryptedKey'].asOctets(), keyPadding)
    except ValueError as e:
        raise PKINITError('Could not decrypt the content encryption key with our private key: %s' % e)

    encryptedContentInfo = envelopedData['encryptedContentInfo']
    algorithm = encryptedContentInfo['contentEncryptionAlgorithm']
    initializationVector = decodeASN1(bytes(algorithm['parameters']), univ.OctetString(),
                                      'content encryption parameters').asOctets()
    if not encryptedContentInfo['encryptedContent'].hasValue():
        raise PKINITError('The EnvelopedData carries no encrypted content')
    encryptedContent = encryptedContentInfo['encryptedContent'].asOctets()

    contentEncryptionOid = str(algorithm['algorithm'])
    if contentEncryptionOid not in (ID_DES_EDE3_CBC, ID_AES128_CBC, ID_AES192_CBC, ID_AES256_CBC):
        raise PKINITError('Unsupported content encryption algorithm %s' % contentEncryptionOid)

    # Key, IV and content length all come from the KDC, a mismatch with the announced algorithm is its fault
    try:
        if contentEncryptionOid == ID_DES_EDE3_CBC:
            cipher = DES3.new(contentEncryptionKey, DES3.MODE_CBC, initializationVector)
        else:
            cipher = AES.new(contentEncryptionKey, AES.MODE_CBC, initializationVector)
        content = cipher.decrypt(encryptedContent)
    except ValueError as e:
        raise PKINITError('Could not decrypt the enveloped content: %s' % e)

    if not content:
        raise PKINITError('The enveloped content is empty')
    paddingLength = content[-1]
    if paddingLength < 1 or paddingLength > len(content):
        raise PKINITError('Invalid padding in the encrypted content')
    return content[:-paddingLength]


class PKINITCredentials:
    """A client certificate and its private key, used to authenticate through PKINIT.

    keyExchange selects the AS reply key delivery method: 'dh' for the MODP
    Diffie-Hellman method (RFC 4556 3.2.3.1), 'ecdh' for its elliptic curve
    variant (RFC 5349) and 'rsa' for the public key encryption method
    (RFC 4556 3.2.3.2).
    """

    def __init__(self, privateKey, certificate, chain=None, keyExchange='dh', dhGroup=14, curve='P-256',
                 digest='sha256', trustedCAs=None, verifyKDC=True, requestOCSP=False, requireOCSP=False):
        if keyExchange not in ('dh', 'ecdh', 'rsa'):
            raise PKINITError('Unknown key exchange method %s' % keyExchange)
        if digest not in DIGEST_ALGORITHMS:
            raise PKINITError('Unknown digest algorithm %s' % digest)

        self.privateKey = privateKey
        self.certificate = certificate
        # RFC 4556 3.2.1: the certificates field must not carry root CA certificates
        self.chain = [candidate for candidate in (chain or []) if candidate.subject != candidate.issuer]
        self.keyExchange = keyExchange
        self.dhGroup = dhGroup
        self.curve = curve
        self.digest = digest
        self.trustedCAs = trustedCAs or []
        self.verifyKDC = verifyKDC
        # RFC 4557 3: requiring a response only makes sense if one is asked for
        self.requestOCSP = requestOCSP or requireOCSP
        self.requireOCSP = requireOCSP

    @classmethod
    def fromPFX(cls, pfxFile, password=None, **kwargs):
        with open(pfxFile, 'rb') as fd:
            data = fd.read()
        return cls.fromPFXData(data, password, source='the PFX file %s' % pfxFile, **kwargs)

    @classmethod
    def fromPFXData(cls, data, password=None, source='the PFX data', **kwargs):
        """Load a PKCS#12 from memory, for callers holding it as bytes rather than a file."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        try:
            privateKey, certificate, chain = pkcs12.load_key_and_certificates(data, password or None)
        except ValueError as e:
            raise PKINITError('Could not load %s: %s. Certificates encrypted with legacy algorithms must be '
                              'converted first, e.g. openssl pkcs12 -in old.pfx -out new.pfx -legacy' % (source, e))
        if privateKey is None or certificate is None:
            raise PKINITError('%s does not hold both a certificate and its private key' % source.capitalize())
        return cls(privateKey, certificate, chain, **kwargs)

    @classmethod
    def fromPEM(cls, certFile, keyFile, password=None, **kwargs):
        with open(certFile, 'rb') as fd:
            certificateData = fd.read()
        with open(keyFile, 'rb') as fd:
            keyData = fd.read()
        return cls.fromPEMData(certificateData, keyData, password, source='%s and %s' % (certFile, keyFile), **kwargs)

    @classmethod
    def fromPEMData(cls, certificateData, keyData, password=None, source='the PEM data', **kwargs):
        """Load a PEM certificate and its key from memory."""
        certificates = readPEMCertificates(certificateData)
        if not certificates:
            raise PKINITError('No certificate found in %s' % source)
        if isinstance(password, str):
            password = password.encode('utf-8')
        try:
            privateKey = serialization.load_pem_private_key(keyData, password or None)
        except (TypeError, ValueError) as e:
            raise PKINITError('Could not load the private key of %s: %s' % (source, e))
        return cls(privateKey, certificates[0], certificates[1:], **kwargs)

    def getUPN(self):
        upns = getUPNs(self.certificate)
        return upns[0] if upns else None

    def getPrincipal(self):
        """Return the identity the certificate is bound to, as principal@realm."""
        principals = getKerberosPrincipals(self.certificate)
        if principals:
            return principals[0]
        return self.getUPN()


def readPEMCertificates(data):
    certificates = []
    marker = b'-----BEGIN CERTIFICATE-----'
    while marker in data:
        start = data.index(marker)
        end = data.index(b'-----END CERTIFICATE-----', start) + len(b'-----END CERTIFICATE-----')
        certificates.append(x509.load_pem_x509_certificate(data[start:end]))
        data = data[end:]
    return certificates


class PKINIT:
    """Request a TGT with a certificate, as defined in RFC 4556."""

    def __init__(self, clientName, domain, credentials, kdcHost=None, requestPAC=True, serverName=None,
                 supportedCiphers=None):
        self.clientName = clientName
        self.domain = domain.upper()
        self.credentials = credentials
        self.kdcHost = kdcHost
        self.requestPAC = requestPAC
        self.serverName = serverName
        self.supportedCiphers = supportedCiphers or (
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.rc4_hmac.value),
        )
        self.digest = credentials.digest
        self.keyExchange = None
        self.nonce = 0
        self.asReq = b''
        self.ocspResponses = []

    def newKeyExchange(self):
        if self.credentials.keyExchange == 'dh':
            return DiffieHellman(self.credentials.dhGroup)
        if self.credentials.keyExchange == 'ecdh':
            return EllipticCurveDiffieHellman(self.credentials.curve)
        return None

    def buildAuthPack(self, reqBody):
        authPack = AuthPack()
        pkAuthenticator = authPack['pkAuthenticator']
        now = datetime.datetime.now(datetime.timezone.utc)
        pkAuthenticator['cusec'] = now.microsecond
        pkAuthenticator['ctime'] = KerberosTime.to_asn1(now)
        # Windows KDCs echo this nonce back as the AS-REP nonce, so it must match the KDC-REQ-BODY one
        pkAuthenticator['nonce'] = self.nonce
        pkAuthenticator['paChecksum'] = sha1(getReqBodyBytes(reqBody)).digest()

        if self.keyExchange is not None:
            publicKeyInfo = self.keyExchange.getSubjectPublicKeyInfo()
            clientPublicValue = authPack['clientPublicValue']
            clientPublicValue['algorithm'] = publicKeyInfo['algorithm']
            clientPublicValue['subjectPublicKey'] = publicKeyInfo['subjectPublicKey']

        digests = [self.digest] + [name for name in ('sha512', 'sha384', 'sha256', 'sha1') if name != self.digest]
        supportedCMSTypes = [getSignatureAlgorithm(self.credentials.privateKey, digest) for digest in digests]
        if self.credentials.keyExchange == 'rsa':
            supportedCMSTypes.append(buildAlgorithmIdentifier(ID_RSA_ENCRYPTION, encoder.encode(univ.Null(''))))
            supportedCMSTypes.append(buildAlgorithmIdentifier(ID_AES256_CBC))
            supportedCMSTypes.append(buildAlgorithmIdentifier(ID_DES_EDE3_CBC))
        seq_set_iter(authPack, 'supportedCMSTypes', supportedCMSTypes)
        return encoder.encode(authPack)

    def buildAsReq(self):
        asReq = AS_REQ()
        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        reqBody = seq_set(asReq, 'req-body')
        options = [constants.KDCOptions.forwardable.value,
                   constants.KDCOptions.renewable.value,
                   constants.KDCOptions.proxiable.value]
        reqBody['kdc-options'] = constants.encodeFlags(options)

        serverName = self.serverName
        if serverName is None:
            serverName = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        elif not isinstance(serverName, Principal):
            # getKerberosTGT also takes the service as a plain string
            serverName = Principal(serverName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', self.clientName.components_to_asn1)
        reqBody['realm'] = self.domain

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        self.nonce = int.from_bytes(os.urandom(4), 'big') >> 1
        reqBody['nonce'] = self.nonce
        seq_set_iter(reqBody, 'etype', self.supportedCiphers)

        signedAuthPack = buildSignedData(self.credentials.privateKey, self.credentials.certificate,
                                         self.credentials.chain, ID_PKINIT_AUTHDATA,
                                         self.buildAuthPack(reqBody), self.digest)
        paPkAsReq = PA_PK_AS_REQ()
        paPkAsReq['signedAuthPack'] = signedAuthPack

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = self.requestPAC

        asReq['padata'] = univ.noValue
        asReq['padata'][0] = univ.noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value)
        asReq['padata'][0]['padata-value'] = encoder.encode(paPkAsReq)
        asReq['padata'][1] = univ.noValue
        asReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][1]['padata-value'] = encoder.encode(pacRequest)

        if self.credentials.requestOCSP:
            asReq['padata'][2] = univ.noValue
            asReq['padata'][2]['padata-type'] = int(
                constants.PreAuthenticationDataTypes.PA_PK_OCSP_RESPONSE.value)
            asReq['padata'][2]['padata-value'] = encoder.encode(PKOcspData())

        return encoder.encode(asReq)

    def getTGT(self):
        # Imported here, kerberosv5 dispatches to this module
        from impacket.krb5.kerberosv5 import KerberosError, sendReceive

        self.keyExchange = self.newKeyExchange()
        # One retry per recoverable error: rejected domain parameters and rejected digest (RFC 4556 3.2.2)
        for attempt in range(3):
            self.asReq = self.buildAsReq()
            try:
                response = sendReceive(self.asReq, self.domain, self.kdcHost)
                break
            except KerberosError as e:
                if attempt == 2:
                    raise
                self.handleError(e)

        asRep = decodeASN1(response, AS_REP(), 'AS-REP')
        replyKey = self.getReplyKey(asRep)

        # Key usage 3: AS-REP encrypted part, encrypted with the client key
        cipher = getCipher(int(asRep['enc-part']['etype']), 'encrypted part of the AS-REP')
        try:
            plainText = cipher.decrypt(replyKey, 3, asRep['enc-part']['cipher'].asOctets())
        except InvalidChecksum:
            raise PKINITError('The reply key derived from the certificate exchange does not decrypt the AS-REP')
        encASRepPart = decodeASN1(plainText, EncASRepPart(), 'encrypted part of the AS-REP')
        if int(encASRepPart['nonce']) != self.nonce:
            raise PKINITError('The AS-REP nonce does not match the one of our AS-REQ')

        sessionCipher = getCipher(int(encASRepPart['key']['keytype']), 'session key')
        sessionKey = Key(sessionCipher.enctype, encASRepPart['key']['keyvalue'].asOctets())
        return response, sessionCipher, replyKey, sessionKey

    def handleError(self, error):
        """Recover from the errors RFC 4556 3.2.2 lets the client retry after."""
        errorCode = error.getErrorCode()
        if errorCode == constants.ErrorCodes.KDC_ERR_KEY_TOO_WEAK.value:
            # 65 is KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED in RFC 4556 3.1.3, not KDC_ERR_KEY_TOO_WEAK
            self.keyExchange = self.getAcceptedKeyExchange(error)
        elif errorCode in (constants.ErrorCodes.KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED.value,
                           constants.ErrorCodes.KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED.value):
            if self.digest == 'sha1':
                raise error
            LOG.debug('KDC rejected the %s digest, retrying with sha1' % self.digest)
            self.digest = 'sha1'
        elif errorCode in (constants.ErrorCodes.KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED.value,
                           constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value) and self.credentials.keyExchange == 'rsa':
            # Windows KDCs implement no CMS algorithm for this method and answer KDC_ERR_ETYPE_NOSUPP
            raise PKINITError('The KDC does not support the public key encryption method, use the Diffie-Hellman '
                              'key delivery method instead')
        else:
            raise error

    def getAcceptedKeyExchange(self, error):
        """Pick a key exchange from the domain parameters the KDC proposed.

        RFC 4556 3.2.2 and RFC 5349 4: the KDC answers rejected domain parameters
        with a TD-DH-PARAMETERS holding the ones it accepts, in decreasing
        preference order, be they MODP groups or elliptic curves.
        """
        eData = error.getErrorPacket()['e-data']
        if not eData.hasValue():
            raise PKINITError('The KDC rejected our Diffie-Hellman domain parameters without proposing any')

        for dataType, dataValue in self.parseErrorData(eData.asOctets()):
            if dataType != constants.PreAuthenticationDataTypes.TD_DH_PARAMETERS.value:
                continue
            for algorithm in decoder.decode(dataValue, asn1Spec=TD_DH_PARAMETERS())[0]:
                keyExchange = self.newKeyExchangeFromParameters(algorithm)
                if keyExchange is not None:
                    return keyExchange
        raise PKINITError('The KDC did not propose any Diffie-Hellman domain parameters we support')

    def newKeyExchangeFromParameters(self, algorithm):
        """Build the key exchange a TD-DH-PARAMETERS entry stands for, or None if unsupported."""
        oid = str(algorithm['algorithm'])
        if not algorithm['parameters'].hasValue():
            return None
        try:
            if oid == ID_DH_PUBLIC_NUMBER:
                parameters = decoder.decode(bytes(algorithm['parameters']), asn1Spec=rfc3279.DomainParameters())[0]
                prime = int(parameters['p'])
                for group, (groupPrime, _) in DH_GROUPS.items():
                    if groupPrime == prime:
                        LOG.debug('Retrying with the MODP group %d the KDC proposed' % group)
                        return DiffieHellman(group)
                return None
            if oid == ID_EC_PUBLIC_KEY:
                # RFC 5480 2.1.1: named curves are an OID, custom curves a SEQUENCE we do not support
                curveOid = str(decoder.decode(bytes(algorithm['parameters']),
                                              asn1Spec=univ.ObjectIdentifier())[0])
                curve = EC_CURVE_OIDS.get(curveOid)
                if curve is None:
                    return None
                LOG.debug('Retrying with the %s curve the KDC proposed' % curve)
                return EllipticCurveDiffieHellman(curve)
        except PyAsn1Error as e:
            LOG.debug('Ignoring domain parameters the KDC proposed for %s: %s' % (oid, e))
        return None

    def parseErrorData(self, eData):
        """Return the (type, value) elements of a KRB-ERROR e-data field."""
        try:
            return [(int(element['data-type']), element['data-value'].asOctets())
                    for element in decoder.decode(eData, asn1Spec=TYPED_DATA())[0]]
        except PyAsn1Error as e:
            LOG.debug('e-data is not a TYPED-DATA (%s), reading it as a METHOD-DATA' % e)
            return [(int(element['padata-type']), element['padata-value'].asOctets())
                    for element in decoder.decode(eData, asn1Spec=METHOD_DATA())[0]]

    def getReplyKey(self, asRep):
        paPkAsRep = None
        for padata in asRep['padata']:
            padataType = int(padata['padata-type'])
            if padataType == constants.PreAuthenticationDataTypes.PA_PK_AS_REP.value:
                paPkAsRep = decodeASN1(padata['padata-value'], PA_PK_AS_REP(), 'PA-PK-AS-REP')
            elif padataType == constants.PreAuthenticationDataTypes.PA_PK_OCSP_RESPONSE.value:
                try:
                    self.ocspResponses = decodeASN1(padata['padata-value'], PKOcspData(), 'PA-PK-OCSP-RESPONSE')
                except PKINITError as e:
                    LOG.debug('Ignoring a malformed PA-PK-OCSP-RESPONSE: %s' % e)

        if paPkAsRep is None:
            raise PKINITError('The KDC did not answer with a PA-PK-AS-REP, PKINIT is probably not enabled')

        cipher = getCipher(int(asRep['enc-part']['etype']), 'encrypted part of the AS-REP')
        # Reading a component of a pyasn1 Choice selects it, so go through the name the KDC chose
        if paPkAsRep.getName() == 'dhInfo':
            return self.getReplyKeyFromDH(paPkAsRep.getComponent(), cipher)
        return self.getReplyKeyFromEncKeyPack(bytes(paPkAsRep.getComponent()), cipher)

    def getReplyKeyFromDH(self, dhInfo, cipher):
        """Derive the AS reply key from the DH exchange (RFC 4556 3.2.3.1)."""
        if self.keyExchange is None:
            raise PKINITError('The KDC answered with a Diffie-Hellman reply to a public key encryption request')

        content, certificate, certificates = verifySignedData(bytes(dhInfo['dhSignedData']), ID_PKINIT_DHKEYDATA)
        self.checkKDCCertificate(certificate, certificates)

        keyInfo = decodeASN1(content, KDCDHKeyInfo(), 'KDCDHKeyInfo')
        # RFC 4556 3.2.3.1: dhKeyExpiration is present if and only if the KDC reuses its DH keys
        reusedKeys = keyInfo['dhKeyExpiration'].hasValue()
        if reusedKeys:
            expiration = KerberosTime.from_asn1(keyInfo['dhKeyExpiration']).replace(tzinfo=datetime.timezone.utc)
            if expiration <= datetime.datetime.now(datetime.timezone.utc):
                raise PKINITError('The Diffie-Hellman key the KDC reused expired on %s, its signature over the '
                                  'DHRepInfo is no longer valid' % expiration)

        # RFC 4556 3.2.3.1: the nonce is our pkAuthenticator one, or 0 when the KDC reuses its DH keys
        expectedNonce = 0 if reusedKeys else self.nonce
        if int(keyInfo['nonce']) != expectedNonce:
            raise PKINITError('The KDCDHKeyInfo nonce does not match the one of our PKAuthenticator')

        # k = octetstring2key(DHSharedSecret | n_c | n_k), n_c stays empty since we send no clientDHNonce
        serverDHNonce = b''
        if reusedKeys:
            if not dhInfo['serverDHNonce'].hasValue():
                raise PKINITError('The KDC reused its Diffie-Hellman key without sending a serverDHNonce')
            serverDHNonce = bytes(dhInfo['serverDHNonce'])

        sharedSecret = self.keyExchange.getSharedSecret(
            self.keyExchange.getPeerPublicKey(keyInfo['subjectPublicKey']))
        return octetstring2key(sharedSecret + serverDHNonce, cipher)

    def getReplyKeyFromEncKeyPack(self, encKeyPack, cipher):
        """Extract the AS reply key from the encrypted key pack."""
        if self.keyExchange is not None:
            raise PKINITError('The KDC answered with an encrypted key pack to a Diffie-Hellman request')

        content, certificate, certificates = verifySignedData(
            decryptEnvelopedData(encKeyPack, self.credentials.privateKey), ID_PKINIT_RKEYDATA)
        self.checkKDCCertificate(certificate, certificates)

        replyKeyPack = decodeASN1(content, ReplyKeyPack(), 'ReplyKeyPack')
        enctype = int(replyKeyPack['replyKey']['keytype'])
        try:
            replyKey = Key(enctype, replyKeyPack['replyKey']['keyvalue'].asOctets())
        except ValueError as e:
            raise PKINITError('The KDC sent an unusable reply key: %s' % e)

        checksum = replyKeyPack['asChecksum']
        cksumtype = int(checksum['cksumtype'])
        if cksumtype != CHECKSUM_FOR_ENCTYPE.get(enctype):
            raise PKINITError('The asChecksum uses checksum type %d, which is not the required one for the reply key'
                              % cksumtype)
        try:
            verify_checksum(cksumtype, replyKey, KEY_USAGE_AS_REQ_CHECKSUM, self.asReq,
                            checksum['checksum'].asOctets())
        except InvalidChecksum:
            raise PKINITError('The asChecksum of the ReplyKeyPack does not match our AS-REQ')
        return replyKey

    def checkKDCCertificate(self, certificate, certificates):
        if not self.credentials.verifyKDC:
            LOG.debug('KDC certificate validation is disabled')
            return
        verifyKDCCertificate(certificate, certificates, self.domain, self.credentials.trustedCAs)
        self.checkOCSPResponses(certificate, certificates)

    def checkOCSPResponses(self, certificate, certificates):
        """Check the revocation status the KDC piggybacked in the reply."""
        checked = False
        for response in self.ocspResponses:
            try:
                ocspResponse = ocsp.load_der_ocsp_response(bytes(response))
                status = ocspResponse.response_status
                if status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                    LOG.debug('Ignoring an unsuccessful OCSP response (%s)' % status.name)
                    continue
                if ocspResponse.serial_number != certificate.serial_number:
                    continue
                verifyOCSPResponse(ocspResponse, certificate, certificates + self.credentials.trustedCAs)
                if ocspResponse.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                    raise KDCCertificateError('The KDC certificate was revoked on %s'
                                              % getRevocationTime(ocspResponse))
                LOG.debug('OCSP status of the KDC certificate: %s' % ocspResponse.certificate_status.name)
                checked = True
            except (ValueError, PKINITError) as e:
                if isinstance(e, KDCCertificateError):
                    raise
                LOG.debug('Ignoring an invalid OCSP response: %s' % e)

        # RFC 4557 3: a missing response should be an error, but no Windows KDC sends one, so it is opt-in
        if not checked and self.credentials.requireOCSP:
            raise KDCCertificateError('The KDC did not return a usable OCSP response for its certificate')


def getKerberosTGTPKINIT(clientName, domain, credentials, kdcHost=None, requestPAC=True, serverName=None,
                         supportedCiphers=None):
    """Request a TGT with a client certificate, as defined in RFC 4556.

    Returns the same (tgt, cipher, oldSessionKey, sessionKey) tuple as
    getKerberosTGT, where oldSessionKey is the AS reply key derived from the
    certificate exchange.
    """
    pkinit = PKINIT(clientName, domain, credentials, kdcHost=kdcHost, requestPAC=requestPAC, serverName=serverName,
                    supportedCiphers=supportedCiphers)
    return pkinit.getTGT()