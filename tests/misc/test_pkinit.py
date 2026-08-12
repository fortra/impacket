#!/usr/bin/env python
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
#   Tests for the PKINIT client (RFC 4556, RFC 5349, RFC 4557).
#
#   The AS exchange is played against a KDC implemented in this file, so both AS
#   reply key delivery methods are exercised end to end without a domain.
#
from __future__ import print_function

import datetime
import unittest
from binascii import hexlify, unhexlify
from hashlib import sha1

from Cryptodome.Cipher import AES, DES3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ
from pyasn1_modules import rfc3279, rfc5280, rfc5652

import impacket.krb5.kerberosv5 as kerberosv5
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import AS_REP, AS_REQ, AuthPack, EncASRepPart, KDCDHKeyInfo, METHOD_DATA, \
    PA_PK_AS_REP, PA_PK_AS_REQ, PKOcspData, ReplyKeyPack, TD_DH_PARAMETERS, TYPED_DATA, seq_set, seq_set_iter
from impacket.krb5.crypto import Cksumtype, Enctype, Key, _enctype_table, make_checksum
from impacket.krb5.pkinit import DH_GROUPS, DIGEST_ALGORITHMS, EC_CURVES, EC_CURVE_OIDS, ID_AES256_CBC, ID_DES_EDE3_CBC, \
    ID_ENVELOPED_DATA, decryptEnvelopedData, \
    ID_DH_PUBLIC_NUMBER, ID_EC_PUBLIC_KEY, ID_MS_SAN_SC_LOGON_UPN, ID_PKINIT_AUTHDATA, \
    ID_PKINIT_DHKEYDATA, ID_PKINIT_KP_KDC, ID_PKINIT_RKEYDATA, ID_PKINIT_SAN, ID_RSA_ENCRYPTION, DiffieHellman, \
    EllipticCurveDiffieHellman, KDCCertificateError, PKINIT, PKINITCredentials, PKINITError, buildAlgorithmIdentifier, \
    buildCertificateSet, buildContentInfo, buildSignedData, getReqBodyBytes, getSignatureAlgorithm,\
    buildSignerIdentifier, signData, octetstring2key, parseSignedData, verifyKDCCertificate, verifySignedData
from impacket.krb5.types import KerberosTime, Principal

REALM = 'CONTOSO.COM'
CLIENT = 'jdoe'


def h(hexstr):
    return unhexlify(hexstr.replace(' ', '').replace('\n', ''))


def setComponent(sequence, name, **kwargs):
    """Set a simple component from raw octets, keeping the context tag of its slot."""
    sequence[name] = sequence[name].clone(**kwargs)


def makeKerberosPrincipalName(realm, components):
    from impacket.krb5.asn1 import KRB5PrincipalName
    principalName = KRB5PrincipalName()
    principalName['realm'] = realm
    principalName['principalName']['name-type'] = int(constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set_iter(principalName['principalName'], 'name-string', components)
    return encoder.encode(principalName)


def makeKeyUsage(**bits):
    """Build a KeyUsage extension, every bit defaulting to False."""
    usage = dict(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                 key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    usage.update(bits)
    return x509.KeyUsage(**usage)


def makeCertificate(commonName, issuerCertificate=None, issuerKey=None, otherName=None, extendedKeyUsage=None,
                    isCA=None, key=None, pathLength=None, keyUsage=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, commonName)])
    issuer = issuerCertificate.subject if issuerCertificate is not None else subject
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)) \
        .not_valid_after(now + datetime.timedelta(days=365)) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if isCA is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=isCA, path_length=pathLength), critical=True)
    if keyUsage is not None:
        builder = builder.add_extension(keyUsage, critical=True)
    if otherName is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([otherName]), critical=False)
    if extendedKeyUsage is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid) for oid in extendedKeyUsage]), critical=False)

    certificate = builder.sign(issuerKey or key, hashes.SHA256())
    return key, certificate


class PKI:
    """A CA, a KDC certificate and a client certificate, as an enterprise CA would issue them."""

    def __init__(self):
        self.caKey, self.caCertificate = makeCertificate('Contoso Root CA', isCA=True)
        self.kdcKey, self.kdcCertificate = makeCertificate(
            'dc01.contoso.com', self.caCertificate, self.caKey,
            otherName=x509.OtherName(x509.ObjectIdentifier(ID_PKINIT_SAN),
                                     makeKerberosPrincipalName(REALM, ['krbtgt', REALM])),
            extendedKeyUsage=[ID_PKINIT_KP_KDC])
        self.clientKey, self.clientCertificate = makeCertificate(
            CLIENT, self.caCertificate, self.caKey,
            otherName=x509.OtherName(x509.ObjectIdentifier(ID_MS_SAN_SC_LOGON_UPN),
                                     encoder.encode(char.UTF8String('%s@contoso.com' % CLIENT))))


class KDC:
    """A minimal PKINIT KDC, implementing RFC 4556 3.2.2 and 3.2.3."""

    def __init__(self, pki, enctype=Enctype.AES256, useEncKeyPack=False, rejectDHGroup=None, nonceOverride=None,
                 rejectDigest=None, ocspStatus=None, contentEncryption='aes256-CBC', reuseDHKeys=False,
                 dhKeyLifetime=3600, serverDHNonce=None, rejectCurve=None, proposeCurve=None, useTypedData=False,
                 ocspResponder=None, ocspExpired=False, answerDHWithoutRequest=False):
        self.pki = pki
        self.cipher = _enctype_table[enctype]
        self.useEncKeyPack = useEncKeyPack
        self.rejectDHGroup = rejectDHGroup
        self.nonceOverride = nonceOverride
        self.rejectDigest = rejectDigest
        self.ocspStatus = ocspStatus
        self.contentEncryption = contentEncryption
        self.reuseDHKeys = reuseDHKeys
        self.dhKeyLifetime = dhKeyLifetime
        self.serverDHNonce = serverDHNonce if serverDHNonce is not None else b'N' * 32
        self.rejectCurve = rejectCurve
        self.proposeCurve = proposeCurve
        self.useTypedData = useTypedData
        self.ocspResponder = ocspResponder
        self.ocspExpired = ocspExpired
        self.answerDHWithoutRequest = answerDHWithoutRequest
        self.replyKey = None
        self.ocspRequested = False
        self.sessionKey = Key(enctype, b'S' * self.cipher.keysize)

    def sendReceive(self, data, host, kdcHost, port=88):
        asReq = decoder.decode(data, asn1Spec=AS_REQ())[0]
        authPack, clientCertificate = self.verifyRequest(asReq)

        if self.useEncKeyPack:
            paPkAsRep = self.buildEncKeyPack(data, clientCertificate)
        else:
            paPkAsRep = self.buildDHInfo(authPack)
        return self.buildAsRep(asReq, paPkAsRep)

    def verifyRequest(self, asReq):
        padata = {int(entry['padata-type']): entry['padata-value'] for entry in asReq['padata']}
        assert constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value in padata, 'no PA-PK-AS-REQ in the AS-REQ'
        assert constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value in padata, 'no PA-PAC-REQUEST in the AS-REQ'

        self.ocspRequested = constants.PreAuthenticationDataTypes.PA_PK_OCSP_RESPONSE.value in padata

        paPkAsReq = decoder.decode(padata[constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value],
                                   asn1Spec=PA_PK_AS_REQ())[0]
        if self.rejectDigest is not None and self.usesDigest(paPkAsReq, self.rejectDigest):
            self.raiseError(constants.ErrorCodes.KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED.value)
        content, certificate, _ = verifySignedData(bytes(paPkAsReq['signedAuthPack']), ID_PKINIT_AUTHDATA)
        authPack = decoder.decode(content, asn1Spec=AuthPack())[0]

        expected = sha1(getReqBodyBytes(asReq['req-body'])).digest()
        assert bytes(authPack['pkAuthenticator']['paChecksum']) == expected, 'bad paChecksum'
        return authPack, certificate

    def buildDHInfo(self, authPack):
        publicKeyInfo = authPack['clientPublicValue']
        if not publicKeyInfo.hasValue():
            assert self.answerDHWithoutRequest, 'no clientPublicValue in the AuthPack'
            return self.buildDHRepInfo(DiffieHellman(14), b'unused', encoder.encode(univ.Integer(1)), 0)

        algorithm = str(publicKeyInfo['algorithm']['algorithm'])
        if algorithm == ID_DH_PUBLIC_NUMBER:
            parameters = decoder.decode(bytes(publicKeyInfo['algorithm']['parameters']),
                                        asn1Spec=rfc3279.DomainParameters())[0]
            prime, generator = int(parameters['p']), int(parameters['g'])
            assert int(parameters['q']) == (prime - 1) // 2, 'bad DH subgroup order'
            if self.rejectDHGroup is not None and prime == DH_GROUPS[self.rejectDHGroup][0]:
                self.raiseDHParametersNotAccepted()
            keyExchange = DiffieHellman(prime=prime, generator=generator)
            clientPublicKey = int(decoder.decode(publicKeyInfo['subjectPublicKey'].asOctets(),
                                                 asn1Spec=univ.Integer())[0])
            sharedSecret = keyExchange.getSharedSecret(clientPublicKey)
            subjectPublicKey = encoder.encode(univ.Integer(keyExchange.publicKey))
        else:
            assert algorithm == ID_EC_PUBLIC_KEY, 'unexpected key agreement algorithm %s' % algorithm
            curveOid = str(decoder.decode(bytes(publicKeyInfo['algorithm']['parameters']),
                                          asn1Spec=univ.ObjectIdentifier())[0])
            curve = EC_CURVE_OIDS[curveOid]
            if self.rejectCurve is not None and curve == self.rejectCurve:
                self.raiseDHParametersNotAccepted()
            keyExchange = EllipticCurveDiffieHellman(curve)
            clientPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(
                EC_CURVES[curve](), publicKeyInfo['subjectPublicKey'].asOctets())
            sharedSecret = keyExchange.getSharedSecret(clientPublicKey)
            subjectPublicKey = keyExchange.privateKey.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

        return self.buildDHRepInfo(keyExchange, sharedSecret, subjectPublicKey,
                                   int(authPack['pkAuthenticator']['nonce']))

    def buildDHRepInfo(self, keyExchange, sharedSecret, subjectPublicKey, nonce):
        serverDHNonce = self.serverDHNonce if self.reuseDHKeys else b''
        self.replyKey = octetstring2key(sharedSecret + serverDHNonce, self.cipher)

        keyInfo = KDCDHKeyInfo()
        setComponent(keyInfo, 'subjectPublicKey', hexValue=hexlify(subjectPublicKey).decode('ascii'))
        if self.nonceOverride is not None:
            keyInfo['nonce'] = self.nonceOverride
        elif self.reuseDHKeys:
            keyInfo['nonce'] = 0
        else:
            keyInfo['nonce'] = nonce

        paPkAsRep = PA_PK_AS_REP()
        dhRepInfo = paPkAsRep.setComponentByName('dhInfo').getComponentByName('dhInfo')
        if self.reuseDHKeys:
            expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.dhKeyLifetime)
            keyInfo['dhKeyExpiration'] = KerberosTime.to_asn1(expiration)
            if self.serverDHNonce:
                setComponent(dhRepInfo, 'serverDHNonce', value=self.serverDHNonce)
        dhRepInfo['dhSignedData'] = buildSignedData(self.pki.kdcKey, self.pki.kdcCertificate, [],
                                                    ID_PKINIT_DHKEYDATA, encoder.encode(keyInfo), 'sha256')
        return paPkAsRep

    def buildEncKeyPack(self, asReq, clientCertificate):
        self.replyKey = Key(self.cipher.enctype, b'R' * self.cipher.keysize)

        replyKeyPack = ReplyKeyPack()
        replyKeyPack['replyKey']['keytype'] = self.replyKey.enctype
        replyKeyPack['replyKey']['keyvalue'] = self.replyKey.contents
        # key usage 6
        cksumtype = {Enctype.AES256: Cksumtype.SHA1_AES256, Enctype.AES128: Cksumtype.SHA1_AES128,
                     Enctype.RC4: Cksumtype.HMAC_MD5}[self.cipher.enctype]
        replyKeyPack['asChecksum']['cksumtype'] = cksumtype
        replyKeyPack['asChecksum']['checksum'] = make_checksum(cksumtype, self.replyKey, 6, asReq)

        signedData = buildSignedData(self.pki.kdcKey, self.pki.kdcCertificate, [], ID_PKINIT_RKEYDATA,
                                     encoder.encode(replyKeyPack), 'sha256')

        if self.contentEncryption == 'des-ede3-cbc':
            contentEncryptionKey, initializationVector, blockSize = b'KEY' * 8, b'IV' * 4, 8
            algorithm = DES3.new(contentEncryptionKey, DES3.MODE_CBC, initializationVector)
            algorithmOid = ID_DES_EDE3_CBC
        else:
            contentEncryptionKey, initializationVector, blockSize = b'K' * 32, b'I' * 16, 16
            algorithm = AES.new(contentEncryptionKey, AES.MODE_CBC, initializationVector)
            algorithmOid = ID_AES256_CBC
        padLength = blockSize - len(signedData) % blockSize
        encryptedContent = algorithm.encrypt(signedData + bytes([padLength]) * padLength)

        recipientInfo = rfc5652.KeyTransRecipientInfo()
        recipientInfo['version'] = 0
        issuerAndSerial = recipientInfo['rid'].setComponentByName('issuerAndSerialNumber').getComponentByName(
            'issuerAndSerialNumber')
        issuerAndSerial['issuer'] = decoder.decode(clientCertificate.issuer.public_bytes(),
                                                   asn1Spec=rfc5280.Name())[0]
        issuerAndSerial['serialNumber'] = clientCertificate.serial_number
        recipientInfo['keyEncryptionAlgorithm'] = buildAlgorithmIdentifier(
            ID_RSA_ENCRYPTION, encoder.encode(univ.Null('')))
        recipientInfo['encryptedKey'] = clientCertificate.public_key().encrypt(contentEncryptionKey,
                                                                              padding.PKCS1v15())

        envelopedData = rfc5652.EnvelopedData()
        envelopedData['version'] = 0
        envelopedData['recipientInfos'].setComponentByPosition(0, rfc5652.RecipientInfo())
        envelopedData['recipientInfos'][0]['ktri'] = recipientInfo
        envelopedData['encryptedContentInfo']['contentType'] = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
        envelopedData['encryptedContentInfo']['contentEncryptionAlgorithm'] = buildAlgorithmIdentifier(
            algorithmOid, encoder.encode(univ.OctetString(initializationVector)))
        envelopedData['encryptedContentInfo']['encryptedContent'] = univ.OctetString(encryptedContent).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        paPkAsRep = PA_PK_AS_REP()
        paPkAsRep['encKeyPack'] = buildContentInfo('1.2.840.113549.1.7.3', encoder.encode(envelopedData))
        return paPkAsRep

    def usesDigest(self, paPkAsReq, digest):
        signerInfo = parseSignedData(bytes(paPkAsReq['signedAuthPack']), ID_PKINIT_AUTHDATA)[1]
        return str(signerInfo['digestAlgorithm']['algorithm']) == DIGEST_ALGORITHMS[digest][0]

    def buildAcceptedParameters(self):
        accepted = TD_DH_PARAMETERS()
        if self.proposeCurve is not None:
            # sect571r1 stands for a curve of RFC 5349 5 this client does not implement
            curveOid = next((oid for oid, name in EC_CURVE_OIDS.items() if name == self.proposeCurve),
                            '1.3.132.0.39')
            accepted.setComponentByPosition(0, buildAlgorithmIdentifier(
                ID_EC_PUBLIC_KEY, encoder.encode(univ.ObjectIdentifier(curveOid))))
            return accepted
        parameters = rfc3279.DomainParameters()
        prime, generator = DH_GROUPS[14]
        parameters['p'], parameters['g'], parameters['q'] = prime, generator, (prime - 1) // 2
        accepted.setComponentByPosition(0, buildAlgorithmIdentifier(ID_DH_PUBLIC_NUMBER, encoder.encode(parameters)))
        return accepted

    def raiseDHParametersNotAccepted(self):
        accepted = encoder.encode(self.buildAcceptedParameters())
        dataType = int(constants.PreAuthenticationDataTypes.TD_DH_PARAMETERS.value)

        if self.useTypedData:
            # RFC 4556 3.2.2 carries the error details in a TYPED-DATA, which is what Windows KDCs send
            errorData = TYPED_DATA()
            errorData.setComponentByPosition(0, univ.noValue)
            errorData[0]['data-type'] = dataType
            errorData[0]['data-value'] = accepted
        else:
            errorData = METHOD_DATA()
            errorData.setComponentByPosition(0, univ.noValue)
            errorData[0]['padata-type'] = dataType
            errorData[0]['padata-value'] = accepted
        self.raiseError(constants.ErrorCodes.KDC_ERR_KEY_TOO_WEAK.value, encoder.encode(errorData))

    def raiseError(self, errorCode, eData=None):
        from impacket.krb5.asn1 import KRB_ERROR

        krbError = KRB_ERROR()
        krbError['pvno'] = 5
        krbError['msg-type'] = int(constants.ApplicationTagNumbers.KRB_ERROR.value)
        krbError['stime'] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
        krbError['susec'] = 0
        krbError['error-code'] = int(errorCode)
        krbError['realm'] = REALM
        seq_set(krbError, 'sname',
                Principal('krbtgt/%s' % REALM, type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
        if eData is not None:
            krbError['e-data'] = eData
        raise kerberosv5.KerberosError(packet=krbError)

    def buildOCSPResponse(self):
        """Build the OCSP response for the KDC certificate, as RFC 4557 3 allows."""
        now = datetime.datetime.now(datetime.timezone.utc)
        responderKey, responderCertificate = self.ocspResponder or (self.pki.caKey, self.pki.caCertificate)
        thisUpdate = now - datetime.timedelta(days=2) if self.ocspExpired else now
        nextUpdate = thisUpdate + datetime.timedelta(days=1)
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=self.pki.kdcCertificate, issuer=self.pki.caCertificate, algorithm=hashes.SHA1(),
            cert_status=self.ocspStatus, this_update=thisUpdate, next_update=nextUpdate,
            revocation_time=thisUpdate if self.ocspStatus == ocsp.OCSPCertStatus.REVOKED else None,
            revocation_reason=x509.ReasonFlags.key_compromise if self.ocspStatus == ocsp.OCSPCertStatus.REVOKED
            else None).responder_id(ocsp.OCSPResponderEncoding.NAME, responderCertificate) \
            .certificates([responderCertificate, self.pki.caCertificate])
        response = builder.sign(responderKey, hashes.SHA256())

        ocspData = PKOcspData()
        ocspData.setComponentByPosition(0, response.public_bytes(serialization.Encoding.DER))
        return encoder.encode(ocspData)

    def buildAsRep(self, asReq, paPkAsRep):
        encPart = EncASRepPart()
        encPart['key']['keytype'] = self.sessionKey.enctype
        encPart['key']['keyvalue'] = self.sessionKey.contents
        encPart['last-req'] = univ.noValue
        encPart['last-req'][0] = univ.noValue
        encPart['last-req'][0]['lr-type'] = 0
        encPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))
        encPart['nonce'] = int(asReq['req-body']['nonce'])
        encPart['flags'] = constants.encodeFlags([constants.TicketFlags.initial.value])
        now = datetime.datetime.now(datetime.timezone.utc)
        encPart['authtime'] = KerberosTime.to_asn1(now)
        encPart['starttime'] = KerberosTime.to_asn1(now)
        encPart['endtime'] = KerberosTime.to_asn1(now + datetime.timedelta(hours=10))
        encPart['renew-till'] = KerberosTime.to_asn1(now + datetime.timedelta(days=7))
        encPart['srealm'] = REALM
        seq_set(encPart, 'sname',
                Principal('krbtgt/%s' % REALM, type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)

        asRep = AS_REP()
        asRep['pvno'] = 5
        asRep['msg-type'] = int(constants.ApplicationTagNumbers.AS_REP.value)
        asRep['padata'] = univ.noValue
        asRep['padata'][0] = univ.noValue
        asRep['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PK_AS_REP.value)
        asRep['padata'][0]['padata-value'] = encoder.encode(paPkAsRep)
        if self.ocspStatus is not None:
            asRep['padata'][1] = univ.noValue
            asRep['padata'][1]['padata-type'] = int(
                constants.PreAuthenticationDataTypes.PA_PK_OCSP_RESPONSE.value)
            asRep['padata'][1]['padata-value'] = self.buildOCSPResponse()
        asRep['crealm'] = REALM
        seq_set(asRep, 'cname',
                Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)

        ticket = asRep['ticket']
        ticket['tkt-vno'] = 5
        ticket['realm'] = REALM
        seq_set(ticket, 'sname',
                Principal('krbtgt/%s' % REALM, type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
        ticket['enc-part']['etype'] = self.cipher.enctype
        ticket['enc-part']['cipher'] = b'T' * 32

        asRep['enc-part']['etype'] = self.cipher.enctype
        # Key usage 3: AS-REP encrypted part
        asRep['enc-part']['cipher'] = self.cipher.encrypt(self.replyKey, 3, encoder.encode(encPart), None)
        return encoder.encode(asRep)


class OctetString2KeyTests(unittest.TestCase):
    """RFC 4556, Appendix B: test vectors of octetstring2key()."""

    def check(self, x, expected):
        cipher = _enctype_table[Enctype.AES256]
        self.assertEqual(octetstring2key(x, cipher).contents, h(expected))

    def test_set1(self):
        self.check(b'\x00' * 256, '5ee50d675c809fe59e4a7762c54b65837547eafb159bd8cdc75ffca5911e4c41')

    def test_set2(self):
        self.check(b'\x00' * 128, 'acf7707c08973ddfdb27cd361442ccfba355c8884cb472f37da636d07d56787e')

    def test_set3(self):
        self.check(bytes(bytearray(range(0x11)) * 8)[:128],
                   'c442da585fcb80e43b47946f254093e37329d99001380db78371db3acf5c797e')

    def test_set4(self):
        self.check(bytes(bytearray(range(0x11)) * 8)[:77],
                   '0053953b84c896f4eb385c3f2e751c4a590ed6ffadca6ff64f47ebeb8d780ffc')


class DiffieHellmanTests(unittest.TestCase):
    def test_groupsAreTheRFCSafePrimes(self):
        # RFC 2409 E.2 and RFC 3526: p = 2^b - 2^(b-64) - 1 + 2^64 * ([2^(b-130) pi] + offset)
        for group, bits, offset in ((2, 1024, 129093), (5, 1536, 741804), (14, 2048, 124476),
                                    (15, 3072, 1690314), (16, 4096, 240904)):
            prime, generator = DH_GROUPS[group]
            self.assertEqual(prime, self.modpPrime(bits, offset), 'MODP group %d does not match the RFC' % group)
            self.assertEqual(generator, 2)
            self.assertEqual(prime.bit_length(), bits)

    def modpPrime(self, bits, offset):
        return (1 << bits) - (1 << (bits - 64)) - 1 + (1 << 64) * ((self.pi(bits - 130)) + offset)

    def pi(self, bits):
        # Machin's formula in fixed point, with guard bits to absorb the rounding
        one = 1 << (bits + 64)
        value = 4 * (4 * self.arctanInverse(5, one) - self.arctanInverse(239, one))
        return value >> 64

    def arctanInverse(self, x, one):
        total = term = one // x
        square = x * x
        n = 1
        while term:
            term //= square
            n += 2
            total += term // n if (n // 2) % 2 == 0 else -(term // n)
        return total

    def test_sharedSecretIsPaddedToTheModulusSize(self):
        alice, bob = DiffieHellman(group=14), DiffieHellman(group=14)
        shared = alice.getSharedSecret(bob.publicKey)
        self.assertEqual(shared, bob.getSharedSecret(alice.publicKey))
        self.assertEqual(len(shared), 256)

    def test_invalidPublicValueIsRejected(self):
        alice = DiffieHellman(group=14)
        for invalid in (0, 1, alice.prime - 1, alice.prime):
            self.assertRaises(PKINITError, alice.getSharedSecret, invalid)

    def test_subjectPublicKeyInfoRoundTrip(self):
        alice = DiffieHellman(group=2)
        publicKeyInfo = alice.getSubjectPublicKeyInfo()
        self.assertEqual(str(publicKeyInfo['algorithm']['algorithm']), '1.2.840.10046.2.1')
        parameters = decoder.decode(bytes(publicKeyInfo['algorithm']['parameters']),
                                    asn1Spec=rfc3279.DomainParameters())[0]
        self.assertEqual(int(parameters['p']), alice.prime)
        self.assertEqual(alice.getPeerPublicKey(publicKeyInfo['subjectPublicKey']), alice.publicKey)

    def test_ellipticCurveSharedSecret(self):
        alice, bob = EllipticCurveDiffieHellman('P-256'), EllipticCurveDiffieHellman('P-256')
        publicKeyInfo = alice.getSubjectPublicKeyInfo()
        self.assertEqual(str(publicKeyInfo['algorithm']['algorithm']), '1.2.840.10045.2.1')
        self.assertEqual(bob.getSharedSecret(bob.getPeerPublicKey(publicKeyInfo['subjectPublicKey'])),
                         alice.getSharedSecret(alice.getPeerPublicKey(bob.getSubjectPublicKeyInfo()['subjectPublicKey'])))


class SignedDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    def test_roundTrip(self):
        for digest in ('sha1', 'sha256', 'sha384', 'sha512'):
            data = buildSignedData(self.pki.clientKey, self.pki.clientCertificate, [self.pki.caCertificate],
                                   ID_PKINIT_AUTHDATA, b'signed content', digest)
            content, certificate, certificates = verifySignedData(data, ID_PKINIT_AUTHDATA)
            self.assertEqual(content, b'signed content')
            self.assertEqual(certificate, self.pki.clientCertificate)
            self.assertEqual(len(certificates), 2)

    def test_ecdsaSignature(self):
        key, certificate = makeCertificate('ecdsa client', self.pki.caCertificate, self.pki.caKey,
                                           key=ec.generate_private_key(ec.SECP256R1()))
        data = buildSignedData(key, certificate, [], ID_PKINIT_AUTHDATA, b'signed content', 'sha256')
        self.assertEqual(verifySignedData(data, ID_PKINIT_AUTHDATA)[0], b'signed content')

    def test_tamperedSignatureIsRejected(self):
        signed = bytearray(buildSignedData(self.pki.kdcKey, self.pki.kdcCertificate, [], ID_PKINIT_DHKEYDATA,
                                           b'content', 'sha256'))
        signed[-1] ^= 0xFF
        self.assertRaisesRegex(PKINITError, 'signature .* is invalid', verifySignedData, bytes(signed),
                               ID_PKINIT_DHKEYDATA)

    def test_tamperedContentIsRejected(self):
        data = buildSignedData(self.pki.clientKey, self.pki.clientCertificate, [], ID_PKINIT_AUTHDATA,
                               b'signed content', 'sha256')
        tampered = data.replace(b'signed content', b'forged content')
        self.assertRaises(PKINITError, verifySignedData, tampered, ID_PKINIT_AUTHDATA)

    def test_unexpectedContentTypeIsRejected(self):
        data = buildSignedData(self.pki.clientKey, self.pki.clientCertificate, [], ID_PKINIT_AUTHDATA,
                               b'signed content', 'sha256')
        self.assertRaises(PKINITError, verifySignedData, data, ID_PKINIT_DHKEYDATA)


class KDCCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    def test_pkinitSanIsAccepted(self):
        verifyKDCCertificate(self.pki.kdcCertificate, [self.pki.caCertificate], REALM, [self.pki.caCertificate])

    def test_certificateOfAnotherRealmIsRejected(self):
        self.assertRaises(KDCCertificateError, verifyKDCCertificate, self.pki.kdcCertificate,
                          [self.pki.caCertificate], 'OTHER.COM', [self.pki.caCertificate])

    def test_certificateWithoutKDCPurposeIsRejected(self):
        self.assertRaises(KDCCertificateError, verifyKDCCertificate, self.pki.clientCertificate,
                          [self.pki.caCertificate], REALM, [self.pki.caCertificate])

    def test_untrustedIssuerIsRejected(self):
        otherPki = PKI()
        self.assertRaises(KDCCertificateError, verifyKDCCertificate, self.pki.kdcCertificate,
                          [self.pki.caCertificate], REALM, [otherPki.caCertificate])

    def test_pathIsNotValidatedWithoutAnchor(self):
        verifyKDCCertificate(self.pki.kdcCertificate, [], REALM, [])

    def makeKDCCertificate(self, issuerCertificate, issuerKey):
        return makeCertificate('dc01.contoso.com', issuerCertificate, issuerKey,
                               otherName=x509.OtherName(x509.ObjectIdentifier(ID_PKINIT_SAN),
                                                        makeKerberosPrincipalName(REALM, ['krbtgt', REALM])),
                               extendedKeyUsage=[ID_PKINIT_KP_KDC])[1]

    def test_issuerWithoutTheCAFlagIsRejected(self):
        issuerKey, issuerCertificate = makeCertificate('Contoso Leaf', isCA=False)
        certificate = self.makeKDCCertificate(issuerCertificate, issuerKey)
        self.assertRaisesRegex(KDCCertificateError, 'not a CA', verifyKDCCertificate, certificate,
                               [issuerCertificate], REALM, [issuerCertificate])

    def test_certificateWithoutTheDigitalSignatureKeyUsageIsRejected(self):
        # RFC 4556 3.2.4: the digitalSignature key usage bit must be asserted
        certificate = makeCertificate('dc01.contoso.com', self.pki.caCertificate, self.pki.caKey,
                                      otherName=x509.OtherName(x509.ObjectIdentifier(ID_PKINIT_SAN),
                                                               makeKerberosPrincipalName(REALM, ['krbtgt', REALM])),
                                      extendedKeyUsage=[ID_PKINIT_KP_KDC],
                                      keyUsage=makeKeyUsage(key_encipherment=True))[1]
        self.assertRaisesRegex(KDCCertificateError, 'not allowed to sign', verifyKDCCertificate, certificate,
                               [self.pki.caCertificate], REALM, [self.pki.caCertificate])

    def test_issuerWithoutBasicConstraintsIsRejected(self):
        issuerKey, issuerCertificate = makeCertificate('Contoso Leaf')
        certificate = self.makeKDCCertificate(issuerCertificate, issuerKey)
        self.assertRaisesRegex(KDCCertificateError, 'without a basicConstraints', verifyKDCCertificate, certificate,
                               [issuerCertificate], REALM, [issuerCertificate])

    def test_issuerWithoutTheCertificateSigningKeyUsageIsRejected(self):
        issuerKey, issuerCertificate = makeCertificate('Contoso Root CA', isCA=True, keyUsage=makeKeyUsage(digital_signature=True))
        certificate = self.makeKDCCertificate(issuerCertificate, issuerKey)
        self.assertRaisesRegex(KDCCertificateError, 'not allowed to sign certificates', verifyKDCCertificate,
                               certificate, [issuerCertificate], REALM, [issuerCertificate])

    def test_pathLengthConstraintIsEnforced(self):
        rootKey, rootCertificate = makeCertificate('Contoso Root CA', isCA=True, pathLength=0)
        subKey, subCertificate = makeCertificate('Contoso Issuing CA', rootCertificate, rootKey, isCA=True)
        certificate = self.makeKDCCertificate(subCertificate, subKey)
        self.assertRaisesRegex(KDCCertificateError, 'intermediate certificates', verifyKDCCertificate, certificate,
                               [subCertificate], REALM, [rootCertificate])


class ASExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    def setUp(self):
        self.sendReceive = kerberosv5.sendReceive

    def tearDown(self):
        kerberosv5.sendReceive = self.sendReceive

    def credentials(self, **kwargs):
        kwargs.setdefault('trustedCAs', [self.pki.caCertificate])
        return PKINITCredentials(self.pki.clientKey, self.pki.clientCertificate, [], **kwargs)

    def getTGT(self, kdc, credentials):
        kerberosv5.sendReceive = kdc.sendReceive
        clientName = Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        return PKINIT(clientName, REALM, credentials).getTGT()

    def test_diffieHellmanKeyDelivery(self):
        kdc = KDC(self.pki)
        tgt, cipher, replyKey, sessionKey = self.getTGT(kdc, self.credentials())
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)
        self.assertEqual(sessionKey.contents, kdc.sessionKey.contents)
        self.assertEqual(cipher.enctype, Enctype.AES256)
        self.assertEqual(decoder.decode(tgt, asn1Spec=AS_REP())[0]['crealm'], REALM)

    def test_diffieHellmanWithGroup2(self):
        kdc = KDC(self.pki)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(dhGroup=2))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_reusedDHKeysBringTheServerNonceIntoTheReplyKey(self):
        kdc = KDC(self.pki, reuseDHKeys=True)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials())
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_expiredReusedDHKeyIsRejected(self):
        kdc = KDC(self.pki, reuseDHKeys=True, dhKeyLifetime=-60)
        with self.assertRaisesRegex(PKINITError, 'expired'):
            self.getTGT(kdc, self.credentials())

    def test_reusedDHKeysWithoutServerNonceAreRejected(self):
        kdc = KDC(self.pki, reuseDHKeys=True, serverDHNonce=b'')
        with self.assertRaisesRegex(PKINITError, 'without sending a serverDHNonce'):
            self.getTGT(kdc, self.credentials())

    def test_reusedDHKeysWithANonZeroNonceAreRejected(self):
        kdc = KDC(self.pki, reuseDHKeys=True, nonceOverride=1234)
        with self.assertRaisesRegex(PKINITError, 'nonce does not match'):
            self.getTGT(kdc, self.credentials())

    def test_ellipticCurveKeyDelivery(self):
        kdc = KDC(self.pki)
        _, _, replyKey, sessionKey = self.getTGT(kdc, self.credentials(keyExchange='ecdh'))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)
        self.assertEqual(sessionKey.contents, kdc.sessionKey.contents)

    def test_publicKeyEncryptionKeyDelivery(self):
        kdc = KDC(self.pki, useEncKeyPack=True)
        _, _, replyKey, sessionKey = self.getTGT(kdc, self.credentials(keyExchange='rsa'))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)
        self.assertEqual(sessionKey.contents, kdc.sessionKey.contents)

    def test_publicKeyEncryptionWithTripleDES(self):
        kdc = KDC(self.pki, useEncKeyPack=True, contentEncryption='des-ede3-cbc')
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(keyExchange='rsa'))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_serviceTicketIsRequestedDirectly(self):
        # -service of getTGT.py hands the SPN over as a plain string
        kdc = KDC(self.pki)
        kerberosv5.sendReceive = kdc.sendReceive
        clientName = Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        _, _, replyKey, _ = PKINIT(clientName, REALM, self.credentials(),
                                   serverName='cifs/dc01.contoso.com').getTGT()
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_aes128ReplyKey(self):
        kdc = KDC(self.pki, enctype=Enctype.AES128)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials())
        self.assertEqual(len(replyKey.contents), 16)
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_rejectedDomainParametersAreRetried(self):
        # The KDC refuses group 2 and advertises group 14 in TD-DH-PARAMETERS
        kdc = KDC(self.pki, rejectDHGroup=2)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(dhGroup=2))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_rejectedDomainParametersInTypedDataAreRetried(self):
        # RFC 4556 3.2.2: Windows KDCs carry the accepted parameters in a TYPED-DATA
        kdc = KDC(self.pki, rejectDHGroup=2, useTypedData=True)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(dhGroup=2))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_rejectedCurveIsRetriedWithTheProposedOne(self):
        # RFC 5349 4: the KDC may propose elliptic curves instead of MODP groups
        kdc = KDC(self.pki, rejectCurve='P-256', proposeCurve='P-384')
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(keyExchange='ecdh', curve='P-256'))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_rejectedModpGroupIsRetriedWithAProposedCurve(self):
        kdc = KDC(self.pki, rejectDHGroup=2, proposeCurve='P-256')
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(dhGroup=2))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_unsupportedProposedParametersAreReported(self):
        kdc = KDC(self.pki, rejectDHGroup=2, proposeCurve='sect571r1')
        with self.assertRaisesRegex(PKINITError, 'did not propose any'):
            self.getTGT(kdc, self.credentials(dhGroup=2))

    def test_replayedNonceIsRejected(self):
        kdc = KDC(self.pki, nonceOverride=1)
        self.assertRaises(PKINITError, self.getTGT, kdc, self.credentials())

    def test_kdcCertificateOfAnotherRealmIsRejected(self):
        otherPki = PKI()
        otherPki.clientKey, otherPki.clientCertificate = self.pki.clientKey, self.pki.clientCertificate
        kdc = KDC(otherPki)
        self.assertRaises(KDCCertificateError, self.getTGT, kdc, self.credentials())

    def test_rejectedDigestIsRetriedWithSha1(self):
        # RFC 4556 3.2.2: KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED lets the client retry with another digest
        kdc = KDC(self.pki, rejectDigest='sha256')
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials())
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_rejectedSha1DigestIsNotRetried(self):
        kdc = KDC(self.pki, rejectDigest='sha1')
        self.assertRaises(kerberosv5.KerberosError, self.getTGT, kdc, self.credentials(digest='sha1'))

    def test_ocspResponseIsRequestedAndAccepted(self):
        kdc = KDC(self.pki, ocspStatus=ocsp.OCSPCertStatus.GOOD)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(requestOCSP=True))
        self.assertTrue(kdc.ocspRequested, 'no PA-PK-OCSP-RESPONSE in the AS-REQ')
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_revokedKDCCertificateIsRejected(self):
        kdc = KDC(self.pki, ocspStatus=ocsp.OCSPCertStatus.REVOKED)
        self.assertRaises(KDCCertificateError, self.getTGT, kdc, self.credentials(requestOCSP=True))

    def test_keyDeliveryMethodDowngradeIsRejected(self):
        # The client asked for key agreement, the KDC answers with key transport
        kdc = KDC(self.pki, useEncKeyPack=True)
        with self.assertRaisesRegex(PKINITError, 'encrypted key pack to a Diffie-Hellman request'):
            self.getTGT(kdc, self.credentials())

    def test_keyAgreementReplyToAKeyTransportRequestIsRejected(self):
        kdc = KDC(self.pki, answerDHWithoutRequest=True)
        with self.assertRaisesRegex(PKINITError, 'Diffie-Hellman reply to a public key encryption request'):
            self.getTGT(kdc, self.credentials(keyExchange='rsa'))

    def test_ocspResponseFromANonAuthoritativeResponderIsIgnored(self):
        # A revoked status nobody delegated authority for must not be acted upon
        otherPki = PKI()
        kdc = KDC(self.pki, ocspStatus=ocsp.OCSPCertStatus.REVOKED,
                  ocspResponder=(otherPki.caKey, otherPki.caCertificate))
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(requestOCSP=True))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_expiredOCSPResponseIsIgnored(self):
        kdc = KDC(self.pki, ocspStatus=ocsp.OCSPCertStatus.REVOKED, ocspExpired=True)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(requestOCSP=True))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_delegatedOCSPResponderIsAccepted(self):
        responder = makeCertificate('Contoso OCSP', self.pki.caCertificate, self.pki.caKey,
                                    extendedKeyUsage=['1.3.6.1.5.5.7.3.9'])
        kdc = KDC(self.pki, ocspStatus=ocsp.OCSPCertStatus.REVOKED, ocspResponder=responder)
        self.assertRaises(KDCCertificateError, self.getTGT, kdc, self.credentials(requestOCSP=True))

    def test_missingOCSPResponseIsAnErrorWhenRequired(self):
        kdc = KDC(self.pki)
        self.assertRaisesRegex(KDCCertificateError, 'did not return a usable OCSP response',
                               self.getTGT, kdc, self.credentials(requireOCSP=True))

    def test_missingOCSPResponseIsToleratedByDefault(self):
        kdc = KDC(self.pki)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(requestOCSP=True))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

    def test_getKerberosTGTUsesPKINITWithACertificate(self):
        # The whole path an example script goes through: certificate to ccache
        kdc = KDC(self.pki)
        kerberosv5.sendReceive = kdc.sendReceive
        clientName = Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, _, replyKey, _ = kerberosv5.getKerberosTGT(clientName, '', REALM, '', '', certificate=self.credentials())
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)

        ccache = CCache()
        ccache.fromTGT(tgt, replyKey, replyKey)
        credential = ccache.credentials[0]
        self.assertEqual(credential['client'].prettyPrint(), b'%s@%s' % (CLIENT.encode(), REALM.encode()))
        self.assertEqual(credential['server'].prettyPrint(), b'krbtgt/%s@%s' % (REALM.encode(), REALM.encode()))

    def test_kdcVerificationCanBeDisabled(self):
        otherPki = PKI()
        otherPki.clientKey, otherPki.clientCertificate = self.pki.clientKey, self.pki.clientCertificate
        kdc = KDC(otherPki)
        _, _, replyKey, _ = self.getTGT(kdc, self.credentials(verifyKDC=False))
        self.assertEqual(replyKey.contents, kdc.replyKey.contents)


class CredentialsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    def test_upnIsReadFromTheCertificate(self):
        credentials = PKINITCredentials(self.pki.clientKey, self.pki.clientCertificate)
        self.assertEqual(credentials.getUPN(), '%s@contoso.com' % CLIENT)
        self.assertEqual(credentials.getPrincipal(), '%s@contoso.com' % CLIENT)

    def test_kerberosPrincipalIsReadFromTheCertificate(self):
        credentials = PKINITCredentials(self.pki.kdcKey, self.pki.kdcCertificate)
        self.assertEqual(credentials.getPrincipal(), 'krbtgt/%s@%s' % (REALM, REALM))

    def test_rootCertificatesAreNotSent(self):
        credentials = PKINITCredentials(self.pki.clientKey, self.pki.clientCertificate,
                                        [self.pki.caCertificate, self.pki.kdcCertificate])
        self.assertEqual(credentials.chain, [self.pki.kdcCertificate])

    def test_unknownKeyExchangeIsRejected(self):
        self.assertRaises(PKINITError, PKINITCredentials, self.pki.clientKey, self.pki.clientCertificate,
                          keyExchange='rc4')

    def test_pemFilesAreLoaded(self):
        import os
        import tempfile
        certificates = self.pki.clientCertificate.public_bytes(serialization.Encoding.PEM) + \
            self.pki.caCertificate.public_bytes(serialization.Encoding.PEM)
        key = self.pki.clientKey.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())
        certPath, keyPath = tempfile.mktemp(suffix='.crt'), tempfile.mktemp(suffix='.key')
        try:
            with open(certPath, 'wb') as fd:
                fd.write(certificates)
            with open(keyPath, 'wb') as fd:
                fd.write(key)
            credentials = PKINITCredentials.fromPEM(certPath, keyPath)
            self.assertEqual(credentials.certificate, self.pki.clientCertificate)
            # The root CA of the file is dropped, RFC 4556 3.2.1 forbids sending it
            self.assertEqual(credentials.chain, [])
            self.assertEqual(credentials.getUPN(), '%s@contoso.com' % CLIENT)
        finally:
            os.unlink(certPath)
            os.unlink(keyPath)

    def test_pfxIsLoadedFromMemory(self):
        data = serialization.pkcs12.serialize_key_and_certificates(
            b'client', self.pki.clientKey, self.pki.clientCertificate, None,
            serialization.BestAvailableEncryption(b'Passw0rd!'))
        credentials = PKINITCredentials.fromPFXData(data, 'Passw0rd!')
        self.assertEqual(credentials.certificate, self.pki.clientCertificate)
        self.assertEqual(credentials.getUPN(), '%s@contoso.com' % CLIENT)

    def test_pemIsLoadedFromMemory(self):
        certificate = self.pki.clientCertificate.public_bytes(serialization.Encoding.PEM)
        key = self.pki.clientKey.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())
        credentials = PKINITCredentials.fromPEMData(certificate, key)
        self.assertEqual(credentials.certificate, self.pki.clientCertificate)

    def test_pfxWithTheWrongPasswordIsReported(self):
        data = serialization.pkcs12.serialize_key_and_certificates(
            b'client', self.pki.clientKey, self.pki.clientCertificate, None,
            serialization.BestAvailableEncryption(b'Passw0rd!'))
        self.assertRaisesRegex(PKINITError, 'Could not load', PKINITCredentials.fromPFXData, data, 'wrong')

    def test_pfxRoundTrip(self):
        import os
        import tempfile
        data = serialization.pkcs12.serialize_key_and_certificates(
            b'client', self.pki.clientKey, self.pki.clientCertificate, [self.pki.caCertificate],
            serialization.BestAvailableEncryption(b'Passw0rd!'))
        handle, path = tempfile.mkstemp(suffix='.pfx')
        try:
            with os.fdopen(handle, 'wb') as fd:
                fd.write(data)
            credentials = PKINITCredentials.fromPFX(path, 'Passw0rd!')
            self.assertEqual(credentials.certificate, self.pki.clientCertificate)
            self.assertEqual(credentials.getUPN(), '%s@contoso.com' % CLIENT)
        finally:
            os.unlink(path)


class HostileKDCTests(unittest.TestCase):
    """A KDC that answers malformed or degenerate replies must get a clean error, never a traceback."""

    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    def setUp(self):
        self.sendReceive = kerberosv5.sendReceive

    def tearDown(self):
        kerberosv5.sendReceive = self.sendReceive

    def getTGT(self, mutate, kdcKwargs=None, **credentialKwargs):
        kdc = KDC(self.pki, **(kdcKwargs or {}))
        original = kdc.sendReceive

        def sendReceive(data, host, kdcHost, port=88):
            kdc.lastNonce = int(decoder.decode(data, asn1Spec=AS_REQ())[0]['req-body']['nonce'])
            return mutate(kdc, original(data, host, kdcHost, port))

        kerberosv5.sendReceive = sendReceive
        credentials = PKINITCredentials(self.pki.clientKey, self.pki.clientCertificate, [], **credentialKwargs)
        clientName = Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        return PKINIT(clientName, REALM, credentials).getTGT()

    def setPaPkAsRep(self, asRep, paPkAsRep):
        for padata in asRep['padata']:
            if int(padata['padata-type']) == constants.PreAuthenticationDataTypes.PA_PK_AS_REP.value:
                padata['padata-value'] = paPkAsRep
        return encoder.encode(asRep)

    def signedDHKeyInfo(self, kdc, subjectPublicKey):
        keyInfo = KDCDHKeyInfo()
        setComponent(keyInfo, 'subjectPublicKey', hexValue=hexlify(subjectPublicKey).decode('ascii'))
        keyInfo['nonce'] = kdc.lastNonce
        paPkAsRep = PA_PK_AS_REP()
        dhRepInfo = paPkAsRep.setComponentByName('dhInfo').getComponentByName('dhInfo')
        dhRepInfo['dhSignedData'] = buildSignedData(self.pki.kdcKey, self.pki.kdcCertificate, [],
                                                    ID_PKINIT_DHKEYDATA, encoder.encode(keyInfo), 'sha256')
        return encoder.encode(paPkAsRep)

    def test_truncatedReplyIsReported(self):
        with self.assertRaisesRegex(PKINITError, 'Could not parse the AS-REP'):
            self.getTGT(lambda kdc, response: response[:40])

    def test_replyThatIsNotAnAsRepIsReported(self):
        with self.assertRaisesRegex(PKINITError, 'Could not parse the AS-REP'):
            self.getTGT(lambda kdc, response: b'\x30\x03\x02\x01\x01')

    def test_unknownReplyEnctypeIsReported(self):
        def mutate(kdc, response):
            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
            asRep['enc-part']['etype'] = 999
            return encoder.encode(asRep)
        with self.assertRaisesRegex(PKINITError, 'unsupported encryption type 999'):
            self.getTGT(mutate)

    def test_garbagePaPkAsRepIsReported(self):
        def mutate(kdc, response):
            return self.setPaPkAsRep(decoder.decode(response, asn1Spec=AS_REP())[0], b'\x04\x02\xff\xff')
        with self.assertRaisesRegex(PKINITError, 'Could not parse the PA-PK-AS-REP'):
            self.getTGT(mutate)

    def test_emptySignedDataIsReported(self):
        def mutate(kdc, response):
            paPkAsRep = PA_PK_AS_REP()
            dhRepInfo = paPkAsRep.setComponentByName('dhInfo').getComponentByName('dhInfo')
            dhRepInfo['dhSignedData'] = b''
            return self.setPaPkAsRep(decoder.decode(response, asn1Spec=AS_REP())[0], encoder.encode(paPkAsRep))
        with self.assertRaisesRegex(PKINITError, 'Could not parse the CMS ContentInfo'):
            self.getTGT(mutate)

    def test_signedDataWithoutContentIsReported(self):
        def mutate(kdc, response):
            signedData = rfc5652.SignedData()
            signedData['version'] = 3
            signedData['encapContentInfo']['eContentType'] = univ.ObjectIdentifier(ID_PKINIT_DHKEYDATA)
            paPkAsRep = PA_PK_AS_REP()
            dhRepInfo = paPkAsRep.setComponentByName('dhInfo').getComponentByName('dhInfo')
            dhRepInfo['dhSignedData'] = buildContentInfo('1.2.840.113549.1.7.2', encoder.encode(signedData))
            return self.setPaPkAsRep(decoder.decode(response, asn1Spec=AS_REP())[0], encoder.encode(paPkAsRep))
        with self.assertRaisesRegex(PKINITError, 'carries no content'):
            self.getTGT(mutate)

    def test_degenerateDiffieHellmanPublicValuesAreRejected(self):
        prime = DH_GROUPS[14][0]
        for value in (0, 1, prime - 1, prime, prime + 1):
            def mutate(kdc, response, value=value):
                return self.setPaPkAsRep(decoder.decode(response, asn1Spec=AS_REP())[0],
                                         self.signedDHKeyInfo(kdc, encoder.encode(univ.Integer(value))))
            with self.assertRaisesRegex(PKINITError, 'invalid Diffie-Hellman public value'):
                self.getTGT(mutate)

    def test_malformedDiffieHellmanPublicValueIsReported(self):
        def mutate(kdc, response):
            return self.setPaPkAsRep(decoder.decode(response, asn1Spec=AS_REP())[0],
                                     self.signedDHKeyInfo(kdc, b'\xff\xff'))
        with self.assertRaisesRegex(PKINITError, 'Could not parse the Diffie-Hellman public value'):
            self.getTGT(mutate)

    def test_pointNotOnTheCurveIsRejected(self):
        def mutate(kdc, response):
            return self.setPaPkAsRep(decoder.decode(response, asn1Spec=AS_REP())[0],
                                     self.signedDHKeyInfo(kdc, b'\x04' + b'\x01' * 64))
        with self.assertRaisesRegex(PKINITError, 'invalid P-256 public value'):
            self.getTGT(mutate, keyExchange='ecdh')

    def test_malformedOCSPResponseIsIgnored(self):
        def mutate(kdc, response):
            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
            position = len(asRep['padata'])
            asRep['padata'][position] = univ.noValue
            asRep['padata'][position]['padata-type'] = int(
                constants.PreAuthenticationDataTypes.PA_PK_OCSP_RESPONSE.value)
            asRep['padata'][position]['padata-value'] = b'\xff\xff\xff'
            return encoder.encode(asRep)
        self.getTGT(mutate, requestOCSP=True)

    def test_signedDataWithoutSignedAttributesIsRejected(self):
        # RFC 4556 3.2.3.1: the content-type signed attribute must be present
        def mutate(kdc, response):
            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
            keyInfo = KDCDHKeyInfo()
            setComponent(keyInfo, 'subjectPublicKey', hexValue=hexlify(encoder.encode(univ.Integer(2))).decode())
            keyInfo['nonce'] = kdc.lastNonce
            content = encoder.encode(keyInfo)

            signerInfo = rfc5652.SignerInfo()
            signerInfo['version'] = 1
            signerInfo['sid'] = buildSignerIdentifier(self.pki.kdcCertificate)
            signerInfo['digestAlgorithm'] = buildAlgorithmIdentifier('2.16.840.1.101.3.4.2.1')
            signerInfo['signatureAlgorithm'] = getSignatureAlgorithm(self.pki.kdcKey, 'sha256')
            signerInfo['signature'] = signData(self.pki.kdcKey, content, 'sha256')

            signedData = rfc5652.SignedData()
            signedData['version'] = 3
            signedData['digestAlgorithms'].setComponentByPosition(
                0, buildAlgorithmIdentifier('2.16.840.1.101.3.4.2.1'))
            signedData['encapContentInfo']['eContentType'] = univ.ObjectIdentifier(ID_PKINIT_DHKEYDATA)
            signedData['encapContentInfo']['eContent'] = content
            signedData['certificates'] = buildCertificateSet([self.pki.kdcCertificate])
            signedData['signerInfos'].setComponentByPosition(0, signerInfo)

            paPkAsRep = PA_PK_AS_REP()
            dhRepInfo = paPkAsRep.setComponentByName('dhInfo').getComponentByName('dhInfo')
            dhRepInfo['dhSignedData'] = buildContentInfo('1.2.840.113549.1.7.2', encoder.encode(signedData))
            return self.setPaPkAsRep(asRep, encoder.encode(paPkAsRep))
        with self.assertRaisesRegex(PKINITError, 'no signed attributes'):
            self.getTGT(mutate)

    def patchEnvelopedData(self, patch):
        """Return a mutation that rewrites the EnvelopedData of an encKeyPack reply."""
        def mutate(kdc, response):
            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
            for padata in asRep['padata']:
                if int(padata['padata-type']) != constants.PreAuthenticationDataTypes.PA_PK_AS_REP.value:
                    continue
                paPkAsRep = decoder.decode(padata['padata-value'], asn1Spec=PA_PK_AS_REP())[0]
                contentInfo = decoder.decode(bytes(paPkAsRep.getComponent()), asn1Spec=rfc5652.ContentInfo())[0]
                enveloped = decoder.decode(bytes(contentInfo['content']), asn1Spec=rfc5652.EnvelopedData())[0]
                patch(enveloped)
                newPack = PA_PK_AS_REP()
                newPack['encKeyPack'] = buildContentInfo(ID_ENVELOPED_DATA, encoder.encode(enveloped))
                padata['padata-value'] = encoder.encode(newPack)
            return encoder.encode(asRep)
        return mutate

    def test_truncatedEnvelopedContentIsReported(self):
        def patch(enveloped):
            enveloped['encryptedContentInfo']['encryptedContent'] = b'\x01\x02\x03'
        with self.assertRaisesRegex(PKINITError, 'Could not decrypt the enveloped content'):
            self.getTGT(self.patchEnvelopedData(patch), {'useEncKeyPack': True}, keyExchange='rsa')

    def test_corruptedEncryptedKeyIsReported(self):
        def patch(enveloped):
            enveloped['recipientInfos'][0]['ktri']['encryptedKey'] = b'\x00' * 256
        with self.assertRaises(PKINITError):
            self.getTGT(self.patchEnvelopedData(patch), {'useEncKeyPack': True}, keyExchange='rsa')

    def test_badInitializationVectorIsReported(self):
        def patch(enveloped):
            algorithm = enveloped['encryptedContentInfo']['contentEncryptionAlgorithm']
            algorithm['parameters'] = univ.Any(encoder.encode(univ.OctetString(b'\x00' * 3)))
        with self.assertRaisesRegex(PKINITError, 'Could not decrypt the enveloped content'):
            self.getTGT(self.patchEnvelopedData(patch), {'useEncKeyPack': True}, keyExchange='rsa')

    def test_envelopedDataWithoutRecipientIsReported(self):
        def tlv(tag, payload):
            return bytes([tag, len(payload)]) + payload
        algorithm = tlv(0x30, bytes.fromhex('0609608648016503040102'))
        encryptedContentInfo = tlv(0x30, bytes.fromhex('06092A864886F70D010701') + algorithm)
        enveloped = tlv(0x30, tlv(0x02, b'\x00') + tlv(0x31, b'') + encryptedContentInfo)
        with self.assertRaisesRegex(PKINITError, 'single recipientInfo'):
            decryptEnvelopedData(buildContentInfo(ID_ENVELOPED_DATA, enveloped), self.pki.clientKey)

    def test_undecryptableReplyIsReported(self):
        def mutate(kdc, response):
            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
            asRep['enc-part']['cipher'] = b'\x00' * 64
            return encoder.encode(asRep)
        with self.assertRaisesRegex(PKINITError, 'does not decrypt the AS-REP'):
            self.getTGT(mutate)


class FuzzedReplyTests(unittest.TestCase):
    """Corrupting the bytes of a valid reply must never escape as an unrelated exception."""

    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    def setUp(self):
        self.sendReceive = kerberosv5.sendReceive

    def tearDown(self):
        kerberosv5.sendReceive = self.sendReceive

    def fuzz(self, keyExchange, kdcKwargs, iterations=150):
        import random
        random.seed('%s-pkinit' % keyExchange)
        clientName = Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        for _ in range(iterations):
            kdc = KDC(self.pki, **kdcKwargs)
            original = kdc.sendReceive

            def sendReceive(data, host, kdcHost, port=88, original=original):
                response = bytearray(original(data, host, kdcHost, port))
                for _ in range(random.randint(1, 12)):
                    response[random.randrange(len(response))] = random.randrange(256)
                return bytes(response)

            kerberosv5.sendReceive = sendReceive
            credentials = PKINITCredentials(self.pki.clientKey, self.pki.clientCertificate, [],
                                            keyExchange=keyExchange, requestOCSP=True)
            try:
                PKINIT(clientName, REALM, credentials).getTGT()
            except (PKINITError, kerberosv5.KerberosError):
                pass
            except Exception as e:
                self.fail('a corrupted %s reply escaped as %s: %s' % (keyExchange, type(e).__name__, e))

    def test_fuzzedDiffieHellmanReplies(self):
        self.fuzz('dh', {})

    def test_fuzzedEllipticCurveReplies(self):
        self.fuzz('ecdh', {})

    def test_fuzzedKeyTransportReplies(self):
        self.fuzz('rsa', {'useEncKeyPack': True})


if __name__ == '__main__':
    unittest.main(verbosity=1)
