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
#   PKU2U (Public Key User-to-User) Authentication
#   Based on draft-zhu-pku2u-09. No other microsoft open specification was found on the protocol.
#
#   Implements a GSS-API mechanism using public key cryptography
#   for peer-to-peer authentication without requiring a KDC. Mainly used for Hyrid/Entra ID joined devices
#   PKU2U is Negotiated via MS-NEGOEX, which has been fully implemented
#
# References:
#   draft-zhu-pku2u-09 the PKU2U specification
#   RFC 4556 PKINIT
#   Skelsecs Implementation of PKU2U
#
# Author:
#   Abdul Mhanni

import datetime
import hashlib
import os
import random as rand
import struct

from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from pyasn1_modules import rfc5280

from impacket.krb5 import constants, crypto
from impacket.krb5.asn1 import AS_REQ, AS_REP, AP_REQ, AP_REP, KRB_ERROR, Authenticator, EncASRepPart, EncryptedData, Checksum, EncryptionKey, PrincipalName, KerberosTime, AuthorizationData, Int32, UInt32, seq_set, seq_set_iter, _sequence_component, _sequence_optional_component
from impacket.krb5.types import Principal, KerberosTime as KerberosTimeHelper
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import MechIndepToken
from impacket import LOG

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

# Import PKINIT types and helpers from the shared pkinit module
from impacket.krb5.pkinit import PKAuthenticator, AuthPack, PA_PK_AS_REP, DHRepInfo, KDCDHKeyInfo, ReplyKeyPack, ExternalPrincipalIdentifier, DiffieHellman, DH_P, DH_G, signAuthPack, extractSignedContent, buildPaPkAsReq, truncateKey, _buildDERSequence, _buildDERExplicit, _buildDEROctetString, _buildDEROID, id_pkinit_authData, id_pkinit_DHKeyData

################################################################################
#Constants
################################################################################

# draft-zhu-pku2u-09 Section 6:
#   "id-kerberos-pku2u ::=
#    { iso(1) org(3) dod(6) internet(1) security(5) kerberosV5(2) pku2u(7) }"
PKU2U_OID = univ.ObjectIdentifier((1, 3, 6, 1, 5, 2, 7))
PKU2U_OID_RAW = b'\x06\x06\x2b\x06\x01\x05\x02\x07'

# draft-zhu-pku2u-09 Section 6 (token type IDs):
#   "KRB_AS_REQ  05 00"
#   "KRB_AS_REP  06 00"
# Remaining TOK_IDs from RFC 4121 Section 4.1.
TOK_ID_KRB_AS_REQ = b'\x05\x00'
TOK_ID_KRB_AS_REP = b'\x06\x00'
TOK_ID_KRB_AP_REQ = b'\x01\x00'
TOK_ID_KRB_AP_REP = b'\x02\x00'
TOK_ID_KRB_ERROR  = b'\x03\x00'

# draft-zhu-pku2u-09 Section 3
PKU2U_REALM = 'WELLKNOWN:PKU2U'

# draft-zhu-pku2u-09 Section 6.1: "PA_PKU2U_NAME <136>"
PA_PKU2U_NAME = 136

# draft-zhu-pku2u-09 Section 6.2: "ad-pku2u-client-name <143>"
AD_PKU2U_CLIENT_NAME = 143

# draft-zhu-pku2u-09 Section 6.3: "GSS_EXTS_FINISHED  2"
GSS_EXTS_FINISHED = 2

# draft-zhu-pku2u-09 Section 6.3: "KEY_USAGE_FINISHED <41>"
KEY_USAGE_FINISHED = 41

# RFC 6111 / draft-zhu-pku2u-09 Section 4
KRB_NT_WELLKNOWN = 11

# [MS-SPNG] Appendix A:
#   "PKU2U ... (1.3.6.1.5.2.7) 235F69AD-73FB-4dbc-8203-0629E739339B"
PKU2U_NEGOEX_AUTH_SCHEME = (
    b'\xad\x69\x5f\x23\xfb\x73\xbc\x4d'
    b'\x82\x03\x06\x29\xe7\x39\x33\x9b'
)



# PKU2U ASN.1 Types (draft-zhu-pku2u-09 Section 6.1 / 6.3)

class InitiatorName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sanIndex', univ.Integer()),
        namedtype.NamedType('nameNotInCert', rfc5280.GeneralName()),
    )


class TargetName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('exportedTargName', univ.OctetString()),
        namedtype.NamedType('generalName', rfc5280.GeneralName().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )


class InitiatorNameAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('initiatorName', InitiatorName()),
        namedtype.OptionalNamedType('targetName', TargetName()),
    )

# draft-zhu-pku2u-09 Section 6.3
class KRB_FINISHED(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('gss-mic', 1, Checksum()),
    )


# draft-zhu-pku2u-09 Section 6 and RFC 2743 Section 3.1
def wrapInitialContextToken(tokId, krbMessage):
    innerToken = tokId + krbMessage
    token = MechIndepToken(innerToken, PKU2U_OID_RAW)
    header, data = token.to_bytes()
    return header + data

def unwrapInitialContextToken(tokenData):
    token = MechIndepToken.from_bytes(tokenData)
    tokId = token.data[:2]
    krbMessage = token.data[2:]
    return tokId, krbMessage, token.token_oid


# NULL Principal (draft-zhu-pku2u-09 Section 4)
def getNullPrincipal():
    p = Principal()
    p.type = KRB_NT_WELLKNOWN
    p.components = ['WELLKNOWN', 'NULL']
    p.realm = PKU2U_REALM
    return p


# Certificate Matching (draft-zhu-pku2u-09 Section 5.6)
def matchCertToHostname(cert, hostname, serviceName='host'):
    hostname = hostname.lower()

    # Rule 3: dNSName SAN + EKU
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dnsNames = san.value.get_values_for_type(x509.DNSName)
        for dnsName in dnsNames:
            if dnsName.lower() == hostname or _matchWildcard(dnsName, hostname):
                if _checkEKUForService(cert, serviceName):
                    return True
    except x509.ExtensionNotFound:
        pass

    # Rule 4: CN in subject DN
    try:
        cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        for cn in cns:
            if cn.value.lower() == hostname:
                return True
    except Exception:
        pass

    return False

def _matchWildcard(pattern, hostname):
    pattern = pattern.lower()
    hostname = hostname.lower()
    if pattern.startswith('*.'):
        suffix = pattern[2:]
        parts = hostname.split('.', 1)
        if len(parts) == 2 and parts[1] == suffix:
            return True
    return False

def _checkEKUForService(cert, serviceName):
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        ekuOids = list(eku.value)
        anyEku = x509.ObjectIdentifier('2.5.29.37.0')
        if anyEku in ekuOids:
            return True
        if ExtendedKeyUsageOID.SERVER_AUTH in ekuOids:
            return True
        return False
    except x509.ExtensionNotFound:
        return True

################################################################################
# PKU2U AS Exchange draft Section 6.1 / 6.2
################################################################################

def buildPKU2UASReq(certificate, privateKey, targetName, clientName=None, nonce=None):
    if nonce is None:
        nonce = rand.getrandbits(31)

    diffie = DiffieHellman()

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    reqBody = seq_set(asReq, 'req-body')
    #Section 6.1 states the kdc-options should be empty by the initator/client 
    reqBody['kdc-options'] = constants.encodeFlags([])
    reqBody['realm'] = PKU2U_REALM

    useNullCname = False
    if clientName is not None:
        if isinstance(clientName, str):
            clientName = Principal(clientName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)
    else:
        nullPrinc = getNullPrincipal()
        seq_set(reqBody, 'cname', nullPrinc.components_to_asn1)
        useNullCname = True

    if isinstance(targetName, str):
        sname = Principal('host/%s' % targetName, type=constants.PrincipalNameType.NT_SRV_HST.value)
        seq_set(reqBody, 'sname', sname.components_to_asn1)
    elif isinstance(targetName, Principal):
        seq_set(reqBody, 'sname', targetName.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    reqBody['till'] = KerberosTimeHelper.to_asn1(now + datetime.timedelta(days=1))
    reqBody['nonce'] = nonce
    seq_set_iter(reqBody, 'etype', (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ))

    #paChecksum is SHA-1 per RFC 4556 Section 3.2.1
    reqBodyDER = encoder.encode(reqBody)
    paChecksum = hashlib.sha1(reqBodyDER).digest()

    pkAuth = PKAuthenticator()
    pkAuth['cusec'] = now.microsecond
    pkAuth['ctime'] = KerberosTimeHelper.to_asn1(now)
    pkAuth['nonce'] = nonce
    pkAuth['paChecksum'] = paChecksum

    dhPubKey = diffie.getPublicKey()
    domainParamsDER = _buildDERSequence(
        encoder.encode(univ.Integer(diffie.p)) +
        encoder.encode(univ.Integer(diffie.g)) +
        encoder.encode(univ.Integer(0))
    )
    algIdDER = _buildDERSequence(_buildDEROID('1.2.840.10046.2.1') + domainParamsDER)
    pubKeyIntDER = encoder.encode(univ.Integer(dhPubKey))
    pubKeyBitString = univ.BitString(hexValue=pubKeyIntDER.hex())
    spkiDER = _buildDERSequence(algIdDER + encoder.encode(pubKeyBitString))

    pkAuthDER = encoder.encode(pkAuth)
    authPackDER = _buildDERSequence(
        _buildDERExplicit(0, pkAuthDER) +
        _buildDERExplicit(1, spkiDER) +
        _buildDERExplicit(3, _buildDEROctetString(diffie.dhNonce))
    )

    signedAuthPack = signAuthPack(authPackDER, certificate, privateKey)
    paPkAsReqDER = buildPaPkAsReq(signedAuthPack)

    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PK_AS_REQ.value)
    asReq['padata'][0]['padata-value'] = paPkAsReqDER

    if useNullCname:
        nameAssertion = InitiatorNameAssertion()
        initName = InitiatorName()
        initName['sanIndex'] = -1
        nameAssertion['initiatorName'] = initName
        asReq['padata'][1] = noValue
        asReq['padata'][1]['padata-type'] = PA_PKU2U_NAME
        asReq['padata'][1]['padata-value'] = encoder.encode(nameAssertion)

    asReqEncoded = encoder.encode(asReq)
    wrappedToken = wrapInitialContextToken(TOK_ID_KRB_AS_REQ, asReqEncoded)
    return wrappedToken, diffie, nonce

def processPKU2UASRep(tokenData, diffie, expectedNonce):
    try:
        tokId, krbMessage, oid = unwrapInitialContextToken(tokenData)
    except Exception:
        tokId = tokenData[:2]
        krbMessage = tokenData[2:]

    if tokId == TOK_ID_KRB_ERROR:
        krbError = decoder.decode(krbMessage, asn1Spec=KRB_ERROR())[0]
        raise Exception('PKU2U KRB-ERROR: error-code %d' % int(krbError['error-code']))

    if tokId != TOK_ID_KRB_AS_REP:
        raise Exception('Expected AS-REP (0x0600), got 0x%s' % tokId.hex())

    asRep = decoder.decode(krbMessage, asn1Spec=AS_REP())[0]

    # Extract PA-PK-AS-REP
    paPkAsRepDER = None
    if asRep['padata'].hasValue():
        for pa in asRep['padata']:
            if int(pa['padata-type']) == int(constants.PreAuthenticationDataTypes.PA_PK_AS_REP.value):
                paPkAsRepDER = bytes(pa['padata-value'])
                break

    if paPkAsRepDER is None:
        raise Exception('No PA-PK-AS-REP in AS-REP')

    paPkAsRep = decoder.decode(paPkAsRepDER, asn1Spec=PA_PK_AS_REP())[0]
    dhInfo = paPkAsRep['dhInfo']
    dhSignedData = bytes(dhInfo['dhSignedData'])
    serverDHNonce = None
    if dhInfo['serverDHNonce'].hasValue():
        serverDHNonce = bytes(dhInfo['serverDHNonce'])

    contentBytes, contentType = extractSignedContent(dhSignedData)
    kdcDHKeyInfo = decoder.decode(contentBytes, asn1Spec=KDCDHKeyInfo())[0]

    replyNonce = int(kdcDHKeyInfo['nonce'])
    if replyNonce != expectedNonce:
        raise Exception('Nonce mismatch: expected %d, got %d' % (expectedNonce, replyNonce))

    serverPubKeyDER = bytes(kdcDHKeyInfo['subjectPublicKey'])
    serverPubKeyInt, _ = decoder.decode(serverPubKeyDER, asn1Spec=univ.Integer())
    serverPublicKey = int(serverPubKeyInt)

    sharedKey = diffie.exchange(serverPublicKey)
    if serverDHNonce is not None:
        fullKey = sharedKey + diffie.dhNonce + serverDHNonce
    else:
        fullKey = sharedKey

    enctype = int(asRep['enc-part']['etype'])
    cipher = _enctype_table[enctype]
    if enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        tKey = truncateKey(fullKey, 32)
    elif enctype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        tKey = truncateKey(fullKey, 16)
    else:
        raise Exception('Unsupported enctype %d' % enctype)

    sessionKey = Key(cipher.enctype, tKey)
    cipherText = bytes(asRep['enc-part']['cipher'])
    plainText = cipher.decrypt(sessionKey, 3, cipherText)
    encAsRepPart = decoder.decode(plainText, asn1Spec=EncASRepPart())[0]

    realEnctype = int(encAsRepPart['key']['keytype'])
    realCipher = _enctype_table[realEnctype]
    realSessionKey = Key(realCipher.enctype, bytes(encAsRepPart['key']['keyvalue']))

    return asRep['ticket'], realSessionKey, realEnctype

################################################################################
# PKU2U AP Exchange in draft-zhu-pku2u-09 Section 6.3
################################################################################

def buildPKU2UAPReq(sessionKey, ticket, precedingTokens=None, sequenceNumber=None):
    if sequenceNumber is None:
        sequenceNumber = rand.getrandbits(31)

    enctype = sessionKey.enctype
    cipher = _enctype_table[enctype]

    # draft Section 6.3 states that The sub-session key is the one to use
    subKeyMaterial = os.urandom(cipher.keysize)
    subKey = Key(enctype, subKeyMaterial)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = PKU2U_REALM
    nullPrinc = getNullPrincipal()
    seq_set(authenticator, 'cname', nullPrinc.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTimeHelper.to_asn1(now)
    authenticator['seq-number'] = sequenceNumber

    authenticator['subkey'] = noValue
    authenticator['subkey']['keytype'] = subKey.enctype
    authenticator['subkey']['keyvalue'] = subKey.contents

    #Section 6.3, GSS_EXTS_FINISHED checksum over preceding tokens
    if precedingTokens is not None and len(precedingTokens) > 0:
        allPrecedingData = b''.join(precedingTokens)

        if enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            checksumType = constants.ChecksumTypes.hmac_sha1_96_aes256.value
        elif enctype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            checksumType = constants.ChecksumTypes.hmac_sha1_96_aes128.value
        else:
            checksumType = constants.ChecksumTypes.hmac_md5.value

        checksumEngine = crypto._checksum_table[checksumType]
        checksumValue = checksumEngine.checksum(subKey, KEY_USAGE_FINISHED, allPrecedingData)

        krbFinished = KRB_FINISHED()
        krbFinished['gss-mic'] = noValue
        krbFinished['gss-mic']['cksumtype'] = checksumType
        krbFinished['gss-mic']['checksum'] = checksumValue
        krbFinishedEncoded = encoder.encode(krbFinished)

        authenticator['authorization-data'] = noValue
        authenticator['authorization-data'][0] = noValue
        authenticator['authorization-data'][0]['ad-type'] = GSS_EXTS_FINISHED
        authenticator['authorization-data'][0]['ad-data'] = krbFinishedEncoded

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    apReq['ap-options'] = constants.encodeFlags([])
    apReq.setComponentByName('ticket', ticket)

    encodedAuthenticator = encoder.encode(authenticator)
    encryptedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)
    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedAuthenticator

    wrappedToken = wrapInitialContextToken(TOK_ID_KRB_AP_REQ, encoder.encode(apReq))
    return wrappedToken, subKey, sequenceNumber

def processPKU2UAPRep(tokenData, subKey):
    try:
        tokId, krbMessage, oid = unwrapInitialContextToken(tokenData)
    except Exception:
        tokId = tokenData[:2]
        krbMessage = tokenData[2:]

    if tokId == TOK_ID_KRB_ERROR:
        krbError = decoder.decode(krbMessage, asn1Spec=KRB_ERROR())[0]
        raise Exception('PKU2U AP-REP KRB-ERROR: error-code %d' % int(krbError['error-code']))

    apRep = decoder.decode(krbMessage, asn1Spec=AP_REP())[0]
    enctype = int(apRep['enc-part']['etype'])
    cipher = _enctype_table[enctype]

    from impacket.krb5.asn1 import EncAPRepPart
    plainText = cipher.decrypt(subKey, 12, bytes(apRep['enc-part']['cipher']))
    encApRepPart = decoder.decode(plainText, asn1Spec=EncAPRepPart())[0]

    acceptorSubKey = None
    if encApRepPart['subkey'].hasValue():
        aEnctype = int(encApRepPart['subkey']['keytype'])
        acceptorSubKey = Key(_enctype_table[aEnctype].enctype,
                             bytes(encApRepPart['subkey']['keyvalue']))

    seqNumber = None
    if encApRepPart['seq-number'].hasValue():
        seqNumber = int(encApRepPart['seq-number'])

    return acceptorSubKey, seqNumber

################################################################################
# PKU2U Context State Machine
################################################################################

class PKU2UContext(object):
    STATE_INITIAL  = 0
    STATE_AS_REQ   = 1
    STATE_AP_REQ   = 2
    STATE_COMPLETE = 3

    def __init__(self, certificate, privateKey, targetName):
        self.certificate = certificate
        self.privateKey = privateKey
        self.targetName = targetName
        self.state = self.STATE_INITIAL
        self.sessionKey = None
        self.subKey = None
        self.sequenceNumber = None
        self.diffie = None
        self.nonce = None
        self.ticket = None
        self.precedingTokens = []

    def step(self, inputToken=None):
        if self.state == self.STATE_INITIAL:
            outputToken, self.diffie, self.nonce = buildPKU2UASReq(
                self.certificate, self.privateKey, self.targetName
            )
            self.precedingTokens.append(outputToken)
            self.state = self.STATE_AS_REQ
            return outputToken

        elif self.state == self.STATE_AS_REQ:
            if inputToken is None:
                raise Exception('Expected AS-REP token')
            self.precedingTokens.append(inputToken)
            self.ticket, self.sessionKey, enctype = processPKU2UASRep(
                inputToken, self.diffie, self.nonce
            )
            outputToken, self.subKey, self.sequenceNumber = buildPKU2UAPReq(
                self.sessionKey, self.ticket, self.precedingTokens
            )
            self.precedingTokens.append(outputToken)
            self.state = self.STATE_AP_REQ
            return outputToken

        elif self.state == self.STATE_AP_REQ:
            if inputToken is None:
                raise Exception('Expected AP-REP token')
            acceptorSubKey, seqNumber = processPKU2UAPRep(inputToken, self.subKey)
            if acceptorSubKey is not None:
                self.sessionKey = acceptorSubKey
            self.state = self.STATE_COMPLETE
            return None

        else:
            raise Exception('PKU2U context already established')

    def isEstablished(self):
        return self.state == self.STATE_COMPLETE

def createNegoExContext(certificate, privateKey, targetName):
    return PKU2UContext(certificate, privateKey, targetName)

def getAuthSchemeId(self):
    return PKU2U_NEGOEX_AUTH_SCHEME

def getVerifyKey(self):
    # Key is available once AS exchange completes and we have a session key
    if self.sessionKey is None:
        return None
    if self.sessionKey.enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        checksumType = constants.ChecksumTypes.hmac_sha1_96_aes256.value
    elif self.sessionKey.enctype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        checksumType = constants.ChecksumTypes.hmac_sha1_96_aes128.value
    else:
        return None
    return self.sessionKey.contents, self.sessionKey.enctype, checksumType
