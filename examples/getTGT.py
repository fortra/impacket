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
#   Given a password, hash or aesKey, it will request a TGT and save it as ccache.
#
#   Silo / FAST support (added): when armor options are supplied it performs a
#   Kerberos-armored AS-REQ (FAST, RFC 6113). This is required to obtain a TGT for
#   accounts protected by an Authentication Policy Silo whose policy restricts the
#   devices/silo a user may authenticate from (un-armored requests get KDC_ERR_POLICY).
#
#   The armor TGT is provided by the user, never read from a keytab:
#     * a machine account (password / NT hash / aesKey), or
#     * an existing ccache (-armor-ccache or the KRB5CCNAME env var).
#
#   Examples:
#       ./getTGT.py -hashes lm:nt contoso.com/user
#       ./getTGT.py contoso.com/user -password P@ss -dc-ip 10.0.0.1 \
#                   -armor-account WS01$ -armor-password Machine123
#       KRB5CCNAME=armor.ccache ./getTGT.py contoso.com/user -aesKey <hex> -dc-ip 10.0.0.1
#       ./getTGT.py -selftest        # offline unit checks (no network)
#
# Author:
#   Alberto Solino (@agsolino)
#   FAST/silo support added on top of the original example.
#

import argparse
import datetime
import logging
import os
import random
import sys
from binascii import unhexlify

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder, decoder

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_identity
from impacket.krb5 import constants
from impacket.krb5.asn1 import (AS_REQ, AS_REP, EncASRepPart, KRB_ERROR, METHOD_DATA, ETYPE_INFO2,
                                PA_ENC_TS_ENC, AP_REQ, Authenticator, EncryptedData,
                                EncryptionKey, Checksum, KDC_REQ_BODY, PA_DATA,
                                KerberosFlags, Int32, Microseconds, Realm, PrincipalName,
                                KerberosTime as KerberosTimeASN1, KERB_PA_PAC_REQUEST,
                                PA_PAC_OPTIONS, AuthorizationData, seq_set, seq_set_iter,
                                _sequence_component, _sequence_optional_component)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum, make_checksum, cf2
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive, KerberosError
from impacket.krb5.types import Principal, Ticket, KerberosTime

# ---------------------------------------------------------------------------
# FAST (RFC 6113) constants
# ---------------------------------------------------------------------------
KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1
KEY_USAGE_AS_REP_ENCPART          = 3
KEY_USAGE_AP_REQ_AUTHENTICATOR    = 11
KEY_USAGE_FAST_REQ_CHKSUM         = 50
KEY_USAGE_FAST_ENC                = 51
KEY_USAGE_FAST_REP                = 52
KEY_USAGE_ENC_CHALLENGE_CLIENT    = 54

FX_FAST_ARMOR_AP_REQUEST = 1
PA_FX_FAST_TYPE          = int(constants.PreAuthenticationDataTypes.PA_FX_FAST.value)  # 136
PA_FX_COOKIE_TYPE        = int(constants.PreAuthenticationDataTypes.PA_FX_COOKIE.value)  # 133
PA_ENCRYPTED_CHALLENGE_TYPE = int(constants.PreAuthenticationDataTypes.PA_ENCRYPTED_CHALLENGE.value)  # 138
PA_ENC_TIMESTAMP_TYPE    = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)  # 2
PA_PAC_REQUEST_TYPE      = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)  # 128
PA_ETYPE_INFO2_TYPE      = int(constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value)  # 19
PA_PAC_OPTIONS_TYPE      = int(constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value)  # 167

# required checksum type for each enctype (RFC 3962 / 4757)
_CKSUM_FOR_ENCTYPE = {
    constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value: constants.ChecksumTypes.hmac_sha1_96_aes256.value,
    constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value: constants.ChecksumTypes.hmac_sha1_96_aes128.value,
    constants.EncryptionTypes.rc4_hmac.value: constants.ChecksumTypes.hmac_md5.value,
}

# ---------------------------------------------------------------------------
# FAST ASN.1 structures (absent from impacket.krb5.asn1)
# ---------------------------------------------------------------------------
class KrbFastArmor(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('armor-type', 0, Int32()),
        _sequence_component('armor-value', 1, univ.OctetString()))


class KrbFastArmoredReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component('armor', 0, KrbFastArmor()),
        _sequence_component('req-checksum', 1, Checksum()),
        _sequence_component('enc-fast-req', 2, EncryptedData()))


class PA_FX_FAST_REQUEST(univ.Choice):
    componentType = namedtype.NamedTypes(
        _sequence_component('armored-data', 0, KrbFastArmoredReq()))


class KrbFastReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('fast-options', 0, KerberosFlags()),
        _sequence_component('padata', 1, univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('req-body', 2, KDC_REQ_BODY()))


class KrbFastArmoredRep(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('enc-fast-rep', 0, EncryptedData()))


class PA_FX_FAST_REPLY(univ.Choice):
    componentType = namedtype.NamedTypes(
        _sequence_component('armored-data', 0, KrbFastArmoredRep()))


class KrbFastFinished(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('timestamp', 0, KerberosTimeASN1()),
        _sequence_component('usec', 1, Microseconds()),
        _sequence_component('crealm', 2, Realm()),
        _sequence_component('cname', 3, PrincipalName()),
        _sequence_component('ticket-checksum', 4, Checksum()))


class KrbFastResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('padata', 0, univ.SequenceOf(componentType=PA_DATA())),
        _sequence_optional_component('strengthen-key', 1, EncryptionKey()),
        _sequence_optional_component('finished', 2, KrbFastFinished()),
        _sequence_component('nonce', 3, univ.Integer()))


def _fast_alt(choiceCls):
    """Empty, correctly context-tagged instance of a CHOICE's [0] alternative.

    pyasn1 refuses assigning a bare value to an explicitly-tagged CHOICE member,
    so we clone the schema alternative, fill it, then assign it back."""
    return choiceCls().componentType.getTypeByPosition(0).clone()


# KRB-FX-CF2 (RFC 6113 5.1) for the armor/reply keys is impacket.krb5.crypto.cf2,
# imported above; it takes an enctype (int), not a cipher object.


# ---------------------------------------------------------------------------
# helpers shared by the plain probe and the armored request
# ---------------------------------------------------------------------------
def _fill_req_body(body, clientName, serverName, domain, etypes, nonce, till):
    """Fill an (already correctly-tagged) KDC_REQ_BODY in place.

    Callers pass precomputed <nonce> and <till> so the inner FAST body, the outer
    AS-REQ body and the body used for the req-checksum all encode to identical bytes."""
    opts = [constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value]
    body['kdc-options'] = constants.encodeFlags(opts)
    seq_set(body, 'sname', serverName.components_to_asn1)
    seq_set(body, 'cname', clientName.components_to_asn1)
    body['realm'] = domain
    body['till'] = KerberosTime.to_asn1(till)
    body['rtime'] = KerberosTime.to_asn1(till)
    body['nonce'] = nonce
    seq_set_iter(body, 'etype', etypes)
    return body


def _pa_pac_request(include=True):
    pac = KERB_PA_PAC_REQUEST()
    pac['include-pac'] = include
    pa = PA_DATA()
    pa['padata-type'] = PA_PAC_REQUEST_TYPE
    pa['padata-value'] = encoder.encode(pac)
    return pa


def _pa_enc_timestamp(clientCipher, clientKey):
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = PA_ENC_TS_ENC()
    ts['patimestamp'] = KerberosTime.to_asn1(now)
    ts['pausec'] = now.microsecond
    enc = clientCipher.encrypt(clientKey, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
                               encoder.encode(ts), None)
    ed = EncryptedData()
    ed['etype'] = clientKey.enctype
    ed['cipher'] = enc
    pa = PA_DATA()
    pa['padata-type'] = PA_ENC_TIMESTAMP_TYPE
    pa['padata-value'] = encoder.encode(ed)
    return pa


def _pa_pac_options(flags=(0,)):
    """PA-PAC-OPTIONS (MS-KILE 2.2.10). Default: claims bit (0) - signals the KDC to
    perform claims/compound processing so the armoring device is surfaced for the
    AllowedToAuthenticateFrom (silo) access check."""
    opt = PA_PAC_OPTIONS()
    opt['flags'] = constants.encodeFlags(list(flags))
    pa = PA_DATA()
    pa['padata-type'] = PA_PAC_OPTIONS_TYPE
    pa['padata-value'] = encoder.encode(opt)
    return pa


def _pa_encrypted_challenge(clientKey, armorKey):
    """PA-ENCRYPTED-CHALLENGE (RFC 6113 5.4.6): the FAST preauth factor Windows expects.

    challenge key = CF2(armor key, client key, "clientchallengearmor", "challengelongterm")."""
    challengeKey = cf2(armorKey.enctype, armorKey, clientKey,
                       b'clientchallengearmor', b'challengelongterm')
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = PA_ENC_TS_ENC()
    ts['patimestamp'] = KerberosTime.to_asn1(now)
    ts['pausec'] = now.microsecond
    enc = _enctype_table[challengeKey.enctype].encrypt(
        challengeKey, KEY_USAGE_ENC_CHALLENGE_CLIENT, encoder.encode(ts), None)
    ed = EncryptedData()
    ed['etype'] = challengeKey.enctype
    ed['cipher'] = enc
    pa = PA_DATA()
    pa['padata-type'] = PA_ENCRYPTED_CHALLENGE_TYPE
    pa['padata-value'] = encoder.encode(ed)
    return pa


def _harvest_salt(clientName, domain, kdcHost):
    """Unarmored no-preauth probe: returns (enctype, salt bytes) from ETYPE-INFO2.

    This is answered with KDC_ERR_PREAUTH_REQUIRED (evaluated before the silo policy),
    so it works even for armor-required accounts."""
    serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    etypes = [constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
              constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
              constants.EncryptionTypes.rc4_hmac.value]
    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    asReq['padata'] = univ.noValue
    asReq['padata'][0] = univ.noValue
    asReq['padata'][0]['padata-type'] = PA_PAC_REQUEST_TYPE
    asReq['padata'][0]['padata-value'] = _pa_pac_request()['padata-value']
    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    _fill_req_body(seq_set(asReq, 'req-body'), clientName, serverName, domain, etypes,
                   random.getrandbits(31), till)

    r = sendReceive(encoder.encode(asReq), domain, kdcHost)
    # If we somehow got an AS-REP (preauth not required) there is no salt to parse.
    try:
        err = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
    except Exception:
        raise Exception('Expected KDC_ERR_PREAUTH_REQUIRED while harvesting salt')
    methods = decoder.decode(err['e-data'], asn1Spec=METHOD_DATA())[0]
    salts = {}
    for m in methods:
        if m['padata-type'] == PA_ETYPE_INFO2_TYPE:
            info = decoder.decode(m['padata-value'], asn1Spec=ETYPE_INFO2())[0]
            for e in info:
                salt = e['salt'].asOctets() if e['salt'].hasValue() else b''
                salts[int(e['etype'])] = salt
    for et in (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
               constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
               constants.EncryptionTypes.rc4_hmac.value):
        if et in salts:
            return et, salts[et]
    raise Exception('No usable ETYPE-INFO2 returned by the KDC')


# ---------------------------------------------------------------------------
# armor TGT (from user-supplied machine creds or an existing ccache)
# ---------------------------------------------------------------------------
def _request_device_tgt(principal, password, lmhash, nthash, aesKey, domain, kdcHost):
    """AS-REQ for a machine (device) account that includes PA-PAC-OPTIONS(claims), so the
    resulting TGT is claims/compound-capable and the KDC will surface it as the *device*
    when it later armors a user's request (needed for AllowedToAuthenticateFrom silo checks).

    Returns (armorTicket, armorSessionKey)."""
    domain = domain.upper()
    # device long-term key
    if aesKey:
        raw = unhexlify(aesKey)
        et = (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value if len(raw) == 32
              else constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)
        key = Key(et, raw)
    elif nthash:
        et = constants.EncryptionTypes.rc4_hmac.value
        key = Key(et, nthash if isinstance(nthash, bytes) else unhexlify(nthash))
    else:
        et, salt = _harvest_salt(principal, domain, kdcHost)
        key = _enctype_table[et].string_to_key(password, salt, None)
    cipher = _enctype_table[et]

    serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    nonce = random.getrandbits(31)
    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    for i, pa in enumerate([_pa_enc_timestamp(cipher, key), _pa_pac_request(), _pa_pac_options()]):
        asReq['padata'][i] = pa
    _fill_req_body(seq_set(asReq, 'req-body'), principal, serverName, domain, [et], nonce, till)

    r = sendReceive(encoder.encode(asReq), domain, kdcHost)
    asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
    enc = cipher.decrypt(key, KEY_USAGE_AS_REP_ENCPART, asRep['enc-part']['cipher'].asOctets())
    encPart = decoder.decode(enc, asn1Spec=EncASRepPart())[0]
    sessionKey = Key(int(encPart['key']['keytype']), encPart['key']['keyvalue'].asOctets())
    ticket = Ticket()
    ticket.from_asn1(asRep['ticket'])
    _request_device_tgt.last_asrep = r
    _request_device_tgt.last_replykey = key
    return ticket, sessionKey


def getArmorTGT(options, userDomain):
    """Return (armorPrincipal, armorRealm, armorTicket, armorSessionKey)."""
    armorDomain = (options.armor_domain or userDomain).upper()
    if options.armor_account:
        principal = Principal(options.armor_account, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        lmhash = nthash = b''
        if options.armor_hashes:
            lm, nt = options.armor_hashes.split(':')
            lmhash, nthash = unhexlify(lm), unhexlify(nt)
        aesKey = options.armor_aesKey if options.armor_aesKey else ''
        logging.info('Requesting armor (device) TGT for %s' % options.armor_account)
        ticket, sessionKey = _request_device_tgt(
            principal, options.armor_password, lmhash, nthash, aesKey, armorDomain, options.dc_ip)

        if getattr(options, 'armor_compound', False):
            # A silo member's *unarmored* TGT carries no claims. Re-requesting the TGT
            # self-armored (compound), as a real Windows machine does, makes the KDC put the
            # machine's own claims (incl. AuthenticationSilo) into PAC_CLIENT_CLAIMS_INFO --
            # needed for silos whose AllowedToAuthenticateFrom reads the device silo claim.
            devOpts = argparse.Namespace(aesKey=options.armor_aesKey, nthash=nthash,
                                         password=options.armor_password, dc_ip=options.dc_ip)
            logging.info('Self-arming device TGT for %s (compound)' % options.armor_account)
            rep, replyKey = getKerberosTGTArmored(principal, armorDomain, devOpts,
                                                  principal, armorDomain, ticket, sessionKey)
            asRep = decoder.decode(rep, asn1Spec=AS_REP())[0]
            enc = _enctype_table[replyKey.enctype].decrypt(
                replyKey, KEY_USAGE_AS_REP_ENCPART, asRep['enc-part']['cipher'].asOctets())
            encPart = decoder.decode(enc, asn1Spec=EncASRepPart())[0]
            sessionKey = Key(int(encPart['key']['keytype']), encPart['key']['keyvalue'].asOctets())
            ticket = Ticket()
            ticket.from_asn1(asRep['ticket'])
            getArmorTGT.armor_asrep, getArmorTGT.armor_replykey = rep, replyKey
        else:
            getArmorTGT.armor_asrep = _request_device_tgt.last_asrep
            getArmorTGT.armor_replykey = _request_device_tgt.last_replykey
        return principal, armorDomain, ticket, sessionKey

    ccachePath = options.armor_ccache or os.getenv('KRB5CCNAME')
    if not ccachePath:
        raise Exception('No armor source: pass -armor-account with creds, or -armor-ccache / KRB5CCNAME')
    logging.info('Loading armor TGT from ccache %s' % ccachePath)
    ccache = CCache.loadFile(ccachePath)
    creds = ccache.getCredential('krbtgt/%s@%s' % (armorDomain, armorDomain))
    if creds is None:
        raise Exception('No krbtgt TGT for %s found in %s' % (armorDomain, ccachePath))
    tgtDict = creds.toTGT()
    kdcRep = decoder.decode(tgtDict['KDC_REP'], asn1Spec=AS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(kdcRep['ticket'])
    principal = Principal()
    principal.from_asn1(kdcRep, 'crealm', 'cname')  # armor client from the AS-REP
    return principal, armorDomain, ticket, tgtDict['sessionKey']


# ---------------------------------------------------------------------------
# FAST-armored AS-REQ
# ---------------------------------------------------------------------------
# Windows always carries a KERB-AD-RESTRICTION-ENTRY in the armor AP-REQ authenticator; we match
# that (always included) so hardened KDCs accept the armor.
class KERB_AD_RESTRICTION_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('restriction-type', 0, Int32()),
        _sequence_component('restriction', 1, univ.OctetString()))


def _armor_restriction_addata():
    """DER of the AD-IF-RELEVANT content for the armor AP-REQ authenticator, as real Windows
    sends it: one KERB-AUTH-DATA-TOKEN-RESTRICTIONS(141) carrying a KERB-AD-RESTRICTION-ENTRY
    with LSAP_TOKEN_INFO_INTEGRITY (Flags=0, TokenIL=System 0x4000, 32-byte MachineID). Some
    hardened KDCs reject an armor whose authenticator lacks this entry; impacket never sent it."""
    import struct
    lsap = struct.pack('<II', 0, 0x4000) + os.urandom(32)
    entry = KERB_AD_RESTRICTION_ENTRY()
    entry['restriction-type'] = 0
    entry['restriction'] = lsap
    relevant = AuthorizationData()          # AD-IF-RELEVANT content
    relevant[0] = univ.noValue
    relevant[0]['ad-type'] = 141
    relevant[0]['ad-data'] = encoder.encode(entry)
    return encoder.encode(relevant)


def _build_armor_apreq(armorPrincipal, armorRealm, armorTicket, armorSessionKey, subKey):
    armorCipher = _enctype_table[armorSessionKey.enctype]
    now = datetime.datetime.now(datetime.timezone.utc)
    auth = Authenticator()
    auth['authenticator-vno'] = 5
    auth['crealm'] = armorRealm
    seq_set(auth, 'cname', armorPrincipal.components_to_asn1)
    auth['cusec'] = now.microsecond
    auth['ctime'] = KerberosTime.to_asn1(now)
    auth['subkey'] = univ.noValue
    auth['subkey']['keytype'] = subKey.enctype
    auth['subkey']['keyvalue'] = subKey.contents
    # KERB-AD-RESTRICTION-ENTRY, as Windows always sends it. The authenticator's [8] slot is
    # populated in place (the CHOICE/padata idiom) to avoid pyasn1's "tag-incompatible"
    # rejection of a bare AuthorizationData assignment.
    auth['authorization-data'] = univ.noValue
    auth['authorization-data'][0] = univ.noValue
    auth['authorization-data'][0]['ad-type'] = 1          # AD-IF-RELEVANT
    auth['authorization-data'][0]['ad-data'] = _armor_restriction_addata()
    encAuth = armorCipher.encrypt(armorSessionKey, KEY_USAGE_AP_REQ_AUTHENTICATOR,
                                  encoder.encode(auth), None)
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    apReq['ap-options'] = constants.encodeFlags(list())
    seq_set(apReq, 'ticket', armorTicket.to_asn1)
    apReq['authenticator'] = univ.noValue
    apReq['authenticator']['etype'] = armorCipher.enctype
    apReq['authenticator']['cipher'] = encAuth
    return encoder.encode(apReq)


def _decrypt_fast_reply(paFxFastValue, armorCipher, armorKey):
    """Decrypt a PA-FX-FAST reply padata-value into a KrbFastResponse."""
    fastRep = decoder.decode(paFxFastValue, asn1Spec=PA_FX_FAST_REPLY())[0]
    encRep = fastRep['armored-data']['enc-fast-rep']
    plain = armorCipher.decrypt(armorKey, KEY_USAGE_FAST_REP, encRep['cipher'].asOctets())
    return decoder.decode(plain, asn1Spec=KrbFastResponse())[0]


def _find_padata(padataSeq, ptype):
    for pa in padataSeq:
        if int(pa['padata-type']) == ptype:
            return pa
    return None


def _send_armored(kdcHost, clientName, serverName, domain, etypes,
                  armorPrincipal, armorRealm, armorTicket, armorSessionKey, makeInnerPadata,
                  subKey, armorKey):
    """Build and send one FAST-armored AS-REQ with the caller-supplied subKey/armorKey.

    The same armor is reused across the cookie and challenge rounds so the KDC can correlate
    the device (compound identity) across the exchange. makeInnerPadata(armorKey) returns the
    inner KrbFastReq padata list."""
    armorCipher = _enctype_table[armorSessionKey.enctype]
    nonce = random.getrandbits(31)
    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

    # The FAST req-body, the req-checksum body and PKINIT's paChecksum all sign the SAME
    # KDC-REQ-BODY, so build it once and reuse the bytes.
    bareBody = KDC_REQ_BODY()
    _fill_req_body(bareBody, clientName, serverName, domain, etypes, nonce, till)
    bodyBytes = encoder.encode(bareBody)

    fastReq = KrbFastReq()
    fastReq['fast-options'] = constants.encodeFlags(list())
    for i, pa in enumerate(makeInnerPadata(armorKey, bodyBytes, nonce)):
        fastReq['padata'][i] = pa
    _fill_req_body(seq_set(fastReq, 'req-body'), clientName, serverName, domain, etypes, nonce, till)
    encFastReq = armorCipher.encrypt(armorKey, KEY_USAGE_FAST_ENC, encoder.encode(fastReq), None)

    cksumType = _CKSUM_FOR_ENCTYPE[armorKey.enctype]
    reqCksum = make_checksum(cksumType, armorKey, KEY_USAGE_FAST_REQ_CHKSUM, bodyBytes)

    armoredReq = _fast_alt(PA_FX_FAST_REQUEST)
    a = seq_set(armoredReq, 'armor')
    a['armor-type'] = FX_FAST_ARMOR_AP_REQUEST
    a['armor-value'] = _build_armor_apreq(armorPrincipal, armorRealm, armorTicket,
                                          armorSessionKey, subKey)
    armoredReq['req-checksum']['cksumtype'] = cksumType
    armoredReq['req-checksum']['checksum'] = reqCksum
    armoredReq['enc-fast-req']['etype'] = armorKey.enctype
    armoredReq['enc-fast-req']['cipher'] = encFastReq

    fastRequest = PA_FX_FAST_REQUEST()
    fastRequest['armored-data'] = armoredReq

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    asReq['padata'] = univ.noValue
    asReq['padata'][0] = univ.noValue
    asReq['padata'][0]['padata-type'] = PA_FX_FAST_TYPE
    asReq['padata'][0]['padata-value'] = encoder.encode(fastRequest)
    _fill_req_body(seq_set(asReq, 'req-body'), clientName, serverName, domain, etypes, nonce, till)

    return sendReceive(encoder.encode(asReq), domain, kdcHost)


def _client_key_direct(options):
    """Client key when we have key material directly (aesKey/hashes); else (None, None)."""
    if options.aesKey:
        raw = unhexlify(options.aesKey)
        et = (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value if len(raw) == 32
              else constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)
        return Key(et, raw), _enctype_table[et]
    if options.nthash:
        et = constants.EncryptionTypes.rc4_hmac.value
        nt = options.nthash if isinstance(options.nthash, bytes) else unhexlify(options.nthash)
        return Key(et, nt), _enctype_table[et]
    return None, None


def _etype_salt_from_padata(padataSeq):
    """Extract (enctype, salt) from an ETYPE-INFO2 in a (FAST-protected) padata sequence."""
    for pa in padataSeq:
        if int(pa['padata-type']) == PA_ETYPE_INFO2_TYPE:
            info = decoder.decode(pa['padata-value'], asn1Spec=ETYPE_INFO2())[0]
            salts = {}
            for e in info:
                salts[int(e['etype'])] = e['salt'].asOctets() if e['salt'].hasValue() else b''
            for et in (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                       constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                       constants.EncryptionTypes.rc4_hmac.value):
                if et in salts:
                    return et, salts[et]
    return None, None


# ---------------------------------------------------------------------------
# PKINIT (RFC 4556) - certificate pre-auth carried INSIDE the FAST armor, so a
# smartcard-required (SCRIL) user on an Authentication Policy Silo can get a TGT
# from Linux: the cert satisfies "smartcard required", the armor satisfies the
# silo's device condition. DH key agreement + legacy octetstring2key reply key
# (then the FAST strengthen-key CF2). Input: PFX (pywhisker/certipy output).
# asn1crypto + cryptography are imported lazily so non-PKINIT use needs neither.
# ponytail: DH group 14 + octetstring2key (PKINITtools-compatible); RSA PFX only;
#           no PKCS#11/Yubikey-hardware and no SP800-56A agility KDF (upgrade if a
#           KDC rejects the legacy KDF).
# ---------------------------------------------------------------------------
PA_PK_AS_REQ_TYPE = 16
PA_PK_AS_REP_TYPE = 17
_ID_PKINIT_AUTHDATA = '1.3.6.1.5.2.3.1'
_OID_DHPUBLICNUMBER = '1.2.840.10046.2.1'
# RFC 3526 MODP group 14 (2048-bit), g = 2
_DH_P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
            '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
            '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
            '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
            '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
            '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
_DH_G = 2
_PK_ASN1 = {}


def _pk_classes():
    """Lazily define & cache the PKINIT asn1crypto structures (RFC 4556)."""
    if _PK_ASN1:
        return _PK_ASN1
    from asn1crypto import core

    class DomainParameters(core.Sequence):
        _fields = [('p', core.Integer), ('g', core.Integer), ('q', core.Integer, {'optional': True})]

    class DHAlgId(core.Sequence):
        _fields = [('algorithm', core.ObjectIdentifier), ('parameters', DomainParameters)]

    class DHPublicKeyInfo(core.Sequence):  # SubjectPublicKeyInfo w/ dhpublicnumber
        _fields = [('algorithm', DHAlgId), ('subject_public_key', core.OctetBitString)]

    class PKAuthenticator(core.Sequence):
        _fields = [('cusec', core.Integer, {'explicit': 0}),
                   ('ctime', core.GeneralizedTime, {'explicit': 1}),
                   ('nonce', core.Integer, {'explicit': 2}),
                   ('paChecksum', core.OctetString, {'explicit': 3, 'optional': True})]

    class AuthPack(core.Sequence):
        _fields = [('pkAuthenticator', PKAuthenticator, {'explicit': 0}),
                   ('clientPublicValue', DHPublicKeyInfo, {'explicit': 1, 'optional': True})]

    class PA_PK_AS_REQ(core.Sequence):
        _fields = [('signedAuthPack', core.OctetString, {'implicit': 0}),
                   ('trustedCertifiers', core.Any, {'explicit': 1, 'optional': True}),
                   ('kdcPkId', core.OctetString, {'implicit': 2, 'optional': True})]

    class KDCDHKeyInfo(core.Sequence):
        _fields = [('subjectPublicKey', core.OctetBitString, {'explicit': 0}),
                   ('nonce', core.Integer, {'explicit': 1}),
                   ('dhKeyExpiration', core.GeneralizedTime, {'explicit': 2, 'optional': True})]

    class DHRepInfo(core.Sequence):
        _fields = [('dhSignedData', core.OctetString, {'implicit': 0}),
                   ('serverDHNonce', core.OctetString, {'explicit': 1, 'optional': True})]

    class PA_PK_AS_REP(core.Choice):
        _alternatives = [('dhInfo', DHRepInfo, {'explicit': 0}),
                         ('encKeyPack', core.OctetString, {'implicit': 1})]

    _PK_ASN1.update(dict(DHPublicKeyInfo=DHPublicKeyInfo, PKAuthenticator=PKAuthenticator,
                         AuthPack=AuthPack, PA_PK_AS_REQ=PA_PK_AS_REQ, KDCDHKeyInfo=KDCDHKeyInfo,
                         PA_PK_AS_REP=PA_PK_AS_REP))
    return _PK_ASN1


class _PKDH:
    """Ephemeral client DH keypair over MODP group 14."""
    def __init__(self):
        self.x = int.from_bytes(os.urandom(32), 'big') + 2
        self.y = pow(_DH_G, self.x, _DH_P)
        self.nonce = random.getrandbits(31)

    def shared_bytes(self, kdc_y):
        plen = (_DH_P.bit_length() + 7) // 8
        return pow(kdc_y, self.x, _DH_P).to_bytes(plen, 'big')


def _octetstring2key(x, cipher):
    """RFC 4556 3.2.3.1: K-truncate(SHA1(0x00|x) | SHA1(0x01|x) | ...) -> random_to_key."""
    import hashlib
    seedsize = getattr(cipher, 'seedsize', cipher.keysize)
    seed, c = b'', 0
    while len(seed) < seedsize:
        seed += hashlib.sha1(bytes([c]) + x).digest()
        c += 1
    return cipher.random_to_key(seed[:seedsize])


def _load_pkinit_creds(options):
    """(cryptography cert, private key) from -pfx (+ -pfx-pass) or -cert-pem/-key-pem."""
    from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key
    from cryptography import x509 as cx509
    if getattr(options, 'pfx', None):
        with open(options.pfx, 'rb') as f:
            data = f.read()
        pw = options.pfx_pass.encode() if getattr(options, 'pfx_pass', None) else None
        key, cert, _ = pkcs12.load_key_and_certificates(data, pw)
        if key is None or cert is None:
            raise Exception('PFX %s is missing a key or certificate' % options.pfx)
        return cert, key
    if getattr(options, 'cert_pem', None) and getattr(options, 'key_pem', None):
        with open(options.cert_pem, 'rb') as f:
            cert = cx509.load_pem_x509_certificate(f.read())
        kp = options.key_pass.encode() if getattr(options, 'key_pass', None) else None
        with open(options.key_pem, 'rb') as f:
            key = load_pem_private_key(f.read(), kp)
        return cert, key
    raise Exception('PKINIT needs -pfx (or -cert-pem + -key-pem)')


def _build_pk_as_req(cert, privkey, dh, bodyBytes):
    """PA-PK-AS-REQ (padata 16): a CMS SignedData (eContentType id-pkinit-authData) over an
    AuthPack{PKAuthenticator(paChecksum=SHA1(req-body)), clientPublicValue=DH SPKI}."""
    import hashlib, datetime as _dt
    from asn1crypto import core, cms, x509
    from cryptography.hazmat.primitives import hashes as _h, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    C = _pk_classes()
    spki = C['DHPublicKeyInfo']({
        'algorithm': {'algorithm': _OID_DHPUBLICNUMBER,
                      'parameters': {'p': _DH_P, 'g': _DH_G, 'q': (_DH_P - 1) // 2}},
        'subject_public_key': core.Integer(dh.y).dump()})
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    authpack = C['AuthPack']({
        'pkAuthenticator': {'cusec': 0, 'ctime': now, 'nonce': dh.nonce,
                            'paChecksum': hashlib.sha1(bodyBytes).digest()},
        'clientPublicValue': spki})
    econtent = authpack.dump()

    acert = x509.Certificate.load(cert.public_bytes(_ser.Encoding.DER))
    attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': [cms.ContentType(_ID_PKINIT_AUTHDATA)]}),
        cms.CMSAttribute({'type': 'message_digest',
                          'values': [core.OctetString(hashlib.sha256(econtent).digest())]}),
        cms.CMSAttribute({'type': 'signing_time', 'values': [cms.Time({'utc_time': core.UTCTime(now)})]})])
    # signed over the SET OF (0x31) form; SignerInfo stores it under IMPLICIT [0]
    signature = privkey.sign(attrs.dump(), _pad.PKCS1v15(), _h.SHA256())
    eci = cms.EncapsulatedContentInfo()
    eci['content_type'] = _ID_PKINIT_AUTHDATA
    eci['content'] = econtent
    si = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({'issuer_and_serial_number': cms.IssuerAndSerialNumber(
            {'issuer': acert.issuer, 'serial_number': acert.serial_number})}),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signed_attrs': attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature})
    sd = cms.SignedData({'version': 'v3', 'digest_algorithms': [{'algorithm': 'sha256'}],
                         'encap_content_info': eci, 'certificates': [acert], 'signer_infos': [si]})
    req = C['PA_PK_AS_REQ']({'signedAuthPack': cms.ContentInfo(
        {'content_type': 'signed_data', 'content': sd}).dump()})
    pa = PA_DATA()
    pa['padata-type'] = PA_PK_AS_REQ_TYPE
    pa['padata-value'] = req.dump()
    return pa


def _pk_reply_key(padataValue, dh, repEnctype):
    """Derive the AS reply key from PA-PK-AS-REP (DH): extract the KDC's DH pubkey from the
    (unverified - the AS-REP decrypt is the integrity check) dhSignedData, agree, octetstring2key."""
    from asn1crypto import core, cms
    C = _pk_classes()
    rep = C['PA_PK_AS_REP'].load(bytes(padataValue))
    if rep.name != 'dhInfo':
        raise Exception('PKINIT reply is encKeyPack (RSA) - only DH is supported')
    ci = cms.ContentInfo.load(rep.chosen['dhSignedData'].native)
    kdk = C['KDCDHKeyInfo'].load(ci['content']['encap_content_info']['content'].native)
    kdc_y = core.Integer.load(kdk['subjectPublicKey'].native).native
    return _octetstring2key(dh.shared_bytes(kdc_y), _enctype_table[repEnctype])


def getKerberosTGTArmored(clientName, domain, options,
                          armorPrincipal, armorRealm, armorTicket, armorSessionKey):
    domain = domain.upper()
    kdcHost = options.dc_ip
    armorCipher = _enctype_table[armorSessionKey.enctype]

    # With password auth we cannot probe the client's salt un-armored: a silo-restricted
    # user answers that with KDC_ERR_POLICY, not the salt. So defer the client key and read
    # the salt from ETYPE-INFO2 inside the armored (FAST-protected) PREAUTH_REQUIRED reply.
    pkinit = bool(getattr(options, 'pfx', None) or getattr(options, 'cert_pem', None))
    pkCert = pkKey = pkDH = None
    if pkinit:
        pkCert, pkKey = _load_pkinit_creds(options)
        pkDH = _PKDH()
        clientKey, clientCipher = None, None  # reply key comes from the DH agreement
        etypes = [constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                  constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                  constants.EncryptionTypes.rc4_hmac.value]
    else:
        clientKey, clientCipher = _client_key_direct(options)
        if clientKey is not None:
            etypes = [clientKey.enctype]
        else:
            etypes = [constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                      constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                      constants.EncryptionTypes.rc4_hmac.value]
    serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    # One armor key for the whole exchange so the KDC correlates the device across rounds.
    subKey = Key(armorCipher.enctype, os.urandom(armorCipher.keysize))
    usedArmorKey = cf2(armorSessionKey.enctype, subKey, armorSessionKey, b'subkeyarmor', b'ticketarmor')

    # Windows FAST AS is a two-step exchange: the first armored request is answered with
    # KDC_ERR_PREAUTH_REQUIRED carrying a PA-FX-COOKIE (and ETYPE-INFO2); the second echoes
    # the cookie and adds the PA-ENCRYPTED-CHALLENGE factor (keyed with the armor key).
    cookie = None
    asRep = None
    fastResponse = None
    for attempt in range(2):
        def makeInner(armorKey, bodyBytes, nonce, cookie=cookie):
            pas = []
            if cookie is not None:
                pas.append(cookie)
            if pkinit:  # certificate pre-auth (paChecksum signs this exchange's req-body)
                pas.append(_build_pk_as_req(pkCert, pkKey, pkDH, bodyBytes))
            elif clientKey is not None:  # only once we have the client key can we challenge
                pas.append(_pa_encrypted_challenge(clientKey, armorKey))
            pas.append(_pa_pac_request())
            pas.append(_pa_pac_options())  # request claims/compound so the device is evaluated
            return pas

        r = _send_armored(kdcHost, clientName, serverName, domain, etypes,
                          armorPrincipal, armorRealm, armorTicket,
                          armorSessionKey, makeInner, subKey, usedArmorKey)

        try:
            err = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except Exception:
            err = None

        if err is None:
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
            pa = _find_padata(asRep['padata'], PA_FX_FAST_TYPE)
            if pa is not None:
                fastResponse = _decrypt_fast_reply(pa['padata-value'], armorCipher, usedArmorKey)
            break

        # error path: read the FAST reply for the cookie (and salt, for password auth)
        code = int(err['error-code'])
        if err['e-data'].hasValue():
            methods = decoder.decode(err['e-data'], asn1Spec=METHOD_DATA())[0]
            paFast = _find_padata(methods, PA_FX_FAST_TYPE)
            if paFast is not None:
                fr = _decrypt_fast_reply(paFast['padata-value'], armorCipher, usedArmorKey)
                cookie = _find_padata(fr['padata'], PA_FX_COOKIE_TYPE)
                if clientKey is None and not pkinit:
                    et, salt = _etype_salt_from_padata(fr['padata'])
                    if et is not None:
                        clientCipher = _enctype_table[et]
                        clientKey = clientCipher.string_to_key(options.password, salt, None)
                        etypes = [et]
        if code != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            raise KerberosError(packet=err)

    if asRep is None:
        raise Exception('FAST-armored AS-REQ failed: KDC kept requesting pre-authentication')

    if pkinit:  # reply key = octetstring2key(DH shared) from PA-PK-AS-REP (inside the FAST reply)
        paRep = None
        if fastResponse is not None:
            paRep = _find_padata(fastResponse['padata'], PA_PK_AS_REP_TYPE)
        if paRep is None:
            paRep = _find_padata(asRep['padata'], PA_PK_AS_REP_TYPE)
        if paRep is None:
            raise Exception('PKINIT: no PA-PK-AS-REP in the (FAST) reply')
        clientKey = _pk_reply_key(paRep['padata-value'].asOctets(), pkDH,
                                  int(asRep['enc-part']['etype']))

    # reply key = CF2(strengthen-key, client key, "strengthenkey", "replykey") when present
    replyKey = clientKey
    if fastResponse is not None and fastResponse['strengthen-key'].hasValue():
        sk = fastResponse['strengthen-key']
        strengthenKey = Key(int(sk['keytype']), sk['keyvalue'].asOctets())
        replyKey = cf2(strengthenKey.enctype, strengthenKey, clientKey,
                       b'strengthenkey', b'replykey')

    # sanity: the reply key must decrypt the AS-REP enc-part
    _enctype_table[replyKey.enctype].decrypt(replyKey, KEY_USAGE_AS_REP_ENCPART,
                                             asRep['enc-part']['cipher'].asOctets())
    return encoder.encode(asRep), replyKey


def _pac_buffers(ticketEncPartPlain):
    """Return {ulType: buffer_bytes} for every PAC buffer in a decrypted ticket enc-part."""
    from impacket.krb5.asn1 import EncTicketPart, AD_IF_RELEVANT
    etp = decoder.decode(ticketEncPartPlain, asn1Spec=EncTicketPart())[0]
    pac = None
    for a in etp['authorization-data']:
        if int(a['ad-type']) == 1:
            for b in decoder.decode(a['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]:
                if int(b['ad-type']) == 128:
                    pac = b['ad-data'].asOctets()
    if pac is None:
        return {}
    import struct
    n = struct.unpack('<I', pac[:4])[0]
    off, bufs = 8, {}
    for _ in range(n):
        ulType, cb, offset = struct.unpack('<IIQ', pac[off:off + 16]); off += 16
        bufs[ulType] = pac[offset:offset + cb]
    return bufs


def _dump_armor_claims(options, armorRealm, armorSessionKey):
    """Diagnostic: request a self-service TGS with the armor TGT and print its PAC buffer
    types, so we can see whether the armor (device) TGT carries the AuthenticationSilo
    claim (PAC_CLIENT_CLAIMS_INFO = buffer type 13). Requires -armor-aesKey."""
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.asn1 import TGS_REP
    account = options.armor_account
    if not options.armor_aesKey:
        logging.error('-dump-armor needs -armor-aesKey (to decrypt the service ticket)')
        return
    fqdn = account.rstrip('$').lower() + '.' + armorRealm.lower()
    spn = Principal('host/%s' % fqdn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    cipher = _enctype_table[armorSessionKey.enctype]
    logging.info('Requesting self-service TGS host/%s to inspect the armor PAC' % fqdn)
    tgs, _c, _o, _n = getKerberosTGS(spn, armorRealm, options.dc_ip,
                                     getArmorTGT.armor_asrep, cipher, armorSessionKey)
    rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    raw = unhexlify(options.armor_aesKey)
    et = (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value if len(raw) == 32
          else constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)
    svcKey = Key(et, raw)
    plain = _enctype_table[et].decrypt(svcKey, 2, rep['ticket']['enc-part']['cipher'].asOctets())
    bufs = _pac_buffers(plain)
    types = sorted(bufs.keys())
    kind = 'compound (self-armored)' if getattr(options, 'armor_compound', False) else 'plain (PA-PAC-OPTIONS)'
    print('[*] Armor (%s) machine TGT PAC buffer types: %s' % (kind, types))
    print('[*] CLIENT_CLAIMS (13): %s   DEVICE_CLAIMS (15): %s'
          % ('present' if 13 in bufs else 'absent', 'present' if 15 in bufs else 'absent'))
    from impacket.krb5.pac import parse_claims_set
    for btype, label in ((13, 'CLIENT_CLAIMS (13)'), (15, 'DEVICE_CLAIMS (15)')):
        if btype not in bufs:
            continue
        try:
            claims = parse_claims_set(bufs[btype])
            print('[*] %s:' % label)
            for c in claims:
                print('      %s = %s' % (c['id'], c['values']))
            silo = [c['values'] for c in claims if c['id'].lower() == 'ad://ext/authenticationsilo']
            if silo:
                print('    -> AuthenticationSilo in %s = %s' % (label, silo[0]))
        except Exception as e:
            print('    (%s: could not decode: %s)' % (label, e))
    if 13 not in bufs and 15 not in bufs:
        print('    -> the machine TGT carries NO claims; try -armor-compound / -armor-levels 2.')


class GETTGT:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user = target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__service = options.service
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__user + '.ccache'))
        ccache = CCache()
        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__user + '.ccache')

    def run(self):
        userName = Principal(self.__user, type=self.__options.principalType.value)

        armorEngaged = bool(self.__options.armor or self.__options.armor_account
                            or self.__options.armor_ccache)
        if (getattr(self.__options, 'pfx', None) or getattr(self.__options, 'cert_pem', None)) \
                and not armorEngaged:
            raise Exception('PKINIT here is meant for silo auth and needs an armor TGT: add '
                            '-armor-account <machine$> with its creds. For plain unarmored PKINIT, '
                            'use certipy/gettgtpkinit.')
        if armorEngaged:
            # normalise the user auth material onto the options object for the armored path
            self.__options.password = self.__password
            self.__options.nthash = self.__nthash
            armorPrincipal, armorRealm, armorTicket, armorSessionKey = getArmorTGT(
                self.__options, self.__domain)
            if getattr(self.__options, 'dump_armor', False):
                _dump_armor_claims(self.__options, armorRealm, armorSessionKey)
                return
            tgt, replyKey = getKerberosTGTArmored(
                userName, self.__domain, self.__options,
                armorPrincipal, armorRealm, armorTicket, armorSessionKey)
            self.saveTicket(tgt, replyKey)
            return

        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            clientName=userName, password=self.__password, domain=self.__domain,
            lmhash=unhexlify(self.__lmhash), nthash=unhexlify(self.__nthash),
            aesKey=self.__aesKey, kdcHost=self.__kdcHost, serverName=self.__service)
        self.saveTicket(tgt, oldSessionKey)


# ---------------------------------------------------------------------------
# offline self-test (no network): CF2 vectors + FAST ASN.1 round-trips
# ---------------------------------------------------------------------------
def selftest():
    from impacket.krb5.crypto import random_to_key
    ok = True

    for et in (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
               constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
               constants.EncryptionTypes.rc4_hmac.value):
        cipher = _enctype_table[et]
        k1 = cipher.random_to_key(os.urandom(cipher.seedsize))
        k2 = cipher.random_to_key(os.urandom(cipher.seedsize))
        out = cf2(et, k1, k2, b'a', b'b')
        assert len(out.contents) == cipher.keysize, 'cf2 wrong key length for et %d' % et
        # identical key+pepper on both sides XORs to zero -> random_to_key(zeros)
        zero = cf2(et, k1, k1, b'p', b'p')
        assert zero.contents == random_to_key(et, b'\x00' * cipher.seedsize).contents, \
            'cf2 self-xor not zero for et %d' % et
        logging.debug('cf2 OK for enctype %d' % et)

    # ASN.1 round-trips
    armor = KrbFastArmor()
    armor['armor-type'] = FX_FAST_ARMOR_AP_REQUEST
    armor['armor-value'] = b'\x01\x02\x03'
    d = decoder.decode(encoder.encode(armor), asn1Spec=KrbFastArmor())[0]
    assert int(d['armor-type']) == 1 and d['armor-value'].asOctets() == b'\x01\x02\x03'

    req = _fast_alt(PA_FX_FAST_REQUEST)
    req['req-checksum']['cksumtype'] = constants.ChecksumTypes.hmac_sha1_96_aes256.value
    req['req-checksum']['checksum'] = b'\x00' * 12
    req['enc-fast-req']['etype'] = constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
    req['enc-fast-req']['cipher'] = b'abcd'
    fr = PA_FX_FAST_REQUEST()
    fr['armored-data'] = req
    d = decoder.decode(encoder.encode(fr), asn1Spec=PA_FX_FAST_REQUEST())[0]
    assert d['armored-data']['enc-fast-req']['cipher'].asOctets() == b'abcd'

    rep = _fast_alt(PA_FX_FAST_REPLY)
    rep['enc-fast-rep']['etype'] = 18
    rep['enc-fast-rep']['cipher'] = b'zzzz'
    fp = PA_FX_FAST_REPLY()
    fp['armored-data'] = rep
    d = decoder.decode(encoder.encode(fp), asn1Spec=PA_FX_FAST_REPLY())[0]
    assert d['armored-data']['enc-fast-rep']['cipher'].asOctets() == b'zzzz'

    resp = KrbFastResponse()
    resp['padata'][0] = _pa_pac_request()
    resp['strengthen-key']['keytype'] = 18
    resp['strengthen-key']['keyvalue'] = b'\x11' * 32
    resp['nonce'] = 12345
    d = decoder.decode(encoder.encode(resp), asn1Spec=KrbFastResponse())[0]
    assert int(d['nonce']) == 12345 and d['strengthen-key']['keyvalue'].asOctets() == b'\x11' * 32

    # PKINIT path (needs asn1crypto + cryptography): exercise the real request builder and
    # reply-key derivation, with an in-memory cert and a simulated KDC DH side.
    try:
        import datetime as _dt, hashlib
        from asn1crypto import cms
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes as _h
        from cryptography.hazmat.primitives.asymmetric import rsa, padding as _pad
        from cryptography.x509.oid import NameOID
        C = _pk_classes()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nm = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, u'pk-selftest')])
        cert = (cx509.CertificateBuilder().subject_name(nm).issuer_name(nm)
                .public_key(key.public_key()).serial_number(cx509.random_serial_number())
                .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
                .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
                .sign(key, _h.SHA256()))
        dh = _PKDH()
        body = b'\x30\x05\xa0\x03\x02\x01\x01'
        pa = _build_pk_as_req(cert, key, dh, body)
        req = C['PA_PK_AS_REQ'].load(bytes(pa['padata-value']))
        sd = cms.ContentInfo.load(req['signedAuthPack'].native)['content']
        ap = C['AuthPack'].load(sd['encap_content_info']['content'].native)
        assert bytes(ap['pkAuthenticator']['paChecksum'].native) == hashlib.sha1(body).digest(), \
            'PKINIT paChecksum mismatch'
        si = sd['signer_infos'][0]
        retag = b'\x31' + si['signed_attrs'].dump()[1:]  # IMPLICIT [0] -> SET OF for verify
        cert.public_key().verify(si['signature'].native, retag, _pad.PKCS1v15(), _h.SHA256())
        # simulate the KDC DH side; both must derive the same reply key
        kx = int.from_bytes(os.urandom(32), 'big') + 2
        et = constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
        kdc_shared = pow(dh.y, kx, _DH_P).to_bytes((_DH_P.bit_length() + 7) // 8, 'big')
        kdc_key = _octetstring2key(kdc_shared, _enctype_table[et])
        cli_key = _octetstring2key(dh.shared_bytes(pow(_DH_G, kx, _DH_P)), _enctype_table[et])
        assert kdc_key.contents == cli_key.contents, 'PKINIT DH reply key mismatch'
        print('[+] PKINIT selftest OK (AuthPack/CMS sign+verify, DH octetstring2key agreement)')
    except ImportError as e:
        print('[!] PKINIT selftest skipped (missing %s - pip install asn1crypto cryptography)' % e.name)

    print('[+] selftest OK (cf2 for aes256/aes128/rc4, FAST ASN.1 round-trips)')
    return 0 if ok else 1


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Given a password, hash or aesKey, "
                                     "it will request a TGT and save it as ccache. Supply armor "
                                     "options to obtain a TGT for Authentication Policy Silo "
                                     "accounts (Kerberos armoring / FAST).")
    parser.add_argument('identity', action='store', nargs='?', default=None,
                        help='[domain/]username[:password]')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-selftest', action='store_true',
                        help='Run offline unit checks (cf2 + FAST ASN.1) and exit; no network')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                       '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-service', action='store', metavar="SPN", help='Request a Service Ticket directly through an AS-REQ')
    group.add_argument('-principalType', nargs="?", type=lambda value: constants.PrincipalNameType[value.upper()] if value.upper() in constants.PrincipalNameType.__members__ else None,  action='store', default=constants.PrincipalNameType.NT_PRINCIPAL, help='PrincipalType of the token, can be one of  NT_UNKNOWN, NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST, NT_SRV_XHST, NT_UID, NT_SMTP_NAME, NT_ENTERPRISE, NT_WELLKNOWN, NT_SRV_HST_DOMAIN, NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID, NT_ENT_PRINCIPAL_AND_ID; default is NT_PRINCIPAL, ')

    armor = parser.add_argument_group('armoring (Kerberos FAST / silo)',
                                      'Supply an armor TGT to send a FAST-armored AS-REQ. Use a machine '
                                      'account you control, or an existing ccache (never the keytab).')
    armor.add_argument('-armor', action='store_true',
                       help='Force a FAST-armored AS-REQ using the armor TGT from KRB5CCNAME '
                            '(implied by -armor-account / -armor-ccache)')
    armor.add_argument('-armor-account', action='store', metavar='MACHINE$',
                       help='Machine account whose TGT armors the request (e.g. WS01$)')
    armor.add_argument('-armor-password', action='store', metavar='PASSWORD', help='Password for -armor-account')
    armor.add_argument('-armor-hashes', action='store', metavar='LMHASH:NTHASH', help='NT hash for -armor-account')
    armor.add_argument('-armor-aesKey', action='store', metavar='hex key', help='AES key for -armor-account')
    armor.add_argument('-armor-compound', action='store_true',
                       help='Self-arm the device TGT (compound) so it carries the AuthenticationSilo '
                            'claim - needed for silos whose policy uses the claim condition')
    armor.add_argument('-dump-armor', action='store_true',
                       help='Diagnostic: request the armor (device) TGT, then print its PAC buffer '
                            'types and decode the silo claim (needs -armor-aesKey), and exit')
    armor.add_argument('-armor-ccache', action='store', metavar='PATH',
                       help='Existing ccache holding the armor TGT (else KRB5CCNAME is used)')
    armor.add_argument('-armor-domain', action='store', metavar='DOMAIN',
                       help='Domain of the armor account (defaults to the target domain)')

    pk = parser.add_argument_group('PKINIT (certificate / smartcard, RFC 4556)',
                                   'Authenticate with a certificate instead of a password - required '
                                   'for smartcard-required (SCRIL) accounts. Combine with the armoring '
                                   'options above to get a TGT for such a user on a silo. Get the PFX '
                                   'from pywhisker / certipy shadow / ADCS enrollment.')
    pk.add_argument('-pfx', action='store', metavar='FILE', help='PKCS#12 (.pfx) holding the cert + key')
    pk.add_argument('-pfx-pass', action='store', metavar='PASS', help='Password for -pfx (if any)')
    pk.add_argument('-cert-pem', action='store', metavar='FILE', help='Certificate in PEM (use with -key-pem)')
    pk.add_argument('-key-pem', action='store', metavar='FILE', help='Private key in PEM (use with -cert-pem)')
    pk.add_argument('-key-pass', action='store', metavar='PASS', help='Password for -key-pem (if any)')

    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getTGT.py -hashes lm:nt contoso.com/user")
        print("\t./getTGT.py contoso.com/user -password P@ss -dc-ip 10.0.0.1 -armor-account WS01$ -armor-password Machine123\n")
        sys.exit(1)
    options = parser.parse_args()

    logger.init(options.ts, options.debug)

    if options.selftest:
        sys.exit(selftest())

    if options.identity is None:
        logging.critical('identity ([domain/]username[:password]) is required')
        sys.exit(1)

    if options.pfx or options.cert_pem:
        options.no_pass = True  # certificate pre-auth - never prompt for a password

    domain, username, password, _, _, options.k = parse_identity(options.identity, options.hashes, options.no_pass, options.aesKey, options.k)

    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.principalType is None:
        logging.critical('Invalid principalType!')
        sys.exit(1)

    try:
        executer = GETTGT(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
