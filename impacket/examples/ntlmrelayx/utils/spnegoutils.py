# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

"""Helpers for inspecting SPNEGO tokens received by relay listeners."""

from collections import namedtuple
from struct import unpack

from impacket.spnego import ASN1_AID, SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech


NTLM_MECH = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
NEGOEX_MECH = TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism']


SPNEGOTokenInfo = namedtuple(
    'SPNEGOTokenInfo',
    (
        'is_spnego',
        'is_init',
        'is_response',
        'mech_types',
        'selected_mech',
        'inner_token',
        'negoex_offered',
        'negoex_selected',
    ),
)


def inspect_spnego_token(data):
    """Return framing and mechanism information without parsing mechanism payloads."""
    raw = data or b''
    default = SPNEGOTokenInfo(False, False, False, [], None, raw, False, False)
    if not raw:
        return default

    tag = unpack('B', raw[:1])[0]
    if tag == ASN1_AID:
        blob = SPNEGO_NegTokenInit(raw)
        mech_types = blob['MechTypes'] if 'MechTypes' in blob.fields else []
        inner_token = blob['MechToken'] if 'MechToken' in blob.fields else b''
        return SPNEGOTokenInfo(
            True,
            True,
            False,
            mech_types,
            None,
            inner_token,
            NEGOEX_MECH in mech_types,
            False,
        )

    if tag == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
        blob = SPNEGO_NegTokenResp(raw)
        selected_mech = blob.getSupportedMech()
        inner_token = blob['ResponseToken'] if 'ResponseToken' in blob.fields else b''
        return SPNEGOTokenInfo(
            True,
            False,
            True,
            [],
            selected_mech,
            inner_token,
            False,
            blob.isNegoExSelected(),
        )

    return default


def find_embedded_spnego_token(data):
    """Find the first structurally valid SPNEGO token embedded in a framing blob."""
    raw = data or b''
    candidate_tags = (ASN1_AID, SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP)
    for offset, value in enumerate(bytearray(raw)):
        if value not in candidate_tags:
            continue
        try:
            info = inspect_spnego_token(raw[offset:])
        except Exception:
            continue
        if info.is_spnego:
            return info
    return None


def get_ntlm_message_type(token):
    """Return the NTLM message type, or None when token is not a complete NTLM header."""
    if not token or len(token) < 12 or not token.startswith(b'NTLMSSP\x00'):
        return None
    return unpack('<L', token[8:12])[0]


def build_ntlm_fallback_token():
    """Build a SPNEGO request asking the peer to continue with NTLM."""
    response = SPNEGO_NegTokenResp()
    response['NegState'] = b'\x03'  # request-mic
    response['SupportedMech'] = NTLM_MECH
    return response.getData()


def build_ntlm_challenge_token(challenge):
    """Wrap an NTLM challenge in a SPNEGO accept-incomplete response."""
    response = SPNEGO_NegTokenResp()
    response['NegState'] = b'\x01'  # accept-incomplete
    response['SupportedMech'] = NTLM_MECH
    response['ResponseToken'] = challenge
    return response.getData()
