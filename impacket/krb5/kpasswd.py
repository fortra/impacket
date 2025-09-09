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
#   Functions for Microsoft Windows 2000 Kerberos Change Password
#   and Set Password Protocols
#
# References:
#   https://www.rfc-editor.org/rfc/rfc3244.txt
#
# Author:
#   Thomas Fargeix (@Alef-Burzmali)
#

import base64
import binascii
import datetime
import os
import struct

from pyasn1.type import namedtype, univ
from pyasn1.codec.der import decoder, encoder

from impacket import LOG
from impacket.dcerpc.v5.enum import Enum

from .kerberosv5 import getKerberosTGT, sendReceive
from .asn1 import (_sequence_component, _sequence_optional_component, seq_set,
                   Realm, PrincipalName, Authenticator,
                   AS_REP, AP_REQ, AP_REP,
                   KRB_PRIV, EncKrbPrivPart)
from .ccache import CCache
from .constants import PrincipalNameType, ApplicationTagNumbers, AddressType, encodeFlags
from .crypto import Key, get_random_bytes
from .types import Principal, KerberosTime, Ticket


# KPASSWD constants and structures

KRB5_KPASSWD_PORT = 464
KRB5_KPASSWD_PROTOCOL_VERSION = 0xFF80
KRB5_KPASSWD_TGT_SPN = "kadmin/changepw"


class KPasswdResultCodes(Enum):
    SUCCESS = 0
    MALFORMED = 1
    HARDERROR = 2
    AUTHERROR = 3
    SOFTERROR = 4
    ACCESSDENIED = 5
    BAD_VERSION = 6
    INITIAL_FLAG_NEEDED = 7
    UNKNOWN = 0xFFFF


RESULT_MESSAGES = {
    0: "password changed successfully",
    1: "protocol error: malformed request",
    2: "server error (KRB5_KPASSWD_HARDERROR)",
    3: "authentication failed (may also indicate that the target user was not found)",
    4: "password change rejected (KRB5_KPASSWD_SOFTERROR)",
    5: "access denied",
    6: "protocol error: bad version",
    7: "protocol error: initial flag needed",
    0xFFFF: "unknown error",
}


class ChangePasswdData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("newpasswd", 0, univ.OctetString()),  # cleartext password
        _sequence_optional_component("targname", 1, PrincipalName()),
        _sequence_optional_component("targrealm", 2, Realm()),
    )


# PasswordPolicy parsing
# From https://github.com/GhostPack/Rubeus/blob/84610f13e4d47d1a952be3f5348dd1cb18bd92fa/Rubeus/lib/Reset.cs#L180


class PasswordPolicyFlags(Enum):
    Complex = 0x1
    NoAnonChange = 0x2
    NoClearChange = 0x4
    LockoutAdmins = 0x8
    StoreCleartext = 0x10
    RefusePasswordChange = 0x20


def _decodePasswordPolicy(ppolicyString):
    ppolicyStruct = "!HIIIQQ"
    ticksInADay = 86400 * 10_000_000

    if len(ppolicyString) != struct.calcsize(ppolicyStruct) or ppolicyString[0:2] != b"\x00\x00":
        raise ValueError

    properties = struct.unpack(ppolicyStruct, ppolicyString)
    passwordPolicy = {
        "minLength": properties[1],
        "history": properties[2],
        "maxAge": properties[4] / ticksInADay,
        "minAge": properties[5] / ticksInADay,
        "flags": [flag.name for flag in PasswordPolicyFlags if flag.value & properties[3]],
    }
    return passwordPolicy


# KPASSWD protocol messages


class KPasswdError(Exception):
    pass


def createKPasswdRequest(principal, domain, newPasswd, tgs, cipher, sessionKey, subKey,
                         targetPrincipal=None, targetDomain=None, sequenceNumber=None,
                         now=None, hostname=b"localhost"):

    # Generate the parameters that we need
    if sequenceNumber is None:
        sequenceNumber = int.from_bytes(get_random_bytes(4), "big")

    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    if not isinstance(newPasswd, bytes):
        newPasswd = newPasswd.encode("utf-8")

    # Build the Authenticator
    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", principal.components_to_asn1)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)
    authenticator["seq-number"] = sequenceNumber
    authenticator["subkey"] = univ.noValue
    authenticator["subkey"]["keytype"] = subKey.enctype
    authenticator["subkey"]["keyvalue"] = subKey.contents

    encodedAuthenticator = encoder.encode(authenticator)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    LOG.debug("b64(authenticator): {}".format(base64.b64encode(encodedAuthenticator)))

    # Build the AP_REQ
    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(ApplicationTagNumbers.AP_REQ.value)
    apReq["ap-options"] = encodeFlags(list())
    seq_set(apReq, "ticket", tgs.to_asn1)
    apReq["authenticator"] = univ.noValue
    apReq["authenticator"]["etype"] = cipher.enctype
    apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

    apReqEncoded = encoder.encode(apReq)

    # Build the ChangePasswdData structure
    changePasswdData = ChangePasswdData()
    changePasswdData["newpasswd"] = newPasswd
    if targetDomain and targetPrincipal:
        changePasswdData["targrealm"] = targetDomain.upper()
        changePasswdData["targname"] = univ.noValue
        changePasswdData["targname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
        changePasswdData["targname"]["name-string"][0] = targetPrincipal

    encodedChangePasswdData = encoder.encode(changePasswdData)

    LOG.debug("b64(changePasswdData): {}".format(base64.b64encode(encodedChangePasswdData)))

    # Build the EncKrbPrivPart structure
    encKrbPrivPart = EncKrbPrivPart()
    encKrbPrivPart["user-data"] = encoder.encode(changePasswdData)
    encKrbPrivPart["seq-number"] = sequenceNumber
    encKrbPrivPart["s-address"] = univ.noValue
    encKrbPrivPart["s-address"]["addr-type"] = AddressType.IPv4.value
    encKrbPrivPart["s-address"]["address"] = hostname

    # Key Usage 13.
    # KRB-PRIV encrypted part, encrypted with a key chosen by
    # the application (Section 5.7.1)
    encodedEncKrbPrivPart = encoder.encode(encKrbPrivPart)
    encryptedEncKrbPrivPart = cipher.encrypt(subKey, 13, encodedEncKrbPrivPart, None)

    LOG.debug("b64(encKrbPrivPart): {}".format(base64.b64encode(encodedEncKrbPrivPart)))

    # Build the KRB_PRIV
    krbPriv = KRB_PRIV()
    krbPriv["pvno"] = 5
    krbPriv["msg-type"] = int(ApplicationTagNumbers.KRB_PRIV.value)
    krbPriv["enc-part"] = univ.noValue
    krbPriv["enc-part"]["etype"] = cipher.enctype
    krbPriv["enc-part"]["cipher"] = encryptedEncKrbPrivPart

    krbPrivEncoded = encoder.encode(krbPriv)

    # Assemble the Kpasswd Request packet
    apReqLen = len(apReqEncoded)
    krbPrivLen = len(krbPrivEncoded)
    messageLen = 2 + 2 + 2 + apReqLen + krbPrivLen

    encoded = struct.pack("!HHH", messageLen, KRB5_KPASSWD_PROTOCOL_VERSION, apReqLen)
    encoded = encoded + apReqEncoded + krbPrivEncoded
    return encoded


def decodeKPasswdReply(encoded, cipher, subKey):
    # Extract the AP_REP and KRB_PRIV
    headerStruct = "!HHH"
    headerLen = struct.calcsize(headerStruct)
    try:
        headers = encoded[:headerLen]
        _, _, apRepLen = struct.unpack(headerStruct, headers)
        apRepEncoded = encoded[headerLen : headerLen + apRepLen]
        krbPrivEncoded = encoded[headerLen + apRepLen :]
    except:
        raise KPasswdError("kpasswd: malformed reply from the server")

    # Decode the ASN.1
    try:
        apRep = decoder.decode(apRepEncoded, asn1Spec=AP_REP())[0]
        krbPriv = decoder.decode(krbPrivEncoded, asn1Spec=KRB_PRIV())[0]
    except:
        raise KPasswdError("kpasswd: malformed AP_REP or KRB_PRIV in the reply from the server")

    # Decrypt the KRB_PRIV
    encryptedEncKrbPrivPart = krbPriv["enc-part"]["cipher"]
    try:
        # Key Usage 13.
        # KRB-PRIV encrypted part, encrypted with a key chosen by
        # the application (Section 5.7.1)
        encodedEncKrbPrivPart = cipher.decrypt(subKey, 13, encryptedEncKrbPrivPart)
    except:
        raise KPasswdError("kpasswd: cannot decrypt KRB_PRIV in the reply from the server")

    LOG.debug("b64(encKrbPrivPart): {}".format(base64.b64encode(encodedEncKrbPrivPart)))

    # Decode the result
    try:
        encKrbPrivPart = decoder.decode(encodedEncKrbPrivPart, asn1Spec=EncKrbPrivPart())[0]
        result = encKrbPrivPart["user-data"].asOctets()
        resultCode, message = int.from_bytes(result[:2], "big"), result[2:]
    except:
        raise KPasswdError("kpasswd: malformed EncKrbPrivPart in the KRB_PRIV in the reply from the server")

    # Interpret the return code and string
    LOG.debug("resultCode: {}, message: {}".format(resultCode, message))

    try:
        resultCodeMessage = RESULT_MESSAGES[resultCode]
    except KeyError:
        resultCodeMessage = RESULT_MESSAGES[0xFFFF]

    try:
        ppolicy = _decodePasswordPolicy(message)
        message = (
            "Password policy:"
            "\n\tMinimum length: {minLength}"
            "\n\tPassword history: {history}"
            "\n\tFlags: {flags}"
            "\n\tMaximum password age: {maxAge} days"
            "\n\tMinimum password age: {minAge} days"
        ).format(**ppolicy)
    except (ValueError, struct.error):
        try:
            message = message.decode("utf-8")
        except UnicodeDecodeError:
            message = binascii.hexlify(message).decode("latin-1")

    success = resultCode == KPasswdResultCodes.SUCCESS.value
    return success, resultCode, resultCodeMessage, message


# Wrapper functions

def changePassword(clientName, domain, newPasswd,
                   oldPasswd="", oldLmhash="", oldNthash="", aesKey="", TGT=None,
                   kdcHost=None, kpasswdHost=None, kpasswdPort=KRB5_KPASSWD_PORT, subKey=None):
    """
    Change the password of the requesting user with RFC 3244 Kerberos Change-Password protocol.

    At least one of oldPasswd, (oldLmhash, oldNthash) or (TGT, aesKey) should be defined.

    :param string clientName:   username of the account changing their password
    :param string domain:       domain of the account changing their password
    :param string newPasswd:    new password for the account
    :param string oldPasswd:    current password of the account
    :param string oldLmhash:    current LM hash of the account
    :param string oldNthash:    current NT hash of the account
    :param string aesKey:       current AES key of the account
    :param string TGT:          TGT of the account. It must be a TGT with a SPN of kadmin/changepw
    :param string kdcHost:      KDC address/hostname, used for Kerberos authentication
    :param string kpasswdHost:  KDC exposing the kpasswd service (TCP/464, UDP/464),
                                used when sending the password change requests
                                (Default: same as kdcHost)
    :param int kpasswdPort:     TCP port where kpasswd is exposed (Default: 464)
    :param string subKey:       Subkey to use to encrypt the password change request
                                (Default: generate a random one)

    :return void:               Raise an KPasswdError exception on error.
    """
    setPassword(
        clientName, domain, None, None, newPasswd,
        oldPasswd, oldLmhash, oldNthash, aesKey, TGT,
        kdcHost, kpasswdHost, kpasswdPort, subKey
    )


def setPassword(clientName, domain, targetName, targetDomain, newPasswd,
                oldPasswd="", oldLmhash="", oldNthash="", aesKey="", TGT=None,
                kdcHost=None, kpasswdHost=None, kpasswdPort=KRB5_KPASSWD_PORT, subKey=None):
    """
    Set the password of a target account with RFC 3244 Kerberos Set-Password protocol.
    Requires "Reset password" permission on the target, for the user.

    At least one of oldPasswd, (oldLmhash, oldNthash) or (TGT, aesKey) should be defined.

    :param string clientName:   username of the account performing the reset
    :param string domain:       domain of the account performing the reset
    :param string targetName:   username of the account whose password will be changed
    :param string targetDomain: domain of the account whose password will be changed
    :param string newPasswd:    new password for the target account
    :param string oldPasswd:    current password of the account performing the reset
    :param string oldLmhash:    current LM hash of the account performing the reset
    :param string oldNthash:    current NT hash of the account performing the reset
    :param string aesKey:       current AES key of the account performing the reset
    :param string TGT:          TGT of the account performing the reset
                                It must be a TGT with a SPN of kadmin/changepw
    :param string kdcHost:      KDC address/hostname, used for Kerberos authentication
    :param string kpasswdHost:  KDC exposing the kpasswd service (TCP/464, UDP/464),
                                used when sending the password change requests
                                (Default: same as kdcHost)
    :param int kpasswdPort:     TCP port where kpasswd is exposed (Default: 464)
    :param string subKey:       Subkey to use to encrypt the password change request
                                (Default: generate a random one)

    :return bool:               True if successful, raise an KPasswdError exception on error.
    """

    if kpasswdHost is None:
        kpasswdHost = kdcHost

    # Get a TGT for clientName
    userName = Principal(clientName, type=PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None and os.getenv("KRB5CCNAME"):
        KRB5CCNAME = os.getenv("KRB5CCNAME")
        try:
            ccache = CCache.loadFile(KRB5CCNAME)
        except:
            # No cache present
            pass
        else:
            LOG.debug("Using Kerberos cache: {}".format(KRB5CCNAME))
            principal = KRB5_KPASSWD_TGT_SPN
            creds = ccache.getCredential(principal, False)

            if creds is not None:
                TGT = creds.toTGT()
                LOG.info("Using TGT for {} from cache {}".format(principal, KRB5CCNAME))
            else:
                LOG.info("No valid TGT for {} found in cache {}".format(principal, KRB5CCNAME))

    if TGT is None:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            userName, oldPasswd, domain, oldLmhash, oldNthash, aesKey, kdcHost, serverName=KRB5_KPASSWD_TGT_SPN
        )
    else:
        tgt = TGT["KDC_REP"]
        cipher = TGT["cipher"]
        sessionKey = TGT["sessionKey"]

    # Extract the raw ticket from the TGT
    tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgt["ticket"])

    # Generate a random subkey (if not provided)
    if subKey is None:
        subKeyBytes = get_random_bytes(cipher.keysize)
        subKey = Key(cipher.enctype, subKeyBytes)

    # Generate the Request packet
    kpasswordReq = createKPasswdRequest(
        userName, domain, newPasswd, ticket, cipher, sessionKey, subKey, targetName, targetDomain
    )

    # Send the request to KPASSWD
    kpasswordRep = sendReceive(kpasswordReq, domain, kpasswdHost, kpasswdPort)

    # Decode the result
    success, resultCode, resultCodeMessage, message = decodeKPasswdReply(kpasswordRep, cipher, subKey)

    if success:
        return

    errorMessage = resultCodeMessage
    if message:
        errorMessage += ": " + message
    raise KPasswdError(errorMessage)
