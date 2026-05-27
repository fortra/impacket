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
#   NEGOEX: SPNEGO Extended Negotiation Security Mechanism, is provided to
#   allow SPNEGO to negotiate authentication mechanisms that require more
#   complex exchanges than the simple OID exchange SPNEGO supports, and to
#   address some of SPNEGO's limitations around use of OID as a pure method
#   of selection of authentication mechanisms. Additionally, NEGOEX provides
#   a new type of exchange, in the form of metadata tokens that provide
#   additional information about each of the proposed/exchanged authentication
#   mechanisms.
#
# References:
#   [MS-NEGOEX] - SPNEGO Extended Negotiation Security Mechanism
#   [IETFDRAFT-NEGOEX-04] - draft-zhu-negoex-04
#
# Author:
#   Abdul Mhanni
#
from enum import IntEnum
import uuid

from impacket import LOG
from impacket.structure import Structure


# [MS-NEGOEX] 2.2.3 MESSAGE_SIGNATURE: little-endian "NEGOEXTS" (0x535458454f47454e)
MESSAGE_SIGNATURE = b'NEGOEXTS'

# OID for NEGOEX inside SPNEGO (1.3.6.1.4.1.311.2.2.30).
NEGOEX_OID = b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e'

# [MS-NEGOEX] 2.2.3 / draft-zhu-negoex-04
CHECKSUM_SCHEME_RFC3961 = 1
NEGOEX_PROTOCOL_VERSION = 0

# [MS-NEGOEX] 2.2.3 - Alert type and reason code. Only one alert type
# (ALERT_TYPE_PULSE) and one reason (ALERT_VERIFY_NO_KEY) are defined.
ALERT_TYPE_PULSE = 1
ALERT_VERIFY_NO_KEY = 1

# draft-zhu-negoex-04 7.7 - RFC 3961 key usage numbers used when computing
# the VERIFY checksum. 23 when signed by the initiator, 25 when signed by
# the acceptor.
NEGOEX_KEYUSAGE_INITIATOR = 23
NEGOEX_KEYUSAGE_ACCEPTOR = 25

HEADER_SIZE = 40
NEGO_HEADER_SIZE = 96
EXCHANGE_HEADER_SIZE = 64
VERIFY_HEADER_SIZE = 80
ALERT_HEADER_SIZE = 68
CHECKSUM_HEADER_SIZE = 20

AUTH_SCHEME_SIZE = 16   # AUTH_SCHEME is a GUID (16 bytes). [MS-NEGOEX] 2.2.2, [MS-DTYP] 2.3.4.2
EXTENSION_SIZE = 12     # [MS-NEGOEX] 2.2.5.1.4
ALERT_SIZE = 12


class MESSAGE_TYPE(IntEnum):
    # [MS-NEGOEX] 2.2.6.1
    INITIATOR_NEGO = 0
    ACCEPTOR_NEGO = 1
    INITIATOR_META_DATA = 2
    ACCEPTOR_META_DATA = 3
    CHALLENGE = 4
    AP_REQUEST = 5
    VERIFY = 6
    ALERT = 7


# Message types carried in an EXCHANGE_MESSAGE.
EXCHANGE_MESSAGE_TYPES = (
    MESSAGE_TYPE.INITIATOR_META_DATA,
    MESSAGE_TYPE.ACCEPTOR_META_DATA,
    MESSAGE_TYPE.CHALLENGE,
    MESSAGE_TYPE.AP_REQUEST,
)


def _checkHeader(header, expectedHeaderLen, actualLen, name):
    cbHeader = header['cbHeaderLength']
    cbMessage = header['cbMessageLength']

    if cbHeader != expectedHeaderLen:
        raise NegoExParseError(
            '%s.cbHeaderLength expected %d, got %d' % (name, expectedHeaderLen, cbHeader),
            field='%s.cbHeaderLength' % name,
        )
    if cbMessage < cbHeader:
        raise NegoExParseError(
            '%s.cbMessageLength smaller than cbHeaderLength' % name,
            field='%s.cbMessageLength' % name,
        )
    if cbMessage != actualLen:
        raise NegoExParseError(
            '%s.cbMessageLength = %d but slice is %d bytes' % (name, cbMessage, actualLen),
            field='%s.cbMessageLength' % name,
        )


def _messageHeader(messageType, seqNum, conversationId, headerLen, messageLen):
    header = MessageHeader()
    header['Signature'] = MESSAGE_SIGNATURE
    header['MessageType'] = messageType
    header['SequenceNum'] = seqNum
    header['cbHeaderLength'] = headerLen
    header['cbMessageLength'] = messageLen
    header['ConversationId'] = conversationId.bytes_le
    return header


class MessageHeader(Structure):
    # [MS-NEGOEX] 2.2.6.2
    structure = (
        ('Signature', '8s=b"NEGOEXTS"'),
        ('MessageType', '<L=0'),
        ('SequenceNum', '<L=0'),
        ('cbHeaderLength', '<L=0'),
        ('cbMessageLength', '<L=0'),
        ('ConversationId', '16s=""'),
    )

    def fromString(self, data):
        if len(data) < HEADER_SIZE:
            raise NegoExParseError('Truncated MESSAGE_HEADER', field='Header')
        Structure.fromString(self, data)
        if self['Signature'] != MESSAGE_SIGNATURE:
            raise NegoExParseError('Invalid NEGOEX signature', field='Header.Signature')


class Checksum(Structure):
    # [MS-NEGOEX] 2.2.5.1.3
    structure = (
        ('cbHeaderLength', '<I=20'),
        ('ChecksumScheme', '<I=1'),
        ('ChecksumType', '<I=0'),
        ('ChecksumOffset', '<I=0'),
        ('ChecksumLength', '<I=0'),
    )


class Extension(Structure):
    # [MS-NEGOEX] 2.2.5.1.4
    structure = (
        ('ExtensionType', '<I=0'),
        ('ByteArrayOffset', '<I=0'),
        ('ByteArrayLength', '<I=0'),
    )

    def __init__(self, data=None):
        self.ExtensionValue = b''
        Structure.__init__(self, data)

    def isCritical(self):
        # [MS-NEGOEX] 2.2.5.1.4: all negative extension types (highest bit set)
        # are critical and must be rejected if unknown.
        return (self['ExtensionType'] & 0x80000000) != 0

    def isKnown(self):
        return

class Alert(Structure):
    # [MS-NEGOEX] 2.2.5.1.2
    structure = (
        ('AlertType', '<I=1'),
        ('ByteArrayOffset', '<I=0'),
        ('ByteArrayLength', '<I=0'),
    )

    def __init__(self, data=None):
        self.AlertValue = b''
        Structure.__init__(self, data)


class AlertPulse(Structure):
    # [MS-NEGOEX] 2.2.5.1.2.1
    structure = (
        ('cbHeaderLength', '<I=8'),
        ('Reason', '<I=1'),
    )


class AuthSchemeVector(Structure):
    # [MS-NEGOEX] 2.2.5.2.2
    structure = (
        ('ArrayOffset', '<I=0'),
        ('Count', '<H=0'),
        ('Pad', '2s=""'),
    )


class ExtensionVector(Structure):
    # [MS-NEGOEX] 2.2.5.2.4
    structure = (
        ('ArrayOffset', '<I=0'),
        ('Count', '<H=0'),
        ('Pad', '2s=""'),
    )


class NegoMessage(Structure):
    # [MS-NEGOEX] 2.2.6.3
    structure = (
        ('Header', ':', MessageHeader),
        ('Random', '32s=""'),
        ('ProtocolVersion', '<Q=0'),
        ('AuthSchemes', ':', AuthSchemeVector),
        ('Extensions', ':', ExtensionVector),
        ('Payload', ':'),
    )

    def __init__(self, data=None):
        self._authSchemes = []
        self._extensions = []
        Structure.__init__(self, data)

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], NEGO_HEADER_SIZE, len(data), 'NegoMessage.Header')

        if self['Header']['MessageType'] not in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            raise NegoExParseError('Invalid NEGO_MESSAGE type: %r' % self['Header']['MessageType'])
        if self['ProtocolVersion'] != NEGOEX_PROTOCOL_VERSION:
            raise NegoExParseError('Unsupported NEGOEX protocol version: %r' % self['ProtocolVersion'])

        offset = self['AuthSchemes']['ArrayOffset']
        length = self['AuthSchemes']['Count'] * AUTH_SCHEME_SIZE
        authBlob = data[offset:offset + length]
        if len(authBlob) != length:
            raise NegoExParseError('AuthSchemes extends beyond message', offset=offset, field='AuthSchemes')
        self._authSchemes = [uuid.UUID(bytes_le=authBlob[i:i + AUTH_SCHEME_SIZE]) for i in range(0, len(authBlob), AUTH_SCHEME_SIZE)]

        offset = self['Extensions']['ArrayOffset']
        length = self['Extensions']['Count'] * EXTENSION_SIZE
        extBlob = data[offset:offset + length]
        if len(extBlob) != length:
            raise NegoExParseError('Extensions extends beyond message', offset=offset, field='Extensions')
        self._extensions = []
        for i in range(0, len(extBlob), EXTENSION_SIZE):
            ext = Extension(extBlob[i:i + EXTENSION_SIZE])
            valueOffset = ext['ByteArrayOffset']
            ext.ExtensionValue = data[valueOffset:valueOffset + ext['ByteArrayLength']]
            self._extensions.append(ext)

    def getAuthSchemeList(self):
        return self._authSchemes

    def getExtensionList(self):
        return self._extensions


class ExchangeMessage(Structure):
    # [MS-NEGOEX] 2.2.6.4
    structure = (
        ('Header', ':', MessageHeader),
        ('AuthScheme', '16s=""'),
        ('ExchangeOffset', '<I=0'),
        ('ExchangeLength', '<I=0'),
        ('Exchange', ':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], EXCHANGE_HEADER_SIZE, len(data), 'ExchangeMessage.Header')

        try:
            msgType = MESSAGE_TYPE(self['Header']['MessageType'])
        except ValueError:
            raise NegoExParseError('Invalid EXCHANGE_MESSAGE type: %r' % self['Header']['MessageType'])
        if msgType not in EXCHANGE_MESSAGE_TYPES:
            raise NegoExParseError('Invalid EXCHANGE_MESSAGE type: %r' % self['Header']['MessageType'])

        offset = self['ExchangeOffset']
        self['Exchange'] = data[offset:offset + self['ExchangeLength']]


class VerifyMessage(Structure):
    # [MS-NEGOEX] 2.2.6.5
    structure = (
        ('Header', ':', MessageHeader),
        ('AuthScheme', '16s=""'),
        ('CHeader', ':', Checksum),
        # 4-byte alignment pad, see VERIFY_HEADER_SIZE.
        ('Pad', '4s=""'),
        ('ChecksumValue', ':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], VERIFY_HEADER_SIZE, len(data), 'VerifyMessage.Header')

        if self['Header']['MessageType'] != MESSAGE_TYPE.VERIFY:
            raise NegoExParseError('Invalid VERIFY_MESSAGE type: %r' % self['Header']['MessageType'])
        if self['CHeader']['cbHeaderLength'] != CHECKSUM_HEADER_SIZE:
            raise NegoExParseError('Invalid CHECKSUM header length', field='CHeader.cbHeaderLength')
        if self['CHeader']['ChecksumScheme'] != CHECKSUM_SCHEME_RFC3961:
            raise NegoExParseError('Unsupported CHECKSUM scheme', field='CHeader.ChecksumScheme')

        offset = self['CHeader']['ChecksumOffset']
        self['ChecksumValue'] = data[offset:offset + self['CHeader']['ChecksumLength']]


class AlertMessage(Structure):
    # [MS-NEGOEX] 2.2.6.6
    structure = (
        ('Header', ':', MessageHeader),
        ('AuthScheme', '16s=""'),
        ('ErrorCode', '<I=0'),
        ('AlertArrayOffset', '<I=0'),
        ('AlertCount', '<H=0'),
        ('AlertPad', '2s=""'),
        ('Payload', ':'),
    )

    def __init__(self, data=None):
        self._alerts = []
        Structure.__init__(self, data)

    def fromString(self, data):
        Structure.fromString(self, data)
        _checkHeader(self['Header'], ALERT_HEADER_SIZE, len(data), 'AlertMessage.Header')

        if self['Header']['MessageType'] != MESSAGE_TYPE.ALERT:
            raise NegoExParseError('Invalid ALERT_MESSAGE type: %r' % self['Header']['MessageType'])

        offset = self['AlertArrayOffset']
        length = self['AlertCount'] * ALERT_SIZE
        alertBlob = data[offset:offset + length]
        if len(alertBlob) != length:
            raise NegoExParseError('Alerts extends beyond message', offset=offset, field='Alerts')
        self._alerts = []
        for i in range(0, len(alertBlob), ALERT_SIZE):
            alert = Alert(alertBlob[i:i + ALERT_SIZE])
            valueOffset = alert['ByteArrayOffset']
            alert.AlertValue = data[valueOffset:valueOffset + alert['ByteArrayLength']]
            self._alerts.append(alert)

    def getAlertList(self):
        return self._alerts


class ParsedMessage(object):
    """One element of the list returned by parseNegoExToken.

    message_type is the raw integer from the wire. message is the parsed
    Structure, or None if the type was unknown. raw_data is the exact bytes
    for that message (including header), used when computing VERIFY checksums.
    """

    def __init__(self, messageType, message, offset, rawData):
        self.message_type = messageType
        self.message = message
        self.offset = offset
        self.raw_data = rawData


def parseNegoExToken(data):
    """Split a concatenated NEGOEX token into its component messages.

    Per [MS-NEGOEX] 3.1.5.1, a context-level token is one or more NEGOEX
    messages concatenated together. Each message advertises its own length
    in the header, so we traverse until consumed.
    """
    messages = []
    offset = 0

    while offset < len(data):
        if len(data) - offset < HEADER_SIZE:
            raise NegoExParseError('Truncated NEGOEX header', offset=offset, field='Header')

        header = MessageHeader(data[offset:offset + HEADER_SIZE])
        msgLength = header['cbMessageLength']
        if msgLength < HEADER_SIZE:
            raise NegoExParseError('Invalid cbMessageLength: %d' % msgLength, offset=offset, field='Header.cbMessageLength')
        if msgLength > len(data) - offset:
            raise NegoExParseError('Truncated NEGOEX message', offset=offset, field='Header.cbMessageLength')

        msgData = data[offset:offset + msgLength]
        rawType = header['MessageType']

        try:
            msgType = MESSAGE_TYPE(rawType)
        except ValueError:
            LOG.warning('Unknown NEGOEX MessageType: %r' % rawType)
            messages.append(ParsedMessage(rawType, None, offset, msgData))
            offset += msgLength
            continue

        if msgType in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            message = NegoMessage(msgData)
        elif msgType in EXCHANGE_MESSAGE_TYPES:
            message = ExchangeMessage(msgData)
        elif msgType == MESSAGE_TYPE.VERIFY:
            message = VerifyMessage(msgData)
        elif msgType == MESSAGE_TYPE.ALERT:
            message = AlertMessage(msgData)
        else:
            raise NegoExParseError('Unhandled NEGOEX MessageType: %r' % rawType, offset=offset)

        messages.append(ParsedMessage(msgType, message, offset, msgData))
        offset += msgLength

    return messages


class NegoExContext(object):
    """Drives a NEGOEX negotiation as either initiator or acceptor."""

    def __init__(self, isInitiator=True):
        self.isInitiator = isInitiator
        # 16-byte conversation ID, generated by the initiator and echoed by
        # the acceptor in all messages. [MS-NEGOEX] 2.2.3
        self.conversationId = None
        # The scheme selected for the exchange.
        self.selectedScheme = None
        self._seqNum = 0
        # Schemes registered by the caller to offer to the acceptor, and the
        # order in which they are offered.
        self._authSchemes = {}
        self._authSchemeOrder = []
        # Schemes mutually supported by initiator and acceptor.
        self._mutualSchemes = []
        # All messages sent and received, for the VERIFY checksum computation.
        self._messageHistory = []
        self._verifySent = False
        self._verifyReceived = False

    def registerAuthScheme(self, scheme):
        schemeId = scheme.getAuthSchemeId()
        self._authSchemes[schemeId] = scheme
        self._authSchemeOrder.append(schemeId)


class NegoExError(Exception):
    pass


class NegoExParseError(NegoExError):
    def __init__(self, message, offset=None, field=None):
        self.offset = offset
        self.field = field
        parts = [message]
        if field is not None:
            parts.append('field=%s' % field)
        if offset is not None:
            parts.append('offset=0x%x' % offset)
        Exception.__init__(self, ' | '.join(parts))


class NegoExChecksumError(NegoExError):
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual
        NegoExError.__init__(self, 'NEGOEX VERIFY checksum mismatch: expected %s, got %s' % (expected.hex(), actual.hex()),)
