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
import os

from impacket import LOG
from impacket.krb5.crypto import make_checksum, Key
from impacket.structure import Structure


# [MS-NEGOEX] 2.2.3 MESSAGE_SIGNATURE: little-endian "NEGOEXTS" (0x535458454f47454e)
MESSAGE_SIGNATURE = b'NEGOEXTS'

# OID for NEGOEX inside SPNEGO (1.3.6.1.4.1.311.2.2.30).
NEGOEX_OID = b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e'

AUTH_SCHEME_PKU2U = uuid.UUID('235f69ad-73fb-4dbc-8203-0629e739339b')

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

################################################################################
# CONSTANTS
################################################################################

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

################################################################################
# INTERNAL HELPER THINGIES
################################################################################
def _normalizeGuid(value):
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, bytes) and len(value) == 16:
        return uuid.UUID(bytes_le=value)
    if isinstance(value, str):
        return uuid.UUID(value)
    raise NegoExError(f'Invalid GUID value: {value!r}')


def _normalizeGuidBytes(value):
    return _normalizeGuid(value).bytes_le


def _asBytes(value, name):
    if value is None:
        return b''
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise NegoExError(f'{name} must be bytes or str, got {type(value)}')


def _checkHeader(header, expectedHeaderLen, actualLen, name):
    signature = header['Signature']
    cbHeader = header['cbHeaderLength']
    cbMessage = header['cbMessageLength']

    if signature != MESSAGE_SIGNATURE:
        raise NegoExParseError(
            f'{name}.Signature invalid: {signature!r}',
            field=f'{name}.Signature',
        )
    if cbHeader != expectedHeaderLen:
        raise NegoExParseError(
            f'{name}.cbHeaderLength expected {expectedHeaderLen}, got {cbHeader}',
            field=f'{name}.cbHeaderLength',
        )
    if cbMessage < cbHeader:
        raise NegoExParseError(
            f'{name}.cbMessageLength smaller than cbHeaderLength',
            field=f'{name}.cbMessageLength',
        )
    if cbMessage != actualLen:
        raise NegoExParseError(
            f'{name}.cbMessageLength = {cbMessage} but slice is {actualLen} bytes',
            field=f'{name}.cbMessageLength',
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

#This helper is used to slice out variable-length fields in messages, and performs bounds checking
#This was added since otherwise, in certain test cases we had 4 failures that were due to malformed
#messages struct errors and not negoex parsing errors
def _sliceMessageData(data, offset, length, field):
    if length == 0:
        return b''
    if offset + length > len(data):
        raise NegoExParseError(
            f'{field} extends beyond message',
            offset=offset,
            field=field,
        )
    return data[offset:offset + length]

################################################################################
# STRUCTURES
################################################################################

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
            raise NegoExParseError(f'Invalid NEGO_MESSAGE type: {self["Header"]["MessageType"]}')
        if self['ProtocolVersion'] != NEGOEX_PROTOCOL_VERSION:
            raise NegoExParseError(f'Unsupported NEGOEX protocol version: {self["ProtocolVersion"]}')

        offset = self['AuthSchemes']['ArrayOffset']
        length = self['AuthSchemes']['Count'] * AUTH_SCHEME_SIZE
        authBlob = data[offset:offset + length]
        if len(authBlob) != length:
            raise NegoExParseError('AuthSchemes extends beyond message', offset=offset, field='AuthSchemes')
        self._authSchemes = [_normalizeGuidBytes(authBlob[i:i + AUTH_SCHEME_SIZE]) for i in range(0, len(authBlob), AUTH_SCHEME_SIZE)]

        offset = self['Extensions']['ArrayOffset']
        length = self['Extensions']['Count'] * EXTENSION_SIZE
        extBlob = data[offset:offset + length]
        if len(extBlob) != length:
            raise NegoExParseError('Extensions extends beyond message', offset=offset, field='Extensions')
        self._extensions = []
        for i in range(0, len(extBlob), EXTENSION_SIZE):
            ext = Extension(extBlob[i:i + EXTENSION_SIZE])
            valueOffset = ext['ByteArrayOffset']
            #ext.ExtensionValue = data[valueOffset:valueOffset + ext['ByteArrayLength']]
            ext.ExtensionValue = _sliceMessageData(data, valueOffset, ext['ByteArrayLength'], 'ExtensionValue')
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
            raise NegoExParseError(f'Invalid EXCHANGE_MESSAGE type: {self["Header"]["MessageType"]}')
        if msgType not in EXCHANGE_MESSAGE_TYPES:
            raise NegoExParseError(f'Invalid EXCHANGE_MESSAGE type: {self["Header"]["MessageType"]}')

        offset = self['ExchangeOffset']
        self['Exchange'] = _sliceMessageData(data, offset, self['ExchangeLength'], 'Exchange')
    
    def getAuthScheme(self):
        return _normalizeGuidBytes(self['AuthScheme'])

    def getExchangeData(self):
        return self['Exchange']

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
            raise NegoExParseError(f'Invalid VERIFY_MESSAGE type: {self["Header"]["MessageType"]}')
        if self['CHeader']['cbHeaderLength'] != CHECKSUM_HEADER_SIZE:
            raise NegoExParseError('Invalid CHECKSUM header length', field='CHeader.cbHeaderLength')
        if self['CHeader']['ChecksumScheme'] != CHECKSUM_SCHEME_RFC3961:
            raise NegoExParseError('Unsupported CHECKSUM scheme', field='CHeader.ChecksumScheme')

        offset = self['CHeader']['ChecksumOffset']
        self['ChecksumValue'] = _sliceMessageData(data, offset, self['CHeader']['ChecksumLength'], 'ChecksumValue')

    def getChecksumValue(self):
        return self['ChecksumValue']

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
            alert.AlertValue = _sliceMessageData(data, valueOffset, alert['ByteArrayLength'], 'AlertValue')
            self._alerts.append(alert)

    def getAlertList(self):
        return self._alerts

################################################################################
# NEGOEX TOKEN PARSING AND MESSAGE CREATION FUNCTIONS
################################################################################

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
    
    def getRawData(self):
        return self.raw_data
    
    def getMessageType(self):
        return self.message_type
    

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
            LOG.warning(f'Unknown NEGOEX MessageType: {rawType}')
            messages.append(ParsedMessage(rawType, None, offset, msgData))
            offset += msgLength
            continue
        #this is super ugly but since impacket supports python v 3.9 then theres no match/case support : ( 
        if msgType in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            message = NegoMessage(msgData)
        elif msgType in EXCHANGE_MESSAGE_TYPES:
            message = ExchangeMessage(msgData)
        elif msgType == MESSAGE_TYPE.VERIFY:
            message = VerifyMessage(msgData)
        elif msgType == MESSAGE_TYPE.ALERT:
            message = AlertMessage(msgData)
        else:
            raise NegoExParseError(f'Unhandled NEGOEX MessageType: {rawType}', offset=offset)

        messages.append(ParsedMessage(msgType, message, offset, msgData))
        offset += msgLength

    return messages

#Section 2.2.6.3 of MS-NEGOEX
def createNegoMessage(messageType, seqNum, conversationId, authSchemes, extensions=None):
    """Create a NEGO message and return its message object."""
    if messageType not in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
        raise NegoExError('Invalid message type for NEGO_MESSAGE: %r' % messageType)

    authParts = [_normalizeGuidBytes(scheme) for scheme in authSchemes]
    authentication_scheme_count = len(authParts)
    authPayload = b''.join(authParts)
    authOffset = NEGO_HEADER_SIZE if authentication_scheme_count else 0

    extensions = extensions or []
    extensions_count = len(extensions)
    extOffset = NEGO_HEADER_SIZE + len(authPayload) if extensions_count else 0
    extHeaders = b''
    extValues = b''

    if extensions_count:
        valueBase = extOffset + extensions_count * EXTENSION_SIZE
        for extType, extValue in extensions:
            # extValue should be bytes
            extValue = _asBytes(extValue, 'extension value')
            ext = Extension()
            ext['ExtensionType'] = extType
            ext['ByteArrayOffset'] = valueBase + len(extValues) if extValue else 0
            ext['ByteArrayLength'] = len(extValue)
            extHeaders += ext.getData()
            extValues += extValue

    payload = authPayload + extHeaders + extValues

    msg = NegoMessage()
    msg['Header'] = _messageHeader(messageType, seqNum, conversationId, NEGO_HEADER_SIZE, NEGO_HEADER_SIZE + len(payload))
    msg['Random'] = os.urandom(32)
    msg['ProtocolVersion'] = NEGOEX_PROTOCOL_VERSION
    msg['AuthSchemes'] = AuthSchemeVector()
    msg['AuthSchemes']['ArrayOffset'] = authOffset
    msg['AuthSchemes']['Count'] = authentication_scheme_count
    msg['Extensions'] = ExtensionVector()
    msg['Extensions']['ArrayOffset'] = extOffset
    msg['Extensions']['Count'] = extensions_count
    msg['Payload'] = payload
    return msg.getData()

#Section 2.2.6.4 of MS-NEGOEX
def createExchangeMessage(messageType, seqNum, conversationId, authScheme, exchangeData):
    if messageType not in EXCHANGE_MESSAGE_TYPES:
        raise NegoExError(f'Invalid message type for EXCHANGE_MESSAGE: {messageType}')

    exchangeData = _asBytes(exchangeData, 'exchangeData')
    exchangeLen = len(exchangeData)

    msg = ExchangeMessage()
    msg['Header'] = _messageHeader(messageType, seqNum, conversationId, EXCHANGE_HEADER_SIZE, EXCHANGE_HEADER_SIZE + exchangeLen)
    msg['AuthScheme'] = _normalizeGuidBytes(authScheme)
    msg['ExchangeOffset'] = EXCHANGE_HEADER_SIZE if exchangeLen else 0
    msg['ExchangeLength'] = exchangeLen
    msg['Exchange'] = exchangeData
    return msg.getData()

#Section 2.2.6.5 of MS-NEGOEX
def createVerifyMessage(seqNum, conversationId, authScheme, checksumValue, checksumType):
    checksumValue = _asBytes(checksumValue, 'checksumValue')

    msg = VerifyMessage()
    msg['Header'] = _messageHeader(MESSAGE_TYPE.VERIFY, seqNum, conversationId, VERIFY_HEADER_SIZE,VERIFY_HEADER_SIZE + len(checksumValue))
    msg['AuthScheme'] = _normalizeGuidBytes(authScheme)
    msg['CHeader'] = Checksum()
    msg['CHeader']['cbHeaderLength'] = CHECKSUM_HEADER_SIZE
    msg['CHeader']['ChecksumScheme'] = CHECKSUM_SCHEME_RFC3961
    msg['CHeader']['ChecksumType'] = checksumType
    msg['CHeader']['ChecksumOffset'] = VERIFY_HEADER_SIZE if checksumValue else 0
    msg['CHeader']['ChecksumLength'] = len(checksumValue)
    msg['Pad'] = b'\x00' * 4
    msg['ChecksumValue'] = checksumValue
    return msg.getData()

#Section 2.2.6.6 of MS-NEGOEX
def createAlertMessage(seqNum, conversationId, authScheme, errorCode=0, reason=ALERT_VERIFY_NO_KEY):
    pulse = AlertPulse()
    pulse['Reason'] = reason
    pulseData = pulse.getData()

    alert = Alert()
    alert['AlertType'] = ALERT_TYPE_PULSE
    alert['ByteArrayOffset'] = ALERT_HEADER_SIZE + ALERT_SIZE  
    alert['ByteArrayLength'] = len(pulseData)

    payload = alert.getData() + pulseData

    msg = AlertMessage()
    msg['Header'] = _messageHeader(MESSAGE_TYPE.ALERT, seqNum, conversationId, ALERT_HEADER_SIZE, ALERT_HEADER_SIZE + len(payload))
    msg['AuthScheme'] = _normalizeGuidBytes(authScheme)
    msg['ErrorCode'] = errorCode
    msg['AlertArrayOffset'] = ALERT_HEADER_SIZE
    msg['AlertCount'] = 1
    msg['Payload'] = payload
    return msg.getData()


################################################################################
# NEGOEX STATE MACHINE IMPLEMENTATION 
################################################################################

class NegoExContext(object):
    """Drives a NEGOEX negotiation as either initiator or acceptor.
    """

    def __init__(self, isInitiator=True):
        #Since mostly impacket is used for pentesting, safe to assume the person running will be iniator
        self.isInitiator = isInitiator
        self.conversationId = None
        #The scheme selected for use for the exchange.
        self.selectedScheme = None
        self._seqNum = 0
        self._authSchemes = {}
        #The order in which the exchange will decide which scheme will end up being selected.
        self._authSchemeOrder = []
        self._mutualSchemes = []
        #Used to track all messages sent and recieved during the whole exchaange for use in the VERIFY msg checkum creation
        self._messageHistory = []
        self._verifySent = False
        self._verifyReceived = False
    
    def registerAuthScheme(self, scheme):
        schemeId = _normalizeGuid(scheme.getAuthSchemeId())
        self._authSchemes[schemeId] = scheme
        self._authSchemeOrder.append(schemeId)

    def createInitialToken(self, optimisticToken=None):
        """Build the INITIATOR_NEGO token with our single auth scheme. We dont really care about extensions or metadata since I expect like with SPENGO
        that impacket consumers will only initate one authentication scheme at a time. Like you never see someone offering ntlm and kerberos and krb u 2 u in mechlist in spengo.
        If the caller sends in an optimsitic token, which is defined in MS-NEGOEX §3.1.5.4 and §1.3 then you can avoid a round trip : )"""
        
        if not self._authSchemeOrder:
            raise NegoExError('No auth schemes registered')
 
        if self.conversationId is None:
            self.conversationId = _normalizeGuid(os.urandom(16))
 
        self.selectedScheme = self._authSchemeOrder[0]
 
        negoBytes = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, self._nextSeq(), self.conversationId, self._authSchemeOrder)
        self._messageHistory.append(negoBytes)
        
        if optimisticToken is None:
            return negoBytes

        apBytes = createExchangeMessage(MESSAGE_TYPE.AP_REQUEST, self._nextSeq(), self.conversationId, self.selectedScheme, optimisticToken)
        self._messageHistory.append(apBytes)
        
        return negoBytes + apBytes
    
    def createContextToken(self, exchangeData, includeVerify=False):
        #this builds the EXCHANGE_MESSAGE for non-initial turns during the negoex exchange.
        if self.selectedScheme is None:
            raise NegoExError('No NEGOEX mechanism selected')

        msgType = MESSAGE_TYPE.AP_REQUEST if self.isInitiator else MESSAGE_TYPE.CHALLENGE
        tokenParts = []

        if exchangeData:
            exchangeBytes = createExchangeMessage(msgType, self._nextSeq(), self.conversationId, self.selectedScheme, exchangeData)
            tokenParts.append(exchangeBytes)
            self._messageHistory.append(exchangeBytes)

        if includeVerify:
            verifyBytes = self._createVerify()
            if verifyBytes:
                tokenParts.append(verifyBytes)
                # _createVerify computes its checksum from
                # _messageHistory before the VERIFY is appended, so we
                # only append after the checksum is sealed. Check comments below for more
                self._messageHistory.append(verifyBytes)

        return b''.join(tokenParts)
    
    # [MS-NEGOEX] 3.1.5.6
    def processToken(self, data):
        """Process an incoming NEGOEX token using parseNegoExToken().
 
       Returns the exchange payload bytes for the caller to pass to their
        auth scheme, or None if no exchange data was present.
        """
        #NOTE: This function fails the exchange if the peer doesnt send or pick our authentication scheme 
        messages = parseNegoExToken(data)
        exchangePayload = None
        pendingVerify = []
 
        for pm in messages:
            # Defer VERIFY so its checksum is validated against all prior messages
            if pm.message_type == MESSAGE_TYPE.VERIFY:
                pendingVerify.append(pm)
                continue
            self._validateConversationId(pm.message)
            self._messageHistory.append(pm.raw_data)
 
            if pm.message is None:
                continue
 
            if pm.message_type in (MESSAGE_TYPE.ACCEPTOR_NEGO, MESSAGE_TYPE.INITIATOR_NEGO):
                self._processNego(pm.message_type, pm.message)
 
            elif pm.message_type in (MESSAGE_TYPE.CHALLENGE, MESSAGE_TYPE.AP_REQUEST):
                peerScheme = _normalizeGuid(pm.message.getAuthScheme())
                if self.selectedScheme and peerScheme != self.selectedScheme:
                    raise NegoExError('Exchange AuthScheme mismatch: expected {self.selectedScheme}, got {peerScheme}')
                exchangePayload = pm.message.getExchangeData()
 
            elif pm.message_type == MESSAGE_TYPE.ALERT:
                self._processAlert(pm.message)
            self._seqNum = self._seqNum + 1
            # META_DATA messages are recorded in history
            # for checksum purposes but otherwise ignored
            # Since this is impacket, we only offer one scheme
            # so there is nothing to negotiate based on metadata.
 
        # Now validate any VERIFY messages against the complete history
        for pm in pendingVerify:
            self._processVerify(pm.message)
            self._messageHistory.append(pm.raw_data)
            self._seqNum = self._seqNum + 1
 
        return exchangePayload
    
    def _processNego(self, messageType, negoMsg):
        """Process an incoming NEGO_MESSAGE, validating ConversationId and
        computing the mutually supported auth scheme set."""
        peerConversationId = _normalizeGuid(negoMsg['Header']['ConversationId'])
        if self.conversationId is None:
            self.conversationId = peerConversationId
        elif self.conversationId != peerConversationId:
            raise NegoExError('NEGOEX ConversationId mismatch')

        peerSchemes = [_normalizeGuid(s) for s in negoMsg.getAuthSchemeList()]

        if messageType == MESSAGE_TYPE.INITIATOR_NEGO:
            if self.isInitiator:
                raise NegoExError('Initiator received unexpected INITIATOR_NEGO')

            self._mutualSchemes = [
                schemeId for schemeId in self._authSchemeOrder
                if schemeId in peerSchemes
            ]
            if not self._mutualSchemes:
                raise NegoExError('No mutually supported NEGOEX auth scheme')

            self.selectedScheme = self._mutualSchemes[0]
            return

        if messageType == MESSAGE_TYPE.ACCEPTOR_NEGO:
            if not self.isInitiator:
                raise NegoExError('Acceptor received unexpected ACCEPTOR_NEGO')
            if self.selectedScheme not in peerSchemes:
                raise NegoExError(f'Auth scheme {self.selectedScheme} was not accepted by peer')
            return

        raise NegoExError(f'Unexpected NEGOEX negotiation message type: {messageType}')

    def _validateConversationId(self, msg):
        """Verify the ConversationId in any incoming message matches our context."""
        peerConvId = _normalizeGuid(msg['Header']['ConversationId'])
        if self.conversationId is None:
            self.conversationId = peerConvId
        elif self.conversationId != peerConvId:
            raise NegoExError(f'ConversationId mismatch: expected {self.conversationId}, got {peerConvId}')
            
    def _processVerify(self, verifyMsg):
        """Validate an incoming VERIFY_MESSAGE checksum"""

        scheme = self._authSchemes.get(self.selectedScheme)
        if scheme is None:
            raise NegoExError('No auth scheme available for VERIFY validation')
 
        keyInfo = scheme.getVerifyKey()
        if keyInfo is None:
            raise NegoExError('Auth scheme has no verify key for VERIFY validation')
 
        keyBytes, enctype, checksumType = keyInfo
 
        keyUsage = NEGOEX_KEYUSAGE_ACCEPTOR if self.isInitiator else NEGOEX_KEYUSAGE_INITIATOR
 
        checksumInput = b''.join(self._messageHistory)
        expectedChecksum = make_checksum(checksumType, Key(enctype, keyBytes), keyUsage, checksumInput)
        actualChecksum = verifyMsg.getChecksumValue()
 
        if expectedChecksum != actualChecksum:
            raise NegoExChecksumError(expectedChecksum, actualChecksum)
 
        self._verifyReceived = True
    

    def _createVerify(self):
        if self._verifySent or self.selectedScheme is None:
            return None

        scheme = self._authSchemes.get(self.selectedScheme)
        if scheme is None:
            return None

        keyInfo = scheme.getVerifyKey()
        if keyInfo is None:
            return None

        keyBytes, enctype, checksumType = keyInfo
        #We are only a initator so not sure how useful this part is
        keyUsage = NEGOEX_KEYUSAGE_INITIATOR if self.isInitiator else NEGOEX_KEYUSAGE_ACCEPTOR

        # Snapshot the history before producing the VERIFY messaage. Since caller
        # (createContextToken) is responsible for appending the resulting
        # bytes to _messageHistory, after this function returns.
        checksumInput = b''.join(self._messageHistory)
        checksum = make_checksum(checksumType, Key(enctype, keyBytes), keyUsage, checksumInput)
        verify = createVerifyMessage(self._nextSeq(), self.conversationId, self.selectedScheme, checksum, checksumType)
        self._verifySent = True
        
        return verify

    def _nextSeq(self):
        seq = self._seqNum
        self._seqNum += 1
        return seq
    
    def isComplete(self):
        """True when both sides have exchanged VERIFY messages."""
        return self._verifySent and self._verifyReceived
    
    def _processAlert(self, parsedMsg):
        """We do not really need to do anything for now. The currently defined alert does not require anything for us to do
        unless new alert types/variants are defined in the future, this function may have to be revisited. As of now, 
        you do nothing different and continue the negotiation regardless"""
        LOG.debug('NEGOEX ALERT_MESSAGE received')
    
class NegoExError(Exception):
    pass


class NegoExParseError(NegoExError):
    def __init__(self, message, offset=None, field=None):
        self.offset = offset
        self.field = field
        parts = [message]
        if field is not None:
            parts.append(f'field={field}')
        if offset is not None:
            parts.append(f'offset=0x{offset:x}')
        Exception.__init__(self, ' | '.join(parts))


class NegoExChecksumError(NegoExError):
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual
        NegoExError.__init__(self, f"NEGOEX VERIFY checksum mismatch: expected {expected.hex()}, got {actual.hex()}")
