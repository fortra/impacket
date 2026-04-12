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
# Description: Executes commands through WinRM/WinRS.
# Originaly writen by @Ozelis
# Reviewed by @gabrielg5 and @Defte


import os
import re
import ssl
import uuid
import base64
import logging
from typing import List, Tuple
from struct import pack, unpack
from dataclasses import dataclass
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5, SHA256
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import namedtype, tag, univ
from pyasn1.type.univ import noValue

from impacket.tls import tls_server_end_point_channel_binding_from_certificate
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3, SEAL, SEALKEY, SIGN, SIGNKEY
from impacket.krb5.asn1 import AP_REP, AP_REQ, Authenticator, EncAPRepPart, TGS_REP, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import ApplicationTagNumbers, PrincipalNameType, encodeFlags
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import (
    KRB5_AP_REQ,
    KG_USAGE_ACCEPTOR_SEAL,
    KG_USAGE_INITIATOR_SEAL,
    CheckSumField,
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
    GSS_C_MUTUAL_FLAG,
    GSS_C_SEQUENCE_FLAG,
    MechIndepToken,
)
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT, SessionError
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

SOAP_CONTENT_TYPE = 'application/soap+xml;charset=UTF-8'
MULTIPART_BOUNDARY = 'Encrypted Boundary'
MULTIPART_BOUNDARY_BYTES = ('--%s' % MULTIPART_BOUNDARY).encode('ascii')
WINRS_RESOURCE_URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd'
CLIENT_CERT_AUTHORIZATION = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual'
WINRS_SIGNAL_CTRL_C = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c'
WINRS_SIGNAL_TERMINATE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate'

WSMAN_ACTIONS = {
    'create': 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
    'delete': 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete',
    'command': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command',
    'receive': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',
    'signal': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',
}

SOAP_NAMESPACES = {
    's': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    'wsman': 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd',
    'wsmv': 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd',
    'rsp': 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell',
}

for prefix, namespace in SOAP_NAMESPACES.items():
    ET.register_namespace(prefix, namespace)


class WinRMError(Exception):
    pass


class WinRMTransportError(WinRMError):
    pass


class WinRMAuthError(WinRMTransportError):
    pass


class WinRMFaultError(WinRMError):
    def __init__(self, code, reason, detail='', status=None):
        self.code = code
        self.reason = reason
        self.detail = detail
        self.status = status

        message = reason or code or 'WinRM fault'
        if detail:
            message = '%s (%s)' % (message, detail)

        super().__init__(message)


@dataclass
class NTCredential:
    domain: str
    username: str
    password: str = ''
    lmhash: str = ''
    nthash: str = ''


@dataclass
class KerberosCredential:
    domain: str
    username: str
    ticket: Ticket
    tgs_key: Key
    password: str = ''


@dataclass
class _HTTPResponse:
    status: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes

    def get_all(self, name):
        name = name.lower()
        return [value for header, value in self.headers if header.lower() == name]

    def get(self, name, default=''):
        values = self.get_all(name)
        if not values:
            return default
        return ', '.join(values)


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode('utf-8')


def _chunks(data, chunk_size):
    for offset in range(0, len(data), chunk_size):
        yield data[offset:offset + chunk_size]


def _xml_text(root, xpath, default=''):
    node = root.find(xpath, SOAP_NAMESPACES)
    if node is None or node.text is None:
        return default
    return node.text


def _xml_attrib(root, xpath, attribute, default=''):
    node = root.find(xpath, SOAP_NAMESPACES)
    if node is None:
        return default
    return node.get(attribute, default)


def _must_understand(value=True):
    return {'{%s}mustUnderstand' % SOAP_NAMESPACES['s']: str(value).lower()}


def _new_message_id():
    return 'uuid:%s' % str(uuid.uuid4()).upper()


def _new_session_id():
    return 'uuid:%s' % str(uuid.uuid4()).upper()


def _build_envelope(action, resource_uri=WINRS_RESOURCE_URI, shell_id=None, timeout=20, session_id=None):
    envelope = ET.Element('{%s}Envelope' % SOAP_NAMESPACES['s'])
    header = ET.SubElement(envelope, '{%s}Header' % SOAP_NAMESPACES['s'])
    body = ET.SubElement(envelope, '{%s}Body' % SOAP_NAMESPACES['s'])

    resource = ET.SubElement(header, '{%s}ResourceURI' % SOAP_NAMESPACES['wsman'], _must_understand())
    resource.text = resource_uri

    reply_to = ET.SubElement(header, '{%s}ReplyTo' % SOAP_NAMESPACES['wsa'])
    address = ET.SubElement(reply_to, '{%s}Address' % SOAP_NAMESPACES['wsa'], _must_understand())
    address.text = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'

    to_node = ET.SubElement(header, '{%s}To' % SOAP_NAMESPACES['wsa'])
    to_node.text = 'http://localhost/wsman'

    action_node = ET.SubElement(header, '{%s}Action' % SOAP_NAMESPACES['wsa'], _must_understand())
    action_node.text = WSMAN_ACTIONS[action]

    message_id = ET.SubElement(header, '{%s}MessageID' % SOAP_NAMESPACES['wsa'])
    message_id.text = _new_message_id()

    max_envelope = ET.SubElement(header, '{%s}MaxEnvelopeSize' % SOAP_NAMESPACES['wsman'], _must_understand())
    max_envelope.text = '153600'

    ET.SubElement(
        header,
        '{%s}Locale' % SOAP_NAMESPACES['wsman'],
        {'{%s}lang' % 'http://www.w3.org/XML/1998/namespace': 'en-US'},
    )
    ET.SubElement(
        header,
        '{%s}DataLocale' % SOAP_NAMESPACES['wsmv'],
        {'{%s}lang' % 'http://www.w3.org/XML/1998/namespace': 'en-US'},
    )

    operation_timeout = ET.SubElement(header, '{%s}OperationTimeout' % SOAP_NAMESPACES['wsman'])
    operation_timeout.text = 'PT%dS' % timeout

    ET.SubElement(header, '{%s}OptionSet' % SOAP_NAMESPACES['wsman'], _must_understand())

    if session_id is not None:
        session = ET.SubElement(header, '{%s}SessionId' % SOAP_NAMESPACES['wsmv'])
        session.text = session_id

    selector_set = ET.SubElement(header, '{%s}SelectorSet' % SOAP_NAMESPACES['wsman'])
    if shell_id is not None:
        selector = ET.SubElement(selector_set, '{%s}Selector' % SOAP_NAMESPACES['wsman'], {'Name': 'ShellId'})
        selector.text = shell_id

    return envelope, header, body


def envelope_to_bytes(envelope):
    return ET.tostring(envelope, encoding='utf-8')


def build_winrs_create_request(
    timeout=20,
    session_id=None,
    input_streams='stdin',
    output_streams='stdout stderr',
    codepage=437,
    no_profile=False,
):
    envelope, header, body = _build_envelope('create', timeout=timeout, session_id=session_id)
    option_set = header.find('wsman:OptionSet', SOAP_NAMESPACES)
    ET.SubElement(option_set, '{%s}Option' % SOAP_NAMESPACES['wsman'], {'Name': 'WINRS_NOPROFILE'}).text = (
        'TRUE' if no_profile else 'FALSE'
    )
    ET.SubElement(option_set, '{%s}Option' % SOAP_NAMESPACES['wsman'], {'Name': 'WINRS_CODEPAGE'}).text = str(codepage)

    shell = ET.SubElement(body, '{%s}Shell' % SOAP_NAMESPACES['rsp'])
    ET.SubElement(shell, '{%s}InputStreams' % SOAP_NAMESPACES['rsp']).text = input_streams
    ET.SubElement(shell, '{%s}OutputStreams' % SOAP_NAMESPACES['rsp']).text = output_streams
    return envelope


def build_winrs_command_request(shell_id, command, arguments=None, timeout=20, session_id=None):
    envelope, _, body = _build_envelope('command', shell_id=shell_id, timeout=timeout, session_id=session_id)
    command_line = ET.SubElement(body, '{%s}CommandLine' % SOAP_NAMESPACES['rsp'])
    ET.SubElement(command_line, '{%s}Command' % SOAP_NAMESPACES['rsp']).text = command
    for argument in arguments or []:
        ET.SubElement(command_line, '{%s}Arguments' % SOAP_NAMESPACES['rsp']).text = argument
    return envelope


def build_winrs_receive_request(shell_id, command_id, timeout=20, session_id=None, streams='stdout stderr', keepalive=True):
    envelope, header, body = _build_envelope('receive', shell_id=shell_id, timeout=timeout, session_id=session_id)
    if keepalive:
        option_set = header.find('wsman:OptionSet', SOAP_NAMESPACES)
        ET.SubElement(
            option_set,
            '{%s}Option' % SOAP_NAMESPACES['wsman'],
            {'Name': 'WSMAN_CMDSHELL_OPTION_KEEPALIVE'},
        ).text = 'true'

    receive = ET.SubElement(body, '{%s}Receive' % SOAP_NAMESPACES['rsp'])
    desired = ET.SubElement(receive, '{%s}DesiredStream' % SOAP_NAMESPACES['rsp'], {'CommandId': command_id})
    desired.text = streams
    return envelope


def build_winrs_signal_request(shell_id, command_id, code, timeout=20, session_id=None):
    envelope, _, body = _build_envelope('signal', shell_id=shell_id, timeout=timeout, session_id=session_id)
    signal = ET.SubElement(body, '{%s}Signal' % SOAP_NAMESPACES['rsp'], {'CommandId': command_id})
    ET.SubElement(signal, '{%s}Code' % SOAP_NAMESPACES['rsp']).text = code
    return envelope


def build_winrs_delete_request(shell_id, timeout=20, session_id=None):
    envelope, _, _ = _build_envelope('delete', shell_id=shell_id, timeout=timeout, session_id=session_id)
    return envelope


def parse_shell_id(root):
    return _xml_text(root, './/wsman:Selector[@Name="ShellId"]') or _xml_text(root, './/rsp:Shell/rsp:ShellId')


def parse_command_id(root):
    return _xml_text(root, './/rsp:CommandId')


def parse_command_state(root):
    state = _xml_attrib(root, './/rsp:CommandState', 'State')
    exit_code = _xml_text(root, './/rsp:CommandState/rsp:ExitCode')
    return state, int(exit_code) if exit_code not in ('', None) else None


def iter_streams(root):
    for stream in root.findall('.//rsp:Stream', SOAP_NAMESPACES):
        name = stream.get('Name', '')
        data = stream.text or ''
        yield name, base64.b64decode(data) if data else b''


def parse_fault(root):
    fault = root.find('.//s:Fault', SOAP_NAMESPACES)
    if fault is None:
        return None

    return {
        'code': _xml_text(root, './/s:Subcode/s:Value') or _xml_text(root, './/s:Code/s:Value'),
        'reason': _xml_text(root, './/s:Reason/s:Text'),
        'detail': _xml_text(root, './/s:Detail/s:Message') or _xml_text(root, './/s:Detail'),
    }


def parse_wsman_response(content, status=None):
    root = ET.fromstring(content)
    fault = parse_fault(root)
    if fault is not None:
        raise WinRMFaultError(fault['code'], fault['reason'], fault['detail'], status=status)
    return root


def _find_auth_header(response, scheme):
    pattern = re.compile(r'(^|,)\s*%s(?:\s+([^,\s]+))?' % re.escape(scheme), re.IGNORECASE)
    for value in response.get_all('WWW-Authenticate'):
        match = pattern.search(value)
        if match is not None:
            return match.group(2) or ''
    return None


def _send_scheme_offered(response, scheme):
    return _find_auth_header(response, scheme) is not None


def _tls_trailer_length(data_length, protocol, cipher_suite):
    if protocol == 'TLSv1.3':
        return 17

    if re.match(r'^.*[-_]GCM[-_][\w\d]*$', cipher_suite):
        return 16

    hash_algorithm = cipher_suite.split('-')[-1]
    hash_length = {'MD5': 16, 'SHA': 20, 'SHA256': 32, 'SHA384': 48}.get(hash_algorithm, 0)
    pre_pad_length = data_length + hash_length

    if 'RC4' in cipher_suite:
        padding_length = 0
    elif 'DES' in cipher_suite or '3DES' in cipher_suite:
        padding_length = 8 - (pre_pad_length % 8)
    else:
        padding_length = 16 - (pre_pad_length % 16)

    return (pre_pad_length + padding_length) - data_length


def _get_credssp_public_key(cert_bytes):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    certificate = x509.load_der_x509_certificate(cert_bytes)
    return certificate.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)


class _NegoData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'negoToken',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        )
    )


class _TSRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'version',
            univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        ),
        namedtype.OptionalNamedType(
            'negoTokens',
            univ.SequenceOf(componentType=_NegoData()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
        namedtype.OptionalNamedType(
            'authInfo',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
        ),
        namedtype.OptionalNamedType(
            'pubKeyAuth',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)),
        ),
        namedtype.OptionalNamedType(
            'errorCode',
            univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)),
        ),
        namedtype.OptionalNamedType(
            'clientNonce',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5)),
        ),
    )

    @staticmethod
    def nego_response(token, version=6):
        ts_request = _TSRequest()
        ts_request['version'] = version
        if token:
            token_data = _NegoData()
            token_data['negoToken'] = token
            ts_request['negoTokens'].extend([token_data])
        return ts_request


class _TSPasswordCreds(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'domainName',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        ),
        namedtype.NamedType(
            'userName',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
        namedtype.NamedType(
            'password',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
        ),
    )


class _TSCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'credType',
            univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        ),
        namedtype.NamedType(
            'credentials',
            univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
    )


class _NTLMSessionCipher:
    def __init__(self, flags, session_key):
        self._client_sequence = 0
        self._server_sequence = 0
        self._client_sign_key = SIGNKEY(flags, session_key, 'Client')
        self._server_sign_key = SIGNKEY(flags, session_key, 'Server')
        self._client_seal_handle = ARC4.new(SEALKEY(flags, session_key, 'Client'))
        self._server_seal_handle = ARC4.new(SEALKEY(flags, session_key, 'Server'))

    def wrap(self, data):
        sequence = pack('<I', self._client_sequence)
        encrypted = self._client_seal_handle.encrypt(data)
        signature = HMAC.new(self._client_sign_key, sequence + data, digestmod=MD5).digest()[:8]
        signature = pack('<I', 1) + self._client_seal_handle.encrypt(signature) + sequence
        self._client_sequence += 1
        return signature, encrypted

    def unwrap(self, signature, encrypted):
        data = self._server_seal_handle.decrypt(encrypted)
        sequence = pack('<I', self._server_sequence)
        check = HMAC.new(self._server_sign_key, sequence + data, digestmod=MD5).digest()[:8]
        check = self._server_seal_handle.decrypt(check)
        if signature[4:12] != check:
            raise WinRMAuthError('NTLM message integrity failure')
        self._server_sequence += 1
        return data


class _NegotiateNTLMContext:
    def __init__(self, credentials, channel_binding=None):
        self._credentials = credentials
        self._channel_binding = channel_binding or b''
        self._type1 = None
        self._cipher = None
        self._final_sent = False
        self.complete = False

    def step(self, token=None):
        if token is None:
            self._type1 = getNTLMSSPType1(signingRequired=True)
            self._final_sent = False
            token_init = SPNEGO_NegTokenInit()
            token_init['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
            token_init['MechToken'] = self._type1.getData()
            return token_init.getData()

        if token == b'' and self._final_sent:
            self.complete = True
            return b''

        response = SPNEGO_NegTokenResp(token)
        neg_state = response['NegState'][0]
        if neg_state == 2:
            raise WinRMAuthError('NTLM authentication rejected')
        if neg_state == 0:
            self.complete = True
            return b''

        if neg_state != 1:
            raise WinRMAuthError('Unexpected NTLM SPNEGO state %d' % neg_state)

        challenge = response['ResponseToken']
        type3, session_key = getNTLMSSPType3(
            self._type1,
            challenge,
            self._credentials.username,
            self._credentials.password,
            self._credentials.domain,
            self._credentials.lmhash,
            self._credentials.nthash,
            channel_binding_value=self._channel_binding,
            service='HTTP',
        )

        reply = SPNEGO_NegTokenResp()
        reply['NegState'] = b'\x01'
        reply['SupportedMech'] = b''
        reply['ResponseToken'] = type3.getData()
        self._cipher = _NTLMSessionCipher(type3['flags'], session_key)
        self._final_sent = True
        return reply.getData()

    def wrap(self, data):
        return self._cipher.wrap(data)

    def unwrap(self, signature, encrypted):
        return self._cipher.unwrap(signature, encrypted)


class _KerberosSessionCipher:
    def __init__(self, subkey, cipher, initial_sequence):
        self._subkey = subkey
        self._cipher = cipher
        self._client_sequence = 0
        self._server_sequence = initial_sequence

    def wrap(self, data):
        signature = pack('>BBBBHHQ', 5, 4, 6, 0xFF, 0, 0, self._client_sequence)
        encrypted = self._cipher.encrypt(self._subkey, KG_USAGE_INITIATOR_SEAL, data + signature, None)
        rotate = len(encrypted) - (28 % len(encrypted))
        encrypted = encrypted[rotate:] + encrypted[:rotate]
        signature = pack('>BBBBHHQ', 5, 4, 6, 0xFF, 0, 28, self._client_sequence)
        self._client_sequence += 1
        return signature + encrypted[:44], encrypted[44:]

    def unwrap(self, signature, encrypted):
        _, _, _, _, ec, rrc, sequence = unpack('>BBBBHHQ', signature[:16])
        if sequence != self._server_sequence:
            raise WinRMAuthError('Kerberos message replay detected')

        self._server_sequence += 1
        encrypted = signature[16:] + encrypted
        rotate = (rrc + ec) % len(encrypted)
        encrypted = encrypted[rotate:] + encrypted[:rotate]
        plaintext = self._cipher.decrypt(self._subkey, KG_USAGE_ACCEPTOR_SEAL, encrypted)
        return plaintext[:-(ec + 16)]


class _NegotiateKerberosContext:
    def __init__(self, credentials, channel_binding=None):
        self._credentials = credentials
        self._channel_binding = channel_binding
        self._cipher = None
        self.complete = False

    def step(self, token=None):
        if token is None:
            user = Principal(self._credentials.username, type=PrincipalNameType.NT_PRINCIPAL.value)
            cipher = _enctype_table[self._credentials.tgs_key.enctype]

            checksum = CheckSumField()
            checksum['Lgth'] = 16
            checksum['Flags'] = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG
            if self._channel_binding:
                checksum['Bnd'] = self._channel_binding

            authenticator = Authenticator()
            seq_set(authenticator, 'cname', user.components_to_asn1)
            authenticator['authenticator-vno'] = 5
            authenticator['crealm'] = self._credentials.domain.upper()
            now = datetime.now(timezone.utc)
            authenticator['ctime'] = KerberosTime.to_asn1(now)
            authenticator['cusec'] = now.microsecond
            authenticator['cksum'] = noValue
            authenticator['cksum']['cksumtype'] = 0x8003
            authenticator['cksum']['checksum'] = checksum.getData()
            authenticator['seq-number'] = 0
            authenticator['subkey'] = noValue
            authenticator['subkey']['keyvalue'] = os.urandom(32)
            authenticator['subkey']['keytype'] = 18

            encoded_authenticator = encoder.encode(authenticator)
            encrypted_authenticator = cipher.encrypt(self._credentials.tgs_key, 11, encoded_authenticator, None)

            ap_req = AP_REQ()
            ap_req['pvno'] = 5
            ap_req['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
            ap_req['ap-options'] = encodeFlags([2])
            ap_req['authenticator'] = noValue
            ap_req['authenticator']['etype'] = cipher.enctype
            ap_req['authenticator']['cipher'] = encrypted_authenticator
            seq_set(ap_req, 'ticket', self._credentials.ticket.to_asn1)

            token_init = SPNEGO_NegTokenInit()
            token_init['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
            token_init['MechToken'] = encoder.encode(ap_req)
            return token_init.getData()

        response = SPNEGO_NegTokenResp(token)
        neg_state = response['NegState'][0]
        if neg_state == 2:
            raise WinRMAuthError('Kerberos authentication rejected')
        if neg_state != 0:
            raise WinRMAuthError('Unexpected Kerberos SPNEGO state %d' % neg_state)

        mech_token = MechIndepToken.from_bytes(response['ResponseToken']).data
        ap_rep = decoder.decode(mech_token[2:], asn1Spec=AP_REP())[0]
        cipher = _enctype_table[self._credentials.tgs_key.enctype]
        decrypted = cipher.decrypt(self._credentials.tgs_key, 12, ap_rep['enc-part']['cipher'])
        decoded = decoder.decode(decrypted, asn1Spec=EncAPRepPart())[0]

        keytype = int(decoded['subkey']['keytype'])
        keyvalue = decoded['subkey']['keyvalue'].asOctets()
        subkey = Key(keytype, keyvalue)
        sequence = int(decoded['seq-number'])
        self._cipher = _KerberosSessionCipher(subkey, _enctype_table[keytype], sequence)
        self.complete = True
        return b''

    def wrap(self, data):
        return self._cipher.wrap(data)

    def unwrap(self, signature, encrypted):
        return self._cipher.unwrap(signature, encrypted)


class WinRMTransport:
    def __init__(self, url, timeout=30, ssl_context=None):
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise WinRMTransportError('Unsupported WinRM URL scheme %s' % parsed.scheme)

        self.url = url
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (5986 if parsed.scheme == 'https' else 5985)
        self.path = parsed.path or '/wsman'
        self.timeout = timeout
        self._connection = None
        self._peer_certificate = None

        if ssl_context is None and self.scheme == 'https':
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._ssl_context = ssl_context

    @property
    def is_https(self):
        return self.scheme == 'https'

    @property
    def peer_certificate(self):
        return self._peer_certificate

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None

    def _create_connection(self):
        if self.is_https:
            return HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self._ssl_context)
        return HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _ensure_connection(self):
        if self._connection is None:
            self._connection = self._create_connection()
        return self._connection

    def _perform_request(self, body=b'', headers=None):
        body = _to_bytes(body)
        request_headers = {
            'Content-Length': str(len(body)),
        }
        if headers:
            request_headers.update(headers)

        if 'Content-Type' not in request_headers:
            request_headers['Content-Type'] = SOAP_CONTENT_TYPE

        connection = self._ensure_connection()
        connection.request('POST', self.path, body=body, headers=request_headers)
        response = connection.getresponse()
        content = response.read()

        if self.is_https and self._peer_certificate is None and getattr(connection, 'sock', None) is not None:
            try:
                self._peer_certificate = connection.sock.getpeercert(binary_form=True)
            except Exception:
                self._peer_certificate = None

        return _HTTPResponse(response.status, response.reason, response.getheaders(), content)

    def _request(self, body=b'', headers=None):
        try:
            return self._perform_request(body, headers=headers)
        except Exception as error:
            self.close()
            try:
                return self._perform_request(body, headers=headers)
            except Exception as retry_error:
                raise WinRMTransportError(str(retry_error or error))

    def send(self, request):
        response = self._request(request)
        if response.status not in (200, 500):
            raise WinRMTransportError('Unexpected WinRM HTTP status %d' % response.status)
        return response.body


class BasicTransport(WinRMTransport):
    def __init__(self, url, username, password, timeout=30):
        super().__init__(url, timeout=timeout)
        credentials = ('%s:%s' % (username, password)).encode('utf-8')
        self._authorization = 'Basic %s' % base64.b64encode(credentials).decode('ascii')

    def send(self, request):
        response = self._request(request, headers={'Authorization': self._authorization})
        if response.status not in (200, 500):
            raise WinRMTransportError('Unexpected WinRM HTTP status %d' % response.status)
        return response.body


class ClientCertificateTransport(WinRMTransport):
    def __init__(self, url, certificate_file, key_file, timeout=30):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.load_cert_chain(certificate_file, key_file)
        super().__init__(url, timeout=timeout, ssl_context=ssl_context)

    def send(self, request):
        response = self._request(request, headers={'Authorization': CLIENT_CERT_AUTHORIZATION})
        if response.status not in (200, 500):
            raise WinRMTransportError('Unexpected WinRM HTTP status %d' % response.status)
        return response.body


class _EncryptedTransport(WinRMTransport):
    auth_scheme = None
    encryption_protocol = None

    def __init__(self, url, timeout=30):
        super().__init__(url, timeout=timeout)
        self._authenticated = False

    def _send_authorization(self, token, scheme, phase=''):
        header = '%s %s' % (scheme, base64.b64encode(token).decode('ascii'))
        response = self._request(b'', headers={'Authorization': header})

        header_value = _find_auth_header(response, scheme)
        if response.status == 200 and not header_value:
            return b''
        if header_value is None:
            raise WinRMAuthError('%s authentication failed%s' % (scheme, ' during %s' % phase if phase else ''))
        return base64.b64decode(header_value) if header_value else b''

    def _build_encrypted_message(self, request, wrap_fn):
        request = _to_bytes(request)
        multipart = b''

        for chunk in _chunks(request, 16384):
            multipart += MULTIPART_BOUNDARY_BYTES + b'\r\n'
            multipart += ('Content-Type: %s\r\n' % self.encryption_protocol).encode('ascii')
            multipart += ('OriginalContent: type=%s;Length=%d\r\n' % (SOAP_CONTENT_TYPE, len(chunk))).encode('ascii')
            multipart += MULTIPART_BOUNDARY_BYTES + b'\r\n'
            signature, encrypted = wrap_fn(chunk)
            multipart += b'Content-Type: application/octet-stream\r\n'
            multipart += pack('<I', len(signature)) + signature + encrypted

        multipart += MULTIPART_BOUNDARY_BYTES + b'--\r\n'
        headers = {
            'Content-Type': 'multipart/x-multi-encrypted;protocol="%s";boundary="%s"'
            % (self.encryption_protocol, MULTIPART_BOUNDARY),
        }
        return multipart, headers

    def _decrypt_response(self, response, unwrap_fn):
        if response.status not in (200, 500):
            return response

        plaintext = b''
        prefixes = (
            b'\r\nContent-Type: application/octet-stream\r\n',
            b'\r\n\tContent-Type: application/octet-stream\r\n',
            b'Content-Type: application/octet-stream\r\n',
        )

        for part in response.body.split(MULTIPART_BOUNDARY_BYTES):
            for prefix in prefixes:
                if part.startswith(prefix):
                    part = part[len(prefix):]
                    break
            else:
                continue

            if len(part) < 4:
                continue

            signature_length = unpack('<I', part[:4])[0]
            if len(part) < 4 + signature_length:
                continue

            plaintext += unwrap_fn(part[4:4 + signature_length], part[4 + signature_length:])

        return _HTTPResponse(response.status, response.reason, response.headers, plaintext)

    def _send_encrypted(self, request):
        body, headers = self._build_encrypted_message(request, self._wrap)
        return self._request(body, headers=headers)

    def send(self, request):
        if not self._authenticated:
            self._authenticate()

        response = self._send_encrypted(request)
        if response.status == 401:
            self.close()
            self._authenticated = False
            self._authenticate()
            response = self._send_encrypted(request)

        if response.status not in (200, 500):
            raise WinRMTransportError('Unexpected WinRM HTTP status %d' % response.status)

        return self._decrypt_response(response, self._unwrap).body


class NegotiateTransport(_EncryptedTransport):
    auth_scheme = 'Negotiate'
    encryption_protocol = 'application/HTTP-SPNEGO-session-encrypted'

    def __init__(self, url, credentials, timeout=30):
        super().__init__(url, timeout=timeout)
        self._credentials = credentials
        self._context = None

    def _authenticate(self):
        channel_binding = None
        if self.is_https:
            initial_response = self._request(b'')
            if initial_response.status not in (401, 200):
                raise WinRMTransportError('Unexpected WinRM HTTP status %d' % initial_response.status)
            if self.peer_certificate is not None:
                channel_binding = tls_server_end_point_channel_binding_from_certificate(self.peer_certificate)

        if isinstance(self._credentials, KerberosCredential):
            self._context = _NegotiateKerberosContext(self._credentials, channel_binding=channel_binding)
        else:
            self._context = _NegotiateNTLMContext(self._credentials, channel_binding=channel_binding)

        token = self._context.step()
        while not self._context.complete:
            response_token = self._send_authorization(token, self.auth_scheme, phase='Negotiate')
            token = self._context.step(response_token)

        self._authenticated = True

    def _wrap(self, data):
        return self._context.wrap(data)

    def _unwrap(self, signature, encrypted):
        return self._context.unwrap(signature, encrypted)


class KerberosTransport(_EncryptedTransport):
    auth_scheme = 'Kerberos'
    encryption_protocol = 'application/HTTP-Kerberos-session-encrypted'

    def __init__(self, url, credentials, timeout=30):
        super().__init__(url, timeout=timeout)
        self._credentials = credentials
        self._context = None

    def _authenticate(self):
        channel_binding = None
        if self.is_https:
            initial_response = self._request(b'')
            if initial_response.status not in (401, 200):
                raise WinRMTransportError('Unexpected WinRM HTTP status %d' % initial_response.status)
            if self.peer_certificate is not None:
                channel_binding = tls_server_end_point_channel_binding_from_certificate(self.peer_certificate)

        self._context = _NegotiateKerberosContext(self._credentials, channel_binding=channel_binding)
        negotiate_token = self._context.step()
        ap_req = SPNEGO_NegTokenInit(negotiate_token)['MechToken']
        ap_req = b''.join(MechIndepToken(KRB5_AP_REQ + ap_req).to_bytes())

        server_token = self._send_authorization(ap_req, self.auth_scheme, phase='AP_REQ')
        response = SPNEGO_NegTokenResp()
        response['NegState'] = b'\x00'
        response['SupportedMech'] = b''
        response['ResponseToken'] = server_token
        self._context.step(response.getData())
        self._authenticated = True

    def _wrap(self, data):
        return self._context.wrap(data)

    def _unwrap(self, signature, encrypted):
        return self._context.unwrap(signature, encrypted)


class CredSSPTransport(_EncryptedTransport):
    auth_scheme = 'CredSSP'
    encryption_protocol = 'application/HTTP-CredSSP-session-encrypted'

    def __init__(self, url, credentials, timeout=30):
        super().__init__(url, timeout=timeout)
        self._credentials = credentials
        self._tls_input = None
        self._tls_output = None
        self._tls_object = None

    def _authenticate(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.options |= getattr(ssl, 'OP_NO_COMPRESSION', 0)

        self._tls_input = ssl.MemoryBIO()
        self._tls_output = ssl.MemoryBIO()
        self._tls_object = context.wrap_bio(self._tls_input, self._tls_output, server_side=False)

        while True:
            try:
                self._tls_object.do_handshake()
            except ssl.SSLWantReadError:
                pass

            pending = self._tls_output.read()
            if not pending:
                break

            response = self._send_authorization(pending, self.auth_scheme, phase='TLS handshake')
            if response:
                self._tls_input.write(response)

        certificate = self._tls_object.getpeercert(binary_form=True)
        public_key = _get_credssp_public_key(certificate)
        nonce = os.urandom(32)
        public_key_hash = SHA256.new(
            b'CredSSP Client-To-Server Binding Hash\x00' + nonce + public_key
        ).digest()

        if isinstance(self._credentials, KerberosCredential):
            auth_context = _NegotiateKerberosContext(self._credentials)
        else:
            auth_context = _NegotiateNTLMContext(self._credentials)

        token = auth_context.step()
        response = self._send_credssp_request(_TSRequest.nego_response(token), phase='SPNEGO init')
        token = response['negoTokens'][0]['negoToken'].asOctets()
        token = auth_context.step(token)

        request = _TSRequest.nego_response(token)
        request['clientNonce'] = nonce
        signature, encrypted = auth_context.wrap(public_key_hash)
        request['pubKeyAuth'] = signature + encrypted
        self._send_credssp_request(request, phase='public key exchange')

        password_credentials = _TSPasswordCreds()
        password_credentials['domainName'] = self._credentials.domain.encode('utf-16le')
        password_credentials['userName'] = self._credentials.username.encode('utf-16le')
        password_credentials['password'] = self._credentials.password.encode('utf-16le')

        credentials = _TSCredentials()
        credentials['credType'] = 1
        credentials['credentials'] = encoder.encode(password_credentials)

        request = _TSRequest()
        request['version'] = 6
        signature, encrypted = auth_context.wrap(encoder.encode(credentials))
        request['authInfo'] = signature + encrypted
        self._send_credssp_request(request, phase='credential delegation')

        self._authenticated = True

    def _send_credssp_request(self, request, phase=''):
        signature, encrypted = self._wrap_tls(encoder.encode(request))
        response = self._send_authorization(signature + encrypted, self.auth_scheme, phase=phase)
        if not response:
            return _TSRequest()

        decoded = decoder.decode(self._unwrap_tls(b'', response), asn1Spec=_TSRequest())[0]
        if decoded['errorCode'].hasValue():
            error_code = int(decoded['errorCode'])
            raise WinRMAuthError('CredSSP failed during %s with NTSTATUS 0x%08x' % (phase, error_code & 0xFFFFFFFF))
        return decoded

    def _wrap_tls(self, data):
        self._tls_object.write(data)
        encrypted = self._tls_output.read()
        cipher_suite, protocol, _ = self._tls_object.cipher()
        trailer_length = _tls_trailer_length(len(encrypted), protocol, cipher_suite)
        return encrypted[:trailer_length], encrypted[trailer_length:]

    def _unwrap_tls(self, signature, encrypted):
        self._tls_input.write(signature + encrypted)
        plaintext = []

        while True:
            try:
                plaintext.append(self._tls_object.read())
            except ssl.SSLWantReadError:
                break

        return b''.join(plaintext)

    def _wrap(self, data):
        return self._wrap_tls(data)

    def _unwrap(self, signature, encrypted):
        return self._unwrap_tls(signature, encrypted)


def get_kerberos_credential(
    spn,
    domain='',
    username='',
    password='',
    lmhash='',
    nthash='',
    aes_key='',
    kdc_host=None,
    use_cache=True,
):
    ticket = Ticket()
    tgt = None
    tgs = None
    cipher = None
    tgt_session_key = None

    if use_cache:
        domain, username, tgt, tgs = CCache.parseFile(domain, username, spn)
        if tgs is not None:
            ticket.from_asn1(decoder.decode(tgs['KDC_REP'], asn1Spec=TGS_REP())[0]['ticket'])
            return KerberosCredential(domain, username, ticket, tgs['sessionKey'], password=password)

        if tgt is not None:
            cipher = tgt['cipher']
            tgt_session_key = tgt['sessionKey']
            tgt = tgt['KDC_REP']

    if not username or not domain:
        raise WinRMAuthError('Kerberos authentication needs a domain and username')

    user = Principal(username, type=PrincipalNameType.NT_PRINCIPAL.value)
    service = Principal(spn, type=PrincipalNameType.NT_SRV_INST.value)

    if tgt is None:
        tgt, cipher, _, tgt_session_key = getKerberosTGT(user, password, domain, lmhash, nthash, aes_key, kdc_host)

    try:
        tgs, cipher, _, tgs_key = getKerberosTGS(service, domain, kdc_host, tgt, cipher, tgt_session_key)
    except SessionError as e:
        if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
            logging.error("KDC_ERR_S_PRINCIPAL_UNKNOWN: domain names specified in TGS and in target do not match.")
            exit()

    ticket.from_asn1(decoder.decode(tgs, asn1Spec=TGS_REP())[0]['ticket'])
    return KerberosCredential(domain, username, ticket, tgs_key, password=password)


class WinRSCommand:
    def __init__(self, client, command_id):
        self._client = client
        self.command_id = command_id
        self._closed = False

    def interrupt(self):
        self._client.signal(self.command_id, WINRS_SIGNAL_CTRL_C)

    def close(self):
        if self._closed:
            return

        try:
            self._client.signal(self.command_id, WINRS_SIGNAL_TERMINATE)
        finally:
            self._closed = True

    def iter_output(self):
        try:
            return (yield from self._client.receive(self.command_id))
        finally:
            self.close()


class WinRSClient:
    def __init__(self, transport, timeout=20, codepage=437, no_profile=False):
        self._transport = transport
        self.timeout = timeout
        self.codepage = codepage
        self.no_profile = no_profile
        self.session_id = _new_session_id()
        self.shell_id = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _send(self, envelope):
        content = self._transport.send(envelope_to_bytes(envelope))
        return parse_wsman_response(content)

    def open(self):
        if self.shell_id is not None:
            return self.shell_id

        request = build_winrs_create_request(
            timeout=self.timeout,
            session_id=self.session_id,
            codepage=self.codepage,
            no_profile=self.no_profile,
        )
        response = self._send(request)
        self.shell_id = parse_shell_id(response)
        if not self.shell_id:
            raise WinRMTransportError('WinRM shell was created without a ShellId')
        return self.shell_id

    def close(self):
        if self.shell_id is None:
            self._transport.close()
            return

        try:
            request = build_winrs_delete_request(self.shell_id, timeout=self.timeout, session_id=self.session_id)
            self._send(request)
        except Exception:
            logging.debug('Failed to delete WinRM shell', exc_info=True)
        finally:
            self.shell_id = None
            self._transport.close()

    def command(self, command, arguments=None):
        request = build_winrs_command_request(
            self.open(),
            command,
            arguments=arguments or [],
            timeout=self.timeout,
            session_id=self.session_id,
        )
        response = self._send(request)
        command_id = parse_command_id(response)
        if not command_id:
            raise WinRMTransportError('WinRM command response did not include a CommandId')
        return command_id

    def execute(self, command, arguments=None):
        return WinRSCommand(self, self.command(command, arguments=arguments))

    def signal(self, command_id, code):
        request = build_winrs_signal_request(
            self.open(),
            command_id,
            code,
            timeout=self.timeout,
            session_id=self.session_id,
        )
        try:
            self._send(request)
        except WinRMFaultError as error:
            logging.debug('WinRM signal failed: %s', error)

    def receive(self, command_id):
        while True:
            try:
                request = build_winrs_receive_request(
                    self.open(),
                    command_id,
                    timeout=self.timeout,
                    session_id=self.session_id,
                )
                response = self._send(request)
            except WinRMFaultError as error:
                if error.code == 'w:TimedOut':
                    continue
                raise

            for name, data in iter_streams(response):
                yield name, data

            state, exit_code = parse_command_state(response)
            if state.endswith('/Done'):
                return exit_code if exit_code is not None else 0
