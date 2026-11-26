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
#   Kerberos KDC Proxy Protocol (MS-KKDCP) client transport.
#

import ssl
from http.client import HTTPSConnection
from urllib.parse import urlsplit

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error

from impacket.krb5 import constants
from impacket.krb5.asn1 import KDC_PROXY_MESSAGE, KRB_ERROR
from impacket.krb5.kerberosv5 import KerberosError


MAX_RESPONSE_SIZE = 4 * 1024 * 1024


class KDCProxyError(Exception):
    pass


class KDCProxyClient:
    """Send Kerberos AS and TGS messages through an HTTPS KDC proxy."""

    def __init__(self, url, ca_file=None, timeout=30):
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            raise ValueError('Expected an HTTPS KDC proxy URL without credentials or fragment')
        self.host = parsed.hostname
        self.port = parsed.port
        self.path = parsed.path or '/KdcProxy'
        if parsed.query:
            self.path += '?' + parsed.query
        self.timeout = timeout
        # Examples globally replace ssl.create_default_context with an insecure
        # variant. Build this context explicitly so proxy TLS stays verified.
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_file is None:
            self.context.load_default_certs()
        else:
            self.context.load_verify_locations(cafile=ca_file)

    def exchange(self, data, realm, kdcHost=None, timeout=None):
        """Match the selected KDC exchange callback used by kerberosv5."""
        if kdcHost is not None:
            raise ValueError('kdcHost cannot be used with a KDC proxy')
        if not isinstance(data, bytes) or not data or not isinstance(realm, str) or not realm:
            raise ValueError('KDC proxy exchange requires a Kerberos request and realm')

        message = KDC_PROXY_MESSAGE()
        message['kerb-message'] = len(data).to_bytes(4, 'big') + data
        message['target-domain'] = realm
        connection = HTTPSConnection(self.host, self.port, timeout=self.timeout if timeout is None else timeout,
                                     context=self.context)
        try:
            connection.request('POST', self.path, encoder.encode(message),
                               headers={'Content-Type': 'application/kerberos'})
            response = connection.getresponse()
            if response.status != 200:
                raise KDCProxyError('KDC proxy returned HTTP status %d' % response.status)
            body = response.read(MAX_RESPONSE_SIZE + 1)
        finally:
            connection.close()

        if len(body) > MAX_RESPONSE_SIZE:
            raise KDCProxyError('KDC proxy response is too large')
        try:
            result, rest = decoder.decode(body, asn1Spec=KDC_PROXY_MESSAGE())
        except (PyAsn1Error, ValueError) as exc:
            raise KDCProxyError('Invalid KDC proxy response') from exc
        if rest:
            raise KDCProxyError('Trailing data after KDC proxy response')
        framed = result['kerb-message'].asOctets()
        if len(framed) < 4 or int.from_bytes(framed[:4], 'big') != len(framed) - 4:
            raise KDCProxyError('Invalid KDC proxy Kerberos message length')

        reply = framed[4:]
        if reply[:1] == b'\x7e':
            try:
                error, rest = decoder.decode(reply, asn1Spec=KRB_ERROR())
            except (PyAsn1Error, ValueError) as exc:
                raise KDCProxyError('Invalid KDC proxy Kerberos error') from exc
            if rest:
                raise KDCProxyError('Trailing data after KDC proxy Kerberos error')
            error = KerberosError(packet=error)
            if error.getErrorCode() != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                raise error
        return reply
