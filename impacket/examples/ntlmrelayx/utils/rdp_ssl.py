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
#   RDP SSL/TLS utilities for the RDP relay server.
#   Handles TLS context creation and self-signed certificate generation.

import random
import tempfile

from OpenSSL import SSL, crypto


class ServerTLSContext:
    def __init__(self, privateKeyFileName, certificateFileName):
        """
        :param privateKeyFileName: Path to private key file (PEM format)
        :param certificateFileName: Path to certificate file (PEM format)
        """
        self.privateKeyFileName = privateKeyFileName
        self.certificateFileName = certificateFileName

    def getContext(self):
        context = SSL.Context(SSL.SSLv23_METHOD)
        
        # SSL options for RDP compatibility
        context.set_options(SSL.OP_DONT_INSERT_EMPTY_FRAGMENTS)
        context.set_options(SSL.OP_TLS_BLOCK_PADDING_BUG)
        context.set_options(SSL.OP_NO_SSLv2)
        context.set_options(SSL.OP_NO_SSLv3)

        # Load certificate and private key
        with open(self.certificateFileName, 'rb') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(self.privateKeyFileName, 'rb') as f:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        context.use_certificate(cert)
        context.use_privatekey(key)

        return context


def generate_self_signed_cert(common_name="RDP-Server"):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Create self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = common_name
    cert.set_serial_number(random.randint(0, 100000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year validity
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Save to temporary files
    cert_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.crt')
    key_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem')

    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    cert_file.close()
    key_file.close()

    return key_file.name, cert_file.name