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
#   SSL utilities
#
#   Various functions and classes for SSL support:
#     - generating certificates
#     - creating SSL capable SOCKS protocols
#
#   Most of the SSL generation example code comes from the pyopenssl examples
#     https://github.com/pyca/pyopenssl/blob/master/examples/certgen.py
#
#   Made available under the Apache license by the pyopenssl team
#     See https://github.com/pyca/pyopenssl/blob/master/LICENSE
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
from OpenSSL import crypto, SSL
from impacket import LOG
from typing import Tuple, Optional
import ipaddress
import socket
from ssl import SSLSocket
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ssl

# This certificate is not supposed to be exposed on the network
# but only used for the local SOCKS plugins
# therefore, for now we don't bother with a CA and with hosts/hostnames matching
def generateImpacketCert(certname='/tmp/impacket.crt'):
    # Create a private key
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    # Create the certificate
    cert = crypto.X509()
    cert.gmtime_adj_notBefore(0)
    # Valid for 5 years
    cert.gmtime_adj_notAfter(60*60*24*365*5)
    subj = cert.get_subject()
    subj.CN = 'impacket'
    cert.set_pubkey(pkey)
    cert.sign(pkey, "sha256")
    # We write both from the same file
    with open(certname, 'w') as certfile:
        certfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode('utf-8'))
        certfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
    LOG.debug('Wrote certificate to %s' % certname)

# Class to wrap the client socket in SSL when serving as a SOCKS server
class SSLServerMixin(object):
    # This function will wrap the socksSocket in an SSL layer
    def wrapClientConnection(self, cert='/tmp/impacket.crt'):
        # Create a context, we don't really care about the SSL/TLS
        # versions used since it is only intended for local use and thus
        # doesn't have to be super-secure
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_cipher_list('ALL:@SECLEVEL=0'.encode('utf-8'))
        try:
            ctx.use_privatekey_file(cert)
            ctx.use_certificate_file(cert)
        except SSL.Error:
            LOG.info('SSL requested - generating self-signed certificate in /tmp/impacket.crt')
            generateImpacketCert(cert)
            ctx.use_privatekey_file(cert)
            ctx.use_certificate_file(cert)

        sslSocket = SSL.Connection(ctx, self.socksSocket)
        sslSocket.set_accept_state()

        # Now set this property back to the SSL socket instead of the regular one
        self.socksSocket = sslSocket



def sni_callback(ssl_sock: SSLSocket, 
                    sni_name: Optional[str], 
                    ssl_context: ssl.SSLContext):
    """ Callback, called when client send SNI """
    if not sni_name:
        return None
    
    certificate, private_key = generate_self_signed_certificate(certificate_string=sni_name)

    ssl_sock.context.use_certificate(certificate)
    ssl_sock.context.use_privatekey(private_key)


def generate_self_signed_certificate(certificate_string: str="Impacket") -> Tuple[str, str]:
    ''' Generate a new self-signed certificate'''
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Subject Information
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization of Information Security Research"),
        x509.NameAttribute(NameOID.COMMON_NAME, certificate_string),
    ])

    # Issuer information (self-signed)
    issuer = subject

    # Certification create
    builder = x509.CertificateBuilder()

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))

    # 1. Add keyUsage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )

    # 2. Add basicConstraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    try:
        sni_ip = ipaddress.IPv4Address(certificate_string)
    except ipaddress.AddressValueError:
        sni_ip = None
    sans = []
    if sni_ip is None:
        sans.append(x509.DNSName(certificate_string))
        try:
            sni_ip = socket.gethostbyname(certificate_string)
            sans.append(x509.IPAddress(ipaddress.IPv4Address(sni_ip)))
        except socket.gaierror:
            pass
    else:
        sans.append(x509.IPAddress(sni_ip))


    # 3. ADD subjectAltName
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sans),
        critical=False
    )

    # Extended Key Usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
        ]),
        critical=False
    )
    # Sign certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    return certificate.public_bytes(encoding=serialization.Encoding.PEM), private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                                                    format=serialization.PrivateFormat.PKCS8,
                                                                                                    encryption_algorithm=serialization.NoEncryption())