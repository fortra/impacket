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
