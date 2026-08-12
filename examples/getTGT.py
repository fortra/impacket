#!/usr/bin/env python
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
#   Given a password, hash, aesKey or certificate, it will request a TGT and save it as ccache
#
#   Examples:
#       ./getTGT.py -hashes lm:nt contoso.com/user
#       ./getTGT.py -cert-pfx user.pfx contoso.com/user
#
# Author:
#   Alberto Solino (@agsolino)
#

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
from binascii import unhexlify

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_identity
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.pkinit import DH_GROUPS, EC_CURVES, PKINITCredentials, readPEMCertificates
from impacket.krb5.types import Principal


class GETTGT:
    @staticmethod
    def loadCertificate(options):
        """Build the PKINIT credentials out of the certificate options, if any."""
        if options.cert_pfx is None and options.cert_pem is None:
            return None

        trustedCAs = []
        if options.ca_cert is not None:
            with open(options.ca_cert, 'rb') as fd:
                trustedCAs = readPEMCertificates(fd.read())

        settings = {'keyExchange': options.key_exchange, 'dhGroup': options.dh_group, 'curve': options.curve,
                    'trustedCAs': trustedCAs, 'verifyKDC': not options.no_verify_kdc,
                    'requestOCSP': options.request_ocsp, 'requireOCSP': options.require_ocsp}

        if options.cert_pfx is not None:
            return PKINITCredentials.fromPFX(options.cert_pfx, options.pfx_pass, **settings)
        if options.key_pem is None:
            logging.critical('-key-pem is required along with -cert-pem!')
            sys.exit(1)
        return PKINITCredentials.fromPEM(options.cert_pem, options.key_pem, options.pfx_pass, **settings)

    def __init__(self, target, password, domain, options, certificate=None):
        self.__password = password
        self.__user= target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__service = options.service
        self.__certificate = certificate
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__user + '.ccache'))
        from impacket.krb5.ccache import CCache
        ccache = CCache()

        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__user + '.ccache')

    def run(self):
        userName = Principal(self.__user, type=options.principalType.value)
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName = userName,
                                                                password = self.__password,
                                                                domain = self.__domain,
                                                                lmhash = unhexlify(self.__lmhash),
                                                                nthash = unhexlify(self.__nthash),
                                                                aesKey = self.__aesKey,
                                                                kdcHost = self.__kdcHost,
                                                                serverName = self.__service,
                                                                certificate = self.__certificate)
        self.saveTicket(tgt,oldSessionKey)

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Given a password, hash or aesKey, it will request a "
                                                                "TGT and save it as ccache")
    parser.add_argument('identity', action='store', help='[domain/]username[:password]')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-service', action='store', metavar="SPN", help='Request a Service Ticket directly through an AS-REQ')
    group.add_argument('-principalType', nargs="?", type=lambda value: constants.PrincipalNameType[value.upper()] if value.upper() in constants.PrincipalNameType.__members__ else None,  action='store', default=constants.PrincipalNameType.NT_PRINCIPAL, help='PrincipalType of the token, can be one of  NT_UNKNOWN, NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST, NT_SRV_XHST, NT_UID, NT_SMTP_NAME, NT_ENTERPRISE, NT_WELLKNOWN, NT_SRV_HST_DOMAIN, NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID, NT_ENT_PRINCIPAL_AND_ID; default is NT_PRINCIPAL, ')

    group = parser.add_argument_group('certificate (PKINIT, RFC 4556)')

    group.add_argument('-cert-pfx', action='store', metavar="FILE", help='Client certificate and private key in PKCS#12 format')
    group.add_argument('-pfx-pass', action='store', metavar="PASSWORD", help='Password of the PKCS#12 file')
    group.add_argument('-cert-pem', action='store', metavar="FILE", help='Client certificate in PEM format')
    group.add_argument('-key-pem', action='store', metavar="FILE", help='Client private key in PEM format')
    group.add_argument('-key-exchange', action='store', choices=['dh', 'ecdh', 'rsa'], default='dh',
                       help='AS reply key delivery method: Diffie-Hellman (default), its elliptic curve variant '
                            '(RFC 5349) or public key encryption')
    group.add_argument('-dh-group', action='store', type=int, choices=sorted(DH_GROUPS), default=14,
                       help='MODP group to use for the Diffie-Hellman key agreement, default is 14 (2048 bits)')
    group.add_argument('-curve', action='store', choices=sorted(EC_CURVES), default='P-256',
                       help='Named curve to use for the ECDH key agreement, default is P-256')
    group.add_argument('-ca-cert', action='store', metavar="FILE", help='PEM file holding the CA certificates trusted '
                       'to certify the KDC. Without it the KDC certification path is not validated')
    group.add_argument('-no-verify-kdc', action='store_true', help='Do not check the KDC certificate at all')
    group.add_argument('-request-ocsp', action='store_true', help='Ask the KDC for the OCSP responses of its '
                       'certificates (RFC 4557)')
    group.add_argument('-require-ocsp', action='store_true', help='Ask for the OCSP responses and fail if the KDC '
                       'returns no usable one for its certificate. Windows KDCs never do')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getTGT.py -hashes lm:nt contoso.com/user\n")
        print("\tit will use the lm:nt hashes for authentication. If you don't specify them, a password will be asked")
        print("\t./getTGT.py -cert-pfx user.pfx contoso.com/user\n")
        print("\tit will authenticate with the certificate of the PKCS#12 file, through PKINIT")
        sys.exit(1)
    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    certificate = GETTGT.loadCertificate(options)
    if certificate is not None:
        options.no_pass = True

    domain, username, password, _, _, options.k = parse_identity(options.identity, options.hashes, options.no_pass, options.aesKey, options.k)

    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if username == '' and certificate is not None:
        # Fall back on the identity the certificate is bound to
        upn = certificate.getUPN()
        if upn is None:
            logging.critical('No username given and the certificate holds no UPN!')
            sys.exit(1)
        username = upn.split('@')[0]
        logging.info('Using %s, the UPN of the certificate' % upn)

    if options.principalType is None:
        logging.critical('Invalid principalType!')
        sys.exit(1)

    try:
        executer = GETTGT(username, password, domain, options, certificate)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
