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
#   Given a password, hash or aesKey, it will request a TGT and save it as ccache
#
#   Examples:
#       ./getTGT.py -hashes lm:nt contoso.com/user
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
from impacket.examples.utils import parse_credentials
from impacket.krb5.kerberosv5 import getKerberosTGT, parseKerberosOptions
from impacket.krb5 import constants
from impacket.krb5.types import Principal


class GETTGT:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user= target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__service = options.service
        self.__encryption = options.encryption
        self.__tgtOptions = parseKerberosOptions(options.tgt_options)
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
                                                                serverName = self.__service, encType=self.__encryption, options=self.__tgtOptions)
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
    
    kerberos_options = parser.add_argument_group('kerberos options')

    kerberos_options.add_argument('-tgs-options', action="store", metavar="hex value", default=None, help='The hexadecimal value to send to the Kerberos Ticket Granting Service (TGS).')
    kerberos_options.add_argument('-tgt-options', action="store", metavar="hex value", default=None, help='The hexadecimal value to send to the Kerberos Ticket Granting Ticket (TGT).')
    kerberos_options.add_argument('-encryption', action="store", metavar="18 or 23", default="23", help='Set encryption to AES256 (18) or RC4 (23).')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getTGT.py -hashes lm:nt contoso.com/user\n")
        print("\tit will use the lm:nt hashes for authentication. If you don't specify them, a password will be asked")
        sys.exit(1)
    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.identity)

    try:
        if domain is None:
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if options.principalType is None:
            logging.critical('Invalid principalType!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = GETTGT(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
