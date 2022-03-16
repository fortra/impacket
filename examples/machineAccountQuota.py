#!/usr/bin/env python3
#Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.

# Description:
#   This module will try to get the Machine Account Quota from the domain attribute ms-DS-MachineAccountQuota.
#   If the value is superior to 0, it opens new paths to enumerate further the target domain.
#
#   Author:
#       TahiTi
#

import argparse
import logging
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection

class GetMachineAccountQuota:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__target = None
        self.__kdcHost = cmdLineOptions.dc_ip
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

    def getMachineName(self):
        if self.__kdcHost is not None:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__domain, self.__domain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s')
        else:
            s.logoff()
        return s.getServerName()

    def run(self):
        if self.__doKerberos:
            self.__target = self.getMachineName()
        else:
            if self.__kdcHost is not None:
                self.__target = self.__kdcHost
            else:
                self.__target = self.__domain

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                             self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                                 self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

        logging.info('Querying %s for information about domain.' % self.__target)

        # Building the search filter
        searchFilter = "(objectClass=*)"
        attributes = ['ms-DS-MachineAccountQuota']

        try:
            result = ldapConnection.search(searchFilter=searchFilter, attributes=attributes)
            for item in result:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue
                machineAccountQuota = 0
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'ms-DS-MachineAccountQuota':
                        machineAccountQuota = attribute['vals'][0]
                    logging.info('MachineAccountQuota: %d' % machineAccountQuota)

        except ldap.LDAPSearchError:
            raise

        ldapConnection.close()

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description='Retrieve the machine account quota value from the domain.')

    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true',
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                            'omitted it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv) == 1:
        parser.print_help()
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

    domain, username, password = parse_credentials(options.target)

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass('Password:')

    try:
        execute = GetMachineAccountQuota(username, password, domain, options)
        execute.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        print((str(e)))
