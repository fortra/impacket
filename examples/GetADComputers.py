#!/usr/bin/python3
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#   Hypnoze (@Hypnoze57)
#   Based on the work of Alberto Solino (@agsolino) on GetADUsers.py
#
# Description:
#     This script will gather name and operating systems about the domain's computers.
#     It could also be used across domain trust by using the -target-domain paramter.
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys
from datetime import datetime

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.examples import logger
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection


class GetADComputers:
    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__target = None
        self.__kdcHost = cmdLineOptions.dc_ip
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        # Let's calculate the header and format
        self.__header = ["Name", "operatingSystem"]
        # Since we won't process all rows at once, this will be fixed lengths
        # self.__colLen = [20, 30, 19, 19]
        self.__colLen = [20, 30]
        self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])


    def getMachineName(self):
        if self.__targetDomain != self.__domain:
            if self.__kdcHost is None:
                s = SMBConnection(self.__targetDomain, self.__targetDomain)
            else:
                s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__domain if self.__kdcHost is None else self.__kdcHost, self.__domain if self.__kdcHost is None else self.__kdcHost)

        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % self.__domain)
        else:
            s.logoff()
        return s.getServerName()


    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t


    def processRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return

        name = ''
        operatingSystem = 'N/A'

        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'name':
                    if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                        name = attribute['vals'][0].asOctets().decode('utf-8')
                elif str(attribute['type']) == 'operatingSystem':
                    if str(attribute['vals'][0]) == '0':
                        operatingSystem = 'N/A'
                    else:
                        operatingSystem = str((attribute['vals'][0]))

            print((self.__outputFormat.format(*[name, operatingSystem])))
        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error('Skipping item, cannot process due to error %s' % str(e))
            pass


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
            ldapConnection = ldap.LDAPConnection('ldap://%s'%self.__target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

        logging.info('Querying %s for information about domain.' % self.__target)
        # Print header
        print((self.__outputFormat.format(*self.__header)))
        print(('  '.join(['-' * itemLen for itemLen in self.__colLen])))

        # Building the search filter
        searchFilter = "(&(sAMAccountName=*)(objectCategory=computer))"

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)

            ldapConnection.search(searchFilter=searchFilter,
                                  attributes=['name', 'operatingSystem'],
                                  sizeLimit=0, searchControls = [sc], perRecordCallback=self.processRecord)
        except ldap.LDAPSearchError:
                raise

        ldapConnection.close()


# Process command-line arguments.
if __name__ == '__main__':
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for computers data")

    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument('-target-domain', action='store', help='Domain to query if different than the domain of the user. Usefull with trusts')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')

    if len(sys.argv)==1:
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

    import re
    domain, username, password = re.compile('(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?').match(options.target).groups('')

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True


    if options.target_domain:
        logging.debug('Target domain set !')
        targetDomain = options.target_domain
    else:
        targetDomain = domain

    try:
        executer = GetADComputers(username, password, domain, targetDomain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print((str(e)))
