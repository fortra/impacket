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
#   This module will try to find all delegation relationships in a given domain.
#   Delegation relationships can provide info on specific users and systems to target,
#   as access to these systems will grant access elsewhere also.
#   Unconstrained, constrained, and resource-based constrained delegation types are queried
#   for and displayed.
#
# Author:
#   Dave Cossa (@G0ldenGunSec)
#   Based on GetUserSPNs.py by Alberto Solino (@agsolino)
#

from __future__ import division
from __future__ import print_function

import argparse
import logging
import sys

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.ldap import ldap, ldapasn1
from impacket.ldap import ldaptypes


def checkIfSPNExists(ldapConnection, sAMAccountName, rights):
    # Check if SPN exists
    spnExists = "-"
    if rights == "N/A":
        query = "(servicePrincipalName=HOST/%s)" % sAMAccountName.rstrip("$")
    else:
        query = "(servicePrincipalName=%s)"%rights

    respSpnExists = ldapConnection.search(
        searchFilter=query, 
        attributes=["servicePrincipalName", "distinguishedName"], 
        sizeLimit=1
    )
    results = [item for item in respSpnExists if isinstance(item, ldapasn1.SearchResultEntry)]
    if len(results) != 0:
        spnExists = "Yes"
    else:
        spnExists = "No"
    
    return spnExists


class FindDelegation:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        #[!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP or Hostname when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            logging.warning('KDC IP address and hostname will be ignored because of cross-domain targeting.')
            self.__kdcIP = None
            self.__kdcHost = None

    def run(self):
        # Connect to LDAP
        ldapConnection = ldap_login(self.__target, self.baseDN, self.__kdcIP, self.__kdcHost, self.__doKerberos, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, target_domain=self.__targetDomain, fqdn=True)
        # updating "self.__target" as it may have changed in the ldap_login processing
        self.__target = ldapConnection._dstHost

        searchFilter = "(&(|(UserAccountControl:1.2.840.113556.1.4.803:=16777216)(UserAccountControl:1.2.840.113556.1.4.803:=" \
                       "524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(UserAccountControl:1.2.840.113556.1.4.803:=8192)))"

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName',
                                                     'pwdLastSet', 'userAccountControl', 'objectCategory',
                                                     'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-AllowedToDelegateTo'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))
        
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            userAccountControl = 0
            delegation = ''
            objectType = ''
            rightsTo = []
            protocolTransition = 0

            #after receiving responses we parse through to determine the type of delegation configured on each object
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'Unconstrained'
                            rightsTo.append("N/A")
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'Constrained w/ Protocol Transition'
                            protocolTransition = 1
                    elif str(attribute['type']) == 'objectCategory':
                        objectType = str(attribute['vals'][0]).split('=')[1].split(',')[0]
                    elif str(attribute['type']) == 'msDS-AllowedToDelegateTo':
                        if protocolTransition == 0:
                            delegation = 'Constrained'
                        for delegRights in attribute['vals']:
                            rightsTo.append(str(delegRights))
             
                    #not an elif as an object could both have rbcd and another type of delegation configured for the same object
                    if str(attribute['type']) == 'msDS-AllowedToActOnBehalfOfOtherIdentity':
                        rbcdRights = []
                        rbcdObjType = []
                        searchFilter = '(&(|'
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(attribute['vals'][0]))
                        for ace in sd['Dacl'].aces:
                            searchFilter = searchFilter + "(objectSid="+ace['Ace']['Sid'].formatCanonical()+")"
                        searchFilter = searchFilter + ")(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
                        delegUserResp = ldapConnection.search(searchFilter=searchFilter,attributes=['sAMAccountName', 'objectCategory'],sizeLimit=999)
                        for item2 in delegUserResp:
                            if isinstance(item2, ldapasn1.SearchResultEntry) is not True:
                                continue
                            rbcdRights.append(str(item2['attributes'][0]['vals'][0]))
                            rbcdObjType.append(str(item2['attributes'][1]['vals'][0]).split('=')[1].split(',')[0])
							
                        if mustCommit is True:
                            if int(userAccountControl) & UF_ACCOUNTDISABLE:
                                logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                            else:
                                for rights, objType in zip(rbcdRights,rbcdObjType):
                                    spnExists = checkIfSPNExists(ldapConnection, sAMAccountName, rights)
                                    answers.append([rights, objType, 'Resource-Based Constrained', sAMAccountName, str(spnExists)])
                        
                #print unconstrained + constrained delegation relationships
                if delegation in ['Unconstrained', 'Constrained', 'Constrained w/ Protocol Transition']:
                    if mustCommit is True:
                            if int(userAccountControl) & UF_ACCOUNTDISABLE:
                                logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                            else:
                                for rights in rightsTo:
                                    spnExists = checkIfSPNExists(ldapConnection, sAMAccountName, rights)
                                    answers.append([sAMAccountName, objectType, delegation, rights, str(spnExists)])
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers) > 0:
            self.printTable(answers, header=["AccountName", "AccountType", "DelegationType", "DelegationRightsTo", "SPN Exists"])
            print('\n\n')
        else:
            print("No entries found!")


# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for delegation relationships ")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-target-domain', action='store', help='Domain to query/request if different than the domain of the user. '
                                                               'Allows for retrieving delegation info across trusts.')

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

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter. Ignored'
                                                                              'if -target-domain is specified.')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    userDomain, username, password, _, _, options.k = parse_identity(options.target, options.hashes, options.no_pass, options.aesKey, options.k)

    if userDomain == '':
        logging.critical('userDomain should be specified!')
        sys.exit(1)

    if options.target_domain:
        targetDomain = options.target_domain
    else:
        targetDomain = userDomain

    try:
        executer = FindDelegation(username, password, userDomain, targetDomain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
