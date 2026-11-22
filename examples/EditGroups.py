#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2024 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script to change a group on AD, this script let you read if a user is part of a group, add a user to a group or remove a user from a group, the script use ldap to read, write or remove.
# Author:
#   Fabrizzio Bridi (@Fabrizzio53)

import argparse
import logging
import sys
import traceback
import ldap3
import ldapdomaindump

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldaptypes

from impacket.examples.utils import init_ldap_session, parse_identity

class Groupchanger(object):

    def __init__(self, ldap_server, ldap_session, args):

        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

        self.__action = args.action
        self.__user = args.user
        self.__group = args.group
        self.__group_domain = args.group_domain
        self.__user_domain = args.user_domain

    def domain_to_ldap(self,domain):

        parts = domain.split('.')

        ldap_format = ','.join(['DC=' + part for part in parts])

        return ldap_format

    def run(self):
        
        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None

        if self.__group_domain == None:

            self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

            dn = self.domain_dumper.root

        else:
            
            self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

            dn = self.domain_to_ldap(self.__group_domain)


        print(f"[+] Checking if group {self.__group} is in the domain {dn}!")

        self.ldap_session.search(
            search_base=dn,
            search_filter=f'(&(objectClass=group)(cn={self.__group}))',
            attributes=['member']
        )

        if self.ldap_session.entries:

            print('[+] Group ' + self.__group + ' found at domain ' + dn)

        else:

            print('[-] Error: group' + self.__group + 'not found.')
            sys.exit(1)

        group_dn = self.ldap_session.entries[0].entry_dn
        members = self.ldap_session.entries[0].member

        if self.__user_domain == None:

            dn = self.domain_dumper.root

        else:
            
            dn = self.domain_to_ldap(self.__user_domain)
           
        print(f"[+] Checking if {self.__user} exists in the domain {dn} and if is already part of {self.__group}!")
            
        self.ldap_session.search(
            search_base=dn,
            search_filter=f'(&(objectClass=user)(sAMAccountName={self.__user}))',
            attributes=['distinguishedName']
        )
        
        if self.ldap_session.entries:
            print('[+] User ' + self.__user + ' found at the domain ' + dn)
        else:
            print('[-] Error: user not found.')
            sys.exit(1)

        user_dn = self.ldap_session.entries[0].distinguishedName.value

        if user_dn in members:

            print(f'[+] User {self.__user} is already a member of the group {self.__group}.')

            if self.__action == 'add':

                print(f"[+] Add action was called, since the user is already part of the group nothing got changed!")
                sys.exit(0)

            elif self.__action == 'remove':

                if self.ldap_session.modify(
                    dn=group_dn,
                    changes={'member': [(ldap3.MODIFY_DELETE, [user_dn])]}
                ):
                    print(f'[+] User {self.__user} got deleted from the group {self.__group}.')
                else:
                    print(f'[-] There was an error at deleting user {self.__user} from the group {self.__group} with error: {self.ldap_session.result["description"]}')               

        else:
            
            if self.__action == 'add':

                if self.ldap_session.modify(
                    dn=group_dn,
                    changes={'member': [(ldap3.MODIFY_ADD, [user_dn])]}
                ):
                    print(f'[+] User {self.__user} got added to the group {self.__group} successfully.')
                else:
                    print(f'[-] There was an error at adding user {self.__user} to the group {self.__group} with error: {self.ldap_session.result["description"]}')
            
            elif self.__action == "remove":

                print(f"[+] remove action was called, since the user is not in the group, nothing got changed!")
                sys.exit(0)      

            else:

                print(f"[+] User {self.__user} is not inside the group: {self.__group}.")         


def init_logger(args):
    # Init the example's logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Add or remove a user from a group that you have control over.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-user', action='store', metavar='username', help='The user that you want to add or remove from a group')
    parser.add_argument('-group', action='store', help='The group you want the user to be added ')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-group_domain', action='store', help='The domain the group is at, usefull when you have trusts and need to add a user to a group from another domain, by default it uses the current domain')
    parser.add_argument('-user_domain', action='store', help='The domain the user is at, usefull when you have trusts and need to add a user to a group from another domain, by default it uses the current domain')


    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth_con.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auth_con.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_con.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    auth_con.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, -dc-ip will be used')

    dacl_parser = parser.add_argument_group("group editor")
    dacl_parser.add_argument('-action', choices=['add', 'remove', 'read'], nargs='?', default='read', help='Action to operate over the group')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)
  
    if args.user is None and args.group is None:
        logging.critical('A username and a group to add should be specified!')
        sys.exit(1)

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:

        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)

        groupchanger = Groupchanger(ldap_server, ldap_session, args)

        groupchanger.run()

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':

    main()
