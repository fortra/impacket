#!/usr/bin/env python3
import argparse
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.ldap_shell import LdapShell
from impacket.examples.utils import init_ldap_session, parse_identity


class DummyDomainDumper:
    def __init__(self, root: str):
        self.root = root


def ldap_shell(ldap_server, ldap_conn):
    root = ldap_server.info.other["defaultNamingContext"][0]
    domain_dumper = DummyDomainDumper(root)
    ldap_shell = LdapShell(sys, domain_dumper, ldap_conn)
    try:
        ldap_shell.cmdloop()
    except KeyboardInterrupt:
        print("Bye!\n")
        pass

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='LDAP Shell')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth_con.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auth_con.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_con.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    auth_con.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, -dc-ip will be used')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

if __name__ == '__main__':
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)
    ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)
    ldap_shell(ldap_server, ldap_session)
