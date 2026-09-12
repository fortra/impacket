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
#   DNS record management tool for Active Directory integrated DNS via LDAP.
#
#   All record handling is done by impacket.dnsp.ADIDNSManager, this example
#   only takes care of the LDAP session and the command line interface.
#
#   Examples:
#     adidns.py 'domain.local/user:pass@dc.domain.local' list-zones
#     adidns.py 'domain.local/user:pass@dc.domain.local' list-zones-dn
#     adidns.py 'domain.local/user:pass@dc.domain.local' query -record test
#     adidns.py 'domain.local/user:pass@dc.domain.local' add -record test -data 192.168.1.100
#     adidns.py 'domain.local/user:pass@dc.domain.local' modify -record test -data 192.168.1.200
#     adidns.py 'domain.local/user:pass@dc.domain.local' remove -record test
#     adidns.py 'domain.local/user:pass@dc.domain.local' ldap-delete -record test
#     adidns.py 'domain.local/user:pass@dc.domain.local' resurrect -record test
#
# Authors:
#   Hakan Yavuz (@lodos2005) - Impacket integration and enhancements
#   Dirk-jan Mollema (@_dirkjan) - Original dnstool.py implementation
#
# References:
#   [MS-DNSP]: Domain Name System (DNS) Server Management Protocol
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/

import argparse
import logging
import sys
import traceback

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target, parse_identity
from impacket.ldap import ldap as ldap_impacket
from impacket.dnsp import ADIDNSManager, format_record


def build_ldap_session(args, domain, username, password, lmhash, nthash, address):
    """Create an authenticated impacket LDAP connection to the target"""
    url_host = args.dc_host or address
    ldap_url = ('ldaps' if args.use_ldaps else 'ldap') + f'://{url_host}'
    ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, dstIp=args.dc_ip or address)
    if args.k:
        ldap_connection.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip)
    else:
        ldap_connection.login(username, password, domain, lmhash, nthash)
    return ldap_connection


def print_result(manager, args):
    """Dispatch the requested action to the ADIDNSManager and print the result"""
    if args.action in ('list-zones', 'list-zones-dn'):
        zones = manager.get_dns_zones(args.partition, return_dn=args.action == 'list-zones-dn')
        if zones:
            logging.info(f'Found {len(zones)} {args.partition} DNS zones:')
            for zone in zones:
                print(f'  {zone}')
        else:
            logging.info(f'No DNS zones found in {args.partition} partition')
        return True

    if args.action == 'query':
        entry = manager.query_record(args.record, args.zone, args.partition)
        if entry is None:
            logging.error(manager.last_error)
            return False
        logging.info(f'Found record {entry["name"]}')
        print(entry['dn'])
        for record in entry['records']:
            for line in format_record(record, entry['tombstoned']):
                print(line)
        return True

    actions = {
        'add': lambda: manager.add_record(args.record, args.data, args.type, args.zone,
                                          args.partition, args.allow_multiple, args.ttl),
        'modify': lambda: manager.modify_record(args.record, args.data, args.zone, args.partition, args.ttl),
        'remove': lambda: manager.remove_record(args.record, args.zone, args.partition, args.data),
        'ldap-delete': lambda: manager.ldap_delete(args.record, args.zone, args.partition),
        'resurrect': lambda: manager.resurrect_record(args.record, args.zone, args.partition),
    }

    if actions[args.action]():
        message = {
            'add': f'Successfully added record {args.record}',
            'modify': f'Successfully modified record {args.record}',
            'remove': f'Successfully tombstoned record {args.record}',
            'ldap-delete': f'Successfully deleted record {args.record}',
            'resurrect': f'Record {args.record} resurrected. You will need to (re)add the record with the IP address.',
        }
        logging.info(message[args.action])
        return True

    logging.error(manager.last_error)
    return False


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        description='DNS record management tool for Active Directory integrated DNS via LDAP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
DNS Record Management Examples:

Basic Operations:
  %(prog)s 'domain.local/user:pass@dc.domain.local' list-zones
  %(prog)s 'domain.local/user:pass@dc.domain.local' list-zones-dn
  %(prog)s 'domain.local/user:pass@dc.domain.local' query -record test
  %(prog)s 'domain.local/user:pass@dc.domain.local' add -record test -data 192.168.1.100
  %(prog)s 'domain.local/user:pass@dc.domain.local' modify -record test -data 192.168.1.200
  %(prog)s 'domain.local/user:pass@dc.domain.local' remove -record test
  %(prog)s 'domain.local/user:pass@dc.domain.local' ldap-delete -record test
  %(prog)s 'domain.local/user:pass@dc.domain.local' resurrect -record test

Different DNS Partitions:
  %(prog)s 'domain.local/user:pass@dc.domain.local' list-zones -partition domain
  %(prog)s 'domain.local/user:pass@dc.domain.local' list-zones -partition forest
  %(prog)s 'domain.local/user:pass@dc.domain.local' list-zones -partition legacy

Advanced A Record Operations:
  %(prog)s 'domain.local/user:pass@dc.domain.local' add -record web01 -data 10.0.20.5 -ttl 300
  %(prog)s 'domain.local/user:pass@dc.domain.local' add -record web01 -data 10.0.20.5 -allow-multiple
  %(prog)s 'domain.local/user:pass@dc.domain.local' remove -record web01 -data 10.0.20.5
  %(prog)s 'domain.local/user:pass@dc.domain.local' query -record web01 -zone example.com

Authentication Methods:
  %(prog)s 'domain.local/user:pass@192.168.1.10' list-zones
  %(prog)s 'domain.local/user@dc.domain.local' list-zones -hashes :ntlmhash
  %(prog)s 'domain.local/user@dc.domain.local' list-zones -k
  %(prog)s 'domain.local/user:pass@dc.domain.local' list-zones -use-ldaps

Cross-Zone Operations:
  %(prog)s 'domain.local/user:pass@dc.domain.local' add -record service -data 10.0.2.100 -zone sub.domain.local
  %(prog)s 'domain.local/user:pass@dc.domain.local' query -record _ldap._tcp -partition forest
        ''')

    parser.add_argument('target', help='[[domain/]username[:password]@]<targetName or address>')

    # Main action argument
    parser.add_argument('action', choices=[
        'query', 'add', 'modify', 'remove', 'ldap-delete',
        'resurrect', 'list-zones', 'list-zones-dn',
    ], help='Action to perform: query (show record), add (create new), modify (change existing), remove (tombstone), '
            'ldap-delete (permanent delete), resurrect (restore tombstoned), list-zones (show zone names), '
            'list-zones-dn (show zone DNs)')

    # Record options
    parser.add_argument('-record', metavar='RECORD', help='DNS record name (FQDN or relative)')
    parser.add_argument('-data', metavar='DATA', help='Record data (IP address for A records)')
    parser.add_argument('-type', choices=['A'], default='A', help='Record type (currently only A supported)')
    parser.add_argument('-zone', metavar='ZONE', help='Zone to operate in (if different from current domain)')
    parser.add_argument('-partition', choices=['domain', 'forest', 'legacy'], default='domain',
                        help='DNS partition to use (default: domain)')
    parser.add_argument('-allow-multiple', action='store_true',
                        help='Allow multiple A records for the same name')
    parser.add_argument('-ttl', type=int, default=180, help='TTL for record (default: 180 seconds)')

    # Authentication options
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', metavar='LMHASH:NTHASH', help='NTLM hashes (format: LMHASH:NTHASH)')
    group.add_argument('-no-pass', action='store_true', help="Don't ask for password (useful for -k)")
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication')
    group.add_argument('-aesKey', metavar='hex key', help='AES key for Kerberos authentication (128 or 256 bits)')

    # Connection options
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', metavar='ip', help='IP address of the domain controller')
    group.add_argument('-dc-host', metavar='hostname', help='Hostname of the domain controller')
    group.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')

    # Logging options
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Add timestamp to every logging output')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Initialize logging
    logger.init(args.ts, args.debug)

    # Validate action-specific arguments
    if args.action not in ('list-zones', 'list-zones-dn') and not args.record:
        logging.error(f'Action "{args.action}" requires -record parameter')
        sys.exit(1)

    if args.action in ('add', 'modify') and not args.data:
        logging.error(f'Action "{args.action}" requires -data parameter')
        sys.exit(1)

    # Parse target
    domain, username, password, address = parse_target(args.target)

    if not domain or not username:
        logging.error('Domain and username must be specified')
        sys.exit(1)

    # Parse identity for additional authentication options
    try:
        domain, username, password, lmhash, nthash, args.k = parse_identity(
            f'{domain}/{username}:{password}', args.hashes, args.no_pass, args.aesKey, args.k)
    except Exception as e:
        logging.error(f'Error parsing identity: {e}')
        sys.exit(1)

    try:
        ldap_connection = build_ldap_session(args, domain, username, password, lmhash, nthash, address)
        manager = ADIDNSManager(ldap_connection, dns_server=args.dc_ip or address)

        if not print_result(manager, args):
            sys.exit(1)
    except ldap_impacket.LDAPSessionError as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(f'Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
