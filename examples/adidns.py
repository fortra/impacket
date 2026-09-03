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
#
# Description:
#   DNS record management tool for Active Directory integrated DNS via LDAP
#   
#   This tool allows querying, adding, modifying, and removing DNS records
#   from Active Directory integrated DNS zones through LDAP operations.
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
import os
import re
import socket
import datetime
import traceback

import ldap3
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE
import dns.resolver

from impacket import version
from impacket.examples import logger, utils
from impacket.examples.utils import parse_target, parse_identity, init_ldap_session
from impacket.dnsp import (
    DNS_RECORD, DNS_COUNT_NAME, DNS_RPC_RECORD_A, DNS_RPC_RECORD_NODE_NAME,
    DNS_RPC_RECORD_SOA, DNS_RPC_RECORD_SRV, DNS_RPC_RECORD_TS,
    new_record, print_record, ldap2domain, RECORD_TYPE_MAPPING
)


class DNSManager:
    """DNS record management class for Active Directory integrated DNS"""
    
    def __init__(self, ldap_connection, server_info):
        self.ldap_connection = ldap_connection
        self.server_info = server_info
        self.domain_root = server_info.other['defaultNamingContext'][0]
        self.forest_root = server_info.other['rootDomainNamingContext'][0]
        self.domain = ldap2domain(self.domain_root)
    
    def get_dns_root(self, partition='domain'):
        """Get DNS root DN based on partition type"""
        if partition == 'forest':
            return f'CN=MicrosoftDNS,DC=ForestDnsZones,{self.forest_root}'
        elif partition == 'legacy':
            return f'CN=MicrosoftDNS,CN=System,{self.domain_root}'
        else:  # domain
            return f'CN=MicrosoftDNS,DC=DomainDnsZones,{self.domain_root}'
    
    def get_dns_zones(self, partition='domain', return_dn=False):
        """Get list of DNS zones"""
        dns_root = self.get_dns_root(partition)
        attr = 'distinguishedName' if return_dn else 'dc'
        
        try:
            self.ldap_connection.search(dns_root, '(objectClass=dnsZone)', 
                                      search_scope=LEVEL, attributes=[attr])
            zones = []
            for entry in self.ldap_connection.response:
                if entry['type'] != 'searchResEntry':
                    continue
                zones.append(entry['attributes'][attr])
            return zones
        except Exception as e:
            logging.error(f'Failed to query DNS zones: {e}')
            return []
    
    def get_next_serial(self, zone=None, dns_server=None):
        """Get next serial number for DNS record"""
        if not zone:
            zone = self.domain
        
        if not dns_server:
            dns_server = self.ldap_connection.server.host
        
        try:
            resolver = dns.resolver.Resolver()
            
            # Try to use the DNS server as resolver
            try:
                socket.inet_aton(dns_server)
                resolver.nameservers = [dns_server]
            except socket.error:
                pass
            
            res = resolver.resolve(zone, 'SOA', tcp=True)
            for answer in res:
                return answer.serial + 1
        except Exception:
            # If we can't get serial, use current timestamp
            return int(datetime.datetime.now().timestamp())
    
    def find_record(self, record_name, zone=None, partition='domain'):
        """Find DNS record by name"""
        if not zone:
            zone = self.domain
        
        # Clean record name
        target = record_name
        if target.lower().endswith(zone.lower()):
            target = target[:-(len(zone)+1)]
        
        dns_root = self.get_dns_root(partition)
        search_target = f'DC={zone},{dns_root}'
        
        try:
            filter_str = f'(&(objectClass=dnsNode)(name={ldap3.utils.conv.escape_filter_chars(target)}))'
            self.ldap_connection.search(search_target, filter_str,
                                      attributes=['dnsRecord', 'dNSTombstoned', 'name'])
            
            for entry in self.ldap_connection.response:
                if entry['type'] != 'searchResEntry':
                    continue
                return entry
            return None
        except Exception as e:
            logging.error(f'Failed to search for DNS record: {e}')
            return None
    
    def query_record(self, record_name, zone=None, partition='domain'):
        """Query DNS record"""
        entry = self.find_record(record_name, zone, partition)
        if not entry:
            logging.error('Target record not found!')
            return False
        
        logging.info(f'Found record {entry["attributes"]["name"]}')
        logging.info(f'DN: {entry["dn"]}')
        
        for record_data in entry['raw_attributes']['dnsRecord']:
            dr = DNS_RECORD(record_data)
            print_record(dr, entry['attributes']['dNSTombstoned'])
        
        return True
    
    def add_record(self, record_name, record_data, record_type='A', zone=None, 
                   partition='domain', allow_multiple=False, ttl=180):
        """Add DNS record"""
        if not zone:
            zone = self.domain
        
        # Clean record name
        target = record_name
        if target.lower().endswith(zone.lower()):
            target = target[:-(len(zone)+1)]
        
        dns_root = self.get_dns_root(partition)
        search_target = f'DC={zone},{dns_root}'
        
        existing_entry = self.find_record(record_name, zone, partition)
        
        # Determine record type number
        record_type_num = 1  # Default to A record
        if record_type.upper() == 'A':
            record_type_num = 1
        # Add other record types as needed
        
        if existing_entry:
            if not allow_multiple and record_type_num == 1:
                # Check if A record already exists
                for record_bytes in existing_entry['raw_attributes']['dnsRecord']:
                    dr = DNS_RECORD(record_bytes)
                    if dr['Type'] == 1:
                        address = DNS_RPC_RECORD_A(dr['Data'])
                        logging.error(f'Record already exists and points to {address.formatCanonical()}')
                        logging.error('Use -modify to overwrite or -allow-multiple to override this')
                        return False
            
            # Add extra record
            record = new_record(record_type_num, self.get_next_serial(zone), ttl)
            if record_type_num == 1:  # A record
                record['Data'] = DNS_RPC_RECORD_A()
                record['Data'].fromCanonical(record_data)
            
            logging.info('Adding extra record')
            try:
                self.ldap_connection.modify(existing_entry['dn'], 
                                          {'dnsRecord': [(MODIFY_ADD, record.getData())]})
                return self._check_ldap_result('add extra record')
            except Exception as e:
                logging.error(f'Failed to add extra record: {e}')
                return False
        else:
            # Create new record
            target_dn = f'DC={target},{search_target}'
            
            node_data = {
                'objectCategory': f'CN=Dns-Node,{self.server_info.other["schemaNamingContext"][0]}',
                'dNSTombstoned': False,
                'name': target
            }
            
            record = new_record(record_type_num, self.get_next_serial(zone), ttl)
            if record_type_num == 1:  # A record
                record['Data'] = DNS_RPC_RECORD_A()
                record['Data'].fromCanonical(record_data)
            
            node_data['dnsRecord'] = record.getData()
            
            logging.info(f'Creating new record {target}')
            try:
                self.ldap_connection.add(target_dn, ['top', 'dnsNode'], node_data)
                return self._check_ldap_result('create record')
            except Exception as e:
                logging.error(f'Failed to create record: {e}')
                return False
    
    def modify_record(self, record_name, new_data, zone=None, partition='domain'):
        """Modify existing DNS record"""
        entry = self.find_record(record_name, zone, partition)
        if not entry:
            logging.error('Target record not found!')
            return False
        
        # For now, we'll implement a simple replace strategy for A records
        # In a full implementation, you'd want more sophisticated logic
        
        new_records = []
        modified = False
        
        for record_data in entry['raw_attributes']['dnsRecord']:
            dr = DNS_RECORD(record_data)
            if dr['Type'] == 1:  # A record
                # Replace the first A record
                if not modified:
                    record = new_record(1, self.get_next_serial(zone))
                    record['Data'] = DNS_RPC_RECORD_A()
                    record['Data'].fromCanonical(new_data)
                    new_records.append(record.getData())
                    modified = True
                else:
                    new_records.append(record_data)
            else:
                new_records.append(record_data)
        
        if not modified:
            logging.error('No A record found to modify')
            return False
        
        try:
            self.ldap_connection.modify(entry['dn'], 
                                      {'dnsRecord': [(MODIFY_REPLACE, new_records)]})
            return self._check_ldap_result('modify record')
        except Exception as e:
            logging.error(f'Failed to modify record: {e}')
            return False
    
    def remove_record(self, record_name, zone=None, partition='domain', 
                     target_data=None, complete_delete=False):
        """Remove DNS record (tombstone or complete delete)"""
        entry = self.find_record(record_name, zone, partition)
        if not entry:
            logging.error('Target record not found!')
            return False
        
        if complete_delete:
            # Complete LDAP delete
            try:
                self.ldap_connection.delete(entry['dn'])
                return self._check_ldap_result('delete record')
            except Exception as e:
                logging.error(f'Failed to delete record: {e}')
                return False
        else:
            # Tombstone the record
            if target_data:
                # Remove specific A record
                new_records = []
                removed = False
                
                for record_data in entry['raw_attributes']['dnsRecord']:
                    dr = DNS_RECORD(record_data)
                    if dr['Type'] == 1:  # A record
                        address = DNS_RPC_RECORD_A(dr['Data'])
                        if address.formatCanonical() == target_data and not removed:
                            # Create tombstone record
                            ts_record = new_record(0, self.get_next_serial(zone))
                            ts_data = DNS_RPC_RECORD_TS()
                            ts_data['entombedTime'] = int((datetime.datetime.now() - 
                                                         datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)
                            ts_record['Data'] = ts_data.getData()
                            new_records.append(ts_record.getData())
                            removed = True
                        else:
                            new_records.append(record_data)
                    else:
                        new_records.append(record_data)
                
                if not removed:
                    logging.error(f'A record with data {target_data} not found')
                    return False
            else:
                # Tombstone all records
                new_records = []
                for record_data in entry['raw_attributes']['dnsRecord']:
                    ts_record = new_record(0, self.get_next_serial(zone))
                    ts_data = DNS_RPC_RECORD_TS()
                    ts_data['entombedTime'] = int((datetime.datetime.now() - 
                                                 datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)
                    ts_record['Data'] = ts_data.getData()
                    new_records.append(ts_record.getData())
            
            try:
                self.ldap_connection.modify(entry['dn'], 
                                          {'dnsRecord': [(MODIFY_REPLACE, new_records)]})
                return self._check_ldap_result('tombstone record')
            except Exception as e:
                logging.error(f'Failed to tombstone record: {e}')
                return False
    
    def resurrect_record(self, record_name, zone=None, partition='domain'):
        """Resurrect tombstoned DNS record"""
        entry = self.find_record(record_name, zone, partition)
        if not entry:
            logging.error('Target record not found!')
            return False
        
        # Check if target has multiple records
        if len(entry['raw_attributes']['dnsRecord']) > 1:
            logging.error('Target has multiple records, I dont know how to handle this.')
            return False
        else:
            logging.info('Target has only one record, resurrecting it')
            
            # Create a tombstone record but set dNSTombstoned to False
            # This follows the original dnstool.py logic
            ts_record = new_record(0, self.get_next_serial(zone))  # Type 0 = tombstone
            ts_data = DNS_RPC_RECORD_TS()
            ts_data['entombedTime'] = int((datetime.datetime.now() - 
                                         datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)
            ts_record['Data'] = ts_data.getData()
            
            try:
                self.ldap_connection.modify(entry['dn'], {
                    'dnsRecord': [(MODIFY_REPLACE, [ts_record.getData()])],
                    'dNSTombstoned': [(MODIFY_REPLACE, [False])]
                })
                if self._check_ldap_result('resurrect record'):
                    logging.info('Record resurrected. You will need to (re)add the record with the IP address.')
                    return True
                return False
            except Exception as e:
                logging.error(f'Failed to resurrect record: {e}')
                return False
    
    def _check_ldap_result(self, operation):
        """Check LDAP operation result and log appropriate message"""
        if self.ldap_connection.result['result'] == 0:
            logging.info(f'LDAP operation completed successfully: {operation}')
            return True
        else:
            logging.error(f'LDAP operation failed ({operation}): {self.ldap_connection.result["description"]} - {self.ldap_connection.result.get("message", "")}')
            return False


def main():
    print(version.BANNER)
    
    parser = argparse.ArgumentParser(
        description='Advanced DNS record management tool for Active Directory integrated DNS via LDAP',
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
  %(prog)s 'domain.local/user:pass@dc.domain.local' add -record web01 -data 10.0.20.05 -ttl 300
  %(prog)s 'domain.local/user:pass@dc.domain.local' add -record web01 -data 10.0.20.05 -allow-multiple
  %(prog)s 'domain.local/user:pass@dc.domain.local' remove -record web01 -data 10.0.20.05
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
        'resurrect', 'list-zones', 'list-zones-dn'
    ], help='Action to perform: query (show record), add (create new), modify (change existing), remove (tombstone), ldap-delete (permanent delete), resurrect (restore tombstoned), list-zones (show zone names), list-zones-dn (show zone DNs)')
    
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
    if args.action in ['query', 'add', 'modify', 'remove', 'ldap-delete', 'resurrect']:
        if not args.record:
            logging.error(f'Action "{args.action}" requires -record parameter')
            sys.exit(1)
    
    if args.action in ['add', 'modify']:
        if not args.data:
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
        # Initialize LDAP session
        ldap_server, ldap_session = init_ldap_session(
            domain, username, password, lmhash, nthash, args.k, 
            args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)
        
        # Create DNS manager
        dns_manager = DNSManager(ldap_session, ldap_server.info)
        
        # Execute requested action
        if args.action == 'list-zones':
            zones = dns_manager.get_dns_zones(args.partition, return_dn=False)
            if zones:
                partition_name = args.partition.title()
                logging.info(f'Found {len(zones)} {partition_name} DNS zones:')
                for zone in zones:
                    print(f'  {zone}')
            else:
                logging.info(f'No DNS zones found in {args.partition} partition')
        
        elif args.action == 'list-zones-dn':
            zones = dns_manager.get_dns_zones(args.partition, return_dn=True)
            if zones:
                partition_name = args.partition.title()
                logging.info(f'Found {len(zones)} {partition_name} DNS zones with Distinguished Names:')
                for zone in zones:
                    print(f'  {zone}')
            else:
                logging.info(f'No DNS zones found in {args.partition} partition')
        
        elif args.action == 'query':
            dns_manager.query_record(args.record, args.zone, args.partition)
        
        elif args.action == 'add':
            dns_manager.add_record(args.record, args.data, args.type, args.zone, 
                                 args.partition, args.allow_multiple, args.ttl)
        
        elif args.action == 'modify':
            dns_manager.modify_record(args.record, args.data, args.zone, args.partition)
        
        elif args.action == 'remove':
            dns_manager.remove_record(args.record, args.zone, args.partition, 
                                    args.data, complete_delete=False)
        
        elif args.action == 'ldap-delete':
            dns_manager.remove_record(args.record, args.zone, args.partition, 
                                    complete_delete=True)
        
        elif args.action == 'resurrect':
            dns_manager.resurrect_record(args.record, args.zone, args.partition)
    
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(f'Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main() 
