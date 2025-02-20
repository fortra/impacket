#!/usr/bin/env python
####################
#
# Copyright (c) 2019 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Tool to interact with ADIDNS over LDAP
# 
####################
import sys
import argparse
import getpass
import re
import os
import socket
from struct import unpack, pack
from impacket.structure import Structure
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.examples.krbrelayx.utils.kerberos import ldap_kerberos
import ldap3
from impacket.ldap import ldaptypes
import dns.resolver
import datetime

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))



class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

def get_dns_zones(connection, root, attr="dc"):
    connection.search(root, '(objectClass=dnsZone)', search_scope=LEVEL, attributes=[attr])
    zones = []
    for entry in connection.response:
        if entry['type'] != 'searchResEntry':
            continue
        zones.append(entry['attributes'][attr])
    return zones

def get_next_serial(dnsserver, dc, zone, tcp):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    # Check if DNS-server is present
    if dnsserver:
       server = dnsserver
    else:
        server = dc
   

    # Is our host an IP? In that case make sure the server IP is used
    # if not assume lookups are working already
    try:
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
        
    except socket.error:
        pass
    res = dnsresolver.resolve(zone, 'SOA',tcp=tcp)
    for answer in res:
        return answer.serial + 1

def ldap2domain(ldap):
    return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]

def print_record(record, ts=False):
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'
    if ts:
        print('Record is tombStoned (inactive)')
    print_o('Record entry:')
    print(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))
    if record['Type'] == 0:
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        print(' - Tombstoned at: %s' % tstime.toDatetime())
    # A record
    if record['Type'] == 1:
        address = DNS_RPC_RECORD_A(record['Data'])
        print(' - Address: %s' % address.formatCanonical())
    # NS record or CNAME record
    if record['Type'] == 2 or record['Type'] == 5:
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        # address.dump()
        print(' - Address: %s' %  address['nameNode'].toFqdn())
    # SRV record
    if record['Type'] == 33:
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        # record_data.dump()
        print(' - Priority: %d' %  record_data['wPriority'])
        print(' - Weight: %d' %  record_data['wWeight'])
        print(' - Port: %d' %  record_data['wPort'])
        print(' - Name: %s' %  record_data['nameTarget'].toFqdn())
    # SOA record
    if record['Type'] == 6:
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        # record_data.dump()
        print(' - Serial: %d' %  record_data['dwSerialNo'])
        print(' - Refresh: %d' %  record_data['dwRefresh'])
        print(' - Retry: %d' %  record_data['dwRetry'])
        print(' - Expire: %d' %  record_data['dwExpire'])
        print(' - Minimum TTL: %d' %  record_data['dwMinimumTtl'])
        print(' - Primary server: %s' %  record_data['namePrimaryServer'].toFqdn())
        print(' - Zone admin email: %s' %  record_data['zoneAdminEmail'].toFqdn())

def new_record(rtype, serial):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = 180
    # From authoritive zone
    nr['Rank'] = 240
    return nr

def print_operation_result(result):
    if result['result'] == 0:
        print_o('LDAP operation completed successfully')
        return True
    else:
        print_f('LDAP operation failed. Message returned from server: %s %s' %  (result['description'], result['message']))
        return False

RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    33: 'SRV',
    65281: 'WINS'
}

def main():
    parser = argparse.ArgumentParser(description='Query/modify DNS records for Active Directory integrated DNS via LDAP')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    #maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host", type=str,metavar='HOSTNAME',help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u","--user",type=str,metavar='USERNAME',help="DOMAIN\\username for authentication.")
    parser.add_argument("-p","--password",type=str,metavar='PASSWORD',help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("--forest", action='store_true', help="Search the ForestDnsZones instead of DomainDnsZones")
    parser.add_argument("--legacy", action='store_true', help="Search the System partition (legacy DNS storage)")
    parser.add_argument("--zone", help="Zone to search in (if different than the current domain)")
    parser.add_argument("--print-zones", action='store_true', help="Only query all zones on the DNS server, no other modifications are made")
    parser.add_argument("--print-zones-dn", action='store_true', help="Query and print the Distinguished Names of all zones on the DNS server")
    parser.add_argument("--tcp", action='store_true', help="use DNS over TCP")
    parser.add_argument('-k', '--kerberos', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-port', default=389, metavar="port", type=int, help='LDAP port, default value is 389')
    parser.add_argument('-force-ssl', action='store_true', default=False, help='Force SSL when connecting to LDAP server')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-dns-ip', action="store", metavar="ip address", help='IP Address of a DNS Server')
    parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    recordopts = parser.add_argument_group("Record options")
    recordopts.add_argument("-r", "--record", type=str, metavar='TARGETRECORD', help="Record to target (FQDN)")
    recordopts.add_argument("-a",
                        "--action",
                        choices=['add', 'modify', 'query', 'remove', 'resurrect', 'ldapdelete'],
                        default='query',
                        help="Action to perform. Options: add (add a new record), modify ("
                             "modify an existing record), query (show existing), remove (mark record "
                             "for cleanup from DNS cache), delete (delete from LDAP). Default: query"
                        )
    recordopts.add_argument("-t", "--type", choices=['A'], default='A', help="Record type to add (Currently only A records supported)")
    recordopts.add_argument("-d", "--data", metavar='RECORDDATA', help="Record data (IP address)")
    recordopts.add_argument("--allow-multiple", action='store_true', help="Allow multiple A records for the same name")
    recordopts.add_argument("--ttl", type=int, default=180, help="TTL for record (default: 180)")



    args = parser.parse_args()

    #Prompt for password if not set
    authentication = None
    if not args.user or not '\\' in args.user:
        print_f('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)
    domain, user = args.user.split('\\', 1)
    if not args.kerberos:
        authentication = NTLM
        sasl_mech = None
        if args.password is None:
            args.password = getpass.getpass()
    else:
        TGT = None
        TGS = None
        try:
            # Hashes
            lmhash, nthash = args.password.split(':')
            assert len(nthash) == 32
            password = ''
        except:
            # Password
            lmhash = ''
            nthash = ''
            password = args.password
        if 'KRB5CCNAME' in os.environ and os.path.exists(os.environ['KRB5CCNAME']):
            domain, user, TGT, TGS = CCache.parseFile(domain, user, 'ldap/%s' % args.host)
        if args.dc_ip is None:
            kdcHost = domain
        else:
            kdcHost = args.dc_ip
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if not TGT and not TGS:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, args.aesKey, kdcHost)
        elif TGT:
            # Has TGT
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']
        if not TGS:
            # Request TGS
            serverName = Principal('ldap/%s' % args.host, type=constants.PrincipalNameType.NT_SRV_INST.value)
            TGS = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
        else:
            # Convert to tuple expected
            TGS = (TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey'], TGS['sessionKey'])
        authentication = SASL
        sasl_mech = KERBEROS

    # define the server and the connection
    s = Server(args.host, port=args.port, use_ssl=args.force_ssl, get_info=ALL)
    print_m('Connecting to host...')
    c = Connection(s, user=args.user, password=args.password, authentication=authentication, sasl_mechanism=sasl_mech)
    print_m('Binding to host')
    # perform the Bind operation
    if authentication == NTLM:
        if not c.bind():
            print_f('Could not bind with specified credentials')
            print_f(c.result)
            sys.exit(1)
    else:
        ldap_kerberos(domain, kdcHost, None, userName, c, args.host, TGS)
    print_o('Bind OK')
    domainroot = s.info.other['defaultNamingContext'][0]
    forestroot = s.info.other['rootDomainNamingContext'][0]
    if args.forest:
        dnsroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % forestroot
    else:
        if args.legacy:
            dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % domainroot
        else:
            dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot

    if args.print_zones or args.print_zones_dn:
        if args.print_zones_dn:
            attr = "distinguishedName"
        else:
            attr = "dc"
        zones = get_dns_zones(c, dnsroot,attr)
        if len(zones) > 0:
            print_m('Found %d domain DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        forestdns = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % s.info.other['rootDomainNamingContext'][0]
        zones = get_dns_zones(c, forestdns,attr)
        if len(zones) > 0:
            print_m('Found %d forest DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        return

    
    target = args.record
    if args.zone:
        zone = args.zone
    else:
        # Default to current domain
        zone = ldap2domain(domainroot)

    if not target:
        print_f('You need to specify a target record')
        return

    if target.lower().endswith(zone.lower()):
        target = target[:-(len(zone)+1)]


    searchtarget = 'DC=%s,%s' % (zone, dnsroot)
    # print s.info.naming_contexts
    c.search(searchtarget, '(&(objectClass=dnsNode)(name=%s))' % ldap3.utils.conv.escape_filter_chars(target), attributes=['dnsRecord','dNSTombstoned','name'])
    targetentry = None
    for entry in c.response:
        if entry['type'] != 'searchResEntry':
            continue
        targetentry = entry

    # Check if we have the required data
    if args.action in ['add', 'modify', 'remove'] and not args.data:
        print_f('This operation requires you to specify record data with --data')
        return
    

    # Check if we need the target record to exists, and if yes if it does
    if args.action in ['modify', 'remove', 'ldapdelete', 'resurrect', 'query'] and not targetentry:
        print_f('Target record not found!')
        return


    if args.action == 'query':
        print_o('Found record %s' % targetentry['attributes']['name'])
        for record in targetentry['raw_attributes']['dnsRecord']:
            dr = DNS_RECORD(record)
            # dr.dump()
            print(targetentry['dn'])
            print_record(dr, targetentry['attributes']['dNSTombstoned'])
            continue
    elif args.action == 'add':
        # Only A records for now
        addtype = 1
        # Entry exists
        if targetentry:
            if not args.allow_multiple:
                for record in targetentry['raw_attributes']['dnsRecord']:
                    dr = DNS_RECORD(record)
                    if dr['Type'] == 1:
                        address = DNS_RPC_RECORD_A(dr['Data'])
                        print_f('Record already exists and points to %s. Use --action modify to overwrite or --allow-multiple to override this' % address.formatCanonical())
                        return False
            # If we are here, no A records exists yet
            record = new_record(addtype, get_next_serial(args.dns_ip, args.host, zone,args.tcp))
            record['Data'] = DNS_RPC_RECORD_A()
            record['Data'].fromCanonical(args.data)
            print_m('Adding extra record')
            c.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_ADD, record.getData())]})
            print_operation_result(c.result)
        else:
            node_data = {
                # Schema is in the root domain (take if from schemaNamingContext to be sure)
                'objectCategory': 'CN=Dns-Node,%s' % s.info.other['schemaNamingContext'][0],
                'dNSTombstoned': False,
                'name': target
            }
            record = new_record(addtype, get_next_serial(args.dns_ip, args.host, zone,args.tcp))
            record['Data'] = DNS_RPC_RECORD_A()
            record['Data'].fromCanonical(args.data)
            record_dn = 'DC=%s,%s' % (target, searchtarget)
            node_data['dnsRecord'] = [record.getData()]
            print_m('Adding new record')
            c.add(record_dn, ['top', 'dnsNode'], node_data)
            print_operation_result(c.result)
    elif args.action == 'modify':
        # Only A records for now
        addtype = 1
        # We already know the entry exists
        targetrecord = None
        records = []
        for record in targetentry['raw_attributes']['dnsRecord']:
            dr = DNS_RECORD(record)
            if dr['Type'] == 1:
                targetrecord = dr
            else:
                records.append(record)
        if not targetrecord:
            print_f('No A record exists yet. Use --action add to add it')
        targetrecord['Serial'] = get_next_serial(args.dns_ip, args.host, zone,args.tcp)
        targetrecord['Data'] = DNS_RPC_RECORD_A()
        targetrecord['Data'].fromCanonical(args.data)
        records.append(targetrecord.getData())
        print_m('Modifying record')
        c.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, records)]})
        print_operation_result(c.result)
    elif args.action == 'remove':
        addtype = 0
        if len(targetentry['raw_attributes']['dnsRecord']) > 1:
            print_m('Target has multiple records, removing the one specified')
            targetrecord = None
            for record in targetentry['raw_attributes']['dnsRecord']:
                dr = DNS_RECORD(record)
                if dr['Type'] == 1:
                    tr = DNS_RPC_RECORD_A(dr['Data'])
                    if tr.formatCanonical() == args.data:
                        targetrecord = record
            if not targetrecord:
                print_f('Could not find a record with the specified data')
                return
            c.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_DELETE, targetrecord)]})
            print_operation_result(c.result)
        else:
            print_m('Target has only one record, tombstoning it')
            diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
            tstime = int(diff.total_seconds()*10000)
            # Add a null record
            record = new_record(addtype, get_next_serial(args.dns_ip, args.host, zone,args.tcp))
            record['Data'] = DNS_RPC_RECORD_TS()
            record['Data']['entombedTime'] = tstime
            c.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],
                                         'dNSTombstoned': [(MODIFY_REPLACE, True)]})
            print_operation_result(c.result)
    elif args.action == 'ldapdelete':
        print_m('Deleting record over LDAP')
        c.delete(targetentry['dn'])
        print_operation_result(c.result)
    elif args.action == 'resurrect':
         addtype = 0
         if len(targetentry['raw_attributes']['dnsRecord']) > 1:
             print_m('Target has multiple records, I dont  know how to handle this.')
             return
         else:
             print_m('Target has only one record, resurrecting it')
             diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
             tstime = int(diff.total_seconds()*10000)
             # Add a null record
             record = new_record(addtype, get_next_serial(args.dns_ip, args.host, zone,args.tcp))
             record['Data'] = DNS_RPC_RECORD_TS()
             record['Data']['entombedTime'] = tstime
             c.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],
                                          'dNSTombstoned': [(MODIFY_REPLACE, False)]})
             print_o('Record resurrected. You will need to (re)add the record with the IP address.')

if __name__ == '__main__':
    main()
