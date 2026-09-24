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
#   Microsoft DNS Server (MS-DNSP) protocol structures and a high level
#   manager class to manage DNS records of Active Directory integrated
#   DNS zones via LDAP, using impacket's own LDAP connection (CRUD).
#
# Authors:
#   Hakan Yavuz (@lodos2005) - Impacket integration
#   Dirk-jan Mollema (@_dirkjan) - Original dnstool.py implementation
#
# References:
#   [MS-DNSP]: Domain Name System (DNS) Server Management Protocol
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/


import logging
import random
import re
import socket
import struct
import datetime
from struct import unpack

from impacket.structure import Structure
from impacket.ldap import ldapasn1
from impacket.ldap.ldap import LDAPSessionError, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

LOG = logging.getLogger(__name__)


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
        """Convert DNS_COUNT_NAME to FQDN string"""
        ind = 0
        labels = []
        for _i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind + 1])[0]
            labels.append(self['RawName'][ind + 1:ind + 1 + nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

    @classmethod
    def fromFqdn(cls, fqdn):
        """Create DNS_COUNT_NAME from FQDN string"""
        if fqdn.endswith('.'):
            fqdn = fqdn[:-1]

        if fqdn == '':
            # Root domain case
            dns_name = cls()
            dns_name['Length'] = 1
            dns_name['LabelCount'] = 0
            dns_name['RawName'] = b'\x00'
            return dns_name

        labels = fqdn.split('.')
        raw_name = b''

        for label in labels:
            label_bytes = label.encode('utf-8')
            raw_name += struct.pack('B', len(label_bytes)) + label_bytes

        raw_name += b'\x00'  # Root terminator

        dns_name = cls()
        dns_name['Length'] = len(raw_name)
        dns_name['LabelCount'] = len(labels)
        dns_name['RawName'] = raw_name

        return dns_name


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        """Convert binary IP address to string format"""
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        """Set IP address from string format"""
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
    DNS_RPC_RECORD_TS (Tombstone Record)
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )

    def toDatetime(self):
        """Convert Windows timestamp to datetime object"""
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)


# DNS Record Type Mapping
RECORD_TYPE_MAPPING = {
    0: 'ZERO',      # Tombstone/Zero record
    1: 'A',         # IPv4 address
    2: 'NS',        # Name server
    5: 'CNAME',     # Canonical name
    6: 'SOA',       # Start of authority
    33: 'SRV',      # Service record
    65281: 'WINS'   # WINS record
}

# Partitions supported by get_dns_root()
PARTITIONS = ('domain', 'forest', 'legacy')


def new_record(rtype, serial, ttl=180):
    """
    Create a new DNS_RECORD with specified type and serial

    Args:
        rtype (int): DNS record type (1 for A, 6 for SOA, etc.)
        serial (int): Serial number for the record
        ttl (int): Time to live in seconds (default: 180)

    Returns:
        DNS_RECORD: New DNS record structure
    """
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = ttl
    # From authoritative zone
    nr['Rank'] = 240
    return nr


def build_tombstone_record(serial):
    """
    Create a tombstone (Type 0) DNS_RECORD with the current time as entombedTime

    Args:
        serial (int): Serial number for the record

    Returns:
        DNS_RECORD: Tombstone record structure
    """
    record = new_record(0, serial)
    ts_data = DNS_RPC_RECORD_TS()
    diff = datetime.datetime.today() - datetime.datetime(1601, 1, 1)
    ts_data['entombedTime'] = int(diff.total_seconds() * 10000000)
    record['Data'] = ts_data
    return record


def build_a_record(address, serial, ttl=180):
    """
    Create an A (Type 1) DNS_RECORD pointing to the given IPv4 address

    Args:
        address (str): IPv4 address in dotted quad notation
        serial (int): Serial number for the record
        ttl (int): Time to live in seconds (default: 180)

    Returns:
        DNS_RECORD: A record structure
    """
    record = new_record(1, serial, ttl)
    data = DNS_RPC_RECORD_A()
    data.fromCanonical(address)
    record['Data'] = data
    return record


def format_record(record, ts=False):
    """
    Format DNS record information as human-readable lines

    Args:
        record (DNS_RECORD): The DNS record to format
        ts (bool): Whether the record is tombstoned

    Returns:
        list: Lines of text describing the record
    """
    lines = []
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'

    if ts:
        lines.append('Record is tombStoned (inactive)')

    lines.append('Record entry:')
    lines.append(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))

    if record['Type'] == 0:
        # Tombstone record
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        lines.append(' - Tombstoned at: %s' % tstime.toDatetime())
    elif record['Type'] == 1:
        # A record
        address = DNS_RPC_RECORD_A(record['Data'])
        lines.append(' - Address: %s' % address.formatCanonical())
    elif record['Type'] in (2, 5):
        # NS record or CNAME record
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        lines.append(' - Address: %s' % address['nameNode'].toFqdn())
    elif record['Type'] == 33:
        # SRV record
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        lines.append(' - Priority: %d' % record_data['wPriority'])
        lines.append(' - Weight: %d' % record_data['wWeight'])
        lines.append(' - Port: %d' % record_data['wPort'])
        lines.append(' - Name: %s' % record_data['nameTarget'].toFqdn())
    elif record['Type'] == 6:
        # SOA record
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        lines.append(' - Serial: %d' % record_data['dwSerialNo'])
        lines.append(' - Refresh: %d' % record_data['dwRefresh'])
        lines.append(' - Retry: %d' % record_data['dwRetry'])
        lines.append(' - Expire: %d' % record_data['dwExpire'])
        lines.append(' - Minimum TTL: %d' % record_data['dwMinimumTtl'])
        lines.append(' - Primary server: %s' % record_data['namePrimaryServer'].toFqdn())
        lines.append(' - Zone admin email: %s' % record_data['zoneAdminEmail'].toFqdn())
    return lines


def print_record(record, ts=False):
    """
    Print DNS record information in a human-readable format

    Args:
        record (DNS_RECORD): The DNS record to print
        ts (bool): Whether the record is tombstoned
    """
    for line in format_record(record, ts):
        print(line)


def ldap2domain(ldap_dn):
    """
    Convert LDAP DN to domain name

    Args:
        ldap_dn (str): LDAP Distinguished Name

    Returns:
        str: Domain name in FQDN format
    """
    return re.sub(r',DC=', '.', ldap_dn[ldap_dn.find('DC='):], flags=re.I)[3:]


def escape_filter_chars(value):
    """
    Escape characters that are special in an LDAP filter (RFC 4515)

    Args:
        value (str): Value to escape

    Returns:
        str: Escaped value, safe to embed in a filter
    """
    value = value.replace('\\', '\\5c')
    for char, escaped in (('\x00', '\\00'), ('*', '\\2a'), ('(', '\\28'), (')', '\\29')):
        value = value.replace(char, escaped)
    return value


def _skip_compressed_name(data, offset):
    """
    Skip a possibly compressed DNS name in a raw DNS message

    Args:
        data (bytes): Raw DNS message
        offset (int): Offset of the name within the message

    Returns:
        int: Offset just past the name
    """
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            # Compression pointer, always the last element
            return offset + 2
        if length == 0:
            # Terminating root label
            return offset + 1
        offset += length + 1


def query_soa_serial(zone, server, timeout=3):
    """
    Query the current SOA serial of a zone with a raw DNS query (no external
    dependencies). A new record should use serial + 1 for its data to
    replicate properly.

    Args:
        zone (str): DNS zone to query (e.g. 'domain.local')
        server (str): DNS server, hostname or IP
        timeout (int): Socket timeout in seconds

    Returns:
        int: The current SOA serial, or None if it could not be determined
    """
    try:
        try:
            socket.inet_aton(server)
        except OSError:
            server = socket.gethostbyname(server)

        qname = b''.join(struct.pack('B', len(label)) + label.encode('utf-8')
                         for label in zone.rstrip('.').split('.')) + b'\x00'
        # Standard query, recursion desired, one question of type SOA (6), class IN (1)
        query = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) + qname + struct.pack('>HH', 6, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        flags, qdcount, ancount = struct.unpack('>HHH', data[2:8])
        if not flags & 0x8000 or ancount == 0:
            return None

        offset = _skip_compressed_name(data, 12) + 4  # Skip question name, qtype and qclass
        offset = _skip_compressed_name(data, offset)   # Answer name
        rtype, _rclass, _ttl, _rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        if rtype != 6:
            return None
        offset = _skip_compressed_name(data, offset)   # MNAME
        offset = _skip_compressed_name(data, offset)   # RNAME
        return struct.unpack('>I', data[offset:offset + 4])[0]
    except Exception as e:
        LOG.debug('SOA serial query for %s on %s failed: %s' % (zone, server, e))
        return None


class ADIDNSManager:
    """
    Manage DNS records of Active Directory integrated DNS zones over LDAP,
    using impacket's LDAPConnection (which supports the full CRUD operations).

    All methods return data / True on success and None / False on failure.
    A human readable reason for the last failure is stored in ``last_error``.
    """

    def __init__(self, ldap_connection, dns_server=None, dns_timeout=3,
                 domain_root=None, forest_root=None, schema_root=None):
        """
        Args:
            ldap_connection (LDAPConnection): Authenticated impacket LDAP connection
            dns_server (str): DNS server used for SOA serial queries (hostname or IP).
                If None, record serials fall back to the current timestamp.
            dns_timeout (int): Timeout for SOA serial queries in seconds (default: 3)
            domain_root (str): defaultNamingContext, queried from rootDSE if omitted
            forest_root (str): rootDomainNamingContext, queried from rootDSE if omitted
            schema_root (str): schemaNamingContext, queried from rootDSE if omitted
        """
        self.ldap_connection = ldap_connection
        self.dns_server = dns_server
        self.dns_timeout = dns_timeout
        self.last_error = None

        if domain_root is None or forest_root is None or schema_root is None:
            attributes = []
            if domain_root is None:
                attributes.append('defaultNamingContext')
            if forest_root is None:
                attributes.append('rootDomainNamingContext')
            if schema_root is None:
                attributes.append('schemaNamingContext')

            rootdse = self._search(
                search_base='',
                search_filter='(objectClass=*)',
                attributes=attributes,
                scope=ldapasn1.Scope('baseObject'),
            )
            if not rootdse:
                raise LDAPSessionError(errorString='Could not read rootDSE attributes from the LDAP server')
            attributes = rootdse[0]['attributes']

        self.domain_root = domain_root or self._decode(attributes.get('defaultNamingContext', [b''])[0])
        self.forest_root = forest_root or self._decode(attributes.get('rootDomainNamingContext', [b''])[0])
        self.schema_root = schema_root or self._decode(attributes.get('schemaNamingContext', [b''])[0])
        self.domain = ldap2domain(self.domain_root)

    def _search(self, search_base, search_filter, attributes, scope=None):
        """Run an LDAP search and return a list of {'dn': str, 'attributes': {name: [bytes]}} dicts"""
        try:
            response = self.ldap_connection.search(
                searchBase=search_base,
                searchFilter=search_filter,
                attributes=attributes,
                scope=scope,
            )
        except LDAPSessionError as e:
            self.last_error = str(e)
            return []

        entries = []
        for entry in response:
            if not isinstance(entry, ldapasn1.SearchResultEntry):
                continue
            entry_attributes = {}
            for attribute in entry['attributes']:
                entry_attributes[str(attribute['type'])] = [val.asOctets() for val in attribute['vals']]
            entries.append({'dn': str(entry['objectName']), 'attributes': entry_attributes})
        return entries

    @staticmethod
    def _decode(value):
        """Decode an LDAP attribute value to a string if possible"""
        return value.decode('utf-8') if isinstance(value, bytes) else str(value)

    def get_dns_root(self, partition='domain'):
        """
        Get the DN of the DNS container for the requested partition

        Args:
            partition (str): 'domain' (DomainDnsZones), 'forest' (ForestDnsZones) or 'legacy' (CN=System)

        Returns:
            str: Distinguished Name of the MicrosoftDNS container
        """
        if partition == 'forest':
            return f'CN=MicrosoftDNS,DC=ForestDnsZones,{self.forest_root}'
        if partition == 'legacy':
            return f'CN=MicrosoftDNS,CN=System,{self.domain_root}'
        return f'CN=MicrosoftDNS,DC=DomainDnsZones,{self.domain_root}'

    def get_dns_zones(self, partition='domain', return_dn=False):
        """
        List DNS zones in the requested partition

        Args:
            partition (str): 'domain', 'forest' or 'legacy'
            return_dn (bool): Return the zones' Distinguished Names instead of their names

        Returns:
            list: Zone names (or DNs), empty on failure
        """
        attribute = 'distinguishedName' if return_dn else 'dc'
        entries = self._search(
            search_base=self.get_dns_root(partition),
            search_filter='(objectClass=dnsZone)',
            attributes=[attribute],
            scope=ldapasn1.Scope('singleLevel'),
        )
        return [self._decode(entry['attributes'].get(attribute, [b''])[0]) for entry in entries]

    def get_next_serial(self, zone=None):
        """
        Get the serial number a new record in the zone should use

        Queries the zone's current SOA serial via DNS and increments it. Falls
        back to the current timestamp if the query fails or no DNS server is set.

        Args:
            zone (str): Zone to query, defaults to the domain of the LDAP connection

        Returns:
            int: Serial number for a new record
        """
        if not zone:
            zone = self.domain
        if self.dns_server:
            serial = query_soa_serial(zone, self.dns_server, timeout=self.dns_timeout)
            if serial is not None:
                return serial + 1
        return int(datetime.datetime.now().timestamp())

    def _zone_and_target(self, record_name, zone):
        """Normalize the zone and strip the zone suffix from a record name"""
        if not zone:
            zone = self.domain
        target = record_name
        if target.lower().endswith(zone.lower()):
            target = target[:-(len(zone) + 1)]
        return zone, target

    def find_record(self, record_name, zone=None, partition='domain'):
        """
        Find a dnsNode object by record name

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            zone (str): Zone to search in, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'

        Returns:
            dict: {'dn', 'name', 'tombstoned', 'records': [bytes]} or None if not found
        """
        zone, target = self._zone_and_target(record_name, zone)
        search_target = f'DC={zone},{self.get_dns_root(partition)}'

        entries = self._search(
            search_base=search_target,
            search_filter=f'(&(objectClass=dnsNode)(name={escape_filter_chars(target)}))',
            attributes=['dnsRecord', 'dNSTombstoned', 'name'],
        )
        if not entries:
            return None

        attributes = entries[0]['attributes']
        return {
            'dn': entries[0]['dn'],
            'name': self._decode(attributes.get('name', [target.encode()])[0]),
            'tombstoned': any(self._decode(v).upper() == 'TRUE' for v in attributes.get('dNSTombstoned', [])),
            'records': attributes.get('dnsRecord', []),
        }

    def query_record(self, record_name, zone=None, partition='domain'):
        """
        Query a DNS record and return it parsed

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            zone (str): Zone to search in, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'

        Returns:
            dict: {'dn', 'name', 'tombstoned', 'records': [DNS_RECORD]} or None if not found
        """
        entry = self.find_record(record_name, zone, partition)
        if entry is None:
            self.last_error = 'Target record not found!'
            return None
        entry['records'] = [DNS_RECORD(data) for data in entry['records']]
        return entry

    def add_record(self, record_name, record_data, rtype='A', zone=None, partition='domain',
                   allow_multiple=False, ttl=180):
        """
        Add a DNS record. If the dnsNode already exists the record is appended
        to its dnsRecord attribute, otherwise a new dnsNode object is created.

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            record_data (str): Record data (IPv4 address for A records)
            rtype (str): Record type, only 'A' is currently supported
            zone (str): Zone to add the record in, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'
            allow_multiple (bool): Allow adding the record even if another A record exists
            ttl (int): Time to live in seconds

        Returns:
            bool: True on success, False otherwise (see last_error)
        """
        if rtype.upper() != 'A':
            self.last_error = f'Record type {rtype} is not supported yet, only A records'
            return False

        zone, target = self._zone_and_target(record_name, zone)
        search_target = f'DC={zone},{self.get_dns_root(partition)}'
        entry = self.find_record(record_name, zone, partition)

        record = build_a_record(record_data, self.get_next_serial(zone), ttl)

        try:
            if entry is not None:
                if not allow_multiple:
                    for data in entry['records']:
                        existing = DNS_RECORD(data)
                        if existing['Type'] == 1:
                            address = DNS_RPC_RECORD_A(existing['Data'])
                            self.last_error = (
                                f'Record already exists and points to {address.formatCanonical()}. '
                                'Use modify_record to overwrite or allow_multiple to override this'
                            )
                            return False

                self.ldap_connection.modify(entry['dn'], {'dnsRecord': [(MODIFY_ADD, record.getData())]})
            else:
                node_dn = f'DC={target},{search_target}'
                self.ldap_connection.add(node_dn, ['top', 'dnsNode'], {
                    'objectCategory': f'CN=Dns-Node,{self.schema_root}',
                    'dNSTombstoned': b'FALSE',
                    'name': target,
                    'dnsRecord': record.getData(),
                })
            return True
        except LDAPSessionError as e:
            self.last_error = str(e)
            return False

    def modify_record(self, record_name, record_data, zone=None, partition='domain', ttl=180):
        """
        Modify the A record of an existing dnsNode, keeping any other records intact

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            record_data (str): New IPv4 address
            zone (str): Zone of the record, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'
            ttl (int): Time to live in seconds

        Returns:
            bool: True on success, False otherwise (see last_error)
        """
        zone, _target = self._zone_and_target(record_name, zone)
        entry = self.find_record(record_name, zone, partition)
        if entry is None:
            self.last_error = 'Target record not found!'
            return False

        records = []
        modified = False
        for data in entry['records']:
            existing = DNS_RECORD(data)
            if existing['Type'] == 1 and not modified:
                record = build_a_record(record_data, self.get_next_serial(zone), ttl)
                records.append(record.getData())
                modified = True
            else:
                records.append(data)

        if not modified:
            self.last_error = 'No A record exists yet. Use add_record to add it'
            return False

        try:
            self.ldap_connection.modify(entry['dn'], {'dnsRecord': [(MODIFY_REPLACE, records)]})
            return True
        except LDAPSessionError as e:
            self.last_error = str(e)
            return False

    def remove_record(self, record_name, zone=None, partition='domain', record_data=None):
        """
        Remove a DNS record. Nodes with a single record are tombstoned as
        required by AD integrated DNS, on nodes with multiple records only the
        record matching record_data is removed.

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            zone (str): Zone of the record, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'
            record_data (str): IPv4 address of the record to remove on multi-record nodes

        Returns:
            bool: True on success, False otherwise (see last_error)
        """
        zone, _target = self._zone_and_target(record_name, zone)
        entry = self.find_record(record_name, zone, partition)
        if entry is None:
            self.last_error = 'Target record not found!'
            return False

        node_dn = entry['dn']

        try:
            if len(entry['records']) > 1:
                target_data = None
                for data in entry['records']:
                    existing = DNS_RECORD(data)
                    if existing['Type'] == 1:
                        address = DNS_RPC_RECORD_A(existing['Data'])
                        if record_data and address.formatCanonical() == record_data:
                            target_data = data
                            break
                if target_data is None:
                    self.last_error = 'Could not find a record with the specified data'
                    return False
                self.ldap_connection.modify(node_dn, {'dnsRecord': [(MODIFY_DELETE, target_data)]})
            else:
                tombstone = build_tombstone_record(self.get_next_serial(zone))
                self.ldap_connection.modify(node_dn, {
                    'dnsRecord': [(MODIFY_REPLACE, tombstone.getData())],
                    'dNSTombstoned': [(MODIFY_REPLACE, b'TRUE')],
                })
            return True
        except LDAPSessionError as e:
            self.last_error = str(e)
            return False

    def ldap_delete(self, record_name, zone=None, partition='domain'):
        """
        Delete the dnsNode object of a record directly over LDAP, bypassing
        the tombstone workflow

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            zone (str): Zone of the record, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'

        Returns:
            bool: True on success, False otherwise (see last_error)
        """
        zone, _target = self._zone_and_target(record_name, zone)
        entry = self.find_record(record_name, zone, partition)
        if entry is None:
            self.last_error = 'Target record not found!'
            return False

        try:
            self.ldap_connection.delete(entry['dn'])
            return True
        except LDAPSessionError as e:
            self.last_error = str(e)
            return False

    def resurrect_record(self, record_name, zone=None, partition='domain'):
        """
        Resurrect a tombstoned record by clearing its dNSTombstoned attribute.
        The record data itself is not restored, it has to be added again.

        Args:
            record_name (str): Record name, FQDN or relative to the zone
            zone (str): Zone of the record, defaults to the current domain
            partition (str): 'domain', 'forest' or 'legacy'

        Returns:
            bool: True on success, False otherwise (see last_error)
        """
        zone, _target = self._zone_and_target(record_name, zone)
        entry = self.find_record(record_name, zone, partition)
        if entry is None:
            self.last_error = 'Target record not found!'
            return False

        if len(entry['records']) > 1:
            self.last_error = 'Target has multiple records, I dont know how to handle this.'
            return False

        tombstone = build_tombstone_record(self.get_next_serial(zone))
        try:
            self.ldap_connection.modify(entry['dn'], {
                'dnsRecord': [(MODIFY_REPLACE, tombstone.getData())],
                'dNSTombstoned': [(MODIFY_REPLACE, b'FALSE')],
            })
            return True
        except LDAPSessionError as e:
            self.last_error = str(e)
            return False
