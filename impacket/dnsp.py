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
#   Microsoft DNS Server (MS-DNSP) protocol structures
#   Used for manipulating DNS records via LDAP in Active Directory integrated DNS
#
# Authors:
#   Hakan Yavuz (@lodos2005) - Impacket integration
#   Dirk-jan Mollema (@_dirkjan) - Original dnstool.py implementation
#
# References:
#   [MS-DNSP]: Domain Name System (DNS) Server Management Protocol
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/


import socket
import struct
import datetime
from struct import unpack

from impacket.structure import Structure


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
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
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


def print_record(record, ts=False):
    """
    Print DNS record information in a human-readable format
    
    Args:
        record (DNS_RECORD): The DNS record to print
        ts (bool): Whether the record is tombstoned
    """
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'
    
    if ts:
        print('Record is tombStoned (inactive)')
    
    print('[+] Record entry:')
    print(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))
    
    if record['Type'] == 0:
        # Tombstone record
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        print(' - Tombstoned at: %s' % tstime.toDatetime())
    elif record['Type'] == 1:
        # A record
        address = DNS_RPC_RECORD_A(record['Data'])
        print(' - Address: %s' % address.formatCanonical())
    elif record['Type'] == 2 or record['Type'] == 5:
        # NS record or CNAME record
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        print(' - Address: %s' % address['nameNode'].toFqdn())
    elif record['Type'] == 33:
        # SRV record
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        print(' - Priority: %d' % record_data['wPriority'])
        print(' - Weight: %d' % record_data['wWeight'])
        print(' - Port: %d' % record_data['wPort'])
        print(' - Name: %s' % record_data['nameTarget'].toFqdn())
    elif record['Type'] == 6:
        # SOA record
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        print(' - Serial: %d' % record_data['dwSerialNo'])
        print(' - Refresh: %d' % record_data['dwRefresh'])
        print(' - Retry: %d' % record_data['dwRetry'])
        print(' - Expire: %d' % record_data['dwExpire'])
        print(' - Minimum TTL: %d' % record_data['dwMinimumTtl'])
        print(' - Primary server: %s' % record_data['namePrimaryServer'].toFqdn())
        print(' - Zone admin email: %s' % record_data['zoneAdminEmail'].toFqdn())


def ldap2domain(ldap_dn):
    """
    Convert LDAP DN to domain name
    
    Args:
        ldap_dn (str): LDAP Distinguished Name
    
    Returns:
        str: Domain name in FQDN format
    """
    import re
    return re.sub(',DC=', '.', ldap_dn[ldap_dn.find('DC='):], flags=re.I)[3:] 
