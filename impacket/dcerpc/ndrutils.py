# Copyright (c) 2003-2011 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#

from struct import *
import socket
import random
from impacket import uuid

def uuid_hex(_uuid):
    for i in range(0,len(_uuid)):
        print "\\0x%.2x"%unpack('<B',_uuid[i]),
    print ""

KNOWN_UUIDS = { '\xb9\x99\x3f\x87\x4d\x1b\x10\x99\xb7\xaa\x00\x04\x00\x7f\x07\x01\x00\x00': 'ssmsrp70.dll',
                '\x90\x2c\xfe\x98\x42\xa5\xd0\x11\xa4\xef\x00\xa0\xc9\x06\x29\x10\x01\x00':'advapi32.dll',
                '\x44\xaf\x7d\x8c\xdc\xb6\xd1\x11\x9a\x4c\x00\x20\xaf\x6e\x7c\x57\x01\x00':'appmgmts.dll',
                '\xc0\xeb\x4f\xfa\x91\x45\xce\x11\x95\xe5\x00\xaa\x00\x51\xe5\x10\x04\x00':'autmgr32.exe',
                '\xe0\x42\xc7\x4f\x10\x4a\xcf\x11\x82\x73\x00\xaa\x00\x4a\xe6\x73\x03\x00':'dfssvc.exe',
                '\x98\xd0\xff\x6b\x12\xa1\x10\x36\x98\x33\x46\xc3\xf8\x74\x53\x2d\x01\x00':'DHCPSSVC.DLL',
                '\x20\x17\x82\x5b\x3b\xf6\xd0\x11\xaa\xd2\x00\xc0\x4f\xc3\x24\xdb\x01\x00':'DHCPSSVC.DLL',
                '\xfa\x9d\xd7\xd2\x00\x34\xd0\x11\xb4\x0b\x00\xaa\x00\x5f\xf5\x86\x01\x00':'dmadmin.exe',
                '\xa4\xc2\xab\x50\x4d\x57\xb3\x40\x9d\x66\xee\x4f\xd5\xfb\xa0\x76\x05\x00':'dns.exe',
                '\x90\x38\xa9\x65\xb9\xfa\xa3\x43\xb2\xa5\x1e\x33\x0a\xc2\x8f\x11\x02\x00':'dnsrslvr.dll',
                '\x65\x31\x0a\xea\x34\x48\xd2\x11\xa6\xf8\x00\xc0\x4f\xa3\x46\xcc\x04\x00':'faxsvc.exe',
                '\x64\x1d\x82\x0c\xfc\xa3\xd1\x11\xbb\x7a\x00\x80\xc7\x5e\x4e\xc1\x01\x00':'irftp.exe',
                '\xd0\xbb\xf5\x7a\x63\x60\xd1\x11\xae\x2a\x00\x80\xc7\x5e\x4e\xc1\x00\x00':'irmon.dll',
                '\x40\xb2\x9b\x20\x19\xb9\xd1\x11\xbb\xb6\x00\x80\xc7\x5e\x4e\xc1\x01\x00':'irmon.dll',
                '\xfb\xee\x0c\x13\x66\xe4\xd1\x11\xb7\x8b\x00\xc0\x4f\xa3\x28\x83\x02\x00':'ismip.dll',
                '\x86\xd4\xdc\x68\x9e\x66\xd1\x11\xab\x0c\x00\xc0\x4f\xc2\xdc\xd2\x01\x00':'ismserv.exe',
                '\x40\xfd\x2c\x34\x6c\x3c\xce\x11\xa8\x93\x08\x00\x2b\x2e\x9c\x6d\x00\x00':'llssrv.exe',
                '\xd0\x4c\x67\x57\x00\x52\xce\x11\xa8\x97\x08\x00\x2b\x2e\x9c\x6d\x01\x00':'llssrv.exe',
                '\xc4\x0c\x3c\xe3\x82\x04\x1a\x10\xbc\x0c\x02\x60\x8c\x6b\xa2\x18\x01\x00':'locator.exe',
                '\xf0\x0e\xd7\xd6\x3b\x0e\xcb\x11\xac\xc3\x08\x00\x2b\x1d\x29\xc3\x01\x00':'locator.exe',
                '\x14\xb5\xfb\xd3\x3b\x0e\xcb\x11\x8f\xad\x08\x00\x2b\x1d\x29\xc3\x01\x00':'locator.exe',
                '\xf0\x0e\xd7\xd6\x3b\x0e\xcb\x11\xac\xc3\x08\x00\x2b\x1d\x29\xc4\x01\x00':'locator.exe',
                '\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab\x00\x00':'lsasrv.dll',
                '\x88\xd4\x81\xc6\x50\xd8\xd0\x11\x8c\x52\x00\xc0\x4f\xd9\x0f\x7e\x01\x00':'lsasrv.dll',
                '\xf0\x09\x8f\xed\xb7\xce\x11\xbb\xd2\x00\x00\x1a\x18\x1c\xad\x00\x00\x00':'mprdim.dll',
                '\xe0\xca\x02\xec\xe0\xb9\xd2\x11\xbe\x62\x00\x20\xaf\xed\xdf\x63\x01\x00':'mq1repl.dll',
                '\x80\x7a\xdf\x77\x98\xf2\xd0\x11\x83\x58\x00\xa0\x24\xc4\x80\xa8\x01\x00':'mdqssrv.dll',
                '\x10\xca\x8c\x70\x69\x95\xd1\x11\xb2\xa5\x00\x60\x97\x7d\x81\x18\x01\x00':'mqdssrv.dll',
                '\x80\x35\x5b\x5b\xe0\xb0\xd1\x11\xb9\x2d\x00\x60\x08\x1e\x87\xf0\x01\x00':'mqqm.dll',
                '\xe0\x8e\x20\x41\x70\xe9\xd1\x11\x9b\x9e\x00\xe0\x2c\x06\x4c\x39\x01\x00':'mqqm.dll',
                '\x80\xa9\x88\x10\xe5\xea\xd0\x11\x8d\x9b\x00\xa0\x24\x53\xc3\x37\x01\x00':'mqqm.dll',
                '\xe0\x0c\x6b\x90\x0b\xc7\x67\x10\xb3\x17\x00\xdd\x01\x06\x62\xda\x01\x00':'msdtcprx.dll',
                '\xf8\x91\x7b\x5a\x00\xff\xd0\x11\xa9\xb2\x00\xc0\x4f\xb6\x36\xfc\x01\x00':'msgsvc.dll',
                '\x82\x06\xf7\x1f\x51\x0a\xe8\x30\x07\x6d\x74\x0b\xe8\xce\xe9\x8b\x01\x00':'mstask.exe',
                '\xb0\x52\x8e\x37\xa9\xc0\xcf\x11\x82\x2d\x00\xaa\x00\x51\xe4\x0f\x01\x00':'mstask.exe',
                '\x20\x32\x5f\x2f\x26\xc1\x76\x10\xb5\x49\x07\x4d\x07\x86\x19\xda\x01\x00':'netdde.exe',
                '\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\xcf\xfb\x01\x00':'netlogon.dll',
                '\x18\x5a\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x38\x00':'ntdsa.dll',
                '\x7c\x5a\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x15\x00':'ntdsa.dll',
                '\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2\x04\x00':'ntdsa.dll',
                '\x70\x0d\xec\xec\x03\xa6\xd0\x11\x96\xb1\x00\xa0\xc9\x1e\xce\x30\x01\x00':'ntdsbsrv.dll',
                '\x3a\xcf\xe0\x16\x04\xa6\xd0\x11\x96\xb1\x00\xa0\xc9\x1e\xce\x30\x01\x00':'ntdsbsrv.dll',
                '\xb4\x59\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x01\x00':'ntfrs.exe',
                '\x86\xb1\x49\xd0\x4f\x81\xd1\x11\x9a\x3c\x00\xc0\x4f\xc9\xb2\x32\x01\x00':'ntfrs.exe',
                '\x1c\x02\x0c\xa0\xe2\x2b\xd2\x11\xb6\x78\x00\x00\xf8\x7a\x8f\x8e\x01\x00':'ntfrs.exe',
                '\xa0\x9e\xc0\x69\x09\x4a\x1b\x10\xae\x4b\x08\x00\x2b\x34\x9a\x02\x00\x00':'ole32.dll',
                '\x50\x38\xcd\x15\xca\x28\xce\x11\xa4\xe8\x00\xaa\x00\x61\x16\xcb\x01\x00':'pgpsdkserv.exe',
                '\xf6\xb8\x35\xd3\x31\xcb\xd0\x11\xb0\xf9\x00\x60\x97\xba\x4e\x54\x01\x00':'polagent.dll',
                '\xf0\xe4\x9c\x36\xdc\x0f\xd3\x11\xbd\xe8\x00\xc0\x4f\x8e\xee\x78\x01\x00':'profmap.dll',
                '\x36\x00\x61\x20\x22\xfa\xcf\x11\x98\x23\x00\xa0\xc9\x11\xe5\xdf\x01\x00':'rasmans.dll',
                '\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03\x01\x00':'regsvc.exe',
                '\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00':'rpcss.dll',
                '\x84\x65\x0a\x0b\x0f\x9e\xcf\x11\xa3\xcf\x00\x80\x5f\x68\xcb\x1b\x01\x00':'rpcss.dll',
                '\xb0\x01\x52\x97\xca\x59\xd0\x11\xa8\xd5\x00\xa0\xc9\x0d\x80\x51\x01\x00':'rpcss.dll',
                '\xe6\x73\x0c\xe6\xf9\x88\xcf\x11\x9a\xf1\x00\x20\xaf\x6e\x72\xf4\x02\x00':'rpcss.dll',
                '\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00':'rpcss.dll',
                '\x1e\x24\x2f\x41\x2a\xc1\xce\x11\xab\xff\x00\x20\xaf\x6e\x7a\x17\x00\x00':'rpcss.dll',
                '\x36\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00':'rpcss.dll',
                '\x72\xee\xf3\xc6\x7e\xce\xd1\x11\xb7\x1e\x00\xc0\x4f\xc3\x11\x1a\x01\x00':'rpcss.dll',
                '\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57\x00\x00':'rpcss.dll',
                '\xa0\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00':'rpcss.dll',
                '\x60\x9e\xe7\xb9\x52\x3d\xce\x11\xaa\xa1\x00\x00\x69\x01\x29\x3f\x00\x00':'rpcss.dll',
                '\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xac\x01\x00':'samsrv.dll',
                '\xa2\x9c\x14\x93\x3b\x97\xd1\x11\x8c\x39\x00\xc0\x4f\xb9\x84\xf9\x00\x00':'scesrv.dll',
                '\x24\xe4\xfb\x63\x29\x20\xd1\x11\x8d\xb8\x00\xaa\x00\x4a\xbd\x5e\x01\x00':'sens.dll',
                '\x66\x9f\x9b\x62\x6c\x55\xd1\x11\x8d\xd2\x00\xaa\x00\x4a\xbd\x5e\x02\x00':'sens.dll',
                '\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03\x02\x00':'services.exe',
                '\x7c\xda\x83\x4f\xe8\xd2\x11\x98\x07\x00\xc0\x4f\x8e\xc8\x50\x02\x00\x00':'sfc.dll',
                '\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x00\x00':'sfmsvc.exe',
                '\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab\x01\x00':'spoolsv.exe',
                '\xe0\x6d\x7a\x8c\x8d\x78\xd0\x11\x9e\xdf\x44\x45\x53\x54\x00\x00\x02\x00':'stisvc.exe',
                '\x20\x65\x5f\x2f\x46\xca\x67\x10\xb3\x19\x00\xdd\x01\x06\x62\xda\x01\x00':'tapisrv.dll',
                '\x60\xa7\xa4\x5c\xb1\xeb\xcf\x11\x86\x11\x00\xa0\x24\x54\x20\xed\x01\x00':'termsrv.exe',
                '\x22\xc4\xa1\x4d\x3d\x94\xd1\x11\xac\xae\x00\xc0\x4f\xc2\xaa\x3f\x01\x00':'trksvr.dll',
                '\x32\x35\x0f\x30\xcc\x38\xd0\x11\xa3\xf0\x00\x20\xaf\x6b\x0a\xdd\x01\x00':'trkwks.dll',
                '\x12\xfc\x99\x60\xff\x3e\xd0\x11\xab\xd0\x00\xc0\x4f\xd9\x1a\x4e\x03\x00':'winfax.dll',
                '\xc0\xe0\x4d\x89\x55\x0d\xd3\x11\xa3\x22\x00\xc0\x4f\xa3\x21\xa1\x01\x00':'winlogon.exe',
                '\x28\x2c\xf5\x45\x9f\x7f\x1a\x10\xb5\x2b\x08\x00\x2b\x2e\xfa\xbe\x01\x00':'wins.exe',
                '\xbf\x09\x11\x81\xe1\xa4\xd1\x11\xab\x54\x00\xa0\xc9\x1e\x9b\x45\x01\x00':'wins.exe',
                '\xa0\xb3\x02\xa0\xb7\xc9\xd1\x11\xae\x88\x00\x80\xc7\x5e\x4e\xc1\x01\x00':'wlnotify.dll',
                '\xd1\x51\xa9\xbf\x0e\x2f\xd3\x11\xbf\xd1\x00\xc0\x4f\xa3\x49\x0a\x01\x00':'aqueue.dll',
                '\x80\x42\xad\x82\x6b\x03\xcf\x11\x97\x2c\x00\xaa\x00\x68\x87\xb0\x02\x00':'infocomm.dll',
                '\x70\x5d\xfb\x8c\xa4\x31\xcf\x11\xa7\xd8\x00\x80\x5f\x48\xa1\x35\x03\x00':'smtpsvc.dll',
                '\x80\x42\xad\x82\x6b\x03\xcf\x11\x97\x2c\x00\xaa\x00\x68\x87\xb0\x02\x00':'infoadmn.dll',
                '\x00\xb9\x99\x3f\x87\x4d\x1b\x10\x99\xb7\xaa\x00\x04\x00\x7f\x07\x01\x00':'ssmsrpc.dll - Microsoft SQL Server',
                '\x60\xf4\x82\x4f\x21\x0e\xcf\x11\x90\x9e\x00\x80\x5f\x48\xa1\x35\x04\x00':'nntpsvc.dll',
                '\xc0\x47\xdf\xb3\x5a\xa9\xcf\x11\xaa\x26\x00\xaa\x00\xc1\x48\xb9\x09\x00':'mspadmin.exe - Microsoft ISA Server',
                '\x1f\xa7\x37\x21\x5e\xbb\x29\x4e\x8e\x7e\x2e\x46\xa6\x68\x1d\xbf\x09\x00':'wspsrv.exe - Microsoft ISA Server',
                '\xf8\x91\x7b\x5a\x00\xff\xd0\x11\xa9\xb2\x00\xc0\x4f\xb6\xe6\xfc\x01\x00':'msgsvc.dll'
    }

def uuid_to_exe(_uuid):
    if KNOWN_UUIDS.has_key(_uuid):
        return KNOWN_UUIDS[_uuid]
    else:
        return 'unknown'

#Protocol ids, reference: http://www.opengroup.org/onlinepubs/9629399/apdxi.htm
class NDRFloor:
    PROTO_ID = { 0x0: 'OSI OID',
                 0x2: 'UUID',
                 0x5: 'OSI TP4',
                 0x6: 'OSI CLNS or DNA Routing',
                 0x7: 'DOD TCP',
                 0x8: 'DOD UDP',
                 0x9: 'DOD IP',
                 0xa: 'RPC connectionless protocol',
                 0xb: 'RPC connection-oriented protocol',
                 0xd: 'UUID',
                 0x2: 'DNA Session Control',
                 0x3: 'DNA Session Control V3',
                 0x4: 'DNA NSP Transport',
                 0x0d: 'Netware SPX', 
                 0x0e: 'Netware IPX', #someone read hexa as decimal? (0xe=0x14 in opengroup's list)
                 0x0f: 'Named Pipes',
                 0x10: 'Named Pipes',
                 0x11: 'NetBIOS',
                 0x12: 'NetBEUI',
                 0x13: 'Netware SPX',
                 0x14: 'Netware IPX',
                 0x16: 'Appletalk Stream',
                 0x17: 'Appletalk Datagram',
                 0x18: 'Appletalk',
                 0x19: 'NetBIOS',
                 0x1a: 'Vines SPP',
                 0x1b: 'Vines IPC',
                 0x1c: 'StreeTalk',
                 0x20: 'Unix Domain Socket',
                 0x21: 'null',
                 0x22: 'NetBIOS'}
                 
    def __init__(self,data=''):
        self._lhs_len = 0
        self._protocol = 0
        self._uuid = ''
        self._rhs_len = 0
        self._rhs = ''
        self._floor_len = 0
        if data:
            self._lhs_len, self._protocol = unpack('<HB',data[:3])
            offset = 3
            if self._protocol == 0x0d: # UUID
                self._uuid = data[offset:offset+self._lhs_len-1]
                offset += self._lhs_len-1
            self._rhs_len = unpack('<H',data[offset:offset+2])[0]
            offset += 2
            self._rhs = data[offset:offset+self._rhs_len]
            self._floor_len = offset + self._rhs_len
                                               
    def get_floor_len(self):
        return self._floor_len
    def get_protocol(self):
        return self._protocol
    def get_rhs(self):
        return self._rhs
    def get_rhs_len(self):
        return self._rhs_len
    def get_uuid(self):
        return self._uuid
    def get_protocol_string(self):
        if NDRFloor.PROTO_ID.has_key(self._protocol):
            return NDRFloor.PROTO_ID[self._protocol]
        else:
            return 'unknown'
    def get_uuid_string(self):
        if len(self._uuid) == 18:
            version = unpack('<H',self._uuid[16:18])[0]
            return "%s version: %d" % (parse_uuid(self._uuid), version)
        else:
            return ''

def parse_uuid(_uuid):
    return uuid.bin_to_string(_uuid)

class NDRTower:
    def __init__(self,data=''):
        self._length = 0
        self._length2 = 0
        self._number_of_floors = 0
        self._floors = []
        self._tower_len = 0
        if data:
            self._length, self._length2, self._number_of_floors = unpack('<LLH',data[:10])
            offset = 10
            for i in range(0,self._number_of_floors):
                self._floors.append(NDRFloor(data[offset:]))
                offset += self._floors[i].get_floor_len()
            self._tower_len = offset
    def get_tower_len(self):
        return self._tower_len
    def get_floors(self):
        return self._floors
    def get_number_of_floors(self):
        return self._number_of_floors
    
                                    
class NDREntry:
    def __init__(self,data=''):
        self._objectid = ''
        self._entry_len = 0
        self._tower = 0
        self._referent_id = 0
        self._annotation_offset = 0
        self._annotation_len = 0
        self._annotation = ''
        if data:
            self._objectid = data[:16]
            self._referent_id = unpack('<L',data[16:20])[0]
            self._annotation_offset, self._annotation_len = unpack('<LL',data[20:28])
            self._annotation = data[28:28+self._annotation_len-1]
            if self._annotation_len % 4:
                self._annotation_len += 4 - (self._annotation_len % 4)
            offset = 28 + self._annotation_len
            self._tower = NDRTower(data[offset:])
            self._entry_len = offset + self._tower.get_tower_len()
    def get_entry_len(self):
        if self._entry_len % 4:
            self._entry_len += 4 - (self._entry_len % 4)
        return self._entry_len
    def get_annotation(self):
        return self._annotation
    def get_tower(self):
        return self._tower

    def get_uuid(self):
        binuuid = self._tower.get_floors()[0].get_uuid()
        return binuuid[:16]

    def get_objuuid(self):
        return self._objectid

    def get_version(self):
        binuuid = self._tower.get_floors()[0].get_uuid()
        return unpack('<H', binuuid[16:18])[0]

    def print_friendly(self):
        if self._tower <> 0:
            floors = self._tower.get_floors()
            print "IfId: %s [%s]" % (floors[0].get_uuid_string(), uuid_to_exe(floors[0].get_uuid()))
            if self._annotation:
                print "Annotation: %s" % self._annotation
            print "UUID: %s" % parse_uuid(self._objectid)
            print "Binding: %s" % self.get_string_binding()
            print ''

    def get_string_binding(self):
        if self._tower <> 0:
            tmp_address = ''
            tmp_address2 = ''
            floors = self._tower.get_floors()
            num_floors = self._tower.get_number_of_floors()
            for i in range(3,num_floors):
                if floors[i].get_protocol() == 0x07:
                    tmp_address = 'ncacn_ip_tcp:%%s[%d]' % unpack('!H',floors[i].get_rhs())
                elif floors[i].get_protocol() == 0x08:
                    tmp_address = 'ncadg_ip_udp:%%s[%d]' % unpack('!H',floors[i].get_rhs())
                elif floors[i].get_protocol() == 0x09:
                    # If the address were 0.0.0.0 it would have to be replaced by the remote host's IP.
                    tmp_address2 = socket.inet_ntoa(floors[i].get_rhs())
                    if tmp_address <> '':
                        return tmp_address % tmp_address2
                    else:
                        return 'IP: %s' % tmp_address2
                elif floors[i].get_protocol() == 0x0c:
                    tmp_address = 'ncacn_spx:~%%s[%d]' % unpack('!H',floors[i].get_rhs())
                elif floors[i].get_protocol() == 0x0d:
                    n = floors[i].get_rhs_len()
                    tmp_address2 = ('%02X' * n) % unpack("%dB" % n, floors[i].get_rhs())
                    if tmp_address <> '':
                        return tmp_address % tmp_address2
                    else:
                        return 'SPX: %s' % tmp_address2
                elif floors[i].get_protocol() == 0x0e:
                    tmp_address = 'ncadg_ipx:~%%s[%d]' % unpack('!H',floors[i].get_rhs())
                elif floors[i].get_protocol() == 0x0f:
                    tmp_address = 'ncacn_np:%%s[%s]' % floors[i].get_rhs()[:floors[i].get_rhs_len()-1]
                elif floors[i].get_protocol() == 0x10:
                    return 'ncalrpc:[%s]' % floors[i].get_rhs()[:floors[i].get_rhs_len()-1]
                elif floors[i].get_protocol() == 0x01 or floors[i].get_protocol() == 0x11:
                    if tmp_address <> '':
                        return tmp_address % floors[i].get_rhs()[:floors[i].get_rhs_len()-1]
                    else:
                        return 'NetBIOS: %s' % floors[i].get_rhs()
                elif floors[i].get_protocol() == 0x1f:
                    tmp_address = 'ncacn_http:%%s[%d]' % unpack('!H',floors[i].get_rhs())
                else:
                    if floors[i].get_protocol_string() == 'unknown':
                        return 'unknown_proto_0x%x:[0]' % floors[i].get_protocol()
                    elif floors[i].get_protocol_string() <> 'UUID':
                        return 'protocol: %s, value: %s' % (floors[i].get_protocol_string(), floors[i].get_rhs())


class NDREntries:
    def __init__(self,data=''):
        self._max_count = 0
        self._offset = 0
        self._actual_count = 0
        self._entries_len = 0
        self._entries = []
        if data:
            self._max_count, self._offset, self._actual_count = unpack('<LLL',data[:12])
            self._entries_len = 12
            for i in range (0,self._actual_count):
                self._entries.append(NDREntry(data[self._entries_len:]))
                self._entries_len += self._entries[i].get_entry_len()
                
    def get_max_count(self):
        return self._max_count
    def get_offset(self):
        return self._offset
    def get_actual_count(self):
        return self._actual_count
    def get_entries_len(self):
        return self._entries_len
    def get_entry(self):
        return self._entries[0]
    
class NDRPointer:
    def __init__(self,data='',pointerType = None):
        self._referent_id = random.randint(0,65535)
        self._pointer = None
        if data:
            self._referent_id = unpack('<L',data[:4])[0]
            self._pointer = pointerType(data[4:])
    def set_pointer(self, data):
        self._pointer = data
    def get_pointer(self):
        return self._pointer
    def rawData(self):
        return pack('<L',self._referent_id) + self._pointer.rawData()

class NDRString:
    def __init__(self,data=''):
        self._string = ''
        self._max_len = 0
        self._offset = 0
        self._length = 0
        if data:
            self._max_len, self._offset, self._length = unpack('<LLL',data[:12])
            self._string = unicode(data[12:12 + self._length * 2], 'utf-16le')
    def get_string(self):
        return self._string
    def set_string(self,str):
        self._string = str
        self._max_len = self._length = len(str)+1
    def rawData(self):
        if self._length & 0x1:
            self._tail = pack('<HH',0,0)
        else:
            self._tail = pack('<H',0)
        return pack('<LLL',self._max_len, self._offset, self._length) + self._string.encode('utf-16le') + self._tail

    def get_max_len(self):
        return self._max_len

    def get_length(self):
        return self._length
    
