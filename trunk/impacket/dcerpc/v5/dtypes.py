# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
#
# Description:
#   [MS-DTYP] Interface mini implementation
#
import random
from struct import pack, unpack
from impacket.dcerpc.v5.ndr import NDRULONG, NDRUHYPER, NDRUSMALL, NDRSHORT, NDRLONG, NDRPOINTER, NDRUniConformantArray, NDRUniFixedArray, NDR, NDRHYPER, NDRSMALL, NDRPOINTERNULL, NDRSTRUCT, NULL

DWORD = NDRULONG
ULONGLONG = NDRUHYPER
BOOL = NDRULONG
UCHAR = NDRUSMALL
USHORT = NDRSHORT
ULONG = NDRULONG
LONG = NDRLONG

class LPLONG(NDRPOINTER):
    referent = (
        ('Data', LONG),
    )

class LPULONG(NDRPOINTER):
    referent = (
        ('Data', ULONG),
    )

class PBOOL(NDRPOINTER):
    referent = (
        ('Data', BOOL),
    )

class LPBYTE(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantArray),
    )
PBYTE = LPBYTE

class WIDESTR(NDRUniFixedArray):
    def getDataLen(self, data):
        return data.find('\x00\x00\x00')+3

    def __setitem__(self, key, value):
        if key == 'Data':
            self.fields[key] = value.encode('utf-16le')
            self.data = None        # force recompute
        else:
            return NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return NDR.__getitem__(self,key)

class STR(NDRSTRUCT):
    commonHdr = (
        ('MaximumCount', '<L=len(Data)'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
    )
    commonHdr64 = (
        ('MaximumCount', '<Q=len(Data)'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
    )
    structure = (
        ('Data',':'),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here just print the data
        print " %r" % (self['Data']),

    def __setitem__(self, key, value):
        if key == 'Data':
            self.fields[key] = value
            self.fields['MaximumCount'] = None
            self.fields['ActualCount'] = None
            self.data = None        # force recompute
        else:
            return NDR.__setitem__(self, key, value)

    def getDataLen(self, data):
        return self["ActualCount"]

class LPSTR(NDRPOINTER):
    referent = (
        ('Data', STR),
    )

class WSTR(NDRSTRUCT):
    commonHdr = (
        ('MaximumCount', '<L=len(Data)/2'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)/2'),
    )
    commonHdr64 = (
        ('MaximumCount', '<Q=len(Data)/2'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)/2'),
    )
    structure = (
        ('Data',':'),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here just print the data
        print " %r" % (self['Data']),

    def getDataLen(self, data):
        return self["ActualCount"]*2 

    def __setitem__(self, key, value):
        if key == 'Data':
            self.fields[key] = value.encode('utf-16le')
            self.fields['MaximumCount'] = None
            self.fields['ActualCount'] = None
            self.data = None        # force recompute
        else:
            return NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return NDR.__getitem__(self,key)

class LPWSTR(NDRPOINTER):
    referent = (
        ('Data', WSTR),
    )

# 2.2.26 LMSTR
LMSTR = LPWSTR

# 2.2.36 NET_API_STATUS
NET_API_STATUS = DWORD

# 2.3.2 GUID and UUID
class GUID(NDRSTRUCT):
    structure = (
        ('Data','16s=""'),
    )

    def getAlignment(self):
        return 4

class PGUID(NDRPOINTER):
    referent = (
        ('Data', GUID),
    )

UUID = GUID
PUUID = PGUID

# 2.2.37 NTSTATUS
NTSTATUS = DWORD

# 2.2.59 WCHAR
WCHAR = WSTR

# 2.3.3 LARGE_INTEGER
LARGE_INTEGER = NDRHYPER
class PLARGE_INTEGER(NDRPOINTER):
    referent = (
        ('Data', LARGE_INTEGER),
    )

# 2.3.5 LUID
class LUID(NDRSTRUCT):
    structure = (
        ('LowPart', DWORD),
        ('HighPart', LONG),
    )

# 2.3.8 RPC_UNICODE_STRING
class RPC_UNICODE_STRING(NDRSTRUCT):
    commonHdr = (
        ('Length','<H=len(Data)-12'),
        ('MaximumLength','<H=len(Data)-12'),
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('Length','<H=len(Data)-24'),
        ('MaximumLength','<H=len(Data)-24'),
        ('ReferentID','<Q=0xff'),
    )

    referent = (
        ('Data',WSTR),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here just print the data
        print " %r" % (self['Data']),

    def __setitem__(self, key, value):
        if isinstance(value, NDRPOINTERNULL):
            self.fields['ReferentID'] = 0x00
            self.fields['Data'] = value
        if key == 'Data':
            self.fields['ReferentID'] = random.randint(1, 65535)
            self.fields['Length'] = None
            self.fields['MaximumLength'] = None
            self.data = None        # force recompute
        return NDR.__setitem__(self, key, value)

    def getData(self, soFar = 0):
        # If we have a ReferentID == 0, means there's no data
        if self.fields['ReferentID'] == 0:
            self.fields['Data'].fields['Data']=''

        return NDR.getData(self, soFar)

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here we just print the referent
        if self['ReferentID'] == 0:
            print " NULL",
        else:
            return self.fields['Data'].dump( '', indent)


class PRPC_UNICODE_STRING(NDRPOINTER):
    referent = (
       ('Data', RPC_UNICODE_STRING ),
    )

class LPDWORD(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantArray),
    )
    def __init__(self, data = None,isNDR64 = False, topLevel = False):
        NDRPOINTER.__init__(self, None, isNDR64, topLevel)
        # ToDo: change this so it is DWORD instead of <H
        self.fields['Data'].item = '<L'
        if data is not None:
            self.fromString(data)

# 2.4.2.3 RPC_SID
class DWORD_ARRAY(NDRUniConformantArray):
    item = '<L'

class RPC_SID_IDENTIFIER_AUTHORITY(NDRUniFixedArray):
    align = 1
    align64 = 1
    def getDataLen(self, data):
        return 6

class RPC_SID(NDRSTRUCT):
    structure = (
        ('Revision',NDRSMALL),
        ('SubAuthorityCount',NDRSMALL),
        ('IdentifierAuthority',RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubAuthority',DWORD_ARRAY),
    )
    def getData(self, soFar = 0):
        self['SubAuthorityCount'] = len(self['SubAuthority'])
        return NDRSTRUCT.getData(self, soFar)

    def fromCanonical(self, canonical):
        items = canonical.split('-')
        self['Revision'] = int(items[1])
        self['IdentifierAuthority'] = RPC_SID_IDENTIFIER_AUTHORITY()
        self['IdentifierAuthority'] = '\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
        self['SubAuthorityCount'] = len(items) - 3
        ans = ''
        for i in range(self['SubAuthorityCount']):
            self['SubAuthority'].append(int(items[i+3]))

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority'][5]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % self['SubAuthority'][i]
        return ans

class PRPC_SID(NDRPOINTER):
    referent = (
        ('Data', RPC_SID),
    )

PSID = PRPC_SID

# 2.4.3 ACCESS_MASK
ACCESS_MASK = DWORD
GENERIC_READ            = 0x80000000L
GENERIC_WRITE           = 0x4000000L
GENERIC_EXECUTE         = 0x20000000L
GENERIC_ALL             = 0x10000000L
MAXIMUM_ALLOWED         = 0x02000000L
ACCESS_SYSTEM_SECURITY  = 0x01000000L
SYNCHRONIZE             = 0x00100000L
WRITE_OWNER             = 0x00080000L
WRITE_DACL              = 0x00040000L
READ_CONTROL            = 0x00020000L
DELETE                  = 0x00010000L

# 2.4.5.1 ACL--RPC Representation
class ACL(NDRSTRUCT):
    structure = (
        ('AclRevision',NDRSMALL),
        ('Sbz1',NDRSMALL),
        ('AclSize',NDRSHORT),
        ('AceCount',NDRSHORT),
        ('Sbz2',NDRSHORT),
    )

class PACL(NDRPOINTER):
    referent = (
        ('Data', ACL),
    )

# 2.4.6.1 SECURITY_DESCRIPTOR--RPC Representation
class SECURITY_DESCRIPTOR(NDRSTRUCT):
    structure = (
        ('Revision',UCHAR),
        ('Sbz1',UCHAR),
        ('Control',USHORT),
        ('Owner',PSID),
        ('Group',PSID),
        ('Sacl',PACL),
        ('Dacl',PACL),
    )

# 2.4.7 SECURITY_INFORMATION
OWNER_SECURITY_INFORMATION            = 0x00000001
GROUP_SECURITY_INFORMATION            = 0x00000002
DACL_SECURITY_INFORMATION             = 0x00000004
SACL_SECURITY_INFORMATION             = 0x00000008
LABEL_SECURITY_INFORMATION            = 0x00000010
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
ATTRIBUTE_SECURITY_INFORMATION        = 0x00000020
SCOPE_SECURITY_INFORMATION            = 0x00000040
BACKUP_SECURITY_INFORMATION           = 0x00010000

SECURITY_INFORMATION = DWORD
class PSECURITY_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', SECURITY_INFORMATION),
    )
