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
from struct import pack, unpack
from impacket.dcerpc.v5 import ndr

DWORD = ndr.NDRLONG
ULONGLONG = ndr.NDRHYPER
BOOL = ndr.NDRLONG
UCHAR = ndr.NDRSMALL
USHORT = ndr.NDRSHORT
ULONG = ndr.NDRLONG
LONG = ndr.NDRLONG

class LPLONG(ndr.NDRPointer):
    referent = (
        ('Data', ndr.NDRLONG),
    )

class PBOOL(ndr.NDRPointer):
    referent = (
        ('Data', BOOL),
    )

class LPBYTE(ndr.NDRPointer):
    align = 4
    align64 = 8
    referent = (
        ('Data', ndr.NDRUniConformantArray),
    )
PBYTE = LPBYTE

class WIDESTR(ndr.NDRUniFixedArray):
    def getDataLen(self, data):
        return data.find('\x00\x00\x00')+3

    def __setitem__(self, key, value):
        if key == 'Data':
            self.fields[key] = value.encode('utf-16le')
            self.data = None        # force recompute
        else:
            return ndr.NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return ndr.NDR.__getitem__(self,key)

class STR(ndr.NDR):
    align = 4
    align64 = 8
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
            return ndr.NDR.__setitem__(self, key, value)

    def getDataLen(self, data):
        return self["ActualCount"]

class LPSTR(ndr.NDRPointer):
    referent = (
        ('Data', STR),
    )

class WSTR(ndr.NDR):
    align = 4
    align64 = 8
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
            return ndr.NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return ndr.NDR.__getitem__(self,key)

class LPWSTR(ndr.NDRPointer):
    referent = (
        ('Data', WSTR),
    )

# 2.2.26 LMSTR
LMSTR = LPWSTR

# 2.2.36 NET_API_STATUS
NET_API_STATUS = DWORD

# 2.3.2 GUID and UUID
class GUID(ndr.NDR):
    align = 0
    structure = (
        ('Data','16s=""'),
    )

class PGUID(ndr.NDRPointer):
    referent = (
        ('Data', GUID),
    )

UUID = GUID
PUUID = PGUID

# 2.2.37 NTSTATUS
NTSTATUS = LONG

# 2.2.59 WCHAR
WCHAR = WSTR

# 2.3.3 LARGE_INTEGER
LARGE_INTEGER = ndr.NDRHYPER
class PLARGE_INTEGER(ndr.NDRPointer):
    referent = (
        ('Data', LARGE_INTEGER),
    )

# 2.3.5 LUID
class LUID(ndr.NDR):
    structure = (
        ('LowPart', DWORD),
        ('HighPart', LONG),
    )

# 2.3.8 RPC_UNICODE_STRING
class RPC_UNICODE_STRING(ndr.NDR):
    align = 4
    align64 = 4
    commonHdr = (
        ('MaximumLength','<H=len(Data)-12'),
        ('Length','<H=len(Data)-12'),
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('MaximumLength','<H=len(Data)-24'),
        ('Length','<H=len(Data)-24'),
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
        if key == 'Data':
            self.fields['MaximumLength'] = None
            self.fields['Length'] = None
            self.data = None        # force recompute
        return ndr.NDR.__setitem__(self, key, value)

class UNIQUE_RPC_UNICODE_STRING(ndr.NDRPointer):
    referent = (
       ('Data', RPC_UNICODE_STRING ),
    )

PRPC_UNICODE_STRING = UNIQUE_RPC_UNICODE_STRING

class RPC_UNICODE_STRING_ARRAY(ndr.NDRUniConformantVaryingArray):
    item = RPC_UNICODE_STRING

class LPDWORD(ndr.NDRPointer):
    align = 4
    align64 = 8
    referent = (
        ('Data', ndr.NDRUniConformantArray),
    )
    def __init__(self, data = None,isNDR64 = False, topLevel = False):
        ndr.NDRPointer.__init__(self, None, isNDR64, topLevel)
        # ToDo: change this so it is DWORD instead of <H
        self.fields['Data'].item = '<L'
        if data is not None:
            self.fromString(data)

# 2.4.2.3 RPC_SID
class DWORD_ARRAY(ndr.NDRUniFixedArray):
    align = 0
    align64 = 0
    def getDataLen(self, data):
        return self.count * 4

class RPC_SID_IDENTIFIER_AUTHORITY(ndr.NDRUniFixedArray):
    align = 0
    align64 = 0
    def getDataLen(self, data):
        return 6

class RPC_SID(ndr.NDR):
    align = 4
    align64 = 4
    structure = (
        #('Count', '<L=0'),
        ('Count', ndr.NDRLONG),
        ('Revision',ndr.NDRSMALL),
        ('SubAuthorityCount',ndr.NDRSMALL),
        ('IdentifierAuthority',RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubAuthority',DWORD_ARRAY),
    )
    def __init__(self, data = None,isNDR64 = False):
        ndr.NDR.__init__(self, None, isNDR64)
        # SubAuthority Count is the second byte
        if data is not None:
            self.fromString(data)

    def fromString(self, data, soFar = 0 ):
        count = unpack('<L', data[:4])[0]
        self.fields['SubAuthority'].count = count
        return ndr.NDR.fromString(self,data, soFar)
 
    def getData(self, soFar = 0):
        self['SubAuthorityCount'] = len(self['SubAuthority'])/4
        self['Count'] = self['SubAuthorityCount']
        return ndr.NDR.getData(self, soFar)

    def fromCanonical(self, canonical):
        items = canonical.split('-')
        self['Revision'] = int(items[1])
        self['IdentifierAuthority'] = RPC_SID_IDENTIFIER_AUTHORITY()
        self['IdentifierAuthority'] = '\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
        self['SubAuthorityCount'] = len(items) - 3
        ans = ''
        for i in range(self['SubAuthorityCount']):
            ans += pack('<L', int(items[i+3]))
        self['SubAuthority'] = ans

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority'][5]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % ( unpack('<L',self['SubAuthority'][i*4:i*4+4])[0])
        return ans

class PRPC_SID(ndr.NDRPointer):
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
class ACL(ndr.NDR):
    structure = (
        ('AclRevision',ndr.NDRSMALL),
        ('Sbz1',ndr.NDRSMALL),
        ('AclSize',ndr.NDRSHORT),
        ('AceCount',ndr.NDRSHORT),
        ('Sbz2',ndr.NDRSHORT),
    )

class PACL(ndr.NDRPointer):
    referent = (
        ('Data', ACL),
    )

# 2.4.6.1 SECURITY_DESCRIPTOR--RPC Representation
class SECURITY_DESCRIPTOR(ndr.NDR):
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
class PSECURITY_INFORMATION(ndr.NDRPointer):
    referent = (
        ('Data', SECURITY_INFORMATION),
    )
