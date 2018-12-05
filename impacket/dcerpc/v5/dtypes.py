# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-DTYP] Interface mini implementation
#
from struct import pack

from impacket.dcerpc.v5.ndr import NDRULONG, NDRUHYPER, NDRSHORT, NDRLONG, NDRPOINTER, NDRUniConformantArray, \
    NDRUniFixedArray, NDR, NDRHYPER, NDRSMALL, NDRPOINTERNULL, NDRSTRUCT, \
    NDRUSMALL, NDRBOOLEAN, NDRUSHORT, NDRFLOAT, NDRDOUBLEFLOAT, NULL

DWORD = NDRULONG
BOOL = NDRULONG
UCHAR = NDRUSMALL
SHORT = NDRSHORT
NULL = NULL

class LPDWORD(NDRPOINTER):
    referent = (
        ('Data', DWORD),
    )

class PSHORT(NDRPOINTER):
    referent = (
        ('Data', SHORT),
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

# 2.2.4 BOOLEAN
BOOLEAN = NDRBOOLEAN

# 2.2.6 BYTE
BYTE = NDRUSMALL

# 2.2.7 CHAR
CHAR = NDRSMALL
class PCHAR(NDRPOINTER):
    referent = (
        ('Data', CHAR),
    )

class WIDESTR(NDRUniFixedArray):
    def getDataLen(self, data):
        return data.find('\x00\x00\x00')+3

    def __setitem__(self, key, value):
        if key == 'Data':
            try:
                self.fields[key] = value.encode('utf-16le')
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode('utf-16le')

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
        if msg != '':
            print "%s" % msg,
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
        if msg != '':
            print "%s" % msg,
        # Here just print the data
        print " %r" % (self['Data']),

    def getDataLen(self, data):
        return self["ActualCount"]*2 

    def __setitem__(self, key, value):
        if key == 'Data':
            try:
                self.fields[key] = value.encode('utf-16le')
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode('utf-16le')
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

# 2.2.5 BSTR
BSTR = LPWSTR

# 2.2.8 DOUBLE
DOUBLE = NDRDOUBLEFLOAT
class PDOUBLE(NDRPOINTER):
    referent = (
        ('Data', DOUBLE),
    )

# 2.2.15 FLOAT
FLOAT = NDRFLOAT
class PFLOAT(NDRPOINTER):
    referent = (
        ('Data', FLOAT),
    )

# 2.2.18 HRESULT
HRESULT = NDRLONG
class PHRESULT(NDRPOINTER):
    referent = (
        ('Data', HRESULT),
    )

# 2.2.19 INT
INT = NDRLONG
class PINT(NDRPOINTER):
    referent = (
        ('Data', INT),
    )

# 2.2.26 LMSTR
LMSTR = LPWSTR

# 2.2.27 LONG
LONG = NDRLONG
class LPLONG(NDRPOINTER):
    referent = (
        ('Data', LONG),
    )

PLONG = LPLONG

# 2.2.28 LONGLONG
LONGLONG = NDRHYPER

class PLONGLONG(NDRPOINTER):
    referent = (
        ('Data', LONGLONG),
    )

# 2.2.31 LONG64
LONG64 = NDRUHYPER
class PLONG64(NDRPOINTER):
    referent = (
        ('Data', LONG64),
    )

# 2.2.32 LPCSTR
LPCSTR = LPSTR

# 2.2.36 NET_API_STATUS
NET_API_STATUS = DWORD

# 2.2.52 ULONG_PTR
ULONG_PTR = NDRULONG
# 2.2.10 DWORD_PTR
DWORD_PTR = ULONG_PTR

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

# 2.2.45 UINT
UINT = NDRULONG
class PUINT(NDRPOINTER):
    referent = (
        ('Data', UINT),
    )

# 2.2.50 ULONG
ULONG = NDRULONG
class PULONG(NDRPOINTER):
    referent = (
        ('Data', ULONG),
    )

LPULONG = PULONG

# 2.2.54 ULONGLONG
ULONGLONG = NDRUHYPER
class PULONGLONG(NDRPOINTER):
    referent = (
        ('Data', ULONGLONG),
    )

# 2.2.57 USHORT
USHORT = NDRUSHORT
class PUSHORT(NDRPOINTER):
    referent = (
        ('Data', USHORT),
    )

# 2.2.59 WCHAR
WCHAR = WSTR
PWCHAR = LPWSTR

# 2.2.61 WORD
WORD = NDRUSHORT
class PWORD(NDRPOINTER):
    referent = (
        ('Data', WORD),
    )
LPWORD = PWORD

# 2.3.1 FILETIME
class FILETIME(NDRSTRUCT):
    structure = (
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', LONG),
    )

class PFILETIME(NDRPOINTER):
    referent = (
        ('Data', FILETIME),
    )

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
    # Here we're doing some tricks to make this data type
    # easier to use. It's exactly the same as defined. I changed the
    # Buffer name for Data, so users can write directly to the datatype
    # instead of writing to datatype['Buffer'].
    # The drawback is you cannot directly access the Length and 
    # MaximumLength fields. 
    # If you really need it, you will need to do it this way:
    # class TT(NDRCALL):
    # structure = (
    #     ('str1', RPC_UNICODE_STRING),
    #  )
    # 
    # nn = TT()
    # nn.fields['str1'].fields['MaximumLength'] = 30
    structure = (
        ('Length','<H=0'),
        ('MaximumLength','<H=0'),
        ('Data',LPWSTR),
    )

    def __setitem__(self, key, value):
        if key == 'Data' and isinstance(value, NDR) is False:
            try:
                value.encode('utf-16le')
            except UnicodeDecodeError:
                import sys
                value = value.decode(sys.getfilesystemencoding())
            self['Length'] = len(value)*2
            self['MaximumLength'] = len(value)*2
        return NDRSTRUCT.__setitem__(self, key, value)

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        if msg != '':
            print "%s" % msg,

        if isinstance(self.fields['Data'] , NDRPOINTERNULL):
            print " NULL",
        elif self.fields['Data']['ReferentID'] == 0:
            print " NULL",
        else:
            return self.fields['Data'].dump('',indent)

class PRPC_UNICODE_STRING(NDRPOINTER):
    referent = (
       ('Data', RPC_UNICODE_STRING ),
    )

# 2.3.9 OBJECT_TYPE_LIST
ACCESS_MASK = DWORD
class OBJECT_TYPE_LIST(NDRSTRUCT):
    structure = (
        ('Level', WORD),
        ('Remaining',ACCESS_MASK),
        ('ObjectType',PGUID),
    )

class POBJECT_TYPE_LIST(NDRPOINTER):
    referent = (
       ('Data', OBJECT_TYPE_LIST ),
    )

# 2.3.13 SYSTEMTIME
class SYSTEMTIME(NDRSTRUCT):
    structure = (
        ('wYear', WORD),
        ('wMonth', WORD),
        ('wDayOfWeek', WORD),
        ('wDay', WORD),
        ('wHour', WORD),
        ('wMinute', WORD),
        ('wSecond', WORD),
        ('wMilliseconds', WORD),
    )

class PSYSTEMTIME(NDRPOINTER):
    referent = (
       ('Data', SYSTEMTIME ),
    )

# 2.3.15 ULARGE_INTEGER
class ULARGE_INTEGER(NDRSTRUCT):
    structure = (
        ('QuadPart', LONG64),
    )

class PULARGE_INTEGER(NDRPOINTER):
    referent = (
        ('Data', ULARGE_INTEGER),
    )

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
