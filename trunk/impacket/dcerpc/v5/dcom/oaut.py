# Copyright (c) 2003-2014 CORE Security Technologies
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
#   [MS-OAUT]: OLE Automation Protocol Implementation
#              This was used as a way to test the DCOM runtime. Further 
#              testing is needed to verify it is working as expected
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://code.google.com/p/impacket/source/browse/#svn%2Ftrunk%2Fimpacket%2Ftestcases%2FSMB-RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRENUM, NDRUSHORT, NDRUNION
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown2, PMInterfacePointer, INTERFACE, MInterfacePointer, MInterfacePointer_ARRAY, BYTE_ARRAY
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, DWORD, SHORT, GUID, USHORT, LONG, WSTR, BYTE, LONGLONG, FLOAT, DOUBLE, HRESULT, PSHORT, PLONG, PLONGLONG, PFLOAT, PDOUBLE, PHRESULT, CHAR, ULONGLONG, INT, UINT, PCHAR, PUSHORT, PULONG, PULONGLONG, PINT, PUINT
from impacket.dcerpc.v5.enum import Enum
from impacket import hresult_errors
from impacket.uuid import string_to_bin
from struct import pack, unpack

class DCERPCSessionError(Exception):
    def __init__( self, packet = None, error_code = None):
        Exception.__init__(self)
        self.packet = packet
        if packet is not None:
            self.error_code = packet['ErrorCode']
        else:
            self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code
 
    def get_packet( self ):
        return self.packet

    def __str__( self ):
        if (hresult_errors.ERROR_MESSAGES.has_key(self.error_code)):
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'OAUT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'OAUT SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# CONSTANTS
################################################################################
# 1.9 Standards Assignments
IID_IDispatch = string_to_bin('00020400-0000-0000-C000-000000000046')
IID_ITypeInfo = string_to_bin('00020401-0000-0000-C000-000000000046')

error_status_t = ULONG

LCID = DWORD
WORD = NDRUSHORT

# 2.2.2 IID
IID = GUID

# 2.2.3 LPOLESTR
LPOLESTR = LPWSTR
OLESTR = WSTR

# 2.2.25 DATE
DATE = DOUBLE
class PDATE(NDRPOINTER):
    referent = (
        ('Data', DATE),
    )

# 2.2.27 VARIANT_BOOL
VARIANT_BOOL = USHORT

class PVARIANT_BOOL(NDRPOINTER):
    referent = (
        ('Data', VARIANT_BOOL),
    )

################################################################################
# STRUCTURES
################################################################################
# 2.2.26 DECIMAL
class DECIMAL(NDRSTRUCT):
    structure = (
        ('wReserved',WORD),
        ('scale',BYTE),
        ('sign',BYTE),
        ('Hi32',ULONG),
        ('Lo64',ULONGLONG),
    )

class PDECIMAL(NDRPOINTER):
    referent = (
        ('Data', DECIMAL),
    )

# 2.2.7 VARIANT Type Constants
class VARENUM(NDRENUM):
    class enumItems(Enum):
        VT_EMPTY       = 0
        VT_NULL        = 1
        VT_I2          = 2
        VT_I4          = 3
        VT_R4          = 4
        VT_R8          = 5
        VT_CY          = 6
        VT_DATE        = 7
        VT_BSTR        = 8
        VT_DISPATCH    = 9
        VT_ERROR       = 0xa
        VT_BOOL        = 0xb
        VT_VARIANT     = 0xc
        VT_UNKNOWN     = 0xd
        VT_DECIMAL     = 0xe
        VT_I1          = 0x10
        VT_UI1         = 0x11
        VT_UI2         = 0x12
        VT_UI4         = 0x13
        VT_I8          = 0x14
        VT_UI8         = 0x15
        VT_INT         = 0x16
        VT_UINT        = 0x17
        VT_VOID        = 0x18
        VT_HRESULT     = 0x19
        VT_PTR         = 0x1a
        VT_SAFEARRAY   = 0x1b
        VT_CARRAY      = 0x1c
        VT_USERDEFINED = 0x1d
        VT_LPSTR       = 0x1e
        VT_LPWSTR      = 0x1f
        VT_RECORD      = 0x24
        VT_INT_PTR     = 0x25
        VT_UINT_PTR    = 0x26
        VT_ARRAY       = 0x2000
        VT_BYREF       = 0x4000
        VT_UINT_PTR    = 7
        VT_RECORD_OR_VT_BYREF   = VT_RECORD | VT_BYREF
        VT_UI1_OR_VT_BYREF      = VT_UI1 | VT_BYREF
        VT_I2_OR_VT_BYREF       = VT_I2 | VT_BYREF
        VT_I4_OR_VT_BYREF       = VT_I4 | VT_BYREF
        VT_I8_OR_VT_BYREF       = VT_I8 | VT_BYREF
        VT_R4_OR_VT_BYREF       = VT_R4 | VT_BYREF
        VT_R8_OR_VT_BYREF       = VT_R8 | VT_BYREF
        VT_BOOL_OR_VT_BYREF     = VT_BOOL | VT_BYREF
        VT_ERROR_OR_VT_BYREF    = VT_ERROR | VT_BYREF
        VT_CY_OR_VT_BYREF       = VT_CY | VT_BYREF
        VT_DATE_OR_VT_BYREF     = VT_DATE | VT_BYREF
        VT_BSTR_OR_VT_BYREF     = VT_BSTR | VT_BYREF
        VT_UNKNOWN_OR_VT_BYREF  = VT_UNKNOWN | VT_BYREF
        VT_DISPATCH_OR_VT_BYREF = VT_DISPATCH | VT_BYREF
        VT_ARRAY_OR_VT_BYREF    = VT_ARRAY | VT_BYREF
        VT_VARIANT_OR_VT_BYREF  = VT_VARIANT| VT_BYREF
        VT_I1_OR_VT_BYREF       = VT_I1 | VT_BYREF
        VT_UI2_OR_VT_BYREF      = VT_UI2 | VT_BYREF
        VT_UI4_OR_VT_BYREF      = VT_UI4 | VT_BYREF
        VT_UI8_OR_VT_BYREF      = VT_UI8 | VT_BYREF
        VT_INT_OR_VT_BYREF      = VT_INT | VT_BYREF
        VT_UINT_OR_VT_BYREF     = VT_UINT | VT_BYREF
        VT_DECIMAL_OR_VT_BYREF  = VT_DECIMAL | VT_BYREF

# 2.2.8 SAFEARRAY Feature Constants
class SF_TYPE(NDRENUM):
    class enumItems(Enum):
        SF_ERROR     = VARENUM.VT_ERROR
        SF_I1        = VARENUM.VT_I1
        SF_I2        = VARENUM.VT_I2
        SF_I4        = VARENUM.VT_I4
        SF_I8        = VARENUM.VT_I8
        SF_BSTR      = VARENUM.VT_BSTR
        SF_UNKNOWN   = VARENUM.VT_UNKNOWN
        SF_DISPATCH  = VARENUM.VT_DISPATCH
        SF_VARIANT   = VARENUM.VT_VARIANT
        SF_RECORD    = VARENUM.VT_RECORD
        SF_HAVEIID   = VARENUM.VT_UNKNOWN | 0x8000

# 2.2.17 TYPEKIND Type Kind Constants
class TYPEKIND(NDRENUM):
    class enumItems(Enum):
        TKIND_ENUM      = 0
        TKIND_RECORD    = 1
        TKIND_MODULE    = 2
        TKIND_INTERFACE = 3
        TKIND_DISPATCH  = 4
        TKIND_COCLASS   = 5
        TKIND_ALIAS     = 6
        TKIND_UNION     = 7

# 2.2.23 BSTR
# 2.2.23.1 FLAGGED_WORD_BLOB
class USHORT_ARRAY(NDRUniConformantArray):
    item = '<H'

class FLAGGED_WORD_BLOB(NDRSTRUCT):
    structure = (
        ('cBytes',ULONG),
        ('clSize',ULONG),
        ('asData',USHORT_ARRAY),
    )
    def __setitem__(self, key, value):
        if key == 'asData':
            value = value #+ '\x00'
            array = list()
            for letter in value:
                encoded = letter.encode('utf-16le')
                array.append(unpack('<H', encoded)[0])
            self.fields[key]['Data'] = array
            self['cBytes'] = len(value)*2
            self['clSize'] = len(value)
            self.data = None        # force recompute
        else:
            return NDRSTRUCT.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'asData':
            value = ''
            for letter in self.fields['asData']['Data']:
                value += pack('<H', letter).encode('utf-16le')
            return value
        else:
            return NDRSTRUCT.__getitem__(self,key)

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg)
        value = ''
        #for letter in self['asData']:
        #    value += pack('<H', letter).encode('utf-16le')
        print '\n%sasData: %s' % (ind,self['asData']),

# 2.2.23.2 BSTR Type Definition
class BSTR(NDRPOINTER):
    referent = (
        ('Data', FLAGGED_WORD_BLOB),
    )

class PBSTR(NDRPOINTER):
    referent = (
        ('Data', BSTR),
    )

# 2.2.24 CURRENCY
class CURRENCY(NDRSTRUCT):
    structure = (
        ('int64', LONGLONG),
    )

class PCURRENCY(NDRPOINTER):
    referent = (
        ('Data', CURRENCY),
    )

# 2.2.28.2 BRECORD
# 2.2.28.2.1 _wireBRECORD
class _wireBRECORD(NDRSTRUCT):
    structure = (
        ('fFlags', LONGLONG),
        ('clSize', LONGLONG),
        ('pRecInfo', MInterfacePointer),
        ('pRecord', BYTE_ARRAY),
    )

class BRECORD(NDRPOINTER):
    referent = (
        ('Data', _wireBRECORD),
    )

# 2.2.30 SAFEARRAY
# 2.2.30.1 SAFEARRAYBOUND
class SAFEARRAYBOUND(NDRSTRUCT):
    structure = (
        ('cElements', ULONG),
        ('lLbound', LONG),
    )

class PSAFEARRAYBOUND(NDRPOINTER):
    referent = (
        ('Data', SAFEARRAYBOUND),
    )

# 2.2.30.2 SAFEARR_BSTR
class BSTR_ARRAY(NDRUniConformantArray):
    item = BSTR

class PBSTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BSTR_ARRAY),
    )

class SAFEARR_BSTR(NDRSTRUCT):
    structure = (
        ('Size', ULONG),
        ('aBstr', PBSTR_ARRAY),
    )

# 2.2.30.3 SAFEARR_UNKNOWN
class SAFEARR_UNKNOWN(NDRSTRUCT):
    structure = (
        ('Size', ULONG),
        ('apUnknown', MInterfacePointer_ARRAY),
    )

# 2.2.30.4 SAFEARR_DISPATCH
class SAFEARR_DISPATCH(NDRSTRUCT):
    structure = (
        ('Size', ULONG),
        ('apDispatch', MInterfacePointer_ARRAY),
    )

# 2.2.30.6 SAFEARR_BRECORD
class BRECORD_ARRAY(NDRUniConformantArray):
    item = BRECORD

class SAFEARR_BRECORD(NDRSTRUCT):
    structure = (
        ('Size', ULONG),
        ('aRecord', BRECORD_ARRAY),
    )

# 2.2.30.7 SAFEARR_HAVEIID
class SAFEARR_HAVEIID(NDRSTRUCT):
    structure = (
        ('Size', ULONG),
        ('apUnknown', MInterfacePointer_ARRAY),
        ('iid', IID),
    )

# 2.2.30.8 Scalar-Sized Arrays
# 2.2.30.8.1 BYTE_SIZEDARR
class BYTE_SIZEDARR(NDRSTRUCT):
    structure = (
        ('clSize', ULONG),
        ('pData', BYTE_ARRAY),
    )

# 2.2.30.8.2 WORD_SIZEDARR
class WORD_ARRAY(NDRUniConformantArray):
    item = '<H'

class WORD_SIZEDARR(NDRSTRUCT):
    structure = (
        ('clSize', ULONG),
        ('pData', WORD_ARRAY),
    )

# 2.2.30.8.3 DWORD_SIZEDARR
class DWORD_ARRAY(NDRUniConformantArray):
    item = '<L'

class DWORD_SIZEDARR(NDRSTRUCT):
    structure = (
        ('clSize', ULONG),
        ('pData', DWORD_ARRAY),
    )

# 2.2.30.8.4 HYPER_SIZEDARR
class HYPER_ARRAY(NDRUniConformantArray):
    item = '<Q'

class HYPER_SIZEDARR(NDRSTRUCT):
    structure = (
        ('clSize', ULONG),
        ('pData', HYPER_ARRAY),
    )


# 2.2.36 HREFTYPE
HREFTYPE = DWORD
# ToDo: Make this forward declarations to work
VARIANT = LONG
PVARIANT = NDRPOINTER

# 2.2.30.5 SAFEARR_VARIANT
class VARIANT_ARRAY(NDRUniConformantArray):
    item = VARIANT

class SAFEARR_VARIANT(NDRSTRUCT):
    structure = (
        ('Size', ULONG),
        ('aVariant', VARIANT_ARRAY),
    )

# 2.2.30.9 SAFEARRAYUNION
class SAFEARRAYUNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        SF_TYPE.SF_BSTR     : ('BstrStr', SAFEARR_BSTR),
        SF_TYPE.SF_UNKNOWN  : ('UnknownStr', SAFEARR_UNKNOWN),
        SF_TYPE.SF_DISPATCH : ('DispatchStr', SAFEARR_DISPATCH),
        SF_TYPE.SF_VARIANT  : ('VariantStr', SAFEARR_VARIANT),
        SF_TYPE.SF_RECORD   : ('RecordStr', SAFEARR_BRECORD),
        SF_TYPE.SF_HAVEIID  : ('HaveIidStr', SAFEARR_HAVEIID),
        SF_TYPE.SF_I1       : ('ByteStr', BYTE_SIZEDARR),
        SF_TYPE.SF_I2       : ('WordStr', WORD_SIZEDARR),
        SF_TYPE.SF_I4       : ('LongStr', DWORD_SIZEDARR),
        SF_TYPE.SF_I8       : ('HyperStr', HYPER_SIZEDARR),
    }

# 2.2.30.10 SAFEARRAY
class SAFEARRAYBOUND_ARRAY(NDRUniConformantArray):
    item = SAFEARRAYBOUND

class PSAFEARRAYBOUND_ARRAY(NDRPOINTER):
    referent = (
        ('Data', SAFEARRAYBOUND_ARRAY),
    )

class SAFEARRAY(NDRSTRUCT):
    structure = (
        ('cDims', USHORT),
        ('fFeatures', USHORT),
        ('cbElements', ULONG),
        ('cLocks', ULONG),
        ('uArrayStructs', SAFEARRAYUNION),
        ('rgsabound', SAFEARRAYBOUND_ARRAY),
    )

class PSAFEARRAY(NDRPOINTER):
    referent = (
        ('Data', SAFEARRAY),
    )

# 2.2.29 VARIANT
# 2.2.29.1 _wireVARIANT
class varUnion(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        VARENUM.VT_I8                  : ('llVal', LONGLONG),
        VARENUM.VT_I4                  : ('lVal', LONG),
        VARENUM.VT_UI1                 : ('bVal', BYTE),
        VARENUM.VT_I2                  : ('iVal', SHORT),
        VARENUM.VT_R4                  : ('fltVal', FLOAT),
        VARENUM.VT_R8                  : ('dblVal', DOUBLE),
        VARENUM.VT_BOOL                : ('boolVal', VARIANT_BOOL),
        VARENUM.VT_ERROR               : ('scode', HRESULT),
        VARENUM.VT_CY                  : ('cyVal', CURRENCY),
        VARENUM.VT_DATE                : ('date', DATE),
        VARENUM.VT_BSTR                : ('bstrVal', BSTR),
        VARENUM.VT_UNKNOWN             : ('punkVal', MInterfacePointer),
        VARENUM.VT_DISPATCH            : ('pdispVal', MInterfacePointer),
        VARENUM.VT_ARRAY               : ('parray', SAFEARRAY),
        VARENUM.VT_RECORD              : ('brecVal', BRECORD),
        VARENUM.VT_RECORD_OR_VT_BYREF  : ('brecVal', BRECORD),
        VARENUM.VT_UI1_OR_VT_BYREF     : ('pbVal', BYTE),
        VARENUM.VT_I2_OR_VT_BYREF      : ('piVal', PSHORT),
        VARENUM.VT_I4_OR_VT_BYREF      : ('plVal', PLONG),
        VARENUM.VT_I8_OR_VT_BYREF      : ('pllVal', PLONGLONG),
        VARENUM.VT_R4_OR_VT_BYREF      : ('pfltVal', PFLOAT),
        VARENUM.VT_R8_OR_VT_BYREF      : ('pdblVal', PDOUBLE),
        VARENUM.VT_BOOL_OR_VT_BYREF    : ('pboolVal', PVARIANT_BOOL),
        VARENUM.VT_ERROR_OR_VT_BYREF   : ('pscode', PHRESULT),
        VARENUM.VT_CY_OR_VT_BYREF      : ('pcyVal', PCURRENCY),
        VARENUM.VT_DATE_OR_VT_BYREF    : ('pdate', PDATE),
        VARENUM.VT_BSTR_OR_VT_BYREF    : ('pbstrVal', PBSTR),
        VARENUM.VT_UNKNOWN_OR_VT_BYREF : ('ppunkVal', PMInterfacePointer),
        VARENUM.VT_DISPATCH_OR_VT_BYREF: ('ppdispVal', PMInterfacePointer),
        VARENUM.VT_ARRAY_OR_VT_BYREF   : ('pparray', PSAFEARRAY),
        VARENUM.VT_VARIANT_OR_VT_BYREF : ('pvarVal', PVARIANT),
        VARENUM.VT_I1                  : ('cVal', CHAR),
        VARENUM.VT_UI2                 : ('uiVal', USHORT),
        VARENUM.VT_UI4                 : ('ulVal', ULONG),
        VARENUM.VT_UI8                 : ('ullVal', ULONGLONG),
        VARENUM.VT_INT                 : ('intVal', INT),
        VARENUM.VT_UINT                : ('uintVal', UINT),
        VARENUM.VT_DECIMAL             : ('decVal', DECIMAL),
        VARENUM.VT_I1_OR_VT_BYREF      : ('pcVal', PCHAR),
        VARENUM.VT_UI2_OR_VT_BYREF     : ('puiVal', PUSHORT),
        VARENUM.VT_UI4_OR_VT_BYREF     : ('pulVal', PULONG),
        VARENUM.VT_UI8_OR_VT_BYREF     : ('pullVal', PULONGLONG),
        VARENUM.VT_INT_OR_VT_BYREF     : ('pintVal', PINT),
        VARENUM.VT_UINT_OR_VT_BYREF    : ('puintVal', PUINT),
        VARENUM.VT_DECIMAL_OR_VT_BYREF : ('pdecVal', PDECIMAL),
        VARENUM.VT_EMPTY               : ('', ),
        VARENUM.VT_NULL                : ('', ),
    }

class wireVARIANTStr(NDRSTRUCT):
    structure = (
        ('clSize',DWORD),
        ('rpcReserved',DWORD),
        ('vt',USHORT),
        ('wReserved1',USHORT),
        ('wReserved2',USHORT),
        ('wReserved3',USHORT),
        ('_varUnion',varUnion),
    )

class VARIANT(NDRPOINTER):
    referent = (
        ('Data', wireVARIANTStr),
    )

class PVARIANT(NDRPOINTER):
    referent = (
        ('Data', VARIANT),
    )

# 2.2.38 ARRAYDESC
class ARRAYDESC(NDRSTRUCT):
    structure = (
#        ('tdescElem',TYPEDESC),
        ('cDims',USHORT),
        ('rgbounds',SAFEARRAYBOUND_ARRAY),
    )

# 2.2.37 TYPEDESC
class TYPEDESC(NDRUNION):
    commonHdr = (
        ('tag', USHORT),
    )
    union = {
        VARENUM.VT_PTR: ('lptdesc', HREFTYPE),
        VARENUM.VT_SAFEARRAY: ('lptdesc', HREFTYPE),
        VARENUM.VT_CARRAY: ('lpadesc', ARRAYDESC),
        VARENUM.VT_USERDEFINED: ('hreftype', HREFTYPE),
    }

# 2.2.44 TYPEATTR
class TYPEATTR(NDRSTRUCT):
    structure = (
        ('guid',GUID),
        ('lcid',LCID),
        ('dwReserved1',DWORD),
        ('dwReserved2',DWORD),
        #('dwReserved3',DWORD),
        ('lpstrReserved4',DWORD),
        #('lpstrReserved4',LPOLESTR),
        ('cbSizeInstance',ULONG),
        ('typeKind',TYPEKIND),
        ('cFuncs',WORD),
        ('cVars',WORD),
        ('cImplTypes',WORD),
        ('cbSizeVft',WORD),
        ('cbAlignment',WORD),
        ('wTypeFlags',WORD),
        ('wMajorVerNum',WORD),
        ('wMinorVerNum',WORD),
        #('tdescAlias',TYPEDESC),
        #('dwReserved5',DWORD),
        #('dwReserved6',WORD),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.1.4.1 IDispatch::GetTypeInfoCount (Opnum 3)
class IDispatch_GetTypeInfoCount(DCOMCALL):
    opnum = 3
    structure = (
       ('pwszMachineName', LPWSTR),
    )

class IDispatch_GetTypeInfoCountResponse(DCOMANSWER):
    structure = (
       ('pctinfo', ULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2 IDispatch::GetTypeInfo (Opnum 4)
class IDispatch_GetTypeInfo(DCOMCALL):
    opnum = 4
    structure = (
       ('iTInfo', ULONG),
       ('lcid', DWORD),
    )

class IDispatch_GetTypeInfoResponse(DCOMANSWER):
    structure = (
       ('ppTInfo', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.7.4.1 ITypeInfo::GetTypeAttr (Opnum 3)
class ITypeInfo_GetTypeAttr(DCOMCALL):
    opnum = 3
    structure = (
    )

class ITypeInfo_GetTypeAttrResponse(DCOMANSWER):
    structure = (
       ('ppTypeAttr', TYPEATTR),
       ('pReserved', DWORD),
       ('ErrorCode', error_status_t),
    )


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
}

################################################################################
# HELPER FUNCTIONS
################################################################################
class ITypeInfo(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self,interface)
        self._iid = IID_ITypeInfo

    def GetTypeAttr(self):
        request = ITypeInfo_GetTypeAttr()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp


class IDispatch(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self,interface)
        self._iid = IID_IDispatch

    def GetTypeInfoCount(self):
        request = IDispatch_GetTypeInfoCount()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def GetTypeInfo(self):
        request = IDispatch_GetTypeInfo()
        request['iTInfo'] = 0
        request['lcid'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return ITypeInfo(INTERFACE(self.get_cinstance(), ''.join(resp['ppTInfo']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip()))


