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
#   [MS-WMI]/[MS-WMIO] : Windows Management Instrumentation Remote Protocol. Partial implementation
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
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRUniConformantVaryingArray, NDRUNION, NDRENUM
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown, PMInterfacePointer, INTERFACE, PMInterfacePointer_ARRAY, BYTE_ARRAY, OBJREF_CUSTOM, PPMInterfacePointer
from impacket.dcerpc.v5.dcom.oaut import BSTR
from impacket.dcerpc.v5.dtypes import ULONG, DWORD, NULL, LPWSTR, LONG, HRESULT, PGUID, LPCSTR, GUID
from impacket.dcerpc.v5.enum import Enum
from impacket import hresult_errors
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket.structure import Structure

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
            return 'WMI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            # Let's see if we have it as WBEMSTATUS
            try:
                return 'WMI Session Error: code: 0x%x - %s' % (self.error_code, WBEMSTATUS.enumItems(self.error_code).name)
            except:
                return 'WMI SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# WMIO Structures
################################################################################
# 2.2.6 ObjectFlags
ObjectFlags = 'B=0'

#2.2.77 Signature
Signature = '<L=0x12345678'

# 2.2.4 ObjectEncodingLength
ObjectEncodingLength = '<L=0'

# 2.2.73 EncodingLength
EncodingLength = '<L=0'

# 2.2.78 Encoded-String
Encoded_String_Flag = 'B=0'

# 2.2.76 ReservedOctet
ReservedOctet = 'B=0'

# 2.2.28 NdTableValueTableLength
NdTableValueTableLength = '<L=0'

class Encoded_String(Structure):
    structure = (
        ('Encoded_String_Flag', Encoded_String_Flag),
        ('Character', 'z'),
    )

# 2.2.8 DecServerName
DecServerName = Encoded_String
# 2.2.9 DecNamespaceName
DecNamespaceName = Encoded_String

# 2.2.7 Decoration
class Decoration(Structure):
    structure = (
        ('DecServerName', ':', DecServerName),
        ('DecNamespaceName', ':', DecNamespaceName),
    )


# 2.2.69 HeapRef
HeapRef = '<L=0'

# 2.2.68 HeapStringRef
HeapStringRef = HeapRef

# 2.2.19 ClassNameRef
ClassNameRef = HeapStringRef

# 2.2.16 ClassHeader
class ClassHeader(Structure):
    structure = (
        ('EncodingLength', EncodingLength),
        ('ReservedOctet', ReservedOctet),
        ('ClassNameRef', ClassNameRef),
        ('NdTableValueTableLength', NdTableValueTableLength),
    )

# 2.2.17 DerivationList
class DerivationList(Structure):
    structure = (
        ('EncodingLength', EncodingLength),
        ('_ClassNameEncoding','_-ClassNameEncoding', 'self["EncodingLength"]-4'),
        ('ClassNameEncoding', ':'),
    )

# 2.2.59 QualifierSet
class QualifierSet(Structure):
    structure = (
        ('EncodingLength', EncodingLength),
        ('_Qualifier','_-Qualifier', 'self["EncodingLength"]-4'),
        ('Qualifier', ':'),
    )
      
# 2.2.20 ClassQualifierSet
ClassQualifierSet = QualifierSet

# 2.2.22 PropertyCount
PropertyCount = '<L=0'

# 2.2.24 PropertyNameRef
PropertyNameRef = HeapStringRef

# 2.2.25 PropertyInfoRef
PropertyInfoRef = HeapRef

# 2.2.23 PropertyLookup
class PropertyLookup(Structure):
    structure = (
        ('PropertyNameRef', PropertyNameRef),
        ('PropertyInfoRef', PropertyInfoRef),
    )

# 2.2.21 PropertyLookupTable
class PropertyLookupTable(Structure):
    PropertyLookupSize = len(PropertyLookup())
    structure = (
        ('PropertyCount', PropertyCount),
        ('_PropertyLookup','_-PropertyLookup', 'self["PropertyCount"]*self.PropertyLookupSize'),
        ('PropertyLookup', ':'),
    )

# 2.2.66 Heap
HeapLength = '<L=0'

class Heap(Structure):
    structure = (
        ('HeapLength', HeapLength),
        # HeapLength is a 32-bit value with the most significant bit always set 
        # (using little-endian binary encoding for the 32-bit value), so that the 
        # length is actually only 31 bits.
        ('_HeapItem','_-HeapItem', 'self["HeapLength"]&0x7fffffff'),
        ('HeapItem', ':'),
    )

# 2.2.37 ClassHeap
ClassHeap = Heap

# 2.2.15 ClassPart
class ClassPart(Structure):
    commonHdr = (
        ('ClassHeader', ':', ClassHeader),
        ('DerivationList', ':', DerivationList),
        ('ClassQualifierSet', ':', ClassQualifierSet),
        ('PropertyLookupTable', ':', PropertyLookupTable),
        ('_NdTable_ValueTable','_-NdTable_ValueTable', 'self["ClassHeader"]["NdTableValueTableLength"]'),
        ('NdTable_ValueTable',':'),
        ('ClassHeap', ':', ClassHeap),
    )
#    def __init__(self, data = None, alignment = 0):
#        Structure.__init__(self, data, alignment)
#        if data is not None:
#            # Let's first check the commonHdr
#            self.fromString(data)
#            self.structure = ()
#            if self['ClassHeader']['NdTableValueTableLength'] > 0:
#                self.structure += self.optionals+self.tail
#            else:
#                self.structure = self.tail
#            self.fromString(data)
#        else:
#            self.data = None

# 2.2.39 MethodCount
MethodCount = '<H=0'

# 2.2.40 MethodCountPadding
MethodCountPadding = '<H=0'

# 2.2.42 MethodName
MethodName = HeapStringRef

# 2.2.43 MethodFlags
MethodFlags = 'B=0'

# 2.2.44 MethodPadding
MethodPadding = "3s=''"

# 2.2.45 MethodOrigin
MethodOrigin = '<L=0'

# 2.2.47 HeapQualifierSetRef
HeapQualifierSetRef = HeapRef

# 2.2.46 MethodQualifiers
MethodQualifiers = HeapQualifierSetRef

# 2.2.51 HeapMethodSignatureBlockRef
HeapMethodSignatureBlockRef = HeapRef

# 2.2.50 MethodSignature
MethodSignature = HeapMethodSignatureBlockRef

# 2.2.48 InputSignature
InputSignature = MethodSignature

# 2.2.49 OutputSignature
OutputSignature = MethodSignature

# 2.2.52 MethodHeap
MethodHeap = Heap

# 2.2.41 MethodDescription
class MethodDescription(Structure):
    structure = (
        ('MethodName',MethodName),
        ('MethodFlags', MethodFlags),
        ('MethodPadding', MethodPadding),
        ('MethodOrigin', MethodOrigin),
        ('MethodQualifiers', MethodQualifiers),
        ('InputSignature', InputSignature),
        ('OutputSignature', OutputSignature),
    )

# 2.2.38 MethodsPart
class MethodsPart(Structure):
    MethodDescriptionSize = len(MethodDescription())
    structure = (
        ('EncodingLength',EncodingLength),
        ('MethodCount', MethodCount),
        ('MethodCountPadding', MethodCountPadding),
        ('_MethodDescription', '_-MethodDescription', 'self["MethodCount"]*self.MethodDescriptionSize'),
        ('MethodDescription', ':'),
        ('MethodHeap', ':', MethodHeap),
    )


# 2.2.14 ClassAndMethodsPart
class ClassAndMethodsPart(Structure):
    structure = (
        ('ClassPart', ':', ClassPart),
        ('MethodsPart', ':', MethodsPart),
    )

# 2.2.13 CurrentClass
CurrentClass = ClassAndMethodsPart

# 2.2.53 InstanceType
class InstanceType(Structure):
    structure = (
        ('CurrentClass', ':', CurrentClass),
        #('EncodingLength', ':', DecNamespaceName),
        #('InstanceFlags', ':', DecNamespaceName),
        #('InstanceClassName', ':', DecNamespaceName),
        #('NdTable', ':', DecNamespaceName),
        #('InstanceData', ':', DecNamespaceName),
        #('InstanceQualifierSet', ':', DecNamespaceName),
        #('InstanceHeap', ':', DecNamespaceName),
    )

# 2.2.12 ParentClass
ParentClass = ClassAndMethodsPart

# 2.2.13 CurrentClass
CurrentClass = ClassAndMethodsPart

class ClassType(Structure):
    structure = (
        ('ParentClass', ':', ParentClass),
        ('CurrentClass', ':', CurrentClass),
    )

# 2.2.5 ObjectBlock
class ObjectBlock(Structure):
    commonHdr = (
        ('ObjectFlags', ObjectFlags),
    )

    decoration = (
        ('Decoration', ':', Decoration),
    )

    instanceType = (
        ('InstanceType', ':', InstanceType),
    )

    classType = (
        ('ClassType', ':', ClassType),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is not None:
            self.structure = ()
            if ord(data[0]) & 0x4: 
                # WMIO - 2.2.6 - 0x04 If this flag is set, the object has a Decoration block.
                self.structure += self.decoration
            if ord(data[0]) & 0x01:
                # The object is a CIM class. 
                self.structure += self.classType
            else:
                self.structure += self.instanceType

            self.fromString(data)
        else:
            self.data = None


# 2.2.1 EncodingUnit
class EncodingUnit(Structure):
    structure = (
        ('Signature', Signature),
        ('ObjectEncodingLength', ObjectEncodingLength),
        ('_ObjectBlock', '_-ObjectBlock', 'self["ObjectEncodingLength"]'),
        ('ObjectBlock', ':', ObjectBlock),
    )

################################################################################
# CONSTANTS
################################################################################
# 1.9 Standards Assignments
CLSID_WbemLevel1Login     = string_to_bin('8BC3F05E-D86B-11D0-A075-00C04FB68820')
CLSID_WbemBackupRestore   = string_to_bin('C49E32C6-BC8B-11D2-85D4-00105A1F8304')
CLSID_WbemClassObject     = string_to_bin('4590F812-1D3A-11D0-891F-00AA004B2E24')

IID_IWbemLevel1Login      = uuidtup_to_bin(('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0'))
IID_IWbemLoginClientID    = uuidtup_to_bin(('d4781cd6-e5d3-44df-ad94-930efe48a887', '0.0'))
IID_IWbemLoginHelper      = uuidtup_to_bin(('541679AB-2E5F-11d3-B34E-00104BCC4B4A', '0.0'))
IID_IWbemServices         = uuidtup_to_bin(('9556DC99-828C-11CF-A37E-00AA003240C7', '0.0'))
IID_IWbemBackupRestore    = uuidtup_to_bin(('C49E32C7-BC8B-11d2-85D4-00105A1F8304', '0.0'))
IID_IWbemBackupRestoreEx  = uuidtup_to_bin(('A359DEC5-E813-4834-8A2A-BA7F1D777D76', '0.0'))
IID_IWbemClassObject      = uuidtup_to_bin(('DC12A681-737F-11CF-884D-00AA004B2E24', '0.0'))
IID_IWbemContext          = uuidtup_to_bin(('44aca674-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IEnumWbemClassObject  = uuidtup_to_bin(('027947e1-d731-11ce-a357-000000000001', '0.0'))
IID_IWbemCallResult       = uuidtup_to_bin(('44aca675-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IWbemFetchSmartEnum   = uuidtup_to_bin(('1C1C45EE-4395-11d2-B60B-00104B703EFD', '0.0'))
IID_IWbemWCOSmartEnum     = uuidtup_to_bin(('423EC01E-2E35-11d2-B604-00104B703EFD', '0.0'))

error_status_t = ULONG

# lFlags
WBEM_FLAG_RETURN_WBEM_COMPLETE          = 0x00000000
WBEM_FLAG_UPDATE_ONLY                   = 0x00000001
WBEM_FLAG_CREATE_ONLY                   = 0x00000002
WBEM_FLAG_RETURN_IMMEDIATELY            = 0x00000010
WBEM_FLAG_UPDATE_SAFE_MODE              = 0x00000020
WBEM_FLAG_FORWARD_ONLY                  = 0x00000020
WBEM_FLAG_NO_ERROR_OBJECT               = 0x00000040
WBEM_FLAG_UPDATE_FORCE_MODE             = 0x00000040
WBEM_FLAG_SEND_STATUS                   = 0x00000080
WBEM_FLAG_ENSURE_LOCATABLE              = 0x00000100
WBEM_FLAG_DIRECT_READ                   = 0x00000200
WBEM_MASK_RESERVED_FLAGS                = 0x0001F000
WBEM_FLAG_USE_AMENDED_QUALIFIERS        = 0x00020000
WBEM_FLAG_STRONG_VALIDATION             = 0x00100000
WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001

WBEM_INFINITE = 0xffffffff

################################################################################
# STRUCTURES
################################################################################
class UCHAR_ARRAY_CV(NDRUniConformantVaryingArray):
    item = 'c'

class PUCHAR_ARRAY_CV(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY_CV),
    )

class PMInterfacePointer_ARRAY_CV(NDRUniConformantVaryingArray):
    item = PMInterfacePointer

REFGUID = PGUID

class ULONG_ARRAY(NDRUniConformantArray):
    item = ULONG

class PULONG_ARRAY(NDRPOINTER):
    referent = (
        ('Data', ULONG_ARRAY),
    )

# 2.2.5 WBEM_CHANGE_FLAG_TYPE Enumeration
class WBEM_CHANGE_FLAG_TYPE(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_CREATE_OR_UPDATE  = 0x00
        WBEM_FLAG_UPDATE_ONLY       = 0x01
        WBEM_FLAG_CREATE_ONLY       = 0x02
        WBEM_FLAG_UPDATE_SAFE_MODE  = 0x20
        WBEM_FLAG_UPDATE_FORCE_MODE = 0x40

# 2.2.6 WBEM_GENERIC_FLAG_TYPE Enumeration
class WBEM_GENERIC_FLAG_TYPE(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_RETURN_WBEM_COMPLETE   = 0x00
        WBEM_FLAG_RETURN_IMMEDIATELY     = 0x10
        WBEM_FLAG_FORWARD_ONLY           = 0x20
        WBEM_FLAG_NO_ERROR_OBJECT        = 0x40
        WBEM_FLAG_SEND_STATUS            = 0x80
        WBEM_FLAG_ENSURE_LOCATABLE       = 0x100
        WBEM_FLAG_DIRECT_READ            = 0x200
        WBEM_MASK_RESERVED_FLAGS         = 0x1F000
        WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x20000
        WBEM_FLAG_STRONG_VALIDATION      = 0x100000

# 2.2.7 WBEM_STATUS_TYPE Enumeration
class WBEM_STATUS_TYPE(NDRENUM):
    class enumItems(Enum):
        WBEM_STATUS_COMPLETE     = 0x00
        WBEM_STATUS_REQUIREMENTS = 0x01
        WBEM_STATUS_PROGRESS     = 0x02

# 2.2.8 WBEM_TIMEOUT_TYPE Enumeration
class WBEM_TIMEOUT_TYPE(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_NO_WAIT  = 0x00000000
        WBEM_INFINITE = 0xFFFFFFFF

# 2.2.9 WBEM_QUERY_FLAG_TYPE Enumeration
class WBEM_QUERY_FLAG_TYPE(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_DEEP      = 0x00000000
        WBEM_FLAG_SHALLOW   = 0x00000001
        WBEM_FLAG_PROTOTYPE = 0x00000002

# 2.2.10 WBEM_BACKUP_RESTORE_FLAGS Enumeration
class WBEM_BACKUP_RESTORE_FLAGS(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001

# 2.2.11 WBEMSTATUS Enumeration
class WBEMSTATUS(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_S_NO_ERROR                      = 0x00000000
        WBEM_S_FALSE                         = 0x00000001
        WBEM_S_TIMEDOUT                      = 0x00040004
        WBEM_S_NEW_STYLE                     = 0x000400FF
        WBEM_S_PARTIAL_RESULTS               = 0x00040010
        WBEM_E_FAILED                        = 0x80041001
        WBEM_E_NOT_FOUND                     = 0x80041002
        WBEM_E_ACCESS_DENIED                 = 0x80041003
        WBEM_E_PROVIDER_FAILURE              = 0x80041004
        WBEM_E_TYPE_MISMATCH                 = 0x80041005
        WBEM_E_OUT_OF_MEMORY                 = 0x80041006
        WBEM_E_INVALID_CONTEXT               = 0x80041007
        WBEM_E_INVALID_PARAMETER             = 0x80041008
        WBEM_E_NOT_AVAILABLE                 = 0x80041009
        WBEM_E_CRITICAL_ERROR                = 0x8004100a
        WBEM_E_NOT_SUPPORTED                 = 0x8004100c
        WBEM_E_PROVIDER_NOT_FOUND            = 0x80041011
        WBEM_E_INVALID_PROVIDER_REGISTRATION = 0x80041012
        WBEM_E_PROVIDER_LOAD_FAILURE         = 0x80041013
        WBEM_E_INITIALIZATION_FAILURE        = 0x80041014
        WBEM_E_TRANSPORT_FAILURE             = 0x80041015
        WBEM_E_INVALID_OPERATION             = 0x80041016
        WBEM_E_ALREADY_EXISTS                = 0x80041019
        WBEM_E_UNEXPECTED                    = 0x8004101d
        WBEM_E_INCOMPLETE_CLASS              = 0x80041020
        WBEM_E_SHUTTING_DOWN                 = 0x80041033
        E_NOTIMPL                            = 0x80004001
        WBEM_E_INVALID_SUPERCLASS            = 0x8004100D
        WBEM_E_INVALID_NAMESPACE             = 0x8004100E
        WBEM_E_INVALID_OBJECT                = 0x8004100F
        WBEM_E_INVALID_CLASS                 = 0x80041010
        WBEM_E_INVALID_QUERY                 = 0x80041017
        WBEM_E_INVALID_QUERY_TYPE            = 0x80041018
        WBEM_E_PROVIDER_NOT_CAPABLE          = 0x80041024
        WBEM_E_CLASS_HAS_CHILDREN            = 0x80041025
        WBEM_E_CLASS_HAS_INSTANCES           = 0x80041026
        WBEM_E_ILLEGAL_NULL                  = 0x80041028
        WBEM_E_INVALID_CIM_TYPE              = 0x8004102D
        WBEM_E_INVALID_METHOD                = 0x8004102E
        WBEM_E_INVALID_METHOD_PARAMETERS     = 0x8004102F
        WBEM_E_INVALID_PROPERTY              = 0x80041031
        WBEM_E_CALL_CANCELLED                = 0x80041032
        WBEM_E_INVALID_OBJECT_PATH           = 0x8004103A
        WBEM_E_OUT_OF_DISK_SPACE             = 0x8004103B
        WBEM_E_UNSUPPORTED_PUT_EXTENSION     = 0x8004103D
        WBEM_E_QUOTA_VIOLATION               = 0x8004106c
        WBEM_E_SERVER_TOO_BUSY               = 0x80041045
        WBEM_E_METHOD_NOT_IMPLEMENTED        = 0x80041055
        WBEM_E_METHOD_DISABLED               = 0x80041056
        WBEM_E_UNPARSABLE_QUERY              = 0x80041058
        WBEM_E_NOT_EVENT_CLASS               = 0x80041059
        WBEM_E_MISSING_GROUP_WITHIN          = 0x8004105A
        WBEM_E_MISSING_AGGREGATION_LIST      = 0x8004105B
        WBEM_E_PROPERTY_NOT_AN_OBJECT        = 0x8004105c
        WBEM_E_AGGREGATING_BY_OBJECT         = 0x8004105d
        WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING= 0x80041060
        WBEM_E_QUEUE_OVERFLOW                = 0x80041061
        WBEM_E_PRIVILEGE_NOT_HELD            = 0x80041062
        WBEM_E_INVALID_OPERATOR              = 0x80041063
        WBEM_E_CANNOT_BE_ABSTRACT            = 0x80041065
        WBEM_E_AMENDED_OBJECT                = 0x80041066
        WBEM_E_VETO_PUT                      = 0x8004107A
        WBEM_E_PROVIDER_SUSPENDED            = 0x80041081
        WBEM_E_ENCRYPTED_CONNECTION_REQUIRED = 0x80041087
        WBEM_E_PROVIDER_TIMED_OUT            = 0x80041088
        WBEM_E_NO_KEY                        = 0x80041089
        WBEM_E_PROVIDER_DISABLED             = 0x8004108a
        WBEM_E_REGISTRATION_TOO_BROAD        = 0x80042001
        WBEM_E_REGISTRATION_TOO_PRECISE      = 0x80042002

# 2.2.12 WBEM_CONNECT_OPTIONS Enumeration
class WBEM_CONNECT_OPTIONS(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_CONNECT_REPOSITORY_ONLY = 0x40
        WBEM_FLAG_CONNECT_PROVIDERS       = 0x100

# 2.2.14 ObjectArray Structure
class ObjectArray(Structure):
    structure = (
        ('dwByteOrdering', '<L=0'),
        ('abSignature', '8s="WBEMDATA"'),
        ('dwSizeOfHeader1', '<L=0x1a'),
        ('dwDataSize1', '<L=0'),
        ('dwFlags', '<L=0'),
        ('bVersion', 'B=1'),
        ('bPacketType', 'B=0'),
        ('dwSizeOfHeader2', '<L=8'),
        ('dwDataSize2', '<L', 'len(self["wbemObjects"])+12'),
        ('dwSizeOfHeader3', '<L=12'),
        ('dwDataSize3', '<L', 'len(self["dwDataSize2"])-12)'),
        ('dwNumObjects', '<L=0'),
        ('_wbemObjects', '_-wbemObjects', 'self["dwDataSize3"]'),
        ('wbemObjects', ':'),
    )

# 2.2.14.1 WBEM_DATAPACKET_OBJECT Structure
class WBEM_DATAPACKET_OBJECT(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=9'),
        ('dwSizeOfData', '<L','len(self["Object"])'),
        ('bObjectType', 'B=0'),
        ('_Object', '_-Object', 'self["dwSizeOfData"]'),
        ('Object', ':'),
    )

# 2.2.14.2 WBEMOBJECT_CLASS Structure
class WBEMOBJECT_CLASS(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=8'),
        ('dwSizeOfData', '<L','len(self["ObjectData"])'),
        ('_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'),
        ('ObjectData', ':'),
    )

# 2.2.14.3 WBEMOBJECT_INSTANCE Structure
class WBEMOBJECT_INSTANCE(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=0x18'),
        ('dwSizeOfData', '<L','len(self["ObjectData"])'),
        ('classID', '16s="\x00"*16'),
        ('_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'),
        ('ObjectData', ':'),
    )

# 2.2.14.4 WBEMOBJECT_INSTANCE_NOCLASS Structure
class WBEMOBJECT_INSTANCE_NOCLASS(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=0x18'),
        ('dwSizeOfData', '<L','len(self["ObjectData"])'),
        ('classID', '16s="\x00"*16'),
        ('_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'),
        ('ObjectData', ':'),
    )

# 2.2.15 WBEM_REFRESHED_OBJECT Structure
class WBEM_REFRESHED_OBJECT(NDRSTRUCT):
    structure = (
        ('m_lRequestId', LONG),
        ('m_lBlobType', LONG),
        ('m_lBlobLength', LONG),
        ('m_pBlob', BYTE_ARRAY),
    )

class WBEM_REFRESHED_OBJECT_ARRAY(NDRUniConformantArray):
    item = WBEM_REFRESHED_OBJECT

class PWBEM_REFRESHED_OBJECT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WBEM_REFRESHED_OBJECT_ARRAY),
    )

# 2.2.16 WBEM_INSTANCE_BLOB Enumeration
class WBEM_INSTANCE_BLOB(Structure):
    structure = (
        ('Version', '<L=0x1'),
        ('numObjects', '<L=0'),
        ('Objects', ':'),
    )

# 2.2.17 WBEM_INSTANCE_BLOB_TYPE Enumeration
class WBEM_INSTANCE_BLOB_TYPE(NDRENUM):
    # [v1_enum] type
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_CONNECT_REPOSITORY_ONLY = 0x40
        WBEM_FLAG_CONNECT_PROVIDERS       = 0x100

# 2.2.26 _WBEM_REFRESH_INFO_NON_HIPERF Structure
class _WBEM_REFRESH_INFO_NON_HIPERF(NDRSTRUCT):
    structure = (
        ('m_wszNamespace', LPWSTR),
        ('m_pTemplate', PMInterfacePointer),
    )

# 2.2.27 _WBEM_REFRESH_INFO_REMOTE Structure
class _WBEM_REFRESH_INFO_REMOTE(NDRSTRUCT):
    structure = (
        ('m_pRefresher', PMInterfacePointer),
        ('m_pTemplate', PMInterfacePointer),
        ('m_Guid', GUID),
    )

# 2.2.25 WBEM_REFRESH_TYPE Enumeration
class WBEM_REFRESH_TYPE(NDRENUM):
    class enumItems(Enum):
        WBEM_REFRESH_TYPE_INVALID       = 0
        WBEM_REFRESH_TYPE_REMOTE        = 3
        WBEM_REFRESH_TYPE_NON_HIPERF    = 6

# 2.2.28 _WBEM_REFRESH_INFO_UNION Union
class _WBEM_REFRESH_INFO_UNION(NDRUNION):
    commonHdr = (
        ('tag', LONG),
    )
    union = {
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_REMOTE    : ('m_Remote', _WBEM_REFRESH_INFO_REMOTE),
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_NON_HIPERF: ('m_NonHiPerf', _WBEM_REFRESH_INFO_NON_HIPERF),
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_INVALID   : ('m_hres', HRESULT),
    }

# 2.2.20 _WBEM_REFRESH_INFO Structure
class _WBEM_REFRESH_INFO(NDRSTRUCT):
    structure = (
        ('m_lType', LONG),
        ('m_Info', _WBEM_REFRESH_INFO_UNION),
        ('m_lCancelId', LONG),
    )

# 2.2.21 _WBEM_REFRESHER_ID Structure
class _WBEM_REFRESHER_ID(NDRSTRUCT):
    structure = (
        ('m_szMachineName', LPCSTR),
        ('m_dwProcessId', DWORD),
        ('m_guidRefresherId', GUID),
    )

# 2.2.22 _WBEM_RECONNECT_INFO Structure
class _WBEM_RECONNECT_INFO(NDRSTRUCT):
    structure = (
        ('m_lType', LPCSTR),
        ('m_pwcsPath', LPWSTR),
    )

class _WBEM_RECONNECT_INFO_ARRAY(NDRUniConformantArray):
    item = _WBEM_RECONNECT_INFO

# 2.2.23 _WBEM_RECONNECT_RESULTS Structure
class _WBEM_RECONNECT_RESULTS(NDRSTRUCT):
    structure = (
        ('m_lId', LONG),
        ('m_hr', HRESULT),
    )

class _WBEM_RECONNECT_RESULTS_ARRAY(NDRUniConformantArray):
    item = _WBEM_RECONNECT_INFO


################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1 IWbemLevel1Login Interface
# 3.1.4.1.1 IWbemLevel1Login::EstablishPosition (Opnum 3)
class IWbemLevel1Login_EstablishPosition(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', LPWSTR),
       ('reserved2', DWORD),
    )

class IWbemLevel1Login_EstablishPositionResponse(DCOMANSWER):
    structure = (
       ('LocaleVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.2 IWbemLevel1Login::RequestChallenge (Opnum 4)
class IWbemLevel1Login_RequestChallenge(DCOMCALL):
    opnum = 4
    structure = (
       ('reserved1', LPWSTR),
       ('reserved2', LPWSTR),
    )

class IWbemLevel1Login_RequestChallengeResponse(DCOMANSWER):
    structure = (
       ('reserved3', UCHAR_ARRAY_CV),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.3 IWbemLevel1Login::WBEMLogin (Opnum 5)
class IWbemLevel1Login_WBEMLogin(DCOMCALL):
    opnum = 5
    structure = (
       ('reserved1', LPWSTR),
       ('reserved2', PUCHAR_ARRAY_CV),
       ('reserved3', LONG),
       ('reserved4', PMInterfacePointer),
    )

class IWbemLevel1Login_WBEMLoginResponse(DCOMANSWER):
    structure = (
       ('reserved5', UCHAR_ARRAY_CV),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.4 IWbemLevel1Login::NTLMLogin (Opnum 6)
class IWbemLevel1Login_NTLMLogin(DCOMCALL):
    opnum = 6
    structure = (
       ('wszNetworkResource', LPWSTR),
       ('wszPreferredLocale', LPWSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemLevel1Login_NTLMLoginResponse(DCOMANSWER):
    structure = (
       ('ppNamespace', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2 IWbemObjectSink Interface Server Details
# 3.1.4.2.1 IWbemObjectSink::Indicate (Opnum 3) Server details
class IWbemObjectSink_Indicate(DCOMCALL):
    opnum = 3
    structure = (
       ('lObjectCount', LONG),
       ('apObjArray', PMInterfacePointer_ARRAY),
    )

class IWbemObjectSink_IndicateResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.2 IWbemObjectSink::SetStatus (Opnum 4) Server Details
class IWbemObjectSink_SetStatus(DCOMCALL):
    opnum = 4
    structure = (
       ('lFlags', LONG),
       ('hResult', HRESULT),
       ('strParam', BSTR),
       ('pObjParam', PMInterfacePointer),
    )

class IWbemObjectSink_SetStatusResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3 IWbemServices Interface
# 3.1.4.3.1 IWbemServices::OpenNamespace (Opnum 3)
class IWbemServices_OpenNamespace(DCOMCALL):
    opnum = 3
    structure = (
       ('strNamespace', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppWorkingNamespace', PMInterfacePointer),
       ('ppResult', PMInterfacePointer),
    )

class IWbemServices_OpenNamespaceResponse(DCOMANSWER):
    structure = (
       ('ppWorkingNamespace', PPMInterfacePointer),
       ('ppResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.2 IWbemServices::CancelAsyncCall (Opnum 4)
class IWbemServices_CancelAsyncCall(DCOMCALL):
    opnum = 4
    structure = (
       ('IWbemObjectSink', PMInterfacePointer),
    )

class IWbemServices_CancelAsyncCallResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.3 IWbemServices::QueryObjectSink (Opnum 5)
class IWbemServices_QueryObjectSink(DCOMCALL):
    opnum = 5
    structure = (
       ('lFlags', LONG),
    )

class IWbemServices_QueryObjectSinkResponse(DCOMANSWER):
    structure = (
       ('ppResponseHandler', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.4 IWbemServices::GetObject (Opnum 6)
class IWbemServices_GetObject(DCOMCALL):
    opnum = 6
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppObject', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_GetObjectResponse(DCOMANSWER):
    structure = (
       ('ppObject', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.5 IWbemServices::GetObjectAsync (Opnum 7)
class IWbemServices_GetObjectAsync(DCOMCALL):
    opnum = 7
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_GetObjectAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.6 IWbemServices::PutClass (Opnum 8)
class IWbemServices_PutClass(DCOMCALL):
    opnum = 8
    structure = (
       ('pObject', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_PutClassResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.7 IWbemServices::PutClassAsync (Opnum 9)
class IWbemServices_PutClassAsync(DCOMCALL):
    opnum = 9
    structure = (
       ('pObject', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_PutClassAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.8 IWbemServices::DeleteClass (Opnum 10)
class IWbemServices_DeleteClass(DCOMCALL):
    opnum = 10
    structure = (
       ('strClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_DeleteClassResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.9 IWbemServices::DeleteClassAsync (Opnum 11)
class IWbemServices_DeleteClassAsync(DCOMCALL):
    opnum = 11
    structure = (
       ('strClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_DeleteClassAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.10 IWbemServices::CreateClassEnum (Opnum 12)
class IWbemServices_CreateClassEnum(DCOMCALL):
    opnum = 12
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_CreateClassEnumResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.11 IWbemServices::CreateClassEnumAsync (Opnum 13)
class IWbemServices_CreateClassEnumAsync(DCOMCALL):
    opnum = 13
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_CreateClassEnumAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.12 IWbemServices::PutInstance (Opnum 14)
class IWbemServices_PutInstance(DCOMCALL):
    opnum = 14
    structure = (
       ('pInst', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_PutInstanceResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.13 IWbemServices::PutInstanceAsync (Opnum 15)
class IWbemServices_PutInstanceAsync(DCOMCALL):
    opnum = 15
    structure = (
       ('pInst', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_PutInstanceAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.14 IWbemServices::DeleteInstance (Opnum 16)
class IWbemServices_DeleteInstance(DCOMCALL):
    opnum = 16
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_DeleteInstanceResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.15 IWbemServices::DeleteInstanceAsync (Opnum 17)
class IWbemServices_DeleteInstanceAsync(DCOMCALL):
    opnum = 17
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_DeleteInstanceAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.16 IWbemServices::CreateInstanceEnum (Opnum 18)
class IWbemServices_CreateInstanceEnum(DCOMCALL):
    opnum = 18
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_CreateInstanceEnumResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.17 IWbemServices::CreateInstanceEnumAsync (Opnum 19)
class IWbemServices_CreateInstanceEnumAsync(DCOMCALL):
    opnum = 19
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_CreateInstanceEnumAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.18 IWbemServices::ExecQuery (Opnum 20)
class IWbemServices_ExecQuery(DCOMCALL):
    opnum = 20
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_ExecQueryResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.19 IWbemServices::ExecQueryAsync (Opnum 21)
class IWbemServices_ExecQueryAsync(DCOMCALL):
    opnum = 21
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQueryLanguage', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_ExecQueryAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.20 IWbemServices::ExecNotificationQuery (Opnum 22)
class IWbemServices_ExecNotificationQuery(DCOMCALL):
    opnum = 22
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQueryLanguage', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_ExecNotificationQueryResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.21 IWbemServices::ExecNotificationQueryAsync (Opnum 23)
class IWbemServices_ExecNotificationQueryAsync(DCOMCALL):
    opnum = 23
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQueryLanguage', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_ExecNotificationQueryAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.22 IWbemServices::ExecMethod (Opnum 24)
class IWbemServices_ExecMethod(DCOMCALL):
    opnum = 24
    structure = (
       ('strObjectPath', BSTR),
       ('strMethodName', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pInParams', PMInterfacePointer),
       ('ppOutParams', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_ExecMethodResponse(DCOMANSWER):
    structure = (
       ('ppOutParams', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.23 IWbemServices::ExecMethodAsync (Opnum 25)
class IWbemServices_ExecMethodAsync(DCOMCALL):
    opnum = 25
    structure = (
       ('strObjectPath', BSTR),
       ('strMethodName', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pInParams', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_ExecMethodResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4 IEnumWbemClassObject Interface
# 3.1.4.4.1 IEnumWbemClassObject::Reset (Opnum 3)
class IEnumWbemClassObject_Reset(DCOMCALL):
    opnum = 3
    structure = (
    )

class IEnumWbemClassObject_ResetResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.2 IEnumWbemClassObject::Next (Opnum 4)
class IEnumWbemClassObject_Next(DCOMCALL):
    opnum = 4
    structure = (
       ('lTimeout', LONG),
       ('uCount', ULONG),
    )

class IEnumWbemClassObject_NextResponse(DCOMANSWER):
    structure = (
       ('apObjects', PMInterfacePointer_ARRAY_CV),
       ('puReturned', ULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.3 IEnumWbemClassObject::NextAsync (Opnum 5)
class IEnumWbemClassObject_NextAsync(DCOMCALL):
    opnum = 5
    structure = (
       ('lTimeout', LONG),
       ('pSink', PMInterfacePointer),
    )

class IEnumWbemClassObject_NextAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.4 IEnumWbemClassObject::Clone (Opnum 6)
class IEnumWbemClassObject_Clone(DCOMCALL):
    opnum = 6
    structure = (
    )

class IEnumWbemClassObject_CloneResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.5 IEnumWbemClassObject::Skip (Opnum 7)
class IEnumWbemClassObject_Skip(DCOMCALL):
    opnum = 7
    structure = (
       ('lTimeout', LONG),
       ('uCount', ULONG),
    )

class IEnumWbemClassObject_SkipResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5 IWbemCallResult Interface
# 3.1.4.5.1 IWbemCallResult::GetResultObject (Opnum 3)
class IWbemCallResult_GetResultObject(DCOMCALL):
    opnum = 3
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetResultObjectResponse(DCOMANSWER):
    structure = (
       ('ppResultObject', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5.2 IWbemCallResult::GetResultString (Opnum 4)
class IWbemCallResult_GetResultString(DCOMCALL):
    opnum = 4
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetResultStringResponse(DCOMANSWER):
    structure = (
       ('pstrResultString', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5.3 IWbemCallResult::GetResultServices (Opnum 5)
class IWbemCallResult_GetResultServices(DCOMCALL):
    opnum = 5
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetResultServicesResponse(DCOMANSWER):
    structure = (
       ('ppServices', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5.4 IWbemCallResult::GetCallStatus (Opnum 6)
class IWbemCallResult_GetCallStatus(DCOMCALL):
    opnum = 6
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetCallStatusResponse(DCOMANSWER):
    structure = (
       ('plStatus', LONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.6 IWbemFetchSmartEnum Interface
# 3.1.4.6.1 IWbemFetchSmartEnum::GetSmartEnum (Opnum 3)
class IWbemCallResult_GetSmartEnum(DCOMCALL):
    opnum = 3
    structure = (
    )

class IWbemCallResult_GetSmartEnumResponse(DCOMANSWER):
    structure = (
       ('ppSmartEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.7 IWbemWCOSmartEnum Interface
# 3.1.4.7.1 IWbemWCOSmartEnum::Next (Opnum 3)
class IWbemWCOSmartEnum_Next(DCOMCALL):
    opnum = 3
    structure = (
       ('proxyGUID', REFGUID),
       ('lTimeout', LONG),
       ('uCount', ULONG),
    )

class IWbemWCOSmartEnum_NextResponse(DCOMANSWER):
    structure = (
       ('puReturned', ULONG),
       ('pdwBuffSize', ULONG),
       ('pBuffer', BYTE_ARRAY),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.8 IWbemLoginClientID Interface
# 3.1.4.8.1 IWbemLoginClientID::SetClientInfo (Opnum 3)
class IWbemLoginClientID_SetClientInfo(DCOMCALL):
    opnum = 3
    structure = (
       ('wszClientMachine', LPWSTR),
       ('lClientProcId', LONG),
       ('lReserved', LONG),
    )

class IWbemLoginClientID_SetClientInfoResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9 IWbemLoginHelper Interface
# 3.1.4.9.1 IWbemLoginHelper::SetEvent (Opnum 3)
class IWbemLoginHelper_SetEvent(DCOMCALL):
    opnum = 3
    structure = (
       ('sEventToSet', LPCSTR),
    )

class IWbemLoginHelper_SetEventResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# 3.1.4.10 IWbemBackupRestore Interface
# 3.1.4.10.1 IWbemBackupRestore::Backup (Opnum 3)
class IWbemBackupRestore_Backup(DCOMCALL):
    opnum = 3
    structure = (
       ('strBackupToFile', LPWSTR),
       ('lFlags', LONG),
    )

class IWbemBackupRestore_BackupResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.10.2 IWbemBackupRestore::Restore (Opnum 4)
class IWbemBackupRestore_Restore(DCOMCALL):
    opnum = 4
    structure = (
       ('strRestoreFromFile', LPWSTR),
       ('lFlags', LONG),
    )

class IWbemBackupRestore_RestoreResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.11 IWbemBackupRestoreEx Interface
# 3.1.4.11.1 IWbemBackupRestoreEx::Pause (Opnum 5)
class IWbemBackupRestoreEx_Pause(DCOMCALL):
    opnum = 5
    structure = (
    )

class IWbemBackupRestoreEx_PauseResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.11.2 IWbemBackupRestoreEx::Resume (Opnum 6)
class IWbemBackupRestoreEx_Resume(DCOMCALL):
    opnum = 6
    structure = (
    )

class IWbemBackupRestoreEx_ResumeResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.12 IWbemRefreshingServices Interface
# 3.1.4.12.1 IWbemRefreshingServices::AddObjectToRefresher (Opnum 3)
class IWbemRefreshingServices_AddObjectToRefresher(DCOMCALL):
    opnum = 3
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('wszPath', LPWSTR),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_AddObjectToRefresherResponse(DCOMANSWER):
    structure = (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.12.2 IWbemRefreshingServices::AddObjectToRefresherByTemplate (Opnum 4)
class IWbemRefreshingServices_AddObjectToRefresherByTemplate(DCOMCALL):
    opnum = 4
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('pTemplate', PMInterfacePointer),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_AddObjectToRefresherByTemplateResponse(DCOMANSWER):
    structure = (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.12.3 IWbemRefreshingServices::AddEnumToRefresher (Opnum 5)
class IWbemRefreshingServices_AddEnumToRefresher(DCOMCALL):
    opnum = 5
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('wszClass', LPWSTR),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_AddEnumToRefresherResponse(DCOMANSWER):
    structure = (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.12.4 IWbemRefreshingServices::RemoveObjectFromRefresher (Opnum 6)
class IWbemRefreshingServices_RemoveObjectFromRefresher(DCOMCALL):
    opnum = 6
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lId', LONG),
       ('lFlags', LONG),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_RemoveObjectFromRefresherResponse(DCOMANSWER):
    structure = (
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.12.5 IWbemRefreshingServices::GetRemoteRefresher (Opnum 7)
class IWbemRefreshingServices_GetRemoteRefresher(DCOMCALL):
    opnum = 7
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lFlags', LONG),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_GetRemoteRefresherResponse(DCOMANSWER):
    structure = (
       ('ppRemRefresher', PMInterfacePointer),
       ('pGuid', GUID),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.12.6 IWbemRefreshingServices::ReconnectRemoteRefresher (Opnum 8)
class IWbemRefreshingServices_ReconnectRemoteRefresher(DCOMCALL):
    opnum = 8
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lFlags', LONG),
       ('lNumObjects', LONG),
       ('dwClientRefrVersion', DWORD),
       ('apReconnectInfo', _WBEM_RECONNECT_INFO_ARRAY),
    )

class IWbemRefreshingServices_ReconnectRemoteRefresherResponse(DCOMANSWER):
    structure = (
       ('apReconnectResults', _WBEM_RECONNECT_RESULTS_ARRAY),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.13 IWbemRemoteRefresher Interface
# 3.1.4.13.1 IWbemRemoteRefresher::RemoteRefresh (Opnum 3)
class IWbemRemoteRefresher_RemoteRefresh(DCOMCALL):
    opnum = 3
    structure = (
       ('lFlags', LONG),
    )

class IWbemRemoteRefresher_RemoteRefreshResponse(DCOMANSWER):
    structure = (
       ('plNumObjects', _WBEM_RECONNECT_RESULTS_ARRAY),
       ('paObjects', PWBEM_REFRESHED_OBJECT_ARRAY),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.13.2 IWbemRemoteRefresher::StopRefreshing (Opnum 4)
class IWbemRemoteRefresher_StopRefreshing(DCOMCALL):
    opnum = 4
    structure = (
       ('lNumIds', LONG),
       ('aplIds', PULONG_ARRAY),
       ('lFlags', LONG),
    )

class IWbemRemoteRefresher_StopRefreshingResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.14 IWbemShutdown Interface
# 3.1.4.14.1 IWbemShutdown::Shutdown (Opnum 3)
class IWbemShutdown_Shutdown(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', LONG),
       ('reserved2', ULONG),
       ('reserved3', PMInterfacePointer),
    )

class IWbemShutdown_ShutdownResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.15 IUnsecuredApartment Interface
# 3.1.4.15.1 IUnsecuredApartment::CreateObjectStub (Opnum 3)
class IUnsecuredApartment_CreateObjectStub(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', PMInterfacePointer),
    )

class IUnsecuredApartment_CreateObjectStubResponse(DCOMANSWER):
    structure = (
       ('reserved2', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.16 IWbemUnsecuredApartment Interface
# 3.1.4.16.1 IWbemUnsecuredApartment::CreateSinkStub (Opnum 3)
class IWbemUnsecuredApartment_CreateSinkStub(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', PMInterfacePointer),
       ('reserved2', DWORD),
       ('reserved3', LPWSTR),
    )

class IWbemUnsecuredApartment_CreateSinkStubResponse(DCOMANSWER):
    structure = (
       ('reserved4', PMInterfacePointer),
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
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

class IWbemClassObject(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemClassObject
        objRef = self.get_objRef()
        objRef = OBJREF_CUSTOM(objRef)
        from impacket.winregistry import hexdump
        #hexdump(objRef['pObjectData'])
        encodingUnit = EncodingUnit(objRef['pObjectData'])
        encodingUnit.dump()
        #instanceType = InstanceType(objectBlock['Encoding'])
        #instanceType.dump()
 

class IWbemLoginClientID(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLoginClientID

    def SetClientInfo(self, wszClientMachine, lClientProcId = 1234):
        request = IWbemLoginClientID_SetClientInfo()
        request['wszClientMachine'] = checkNullString(wszClientMachine)
        request['lClientProcId'] = lClientProcId
        request['lReserved'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

class IWbemLoginHelper(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLoginHelper

    def SetEvent(self, sEventToSet):
        request = IWbemLoginHelper_SetEvent()
        request['sEventToSet'] = sEventToSet
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp


class IWbemWCOSmartEnum(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemWCOSmartEnum

    def Next(self, proxyGUID, lTimeout, uCount):
        request = IWbemWCOSmartEnum_Next()
        request['proxyGUID'] = proxyGUID
        request['lTimeout'] = lTimeout
        request['uCount'] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemFetchSmartEnum(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemFetchSmartEnum

    def GetSmartEnum(self, lTimeout):
        request = IWbemFetchSmartEnum_GetSmartEnum()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemCallResult(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemCallResult

    def GetResultObject(self, lTimeout):
        request = IWbemCallResult_GetResultObject()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetResultString(self, lTimeout):
        request = IWbemCallResult_GetResultString()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetResultServices(self, lTimeout):
        request = IWbemCallResult_GetResultServices()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetCallStatus(self, lTimeout):
        request = IWbemCallResult_GetCallStatus()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp['plStatus']

class IEnumWbemClassObject(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IEnumWbemClassObject

    def Reset(self):
        request = IEnumWbemClassObject_Reset()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def Next(self, lTimeout, uCount):
        request = IEnumWbemClassObject_Next()
        request['lTimeout'] = lTimeout
        request['uCount'] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        #resp.dump()
        interfaces = list()
        for interface in resp['apObjects']:
            interfaces.append( IWbemClassObject(INTERFACE(self.get_cinstance(), ''.join(interface['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip())) )

        return interfaces

    def NextAsync(self, lTimeout, pSink):
        request = IEnumWbemClassObject_NextAsync()
        request['lTimeout'] = lTimeout
        request['pSink'] = pSink
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def Clone(self):
        request = IEnumWbemClassObject_Clone()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def Skip(self, lTimeout, uCount):
        request = IEnumWbemClassObject_Skip()
        request['lTimeout'] = lTimeout
        request['uCount'] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemServices(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemServices

    def OpenNamespace(self, strNamespace, lFlags=0, pCtx = NULL):
        request = IWbemServices_OpenNamespace()
        request['strNamespace']['asData'] = strNamespace
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CancelAsyncCall(self,IWbemObjectSink ):
        request = IWbemServices_CancelAsyncCall()
        request['IWbemObjectSink'] = IWbemObjectSink
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['ErrorCode']

    def QueryObjectSink(self):
        request = IWbemServices_QueryObjectSink()
        request['lFlags'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return  (INTERFACE(self.get_cinstance(), ''.join(resp['ppResponseHandler']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip()))

    def GetObject(self, strObjectPath, lFlags=0, pCtx=NULL):
        request = IWbemServices_GetObject()
        request['strObjectPath']['asData'] = strObjectPath
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        ppObject =  IWbemClassObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppObject']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip()))
        if resp['ppCallResult'] != NULL:
            ppcallResult = IWbemCallResult(INTERFACE(self.get_cinstance(), ''.join(resp['ppObject']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip()))
        else:
            ppcallResult = NULL
        return ppObject, ppcallResult

    def GetObjectAsync(self, strObjectPath, lFlags=0, pCtx = NULL):
        request = IWbemServices_GetObjectAsync()
        request['strObjectPath']['asData'] = checkNullString(strNamespace)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutClass(self, pObject, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutClass()
        request['pObject'] = pObject
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutClassAsync(self, pObject, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutClassAsync()
        request['pObject'] = pObject
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteClass(self, strClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteClass()
        request['strClass']['asData'] = checkNullString(strClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteClassAsync(self, strClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteClassAsync()
        request['strClass']['asData'] = checkNullString(strClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CreateClassEnum(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateClassEnum()
        request['strSuperClass']['asData'] = checkNullString(strSuperClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CreateClassEnumAsync(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateClassEnumAsync()
        request['strSuperClass']['asData'] = checkNullString(strSuperClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutInstance(self, pInst, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutInstance()
        request['pInst'] = pInst
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutInstanceAsync(self, pInst, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutInstanceAsync()
        request['pInst'] = pInst
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteInstance(self, strObjectPath, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteInstance()
        request['strObjectPath']['asData'] = checkNullString(strObjectPath)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteInstanceAsync(self, strObjectPath, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteInstanceAsync()
        request['strObjectPath']['asData'] = checkNullString(strObjectPath)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CreateInstanceEnum(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateInstanceEnum()
        request['strSuperClass']['asData'] = strSuperClass
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return IEnumWbemClassObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip()))

    def CreateInstanceEnumAsync(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateInstanceEnumAsync()
        request['strSuperClass']['asData'] = checkNullString(strSuperClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecQuery(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecQuery()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumWbemClassObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip()))

    def ExecQueryAsync(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecQueryAsync()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecNotificationQuery(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecNotificationQuery()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecNotificationQueryAsync(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecNotificationQueryAsync()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecMethod(self, strObjectPath, strMethodName, lFlags=0, pCtx=NULL, pInParams=NULL):
        request = IWbemServices_ExecMethod()
        request['strObjectPath']['asData'] = checkNullString('strObjectPath')
        request['strMethodName']['asData'] = checkNullString('strMethodName')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        request['pInParams'] = pInParams
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecMethodAsync(self, strObjectPath, strMethodName, lFlags=0, pCtx=NULL, pInParams=NULL):
        request = IWbemServices_ExecMethodAsync()
        request['strObjectPath']['asData'] = checkNullString('strObjectPath')
        request['strMethodName']['asData'] = checkNullString('strMethodName')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        request['pInParams'] = pInParams
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemLevel1Login(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLevel1Login

    def EstablishPosition(self):
        request = IWbemLevel1Login_EstablishPosition()
        request['reserved1'] = NULL
        request['reserved2'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['LocaleVersion']

    def RequestChallenge(self):
        request = IWbemLevel1Login_RequestChallenge()
        request['reserved1'] = NULL
        request['reserved2'] = NULL
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['reserved3']

    def WBEMLogin(self):
        request = IWbemLevel1Login_NTLMLogin()
        request['reserved1'] = NULL
        request['reserved2'] = NULL
        request['reserved3'] = 0
        request['reserved4'] = NULL
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['reserved5']

    def NTLMLogin(self, wszNetworkResource, wszPreferredLocale, pCtx):
        request = IWbemLevel1Login_NTLMLogin()
        request['wszNetworkResource'] = checkNullString(wszNetworkResource)
        request['wszPreferredLocale'] = checkNullString(wszPreferredLocale)
        request['lFlags'] = 0
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return  IWbemServices(INTERFACE(self.get_cinstance(), ''.join(resp['ppNamespace']['abData']), self.get_ipidRemUnknown(), targetIP = self.get_target_ip(), dce = self.get_dce_rpc()))


if __name__ == '__main__':

    # Example 1
    baseClass = '\x78\x56\x34\x12\xD0\x00\x00\x00\x05\x00\x44\x50\x52\x41\x56\x41\x54\x2D\x44\x45\x56\x00\x00\x52\x4F\x4F\x54\x00\x1D\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x66\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x0A\x00\x00\x00\x05\xFF\xFF\xFF\xFF\x3C\x00\x00\x80\x00\x42\x61\x73\x65\x00\x00\x49\x64\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1C\x00\x00\x00\x0A\x00\x00\x80\x03\x08\x00\x00\x00\x34\x00\x00\x00\x01\x00\x00\x80\x13\x0B\x00\x00\x00\xFF\xFF\x00\x73\x69\x6E\x74\x33\x32\x00\x0C\x00\x00\x00\x00\x00\x34\x00\x00\x00\x00\x80\x00\x80\x13\x0B\x00\x00\x00\xFF\xFF\x00\x73\x69\x6E\x74\x33\x32\x00'

    encodingUnit = EncodingUnit(baseClass)
    encodingUnit.dump()
