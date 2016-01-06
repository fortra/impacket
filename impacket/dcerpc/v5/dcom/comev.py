# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-COMEV]: Component Object Model Plus (COM+) Event System Protocol. 
#               This was used as a way to test the DCOM runtime. Further 
#               testing is needed to verify it is working as expected
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/CoreSecurity/impacket/tree/master/impacket/testcases/SMB_RPC
#
#   Since DCOM is like an OO RPC, instead of helper functions you will see the 
#   classes described in the standards developed. 
#   There are test cases for them too. 
#
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRENUM, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, INTERFACE, PMInterfacePointer, IRemUnknown
from impacket.dcerpc.v5.dcom.oaut import IDispatch, BSTR, VARIANT
from impacket.dcerpc.v5.dtypes import INT, ULONG, LONG, BOOLEAN
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.enum import Enum
from impacket import hresult_errors
from impacket.uuid import string_to_bin, uuidtup_to_bin

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        if hresult_errors.ERROR_MESSAGES.has_key(self.error_code):
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'COMEV SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'COMEV SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 1.9 Standards Assignments
CLSID_EventSystem          = string_to_bin('4E14FBA2-2E22-11D1-9964-00C04FBBB345')
CLSID_EventSystem2         = string_to_bin('99CC098F-A48A-4e9c-8E58-965C0AFC19D5')
CLSID_EventClass           = string_to_bin('cdbec9c0-7a68-11d1-88f9-0080c7d771bf')
CLSID_EventSubscription    = string_to_bin('7542e960-79c7-11d1-88f9-0080c7d771bf')
GUID_DefaultAppPartition   = string_to_bin('41E90F3E-56C1-4633-81C3-6E8BAC8BDD70')
IID_IEventSystem           = uuidtup_to_bin(('4E14FB9F-2E22-11D1-9964-00C04FBBB345','0.0'))
IID_IEventSystem2          = uuidtup_to_bin(('99CC098F-A48A-4e9c-8E58-965C0AFC19D5','0.0'))
IID_IEventSystemInitialize = uuidtup_to_bin(('a0e8f27a-888c-11d1-b763-00c04fb926af','0.0'))
IID_IEventObjectCollection = uuidtup_to_bin(('f89ac270-d4eb-11d1-b682-00805fc79216','0.0'))
IID_IEnumEventObject       = uuidtup_to_bin(('F4A07D63-2E25-11D1-9964-00C04FBBB345','0.0'))
IID_IEventSubscription     = uuidtup_to_bin(('4A6B0E15-2E38-11D1-9965-00C04FBBB345','0.0'))
IID_IEventSubscription2    = uuidtup_to_bin(('4A6B0E16-2E38-11D1-9965-00C04FBBB345','0.0'))
IID_IEventSubscription3    = uuidtup_to_bin(('FBC1D17D-C498-43a0-81AF-423DDD530AF6','0.0'))
IID_IEventClass            = uuidtup_to_bin(('fb2b72a0-7a68-11d1-88f9-0080c7d771bf','0.0'))
IID_IEventClass2           = uuidtup_to_bin(('fb2b72a1-7a68-11d1-88f9-0080c7d771bf','0.0'))
IID_IEventClass3           = uuidtup_to_bin(('7FB7EA43-2D76-4ea8-8CD9-3DECC270295E','0.0'))

error_status_t = ULONG

# 2.2.2.2 Property Value Types
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
        VT_UINT_PTR     = 7

################################################################################
# STRUCTURES
################################################################################
# 2.2.44 TYPEATTR
class TYPEATTR(NDRSTRUCT):
    structure = (
    )

class OBJECT_ARRAY(NDRUniConformantVaryingArray):
    item = PMInterfacePointer

################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1 IEventSystem
# 3.1.4.1.1 Query (Opnum 7)
class IEventSystem_Query(DCOMCALL):
    opnum = 7
    structure = (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    )

class IEventSystem_QueryResponse(DCOMANSWER):
    structure = (
       ('errorIndex', INT),
       ('ppInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.2 Store (Opnum 8)
class IEventSystem_Store(DCOMCALL):
    opnum = 8
    structure = (
       ('progID', BSTR),
       ('pInterface', PMInterfacePointer),
    )

class IEventSystem_StoreResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.3 Remove (Opnum 9)
class IEventSystem_Remove(DCOMCALL):
    opnum = 9
    structure = (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    )

class IEventSystem_RemoveResponse(DCOMANSWER):
    structure = (
       ('errorIndex', INT),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.4 get_EventObjectChangeEventClassID (Opnum 10)
class IEventSystem_get_EventObjectChangeEventClassID(DCOMCALL):
    opnum = 10
    structure = (
    )

class IEventSystem_get_EventObjectChangeEventClassIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.5 QueryS (Opnum 11)
class IEventSystem_QueryS(DCOMCALL):
    opnum = 11
    structure = (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    )

class IEventSystem_QuerySResponse(DCOMANSWER):
    structure = (
       ('pInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.1.6 RemoveS (Opnum 12)
class IEventSystem_RemoveS(DCOMCALL):
    opnum = 12
    structure = (
       ('progID', BSTR),
       ('queryCriteria', BSTR),
    )

class IEventSystem_RemoveSResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.2 IEventClass
# 3.1.4.2.1 get_EventClassID (Opnum 7)
class IEventClass_get_EventClassID(DCOMCALL):
    opnum = 7
    structure = (
    )

class IEventClass_get_EventClassIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.2 put_EventClassID (Opnum 8)
class IEventClass_put_EventClassID(DCOMCALL):
    opnum = 8
    structure = (
       ('bstrEventClassID', BSTR),
    )

class IEventClass_put_EventClassIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.3 get_EventClassName (Opnum 9)
class IEventClass_get_EventClassName(DCOMCALL):
    opnum = 9
    structure = (
    )

class IEventClass_get_EventClassNameResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassName', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.4 put_EventClassName (Opnum 10)
class IEventClass_put_EventClassName(DCOMCALL):
    opnum = 10
    structure = (
       ('bstrEventClassName', BSTR),
    )

class IEventClass_put_EventClassNameResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.5 get_OwnerSID (Opnum 11)
class IEventClass_get_OwnerSID(DCOMCALL):
    opnum = 11
    structure = (
    )

class IEventClass_get_OwnerSIDResponse(DCOMANSWER):
    structure = (
       ('pbstrOwnerSID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.6 put_OwnerSID (Opnum 12)
class IEventClass_put_OwnerSID(DCOMCALL):
    opnum = 12
    structure = (
       ('bstrOwnerSID', BSTR),
    )

class IEventClass_put_OwnerSIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.7 get_FiringInterfaceID (Opnum 13)
class IEventClass_get_FiringInterfaceID(DCOMCALL):
    opnum = 13
    structure = (
    )

class IEventClass_get_FiringInterfaceIDResponse(DCOMANSWER):
    structure = (
       ('pbstrFiringInterfaceID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.8 put_FiringInterfaceID (Opnum 14)
class IEventClass_put_FiringInterfaceID(DCOMCALL):
    opnum = 14
    structure = (
       ('bstrFiringInterfaceID', BSTR),
    )

class IEventClass_put_FiringInterfaceIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.9 get_Description (Opnum 15)
class IEventClass_get_Description(DCOMCALL):
    opnum = 15
    structure = (
    )

class IEventClass_get_DescriptionResponse(DCOMANSWER):
    structure = (
       ('pbstrDescription', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.10 put_Description (Opnum 16)
class IEventClass_put_Description(DCOMCALL):
    opnum = 16
    structure = (
       ('bstrDescription', BSTR),
    )

class IEventClass_put_DescriptionResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.11 get_TypeLib (Opnum 19)
class IEventClass_get_TypeLib(DCOMCALL):
    opnum = 19
    structure = (
    )

class IEventClass_get_TypeLibResponse(DCOMANSWER):
    structure = (
       ('pbstrTypeLib', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.2.12 put_TypeLib (Opnum 20)
class IEventClass_put_TypeLib(DCOMCALL):
    opnum = 20
    structure = (
       ('bstrTypeLib', BSTR),
    )

class IEventClass_put_TypeLibResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.3 IEventClass2
# 3.1.4.3.1 get_PublisherID (Opnum 21)
class IEventClass2_get_PublisherID(DCOMCALL):
    opnum = 21
    structure = (
    )

class IEventClass2_get_PublisherIDResponse(DCOMANSWER):
    structure = (
       ('pbstrSubscriptionID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.2 put_PublisherID (Opnum 22)
class IEventClass2_put_PublisherID(DCOMCALL):
    opnum = 22
    structure = (
       ('bstrPublisherID', BSTR),
    )

class IEventClass2_put_PublisherIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.3 get_MultiInterfacePublisherFilterCLSID (Opnum 23)
class IEventClass2_get_MultiInterfacePublisherFilterCLSID(DCOMCALL):
    opnum = 23
    structure = (
    )

class IEventClass2_get_MultiInterfacePublisherFilterCLSIDResponse(DCOMANSWER):
    structure = (
       ('pbstrPubFilCLSID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.4 put_MultiInterfacePublisherFilterCLSID (Opnum 24)
class IEventClass2_put_MultiInterfacePublisherFilterCLSID(DCOMCALL):
    opnum = 24
    structure = (
       ('bstrPubFilCLSID', BSTR),
    )

class IEventClass2_put_MultiInterfacePublisherFilterCLSIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.5 get_AllowInprocActivation (Opnum 25)
class IEventClass2_get_AllowInprocActivation(DCOMCALL):
    opnum = 25
    structure = (
    )

class IEventClass2_get_AllowInprocActivationResponse(DCOMANSWER):
    structure = (
       ('pfAllowInprocActivation', BOOLEAN),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.6 put_AllowInprocActivation (Opnum 26)
class IEventClass2_put_AllowInprocActivation(DCOMCALL):
    opnum = 26
    structure = (
       ('fAllowInprocActivation', BOOLEAN),
    )

class IEventClass2_put_AllowInprocActivationResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.7 get_FireInParallel (Opnum 27)
class IEventClass2_get_FireInParallel(DCOMCALL):
    opnum = 27
    structure = (
    )

class IEventClass2_get_FireInParallelResponse(DCOMANSWER):
    structure = (
       ('pfFireInParallel', BOOLEAN),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.3.8 put_FireInParallel (Opnum 28)
class IEventClass2_put_FireInParallel(DCOMCALL):
    opnum = 28
    structure = (
       ('pfFireInParallel', BOOLEAN),
    )

class IEventClass2_put_FireInParallelResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.4 IEventSubscription
# 3.1.4.4.1 get_SubscriptionID (Opnum 7)
class IEventSubscription_get_SubscriptionID(DCOMCALL):
    opnum = 7
    structure = (
    )

class IEventSubscription_get_SubscriptionIDResponse(DCOMANSWER):
    structure = (
       ('pbstrSubscriptionID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.2 put_SubscriptionID (Opnum 8)
class IEventSubscription_put_SubscriptionID(DCOMCALL):
    opnum = 8
    structure = (
       ('bstrSubscriptionID', BSTR),
    )

class IEventSubscription_put_SubscriptionIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.3 get_SubscriptionName (Opnum 9)
class IEventSubscription_get_SubscriptionName(DCOMCALL):
    opnum = 9
    structure = (
    )

class IEventSubscription_get_SubscriptionNameResponse(DCOMANSWER):
    structure = (
       ('pbstrSubscriptionName', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.4 put_SubscriptionName (Opnum 10)
class IEventSubscription_put_SubscriptionName(DCOMCALL):
    opnum = 10
    structure = (
       ('strSubscriptionID', BSTR),
    )

class IEventSubscription_put_SubscriptionNameResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.5 get_PublisherID (Opnum 11)
class IEventSubscription_get_PublisherID(DCOMCALL):
    opnum = 11
    structure = (
    )

class IEventSubscription_get_PublisherIDResponse(DCOMANSWER):
    structure = (
       ('pbstrPublisherID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.6 put_PublisherID (Opnum 12)
class IEventSubscription_put_PublisherID(DCOMCALL):
    opnum = 12
    structure = (
       ('bstrPublisherID', BSTR),
    )

class IEventSubscription_put_PublisherIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.7 get_EventClassID (Opnum 13)
class IEventSubscription_get_EventClassID(DCOMCALL):
    opnum = 13
    structure = (
    )

class IEventSubscription_get_EventClassIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.8 put_EventClassID (Opnum 14)
class IEventSubscription_put_EventClassID(DCOMCALL):
    opnum = 14
    structure = (
       ('bstrEventClassID', BSTR),
    )

class IEventSubscription_put_EventClassIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.9 get_MethodName (Opnum 15)
class IEventSubscription_get_MethodName(DCOMCALL):
    opnum = 15
    structure = (
    )

class IEventSubscription_get_MethodNameResponse(DCOMANSWER):
    structure = (
       ('pbstrMethodName', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.10 put_MethodName (Opnum 16)
class IEventSubscription_put_MethodName(DCOMCALL):
    opnum = 16
    structure = (
       ('bstrMethodName', BSTR),
    )

class IEventSubscription_put_MethodNameResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.11 get_SubscriberCLSID (Opnum 17)
class IEventSubscription_get_SubscriberCLSID(DCOMCALL):
    opnum = 17
    structure = (
    )

class IEventSubscription_get_SubscriberCLSIDResponse(DCOMANSWER):
    structure = (
       ('pbstrSubscriberCLSID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.12 put_SubscriberCLSID (Opnum 18)
class IEventSubscription_put_SubscriberCLSID(DCOMCALL):
    opnum = 18
    structure = (
       ('bstrSubscriberCLSID', BSTR),
    )

class IEventSubscription_put_SubscriberCLSIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.13 get_SubscriberInterface (Opnum 19)
class IEventSubscription_get_SubscriberInterface(DCOMCALL):
    opnum = 19
    structure = (
    )

class IEventSubscription_get_SubscriberInterfaceResponse(DCOMANSWER):
    structure = (
       ('ppSubscriberInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.14 put_SubscriberInterface (Opnum 20)
class IEventSubscription_put_SubscriberInterface(DCOMCALL):
    opnum = 20
    structure = (
       ('pSubscriberInterface', PMInterfacePointer),
    )

class IEventSubscription_put_SubscriberInterfaceResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.15 get_PerUser (Opnum 21)
class IEventSubscription_get_PerUser(DCOMCALL):
    opnum = 21
    structure = (
    )

class IEventSubscription_get_PerUserResponse(DCOMANSWER):
    structure = (
       ('pfPerUser', BOOLEAN),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.16 put_PerUser (Opnum 22)
class IEventSubscription_put_PerUser(DCOMCALL):
    opnum = 22
    structure = (
       ('fPerUser', BOOLEAN),
    )

class IEventSubscription_put_PerUserResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.17 get_OwnerSID (Opnum 23)
class IEventSubscription_get_OwnerSID(DCOMCALL):
    opnum = 23
    structure = (
    )

class IEventSubscription_get_OwnerSIDResponse(DCOMANSWER):
    structure = (
       ('pbstrOwnerSID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.18 put_OwnerSID (Opnum 24)
class IEventSubscription_put_OwnerSID(DCOMCALL):
    opnum = 24
    structure = (
       ('bstrOwnerSID', BSTR),
    )

class IEventSubscription_put_OwnerSIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.19 get_Enabled (Opnum 25)
class IEventSubscription_get_Enabled(DCOMCALL):
    opnum = 25
    structure = (
    )

class IEventSubscription_get_EnabledResponse(DCOMANSWER):
    structure = (
       ('pfEnabled', BOOLEAN),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.20 put_Enabled (Opnum 26)
class IEventSubscription_put_Enabled(DCOMCALL):
    opnum = 26
    structure = (
       ('fEnabled', BOOLEAN),
    )

class IEventSubscription_put_EnabledResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.21 get_Description (Opnum 27)
class IEventSubscription_get_Description(DCOMCALL):
    opnum = 27
    structure = (
    )

class IEventSubscription_get_DescriptionResponse(DCOMANSWER):
    structure = (
       ('pbstrDescription', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.22 put_Description (Opnum 28)
class IEventSubscription_put_Description(DCOMCALL):
    opnum = 28
    structure = (
       ('bstrDescription', BSTR),
    )

class IEventSubscription_put_DescriptionResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.23 get_MachineName (Opnum 29)
class IEventSubscription_get_MachineName(DCOMCALL):
    opnum = 29
    structure = (
    )

class IEventSubscription_get_MachineNameResponse(DCOMANSWER):
    structure = (
       ('pbstrMachineName', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.24 put_MachineName (Opnum 30)
class IEventSubscription_put_MachineName(DCOMCALL):
    opnum = 30
    structure = (
       ('bstrMachineName', BSTR),
    )

class IEventSubscription_put_MachineNameResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.25 GetPublisherProperty (Opnum 31)
class IEventSubscription_GetPublisherProperty(DCOMCALL):
    opnum = 31
    structure = (
       ('bstrPropertyName', BSTR),
    )

class IEventSubscription_GetPublisherPropertyResponse(DCOMANSWER):
    structure = (
       ('propertyValue', VARIANT),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.26 PutPublisherProperty (Opnum 32)
class IEventSubscription_PutPublisherProperty(DCOMCALL):
    opnum = 32
    structure = (
       ('bstrPropertyName', BSTR),
       ('propertyValue', VARIANT),
    )

class IEventSubscription_PutPublisherPropertyResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.27 RemovePublisherProperty (Opnum 33)
class IEventSubscription_RemovePublisherProperty(DCOMCALL):
    opnum = 33
    structure = (
       ('bstrPropertyName', BSTR),
    )

class IEventSubscription_RemovePublisherPropertyResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.28 GetPublisherPropertyCollection (Opnum 34)
class IEventSubscription_GetPublisherPropertyCollection(DCOMCALL):
    opnum = 34
    structure = (
    )

class IEventSubscription_GetPublisherPropertyCollectionResponse(DCOMANSWER):
    structure = (
       ('collection', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.29 GetSubscriberProperty (Opnum 35)
class IEventSubscription_GetSubscriberProperty(DCOMCALL):
    opnum = 35
    structure = (
       ('bstrPropertyName', BSTR),
    )

class IEventSubscription_GetSubscriberPropertyResponse(DCOMANSWER):
    structure = (
       ('propertyValue', VARIANT),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.30 PutSubscriberProperty (Opnum 36)
class IEventSubscription_PutSubscriberProperty(DCOMCALL):
    opnum = 36
    structure = (
       ('bstrPropertyName', BSTR),
       ('propertyValue', VARIANT),
    )

class IEventSubscription_PutSubscriberPropertyResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.31 RemoveSubscriberProperty (Opnum 37)
class IEventSubscription_RemoveSubscriberProperty(DCOMCALL):
    opnum = 37
    structure = (
       ('bstrPropertyName', BSTR),
    )

class IEventSubscription_RemoveSubscriberPropertyResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.32 GetSubscriberPropertyCollection (Opnum 38)
class IEventSubscription_GetSubscriberPropertyCollection(DCOMCALL):
    opnum = 38
    structure = (
    )

class IEventSubscription_GetSubscriberPropertyCollectionResponse(DCOMANSWER):
    structure = (
       ('collection', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.33 get_InterfaceID (Opnum 39)
class IEventSubscription_get_InterfaceID(DCOMCALL):
    opnum = 39
    structure = (
    )

class IEventSubscription_get_InterfaceIDResponse(DCOMANSWER):
    structure = (
       ('pbstrInterfaceID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.34 put_InterfaceID (Opnum 40)
class IEventSubscription_put_InterfaceID(DCOMCALL):
    opnum = 40
    structure = (
       ('bstrInterfaceID', BSTR),
    )

class IEventSubscription_put_InterfaceIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.5 IEnumEventObject
# 3.1.4.5.1 Clone (Opnum 3)
class IEnumEventObject_Clone(DCOMCALL):
    opnum = 3
    structure = (
    )

class IEnumEventObject_CloneResponse(DCOMANSWER):
    structure = (
       ('ppInterface', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5.2 Next (Opnum 4)
class IEnumEventObject_Next(DCOMCALL):
    opnum = 4
    structure = (
       ('cReqElem', ULONG),
    )

class IEnumEventObject_NextResponse(DCOMANSWER):
    structure = (
       ('ppInterface', OBJECT_ARRAY),
       ('cRetElem', ULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5.3 Reset (Opnum 5)
class IEnumEventObject_Reset(DCOMCALL):
    opnum = 5
    structure = (
    )

class IEnumEventObject_ResetResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.5.4 Skip (Opnum 6)
class IEnumEventObject_Skip(DCOMCALL):
    opnum = 6
    structure = (
       ('cSkipElem', ULONG),
    )

class IEnumEventObject_SkipResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.6 IEventObjectCollection
# 3.1.4.6.1 get__NewEnum (Opnum 7)
class IEventObjectCollection_get__NewEnum(DCOMCALL):
    opnum = 7
    structure = (
    )

class IEventObjectCollection_get__NewEnumResponse(DCOMANSWER):
    structure = (
       ('ppUnkEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.6.2 get_Item (Opnum 8)
class IEventObjectCollection_get_Item(DCOMCALL):
    opnum = 8
    structure = (
       ('objectID', BSTR),
    )

class IEventObjectCollection_get_ItemResponse(DCOMANSWER):
    structure = (
       ('pItem', VARIANT),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.6.3 get_NewEnum (Opnum 9)
class IEventObjectCollection_get_NewEnum(DCOMCALL):
    opnum = 9
    structure = (
    )

class IEventObjectCollection_get_NewEnumResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.6.4 get_Count (Opnum 10)
class IEventObjectCollection_get_Count(DCOMCALL):
    opnum = 10
    structure = (
    )

class IEventObjectCollection_get_CountResponse(DCOMANSWER):
    structure = (
       ('pCount', LONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.6.5 Add (Opnum 11)
class IEventObjectCollection_Add(DCOMCALL):
    opnum = 11
    structure = (
       ('item', VARIANT),
       ('objectID', BSTR),
    )

class IEventObjectCollection_AddResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.6.6 Remove (Opnum 12)
class IEventObjectCollection_Remove(DCOMCALL):
    opnum = 12
    structure = (
       ('objectID', BSTR),
    )

class IEventObjectCollection_RemoveResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.7 IEventClass3
# 3.1.4.7.1 get_EventClassPartitionID (Opnum 29)
class IEventClass3_get_EventClassPartitionID(DCOMCALL):
    opnum = 29
    structure = (
    )

class IEventClass3_get_EventClassPartitionIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassPartitionID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.7.2 put_EventClassPartitionID (Opnum 30)
class IEventClass3_put_EventClassPartitionID(DCOMCALL):
    opnum = 30
    structure = (
       ('bstrEventClassPartitionID', BSTR),
    )

class IEventClass3_put_EventClassPartitionIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.7.3 get_EventClassApplicationID (Opnum 31)
class IEventClass3_get_EventClassApplicationID(DCOMCALL):
    opnum = 31
    structure = (
    )

class IEventClass3_get_EventClassApplicationIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassApplicationID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.7.4 put_EventClassApplicationID (Opnum 32)
class IEventClass3_put_EventClassApplicationID(DCOMCALL):
    opnum = 32
    structure = (
       ('bstrEventClassApplicationID', BSTR),
    )

class IEventClass3_put_EventClassApplicationIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.8 IEventSubscription2
# 3.1.4.8.1 get_FilterCriteria (Opnum 41)
class IEventSubscription2_get_FilterCriteria(DCOMCALL):
    opnum = 41
    structure = (
    )

class IEventSubscription2_get_FilterCriteriaResponse(DCOMANSWER):
    structure = (
       ('pbstrFilterCriteria', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.8.2 put_FilterCriteria (Opnum 42)
class IEventSubscription2_put_FilterCriteria(DCOMCALL):
    opnum = 42
    structure = (
       ('bstrFilterCriteria', BSTR),
    )

class IEventSubscription2_put_FilterCriteriaResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.8.3 get_SubscriberMoniker (Opnum 43)
class IEventSubscription2_get_SubscriberMoniker(DCOMCALL):
    opnum = 43
    structure = (
    )

class IEventSubscription2_get_SubscriberMonikerResponse(DCOMANSWER):
    structure = (
       ('pbstrMoniker', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.8.4 put_SubscriberMoniker (Opnum 44)
class IEventSubscription2_put_SubscriberMoniker(DCOMCALL):
    opnum = 44
    structure = (
       ('bstrMoniker', BSTR),
    )

class IEventSubscription2_put_SubscriberMonikerResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.9 IEventSubscription3
# 3.1.4.9.1 get_EventClassPartitionID (Opnum 45)
class IEventSubscription3_get_EventClassPartitionID(DCOMCALL):
    opnum = 45
    structure = (
    )

class IEventSubscription3_get_EventClassPartitionIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassPartitionID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.2 put_EventClassPartitionID (Opnum 46)
class IEventSubscription3_put_EventClassPartitionID(DCOMCALL):
    opnum = 46
    structure = (
       ('bstrEventClassPartitionID', BSTR),
    )

class IEventSubscription3_put_EventClassPartitionIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.3 get_EventClassApplicationID (Opnum 47)
class IEventSubscription3_get_EventClassApplicationID(DCOMCALL):
    opnum = 47
    structure = (
    )

class IEventSubscription3_get_EventClassApplicationIDResponse(DCOMANSWER):
    structure = (
       ('pbstrEventClassApplicationID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.4 put_EventClassApplicationID (Opnum 48)
class IEventSubscription3_put_EventClassApplicationID(DCOMCALL):
    opnum = 48
    structure = (
       ('bstrEventClassPartitionID', BSTR),
    )

class IEventSubscription3_put_EventClassApplicationIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.5 get_SubscriberPartitionID (Opnum 49)
class IEventSubscription3_get_SubscriberPartitionID(DCOMCALL):
    opnum = 49
    structure = (
    )

class IEventSubscription3_get_SubscriberPartitionIDResponse(DCOMANSWER):
    structure = (
       ('pbstrSubscriberPartitionID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.6 put_SubscriberPartitionID (Opnum 50)
class IEventSubscription3_put_SubscriberPartitionID(DCOMCALL):
    opnum = 50
    structure = (
       ('bstrSubscriberPartitionID', BSTR),
    )

class IEventSubscription3_put_SubscriberPartitionIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.7 get_SubscriberApplicationID (Opnum 51)
class IEventSubscription3_get_SubscriberApplicationID(DCOMCALL):
    opnum = 51
    structure = (
    )

class IEventSubscription3_get_SubscriberApplicationIDResponse(DCOMANSWER):
    structure = (
       ('pbstrSubscriberApplicationID', BSTR),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.9.8 put_SubscriberApplicationID (Opnum 52)
class IEventSubscription3_put_SubscriberApplicationID(DCOMCALL):
    opnum = 52
    structure = (
       ('bstrSubscriberApplicationID', BSTR),
    )

class IEventSubscription3_put_SubscriberApplicationIDResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.10 IEventSystem2
# 3.1.4.10.1 GetVersion (Opnum 13)
class IEventSystem2_GetVersion(DCOMCALL):
    opnum = 13
    structure = (
    )

class IEventSystem2_GetVersionResponse(DCOMANSWER):
    structure = (
       ('pnVersion', INT),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.10.2 VerifyTransientSubscribers (Opnum 14)
class IEventSystem2_VerifyTransientSubscribers(DCOMCALL):
    opnum = 14
    structure = (
    )

class IEventSystem2_VerifyTransientSubscribersResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

################################################################################
# 3.1.4.11 IEventSystemInitialize
# 3.1.4.11.1 SetCOMCatalogBehaviour (Opnum 3)
class IEventSystemInitialize_SetCOMCatalogBehaviour(DCOMCALL):
    opnum = 3
    structure = (
       ('bRetainSubKeys', BOOLEAN),
    )

class IEventSystemInitialize_SetCOMCatalogBehaviourResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
}

################################################################################
# HELPER FUNCTIONS AND INTERFACES
################################################################################
class IEventClass(IDispatch):
    def __init__(self, interface):
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventClass

    def get_EventClassID(self):
        request = IEventClass_get_EventClassID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassID(self,bstrEventClassID):
        request = IEventClass_put_EventClassID()
        request['bstrEventClassID'] = bstrEventClassID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_EventClassName(self):
        request = IEventClass_get_EventClassName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassName(self, bstrEventClassName):
        request = IEventClass_put_EventClassName()
        request['bstrEventClassName'] = bstrEventClassName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_OwnerSID(self):
        request = IEventClass_get_OwnerSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_OwnerSID(self, bstrOwnerSID):
        request = IEventClass_put_OwnerSID()
        request['bstrOwnerSID'] = bstrOwnerSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_FiringInterfaceID(self):
        request = IEventClass_get_FiringInterfaceID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_FiringInterfaceID(self, bstrFiringInterfaceID):
        request = IEventClass_put_FiringInterfaceID()
        request['bstrFiringInterfaceID'] = bstrFiringInterfaceID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_Description(self):
        request = IEventClass_get_Description()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_Description(self, bstrDescription):
        request = IEventClass_put_Description()
        request['bstrDescription'] = bstrDescription
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_TypeLib(self):
        request = IEventClass_get_TypeLib()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_TypeLib(self, bstrTypeLib):
        request = IEventClass_put_TypeLib()
        request['bstrTypeLib'] = bstrTypeLib
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IEventClass2(IEventClass):
    def __init__(self, interface):
        IEventClass.__init__(self,interface)
        self._iid = IID_IEventClass2

    def get_PublisherID(self):
        request = IEventClass2_get_PublisherID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_PublisherID(self, bstrPublisherID):
        request = IEventClass2_put_PublisherID()
        request['bstrPublisherID'] = bstrPublisherID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_MultiInterfacePublisherFilterCLSID(self):
        request = IEventClass2_get_MultiInterfacePublisherFilterCLSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_MultiInterfacePublisherFilterCLSID(self, bstrPubFilCLSID):
        request = IEventClass2_put_MultiInterfacePublisherFilterCLSID()
        request['bstrPubFilCLSID'] = bstrPubFilCLSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_AllowInprocActivation(self):
        request = IEventClass2_get_AllowInprocActivation()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_AllowInprocActivation(self, fAllowInprocActivation):
        request = IEventClass2_put_AllowInprocActivation()
        request['fAllowInprocActivation '] = fAllowInprocActivation
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_FireInParallel(self):
        request = IEventClass2_get_FireInParallel()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_FireInParallel(self, fFireInParallel):
        request = IEventClass2_put_FireInParallel()
        request['fFireInParallel '] = fFireInParallel
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IEventClass3(IEventClass2):
    def __init__(self, interface):
        IEventClass2.__init__(self,interface)
        self._iid = IID_IEventClass3

    def get_EventClassPartitionID(self):
        request = IEventClass3_get_EventClassPartitionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassPartitionID(self, bstrEventClassPartitionID):
        request = IEventClass3_put_EventClassPartitionID()
        request['bstrEventClassPartitionID '] = bstrEventClassPartitionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_EventClassApplicationID(self):
        request = IEventClass3_get_EventClassApplicationID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassApplicationID(self, bstrEventClassApplicationID):
        request = IEventClass3_put_EventClassApplicationID()
        request['bstrEventClassApplicationID '] = bstrEventClassApplicationID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IEventSubscription(IDispatch):
    def __init__(self, interface):
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventSubscription

    def get_SubscriptionID(self):
        request = IEventSubscription_get_SubscriptionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_SubscriptionID(self, bstrSubscriptionID):
        request = IEventSubscription_put_SubscriptionID()
        request['bstrSubscriptionID'] = bstrSubscriptionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_SubscriptionName(self):
        request = IEventSubscription_get_SubscriptionName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def put_SubscriptionName(self, bstrSubscriptionName):
        request = IEventSubscription_put_SubscriptionName()
        request['bstrSubscriptionName'] = bstrSubscriptionName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_PublisherID(self):
        request = IEventSubscription_get_PublisherID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_PublisherID(self, bstrPublisherID):
        request = IEventSubscription_put_PublisherID()
        request['bstrPublisherID'] = bstrPublisherID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_EventClassID(self):
        request = IEventSubscription_get_EventClassID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassID(self, pbstrEventClassID):
        request = IEventSubscription_put_EventClassID()
        request['pbstrEventClassID'] = pbstrEventClassID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_MethodName(self):
        request = IEventSubscription_get_MethodName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_MethodName(self, bstrMethodName):
        request = IEventSubscription_put_MethodName()
        request['bstrMethodName'] = bstrMethodName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_SubscriberCLSID(self):
        request = IEventSubscription_get_SubscriberCLSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_SubscriberCLSID(self, bstrSubscriberCLSID):
        request = IEventSubscription_put_SubscriberCLSID()
        request['bstrSubscriberCLSID'] = bstrSubscriberCLSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_SubscriberInterface(self):
        request = IEventSubscription_get_SubscriberInterface()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_SubscriberInterface(self, pSubscriberInterface):
        request = IEventSubscription_put_SubscriberInterface()
        request['pSubscriberInterface'] = pSubscriberInterface
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_PerUser(self):
        request = IEventSubscription_get_PerUser()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_PerUser(self, fPerUser):
        request = IEventSubscription_put_PerUser()
        request['fPerUser'] = fPerUser
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_OwnerSID(self):
        request = IEventSubscription_get_OwnerSID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_OwnerSID(self, bstrOwnerSID):
        request = IEventSubscription_put_OwnerSID()
        request['bstrOwnerSID'] = bstrOwnerSID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_Enabled(self):
        request = IEventSubscription_get_Enabled()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_Enabled(self, fEnabled):
        request = IEventSubscription_put_Enabled()
        request['fEnabled'] = fEnabled
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_Description(self):
        request = IEventSubscription_get_Description()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_Description(self, bstrDescription):
        request = IEventSubscription_put_Description()
        request['bstrDescription'] = bstrDescription
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_MachineName(self):
        request = IEventSubscription_get_MachineName()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_MachineName(self, bstrMachineName):
        request = IEventSubscription_put_MachineName()
        request['bstrMachineName'] = bstrMachineName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetPublisherProperty(self):
        request = IEventSubscription_GetPublisherProperty()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutPublisherProperty(self, bstrPropertyName, propertyValue):
        request = IEventSubscription_PutPublisherProperty()
        request['bstrPropertyName'] = bstrPropertyName
        request['propertyValue'] = propertyValue
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def RemovePublisherProperty(self, bstrPropertyName):
        request = IEventSubscription_RemovePublisherProperty()
        request['bstrPropertyName'] = bstrPropertyName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetPublisherPropertyCollection(self):
        request = IEventSubscription_GetPublisherPropertyCollection()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetSubscriberProperty(self):
        request = IEventSubscription_GetSubscriberProperty()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutSubscriberProperty(self, bstrPropertyName, propertyValue):
        request = IEventSubscription_PutSubscriberProperty()
        request['bstrPropertyName'] = bstrPropertyName
        request['propertyValue'] = propertyValue
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def RemoveSubscriberProperty(self, bstrPropertyName):
        request = IEventSubscription_RemoveSubscriberProperty()
        request['bstrPropertyName'] = bstrPropertyName
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetSubscriberPropertyCollection(self):
        request = IEventSubscription_GetSubscriberPropertyCollection()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_InterfaceID(self):
        request = IEventSubscription_get_InterfaceID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_InterfaceID(self, bstrInterfaceID):
        request = IEventSubscription_put_InterfaceID()
        request['bstrInterfaceID'] = bstrInterfaceID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IEventSubscription2(IEventSubscription):
    def __init__(self, interface):
        IEventSubscription.__init__(self,interface)
        self._iid = IID_IEventSubscription2

    def get_FilterCriteria(self):
        request = IEventSubscription2_get_FilterCriteria()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_FilterCriteria(self, bstrFilterCriteria):
        request = IEventSubscription2_put_FilterCriteria()
        request['bstrFilterCriteria'] = bstrFilterCriteria
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_SubscriberMoniker (self):
        request = IEventSubscription2_get_SubscriberMoniker ()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_SubscriberMoniker(self, bstrMoniker):
        request = IEventSubscription2_put_SubscriberMoniker()
        request['bstrMoniker'] = bstrMoniker
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IEventSubscription3(IEventSubscription2):
    def __init__(self, interface):
        IEventSubscription2.__init__(self,interface)
        self._iid = IID_IEventSubscription3

    def get_EventClassPartitionID(self):
        request = IEventSubscription3_get_EventClassPartitionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassPartitionID(self, bstrEventClassPartitionID):
        request = IEventSubscription3_put_EventClassPartitionID()
        request['bstrEventClassPartitionID'] = bstrEventClassPartitionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_EventClassApplicationID(self):
        request = IEventSubscription3_get_EventClassApplicationID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_EventClassApplicationID(self, bstrEventClassApplicationID):
        request = IEventSubscription3_put_EventClassApplicationID()
        request['bstrEventClassApplicationID'] = bstrEventClassApplicationID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_SubscriberPartitionID(self):
        request = IEventSubscription3_get_SubscriberPartitionID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_SubscriberPartitionID(self, bstrSubscriberPartitionID):
        request = IEventSubscription3_put_SubscriberPartitionID()
        request['bstrSubscriberPartitionID'] = bstrSubscriberPartitionID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def get_SubscriberApplicationID(self):
        request = IEventSubscription3_get_SubscriberApplicationID()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def put_SubscriberApplicationID(self, bstrSubscriberApplicationID):
        request = IEventSubscription3_put_SubscriberApplicationID()
        request['bstrSubscriberApplicationID'] = bstrSubscriberApplicationID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp


class IEnumEventObject(IDispatch):
    def __init__(self, interface):
        IDispatch.__init__(self,interface)
        self._iid = IID_IEnumEventObject

    def Clone(self):
        request = IEnumEventObject_Clone()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumEventObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppInterface']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))

    def Next(self, cReqElem):
        request = IEnumEventObject_Next()
        request['cReqElem'] = cReqElem
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        interfaces = list()
        for interface in resp['ppInterface']:
            interfaces.append(IEventClass2(INTERFACE(self.get_cinstance(), ''.join(interface['abData']), self.get_ipidRemUnknown(), target = self.get_target())))
        return interfaces

    def Reset(self):
        request = IEnumEventObject_Reset()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def Skip(self, cSkipElem):
        request = IEnumEventObject_Skip()
        request['cSkipElem'] = cSkipElem
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

class IEventObjectCollection(IDispatch):
    def __init__(self, interface):
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventObjectCollection

    def get__NewEnum(self):
        request = IEventObjectCollection_get__NewEnum()
        resp = self.request(request, iid = self._iid , uuid = self.get_iPid())
        return IEnumEventObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), target = self._get_target()))

    def get_Item(self, objectID):
        request = IEventObjectCollection_get_Item()
        request['objectID']['asData'] = objectID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def get_NewEnum(self):
        request = IEventObjectCollection_get_NewEnum()
        resp = self.request(request, iid = self._iid , uuid = self.get_iPid())
        return IEnumEventObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))

    def get_Count(self):
        request = IEventObjectCollection_get_Count()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def Add(self, item, objectID):
        request = IEventObjectCollection_Add()
        request['item'] = item
        request['objectID']['asData'] = objectID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def Remove(self, objectID):
        request = IEventObjectCollection_Remove()
        request['objectID']['asData'] = objectID
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

class IEventSystem(IDispatch):
    def __init__(self, interface):
        IDispatch.__init__(self,interface)
        self._iid = IID_IEventSystem

    def Query(self, progID, queryCriteria):
        request = IEventSystem_Query()
        request['progID']['asData']=progID
        request['queryCriteria']['asData']=queryCriteria
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        iInterface = IDispatch(INTERFACE(self.get_cinstance(), ''.join(resp['ppInterface']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))
        return IEventObjectCollection(iInterface.RemQueryInterface(1, (IID_IEventObjectCollection,)))

    def Store(self, progID, pInterface):
        request = IEventSystem_Store()
        request['progID']['asData']=progID
        request['pInterface'] = pInterface
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def Remove(self, progID, queryCriteria):
        request = IEventSystem_Remove()
        request['progID']['asData']=progID
        request['queryCriteria'] = queryCriteria
        resp = self.request(request, uuid = self.get_iPid())
        return resp

    def get_EventObjectChangeEventClassID(self):
        request = IEventSystem_get_EventObjectChangeEventClassID()
        resp = self.request(request, uuid = self.get_iPid())
        return resp

    def QueryS(self,progID, queryCriteria):
        request = IEventSystem_QueryS()
        request['progID']['asData']=progID
        request['queryCriteria']['asData']=queryCriteria
        resp = self.request(request, uuid = self.get_iPid())
        iInterface = IDispatch(INTERFACE(self.get_cinstance(), ''.join(resp['ppInterface']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))
        return IEventObjectCollection(iInterface.RemQueryInterface(1, (IID_IEventObjectCollection,)))

    def RemoveS(self,progID, queryCriteria):
        request = IEventSystem_RemoveS()
        request['progID']['asData']=progID
        request['queryCriteria']['asData']=queryCriteria
        resp = self.request(request, uuid = self.get_iPid())
        return resp

class IEventSystem2(IEventSystem):
    def __init__(self, interface):
        IEventSystem.__init__(self,interface)
        self._iid = IID_IEventSystem2

    def GetVersion(self):
        request = IEventSystem2_GetVersion()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def VerifyTransientSubscribers(self):
        request = IEventSystem2_GetVersion()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

class IEventSystemInitialize(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IEventSystemInitialize

    def SetCOMCatalogBehaviour(self, bRetainSubKeys):
        request = IEventSystem2_GetVersion()
        request['bRetainSubKeys'] = bRetainSubKeys
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

