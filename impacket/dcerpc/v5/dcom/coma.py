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
#   [MS-COMA]: Component Object Model Plus (COM+) Remote Administration Protocol.
#            
#   There are currently no test cases present; this was tested using a "example" script of mine alongside following the spec + other modules like comev
#   I will soon push test cases once I finish fleshing everything out as I have been working on this on and off for some while as it sat on my computer untouched
#   Since DCOM is like an OO RPC, instead of helper functions you will see the
#   classes described in the standards developed.
#   
#
# Author:
#   Abdul Mhanni (@abdo_mhanni)

from struct import pack, unpack
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRENUM, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, INTERFACE, PMInterfacePointer, IRemUnknown2
from impacket.dcerpc.v5.dcom.oaut import BSTR, VARIANT_BOOL
from impacket.dcerpc.v5.dtypes import BOOL, DWORD, FLOAT, GUID, HRESULT, INT, LONG, LPWSTR, NULL, PGUID, ULONG
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.enum import Enum
from impacket import hresult_errors
from impacket.uuid import string_to_bin

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
            return 'COMA SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'COMA SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 1.9 Standards Assignments
CLSID_COMAServer                               = string_to_bin('182C40F0-32E4-11D0-818B-00A0C9231C29')
IID_ICatalogSession                            = string_to_bin('182C40FA-32E4-11D0-818B-00A0C9231C29')
IID_ICatalog64BitSupport                       = string_to_bin('1D118904-94B3-4A64-9FA6-ED432666A7B9')
IID_ICatalogTableInfo                          = string_to_bin('A8927A41-D3CE-11D1-8472-006008B0E5CA')
IID_ICatalogTableRead                          = string_to_bin('0E3D6630-B46B-11D1-9D2D-006008B0E5CA')
IID_ICatalogTableWrite                         = string_to_bin('0E3D6631-B46B-11D1-9D2D-006008B0E5CA')
IID_IRegister                                  = string_to_bin('8DB2180E-BD29-11D1-8B7E-00C04FD7A924')
IID_IRegister2                                 = string_to_bin('971668DC-C3FE-4EA1-9643-0C7230F494A1')
IID_IImport                                    = string_to_bin('C2BE6970-DF9E-11D1-8B87-00C04FD7A924')
IID_IImport2                                   = string_to_bin('1F7B1697-ECB2-4CBB-8A0E-75C427F4A6F0')
IID_IExport                                    = string_to_bin('CFADAC84-E12C-11D1-B34C-00C04F990D54')
IID_IExport2                                   = string_to_bin('F131EA3E-B7BE-480E-A60D-51CB2785779E')
IID_IAlternateLaunch                           = string_to_bin('7F43B400-1A0E-4D57-BBC9-6B0C65F7A889')
IID_ICatalogUtils                              = string_to_bin('456129E2-1078-11D2-B0F9-00805FC73204')
IID_ICatalogUtils2                             = string_to_bin('C726744E-5735-4F08-8286-C510EE638FB6')
IID_ICapabilitySupport                         = string_to_bin('47CDE9A1-0BF6-11D2-8016-00C04FB9988E')
IID_IContainerControl                          = string_to_bin('3F3B1B86-DBBE-11D1-9DA6-00805F85CFE3')
IID_IContainerControl2                         = string_to_bin('6C935649-30A6-4211-8687-C4C83E5FE1C7')
IID_IReplicationUtil                           = string_to_bin('98315903-7BE5-11D2-ADC1-00A02463D6E7')

CATID_COMA                                     = string_to_bin('6E38D3C4-C2A7-11D1-8DEC-00C04FC2E0C7')
TBLID_ComponentsAndFullConfigurations          = string_to_bin('6E38D3C8-C2A7-11D1-8DEC-00C04FC2E0C7')
TBLID_ComponentFullConfigurationsReadOnly      = string_to_bin('6E38D3CA-C2A7-11D1-8DEC-00C04FC2E0C7')
TBLID_ComponentLegacyConfigurations            = string_to_bin('09487519-892D-4CA0-A00B-58EEB1662A68')
TBLID_ComponentNativeBitness                   = string_to_bin('39344B1F-EFE8-4286-9DB8-AC0A3D791FF2')
TBLID_ComponentNonNativeBitness                = string_to_bin('96EC9BF1-063B-4ABF-8B90-42C878D9033E')
TBLID_Conglomerations                          = string_to_bin('D495F321-AF37-11D1-8B7E-00C04FD7A924')
TBLID_Partitions                               = string_to_bin('E4AD9FD6-D435-4CF5-95AD-20AD9AC6B59F')
TBLID_MachineSettings                          = string_to_bin('61436562-EE01-11D1-BFE4-00C04FB9988E')
TBLID_Roles                                    = string_to_bin('CD331D11-C739-11D1-9D35-006008B0E5CA')
TBLID_RoleMembers                              = string_to_bin('CD331D10-C739-11D1-9D35-006008B0E5CA')
TBLID_ConfiguredInterfaces                     = string_to_bin('D13B72C6-C426-11D1-8507-006008B0E79D')
TBLID_ConfiguredMethods                        = string_to_bin('D13B72C4-C426-11D1-8507-006008B0E79D')
TBLID_RolesForComponent                        = string_to_bin('CD331D12-C739-11D1-9D35-006008B0E5CA')
TBLID_RolesForInterface                        = string_to_bin('CD331D13-C739-11D1-9D35-006008B0E5CA')
TBLID_RolesForMethod                           = string_to_bin('CD331D14-C739-11D1-9D35-006008B0E5CA')
TBLID_PartitionUsers                           = string_to_bin('0AF55FDC-30B5-4B6E-B258-A9DE4B64818C')
TBLID_PartitionRoles                           = string_to_bin('9D29E285-E24D-4096-98E1-44DBB2EAF7F0')
TBLID_PartitionRoleMembers                     = string_to_bin('352131CD-E0FF-4C46-9675-C3808B249F69')
TBLID_InstanceLoadBalancingTargets             = string_to_bin('B7EEEA91-B3B9-11D1-8B7E-00C04FD7A924')
TBLID_ServerList                               = string_to_bin('2DAF1D50-BD53-11D1-8280-00A0C9231C29')
TBLID_InstanceContainers                       = string_to_bin('DF2FCC47-B7B7-4CB9-8B40-0B3D1E59E7DD')
TBLID_EventClasses                             = string_to_bin('E12539AD-CDE0-4E46-9211-916018B8C4D2')
TBLID_Subscriptions                            = string_to_bin('5A84E823-7277-11D2-9029-3078302C2030')
TBLID_SubscriptionPublisherProperties          = string_to_bin('5A84E824-7277-11D2-9029-3078302C2030')
TBLID_SubscriptionSubscriberProperties         = string_to_bin('5A84E825-7277-11D2-9029-3078302C2030')
TBLID_Protocols                                = string_to_bin('61436563-EE01-11D1-BFE4-00C04FB9988E')
TBLID_FilesForImport                           = string_to_bin('E4053366-BF8F-4E84-B4B2-72B3C2626CC9')

GUID_RequiredFixedGuid                         = string_to_bin('92AD68AB-17E0-11D1-B230-00C04FB9473F')
GUID_Aux_ComponentsAndFullConfigurations       = string_to_bin('B4B3AECB-DFD6-11D1-9DAA-00805F85CFE3')
GUID_Aux_SubscriptionProperties                = string_to_bin('EB56EAE8-BA51-11D2-B121-00805FC73204')
GUID_DefaultAppPartition                       = string_to_bin('41E90F3E-56C1-4633-81C3-6E8BAC8BDD70')
GUID_ProtectedConglomeration_SystemApplication = string_to_bin('01885945-612C-4A53-A479-E97507453926')
GUID_ProtectedConglomeration_COMPlusUtilities  = string_to_bin('9EB3B62C-79A2-11D2-9891-00C04F79AF51')
GUID_ProtectedConglomeration_COMPlusQCDeadQ    = string_to_bin('6B97138E-3C20-48D1-945F-81AE63282DEE')

COMA_TABLES = {
    'ComponentsAndFullConfigurations': TBLID_ComponentsAndFullConfigurations,
    'ComponentFullConfigurationsReadOnly': TBLID_ComponentFullConfigurationsReadOnly,
    'ComponentLegacyConfigurations': TBLID_ComponentLegacyConfigurations,
    'ComponentNativeBitness': TBLID_ComponentNativeBitness,
    'ComponentNonNativeBitness': TBLID_ComponentNonNativeBitness,
    'Conglomerations': TBLID_Conglomerations,
    'Partitions': TBLID_Partitions,
    'MachineSettings': TBLID_MachineSettings,
    'Roles': TBLID_Roles,
    'RoleMembers': TBLID_RoleMembers,
    'ConfiguredInterfaces': TBLID_ConfiguredInterfaces,
    'ConfiguredMethods': TBLID_ConfiguredMethods,
    'RolesForComponent': TBLID_RolesForComponent,
    'RolesForInterface': TBLID_RolesForInterface,
    'RolesForMethod': TBLID_RolesForMethod,
    'PartitionUsers': TBLID_PartitionUsers,
    'PartitionRoles': TBLID_PartitionRoles,
    'PartitionRoleMembers': TBLID_PartitionRoleMembers,
    'InstanceLoadBalancingTargets': TBLID_InstanceLoadBalancingTargets,
    'ServerList': TBLID_ServerList,
    'InstanceContainers': TBLID_InstanceContainers,
    'EventClasses': TBLID_EventClasses,
    'Subscriptions': TBLID_Subscriptions,
    'SubscriptionPublisherProperties': TBLID_SubscriptionPublisherProperties,
    'SubscriptionSubscriberProperties': TBLID_SubscriptionSubscriberProperties,
    'Protocols': TBLID_Protocols,
    'FilesForImport': TBLID_FilesForImport,
}

error_status_t = HRESULT

# 2.2.1.1 fTableFlags
fTABLE_UNSPECIFIED = 0x00000000
fTABLE_32BIT       = 0x00200000
fTABLE_64BIT       = 0x00400000

# 2.2.1.4 QueryCell
eOPERATOR_EQUAL    = 0x00000000
eOPERATOR_NOTEQUAL = 0x00000001

# 3.1.4.7.1, 3.1.4.8.1, 3.1.4.9.1
eQUERYFORMAT_1     = 0x00000001
E_DETAILEDERRORS   = 0x80110802

# 2.2.3 fModuleStatus
fMODULE_LOADED             = 0x00000001
fMODULE_INSTANTIATE        = 0x00000002
fMODULE_SUPPORTCODE        = 0x00000004
fMODULE_CONTAINSCOMP       = 0x00000008
fMODULE_TYPELIB            = 0x00000010
fMODULE_SELFREG            = 0x00000020
fMODULE_SELFUNREG          = 0x00000040
fMODULE_LOADFAILED         = 0x00000080
fMODULE_DOESNOTEXIST       = 0x00000100
fMODULE_ALREADYINSTALLED   = 0x00000200
fMODULE_BADTYPELIB         = 0x00000400
fMODULE_CUSTOMSUPPORTED    = 0x00002000
fMODULE_CUSTOMUNSUPPORTED  = 0x00004000
fMODULE_TYPELIBFAILED      = 0x00008000
fMODULE_SELFREGFAILED      = 0x00010000
fMODULE_CUSTOMFAILED       = 0x00020000

# 2.2.4 fComponentStatus
fCOMPONENT_TYPELIBFOUND    = 0x00000001
fCOMPONENT_COMADATA        = 0x00000002
fCOMPONENT_INTERFACES      = 0x00000008
fCOMPONENT_INSTALLED       = 0x00000010
fCOMPONENT_PROXY           = 0x00000100
fCOMPONENT_CLSIDCONFLICT   = 0x00000200
fCOMPONENT_NOTYPELIB       = 0x00000800
fCOMPONENT_HIDDEN          = 0x00001000

################################################################################
# STRUCTURES
################################################################################
# 2.2.1.2 eDataType
class eDataType(NDRENUM):
    class enumItems(Enum):
        eDT_ULONG  = 0x00000013
        eDT_GUID   = 0x00000048
        eDT_BYTES  = 0x00000080
        eDT_LPWSTR = 0x00000082

# 2.2.1.3 eSpecialQueryOption
class eSpecialQueryOption(NDRENUM):
    class enumItems(Enum):
        eSQO_OPTHINT = 0xf0000005

# 2.2.1.7 PropertyMeta
class PropertyMeta(NDRSTRUCT):
    structure = (
        ('dataType', DWORD),
        ('cbSize', ULONG),
        ('flags', DWORD),
    )

class PROPERTY_META_ARRAY(NDRUniConformantArray):
    item = PropertyMeta

class PPROPERTY_META_ARRAY(NDRPOINTER):
    referent = (
        ('Data', PROPERTY_META_ARRAY),
    )

# 2.2.1.11 eTableEntryAction
class eTableEntryAction(NDRENUM):
    class enumItems(Enum):
        eACTION_ADD    = 0x00000001
        eACTION_UPDATE = 0x00000002
        eACTION_REMOVE = 0x00000003

# 2.2.5 eComponentType
class eComponentType(NDRENUM):
    class enumItems(Enum):
        eCT_UNKNOWN = 0x00000000
        eCT_32BIT   = 0x00000001
        eCT_64BIT   = 0x00000002
        eCT_NATIVE  = 0x00001000

# 2.2.6 SRPLevelInfo
class SRPLevelInfo(NDRSTRUCT):
    structure = (
        ('dwSRPLevel', DWORD),
        ('wszFriendlyName', LPWSTR),
    )

class SRP_LEVEL_INFO_ARRAY(NDRUniConformantArray):
    item = SRPLevelInfo

class PSRP_LEVEL_INFO_ARRAY(NDRPOINTER):
    referent = (
        ('Data', SRP_LEVEL_INFO_ARRAY),
    )

# 2.2.7 CatSrvServices
class CatSrvServices(NDRENUM):
    class enumItems(Enum):
        css_lb = 1

# 2.2.8 CatSrvServiceState
class CatSrvServiceState(NDRENUM):
    class enumItems(Enum):
        css_serviceStopped         = 0
        css_serviceStartPending    = 1
        css_serviceStopPending     = 2
        css_serviceRunning         = 3
        css_serviceContinuePending = 4
        css_servicePausePending    = 5
        css_servicePaused          = 6
        css_serviceUnknownState    = 7

# 2.2.9 InstanceContainer
class InstanceContainer(NDRSTRUCT):
    structure = (
        ('ConglomerationID', GUID),
        ('PartitionID', GUID),
        ('ContainerID', GUID),
        ('dwProcessID', DWORD),
        ('bPaused', BOOL),
        ('bRecycled', BOOL),
    )

class INSTANCE_CONTAINER_ARRAY(NDRUniConformantArray):
    item = InstanceContainer

class PINSTANCE_CONTAINER_ARRAY(NDRPOINTER):
    referent = (
        ('Data', INSTANCE_CONTAINER_ARRAY),
    )

class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class DWORD_ARRAY(NDRUniConformantArray):
    item = '<L'

class PDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY),
    )

class LONG_ARRAY(NDRUniConformantArray):
    item = '<l'

class PLONG_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LONG_ARRAY),
    )

class BOOL_ARRAY(NDRUniConformantArray):
    item = '<L'

class PBOOL_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BOOL_ARRAY),
    )

class GUID_ARRAY(NDRUniConformantArray):
    item = GUID

class PGUID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', GUID_ARRAY),
    )

class LPWSTR_ARRAY(NDRUniConformantArray):
    item = LPWSTR

class PLPWSTR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', LPWSTR_ARRAY),
    )

################################################################################
# RPC CALLS
################################################################################
# 3.1.4.5 ICatalogSession
# 3.1.4.5.1 InitializeSession (Opnum 7)
class ICatalogSession_InitializeSession(DCOMCALL):
    opnum = 7
    structure = (
        ('flVerLower', FLOAT),
        ('flVerUpper', FLOAT),
        ('reserved', LONG),
    )

class ICatalogSession_InitializeSessionResponse(DCOMANSWER):
    structure = (
        ('pflVerSession', FLOAT),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.5.2 GetServerInformation (Opnum 8)
class ICatalogSession_GetServerInformation(DCOMCALL):
    opnum = 8
    structure = (
    )

class ICatalogSession_GetServerInformationResponse(DCOMANSWER):
    structure = (
        ('plReserved1', LONG),
        ('plReserved2', LONG),
        ('plReserved3', LONG),
        ('plMultiplePartitionSupport', LONG),
        ('plReserved4', LONG),
        ('plReserved5', LONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.6 ICatalog64BitSupport
# 3.1.4.6.1 SupportsMultipleBitness (Opnum 3)
class ICatalog64BitSupport_SupportsMultipleBitness(DCOMCALL):
    opnum = 3
    structure = (
    )

class ICatalog64BitSupport_SupportsMultipleBitnessResponse(DCOMANSWER):
    structure = (
        ('pbSupportsMultipleBitness', BOOL),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.6.2 Initialize64BitQueryCellSupport (Opnum 4)
class ICatalog64BitSupport_Initialize64BitQueryCellSupport(DCOMCALL):
    opnum = 4
    structure = (
        ('bClientSupports64BitQueryCells', BOOL),
    )

class ICatalog64BitSupport_Initialize64BitQueryCellSupportResponse(DCOMANSWER):
    structure = (
        ('pbServerSupports64BitQueryCells', BOOL),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.7 ICatalogTableInfo
# 3.1.4.7.1 GetClientTableInfo (Opnum 3)
class ICatalogTableInfo_GetClientTableInfo(DCOMCALL):
    opnum = 3
    structure = (
        ('pCatalogIdentifier', PGUID),
        ('pTableIdentifier', PGUID),
        ('tableFlags', DWORD),
        ('pQueryCellArray', PBYTE_ARRAY),
        ('cbQueryCellArray', ULONG),
        ('pQueryComparison', PBYTE_ARRAY),
        ('cbQueryComparison', ULONG),
        ('eQueryFormat', DWORD),
    )

class ICatalogTableInfo_GetClientTableInfoResponse(DCOMANSWER):
    structure = (
        ('pRequiredFixedGuid', GUID),
        ('ppReserved1', PBYTE_ARRAY),
        ('pcbReserved1', ULONG),
        ('ppAuxiliaryGuid', PGUID_ARRAY),
        ('pcAuxiliaryGuid', ULONG),
        ('ppPropertyMeta', PPROPERTY_META_ARRAY),
        ('pcProperties', ULONG),
        ('piid', GUID),
        ('pItf', PMInterfacePointer),
        ('ppReserved2', PBYTE_ARRAY),
        ('pcbReserved2', ULONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.8 ICatalogTableRead
# 3.1.4.8.1 ReadTable (Opnum 3)
class ICatalogTableRead_ReadTable(DCOMCALL):
    opnum = 3
    structure = (
        ('pCatalogIdentifier', PGUID),
        ('pTableIdentifier', PGUID),
        ('tableFlags', DWORD),
        ('pQueryCellArray', PBYTE_ARRAY),
        ('cbQueryCellArray', ULONG),
        ('pQueryComparison', PBYTE_ARRAY),
        ('cbQueryComparison', ULONG),
        ('eQueryFormat', DWORD),
    )

class ICatalogTableRead_ReadTableResponse(DCOMANSWER):
    structure = (
        ('ppTableDataFixed', PBYTE_ARRAY),
        ('pcbTableDataFixed', ULONG),
        ('ppTableDataVariable', PBYTE_ARRAY),
        ('pcbTableDataVariable', ULONG),
        ('ppTableDetailedErrors', PBYTE_ARRAY),
        ('pcbTableDetailedErrors', ULONG),
        ('ppReserved1', PBYTE_ARRAY),
        ('pcbReserved1', ULONG),
        ('ppReserved2', PBYTE_ARRAY),
        ('pcbReserved2', ULONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.9 ICatalogTableWrite
# 3.1.4.9.1 WriteTable (Opnum 3)
class ICatalogTableWrite_WriteTable(DCOMCALL):
    opnum = 3
    structure = (
        ('pCatalogIdentifier', PGUID),
        ('pTableIdentifier', PGUID),
        ('tableFlags', DWORD),
        ('pQueryCellArray', PBYTE_ARRAY),
        ('cbQueryCellArray', ULONG),
        ('pQueryComparison', PBYTE_ARRAY),
        ('cbQueryComparison', ULONG),
        ('eQueryFormat', DWORD),
        ('pTableDataFixedWrite', PBYTE_ARRAY),
        ('cbTableDataFixedWrite', ULONG),
        ('pTableDataVariable', PBYTE_ARRAY),
        ('cbTableDataVariable', ULONG),
        ('pReserved1', PBYTE_ARRAY),
        ('cbReserved1', ULONG),
        ('pReserved2', PBYTE_ARRAY),
        ('cbReserved2', ULONG),
        ('pReserved3', PBYTE_ARRAY),
        ('cbReserved3', ULONG),
    )

class ICatalogTableWrite_WriteTableResponse(DCOMANSWER):
    structure = (
        ('ppTableDetailedErrors', PBYTE_ARRAY),
        ('pcbTableDetailedErrors', ULONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.10 IRegister
# 3.1.4.10.1 RegisterModule (Opnum 3)
class IRegister_RegisterModule(DCOMCALL):
    opnum = 3
    structure = (
        ('ConglomerationIdentifier', GUID),
        ('ppModules', PLPWSTR_ARRAY),
        ('cModules', DWORD),
        ('dwFlags', DWORD),
        ('pRequestedCLSIDs', PGUID_ARRAY),
        ('cRequested', DWORD),
    )

class IRegister_RegisterModuleResponse(DCOMANSWER):
    structure = (
        ('ppModuleFlags', PDWORD_ARRAY),
        ('pcResults', DWORD),
        ('ppResultCLSIDs', PGUID_ARRAY),
        ('ppResultNames', PLPWSTR_ARRAY),
        ('ppResultFlags', PDWORD_ARRAY),
        ('ppResultHRs', PLONG_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.11 IRegister2
# 3.1.4.11.1 CreateFullConfiguration (Opnum 3)
class IRegister2_CreateFullConfiguration(DCOMCALL):
    opnum = 3
    structure = (
        ('pwszConglomerationIdOrName', LPWSTR),
        ('pwszCLSIDOrProgId', LPWSTR),
        ('ctComponentType', eComponentType),
    )

class IRegister2_CreateFullConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.11.2 CreateLegacyConfiguration (Opnum 4)
class IRegister2_CreateLegacyConfiguration(DCOMCALL):
    opnum = 4
    structure = (
        ('pwszConglomerationIdOrName', LPWSTR),
        ('pwszCLSIDOrProgId', LPWSTR),
        ('ctComponentType', eComponentType),
    )

class IRegister2_CreateLegacyConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.11.3 PromoteLegacyConfiguration (Opnum 5)
class IRegister2_PromoteLegacyConfiguration(DCOMCALL):
    opnum = 5
    structure = (
        ('pwszConglomerationIdOrName', LPWSTR),
        ('pwszCLSIDOrProgId', LPWSTR),
        ('ctComponentType', eComponentType),
    )

class IRegister2_PromoteLegacyConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.11.4 RegisterModule2 (Opnum 8)
class IRegister2_RegisterModule2(DCOMCALL):
    opnum = 8
    structure = (
        ('ConglomerationIdentifier', GUID),
        ('PartitionIdentifier', GUID),
        ('ppModules', PLPWSTR_ARRAY),
        ('cModules', DWORD),
        ('dwFlags', DWORD),
        ('pRequestedCLSIDs', PGUID_ARRAY),
        ('cRequested', DWORD),
    )

class IRegister2_RegisterModule2Response(DCOMANSWER):
    structure = (
        ('ppModuleFlags', PDWORD_ARRAY),
        ('pcResults', DWORD),
        ('ppResultCLSIDs', PGUID_ARRAY),
        ('ppResultNames', PLPWSTR_ARRAY),
        ('ppResultFlags', PDWORD_ARRAY),
        ('ppResultHRs', PLONG_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.12 IImport
# 3.1.4.12.1 ImportFromFile (Opnum 3)
class IImport_ImportFromFile(DCOMCALL):
    opnum = 3
    structure = (
        ('pwszModuleDestination', LPWSTR),
        ('pwszInstallerPackage', LPWSTR),
        ('pwszUser', LPWSTR),
        ('pwszPassword', LPWSTR),
        ('pwszRemoteServerName', LPWSTR),
        ('dwFlags', DWORD),
        ('reserved1', PGUID),
        ('reserved2', DWORD),
    )

class IImport_ImportFromFileResponse(DCOMANSWER):
    structure = (
        ('pcModules', DWORD),
        ('ppModuleFlags', PDWORD_ARRAY),
        ('ppModules', PLPWSTR_ARRAY),
        ('pcComponents', DWORD),
        ('ppResultCLSIDs', PGUID_ARRAY),
        ('ppResultNames', PLPWSTR_ARRAY),
        ('ppResultFlags', PDWORD_ARRAY),
        ('ppResultHRs', PLONG_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.12.2 QueryFile (Opnum 4)
class IImport_QueryFile(DCOMCALL):
    opnum = 4
    structure = (
        ('pwszInstallerPackage', LPWSTR),
    )

class IImport_QueryFileResponse(DCOMANSWER):
    structure = (
        ('pdwConglomerations', DWORD),
        ('ppNames', PLPWSTR_ARRAY),
        ('ppDescriptions', PLPWSTR_ARRAY),
        ('pdwUsers', DWORD),
        ('pdwIsProxy', DWORD),
        ('pcModules', DWORD),
        ('ppModules', PLPWSTR_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.13 IImport2
# 3.1.4.13.1 SetPartition (Opnum 3)
class IImport2_SetPartition(DCOMCALL):
    opnum = 3
    structure = (
        ('pPartitionIdentifier', PGUID),
    )

class IImport2_SetPartitionResponse(DCOMANSWER):
    structure = (
        ('pReserved', GUID),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.14 IExport
# 3.1.4.14.1 ExportConglomeration (Opnum 3)
class IExport_ExportConglomeration(DCOMCALL):
    opnum = 3
    structure = (
        ('pConglomerationIdentifier', PGUID),
        ('pwszInstallerPackage', LPWSTR),
        ('pwszReserved', LPWSTR),
        ('dwFlags', DWORD),
    )

class IExport_ExportConglomerationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.15 IExport2
# 3.1.4.15.1 ExportPartition (Opnum 3)
class IExport2_ExportPartition(DCOMCALL):
    opnum = 3
    structure = (
        ('pPartitionIdentifier', PGUID),
        ('pwszInstallerPackage', LPWSTR),
        ('pwszReserved', LPWSTR),
        ('dwFlags', DWORD),
    )

class IExport2_ExportPartitionResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.16 IAlternateLaunch
# 3.1.4.16.1 CreateConfiguration (Opnum 3)
class IAlternateLaunch_CreateConfiguration(DCOMCALL):
    opnum = 3
    structure = (
        ('ConglomerationIdentifier', GUID),
        ('bstrConfigurationName', BSTR),
        ('dwStartType', DWORD),
        ('dwErrorControl', DWORD),
        ('bstrDependencies', BSTR),
        ('bstrRunAs', BSTR),
        ('bstrPassword', BSTR),
        ('bDesktopOk', VARIANT_BOOL),
    )

class IAlternateLaunch_CreateConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.16.2 DeleteConfiguration (Opnum 4)
class IAlternateLaunch_DeleteConfiguration(DCOMCALL):
    opnum = 4
    structure = (
        ('ConglomerationIdentifier', GUID),
    )

class IAlternateLaunch_DeleteConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.17 ICatalogUtils
# 3.1.4.17.1 ValidateUser (Opnum 3)
class ICatalogUtils_ValidateUser(DCOMCALL):
    opnum = 3
    structure = (
        ('pwszPrincipalName', LPWSTR),
        ('pwszPassword', LPWSTR),
    )

class ICatalogUtils_ValidateUserResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.17.2 WaitForEndWrites (Opnum 4)
class ICatalogUtils_WaitForEndWrites(DCOMCALL):
    opnum = 4
    structure = (
    )

class ICatalogUtils_WaitForEndWritesResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.17.3 GetEventClassesForIID (Opnum 5)
class ICatalogUtils_GetEventClassesForIID(DCOMCALL):
    opnum = 5
    structure = (
        ('wszIID', LPWSTR),
    )

class ICatalogUtils_GetEventClassesForIIDResponse(DCOMANSWER):
    structure = (
        ('pcClasses', DWORD),
        ('pawszCLSIDs', PLPWSTR_ARRAY),
        ('pawszProgIDs', PLPWSTR_ARRAY),
        ('pawszDescriptions', PLPWSTR_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18 ICatalogUtils2
# 3.1.4.18.1 CopyConglomerations (Opnum 3)
class ICatalogUtils2_CopyConglomerations(DCOMCALL):
    opnum = 3
    structure = (
        ('pwszSourcePartition', LPWSTR),
        ('pwszDestPartition', LPWSTR),
        ('cConglomerations', DWORD),
        ('ppwszConglomerationNamesOrIds', PLPWSTR_ARRAY),
    )

class ICatalogUtils2_CopyConglomerationsResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.2 CopyComponentConfiguration (Opnum 4)
class ICatalogUtils2_CopyComponentConfiguration(DCOMCALL):
    opnum = 4
    structure = (
        ('pwszSourceConglomeration', LPWSTR),
        ('pwszComponent', LPWSTR),
        ('pwszDestConglomeration', LPWSTR),
    )

class ICatalogUtils2_CopyComponentConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.3 AliasComponent (Opnum 5)
class ICatalogUtils2_AliasComponent(DCOMCALL):
    opnum = 5
    structure = (
        ('pwszSourceConglomeration', LPWSTR),
        ('pwszComponent', LPWSTR),
        ('pwszDestConglomeration', LPWSTR),
        ('pNewCLSID', PGUID),
        ('pwszNewProgID', LPWSTR),
    )

class ICatalogUtils2_AliasComponentResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.4 MoveComponentConfiguration (Opnum 6)
class ICatalogUtils2_MoveComponentConfiguration(DCOMCALL):
    opnum = 6
    structure = (
        ('pwszSourceConglomeration', LPWSTR),
        ('pwszComponent', LPWSTR),
        ('pwszDestinationConglomeration', LPWSTR),
    )

class ICatalogUtils2_MoveComponentConfigurationResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.5 GetEventClassesForIID2 (Opnum 7)
class ICatalogUtils2_GetEventClassesForIID2(DCOMCALL):
    opnum = 7
    structure = (
        ('wszIID', LPWSTR),
        ('PartitionId', PGUID),
    )

class ICatalogUtils2_GetEventClassesForIID2Response(DCOMANSWER):
    structure = (
        ('pcClasses', DWORD),
        ('pawszCLSIDs', PLPWSTR_ARRAY),
        ('pawszProgIDs', PLPWSTR_ARRAY),
        ('pawszDescriptions', PLPWSTR_ARRAY),
        ('pawszConglomerationIDs', PLPWSTR_ARRAY),
        ('padwIsPrivate', PDWORD_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.6 IsSafeToDelete (Opnum 8)
class ICatalogUtils2_IsSafeToDelete(DCOMCALL):
    opnum = 8
    structure = (
        ('bstrFile', BSTR),
    )

class ICatalogUtils2_IsSafeToDeleteResponse(DCOMANSWER):
    structure = (
        ('pInUse', LONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.7 FlushPartitionCache (Opnum 9)
class ICatalogUtils2_FlushPartitionCache(DCOMCALL):
    opnum = 9
    structure = (
    )

class ICatalogUtils2_FlushPartitionCacheResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.8 EnumerateSRPLevels (Opnum 10)
class ICatalogUtils2_EnumerateSRPLevels(DCOMCALL):
    opnum = 10
    structure = (
        ('Locale', DWORD),
    )

class ICatalogUtils2_EnumerateSRPLevelsResponse(DCOMANSWER):
    structure = (
        ('cLevels', INT),
        ('aSRPLevels', PSRP_LEVEL_INFO_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.18.9 GetComponentVersions (Opnum 11)
class ICatalogUtils2_GetComponentVersions(DCOMCALL):
    opnum = 11
    structure = (
        ('pwszClsidOrProgId', LPWSTR),
    )

class ICatalogUtils2_GetComponentVersionsResponse(DCOMANSWER):
    structure = (
        ('pdwVersions', DWORD),
        ('ppPartitionIDs', PGUID_ARRAY),
        ('ppConglomerationIDs', PGUID_ARRAY),
        ('ppIsPrivate', PBOOL_ARRAY),
        ('ppBitness', PLONG_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.19 ICapabilitySupport
# 3.1.4.19.1 Start (Opnum 3)
class ICapabilitySupport_Start(DCOMCALL):
    opnum = 3
    structure = (
        ('i_css', CatSrvServices),
    )

class ICapabilitySupport_StartResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.19.2 Stop (Opnum 4)
class ICapabilitySupport_Stop(DCOMCALL):
    opnum = 4
    structure = (
        ('i_css', CatSrvServices),
    )

class ICapabilitySupport_StopResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.19.3 IsInstalled (Opnum 7)
class ICapabilitySupport_IsInstalled(DCOMCALL):
    opnum = 7
    structure = (
        ('i_css', CatSrvServices),
    )

class ICapabilitySupport_IsInstalledResponse(DCOMANSWER):
    structure = (
        ('pulStatus', ULONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.19.4 IsRunning (Opnum 8)
class ICapabilitySupport_IsRunning(DCOMCALL):
    opnum = 8
    structure = (
        ('i_css', CatSrvServices),
    )

class ICapabilitySupport_IsRunningResponse(DCOMANSWER):
    structure = (
        ('pulStates', CatSrvServiceState),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.20 IContainerControl
# 3.1.4.20.1 CreateContainer (Opnum 3)
class IContainerControl_CreateContainer(DCOMCALL):
    opnum = 3
    structure = (
        ('pConglomerationIdentifier', PGUID),
    )

class IContainerControl_CreateContainerResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.20.2 ShutdownContainers (Opnum 4)
class IContainerControl_ShutdownContainers(DCOMCALL):
    opnum = 4
    structure = (
        ('pConglomerationIdentifier', PGUID),
    )

class IContainerControl_ShutdownContainersResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.20.3 RefreshComponents (Opnum 5)
class IContainerControl_RefreshComponents(DCOMCALL):
    opnum = 5
    structure = (
    )

class IContainerControl_RefreshComponentsResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21 IContainerControl2
# 3.1.4.21.1 ShutdownContainer (Opnum 3)
class IContainerControl2_ShutdownContainer(DCOMCALL):
    opnum = 3
    structure = (
        ('ContainerIdentifier', PGUID),
    )

class IContainerControl2_ShutdownContainerResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.2 PauseContainer (Opnum 4)
class IContainerControl2_PauseContainer(DCOMCALL):
    opnum = 4
    structure = (
        ('ContainerIdentifier', PGUID),
    )

class IContainerControl2_PauseContainerResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.3 ResumeContainer (Opnum 5)
class IContainerControl2_ResumeContainer(DCOMCALL):
    opnum = 5
    structure = (
        ('ContainerIdentifier', PGUID),
    )

class IContainerControl2_ResumeContainerResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.4 IsContainerPaused (Opnum 6)
class IContainerControl2_IsContainerPaused(DCOMCALL):
    opnum = 6
    structure = (
        ('ContainerIdentifier', PGUID),
    )

class IContainerControl2_IsContainerPausedResponse(DCOMANSWER):
    structure = (
        ('bPaused', BOOL),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.5 GetRunningContainers (Opnum 7)
class IContainerControl2_GetRunningContainers(DCOMCALL):
    opnum = 7
    structure = (
        ('PartitionId', PGUID),
        ('ConglomerationId', PGUID),
    )

class IContainerControl2_GetRunningContainersResponse(DCOMANSWER):
    structure = (
        ('pdwNumContainers', DWORD),
        ('ppContainers', PINSTANCE_CONTAINER_ARRAY),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.6 GetContainerIDFromProcessID (Opnum 8)
class IContainerControl2_GetContainerIDFromProcessID(DCOMCALL):
    opnum = 8
    structure = (
        ('dwPID', DWORD),
    )

class IContainerControl2_GetContainerIDFromProcessIDResponse(DCOMANSWER):
    structure = (
        ('pbstrContainerID', BSTR),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.7 RecycleContainer (Opnum 9)
class IContainerControl2_RecycleContainer(DCOMCALL):
    opnum = 9
    structure = (
        ('ContainerIdentifier', PGUID),
        ('lReasonCode', LONG),
    )

class IContainerControl2_RecycleContainerResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.21.8 GetContainerIDFromConglomerationID (Opnum 10)
class IContainerControl2_GetContainerIDFromConglomerationID(DCOMCALL):
    opnum = 10
    structure = (
        ('ConglomerationIdentifier', PGUID),
    )

class IContainerControl2_GetContainerIDFromConglomerationIDResponse(DCOMANSWER):
    structure = (
        ('ContainerIdentifier', GUID),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.22 IReplicationUtil
# 3.1.4.22.1 CreateShare (Opnum 3)
class IReplicationUtil_CreateShare(DCOMCALL):
    opnum = 3
    structure = (
        ('pwszShareName', LPWSTR),
        ('pwszPath', LPWSTR),
    )

class IReplicationUtil_CreateShareResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.22.2 CreateEmptyDir (Opnum 4)
class IReplicationUtil_CreateEmptyDir(DCOMCALL):
    opnum = 4
    structure = (
        ('pwszPath', LPWSTR),
    )

class IReplicationUtil_CreateEmptyDirResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.22.3 RemoveShare (Opnum 5)
class IReplicationUtil_RemoveShare(DCOMCALL):
    opnum = 5
    structure = (
        ('pwszShareName', LPWSTR),
    )

class IReplicationUtil_RemoveShareResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.22.4 BeginReplicationAsTarget (Opnum 6)
class IReplicationUtil_BeginReplicationAsTarget(DCOMCALL):
    opnum = 6
    structure = (
        ('pwszBaseReplicationDir', LPWSTR),
    )

class IReplicationUtil_BeginReplicationAsTargetResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )

# 3.1.4.22.5 QueryConglomerationPassword (Opnum 7)
class IReplicationUtil_QueryConglomerationPassword(DCOMCALL):
    opnum = 7
    structure = (
        ('ConglomerationId', PGUID),
    )

class IReplicationUtil_QueryConglomerationPasswordResponse(DCOMANSWER):
    structure = (
        ('ppvPassword', PBYTE_ARRAY),
        ('pcbPassword', ULONG),
        ('ErrorCode', error_status_t),
    )

# 3.1.4.22.6 CreateReplicationDir (Opnum 8)
class IReplicationUtil_CreateReplicationDir(DCOMCALL):
    opnum = 8
    structure = (
    )

class IReplicationUtil_CreateReplicationDirResponse(DCOMANSWER):
    structure = (
        ('ppwszBaseReplicationDir', LPWSTR),
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
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def _align4(data):
    return data + b'\x00' * ((4 - len(data) % 4) % 4)

def packQueryCell(indexOrOption, comparisonDataType, comparisonDataSize, queryOperator = eOPERATOR_EQUAL,
                  nonNullComparisonData = True, is64Bit = False):
    if is64Bit is True:
        return pack('<QLLLL', int(bool(nonNullComparisonData)), queryOperator, indexOrOption, comparisonDataType,
                    comparisonDataSize)
    return pack('<LLLLL', int(bool(nonNullComparisonData)), queryOperator, indexOrOption, comparisonDataType,
                comparisonDataSize)

def packQueryComparisonData(comparisonDataType, data):
    if data is None:
        return b''
    if comparisonDataType == eDataType.eDT_ULONG:
        return pack('<L', data)
    if comparisonDataType == eDataType.eDT_GUID:
        return data
    if comparisonDataType == eDataType.eDT_LPWSTR:
        if data[-1:] != '\x00':
            data += '\x00'
        return _align4(data.encode('utf-16le'))
    return _align4(data)

def packTableDetailedErrors(errors):
    data = b''
    for entryIndex, reason, propertyIndex in errors:
        data += pack('<LLL', entryIndex, reason, propertyIndex)
    return data

def unpackTableDetailedErrors(data):
    errors = list()
    for offset in range(0, len(data), 12):
        errors.append(unpack('<LLL', data[offset:offset + 12]))
    return errors

class ICatalogSession(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalogSession

    def InitializeSession(self, flVerLower, flVerUpper, reserved = 0):
        request = ICatalogSession_InitializeSession()
        request['flVerLower'] = flVerLower
        request['flVerUpper'] = flVerUpper
        request['reserved'] = reserved
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetServerInformation(self):
        request = ICatalogSession_GetServerInformation()
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class ICatalog64BitSupport(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalog64BitSupport

    def SupportsMultipleBitness(self):
        request = ICatalog64BitSupport_SupportsMultipleBitness()
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def Initialize64BitQueryCellSupport(self, bClientSupports64BitQueryCells):
        request = ICatalog64BitSupport_Initialize64BitQueryCellSupport()
        request['bClientSupports64BitQueryCells'] = bClientSupports64BitQueryCells
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class ICatalogTableInfo(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalogTableInfo

    def GetClientTableInfo(self, pCatalogIdentifier, pTableIdentifier, tableFlags = fTABLE_UNSPECIFIED,
                           pQueryCellArray = b'', pQueryComparison = b'', eQueryFormat = eQUERYFORMAT_1):
        request = ICatalogTableInfo_GetClientTableInfo()
        request['pCatalogIdentifier'] = pCatalogIdentifier
        request['pTableIdentifier'] = pTableIdentifier
        request['tableFlags'] = tableFlags
        request['pQueryCellArray'] = pQueryCellArray if pQueryCellArray else NULL
        request['cbQueryCellArray'] = len(pQueryCellArray)
        request['pQueryComparison'] = pQueryComparison if pQueryComparison else NULL
        request['cbQueryComparison'] = len(pQueryComparison)
        request['eQueryFormat'] = eQueryFormat
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        if resp['piid']['Data'] == IID_ICatalogTableWrite:
            return ICatalogTableWrite(INTERFACE(self.get_cinstance(), b''.join(resp['pItf']['abData']),
                                                self.get_ipidRemUnknown(), target = self.get_target()))
        return ICatalogTableRead(INTERFACE(self.get_cinstance(), b''.join(resp['pItf']['abData']),
                                           self.get_ipidRemUnknown(), target = self.get_target()))

class ICatalogTableRead(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalogTableRead

    def ReadTable(self, pCatalogIdentifier, pTableIdentifier, tableFlags = fTABLE_UNSPECIFIED,
                  pQueryCellArray = b'', pQueryComparison = b'', eQueryFormat = eQUERYFORMAT_1):
        request = ICatalogTableRead_ReadTable()
        request['pCatalogIdentifier'] = pCatalogIdentifier
        request['pTableIdentifier'] = pTableIdentifier
        request['tableFlags'] = tableFlags
        request['pQueryCellArray'] = pQueryCellArray if pQueryCellArray else NULL
        request['cbQueryCellArray'] = len(pQueryCellArray)
        request['pQueryComparison'] = pQueryComparison if pQueryComparison else NULL
        request['cbQueryComparison'] = len(pQueryComparison)
        request['eQueryFormat'] = eQueryFormat
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class ICatalogTableWrite(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalogTableWrite

    def WriteTable(self, pCatalogIdentifier, pTableIdentifier, tableFlags = fTABLE_UNSPECIFIED,
                   pQueryCellArray = b'', pQueryComparison = b'', eQueryFormat = eQUERYFORMAT_1,
                   pTableDataFixedWrite = b'', pTableDataVariable = b''):
        request = ICatalogTableWrite_WriteTable()
        request['pCatalogIdentifier'] = pCatalogIdentifier
        request['pTableIdentifier'] = pTableIdentifier
        request['tableFlags'] = tableFlags
        request['pQueryCellArray'] = pQueryCellArray if pQueryCellArray else NULL
        request['cbQueryCellArray'] = len(pQueryCellArray)
        request['pQueryComparison'] = pQueryComparison if pQueryComparison else NULL
        request['cbQueryComparison'] = len(pQueryComparison)
        request['eQueryFormat'] = eQueryFormat
        request['pTableDataFixedWrite'] = pTableDataFixedWrite if pTableDataFixedWrite else NULL
        request['cbTableDataFixedWrite'] = len(pTableDataFixedWrite)
        request['pTableDataVariable'] = pTableDataVariable if pTableDataVariable else NULL
        request['cbTableDataVariable'] = len(pTableDataVariable)
        request['pReserved1'] = NULL
        request['cbReserved1'] = 0
        request['pReserved2'] = NULL
        request['cbReserved2'] = 0
        request['pReserved3'] = NULL
        request['cbReserved3'] = 0
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IRegister(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IRegister

    def RegisterModule(self, ConglomerationIdentifier, ppModules, dwFlags = 0, pRequestedCLSIDs = None):
        request = IRegister_RegisterModule()
        request['ConglomerationIdentifier'] = ConglomerationIdentifier
        request['cModules'] = len(ppModules)
        for module in ppModules:
            item = LPWSTR()
            item['Data'] = checkNullString(module)
            request['ppModules'].append(item)
        request['dwFlags'] = dwFlags
        if pRequestedCLSIDs is None:
            request['pRequestedCLSIDs'] = NULL
            request['cRequested'] = 0
        else:
            request['cRequested'] = len(pRequestedCLSIDs)
            for clsid in pRequestedCLSIDs:
                item = GUID()
                item['Data'] = clsid
                request['pRequestedCLSIDs'].append(item)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IRegister2(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IRegister2

    def CreateFullConfiguration(self, pwszConglomerationIdOrName, pwszCLSIDOrProgId,
                                ctComponentType = eComponentType.eCT_UNKNOWN):
        request = IRegister2_CreateFullConfiguration()
        request['pwszConglomerationIdOrName'] = checkNullString(pwszConglomerationIdOrName)
        request['pwszCLSIDOrProgId'] = checkNullString(pwszCLSIDOrProgId)
        request['ctComponentType'] = ctComponentType
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def CreateLegacyConfiguration(self, pwszConglomerationIdOrName, pwszCLSIDOrProgId,
                                  ctComponentType = eComponentType.eCT_UNKNOWN):
        request = IRegister2_CreateLegacyConfiguration()
        request['pwszConglomerationIdOrName'] = checkNullString(pwszConglomerationIdOrName)
        request['pwszCLSIDOrProgId'] = checkNullString(pwszCLSIDOrProgId)
        request['ctComponentType'] = ctComponentType
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def PromoteLegacyConfiguration(self, pwszConglomerationIdOrName, pwszCLSIDOrProgId,
                                   ctComponentType = eComponentType.eCT_UNKNOWN):
        request = IRegister2_PromoteLegacyConfiguration()
        request['pwszConglomerationIdOrName'] = checkNullString(pwszConglomerationIdOrName)
        request['pwszCLSIDOrProgId'] = checkNullString(pwszCLSIDOrProgId)
        request['ctComponentType'] = ctComponentType
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def RegisterModule2(self, ConglomerationIdentifier, PartitionIdentifier, ppModules, dwFlags = 0,
                        pRequestedCLSIDs = None):
        request = IRegister2_RegisterModule2()
        request['ConglomerationIdentifier'] = ConglomerationIdentifier
        request['PartitionIdentifier'] = PartitionIdentifier
        request['cModules'] = len(ppModules)
        for module in ppModules:
            item = LPWSTR()
            item['Data'] = checkNullString(module)
            request['ppModules'].append(item)
        request['dwFlags'] = dwFlags
        if pRequestedCLSIDs is None:
            request['pRequestedCLSIDs'] = NULL
            request['cRequested'] = 0
        else:
            request['cRequested'] = len(pRequestedCLSIDs)
            for clsid in pRequestedCLSIDs:
                item = GUID()
                item['Data'] = clsid
                request['pRequestedCLSIDs'].append(item)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IImport(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IImport

    def ImportFromFile(self, pwszModuleDestination, pwszInstallerPackage, pwszUser = None, pwszPassword = None,
                       pwszRemoteServerName = None, dwFlags = 0, reserved2 = 0):
        request = IImport_ImportFromFile()
        request['pwszModuleDestination'] = checkNullString(pwszModuleDestination)
        request['pwszInstallerPackage'] = checkNullString(pwszInstallerPackage)
        request['pwszUser'] = NULL if pwszUser is None else checkNullString(pwszUser)
        request['pwszPassword'] = NULL if pwszPassword is None else checkNullString(pwszPassword)
        request['pwszRemoteServerName'] = NULL if pwszRemoteServerName is None else checkNullString(pwszRemoteServerName)
        request['dwFlags'] = dwFlags
        request['reserved1'] = NULL
        request['reserved2'] = reserved2
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def QueryFile(self, pwszInstallerPackage):
        request = IImport_QueryFile()
        request['pwszInstallerPackage'] = checkNullString(pwszInstallerPackage)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IImport2(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IImport2

    def SetPartition(self, pPartitionIdentifier):
        request = IImport2_SetPartition()
        request['pPartitionIdentifier'] = pPartitionIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IExport(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IExport

    def ExportConglomeration(self, pConglomerationIdentifier, pwszInstallerPackage, pwszReserved = None, dwFlags = 0):
        request = IExport_ExportConglomeration()
        request['pConglomerationIdentifier'] = pConglomerationIdentifier
        request['pwszInstallerPackage'] = checkNullString(pwszInstallerPackage)
        request['pwszReserved'] = NULL if pwszReserved is None else checkNullString(pwszReserved)
        request['dwFlags'] = dwFlags
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IExport2(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IExport2

    def ExportPartition(self, pPartitionIdentifier, pwszInstallerPackage, pwszReserved = None, dwFlags = 0):
        request = IExport2_ExportPartition()
        request['pPartitionIdentifier'] = pPartitionIdentifier
        request['pwszInstallerPackage'] = checkNullString(pwszInstallerPackage)
        request['pwszReserved'] = NULL if pwszReserved is None else checkNullString(pwszReserved)
        request['dwFlags'] = dwFlags
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IAlternateLaunch(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IAlternateLaunch

    def CreateConfiguration(self, ConglomerationIdentifier, bstrConfigurationName, dwStartType, dwErrorControl,
                            bstrDependencies, bstrRunAs, bstrPassword, bDesktopOk):
        request = IAlternateLaunch_CreateConfiguration()
        request['ConglomerationIdentifier'] = ConglomerationIdentifier
        request['bstrConfigurationName']['asData'] = bstrConfigurationName
        request['dwStartType'] = dwStartType
        request['dwErrorControl'] = dwErrorControl
        if bstrDependencies is None:
            request['bstrDependencies'] = NULL
        else:
            request['bstrDependencies']['asData'] = bstrDependencies
        request['bstrRunAs']['asData'] = bstrRunAs
        if bstrPassword is None:
            request['bstrPassword'] = NULL
        else:
            request['bstrPassword']['asData'] = bstrPassword
        request['bDesktopOk'] = bDesktopOk
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def DeleteConfiguration(self, ConglomerationIdentifier):
        request = IAlternateLaunch_DeleteConfiguration()
        request['ConglomerationIdentifier'] = ConglomerationIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class ICatalogUtils(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalogUtils

    def ValidateUser(self, pwszPrincipalName = None, pwszPassword = None):
        request = ICatalogUtils_ValidateUser()
        request['pwszPrincipalName'] = NULL if pwszPrincipalName is None else checkNullString(pwszPrincipalName)
        request['pwszPassword'] = NULL if pwszPassword is None else checkNullString(pwszPassword)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def WaitForEndWrites(self):
        request = ICatalogUtils_WaitForEndWrites()
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetEventClassesForIID(self, wszIID = None):
        request = ICatalogUtils_GetEventClassesForIID()
        request['wszIID'] = NULL if wszIID is None else checkNullString(wszIID)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class ICatalogUtils2(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICatalogUtils2

    def CopyConglomerations(self, pwszSourcePartition, pwszDestPartition, ppwszConglomerationNamesOrIds):
        request = ICatalogUtils2_CopyConglomerations()
        request['pwszSourcePartition'] = checkNullString(pwszSourcePartition)
        request['pwszDestPartition'] = checkNullString(pwszDestPartition)
        request['cConglomerations'] = len(ppwszConglomerationNamesOrIds)
        for name in ppwszConglomerationNamesOrIds:
            item = LPWSTR()
            item['Data'] = checkNullString(name)
            request['ppwszConglomerationNamesOrIds'].append(item)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def CopyComponentConfiguration(self, pwszSourceConglomeration, pwszComponent, pwszDestConglomeration):
        request = ICatalogUtils2_CopyComponentConfiguration()
        request['pwszSourceConglomeration'] = checkNullString(pwszSourceConglomeration)
        request['pwszComponent'] = checkNullString(pwszComponent)
        request['pwszDestConglomeration'] = checkNullString(pwszDestConglomeration)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def AliasComponent(self, pwszSourceConglomeration, pwszComponent, pwszDestConglomeration, pNewCLSID,
                       pwszNewProgID):
        request = ICatalogUtils2_AliasComponent()
        request['pwszSourceConglomeration'] = checkNullString(pwszSourceConglomeration)
        request['pwszComponent'] = checkNullString(pwszComponent)
        request['pwszDestConglomeration'] = checkNullString(pwszDestConglomeration)
        request['pNewCLSID'] = pNewCLSID
        request['pwszNewProgID'] = checkNullString(pwszNewProgID)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def MoveComponentConfiguration(self, pwszSourceConglomeration, pwszComponent, pwszDestinationConglomeration):
        request = ICatalogUtils2_MoveComponentConfiguration()
        request['pwszSourceConglomeration'] = checkNullString(pwszSourceConglomeration)
        request['pwszComponent'] = checkNullString(pwszComponent)
        request['pwszDestinationConglomeration'] = checkNullString(pwszDestinationConglomeration)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetEventClassesForIID2(self, wszIID, PartitionId):
        request = ICatalogUtils2_GetEventClassesForIID2()
        request['wszIID'] = checkNullString(wszIID)
        request['PartitionId'] = PartitionId
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def IsSafeToDelete(self, bstrFile):
        request = ICatalogUtils2_IsSafeToDelete()
        request['bstrFile']['asData'] = bstrFile
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def FlushPartitionCache(self):
        request = ICatalogUtils2_FlushPartitionCache()
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def EnumerateSRPLevels(self, Locale):
        request = ICatalogUtils2_EnumerateSRPLevels()
        request['Locale'] = Locale
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetComponentVersions(self, pwszClsidOrProgId):
        request = ICatalogUtils2_GetComponentVersions()
        request['pwszClsidOrProgId'] = checkNullString(pwszClsidOrProgId)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class ICapabilitySupport(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_ICapabilitySupport

    def Start(self, i_css):
        request = ICapabilitySupport_Start()
        request['i_css'] = i_css
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def Stop(self, i_css):
        request = ICapabilitySupport_Stop()
        request['i_css'] = i_css
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def IsInstalled(self, i_css):
        request = ICapabilitySupport_IsInstalled()
        request['i_css'] = i_css
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def IsRunning(self, i_css):
        request = ICapabilitySupport_IsRunning()
        request['i_css'] = i_css
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IContainerControl(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IContainerControl

    def CreateContainer(self, pConglomerationIdentifier):
        request = IContainerControl_CreateContainer()
        request['pConglomerationIdentifier'] = pConglomerationIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def ShutdownContainers(self, pConglomerationIdentifier):
        request = IContainerControl_ShutdownContainers()
        request['pConglomerationIdentifier'] = pConglomerationIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def RefreshComponents(self):
        request = IContainerControl_RefreshComponents()
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IContainerControl2(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IContainerControl2

    def ShutdownContainer(self, ContainerIdentifier):
        request = IContainerControl2_ShutdownContainer()
        request['ContainerIdentifier'] = ContainerIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def PauseContainer(self, ContainerIdentifier):
        request = IContainerControl2_PauseContainer()
        request['ContainerIdentifier'] = ContainerIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def ResumeContainer(self, ContainerIdentifier):
        request = IContainerControl2_ResumeContainer()
        request['ContainerIdentifier'] = ContainerIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def IsContainerPaused(self, ContainerIdentifier):
        request = IContainerControl2_IsContainerPaused()
        request['ContainerIdentifier'] = ContainerIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetRunningContainers(self, PartitionId, ConglomerationId):
        request = IContainerControl2_GetRunningContainers()
        request['PartitionId'] = PartitionId
        request['ConglomerationId'] = ConglomerationId
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetContainerIDFromProcessID(self, dwPID):
        request = IContainerControl2_GetContainerIDFromProcessID()
        request['dwPID'] = dwPID
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def RecycleContainer(self, ContainerIdentifier, lReasonCode):
        request = IContainerControl2_RecycleContainer()
        request['ContainerIdentifier'] = ContainerIdentifier
        request['lReasonCode'] = lReasonCode
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def GetContainerIDFromConglomerationID(self, ConglomerationIdentifier):
        request = IContainerControl2_GetContainerIDFromConglomerationID()
        request['ConglomerationIdentifier'] = ConglomerationIdentifier
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

class IReplicationUtil(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IReplicationUtil

    def CreateShare(self, pwszShareName, pwszPath):
        request = IReplicationUtil_CreateShare()
        request['pwszShareName'] = checkNullString(pwszShareName)
        request['pwszPath'] = checkNullString(pwszPath)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def CreateEmptyDir(self, pwszPath):
        request = IReplicationUtil_CreateEmptyDir()
        request['pwszPath'] = checkNullString(pwszPath)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def RemoveShare(self, pwszShareName):
        request = IReplicationUtil_RemoveShare()
        request['pwszShareName'] = checkNullString(pwszShareName)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def BeginReplicationAsTarget(self, pwszBaseReplicationDir):
        request = IReplicationUtil_BeginReplicationAsTarget()
        request['pwszBaseReplicationDir'] = checkNullString(pwszBaseReplicationDir)
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def QueryConglomerationPassword(self, ConglomerationId):
        request = IReplicationUtil_QueryConglomerationPassword()
        request['ConglomerationId'] = ConglomerationId
        return self.request(request, iid = self._iid, uuid = self.get_iPid())

    def CreateReplicationDir(self):
        request = IReplicationUtil_CreateReplicationDir()
        return self.request(request, iid = self._iid, uuid = self.get_iPid())
