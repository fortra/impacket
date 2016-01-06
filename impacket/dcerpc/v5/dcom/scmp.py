# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-SCMP]: Shadow Copy Management Protocol Interface implementation
#              This was used as a way to test the DCOM runtime. Further 
#              testing is needed to verify it is working as expected
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/CoreSecurity/impacket/tree/master/impacket/testcases/SMB_RPC
#
#   Since DCOM is like an OO RPC, instead of helper functions you will see the 
#   classes described in the standards developed. 
#   There are test cases for them too. 
#
from impacket.dcerpc.v5.ndr import NDRENUM, NDRSTRUCT, NDRUNION
from impacket.dcerpc.v5.dcomrt import PMInterfacePointer, INTERFACE, DCOMCALL, DCOMANSWER, IRemUnknown2
from impacket.dcerpc.v5.dtypes import LONG, LONGLONG, ULONG, WSTR
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors
from impacket.uuid import string_to_bin

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        if hresult_errors.ERROR_MESSAGES.has_key(self.error_code):
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'SCMP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SCMP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 1.9 Standards Assignments
CLSID_ShadowCopyProvider = string_to_bin('0b5a2c52-3eb9-470a-96e2-6c6d4570e40f')
IID_IVssSnapshotMgmt = string_to_bin('FA7DF749-66E7-4986-A27F-E2F04AE53772')
IID_IVssEnumObject   = string_to_bin('AE1C7110-2F60-11d3-8A39-00C04F72D8E3')
IID_IVssDifferentialSoftwareSnapshotMgmt = string_to_bin('214A0F28-B737-4026-B847-4F9E37D79529')
IID_IVssEnumMgmtObject = string_to_bin('01954E6B-9254-4e6e-808C-C9E05D007696')
IID_ShadowCopyProvider = string_to_bin('B5946137-7B9F-4925-AF80-51ABD60B20D5')

# 2.2.1.1 VSS_ID
class VSS_ID(NDRSTRUCT):
    structure = (
        ('Data','16s=""'),
    )

    def getAlignment(self):
        return 2

#2.2.1.2 VSS_PWSZ
VSS_PWSZ = WSTR

# 2.2.1.3 VSS_TIMESTAMP
VSS_TIMESTAMP = LONGLONG

error_status_t = LONG
################################################################################
# STRUCTURES
################################################################################
# 2.2.2.1 VSS_OBJECT_TYPE Enumeration
class VSS_OBJECT_TYPE(NDRENUM):
    class enumItems(Enum):
        VSS_OBJECT_UNKNOWN      = 0
        VSS_OBJECT_NONE         = 1
        VSS_OBJECT_SNAPSHOT_SET = 2
        VSS_OBJECT_SNAPSHOT     = 3
        VSS_OBJECT_PROVIDER     = 4
        VSS_OBJECT_TYPE_COUNT   = 5

# 2.2.2.2 VSS_MGMT_OBJECT_TYPE Enumeration
class VSS_MGMT_OBJECT_TYPE(NDRENUM):
    class enumItems(Enum):
        VSS_MGMT_OBJECT_UNKNOWN     = 0
        VSS_MGMT_OBJECT_VOLUME      = 1
        VSS_MGMT_OBJECT_DIFF_VOLUME = 2
        VSS_MGMT_OBJECT_DIFF_AREA   = 3

# 2.2.2.3 VSS_VOLUME_SNAPSHOT_ATTRIBUTES Enumeration
class VSS_VOLUME_SNAPSHOT_ATTRIBUTES(NDRENUM):
    class enumItems(Enum):
        VSS_VOLSNAP_ATTR_PERSISTENT        = 0x01
        VSS_VOLSNAP_ATTR_NO_AUTORECOVERY   = 0x02
        VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE = 0x04
        VSS_VOLSNAP_ATTR_NO_AUTO_RELEASE   = 0x08
        VSS_VOLSNAP_ATTR_NO_WRITERS        = 0x10

# 2.2.2.4 VSS_SNAPSHOT_STATE Enumeration
class VSS_SNAPSHOT_STATE(NDRENUM):
    class enumItems(Enum):
        VSS_SS_UNKNOWN  = 0x01
        VSS_SS_CREATED  = 0x0c

# 2.2.2.5 VSS_PROVIDER_TYPE Enumeration
class  VSS_PROVIDER_TYPE(NDRENUM):
    class enumItems(Enum):
        VSS_PROV_UNKNOWN  = 0

# 2.2.3.7 VSS_VOLUME_PROP Structure
class VSS_VOLUME_PROP(NDRSTRUCT):
    structure = (
        ('m_pwszVolumeName', VSS_PWSZ),
        ('m_pwszVolumeDisplayName', VSS_PWSZ),
    )

# 2.2.3.5 VSS_MGMT_OBJECT_UNION Union
class VSS_MGMT_OBJECT_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        VSS_MGMT_OBJECT_TYPE.VSS_MGMT_OBJECT_VOLUME: ('Vol', VSS_VOLUME_PROP),
        #VSS_MGMT_OBJECT_DIFF_VOLUME: ('DiffVol', VSS_DIFF_VOLUME_PROP),
        #VSS_MGMT_OBJECT_DIFF_AREA: ('DiffArea', VSS_DIFF_AREA_PROP),
    }

# 2.2.3.6 VSS_MGMT_OBJECT_PROP Structure
class VSS_MGMT_OBJECT_PROP(NDRSTRUCT):
    structure = (
        ('Type', VSS_MGMT_OBJECT_TYPE),
        ('Obj', VSS_MGMT_OBJECT_UNION),
    )

################################################################################
# RPC CALLS
################################################################################
# 3.1.3 IVssEnumMgmtObject Details

# 3.1.3.1 Next (Opnum 3)
class IVssEnumMgmtObject_Next(DCOMCALL):
    opnum = 3
    structure = (
       ('celt', ULONG),
    )

class IVssEnumMgmtObject_NextResponse(DCOMANSWER):
    structure = (
       ('rgelt', VSS_MGMT_OBJECT_PROP),
       ('pceltFetched', ULONG),
       ('ErrorCode', error_status_t),
    )

# 3.1.2.1 Next (Opnum 3)
class IVssEnumObject_Next(DCOMCALL):
    opnum = 3
    structure = (
       ('celt', ULONG),
    )

class IVssEnumObject_NextResponse(DCOMANSWER):
    structure = (
       ('rgelt', VSS_MGMT_OBJECT_PROP),
       ('pceltFetched', ULONG),
       ('ErrorCode', error_status_t),
    )

class GetProviderMgmtInterface(DCOMCALL):
    opnum = 3
    structure = (
       ('ProviderId', VSS_ID),
       ('InterfaceId', VSS_ID),
    )

class GetProviderMgmtInterfaceResponse(DCOMANSWER):
    structure = (
       ('ppItf', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

class QueryVolumesSupportedForSnapshots(DCOMCALL):
    opnum = 4
    structure = (
       ('ProviderId', VSS_ID),
       ('IContext', LONG),
    )

class QueryVolumesSupportedForSnapshotsResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

class QuerySnapshotsByVolume(DCOMCALL):
    opnum = 5
    structure = (
       ('pwszVolumeName', VSS_PWSZ),
       ('ProviderId', VSS_ID),
    )

class QuerySnapshotsByVolumeResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.5 QueryDiffAreasForVolume (Opnum 6)
class QueryDiffAreasForVolume(DCOMCALL):
    opnum = 6
    structure = (
       ('pwszVolumeName', VSS_PWSZ),
    )

class QueryDiffAreasForVolumeResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

# 3.1.4.4.6 QueryDiffAreasOnVolume (Opnum 7)
class QueryDiffAreasOnVolume(DCOMCALL):
    opnum = 7
    structure = (
       ('pwszVolumeName', VSS_PWSZ),
    )

class QueryDiffAreasOnVolumeResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
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
class IVssEnumMgmtObject(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IVssEnumMgmtObject

    def Next(self, celt):
        request = IVssEnumMgmtObject_Next()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        request['celt'] = celt
        resp = self.request(request, self._iid, uuid = self.get_iPid())
        return resp 

class IVssEnumObject(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IVssEnumObject

    def Next(self, celt):
        request = IVssEnumObject_Next()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        request['celt'] = celt
        dce = self.connect()
        resp = dce.request(request, self._iid, uuid = self.get_iPid())
        return resp 

class IVssSnapshotMgmt(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IVssSnapshotMgmt

    def GetProviderMgmtInterface(self, providerId = IID_ShadowCopyProvider, interfaceId = IID_IVssDifferentialSoftwareSnapshotMgmt):
        req = GetProviderMgmtInterface()
        classInstance = self.get_cinstance()
        req['ORPCthis'] = classInstance.get_ORPCthis()
        req['ORPCthis']['flags'] = 0
        req['ProviderId'] = providerId
        req['InterfaceId'] = interfaceId
        resp = self.request(req, self._iid, uuid = self.get_iPid())
        return IVssDifferentialSoftwareSnapshotMgmt(INTERFACE(classInstance, ''.join(resp['ppItf']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))

    def QueryVolumesSupportedForSnapshots(self, providerId, iContext):
        req = QueryVolumesSupportedForSnapshots()
        classInstance = self.get_cinstance()
        req['ORPCthis'] = classInstance.get_ORPCthis()
        req['ORPCthis']['flags'] = 0
        req['ProviderId'] = providerId
        req['IContext'] = iContext
        resp = self.request(req, self._iid, uuid = self.get_iPid())
        return IVssEnumMgmtObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(),target = self.get_target()))

    def QuerySnapshotsByVolume(self, volumeName, providerId = IID_ShadowCopyProvider):
        req = QuerySnapshotsByVolume()
        classInstance = self.get_cinstance()
        req['ORPCthis'] = classInstance.get_ORPCthis()
        req['ORPCthis']['flags'] = 0
        req['pwszVolumeName'] = volumeName
        req['ProviderId'] = providerId
        try:
            resp = self.request(req, self._iid, uuid = self.get_iPid())
        except DCERPCException, e:
            print e
            from impacket.winregistry import hexdump
            data = e.get_packet()
            hexdump(data)
            kk = QuerySnapshotsByVolumeResponse(data)
            kk.dump()
        #resp.dump()
        return IVssEnumObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))

class IVssDifferentialSoftwareSnapshotMgmt(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IVssDifferentialSoftwareSnapshotMgmt

    def QueryDiffAreasOnVolume(self, pwszVolumeName):
        req = QueryDiffAreasOnVolume()
        classInstance = self.get_cinstance()
        req['ORPCthis'] = classInstance.get_ORPCthis()
        req['ORPCthis']['flags'] = 0
        req['pwszVolumeName'] = pwszVolumeName
        resp = self.request(req, self._iid, uuid = self.get_iPid())
        return IVssEnumMgmtObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))

    def QueryDiffAreasForVolume(self, pwszVolumeName):
        req = QueryDiffAreasForVolume()
        classInstance = self.get_cinstance()
        req['ORPCthis'] = classInstance.get_ORPCthis()
        req['ORPCthis']['flags'] = 0
        req['pwszVolumeName'] = pwszVolumeName
        resp = self.request(req, self._iid, uuid = self.get_iPid())
        return IVssEnumMgmtObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))




