# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (beto@coresecurity.com)
#
# $Id$
#

import array
import struct
import socket
from struct import unpack
from impacket import ImpactPacket
from impacket import uuid
from impacket import dcerpc
from impacket.structure import Structure
from impacket.dcerpc import ndrutils
from impacket.dcerpc import transport
from impacket.uuid import uuidtup_to_bin


MSRPC_UUID_PORTMAP = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

# EPM Constants
# Inquire Type
RPC_C_EP_ALL_ELTS     = 0x0
RPC_C_EP_MATCH_BY_IF  = 0x1
RPC_C_EP_MATH_BY_OBJ  = 0x2
RPC_C_EP_MATH_BY_BOTH = 0x1

# Vers Option
RPC_C_VERS_ALL        = 0x1
RPC_C_VERS_COMPATIBLE = 0x2
RPC_C_VERS_EXACT      = 0x3
RPC_C_VERS_MARJOR_ONLY= 0x4
RPC_C_VERS_UPTO       = 0x5

# Search 
RPC_NO_MORE_ELEMENTS  = 0x16c9a0d6 

KNOWN_PROTOCOLS = {
'4639DB2A-BFC5-11D2-9318-00C04FBBBFB3':'[MS-ADTG]: Remote Data Services (RDS) Transport Protocol',
'0EAC4842-8763-11CF-A743-00AA00A3F00D':'[MS-ADTG]: Remote Data Services (RDS) Transport Protocol',
'070669EB-B52F-11D1-9270-00C04FBBBFB3':'[MS-ADTG]: Remote Data Services (RDS) Transport Protocol',
'3DDE7C30-165D-11D1-AB8F-00805F14DB40':'[MS-BKRP]: BackupKey Remote Protocol ',
'E3D0D746-D2AF-40FD-8A7A-0D7078BB7092':'[MS-BPAU]: Background Intelligent Transfer Service (BITS) Peer-',
'6BFFD098-A112-3610-9833-012892020162':'[MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary',
'D99E6E71-FC88-11D0-B498-00A0C90312F3':'[MS-CSRA]: Certificate Services Remote Administration Protocol',
'7FE0D935-DDA6-443F-85D0-1CFB58FE41DD':'[MS-CSRA]: Certificate Services Remote Administration Protocol',
'00000131-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'00000143-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'000001A0-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'99FCFEC4-5260-101B-BBCB-00AA0021347A':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'00000000-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'4FC742E0-4A10-11CF-8273-00AA004AE673':'[MS-DFSNM]: Distributed File System (DFS):',
'9009D654-250B-4E0D-9AB0-ACB63134F69F':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'E65E8028-83E8-491B-9AF7-AAF6BD51A0CE':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'D3766938-9FB7-4392-AF2F-2CE8749DBBD0':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'4BB8AB1D-9EF9-4100-8EB6-DD4B4E418B72':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'CEB5D7B4-3964-4F71-AC17-4BF57A379D87':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'7A2323C7-9EBE-494A-A33C-3CC329A18E1D':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'20D15747-6C48-4254-A358-65039FD8C63C':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'C4B0C7D9-ABE0-4733-A1E1-9FDEDF260C7A':'[MS-DFSRH]: DFS Replication Helper Protocol ',
'4DA1C422-943D-11D1-ACAE-00C04FC2AA3F':'[MS-DLTM]: Distributed Link Tracking:',
'300F3532-38CC-11D0-A3F0-0020AF6B0ADD':'[MS-DLTW]: Distributed Link Tracking:',
'D2D79DF5-3400-11D0-B40B-00AA005FF586':'[MS-DMRP]: Disk Management Remote Protocol ',
'DEB01010-3A37-4D26-99DF-E2BB6AE3AC61':'[MS-DMRP]: Disk Management Remote Protocol ',
'3A410F21-553F-11D1-8E5E-00A0C92C9D5D':'[MS-DMRP]: Disk Management Remote Protocol ',
'D2D79DF7-3400-11D0-B40B-00AA005FF586':'[MS-DMRP]: Disk Management Remote Protocol ',
'4BDAFC52-FE6A-11D2-93F8-00105A11164A':'[MS-DMRP]: Disk Management Remote Protocol ',
'135698D2-3A37-4D26-99DF-E2BB6AE3AC61':'[MS-DMRP]: Disk Management Remote Protocol ',
'7C44D7D4-31D5-424C-BD5E-2B3E1F323D22':'[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol',
'3919286A-B10C-11D0-9BA8-00C04FD92EF5':'[MS-DSSP]: Directory Services Setup Remote Protocol ',
'14A8831C-BC82-11D2-8A64-0008C7457E5D':'[MS-EERR]: ExtendedError Remote Data Structure',
'C681D488-D850-11D0-8C52-00C04FD90F7E':'[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol',
'82273FDC-E32A-18C3-3F78-827929DC23EA':'[MS-EVEN]: EventLog Remoting Protocol ',
'6B5BDD1E-528C-422C-AF8C-A4079BE4FE48':'[MS-FASP]: Firewall and Advanced Security Protocol ',
'897E2E5F-93F3-4376-9C9C-FD2277495C27':'[MS-FRS2]: Distributed File System Replication Protocol ',
'91AE6020-9E3C-11CF-8D7C-00AA00C091BE':'[MS-ICPR]: ICertPassage Remote Protocol ',
'12345778-1234-ABCD-EF00-0123456789AB':'[MS-LSAD]: Local Security Authority (Domain Policy) Remote Protocol',
'12345778-1234-ABCD-EF00-0123456789AB':'[MS-LSAT]: Local Security Authority (Translation Methods) Remote',
'17FDD703-1827-4E34-79D4-24A55C53BB37':'[MS-MSRP]: Messenger Service Remote Protocol ',
'12345678-1234-ABCD-EF00-01234567CFFB':'[MS-NRPC]: Netlogon Remote Protocol ',
'00020411-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'00020401-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'00020403-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'00020412-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'00020402-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'00020400-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'00020404-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol ',
'AE33069B-A2A8-46EE-A235-DDFD339BE281':'[MS-PAN]: Print System Asynchronous Notification Protocol',
'0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1':'[MS-PAN]: Print System Asynchronous Notification Protocol',
'76F03F96-CDFD-44FC-A22C-64950A001209':'[MS-PAR]: Print System Asynchronous Remote Protocol ',
'45F52C28-7F9F-101A-B52B-08002B2EFABE':'[MS-RAIW]: Remote Administrative Interface:',
'811109BF-A4E1-11D1-AB54-00A0C91E9B45':'[MS-RAIW]: Remote Administrative Interface:',
'12345678-1234-ABCD-EF00-0123456789AB':'[MS-RPRN]: Print System Remote Protocol ',
'338CD001-2244-31F1-AAAA-900038001003':'[MS-RRP]: Windows Remote Registry Protocol ',
'3BBED8D9-2C9A-4B21-8936-ACB2F995BE6C':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'8DA03F40-3419-11D1-8FB1-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'D61A27C6-8F53-11D0-BFA0-00A024151983':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'081E7188-C080-4FF3-9238-29F66D6CABFD':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'895A2C86-270D-489D-A6C0-DC2A9B35280E':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'D02E4BE0-3419-11D1-8FB1-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'DB90832F-6910-4D46-9F5E-9FD6BFA73903':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'4E934F30-341A-11D1-8FB1-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'879C8BBE-41B0-11D1-BE11-00C04FB6BF70':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'00000000-0000-0000-C000-000000000046':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'69AB7050-3059-11D1-8FAF-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'7D07F313-A53F-459A-BB12-012C15B1846E':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'BB39332C-BFEE-4380-AD8A-BADC8AFF5BB6':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'B057DC50-3059-11D1-8FAF-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'338CD001-2244-31F1-AAAA-900038001003':'[MS-RSP]: Remote Shutdown Protocol ',
'894DE0C0-0D55-11D3-A322-00C04FA321A1':'[MS-RSP]: Remote Shutdown Protocol ',
'D95AFE70-A6D5-4259-822E-2C84DA1DDB0D':'[MS-RSP]: Remote Shutdown Protocol ',
'12345778-1234-ABCD-EF00-0123456789AC':'[MS-SAMR]: Security Account Manager (SAM) Remote Protocol',
'01954E6B-9254-4E6E-808C-C9E05D007696':'[MS-SCMP]: Shadow Copy Management Protocol ',
'FA7DF749-66E7-4986-A27F-E2F04AE53772':'[MS-SCMP]: Shadow Copy Management Protocol ',
'214A0F28-B737-4026-B847-4F9E37D79529':'[MS-SCMP]: Shadow Copy Management Protocol ',
'AE1C7110-2F60-11D3-8A39-00C04F72D8E3':'[MS-SCMP]: Shadow Copy Management Protocol ',
'367ABB81-9844-35F1-AD32-98F038001003':'[MS-SCMR]: Service Control Manager Remote Protocol ',
'4B324FC8-1670-01D3-1278-5A47BF6EE188':'[MS-SRVS]: Server Service Remote Protocol ',
'1FF70682-0A51-30E8-076D-740BE8CEE98B':'[MS-TSCH]: Task Scheduler Service Remoting Protocol ',
'378E52B0-C0A9-11CF-822D-00AA0051E40F':'[MS-TSCH]: Task Scheduler Service Remoting Protocol ',
'86D35949-83C9-4044-B424-DB363231FD0C':'[MS-TSCH]: Task Scheduler Service Remoting Protocol ',
'4DBCEE9A-6343-4651-B85F-5E75D74D983C':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'1E062B84-E5E6-4B4B-8A25-67B81E8F13E8':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'2ABD757F-2851-4997-9A13-47D2A885D6CA':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'9CBE50CA-F2D2-4BF4-ACE1-96896B729625':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'4DAA0135-E1D1-40F1-AAA5-3CC1E53221C3':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'40F73C8B-687D-4A13-8D96-3D7F2E683936':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'8F4B2F5D-EC15-4357-992F-473EF10975B9':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'FC5D23E8-A88B-41A5-8DE0-2D2F73C5A630':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'B07FEDD4-1682-4440-9189-A39B55194DC5':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'72AE6713-DCBB-4A03-B36B-371F6AC6B53D':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'B6B22DA8-F903-4BE7-B492-C09D875AC9DA':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'538684E0-BA3D-4BC0-ACA9-164AFF85C2A9':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'75C8F324-F715-4FE3-A28E-F9011B61A4A1':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'90681B1D-6A7F-48E8-9061-31B7AA125322':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'9882F547-CFC3-420B-9750-00DFBEC50662':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'83BFB87F-43FB-4903-BAA6-127F01029EEC':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'EE2D5DED-6236-4169-931D-B9778CE03DC6':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'9723F420-9355-42DE-AB66-E31BB15BEEAC':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'4AFC3636-DB01-4052-80C3-03BBCB8D3C69':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'D99BDAAE-B13A-4178-9FDB-E27F16B4603E':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'D68168C9-82A2-4F85-B6E9-74707C49A58F':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'13B50BFF-290A-47DD-8558-B7C58DB1A71A':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'6E6F6B40-977C-4069-BDDD-AC710059F8C0':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'9AA58360-CE33-4F92-B658-ED24B14425B8':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'E0393303-90D4-4A97-AB71-E9B671EE2729':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'07E5C822-F00C-47A1-8FCE-B244DA56FD06':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'8326CD1D-CF59-4936-B786-5EFC08798E25':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'1BE2275A-B315-4F70-9E44-879B3A2A53F2':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'0316560B-5DB4-4ED9-BBB5-213436DDC0D9':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'14FBE036-3ED7-4E10-90E9-A5FF991AFF01':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'3B69D7F5-9D94-4648-91CA-79939BA263BF':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'D5D23B6D-5A55-4492-9889-397A3C2D2DBC':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'88306BB2-E71F-478C-86A2-79DA200A0F11':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'118610B7-8D94-4030-B5B8-500889788E4E':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'0AC13689-3134-47C6-A17C-4669216801BE':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'0818A8EF-9BA9-40D8-A6F9-E22833CC771E':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'6788FAF9-214E-4B85-BA59-266953616E09':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'B481498C-8354-45F9-84A0-0BDD2832A91F':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'10C5E575-7984-4E81-A56B-431F5F92AE42':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'38A0A9AB-7CC8-4693-AC07-1F28BD03C3DA':'[MS-VDS]: Virtual Disk Service (VDS) Protocol ',
'8FB6D884-2388-11D0-8C35-00C04FDA2795':'[MS-W32T]: W32Time Remote Protocol ',
'5422FD3A-D4B8-4CEF-A12E-E87D4CA22E90':'[MS-WCCE]: Windows Client Certificate Enrollment Protocol',
'D99E6E70-FC88-11D0-B498-00A0C90312F3':'[MS-WCCE]: Windows Client Certificate Enrollment Protocol',
'6BFFD098-A112-3610-9833-46C3F87E345A':'[MS-WKST]: Workstation Service Remote Protocol ',
'F1E9C5B2-F59B-11D2-B362-00105A1F8177':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'423EC01E-2E35-11D2-B604-00104B703EFD':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'9556DC99-828C-11CF-A37E-00AA003240C7':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'F309AD18-D86A-11D0-A075-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'9A653086-174F-11D2-B5F9-00104B703EFD':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'D4781CD6-E5D3-44DF-AD94-930EFE48A887':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'44ACA674-E8FC-11D0-A07C-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'541679AB-2E5F-11D3-B34E-00104BCC4B4A':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'027947E1-D731-11CE-A357-000000000001':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'A359DEC5-E813-4834-8A2A-BA7F1D777D76':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'C49E32C6-BC8B-11D2-85D4-00105A1F8304':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'C49E32C7-BC8B-11D2-85D4-00105A1F8304':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'2C9273E0-1DC3-11D3-B364-00105A1F8177':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'7C857801-7381-11CF-884D-00AA004B2E24':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'DC12A681-737F-11CF-884D-00AA004B2E24':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'8BC3F05E-D86B-11D0-A075-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'44ACA675-E8FC-11D0-A07C-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'1C1C45EE-4395-11D2-B60B-00104B703EFD':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'674B6698-EE92-11D0-AD71-00C04FD8FDFF':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
}

# EPM Classes
class EPMEntries(Structure):
    structure = (
        ('MaxCount','<L=0'),
        ('Offset','<L=0'),
        ('ActualCount','<L=0'),
        ('Data',':')
    )

class EPMTower(Structure):
    structure = (
        ('Length','<L=0'),
        ('ActualLength','<L=0'),
        ('NumberOfFloors','<H'),
        ('_Floors','_-Floors','self["ActualLength"]-2'),
        ('Floors',':'),
    )
    def fromString(self,data):
        Structure.fromString(self,data)
        floors = self['Floors']
        fList = []
        for f in range(self['NumberOfFloors']):
            floor = EPMFloors[f](floors)
            floors = floors[len(floor):]
            fList.append(floor) 
        self['Floors'] = fList

    def __len__(self):
       ll = 0
       for i in self['Floors']:
           ll += len(i) 
       ll += 10
       ll += (4-ll%4) & 3
       return ll
            
            

class EPMEntry(Structure):
    alignment = 4
    structure = (
        ('Object','16s'),
        ('pTower','<L&Tower'),
        ('AnnotationOffset','<L=0'),
        ('AnnotationLength','<L=0'),
        ('_Annotation','_-Annotation','self["AnnotationLength"]'),
        ('Annotation',':'),
        # As part of the answer there will be a Tower field
        #('Tower',':')
    )

class EPMFloor(Structure):
    structure = (
        ('LHSByteCount','<H=0'),
        ('_ProtocolData','_-ProtocolData','self["LHSByteCount"]'),
        ('ProtocolData',':'),
        ('RHSByteCount','<H=0'),
        ('_RelatedData','_-RelatedData','self["RHSByteCount"]'),
        ('RelatedData',':'),

    ) 

class EPMRPCInterface(EPMFloor):
    def __init__(self, data = None):
        EPMFloor.__init__(self, data)

    def __str__(self):
        assert self["ProtocolData"][0] == '\r'
        aUuid = self["ProtocolData"][1:] + self["RelatedData"]
        tupUuid = uuid.bin_to_uuidtup(aUuid)
        return "%s v%s" % tupUuid

class EPMRPCDataRepresentation(EPMFloor):
    def __init__(self, data = None):
        EPMFloor.__init__(self, data)

    def __str__(self):
        assert self["ProtocolData"][0] == '\r'
        aUuid = self["ProtocolData"][1:] + self["RelatedData"]
        tupUuid = uuid.bin_to_uuidtup(aUuid)
        return "%s v%s" % tupUuid

# Standard Floor Assignments
EPMFloors = [ 
EPMRPCInterface,
EPMRPCDataRepresentation,
EPMFloor,
EPMFloor,
EPMFloor,
EPMFloor
]

class EPMLookup(Structure):
    opnum = 2
    structure = (
        ('InquireType','<L=1'),
        ('UUIDRefId','<L=1'),
        ('UUID','16s=""'),
        ('IfIdRefId','<L=2'),
        ('IfId','20s=""'),
        ('VersionOption','<L'),
        ('EntryHandle','20s=""'), 
        ('MaxEntries','<L=500'),
    )

class EPMLookupResponse(Structure):
    structure = (
        ('Handle','20s'),
        ('NumEntries','<L'),
        ('_Entries','_-Entries','len(self.rawData)-28'),
        ('Entries',':',EPMEntries),
        ('ErrorCode','<L')
    )

class EPMLookupRequestHeader(ImpactPacket.Header):
    OP_NUM = 2

    __SIZE = 76

    def __init__(self, aBuffer = None, endianness = '<'):
        ImpactPacket.Header.__init__(self, EPMLookupRequestHeader.__SIZE)
        self.endianness = endianness

        self.set_inquiry_type(0)
        self.set_referent_id(1)
        self.set_referent_id2(2)
        self.set_max_entries(1)

        if aBuffer: self.load_header(aBuffer)

    def get_inquiry_type(self):
        return self.get_long(0, self.endianness)
    def set_inquiry_type(self, type):
        self.set_long(0, type, self.endianness)

    def get_referent_id(self):
        return self.get_long(4, self.endianness)
    def set_referent_id(self, id):
        self.set_long(4, id, self.endianness)

    def get_obj_binuuid(self):
        return self.get_bytes().tolist()[8:8+16]
    def set_obj_binuuid(self, binuuid):
        assert 16 == len(binuuid)
        self.get_bytes()[8:8+16] = array.array('B', binuuid)

    def get_referent_id2(self):
        return self.get_long(24, self.endianness)
    def set_referent_id2(self, id):
        self.set_long(24, id, self.endianness)

    def get_if_binuuid(self):
        return self.get_bytes().tolist()[28:28+20]
    def set_if_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[28:28+20] = array.array('B', binuuid)

    def get_version_option(self):
        return self.get_long(48, self.endianness)
    def set_version_option(self, opt):
        self.set_long(48, opt, self.endianness)

    def get_handle(self):
        return self.get_bytes().tolist()[52:52+20]
    def set_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[52:52+20] = array.array('B', handle)

    def get_max_entries(self):
        return self.get_long(72, self.endianness)
    def set_max_entries(self, num):
        self.set_long(72, num, self.endianness)


    def get_header_size(self):
        return EPMLookupRequestHeader.__SIZE


class EPMRespLookupRequestHeader(ImpactPacket.Header):
    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, EPMRespLookupRequestHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_handle(self):
        return self.get_bytes().tolist()[0:0+20]
    def set_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[0:0+20] = array.array('B', handle)

    def get_entries_num(self):
        return self.get_long(20, '<')
    def set_entries_num(self, num):
        self.set_long(20, num, '<')

    def get_entry(self):
        return ndrutils.NDREntries(self.get_bytes().tostring()[24:-4])
    def set_entry(self, entry):
        raise Exception, "method not implemented"

    def get_status(self):
        off = self.get_entry().get_entries_len()
        return self.get_long(24 + off, '<')
    def set_status(self, status):
        off = self.get_entry().get_entries_len()
        self.set_long(24 + off, status, '<')


    def get_header_size(self):
        entries_size = self.get_entry().get_entries_len()
        return EPMRespLookupRequestHeader.__SIZE + entries_size

class EpmEntry:
    def __init__(self, uuid, version, annotation, objuuid, protocol, endpoint):
        self.__uuid = uuid
        self.__version = version
        self.__annotation = annotation
        self.__objuuid = objuuid
        self.__protocol = protocol
        self.__endpoint = endpoint

    def getUUID(self):
        return self.__uuid

    def setUUID(self, uuid):
        self.__uuid = uuid

    def getProviderName(self):
        return ndrutils.uuid_to_exe(uuid.string_to_bin(self.getUUID()) + struct.pack('<H', self.getVersion()))

    def getVersion(self):
        return self.__version

    def setVersion(self, version):
        self.__version = version

    def isZeroObjUUID(self):
        return self.__objuuid == '00000000-0000-0000-0000-000000000000'

    def getObjUUID(self):
        return self.__objuuid

    def setObjUUID(self, objuuid):
        self.__objuuid = objuuid

    def getAnnotation(self):
        return self.__annotation

    def setAnnotation(self, annotation):
        self.__annotation = annotation

    def getProtocol(self):
        return self.__protocol

    def setProtocol(self, protocol):
        self.__protocol = protocol

    def getEndpoint(self):
        return self.__endpoint

    def setEndpoint(self, endpoint):
        self.__endpoint = endpoint

    def __str__(self):
        stringbinding = transport.DCERPCStringBindingCompose(self.getObjUUID(), self.getProtocol(), '', self.getEndpoint())
        s = '['
        if self.getAnnotation(): s += "Annotation: \"%s\", " % self.getAnnotation()
        s += "UUID=%s, version %d, %s]" % (self.getUUID(), self.getVersion(), stringbinding)

        return s

    def __cmp__(self, o):
        if (self.getUUID() == o.getUUID()
            and self.getVersion() == o.getVersion()
            and self.getAnnotation() == o.getAnnotation()
            and self.getObjUUID() == o.getObjUUID()
            and self.getProtocol() == o.getProtocol()
            and self.getEndpoint() == o.getEndpoint()):
            return 0
        else:
            return -1 # or +1, for what we care.

class DCERPCEpm:
    endianness = '<'
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def portmap_dump(self, rpc_handle = '\x00'*20):
        if self.endianness == '>':
            from impacket.structure import unpack,pack
            try:
                rpc_handle = ''.join(map(chr, rpc_handle))
            except:
                pass
            
            uuid = list(unpack('<LLHHBB6s', rpc_handle))
            rpc_handle = pack('>LLHHBB6s', *uuid)

        lookup = EPMLookupRequestHeader(endianness = self.endianness)
        lookup.set_handle(rpc_handle);
        self._dcerpc.send(lookup)

        data = self._dcerpc.recv()
        resp = EPMRespLookupRequestHeader(data)

        return resp

    # Use these functions to manipulate the portmapper. The previous ones are left for backward compatibility reasons.


    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                error_code = unpack("<L", answer[-4:])[0]
                raise 
        return answer


    def lookup(self, IfId, ObjectUUID = '\x00'*16, inquireType = RPC_C_EP_MATCH_BY_IF, versOpt = RPC_C_VERS_EXACT,  resumeHandle = '\x00'*20):
        # A more general lookup method. Check [C706] for a description of each parameter
        # It will return a list of records found matching the criteria
        # Entries in the list looks like:
        # EPMEntry
        # pTower: {3}
        # Object: {'termsrv\x00\x00\x00\x00\x00\x00\x00\x00\x00'}
        # AnnotationOffset: {0}
        # AnnotationLength: {19}
        #
        # Tower:{
        #     _Floors: {86}
        #     Length: {88}
        #     Floors: {[<impacket.dcerpc.epm.EPMRPCInterface instance at 0x7fa9dbd43170>, 
        #               <impacket.dcerpc.epm.EPMRPCDataRepresentation instance at 0x7fa9dbd43098>,
        #               <impacket.dcerpc.epm.EPMFloor instance at 0x7fa9dbd431b8>, 
        #               <impacket.dcerpc.epm.EPMFloor instance at 0x7fa9dbd43248>]}
        #     ActualLength: {88}
        #     NumberOfFloors: {4}
        # }
        # _Annotation: {19}
        # Annotation: {'Impl friendly name\x00'}

        lookup = EPMLookup()
        lookup['InquireType'] = inquireType
        lookup['IfId'] = IfId
        lookup['UUID'] = ObjectUUID
        lookup['VersionOption'] = versOpt
        lookup['EntryHandle'] = resumeHandle
        entries = []
        errorCode = 0
        while errorCode != RPC_NO_MORE_ELEMENTS:
           data = self.doRequest(lookup, checkReturn = 0)
           resp = EPMLookupResponse(data)
           data = resp['Entries']['Data']

           tmpEntries = []
           for i in range(resp['Entries']['ActualCount']):
               entry = EPMEntry(data)
               data = data[len(entry):]
               tmpEntries.append(entry)

           for entry in tmpEntries:
               tower = EPMTower(data)
               data = data[len(tower):]
               entry['Tower'] = tower

           entries += tmpEntries

           if resp['Handle'] == '\x00'*20:
               break

           lookup['EntryHandle'] = resp['Handle']
           errorCode = resp['ErrorCode']
        return entries

def PrintStringBinding(floors):
    tmp_address = ''
    tmp_address2 = ''
    for floor in floors[3:]:
        if floor['ProtocolData'] == chr(0x07):
            tmp_address = 'ncacn_ip_tcp:%%s[%d]' % struct.unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x08):
            tmp_address = 'ncadg_ip_udp:%%s[%d]' % struct.unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x09):
            # If the address were 0.0.0.0 it would have to be replaced by the remote host's IP.
            tmp_address2 = socket.inet_ntoa(floor['RelatedData'])
            if tmp_address <> '':
                return tmp_address % tmp_address2
            else:
                return 'IP: %s' % tmp_address2
        elif floor['ProtocolData'] == chr(0x0c):
            tmp_address = 'ncacn_spx:~%%s[%d]' % struct.unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x0d):
            n = len(floor['RelatedData'])
            tmp_address2 = ('%02X' * n) % struct.unpack("%dB" % n, floor['RelatedData'])

            if tmp_address <> '':
                return tmp_address % tmp_address2
            else:
                return 'SPX: %s' % tmp_address2
        elif floor['ProtocolData'] == chr(0x0e):
            tmp_address = 'ncadg_ipx:~%%s[%d]' % struct.unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x0f):
            tmp_address = 'ncacn_np:%%s[%s]' % floor['RelatedData'][:len(floor['RelatedData'])-1]
        elif floor['ProtocolData'] == chr(0x10):
            return 'ncalrpc:[%s]' % floor['RelatedData'][:len(floor['RelatedData'])-1]
        elif floor['ProtocolData'] == chr(0x01) or floor['ProtocolData'] == chr(0x11):
            if tmp_address <> '':
                return tmp_address % floor['RelatedData'][:len(floor['RelatedData'])-1]
            else:
                return 'NetBIOS: %s' % floor['RelatedData'] 
        elif floor['ProtocolData'] == chr(0x1f):
            tmp_address = 'ncacn_http:%%s[%d]' % struct.unpack('!H',floor['RelatedData'])
        else:
            return 'unknown_proto_0x%x:[0]' % ord(floor['ProtocolData'] )

