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

