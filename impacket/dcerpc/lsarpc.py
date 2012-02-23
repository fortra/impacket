# Copyright (c) 2003-2011 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Pablo A. Schachner
#
# Description:
#   LSARPC interface implementation.
#

from impacket.structure import Structure
from impacket.dcerpc import ndrutils
from impacket.dcerpc.samr import SAMR_RPC_SID_IDENTIFIER_AUTHORITY, SAMR_RPC_SID
from impacket.uuid import uuidtup_to_bin
import random
from struct import pack, unpack

MSRPC_UUID_LSARPC = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))

class LSARPCOpenPolicy2(Structure):
    opnum = 44
    alignment = 4
    structure = (
       ('ServerName',':',ndrutils.NDRUniqueStringW),
       ('ObjectAttributes','24s'),
       ('AccessMask','<L'),
    )

class LSARPCOpenPolicy2Response(Structure):
    structure = (
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )

class LSARPCClose(Structure):
    opnum = 0
    alignment = 4
    structure = (
       ('ContextHandle','20s'),
    )

class LSARPCCloseResponse(Structure):
    structure = (
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )
    
class SAMR_RPC_SID_STRUCT(Structure):
    structure = (
        ('Count','<L'),
        ('Sid',':',SAMR_RPC_SID),
    )

class SIDS_BUFF(Structure):
    structure = (
        ('NumSids','<L'),
        ('RefID','<L'),
        ('MaxCount','<L'),
        ('SidsLen','_-Sids','NumSids * len(SAMR_RPC_SID_STRUCT)'),
        ('Sids',':'),
    )

class LSARPCLookupSids(Structure):
    opnum = 15
    alignment = 4
    structure = (
       ('ContextHandle','20s'),
       ('SidsBuff',':',SIDS_BUFF),
       ('TransNames', '8s'),
       ('LookupLevel', 'H'),
       ('MappedCount', '6s'),
    )

class LSARPCLookupSidsResponse(Structure):
     
    structure = (
       ('BuffSize','_-pSidsRespBuffer','len(self.rawData)-8'),
       ('pSidsRespBuffer',':'),
       ('Count','4s'),
       ('ErrorCode','<L'),
    )

    def formatDict(self):
      elem_len = []
      names_size = []
      l_dict = []

      sids_resp = self['pSidsRespBuffer']
      dom_count = unpack('<L',sids_resp[4:8])[0]

      ptr = 20
      for i in range(dom_count):
        elem_len.append(unpack('<H',sids_resp[ptr:ptr+2])[0])
        ptr += 12

      for i in range(dom_count):
        elem_length = elem_len[i]
        ptr += 12
        l_dict.append({'domain': unpack('%ss'%elem_length, sids_resp[ptr:ptr+elem_length])[0].decode('utf16')})
        ptr += elem_length + 4 #for the SID Count

        entry = SAMR_RPC_SID(sids_resp[ptr:])
        l_dict[i]['sid'] = entry
        ptr += len(entry)

      name_count = unpack('<L',sids_resp[ptr:ptr+4])[0]
      ptr += 12

      for i in range(name_count):
        names_size.append([unpack('<H',sids_resp[ptr+4:ptr+6])[0], unpack('<L', sids_resp[ptr+12:ptr+16])[0]])
        ptr += 16

      for i in range(name_count):
        elem_length = names_size[i][0]
        act_count = unpack('<L', sids_resp[ptr+8:ptr+12])[0]
        ptr += 12
        name = unpack('%ss'%elem_length, sids_resp[ptr:ptr+elem_length])[0].decode('utf16')
        ret = l_dict[names_size[i][1]].setdefault('names', [name])
        if ret != [name]:
          l_dict[names_size[i][1]]['names'].append(name)

        ptr += elem_length
        if act_count % 2 == 1:
          ptr += 2 #Only for odd numbers

      return l_dict

class DCERPCLsarpc:
    
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            return answer

    def LsarOpenPolicy2( self, server_name, access_mask = 0x00020801):
      open_policy = LSARPCOpenPolicy2()
      open_policy['ServerName'] = ndrutils.NDRUniqueStringW()
      open_policy['ServerName']['Data'] = (server_name+'\x00').encode('utf-16le')
      #TODO: Implement ObjectAtributes structure
      open_policy['ObjectAttributes'] = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
      open_policy['AccessMask'] = access_mask
      data = self.doRequest(open_policy)
      ans = LSARPCOpenPolicy2Response(data)
      return ans

    def LsarLookupSids( self, context_handle, sids):
      '''
           This method receives the following parameters:
                - Handle(OpenPolicy2 handle)
                - list of sids to look information for ([S1, S2 ...])
      '''

      open_policy = LSARPCLookupSids()
      open_policy['ContextHandle'] = context_handle
      open_policy['SidsBuff'] = SIDS_BUFF()
      open_policy['SidsBuff']['NumSids'] = len(sids)
      open_policy['SidsBuff']['RefID'] = random.randint(0,65535)
      open_policy['SidsBuff']['MaxCount'] = len(sids)
      
      sids_str = ''
      sid_items = 0
      for sid_i in range(len(sids)):
        sid_arr = sids[sid_i].split('-')
        _sid = SAMR_RPC_SID_STRUCT()
        sid_items += 1
        _sid['Count'] = len(sid_arr) - 3
        _sid['Sid'] = SAMR_RPC_SID()
        _sid['Sid']['Revision'] = int(sid_arr[1])
        _sid['Sid']['SubAuthorityCount'] =len(sid_arr) - 3
        _sid['Sid']['IdentifierAuthority'] = SAMR_RPC_SID_IDENTIFIER_AUTHORITY()
        _sid['Sid']['IdentifierAuthority']['Value'] = '\x00\x00\x00\x00\x00' + pack('B',int(sid_arr[2]))

        sub_auth = ''
        for elem in sid_arr[3:]:
            sub_auth += pack('<L', int(elem))
        _sid['Sid']['SubAuthority'] = sub_auth

        sids_str += _sid.getData()

      for i in range(0, sid_items):
        sids_str = pack('<L',random.randint(0,65535)) + sids_str
      open_policy['SidsBuff']['Sids'] = sids_str

      open_policy['TransNames'] = '\x00\x00\x00\x00\x00\x00\x00\x00'
      open_policy['LookupLevel'] = 1
      open_policy['MappedCount'] = '\x00\x00\x00\x00\x00\x00'

      data = self.doRequest(open_policy)
      packet = LSARPCLookupSidsResponse(data)
      return packet

    def LsarClose( self, context_handle):
      open_policy = LSARPCClose()
      open_policy['ContextHandle'] = context_handle
      data = self.doRequest(open_policy)
      ans = LSARPCCloseResponse(data)
      return ans
