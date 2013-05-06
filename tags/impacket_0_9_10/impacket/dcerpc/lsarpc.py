# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Pablo A. Schachner
#         Alberto Solino
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

# Constants

# POLICY_INFORMATION_CLASS
POLICY_AUDIT_LOG_INFORMATION            = 1
POLICY_AUDIT_EVENTS_INFORMATION         = 2
POLICY_PRIMARY_DOMAIN_INFORMATION       = 3
POLICY_PD_ACCOUNT_INFORMATION           = 4
POLICY_ACCOUNT_DOMAIN_INFORMATION       = 5
POLICY_LSA_SERVER_ROLE_INFORMATION      = 6
POLICY_REPLICA_SOURCE_INFORMATION       = 7
POLICY_DEFAULT_QUOTA_INFORMATION        = 8
POLICY_MODIFICATION_INFORMATION         = 9
POLICY_AUDIT_FULL_SET_INFORMATION       = 10
POLICY_AUDIT_FULL_QUERY_INFORMATION     = 11
POLICY_DNS_DOMAIN_INFORMATION           = 12
POLICY_DNS_DOMAIN_INFORMATION_INT       = 13
POLICY_LOCAL_ACCOUNT_DOMAIN_INFORMATION = 14
POLICY_LAST_ENTRY                       = 15


# Structs
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
    
class LSARPCQueryInformationPolicy2(Structure):
    opnum = 46
    structure = (
        ('ContextHandle','20s'),
        ('InformationClass', '<H'),
    )

class LSARPCQueryInformationPolicy2Response(Structure):
    structure = (
        ('RefID','<L'),
        ('Info','<L'),
        ('BuffSize','_-pRespBuffer','len(self.rawData)-12'),
        ('pRespBuffer',':'),
        ('ErrorCode','<L')
    )

class DOMAIN_INFORMATION(Structure):
    structure = (
        ('Length','<H'),
        ('Size','<H'),
        ('pName','<L'),
        ('pSid','<L'),
        ('Data',':'),
    )

    def formatDict(self):
        resp = {}
        resp['name'] = None
        resp['sid']  = None
        data = self['Data']
        if self['pName'] != 0:
            name = ndrutils.NDRStringW(data)
            data = data[name['ActualCount']*2+12:]
            if name['ActualCount'] % 2 == 1:
                data = data[2:]
            resp['name'] = name['Data']
        if self['pSid'] != 0:
            resp['sid'] = SAMR_RPC_SID(data[4:])
        return resp
        

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
    structure = (
       ('ContextHandle','20s'),
       ('SidsBuff',':',SIDS_BUFF),
       ('TransNames', '8s'),
       ('LookupLevel', '<H'),
       ('MappedCount', '6s'),
    )

class LSARPCLookupSids3(Structure):
    opnum = 76 
    structure = (
      # ('ContextHandle','20s'),
       ('SidsBuff',':',SIDS_BUFF),
       ('TransNames', '8s'),
       ('LookupLevel', '<H'),
       ('MappedCount', '6s'),
       ('LookupOptions', '<L=0'),
       ('ClientRevision', '<L=1'),
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
      if dom_count == 0:
          ptr = 8
      else:
          ptr = 20
      for i in range(dom_count):
        elem_len.append(unpack('<H',sids_resp[ptr:ptr+2])[0])
        ptr += 12

      for i in range(dom_count):
        elem_length = elem_len[i]
        ptr += 12
        l_dict.append({'domain': unpack('%ss'%elem_length, sids_resp[ptr:ptr+elem_length])[0].decode('utf16')})
        ptr += elem_length + 4 #for the SID Count

        if (elem_length/2) % 2 == 1:
           ptr += 2

        entry = SAMR_RPC_SID(sids_resp[ptr:])
        l_dict[i]['sid'] = entry
        ptr += len(entry)

      name_count = unpack('<L',sids_resp[ptr:ptr+4])[0]
      ptr += 12

      for i in range(name_count):
        names_size.append([unpack('<H',sids_resp[ptr+4:ptr+6])[0], unpack('<H', sids_resp[ptr:ptr+2])[0], unpack('<L', sids_resp[ptr+12:ptr+16])[0]])
        ptr += 16

      for i in range(name_count):
        elem_length = names_size[i][0]
        sid_type = names_size[i][1]
        if elem_length != 0:
            act_count = unpack('<L', sids_resp[ptr+8:ptr+12])[0]
            ptr += 12
            name = unpack('%ss'%elem_length, sids_resp[ptr:ptr+elem_length])[0].decode('utf16')
        else:
            act_count = 0
            name = ''

        ret = l_dict[names_size[i][2]].setdefault('names', [name])
        if ret != [name]:
          l_dict[names_size[i][2]]['names'].append(name)
  
        ret = l_dict[names_size[i][2]].setdefault('types', [sid_type])
        if ret != [sid_type]:
          l_dict[names_size[i][2]]['types'].append(sid_type)

        ptr += elem_length
        if act_count % 2 == 1:
          ptr += 2 #Only for odd numbers

      return l_dict

class LSARPCSessionError(Exception):

    # TODO, complete the error codes here. Looks like LSA return NT Error codes
    error_messages = {
    }

    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        key = self.error_code
        if (LSARPCSessionError.error_messages.has_key(key)):
            error_msg_short = LSARPCSessionError.error_messages[key][0]
            error_msg_verbose = LSARPCSessionError.error_messages[key][1] 
            return 'LSARPC SessionError: code: %s - %s - %s' % (str(self.error_code), error_msg_short, error_msg_verbose)
        else:
            return 'LSARPC SessionError: unknown error code: 0x%x' % (self.error_code)

class DCERPCLsarpc:
    
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                error_code = unpack('<L', answer[-4:])[0]
                raise LSARPCSessionError(error_code)
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
      open_policy['SidsBuff']['RefID'] = random.randint(1,65535)
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
        sids_str = pack('<L',random.randint(1,65535)) + sids_str
      open_policy['SidsBuff']['Sids'] = sids_str

      open_policy['TransNames'] = '\x00\x00\x00\x00\x00\x00\x00\x00'
      open_policy['LookupLevel'] = 1
      open_policy['MappedCount'] = '\x00\x00\x00\x00\x00\x00'

      data = self.doRequest(open_policy, checkReturn = 0)
      packet = LSARPCLookupSidsResponse(data)
      return packet

    def LsarLookupSids3( self, context_handle, sids):
      '''
           This method receives the following parameters:
                - Handle(OpenPolicy2 handle)
                - list of sids to look information for ([S1, S2 ...])
      '''

      open_policy = LSARPCLookupSids3()
      open_policy['ContextHandle'] = context_handle
      open_policy['SidsBuff'] = SIDS_BUFF()
      open_policy['SidsBuff']['NumSids'] = len(sids)
      open_policy['SidsBuff']['RefID'] = random.randint(1,65535)
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
        sids_str = pack('<L',random.randint(1,65535)) + sids_str
      open_policy['SidsBuff']['Sids'] = sids_str

      open_policy['TransNames'] = '\x00\x00\x00\x00\x00\x00\x00\x00'
      open_policy['LookupLevel'] = 1
      open_policy['MappedCount'] = '\x00\x00\x00\x00\x00\x00'

      data = self.doRequest(open_policy, checkReturn = 0)
      packet = LSARPCLookupSidsResponse(data)
      return packet

    def LsarQueryInformationPolicy2(self, policyHandle, informationClass):
       queryInfo = LSARPCQueryInformationPolicy2()
       queryInfo['ContextHandle'] = policyHandle
       queryInfo['InformationClass'] = informationClass
       packet = self.doRequest(queryInfo)
       
       data = LSARPCQueryInformationPolicy2Response(packet)
       # For the answers we can parse, we return the structs, for the rest, just the data
       if informationClass == POLICY_PRIMARY_DOMAIN_INFORMATION:
           return DOMAIN_INFORMATION(data['pRespBuffer'])
       elif informationClass == POLICY_ACCOUNT_DOMAIN_INFORMATION:
           return DOMAIN_INFORMATION(data['pRespBuffer'])
       else:
           return data

    def LsarClose( self, context_handle):
      open_policy = LSARPCClose()
      open_policy['ContextHandle'] = context_handle
      data = self.doRequest(open_policy)
      ans = LSARPCCloseResponse(data)
      return ans
