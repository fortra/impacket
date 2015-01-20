################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
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
from impacket.nt_errors import ERROR_MESSAGES
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

# LSAP_LOOKUP_LEVEL ( [MS-LSAT] Section 2.2.16 )
LsapLookupWksta                   = 1
LsapLookupPDC                     = 2
LsapLookupTDL                     = 3
LsapLookupGC                      = 4
LsapLookupXForestReferral         = 5
LsapLookupXForestResolve          = 6
LsapLookupRODCReferralToFullDC    = 7

# Structs
class LSAPR_CR_CIPHER_VALUE(Structure):
    structure = (
        ('Length','<L=0'),
        ('MaximumLength','<L=0'),
        ('pBuffer',':', ndrutils.NDRPointerNew ),
        ('Buffer',':', ndrutils.NDRConformantVaryingArray),
    )

class LSARPCQuerySecret(Structure):
    opnum = 30
    alignment = 4
    structure = (
        ('SecretHandle','20s'),
        ('EncryptedCurrentValue','<Q=1'),
        ('pCurrentValueSetTime','<L=2'),
        ('CurrentValueSetTime','<Q=0'),
        ('EncryptedOldValue','L=0'),
        ('OldValueSetTime','<Q=0'),
    )

class LSARPCQuerySecretResponse(Structure):
    #alignment = 8 
    structure = (
        ('pEncryptedCurrentValue',':', ndrutils.NDRPointerNew),
        ('pEncryptedCurrentValue2',':', ndrutils.NDRPointerNew),
        ('EncryptedCurrentValue',':', LSAPR_CR_CIPHER_VALUE),
        ('pCurrentValueSetTime',':', ndrutils.NDRPointerNew),
        ('CurrentValueSetTime','<Q=0'),
    )

class LSARPCRetrievePrivateData(Structure):
    opnum = 43
    alignment = 4
    structure = (
        ('PolicyHandle','20s'),
        ('KeyName',':'),
        ('EncryptedData', '<L=0'),
    )

class LSARPCRetrievePrivateDataResponse(Structure):
    structure = (
        ('pEncryptedData', ':', ndrutils.NDRPointerNew),
        ('EncryptedData', ':', LSAPR_CR_CIPHER_VALUE),
    )

class LSARPCOpenSecret(Structure):
    opnum = 28
    alignment = 4
    structure = (
        ('PolicyHandle','20s'),
        ('SecretName',':'),
        ('DesiredAccess','<L=0'),
    )

class LSARPCOpenSecretResponse(Structure):
    structure = (
        ('SecretHandle', '20s'),
    )

class LSARPCSetSystemAccessAccount(Structure):
    opnum = 24
    alignment = 4
    structure = (
        ('AccountHandle','20s'), 
        ('SystemAccess','<L=0'), 
    )

class LSARPCLookupNames2(Structure):
    opnum = 58
    alignment = 4
    structure = (
        ('PolicyHandle','20s'),
        ('Count','<L=0'),
        ('SizeIs','<L=0'),
        ('Names',':'),
        ('TranslatedSids',':'),
        ('LookupLevel','<H=0'),
        ('MappedCount','<L=0'),
        ('LookupOptions','<L=0'),
        ('ClientRevision','<L=0'),
    )

class RPC_SID(SAMR_RPC_SID):
    commonHdr = (
        ('Count', '<L=0'),
    )
    def __init__(self, data = None, alignment = 0):
        SAMR_RPC_SID.__init__(self, data)

    def fromCanonical(self, canonical):
       items = canonical.split('-')
       self['Revision'] = int(items[1])
       self['IdentifierAuthority'] = SAMR_RPC_SID_IDENTIFIER_AUTHORITY()
       self['IdentifierAuthority']['Value'] = '\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
       self['SubAuthorityCount'] = len(items) - 3
       self['Count'] = self['SubAuthorityCount']
       ans = ''
       for i in range(self['SubAuthorityCount']):
           ans += pack('<L', int(items[i+3]))
       self['SubAuthority'] = ans

class LSAPR_TRUST_INFORMATION(Structure):
    structure = (
        ('pName',':', ndrutils.pRPC_UNICODE_STRING),
        ('pSid',':', ndrutils.NDRPointerNew),
        ('Name',':', ndrutils.RPC_UNICODE_STRING),
        ('Sid', ':', RPC_SID),
    )

class LSAPR_REFERENCED_DOMAIN_LIST(Structure):
    alignment = 4
    structure = (
        ('Entries','<L=0'),
        ('pDomains','<L=0'),
        ('MaxEntries','<L=0'),
        ('Size', '<L=0'),
        ('Domains', ':', LSAPR_TRUST_INFORMATION), 
    )

class PLSAPR_REFERENCED_DOMAIN_LIST(LSAPR_REFERENCED_DOMAIN_LIST):
    alignment = 4
    commonHdr = (
        ('RefId','<L'),
    )
    def __init__(self, data = None, alignment = 0):
        LSAPR_REFERENCED_DOMAIN_LIST.__init__(self,data, alignment)
        self['RefId'] = random.randint(1,65535)

class LSAPR_TRANSLATED_SIDS_EX(Structure):
    alignment = 4
    structure = (
        ('Use', '<H=0'),
        ('RelativeId', '<L=0'),
        ('DomainIndex', '<L=0'),
        ('Flags', '<L=0'),
    )

class LSARPCLookupNames2Response(Structure):
    structure = (
        ('pReferencedDomains',':', PLSAPR_REFERENCED_DOMAIN_LIST),
        ('Entries', '<L=0'),
        ('pTranslatedSids', ':', ndrutils.NDRPointerNew),
        ('Size', '<L=0'),
        ('TranslatedSids',':', LSAPR_TRANSLATED_SIDS_EX),
        ('MappedCount','<L=0'),
    )

class LSARPCDeleteObject(Structure):
    opnum = 34
    alignment = 4
    structure = (
        ('ObjectHandle','20s'),
    )

class LSARPCCreateAccount(Structure):
    opnum = 10
    alignment = 4
    structure = (
        ('PolicyHandle','20s'),
        ('AccountSid',':', RPC_SID),
        ('DesiredAccess','<L=0'),
    )
    
class LSARPCCreateAccountResponse(Structure):
    structure = (
        ('AccountHandle', '20s'),
    )

class LSARPCOpenAccount(Structure):
    opnum = 17
    alignment = 4
    structure = (
        ('PolicyHandle','20s'),
        ('AccountSid',':', RPC_SID),
        ('DesiredAccess','<L=0'),
    )
    
class LSARPCOpenAccountResponse(Structure):
    structure = (
        ('AccountHandle', '20s'),
    )

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
    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        key = self.error_code
        if ERROR_MESSAGES.has_key(key):
            return 'LSARPC SessionError: %s(%s)' % (ERROR_MESSAGES[self.error_code])
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

    def LsarOpenPolicy2( self, systemName, desiredAccess = 0x00020801):
        """
        opens a context handle to the RPC server

        :param string systemName: This parameter does not have any effect on message processing in any environment. It MUST be ignored on receipt.
        :param int desiredAccess: An ACCESS_MASK value that specifies the requested access rights that MUST be granted on the returned PolicyHandle if the request is successful. Check [MS-DTYP], section 2.4.3
  
        :return: a structure with a policy handle, call dump() to check its structure. Otherwise raises an error
        """
        open_policy = LSARPCOpenPolicy2()
        open_policy['ServerName'] = ndrutils.NDRUniqueStringW()
        open_policy['ServerName']['Data'] = (systemName+'\x00').encode('utf-16le')
        #TODO: Implement ObjectAtributes structure
        open_policy['ObjectAttributes'] = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        open_policy['AccessMask'] = desiredAccess
        data = self.doRequest(open_policy)
        ans = LSARPCOpenPolicy2Response(data)
        return ans

    def LsarLookupSids( self, context_handle, sids):
        """
        translates a batch of security principal SIDs to their name forms. It also returns the domains that these names are a part of.

        :param HANDLE context_handle: OpenPolicy2 handle
        :param list sids: list of sids to look information for ([S1, S2 ...])

        :return: a structure with a list of translated sids, call dump() to see its contents. Otherwise it raises an error
        """

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
        """
        translates a batch of security principal SIDs to their name forms. It also returns the domains that these names are a part of.
  
        :param HANDLE context_handle: OpenPolicy2 handle
        :param list sids: list of sids to look information for ([S1, S2 ...])

        :return: a structure with a list of translated sids, call dump() to see its contents. Otherwise it raises an error
        """

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
        """
        query values that represent the server's security policy
 
        :param HANDLE policyHandle: OpenPolicy2 handle
        :param int informationClass: the information class type requests. Check [MS-LSAD], section 3.1.4.4.3. Currently supported POLICY_PRIMARY_DOMAIN_INFORMATION and POLICY_ACCOUNT_DOMAIN_INFORMATION.
 
        :return: a structure with the requested information class. Call the dump() method to check its structure. Otherwise raises an error
        """
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
        """
        frees the resources held by a context handle that was opened earlier
  
        :param HANDLE context_handle: OpenPolicy2 handle
  
        :return: NULL or raises an exception on error
        """
        open_policy = LSARPCClose()
        open_policy['ContextHandle'] = context_handle
        data = self.doRequest(open_policy)
        ans = LSARPCCloseResponse(data)
        return ans

    def LsarLookupNames2(self, policyHandle, names, lookupLevel=LsapLookupWksta, lookupOptions = 0x0, clientRevision = 0x1):
        """
        translates a batch of security principal names to their SID form

        :param HANDLE policyHandle: OpenPolicy2 handle
        :param UNICODE names: contains the security principal names to translate (only supports one name)
        :param int lookupLevel: Specifies what scopes are to be used during translation, as specified in section 2.2.16 [MS-LSAT]
        :param int lookupOptions: flags that control the lookup operation. For possible values and their meanings, see section 3.1.4.5 [MS-LSAT]
        :param int clientRevision: version of the client, which implies the client's capabilities. For possible values and their meanings, see section 3.1.4.5 [MS-LSAT]

        :return: on successful return, call the dump() method to see its contents
        """
        lookupNames2 = LSARPCLookupNames2()
        lookupNames2['PolicyHandle'] = policyHandle
        lookupNames2['Count'] = 1
        lookupNames2['SizeIs'] = 1
        rpcUnicodePtr = ndrutils.pRPC_UNICODE_STRING()
        rpcUnicodePtr.setDataLen(names)
        rpcUnicode = ndrutils.RPC_UNICODE_STRING()
        rpcUnicode['Data'] = names
        lookupNames2['Names'] = str(rpcUnicodePtr) + str(rpcUnicode)
        lookupNames2['TranslatedSids'] = '\x00'*8
        lookupNames2['LookupOptions'] = lookupOptions
        lookupNames2['LookupLevel'] = lookupLevel
        lookupNames2['MappedCount'] = 0
        lookupNames2['ClientRevision'] = clientRevision

        data = self.doRequest(lookupNames2)
        ans = LSARPCLookupNames2Response(data)

        return ans

    def LsarOpenAccount(self, policyHandle, accountSid, desiredAccess=0x02000000):
        """
        obtains a handle to an account object

        :param HANDLE policyHandle: OpenPolicy2 handle
        :param RPC_SID accountSid: A SID of the account to be opened
        :param int desiredAccess: An ACCESS_MASK value that specifies the requested access rights that MUST be granted on the returned PolicyHandle if the request is successful. Check [MS-DTYP], section 2.4.3

        :return: returns the AccountHandle for the opened Sid. Call dump() method to see the structure.
        """
        openAccount = LSARPCOpenAccount()
        openAccount['PolicyHandle'] = policyHandle
        openAccount['AccountSid'] = accountSid
        openAccount['DesiredAccess'] = desiredAccess

        data = self.doRequest(openAccount)
        ans = LSARPCOpenAccountResponse(data)

        return ans

    def LsarCreateAccount(self, policyHandle, accountSid, desiredAccess=0x02000000):
        """
        creates a new account object in the server's database

        :param HANDLE policyHandle: OpenPolicy2 handle
        :param RPC_SID accountSid: A SID of the account to be opened
        :param int desiredAccess: An ACCESS_MASK value that specifies the requested access rights that MUST be granted on the returned PolicyHandle if the request is successful. Check [MS-DTYP], section 2.4.3

        :return: returns the AccountHandle for the created Sid. Call dump() method to see the structure.
        """
        createAccount = LSARPCCreateAccount()
        createAccount['PolicyHandle'] = policyHandle
        createAccount['AccountSid'] = accountSid
        createAccount['DesiredAccess'] = desiredAccess

        data = self.doRequest(createAccount)
        ans = LSARPCCreateAccountResponse(data)

        return ans

    def LsarDeleteObject(self, objectHandle):
        """
        deletes an open account object, secret object, or trusted domain object.

        :param HANDLE objectHandle: handle of the object to delete

        :return: NULL or raises an exception on error
        """
        deleteObject = LSARPCDeleteObject()
        deleteObject['ObjectHandle'] = objectHandle

        data = self.doRequest(deleteObject)

        return data

    def LsarSetSystemAccessAccount(self, accountHandle, systemAccess = 0x10):
        """
        sets system access account flags for an account object.

        :param HANDLE accountHandle: handle for a valid opened account
        :param int systemAccess: a bitmask containing the account flags to be set on the account.

        :return: NULL or raises an exception on error
        """
        setSystemAccess = LSARPCSetSystemAccessAccount()
        setSystemAccess['AccountHandle'] = accountHandle
        setSystemAccess['SystemAccess'] = systemAccess

        data = self.doRequest(setSystemAccess)

        return data

    def LsarOpenSecret(self, policyHandle, secretName, desiredAccess=0x02000000):
        """
        sets system access account flags for an account object.

        :param HANDLE policyHandle: OpenPolicy2 handle
        :param UNICODE secretName: the name of the secret to open
        :param int desiredAccess: An ACCESS_MASK value that specifies the requested access rights that MUST be granted on the returned PolicyHandle if the request is successful. Check [MS-DTYP], section 2.4.3

        :return: returns the SecretHandle for the opened secret. Call dump() method to see the structure.
        """
        openSecret = LSARPCOpenSecret()
        openSecret['PolicyHandle'] = policyHandle
        rpcUnicodePtr = ndrutils.pRPC_UNICODE_STRING()
        rpcUnicodePtr.setDataLen(secretName)
        rpcUnicode = ndrutils.RPC_UNICODE_STRING()
        rpcUnicode['Data'] = secretName
        openSecret['SecretName'] = str(rpcUnicodePtr) + str(rpcUnicode)
        openSecret['DesiredAccess'] = desiredAccess

        data = self.doRequest(openSecret)
        ans = LSARPCOpenSecretResponse(data)

        return ans

    def LsarRetrievePrivateData(self, policyHandle, keyName):
        """
        retrieves a secret value.

        :param HANDLE policyHandle: OpenPolicy2 handle
        :param UNICODE keyName: the name of the secret to retrieve

        :return: returns a structure with the secret. Call dump() method to see the structure. Raises an exception on error
        You can decrypt the secrets using crypto.decryptSecret(). You will need the sessionKey from the SMBConnection as the key for decryption (getSessionKey()).
        """
        retrievePrivateData = LSARPCRetrievePrivateData()
        retrievePrivateData['PolicyHandle'] = policyHandle
        rpcUnicodePtr = ndrutils.pRPC_UNICODE_STRING()
        rpcUnicodePtr.setDataLen(keyName)
        rpcUnicode = ndrutils.RPC_UNICODE_STRING()
        rpcUnicode['Data'] = keyName
        retrievePrivateData['KeyName'] = str(rpcUnicodePtr) + str(rpcUnicode)

        data = self.doRequest(retrievePrivateData)
        ans = LSARPCRetrievePrivateDataResponse(data)

        return ans

    def LsarQuerySecret(self, secretHandle):
        """
        retrieves the current and old (or previous) value of the secret object.

        :param HANDLE secretHandle: LsarOpenSecret handle

        :return: returns a structure with the secret. Call dump() method to see the structure. Raises an exception on error
        """
        querySecret = LSARPCQuerySecret()
        querySecret['SecretHandle'] = secretHandle

        data = self.doRequest(querySecret)
        ans = LSARPCQuerySecretResponse(data)
        ans.dump()

        return ans



