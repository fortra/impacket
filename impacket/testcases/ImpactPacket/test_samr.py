###############################################################################
#  Tested so far: 
#  
#  SamrConnect5  
#  SamrConnect4
#  SamrConnect2
#  SamrConnect
#  SamrOpenDomain
#  SamrOpenGroup
#  SamrOpenAlias
#  SamrOpenUser 
#  SamrEnumerateDomainsInSamServer
#  SamrEnumerateGroupsInDomain  
#  SamrEnumerateAliasesInDomain
#  SamrEnumerateUsersInDomain
#  SamrLookupDomainInSamServer
#  SamrLookupNamesInDomain
#  SamrLookupIdsInDomain  
#  SamrGetGroupsForUser
#  SamrQueryDisplayInformation3  
#  SamrQueryDisplayInformation2
#  SamrQueryDisplayInformation
#  SamrGetDisplayEnumerationIndex2
#  SamrGetDisplayEnumerationIndex
#  SamrCreateGroupInDomain  
#  SamrCreateAliasInDomain
#  SamrCreateUser2InDomain
#  SamrCreateUserInDomain  
#  SamrQueryInformationDomain2  
#  SamrQueryInformationDomain
#  SamrQueryInformationGroup
#  SamrQueryInformationAlias
#  SamrQueryInformationUser2
#  SamrQueryInformationUser
#  
################################################################################

import sys
import unittest
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import samr
from impacket.winregistry import hexdump
from impacket.dcerpc.v5 import dtypes
from impacket import nt_errors

class SAMRTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        request = samr.SamrConnect()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_INITIALIZE | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN | samr.SAM_SERVER_READ | samr.SAM_SERVER_WRITE
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp2 = dce.request(request)
        request = samr.SamrLookupDomainInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['Name'] = resp2['Buffer']['Buffer'][0]['Name']
        resp3 = dce.request(request)
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  samr.DOMAIN_READ_PASSWORD_PARAMETERS | samr.DOMAIN_WRITE_PASSWORD_PARAMS | samr.DOMAIN_READ_OTHER_PARAMETERS | samr.DOMAIN_WRITE_OTHER_PARAMETERS | samr.DOMAIN_CREATE_USER | samr.DOMAIN_CREATE_USER | samr.DOMAIN_CREATE_ALIAS | samr.DOMAIN_GET_ALIAS_MEMBERSHIP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_LOOKUP | samr.DOMAIN_READ
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)

        return dce, rpctransport, resp4['DomainHandle']

    def tes_SamrConnect5(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect5()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['InVersion'] = 1
        request['InRevisionInfo']['tag'] = 1
        resp = dce.request(request)
        resp.dump()

    def tes_SamrConnect4(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect4()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        request['ClientRevision'] = 2
        resp = dce.request(request)
        resp.dump()

    def tes_SamrConnect2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect2()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        resp.dump()

    def tes_SamrConnect(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def tes_SamrOpenDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        request = samr.SamrOpenDomain()
        SID = 'S-1-5-352321536-2562177771-1589929855-2033349547'
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['DomainId'].fromCanonical(SID)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        
    def tes_SamrOpenGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        
    def tes_SamrOpenAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = 25
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_ALIAS') < 0:
                raise

    def tes_SamrOpenUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = 500
        resp = dce.request(request)
        resp.dump()

    def tes_SamrEnumerateDomainsInSamServer(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp2 = dce.request(request)
        resp2.dump()
        request = samr.SamrLookupDomainInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['Name'] = resp2['Buffer']['Buffer'][0]['Name']
        resp3 = dce.request(request)
        resp3.dump()
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)
        resp4.dump()

    def tes_SamrLookupNamesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrLookupNamesInDomain()
        request['DomainHandle'] = domainHandle
        request['Count'] = 2
        entry = dtypes.RPC_UNICODE_STRING()
        entry['Data'] = 'Administrator'
        request['Names'].append(entry)
        entry = dtypes.RPC_UNICODE_STRING()
        entry['Data'] = 'beto'
        request['Names'].append(entry)

        resp5 = dce.request(request)
        resp5.dump()

    def tes_SamrLookupIdsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrLookupIdsInDomain()
        request['DomainHandle'] = domainHandle
        request['Count'] = 2
        request['RelativeIds'].append(500)
        request['RelativeIds'].append(501)
        resp5 = dce.request(request)
        resp5.dump()

    def tes_SamrEnumerateGroupsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateGroupsInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except Exception, e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

    def tes_SamrEnumerateAliasesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except Exception, e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

    def tes_SamrEnumerateUsersInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateUsersInDomain()
        request['DomainHandle'] = domainHandle
        request['UserAccountControl'] =  samr.USER_NORMAL_ACCOUNT
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 8192
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except Exception, e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

    def tes_SamrGetGroupsForUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_LIST_GROUPS
        request['UserId'] = 500
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrGetGroupsForUser()
        request['UserHandle'] = resp['UserHandle'] 
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryDisplayInformation3(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryDisplayInformation2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryDisplayInformation2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryDisplayInformation(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrGetDisplayEnumerationIndex2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrGetDisplayEnumerationIndex2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Prefix'] = 'Gu'
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrGetDisplayEnumerationIndex2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Prefix'] = 'Non'
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrGetDisplayEnumerationIndex(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrGetDisplayEnumerationIndex()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Prefix'] = 'Gu'
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrCreateGroupInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateGroupInDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrCreateAliasInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrCreateUser2InDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = samr.USER_READ_GENERAL
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrCreateUserInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateUserInDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['DesiredAccess'] = samr.USER_READ_GENERAL
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryInformationDomain2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryInformationDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryInformationGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        request = samr.SamrQueryInformationGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAttributeInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupReplicationInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryInformationAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] =  0
        request['PreferedMaximumLength'] = 500
        resp4 = dce.request(request)
        resp4.dump()
        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationAlias()
        request['AliasHandle'] = resp['AliasHandle']
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

    def tes_SamrQueryInformationUser2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_ALL_ACCESS | samr.USER_READ
        request['UserId'] = 500
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationUser2()
        request['UserHandle'] = resp['UserHandle']
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserGeneralInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonHoursInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserFullNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserHomeInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserScriptInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserProfileInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAdminCommentInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserWorkStationsInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserExpiresInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal1Information
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserParametersInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAllInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4Information
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

    def test_SamrQueryInformationUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_ALL_ACCESS | samr.USER_READ
        request['UserId'] = 500
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationUser()
        request['UserHandle'] = resp['UserHandle']
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserGeneralInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonHoursInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserFullNameInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserHomeInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserScriptInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserProfileInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAdminCommentInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserWorkStationsInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserExpiresInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal1Information
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserParametersInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAllInformation
        request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4Information
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass


class SMBTransport(SAMRTests):
    def setUp(self):
        SAMRTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        self.username = 'test'
        self.domain   = ''
        self.serverName = ''
        self.password = 'test'
        self.machine  = '172.16.123.218'
        self.stringBinding = r'ncacn_np:%s[\pipe\samr]' % self.machine
        self.dport = 445
        self.hashes   = ''


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
