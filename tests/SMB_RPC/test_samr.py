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
#  SamrDeleteUser
#  SamrDeleteAlias
#  SamrDeleteGroup
#  SamrAddMemberToGroup
#  SamrRemoveMemberFromGroup
#  SamrGetMembersInGroup  
#  SamrGetMembersInAlias
#  SamrAddMemberToAlias
#  SamrRemoveMemberFromAlias
#  SamrAddMultipleMembersToAlias
#  SamrRemoveMultipleMembersFromAlias
#  SamrRemoveMemberFromForeignDomain
#  SamrGetAliasMembership
#  SamrCloseHandle
#  SamrSetMemberAttributesOfGroup
#  SamrGetUserDomainPasswordInformation
#  SamrGetDomainPasswordInformation
#  SamrRidToSid
#  SamrSetDSRMPassword
#  SamrValidatePassword
#  SamrQuerySecurityObject
#  SamrSetSecurityObject
#  SamrSetInformationDomain
#  SamrSetInformationGroup
#  SamrSetInformationAlias
#  SamrSetInformationUser2
#  SamrChangePasswordUser
#  SamrOemChangePasswordUser2
#  SamrUnicodeChangePasswordUser2
#  hSamrConnect5
#  hSamrConnect4
#  hSamrConnect2
#  hSamrConnect
#  hSamrOpenDomain
#  hSamrOpenGroup
#  hSamrOpenAlias
#  hSamrOpenUser 
#  hSamrEnumerateDomainsInSamServer
#  hSamrEnumerateGroupsInDomain
#  hSamrEnumerateAliasesInDomain
#  hSamrEnumerateUsersInDomain
#  hSamrQueryDisplayInformation3
#  hSamrQueryDisplayInformation2
#  hSamrQueryDisplayInformation
#  hSamrGetDisplayEnumerationIndex2
#  hSamrGetDisplayEnumerationIndex
#  hSamrCreateGroupInDomain
#  hSamrCreateAliasInDomain
#  hSamrCreateUser2InDomain
#  hSamrCreateUserInDomain
#  hSamrQueryInformationDomain2
#  hSamrQueryInformationDomain
#  hSamrQueryInformationGroup
#  hSamrQueryInformationAlias
#  SamrQueryInformationUser2
#  hSamrSetInformationDomain
#  hSamrSetInformationGroup
#  hSamrSetInformationAlias
#  hSamrSetInformationUser2
#  hSamrDeleteGroup
#  hSamrDeleteAlias
#  hSamrDeleteUser
#  hSamrAddMemberToGroup
#  hSamrRemoveMemberFromGroup
#  hSamrGetMembersInGroup
#  hSamrAddMemberToAlias
#  hSamrRemoveMemberFromAlias
#  hSamrGetMembersInAlias
#  hSamrRemoveMemberFromForeignDomain
#  hSamrAddMultipleMembersToAlias
#  hSamrRemoveMultipleMembersFromAlias
#  hSamrGetGroupsForUser 
#  hSamrGetAliasMembership 
#  hSamrChangePasswordUser 
#  hSamrUnicodeChangePasswordUser2 
#  hSamrLookupDomainInSamServer 
#  hSamrSetSecurityObject 
#  hSamrQuerySecurityObject 
#  hSamrCloseHandle 
#  hSamrGetUserDomainPasswordInformation 
#  hSamrGetDomainPasswordInformation 
#  hSamrRidToSid 
#  hSamrValidatePassword
#  hSamrLookupNamesInDomain
#  hSamrLookupIdsInDomain
#  
# ToDo:
# 
# Shouldn't dump errors against a win7
################################################################################

import unittest
import ConfigParser
import string
import random

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import samr, epm
from impacket.dcerpc.v5 import dtypes
from impacket import nt_errors, ntlm
from impacket.dcerpc.v5.ndr import NULL


class SAMRTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        #rpctransport.set_dport(self.dport)
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
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.bind(samr.MSRPC_UUID_SAMR, transfer_syntax = self.ts)
        request = samr.SamrConnect()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = samr.DELETE | samr.READ_CONTROL | samr.WRITE_DAC | samr.WRITE_OWNER | samr.ACCESS_SYSTEM_SECURITY | samr.GENERIC_READ | samr.GENERIC_WRITE | samr.GENERIC_EXECUTE | samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_SHUTDOWN | samr.SAM_SERVER_INITIALIZE | samr.SAM_SERVER_CREATE_DOMAIN | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN | samr.SAM_SERVER_READ | samr.SAM_SERVER_WRITE | samr.SAM_SERVER_EXECUTE
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
        request['DesiredAccess'] =  samr.DOMAIN_READ_PASSWORD_PARAMETERS | samr.DOMAIN_READ_OTHER_PARAMETERS | samr.DOMAIN_CREATE_USER | samr.DOMAIN_CREATE_ALIAS | samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_ADMINISTER_SERVER | samr.DELETE | samr.READ_CONTROL | samr.ACCESS_SYSTEM_SECURITY | samr.DOMAIN_WRITE_OTHER_PARAMETERS | samr.DOMAIN_WRITE_PASSWORD_PARAMS 
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)

        return dce, rpctransport, resp4['DomainHandle']

    def test_SamrCloseHandle(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCloseHandle()
        request['SamHandle'] = domainHandle
        resp = dce.request(request)
        resp.dump()

    def test_hSamrCloseHandle(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrCloseHandle(dce, domainHandle)
        resp.dump()

    def test_SamrConnect5(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect5()
        request['ServerName'] = u'BETO\x00'
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['InVersion'] = 1
        request['InRevisionInfo']['tag'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect5(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrConnect5(dce)
        resp.dump()

    def test_SamrConnect4(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect4()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        request['ClientRevision'] = 2
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect4(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrConnect4(dce)
        resp.dump()

    def test_SamrConnect2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect2()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect2(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrConnect2(dce)
        resp.dump()

    def test_SamrConnect(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrConnect(dce)
        resp.dump()

    def test_SamrOpenDomain(self):
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
        
    def test_hSamrOpenDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrConnect(dce)

        SID = 'S-1-5-352321536-2562177771-1589929855-2033349547'
        sid = dtypes.RPC_SID()
        sid.fromCanonical(SID)
        try:
            resp = samr.hSamrOpenDomain(dce, serverHandle = resp['ServerHandle'], domainId = sid) 
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

    def test_SamrOpenGroup(self):
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
        
    def test_hSamrOpenGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrOpenGroup(dce, domainHandle, groupId=samr.DOMAIN_GROUP_RID_USERS)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

    def test_SamrOpenAlias(self):
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

    def test_hSamrOpenAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrOpenAlias(dce, domainHandle, aliasId = 25)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_ALIAS') < 0:
                raise

    def test_SamrOpenUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()

    def test_hSamrOpenUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrOpenUser(dce, domainHandle, samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT, samr.DOMAIN_USER_RID_ADMIN)

        resp.dump()

    def test_SamrEnumerateDomainsInSamServer(self):
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

    def test_hSamrEnumerateDomainsInSamServer(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrConnect(dce, desiredAccess = samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)
        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, resp['ServerHandle'])
        resp2.dump()
        resp3 = samr.hSamrLookupDomainInSamServer(dce, resp['ServerHandle'],resp2['Buffer']['Buffer'][0]['Name'] )
        resp3.dump()
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)
        resp4.dump()

    def test_SamrLookupNamesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrLookupNamesInDomain()
        request['DomainHandle'] = domainHandle
        request['Count'] = 1
        entry = dtypes.RPC_UNICODE_STRING()
        entry['Data'] = 'Administrator'
        #entry.fields['MaximumLength'] = len('Administrator\x00')*2
        #entry.fields['Data'].fields['Data'].fields['MaximumCount'] = len('Administrator\x00')
        request['Names'].append(entry)
        request.fields['Names'].fields['MaximumCount'] = 1000
        resp5 = dce.request(request)
        resp5.dump()

    def test_hSamrLookupNamesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, ('Administrator','Guest'))
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                pass
            e.get_packet().dump()

    def test_SamrLookupIdsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrLookupIdsInDomain()
        request.dump()
        request['DomainHandle'] = domainHandle
        request['Count'] = 2
        entry = dtypes.ULONG()
        entry['Data'] = 500
        request['RelativeIds'].append(entry)
        entry = dtypes.ULONG()
        entry['Data'] = 501
        request['RelativeIds'].append(entry)
        request.fields['RelativeIds'].fields['MaximumCount'] = 1000
        resp5 = dce.request(request)
        resp5.dump()

    def test_hSamrLookupIdsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrLookupIdsInDomain(dce, domainHandle, (500,501))
        resp.dump()

    def test_SamrEnumerateGroupsInDomain(self):
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

    def test_hSamrEnumerateGroupsInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
        resp.dump()

    def test_SamrEnumerateAliasesInDomain(self):
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

    def test_hSamrEnumerateAliasesInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        resp.dump()

    def test_SamrEnumerateUsersInDomain(self):
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

    def test_hSamrEnumerateUsersInDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                pass
            e.get_packet().dump()

    def test_SamrGetGroupsForUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_LIST_GROUPS
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrGetGroupsForUser()
        request['UserHandle'] = resp['UserHandle'] 
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetGroupsForUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_LIST_GROUPS
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()
        resp = samr.hSamrGetGroupsForUser(dce, resp['UserHandle'])
        resp.dump()

    def test_SamrQueryDisplayInformation3(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise

        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQueryDisplayInformation3(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrQueryDisplayInformation3(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise

        resp = samr.hSamrQueryDisplayInformation3(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine)
        resp.dump()

        resp = samr.hSamrQueryDisplayInformation3(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup)
        resp.dump()

        resp = samr.hSamrQueryDisplayInformation3(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup)
        resp.dump()

    def test_SamrQueryDisplayInformation2(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrQueryDisplayInformation2(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise

        resp = samr.hSamrQueryDisplayInformation2(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine)
        resp.dump()

        resp = samr.hSamrQueryDisplayInformation2(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup)
        resp.dump()

        resp = samr.hSamrQueryDisplayInformation2(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup)
        resp.dump()

    def test_SamrQueryDisplayInformation(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise

        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQueryDisplayInformation(self):
        dce, rpctransport, domainHandle  = self.connect()

        try:
            resp = samr.hSamrQueryDisplayInformation(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise


        resp = samr.hSamrQueryDisplayInformation(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine)
        resp.dump()

        resp = samr.hSamrQueryDisplayInformation(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup)
        resp.dump()

        resp = samr.hSamrQueryDisplayInformation(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup)
        resp.dump()

    def test_SamrGetDisplayEnumerationIndex2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrGetDisplayEnumerationIndex2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Prefix'] = 'Gu'
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrGetDisplayEnumerationIndex2()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup
        request['Prefix'] = 'Non'
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetDisplayEnumerationIndex2(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrGetDisplayEnumerationIndex2(dce, domainHandle, samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, 'Gu')
        resp.dump()

        resp = samr.hSamrGetDisplayEnumerationIndex2(dce, domainHandle, samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup, 'Non')
        resp.dump()

    def test_SamrGetDisplayEnumerationIndex(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrGetDisplayEnumerationIndex(dce, domainHandle, samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, 'Gu')
        resp.dump()

    def test_hSamrGetDisplayEnumerationIndex(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrGetDisplayEnumerationIndex()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Prefix'] = 'Gu'
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_SamrCreateGroupInDomain_SamrDeleteGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateGroupInDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find("STATUS_ACCESS_DENIED") < 0:
                raise
        request = samr.SamrDeleteGroup()
        request['GroupHandle'] = domainHandle
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find("STATUS_OBJECT_TYPE_MISMATCH") < 0:
                raise

    def test_hSamrCreateGroupInDomain_hSamrDeleteGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp = samr.hSamrCreateGroupInDomain(dce, domainHandle, 'testGroup', samr.GROUP_ALL_ACCESS | samr.DELETE)
            resp.dump()
        except Exception, e:
            if str(e).find("STATUS_ACCESS_DENIED") < 0:
                raise
        try:
            resp = samr.hSamrDeleteGroup(dce, domainHandle)
            resp.dump()
        except Exception, e:
            if str(e).find("STATUS_OBJECT_TYPE_MISMATCH") < 0:
                raise

    def test_SamrCreateAliasInDomain_SamrDeleteAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = resp['AliasHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrCreateAliasInDomain_hSamrDeleteAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrCreateAliasInDomain(dce, domainHandle, 'testGroup',  samr.GROUP_ALL_ACCESS | samr.DELETE)
        resp.dump()
        resp = samr.hSamrDeleteAlias(dce, resp['AliasHandle'])
        resp.dump()

    def test_SamrCreateUser2InDomain_SamrDeleteUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrCreateUser2InDomain_hSamrDeleteUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrCreateUser2InDomain(dce, domainHandle, 'testAccount', samr.USER_NORMAL_ACCOUNT,samr.USER_READ_GENERAL | samr.DELETE )
        resp.dump()
        resp = samr.hSamrDeleteUser(dce, resp['UserHandle'])
        resp.dump()

    def test_SamrQueryInformationDomain2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_SamrQueryInformationDomain2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationDomain2()
        request['DomainHandle'] = domainHandle
        request['DomainInformationClass'] = samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQueryInformationDomain2(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2)
        resp.dump()

    def test_hSamrQueryInformationDomain_hSamrSetInformationDomain(self):
        dce, rpctransport, domainHandle  = self.connect()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        resp.dump()

        resp['Buffer']['Password']['MaxPasswordAge']['LowPart'] = 11
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()
 
        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        resp2.dump()
        self.assertTrue( 11 == resp2['Buffer']['Password']['MaxPasswordAge']['LowPart'] )

        resp2['Buffer']['Password']['MaxPasswordAge']['LowPart'] = 0
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()
   
        ################################################################################ 
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
        resp.dump()

        resp['Buffer']['General']['ReplicaSourceNodeName'] = 'BETUS'
        try:
            resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise


        ################################################################################ 

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
        resp.dump()

        oldData = resp['Buffer']['Logoff']['ForceLogoff']['LowPart'] 

        resp['Buffer']['Logoff']['ForceLogoff']['LowPart'] = 11
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()

        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
        resp2.dump()

        self.assertTrue( 11 == resp2['Buffer']['Logoff']['ForceLogoff']['LowPart'] )

        resp2['Buffer']['Logoff']['ForceLogoff']['LowPart'] = oldData
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation)
        resp.dump()

        oldData = resp['Buffer']['Oem']['OemInformation']

        resp['Buffer']['Oem']['OemInformation'] = 'BETUS'
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()

        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation)
        resp2.dump()

        self.assertTrue( 'BETUS'  == resp2['Buffer']['Oem']['OemInformation'])

        resp2['Buffer']['Oem']['OemInformation'] = oldData
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()

        ################################################################################ 

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation)
        resp.dump()

        ################################################################################ 

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation)
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation)
        resp.dump()

        oldData = resp['Buffer']['Replication']['ReplicaSourceNodeName']

        resp['Buffer']['Replication']['ReplicaSourceNodeName'] = 'BETUS'
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()

        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation)
        resp2.dump()

        self.assertTrue( 'BETUS'  == resp2['Buffer']['Replication']['ReplicaSourceNodeName'])

        resp2['Buffer']['Replication']['ReplicaSourceNodeName'] = oldData
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2)
        resp.dump()

    def test_SamrQueryInformationGroup_SamrSetInformationGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp0 = dce.request(request)
            resp0.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        request = samr.SamrQueryInformationGroup()
        request['GroupHandle'] = resp0['GroupHandle']
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        ################################################################################ 

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SamrSetInformationGroup()
        req['GroupHandle'] = resp0['GroupHandle']
        req['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        req['Buffer']['tag'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        req['Buffer']['Name']['Name'] = 'BETUS'
        resp = dce.request(req)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETUS'  == resp['Buffer']['Name']['Name'])

        req['Buffer']['Name']['Name'] = oldData
        resp = dce.request(req)
        resp.dump()


        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAttributeInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Attribute']['Attributes']

        req = samr.SamrSetInformationGroup()
        req['GroupHandle'] = resp0['GroupHandle']
        req['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAttributeInformation
        req['Buffer']['tag'] = samr.GROUP_INFORMATION_CLASS.GroupAttributeInformation
        req['Buffer']['Attribute']['Attributes'] = 2
        resp = dce.request(req)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAttributeInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        #self.assertTrue( 2  == resp['Buffer']['Attribute']['Attributes'])

        req['Buffer']['Attribute']['Attributes'] = oldData
        resp = dce.request(req)
        resp.dump()


        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        oldData = resp['Buffer']['AdminComment']['AdminComment']

        req = samr.SamrSetInformationGroup()
        req['GroupHandle'] = resp0['GroupHandle']
        req['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        req['Buffer']['tag'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        req['Buffer']['AdminComment']['AdminComment'] = 'BETUS'
        resp = dce.request(req)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETUS'  == resp['Buffer']['AdminComment']['AdminComment'])

        req['Buffer']['AdminComment']['AdminComment'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupReplicationInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQueryInformationGroup_hSamrSetInformationGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        try:
            resp0 = samr.hSamrOpenGroup(dce, domainHandle,samr.GROUP_ALL_ACCESS, samr.DOMAIN_GROUP_RID_USERS )
            resp0.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        resp = samr.hSamrQueryInformationGroup(dce, resp0['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
        resp.dump()
        ################################################################################ 

        resp = samr.hSamrQueryInformationGroup(dce, resp0['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupNameInformation)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SAMPR_GROUP_INFO_BUFFER()
        req['tag'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        req['Name']['Name'] = 'BETUS'
        resp = samr.hSamrSetInformationGroup(dce, resp0['GroupHandle'], req)
        resp.dump()

        resp = samr.hSamrQueryInformationGroup(dce, resp0['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupNameInformation)
        resp.dump()
        self.assertTrue( 'BETUS'  == resp['Buffer']['Name']['Name'])

        req['Name']['Name'] = oldData
        resp = samr.hSamrSetInformationGroup(dce, resp0['GroupHandle'], req)
        resp.dump()

    def test_hSamrQueryInformationAlias_hSamrSetInformationAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp4 = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        resp4.dump()

        resp0 = samr.hSamrOpenAlias(dce, domainHandle, aliasId = resp4['Buffer']['Buffer'][0]['RelativeId'])
        resp0.dump()

        resp = samr.hSamrQueryInformationAlias(dce, resp0['AliasHandle'], samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation)
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationAlias(dce, resp0['AliasHandle'], samr.ALIAS_INFORMATION_CLASS.AliasNameInformation)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SAMPR_ALIAS_INFO_BUFFER()
        req['tag'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        req['Name']['Name'] = 'BETUS'
        resp = samr.hSamrSetInformationAlias(dce, resp0['AliasHandle'], req)
        resp.dump()

        resp = samr.hSamrQueryInformationAlias(dce, resp0['AliasHandle'], samr.ALIAS_INFORMATION_CLASS.AliasNameInformation)
        resp.dump()

        self.assertTrue( 'BETUS'  == resp['Buffer']['Name']['Name'])

        req['Name']['Name'] = oldData
        resp = samr.hSamrSetInformationAlias(dce, resp0['AliasHandle'], req)
        resp.dump()

    def test_SamrQueryInformationAlias_SamrSetInformationAlias(self):
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

        resp4.dump()
        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp0 = dce.request(request)
        resp0.dump()

        request = samr.SamrQueryInformationAlias()
        request['AliasHandle'] = resp0['AliasHandle']
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        ################################################################################ 
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SamrSetInformationAlias()
        req['AliasHandle'] = resp0['AliasHandle']
        req['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        req['Buffer']['tag'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        req['Buffer']['Name']['Name'] = 'BETUS'
        resp = dce.request(req)
        resp.dump()

        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETUS'  == resp['Buffer']['Name']['Name'])

        req['Buffer']['Name']['Name'] = oldData
        resp = dce.request(req)
        resp.dump()


        ################################################################################ 
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['AdminComment']['AdminComment']

        req = samr.SamrSetInformationAlias()
        req['AliasHandle'] = resp0['AliasHandle']
        req['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        req['Buffer']['tag'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        req['Buffer']['AdminComment']['AdminComment'] = 'BETUS'
        resp = dce.request(req)
        resp.dump()

        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETUS'  == resp['Buffer']['AdminComment']['AdminComment'])

        req['Buffer']['AdminComment']['AdminComment'] = oldData
        resp = dce.request(req)
        resp.dump()

    def test_SamrQueryInformationUser2_SamrSetInformationUser2(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        #request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_ALL_ACCESS | samr.USER_READ | samr.USER_READ_LOGON 
        request['DesiredAccess'] = \
            samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_WRITE_PREFERENCES | samr.USER_READ_LOGON \
            | samr.USER_READ_ACCOUNT | samr.USER_WRITE_ACCOUNT | samr.USER_CHANGE_PASSWORD | samr.USER_FORCE_PASSWORD_CHANGE  \
            | samr.USER_LIST_GROUPS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION | samr.USER_ALL_ACCESS  \
            | samr.USER_READ | samr.USER_WRITE  | samr.USER_EXECUTE 

        
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationUser2()
        request['UserHandle'] = resp['UserHandle']
        userHandle = resp['UserHandle'] 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserGeneralInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Preferences']['UserComment']

        req = samr.SamrSetInformationUser2()
        req['UserHandle'] = userHandle
        req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        req['Buffer'] = resp['Buffer'] 
        req['Buffer']['Preferences']['UserComment'] = 'BETO'
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETO' == resp['Buffer']['Preferences']['UserComment'])

        req['Buffer']['Preferences']['UserComment'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonHoursInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Name']['FullName']

        req = samr.SamrSetInformationUser2()
        req['UserHandle'] = userHandle
        req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        req['Buffer'] = resp['Buffer'] 
        req['Buffer']['Name']['FullName'] = 'BETO'
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETO' == resp['Buffer']['Name']['FullName'])

        req['Buffer']['Name']['FullName'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        oldData = resp['Buffer']['AccountName']['UserName']

        req = samr.SamrSetInformationUser2()
        req['UserHandle'] = userHandle
        req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        req['Buffer'] = resp['Buffer'] 
        req['Buffer']['AccountName']['UserName'] = 'BETUS'
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETUS' == resp['Buffer']['AccountName']['UserName'])

        req['Buffer']['AccountName']['UserName'] = oldData
        resp = dce.request(req)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserFullNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserHomeInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserScriptInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserProfileInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAdminCommentInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserWorkStationsInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserExpiresInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal1Information
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserParametersInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAllInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
       
        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4Information
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

    def test_hSamrQueryInformationUser2_hSamrSetInformationUser2(self):
        dce, rpctransport, domainHandle  = self.connect()
        desiredAccess = \
            samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_WRITE_PREFERENCES | samr.USER_READ_LOGON \
            | samr.USER_READ_ACCOUNT | samr.USER_WRITE_ACCOUNT | samr.USER_CHANGE_PASSWORD | samr.USER_FORCE_PASSWORD_CHANGE  \
            | samr.USER_LIST_GROUPS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION | samr.USER_ALL_ACCESS  \
            | samr.USER_READ | samr.USER_WRITE  | samr.USER_EXECUTE 
        resp = samr.hSamrOpenUser(dce, domainHandle, desiredAccess, samr.DOMAIN_USER_RID_ADMIN )
        resp.dump()
        userHandle = resp['UserHandle']

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserGeneralInformation)
        resp.dump()
        ################################################################################ 
        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserPreferencesInformation)
        resp.dump()
        oldData = resp['Buffer']['Preferences']['UserComment']

        resp['Buffer']['Preferences']['UserComment'] = 'BETO'
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserPreferencesInformation)
        resp.dump()

        self.assertTrue( 'BETO' == resp['Buffer']['Preferences']['UserComment'])

        resp['Buffer']['Preferences']['UserComment'] = oldData
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserLogonInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserLogonHoursInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserAccountInformation)
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserNameInformation)
        resp.dump()
        oldData = resp['Buffer']['Name']['FullName']

        resp['Buffer']['Name']['FullName'] = 'BETO'
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserNameInformation)
        resp.dump()

        self.assertTrue( 'BETO' == resp['Buffer']['Name']['FullName'])

        resp['Buffer']['Name']['FullName'] = oldData
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserAccountNameInformation)
        resp.dump()

        oldData = resp['Buffer']['AccountName']['UserName']

        resp['Buffer']['AccountName']['UserName'] = 'BETUS'
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserAccountNameInformation)
        resp.dump()

        self.assertTrue( 'BETUS' == resp['Buffer']['AccountName']['UserName'])

        resp['Buffer']['AccountName']['UserName'] = oldData
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserFullNameInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserHomeInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserScriptInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserProfileInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserAdminCommentInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserWorkStationsInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserControlInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserExpiresInformation)
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserParametersInformation)
        resp.dump()


        ################################################################################ 
        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserAllInformation)
        resp.dump()

    def test_SamrQueryInformationUser_SamrSetInformationUser(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_ALL_ACCESS | samr.USER_READ
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationUser()
        request['UserHandle'] = resp['UserHandle']
        userHandle = resp['UserHandle']

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserGeneralInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        ################################################################################ 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Preferences']['UserComment']

        req = samr.SamrSetInformationUser()
        req['UserHandle'] = userHandle
        req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        req['Buffer'] = resp['Buffer'] 
        req['Buffer']['Preferences']['UserComment'] = 'BETO'
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertTrue( 'BETO' == resp['Buffer']['Preferences']['UserComment'])

        req['Buffer']['Preferences']['UserComment'] = oldData
        resp = dce.request(req)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserLogonHoursInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserFullNameInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserHomeInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserScriptInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserProfileInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAdminCommentInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserWorkStationsInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserExpiresInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal1Information
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserParametersInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAllInformation
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4Information
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_INFO_CLASS') < 0:
                raise
            pass

    def test_SamrAddMemberToGroup_SamrRemoveMemberFromGroup(self):
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
        request = samr.SamrRemoveMemberFromGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['MemberId'] = samr.DOMAIN_USER_RID_ADMIN
        try:
            resp2 = dce.request(request)
            resp2.dump()
        except Exception, e:
            if str(e).find('STATUS_MEMBERS_PRIMARY_GROUP') < 0:
                raise
        request = samr.SamrAddMemberToGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['MemberId'] = samr.DOMAIN_USER_RID_ADMIN
        request['Attributes'] = samr.SE_GROUP_ENABLED_BY_DEFAULT
        try:
            resp2 = dce.request(request)
            resp2.dump()
        except Exception, e:
            if str(e).find('STATUS_MEMBER_IN_GROUP') < 0:
                raise

    def test_hSamrAddMemberToGroup_hSamrRemoveMemberFromGroup(self):
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
        try:
            resp2 = samr.hSamrRemoveMemberFromGroup(dce, resp['GroupHandle'],samr.DOMAIN_USER_RID_ADMIN)
            resp2.dump()
        except Exception, e:
            if str(e).find('STATUS_MEMBERS_PRIMARY_GROUP') < 0:
                raise
        try:
            resp2= samr.hSamrAddMemberToGroup(dce, resp['GroupHandle'] ,samr.DOMAIN_USER_RID_ADMIN, samr.SE_GROUP_ENABLED_BY_DEFAULT)
            resp2.dump()
        except Exception, e:
            if str(e).find('STATUS_MEMBER_IN_GROUP') < 0:
                raise

    def test_SamrGetMembersInGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
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

        request = samr.SamrGetMembersInGroup()
        request['GroupHandle'] = resp['GroupHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetMembersInGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
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

        resp = samr.hSamrGetMembersInGroup(dce, resp['GroupHandle'])
        resp.dump()

    def test_SamrGetMembersInAlias(self):
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

        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrGetMembersInAlias()
        request['AliasHandle'] = resp['AliasHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetMembersInAlias(self):
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

        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp = dce.request(request)
        resp.dump()

        resp = samr.hSamrGetMembersInAlias(dce, resp['AliasHandle'])
        resp.dump()

    def test_SamrAddMemberToAlias_SamrRemoveMemberFromAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        request = samr.SamrAddMemberToAlias()
        request['AliasHandle'] = aliasHandle
        request['MemberId'] = sid
        resp2 = dce.request(request)
        resp2.dump()

        request = samr.SamrRemoveMemberFromAlias()
        request['AliasHandle'] = aliasHandle
        request['MemberId'] = sid
        resp2 = dce.request(request)
        resp2.dump()

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)

    def test_hSamrAddMemberToAlias_hSamrRemoveMemberFromAlias(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrCreateAliasInDomain(dce, domainHandle, 'testGroup',  samr.GROUP_ALL_ACCESS | samr.DELETE)
        resp.dump()
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        resp2 = samr.hSamrAddMemberToAlias(dce, aliasHandle, sid)
        resp2.dump()

        resp2 = samr.hSamrRemoveMemberFromAlias(dce, aliasHandle, sid)
        resp2.dump()

        resp = samr.hSamrDeleteAlias(dce, aliasHandle)
        resp.dump()


    def test_SamrAddMultipleMembersToAlias_SamrRemoveMultipleMembersFromAliass(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        guestSID = domainID + '-%d' % samr.DOMAIN_USER_RID_GUEST

        sid1 = samr.RPC_SID()
        sid1.fromCanonical(adminSID)

        sid2 = samr.RPC_SID()
        sid2.fromCanonical(guestSID)

        si = samr.PSAMPR_SID_INFORMATION()
        si['SidPointer'] = sid1

        si2 = samr.PSAMPR_SID_INFORMATION()
        si2['SidPointer'] = sid2

        request = samr.SamrAddMultipleMembersToAlias()
        request['AliasHandle'] = aliasHandle
        request['MembersBuffer']['Count'] = 2
        request['MembersBuffer']['Sids'].append(si)
        request['MembersBuffer']['Sids'].append(si2)
        #request.dump()
        resp2 = dce.request(request)
        resp2.dump()

        request = samr.SamrRemoveMultipleMembersFromAlias()
        request['AliasHandle'] = resp['AliasHandle'] 
        request['MembersBuffer']['Count'] = 2
        request['MembersBuffer']['Sids'].append(si)
        request['MembersBuffer']['Sids'].append(si2)
        resp2 = dce.request(request)
        resp2.dump()

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)

    def test_hSamrAddMultipleMembersToAlias_hSamrRemoveMultipleMembersFromAliass(self):
        dce, rpctransport, domainHandle  = self.connect()
        #resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        #resp = samr.hSamrOpenAlias(dce, domainHandle, samr.DELETE, 1257)
        #resp = samr.hSamrDeleteAlias(dce, resp['AliasHandle'])
        resp = samr.hSamrCreateAliasInDomain(dce, domainHandle, 'testGroup', samr.GROUP_ALL_ACCESS | samr.DELETE)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        guestSID = domainID + '-%d' % samr.DOMAIN_USER_RID_GUEST

        sid1 = samr.RPC_SID()
        sid1.fromCanonical(adminSID)

        sid2 = samr.RPC_SID()
        sid2.fromCanonical(guestSID)

        si = samr.PSAMPR_SID_INFORMATION()
        si['SidPointer'] = sid1

        si2 = samr.PSAMPR_SID_INFORMATION()
        si2['SidPointer'] = sid2

        sidArray = samr.SAMPR_PSID_ARRAY()
        sidArray['Sids'].append(si)
        sidArray['Sids'].append(si2)

        resp = samr.hSamrAddMultipleMembersToAlias(dce, aliasHandle, sidArray)
        resp.dump()

        resp = samr.hSamrRemoveMultipleMembersFromAlias(dce, aliasHandle, sidArray)
        resp.dump()

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)


    def test_SamrRemoveMemberFromForeignDomain(self):
        dce, rpctransport, domainHandle  = self.connect()

        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        request = samr.SamrRemoveMemberFromForeignDomain()
        request['DomainHandle'] = domainHandle
        request['MemberSid'].fromCanonical(adminSID)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_SPECIAL_ACCOUNT') < 0:
                raise

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)

    def test_hSamrRemoveMemberFromForeignDomain(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN
        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)
        try:
            resp= samr.hSamrRemoveMemberFromForeignDomain(dce, domainHandle, sid)
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_SPECIAL_ACCOUNT') < 0:
                raise

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)

    def test_SamrGetAliasMembership(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        guestSID = domainID + '-%d' % samr.DOMAIN_USER_RID_GUEST

        sid1 = samr.RPC_SID()
        sid1.fromCanonical(adminSID)

        sid2 = samr.RPC_SID()
        sid2.fromCanonical(guestSID)

        si = samr.PSAMPR_SID_INFORMATION()
        si['SidPointer'] = sid1

        si2 = samr.PSAMPR_SID_INFORMATION()
        si2['SidPointer'] = sid2


        request = samr.SamrGetAliasMembership()
        request['DomainHandle'] = domainHandle
        request['SidArray']['Count'] = 2
        request['SidArray']['Sids'].append(si)
        request['SidArray']['Sids'].append(si2)
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)

    def test_hSamrGetAliasMembership(self):
        dce, rpctransport, domainHandle  = self.connect()
        #resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        #resp = samr.hSamrOpenAlias(dce, domainHandle, samr.DELETE, 1268)
        #resp = samr.hSamrDeleteAlias(dce, resp['AliasHandle'])

        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = 'testGroup'
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        #request.dump()
        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN

        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)

        guestSID = domainID + '-%d' % samr.DOMAIN_USER_RID_GUEST

        sid1 = samr.RPC_SID()
        sid1.fromCanonical(adminSID)

        sid2 = samr.RPC_SID()
        sid2.fromCanonical(guestSID)

        si = samr.PSAMPR_SID_INFORMATION()
        si['SidPointer'] = sid1

        si2 = samr.PSAMPR_SID_INFORMATION()
        si2['SidPointer'] = sid2

        sidsArray = samr.SAMPR_PSID_ARRAY()
        sidsArray['Sids'].append(si)
        sidsArray['Sids'].append(si2)

        try:
            resp = samr.hSamrGetAliasMembership(dce, domainHandle, sidsArray)
            resp.dump()
        except Exception, e:
            request = samr.SamrDeleteAlias()
            request['AliasHandle'] = aliasHandle
            resp = dce.request(request)
            raise

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        resp = dce.request(request)

    def test_SamrSetMemberAttributesOfGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        resp = dce.request(request)

        request = samr.SamrSetMemberAttributesOfGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['MemberId'] = samr.DOMAIN_USER_RID_ADMIN
        request['Attributes'] = samr.SE_GROUP_ENABLED_BY_DEFAULT
        resp = dce.request(request)
        resp.dump()

    def test_hSamrSetMemberAttributesOfGroup(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = u'BETO\x00'
        resp = dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        resp = dce.request(request)

        resp = samr.hSamrSetMemberAttributesOfGroup(dce, resp['GroupHandle'],samr.DOMAIN_USER_RID_ADMIN, samr.SE_GROUP_ENABLED_BY_DEFAULT)
        resp.dump()


    def test_SamrGetUserDomainPasswordInformation(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)

        request = samr.SamrGetUserDomainPasswordInformation()
        request['UserHandle'] = resp['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetUserDomainPasswordInformation(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)

        resp = samr.hSamrGetUserDomainPasswordInformation(dce, resp['UserHandle'])
        resp.dump()

    def test_SamrGetDomainPasswordInformation(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrGetDomainPasswordInformation()
        request['Unused'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetDomainPasswordInformation(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrGetDomainPasswordInformation(dce)
        resp.dump()

    def test_SamrRidToSid(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] =  samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)

    def test_hSamrRidToSid(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrRidToSid(dce, domainHandle, samr.DOMAIN_USER_RID_ADMIN)
        resp.dump()

    def test_SamrSetDSRMPassword(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrSetDSRMPassword()
        request['Unused'] =  NULL
        request['UserId'] =  samr.DOMAIN_USER_RID_ADMIN
        request['EncryptedNtOwfPassword'] =  '\x00'*16
        # calls made to SamrSetDSRMPassword using NCACN_IP_TCP are rejected with RPC_S_ACCESS_DENIED.
        try:
            resp = dce.request(request)
        except Exception, e:
            if self.stringBinding.find('ncacn_ip_tcp') >=0:
                if str(e).find('rpc_s_access_denied') < 0:
                    raise
            elif str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_SamrValidatePassword(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrValidatePassword()
        request['ValidationType'] =  samr.PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset
        request['InputArg']['tag'] =  samr.PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset
        request['InputArg']['ValidatePasswordResetInput']['InputPersistedFields']['PresentFields'] = samr.SAM_VALIDATE_PASSWORD_HISTORY
        request['InputArg']['ValidatePasswordResetInput']['InputPersistedFields']['PasswordHistory'] = NULL
        request['InputArg']['ValidatePasswordResetInput']['ClearPassword'] = 'AAAAAAAAAAAAAAAA'
        request['InputArg']['ValidatePasswordResetInput']['UserAccountName'] = 'Administrator'
        kk = samr.SamrValidatePassword()
        kk.fromString(str(request))
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_hSamrValidatePassword(self):
        dce, rpctransport, domainHandle  = self.connect()
        inputArg = samr.SAM_VALIDATE_INPUT_ARG()
        inputArg['tag'] =  samr.PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset
        inputArg['ValidatePasswordResetInput']['InputPersistedFields']['PresentFields'] = samr.SAM_VALIDATE_PASSWORD_HISTORY
        inputArg['ValidatePasswordResetInput']['InputPersistedFields']['PasswordHistory'] = NULL
        inputArg['ValidatePasswordResetInput']['ClearPassword'] = 'AAAAAAAAAAAAAAAA'
        inputArg['ValidatePasswordResetInput']['UserAccountName'] = 'Administrator'
        try:
            resp = samr.hSamrValidatePassword(dce, inputArg)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_SamrQuerySecurityObject(self):
        dce, rpctransport, domainHandle  = self.connect()
        request = samr.SamrQuerySecurityObject()
        request['ObjectHandle'] =  domainHandle
        request['SecurityInformation'] =  dtypes.OWNER_SECURITY_INFORMATION | dtypes.GROUP_SECURITY_INFORMATION | dtypes.SACL_SECURITY_INFORMATION | dtypes.DACL_SECURITY_INFORMATION
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQuerySecurityObject(self):
        dce, rpctransport, domainHandle  = self.connect()
        resp = samr.hSamrQuerySecurityObject(dce, domainHandle,dtypes.OWNER_SECURITY_INFORMATION | dtypes.GROUP_SECURITY_INFORMATION | dtypes.SACL_SECURITY_INFORMATION | dtypes.DACL_SECURITY_INFORMATION)
        resp.dump()

    def test_SamrSetSecurityObject(self):
        dce, rpctransport, domainHandle  = self.connect()

        resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.username,))
        resp.dump()

        resp = samr.hSamrOpenUser(dce, domainHandle, samr.USER_ALL_ACCESS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION, resp['RelativeIds']['Element'][0]['Data'])
        resp.dump()
        userHandle = resp['UserHandle']
        request = samr.SamrQuerySecurityObject()
        request['ObjectHandle'] =  userHandle
        request['SecurityInformation'] =  dtypes.GROUP_SECURITY_INFORMATION
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrSetSecurityObject()
        request['ObjectHandle'] =  userHandle
        request['SecurityInformation'] =  dtypes.GROUP_SECURITY_INFORMATION
        request['SecurityDescriptor'] = resp['SecurityDescriptor'] 
        #request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_BAD_DESCRIPTOR_FORMAT') <= 0:
                raise

        resp = samr.hSamrCloseHandle(dce, userHandle)
        resp.dump()

    def test_hSamrSetSecurityObject(self):
        dce, rpctransport, domainHandle  = self.connect()
        dce, rpctransport, domainHandle  = self.connect()

        resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.username,))
        resp.dump()

        resp = samr.hSamrOpenUser(dce, domainHandle, samr.USER_ALL_ACCESS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION, resp['RelativeIds']['Element'][0]['Data'])
        resp.dump()
        userHandle = resp['UserHandle']
        resp = samr.hSamrQuerySecurityObject(dce, userHandle, dtypes.GROUP_SECURITY_INFORMATION)
        resp.dump()

        try:
            resp = samr.hSamrSetSecurityObject(dce, userHandle,dtypes.GROUP_SECURITY_INFORMATION ,resp['SecurityDescriptor']  )
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_BAD_DESCRIPTOR_FORMAT') <= 0:
                raise

        resp = samr.hSamrCloseHandle(dce, userHandle)
        resp.dump()


    def test_SamrChangePasswordUser(self):
        dce, rpctransport, domainHandle  = self.connect()

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE
        #request.dump()
        resp0 = dce.request(request)
        resp0.dump()

        oldPwd = ''
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

        from impacket import crypto
        request = samr.SamrChangePasswordUser()
        request['UserHandle'] = resp0['UserHandle']
        request['LmPresent'] = 0
        request['OldLmEncryptedWithNewLm'] = NULL
        request['NewLmEncryptedWithOldLm'] = NULL
        request['NtPresent'] = 1
        request['OldNtEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
        request['NewNtEncryptedWithOldNt'] = crypto.SamEncryptNTLMHash(newPwdHashNT, oldPwdHashNT) 
        request['NtCrossEncryptionPresent'] = 0
        request['NewNtEncryptedWithNewLm'] = NULL
        request['LmCrossEncryptionPresent'] = 1
        request['NewLmEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(newPwdHashLM, newPwdHashNT)
        resp = dce.request(request)
        resp.dump()

        # Delete the temp user
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp0['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrChangePasswordUser(self):
        dce, rpctransport, domainHandle  = self.connect()

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE
        #request.dump()
        resp0 = dce.request(request)
        resp0.dump()

        resp = samr.hSamrChangePasswordUser(dce, resp0['UserHandle'], '', 'ADMIN')
        resp.dump()

        # Delete the temp user
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp0['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_SamrOemChangePasswordUser2(self):
        dce, rpctransport, domainHandle  = self.connect()
        # As you can guess by now, target machine must have the Administrator account with password admin
        # NOTE: It's giving me WRONG_PASSWORD  'cause the target test server doesn't hold LM Hashes
        # further testing is needed to verify this call works
        oldPwd = 'admin'
        oldPwdHashLM = ntlm.LMOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        from impacket import crypto
        request = samr.SamrOemChangePasswordUser2()
        request['ServerName'] = ''
        request['UserName'] = 'Administrator'
        samUser = samr.SAMPR_USER_PASSWORD()
        samUser['Buffer'] = 'A'*(512-len(newPwd)) + newPwd
        samUser['Length'] = len(newPwd)
        pwdBuff = str(samUser)

        rc4 = ARC4.new(oldPwdHashLM)
        encBuf = rc4.encrypt(pwdBuff)
        request['NewPasswordEncryptedWithOldLm']['Buffer'] = encBuf
        request['OldLmOwfPasswordEncryptedWithNewLm'] = crypto.SamEncryptNTLMHash(oldPwdHashLM, newPwdHashLM)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_WRONG_PASSWORD') < 0:
                raise

    def test_SamrUnicodeChangePasswordUser2(self):
        dce, rpctransport, domainHandle  = self.connect()

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE
        #request.dump()
        resp0 = dce.request(request)
        resp0.dump()

        oldPwd = ''
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

        from impacket import crypto
        request = samr.SamrChangePasswordUser()
        request['UserHandle'] = resp0['UserHandle']
        request['LmPresent'] = 0
        request['OldLmEncryptedWithNewLm'] = NULL
        request['NewLmEncryptedWithOldLm'] = NULL
        request['NtPresent'] = 1
        request['OldNtEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
        request['NewNtEncryptedWithOldNt'] = crypto.SamEncryptNTLMHash(newPwdHashNT, oldPwdHashNT) 
        request['NtCrossEncryptionPresent'] = 0
        request['NewNtEncryptedWithNewLm'] = NULL
        request['LmCrossEncryptionPresent'] = 1
        request['NewLmEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(newPwdHashLM, newPwdHashNT)
        resp = dce.request(request)
        resp.dump()

        oldPwd = 'ADMIN'
        oldPwdHashLM = ntlm.LMOWFv1(oldPwd)
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = chars = "".join( [random.choice(string.letters) for i in xrange(15)] )
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        from impacket import crypto
        request = samr.SamrUnicodeChangePasswordUser2()
        request['ServerName'] = ''
        request['UserName'] = 'testAccount'
        samUser = samr.SAMPR_USER_PASSWORD()
        samUser['Buffer'] = 'A'*(512-len(newPwd)*2) + newPwd.encode('utf-16le')
        samUser['Length'] = len(newPwd)*2
        pwdBuff = str(samUser)

        rc4 = ARC4.new(oldPwdHashNT)
        encBuf = rc4.encrypt(pwdBuff)
        request['NewPasswordEncryptedWithOldNt']['Buffer'] = encBuf
        request['OldNtOwfPasswordEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
        request['LmPresent'] = 0
        request['NewPasswordEncryptedWithOldLm'] = NULL
        request['OldLmOwfPasswordEncryptedWithNewNt'] = NULL

        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_PASSWORD_RESTRICTION') < 0:
                raise

        # Delete the temp user
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp0['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrUnicodeChangePasswordUser2(self):
        dce, rpctransport, domainHandle  = self.connect()

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = 'testAccount'
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE
        #request.dump()
        resp0 = dce.request(request)
        resp0.dump()

        oldPwd = ''
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

        from impacket import crypto
        request = samr.SamrChangePasswordUser()
        request['UserHandle'] = resp0['UserHandle']
        request['LmPresent'] = 0
        request['OldLmEncryptedWithNewLm'] = NULL
        request['NewLmEncryptedWithOldLm'] = NULL
        request['NtPresent'] = 1
        request['OldNtEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldPwdHashNT, newPwdHashNT)
        request['NewNtEncryptedWithOldNt'] = crypto.SamEncryptNTLMHash(newPwdHashNT, oldPwdHashNT) 
        request['NtCrossEncryptionPresent'] = 0
        request['NewNtEncryptedWithNewLm'] = NULL
        request['LmCrossEncryptionPresent'] = 1
        request['NewLmEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(newPwdHashLM, newPwdHashNT)
        resp = dce.request(request)
        resp.dump()

        try:
            resp = samr.hSamrUnicodeChangePasswordUser2(dce, '', 'testAccount', 'ADMIN', 'betus')
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_PASSWORD_RESTRICTION') < 0:
                raise

        # Delete the temp user
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp0['UserHandle']
        resp = dce.request(request)
        resp.dump()

class SMBTransport(SAMRTests):
    def setUp(self):
        SAMRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport(SAMRTests):
    def setUp(self):
        SAMRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        #print epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        self.stringBinding = epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(SAMRTests):
    def setUp(self):
        SAMRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

class TCPTransport64(SAMRTests):
    def setUp(self):
        SAMRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        #print epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        self.stringBinding = epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
