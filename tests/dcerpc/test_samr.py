# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)SamrCloseHandle
#   (h)SamrConnect5
#   (h)SamrConnect4
#   (h)SamrConnect2
#   (h)SamrConnect
#   (h)SamrOpenDomain
#   (h)SamrOpenGroup
#   (h)SamrOpenAlias
#   (h)SamrOpenUser
#   (h)SamrEnumerateDomainsInSamServer
#   (h)SamrLookupNamesInDomain
#   (h)SamrLookupIdsInDomain
#   (h)SamrEnumerateGroupsInDomain
#   (h)SamrEnumerateAliasesInDomain
#   (h)SamrEnumerateUsersInDomain
#   (h)SamrGetGroupsForUser
#   (h)SamrQueryDisplayInformation3
#   (h)SamrQueryDisplayInformation2
#   (h)SamrQueryDisplayInformation
#   (h)SamrGetDisplayEnumerationIndex2
#   (h)SamrGetDisplayEnumerationIndex
#   (h)SamrCreateGroupInDomain
#   (h)SamrDeleteGroup
#   (h)SamrCreateAliasInDomain
#   (h)SamrDeleteAlias
#   (h)SamrCreateUser2InDomain
#   (h)SamrDeleteUser
#   (h)SamrQueryInformationDomain2
#   hSamrQueryInformationDomain
#   hSamrSetInformationDomain
#   (h)SamrQueryInformationGroup
#   (h)SamrSetInformationGroup
#   hSamrQueryInformationAlias
#   hSamrSetInformationAlias
#   SamrQueryInformationAlias
#   SamrSetInformationAlias
#   (h)SamrQueryInformationUser2
#   (h)SamrSetInformationUser2
#   SamrQueryInformationUser
#   SamrSetInformationUser
#   (h)SamrAddMemberToGroup
#   (h)SamrRemoveMemberFromGroup
#   (h)SamrGetMembersInGroup
#   (h)SamrGetMembersInAlias
#   (h)SamrAddMemberToAlias
#   (h)SamrRemoveMemberFromAlias
#   (h)SamrAddMultipleMembersToAlias
#   (h)SamrRemoveMultipleMembersFromAliass
#   (h)SamrRemoveMemberFromForeignDomain
#   (h)SamrGetAliasMembership
#   (h)SamrSetMemberAttributesOfGroup
#   (h)SamrGetUserDomainPasswordInformation
#   (h)SamrGetDomainPasswordInformation
#   (h)SamrRidToSid
#   SamrSetDSRMPassword
#   (h)SamrValidatePassword
#   (h)SamrQuerySecurityObject
#   (h)SamrSetSecurityObject
#   (h)SamrChangePasswordUser
#   SamrOemChangePasswordUser2
#   (h)SamrUnicodeChangePasswordUser2
#   (h)SamrLookupDomainInSamServer
# Not yet
#   SamrCreateUserInDomain
#
import pytest
import unittest
from tests.dcerpc import DCERPCTests

import string
import random
from six import b
from six import assertRaisesRegex

from impacket import crypto
from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5 import dtypes
from impacket import nt_errors, ntlm
from impacket.dcerpc.v5.ndr import NULL


class SAMRTests(DCERPCTests):
    iface_uuid = samr.MSRPC_UUID_SAMR
    authn = True
    authn_level = ntlm.NTLM_AUTH_PKT_INTEGRITY

    server_name_string = "BETO\x00"
    full_name_string = "BETO"
    test_string = "BETUS"
    test_account = "testAccount"
    test_group = "testGroup"

    def get_domain_handle(self, dce):
        request = samr.SamrConnect()
        request['ServerName'] = self.server_name_string
        request['DesiredAccess'] = samr.DELETE | samr.READ_CONTROL | samr.WRITE_DAC | samr.WRITE_OWNER | samr.ACCESS_SYSTEM_SECURITY | samr.GENERIC_READ | samr.GENERIC_WRITE | samr.GENERIC_EXECUTE | samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_SHUTDOWN | samr.SAM_SERVER_INITIALIZE | samr.SAM_SERVER_CREATE_DOMAIN | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN | samr.SAM_SERVER_READ | samr.SAM_SERVER_WRITE | samr.SAM_SERVER_EXECUTE
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        resp2 = dce.request(request)
        request = samr.SamrLookupDomainInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['Name'] = resp2['Buffer']['Buffer'][0]['Name']
        resp3 = dce.request(request)
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] = samr.DOMAIN_READ_PASSWORD_PARAMETERS | samr.DOMAIN_READ_OTHER_PARAMETERS | samr.DOMAIN_CREATE_USER | samr.DOMAIN_CREATE_ALIAS | samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_ADMINISTER_SERVER | samr.DELETE | samr.READ_CONTROL | samr.ACCESS_SYSTEM_SECURITY | samr.DOMAIN_WRITE_OTHER_PARAMETERS | samr.DOMAIN_WRITE_PASSWORD_PARAMS
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)
        return resp4['DomainHandle']

    def test_SamrCloseHandle(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCloseHandle()
        request['SamHandle'] = domainHandle
        resp = dce.request(request)
        resp.dump()

    def test_hSamrCloseHandle(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrCloseHandle(dce, domainHandle)
        resp.dump()

    def test_SamrConnect5(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrConnect5()
        request['ServerName'] = self.server_name_string
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['InVersion'] = 1
        request['InRevisionInfo']['tag'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect5(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrConnect5(dce)
        resp.dump()

    def test_SamrConnect4(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrConnect4()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        request['ClientRevision'] = 2
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect4(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrConnect4(dce)
        resp.dump()

    def test_SamrConnect2(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrConnect2()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect2(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrConnect2(dce)
        resp.dump()

    def test_SamrConnect(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_hSamrConnect(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrConnect(dce)
        resp.dump()

    def test_SamrOpenDomain(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        resp = dce.request(request)
        request = samr.SamrOpenDomain()
        SID = 'S-1-5-352321536-2562177771-1589929855-2033349547'
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['DomainId'].fromCanonical(SID)

        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_NO_SUCH_DOMAIN"):
            dce.request(request)
        
    def test_hSamrOpenDomain(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrConnect(dce)

        SID = 'S-1-5-352321536-2562177771-1589929855-2033349547'
        sid = dtypes.RPC_SID()
        sid.fromCanonical(SID)
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_NO_SUCH_DOMAIN"):
            samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'], domainId=sid)

    def test_SamrOpenGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        
    def test_hSamrOpenGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        try:
            resp = samr.hSamrOpenGroup(dce, domainHandle, groupId=samr.DOMAIN_GROUP_RID_USERS)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

    def test_SamrOpenAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = 25
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_NO_SUCH_ALIAS"):
            dce.request(request)

    def test_hSamrOpenAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_NO_SUCH_ALIAS"):
            samr.hSamrOpenAlias(dce, domainHandle, aliasId=25)

    def test_SamrOpenUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()

    def test_hSamrOpenUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrOpenUser(dce, domainHandle,
                                  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT,
                                  samr.DOMAIN_USER_RID_ADMIN)
        resp.dump()

    def test_SamrEnumerateDomainsInSamServer(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrConnect()
        request['ServerName'] = self.server_name_string
        request['DesiredAccess'] = samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] = 0
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
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)
        resp4.dump()

    def test_hSamrEnumerateDomainsInSamServer(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrConnect(dce, desiredAccess=samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)
        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, resp['ServerHandle'])
        resp2.dump()
        resp3 = samr.hSamrLookupDomainInSamServer(dce, resp['ServerHandle'], resp2['Buffer']['Buffer'][0]['Name'])
        resp3.dump()
        request = samr.SamrOpenDomain()
        request['ServerHandle'] = resp['ServerHandle']
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['DomainId'] = resp3['DomainId']
        resp4 = dce.request(request)
        resp4.dump()

    def test_SamrLookupNamesInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
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
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        try:
            resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, ('Administrator', 'Guest'))
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >= 0:
                pass

    def test_SamrLookupIdsInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
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
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrLookupIdsInDomain(dce, domainHandle, (500, 501))
        resp.dump()

    def test_SamrEnumerateGroupsInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrEnumerateGroupsInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except samr.DCERPCSessionError as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

    def test_hSamrEnumerateGroupsInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
        resp.dump()

    def test_SamrEnumerateAliasesInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except samr.DCERPCSessionError as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

    def test_hSamrEnumerateAliasesInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        resp.dump()

    def test_SamrEnumerateUsersInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrEnumerateUsersInDomain()
        request['DomainHandle'] = domainHandle
        request['UserAccountControl'] = samr.USER_NORMAL_ACCOUNT
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 8192
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except samr.DCERPCSessionError as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

    def test_hSamrEnumerateUsersInDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        try:
            resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                pass
            e.get_packet().dump()

    def test_SamrGetGroupsForUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_LIST_GROUPS
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrGetGroupsForUser()
        request['UserHandle'] = resp['UserHandle'] 
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetGroupsForUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_LIST_GROUPS
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()
        resp = samr.hSamrGetGroupsForUser(dce, resp['UserHandle'])
        resp.dump()

    def test_SamrQueryDisplayInformation3(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrQueryDisplayInformation3()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise

        for display_info_class in [samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup]:
            request = samr.SamrQueryDisplayInformation3()
            request['DomainHandle'] = domainHandle
            request['DisplayInformationClass'] = display_info_class
            request['Index'] = 0
            request['EntryCount'] = 100
            request['PreferredMaximumLength'] = 8192
            resp = dce.request(request)
            resp.dump()

    def test_hSamrQueryDisplayInformation3(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        try:
            resp = samr.hSamrQueryDisplayInformation3(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >=0:
                e.get_packet().dump()
            else:
                raise

        for display_info_class in [samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup]:
            resp = samr.hSamrQueryDisplayInformation3(dce, domainHandle, display_info_class)
            resp.dump()

    def test_SamrQueryDisplayInformation2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        try:
            resp = samr.hSamrQueryDisplayInformation2(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >= 0:
                e.get_packet().dump()
            else:
                raise

        for display_info_class in [samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup]:
            resp = samr.hSamrQueryDisplayInformation2(dce, domainHandle, display_info_class)
            resp.dump()

    def test_SamrQueryDisplayInformation(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrQueryDisplayInformation()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Index'] = 0
        request['EntryCount'] = 100
        request['PreferredMaximumLength'] = 8192
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >= 0:
                e.get_packet().dump()
            else:
                raise

        for display_info_class in [samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup]:
            request = samr.SamrQueryDisplayInformation()
            request['DomainHandle'] = domainHandle
            request['DisplayInformationClass'] = display_info_class
            request['Index'] = 0
            request['EntryCount'] = 100
            request['PreferredMaximumLength'] = 8192
            resp = dce.request(request)
            resp.dump()

    def test_hSamrQueryDisplayInformation(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        try:
            resp = samr.hSamrQueryDisplayInformation(dce, domainHandle,  samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') >= 0:
                e.get_packet().dump()
            else:
                raise

        for display_info_class in [samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayMachine,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup,
                                   samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayOemGroup]:
            resp = samr.hSamrQueryDisplayInformation(dce, domainHandle, display_info_class)
            resp.dump()

    def test_SamrGetDisplayEnumerationIndex2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        for display_info_class, prefix in [(samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, 'Gu'),
                                           (samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup, 'Non')]:
            request = samr.SamrGetDisplayEnumerationIndex2()
            request['DomainHandle'] = domainHandle
            request['DisplayInformationClass'] = display_info_class
            request['Prefix'] = prefix
            resp = dce.request(request)
            resp.dump()

    def test_hSamrGetDisplayEnumerationIndex2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        for display_info_class, prefix in [(samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, 'Gu'),
                                           (samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayGroup, 'Non')]:
            resp = samr.hSamrGetDisplayEnumerationIndex2(dce, domainHandle, display_info_class, prefix)
            resp.dump()

    def test_SamrGetDisplayEnumerationIndex(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrGetDisplayEnumerationIndex(dce, domainHandle, samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser, 'Gu')
        resp.dump()

    def test_hSamrGetDisplayEnumerationIndex(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrGetDisplayEnumerationIndex()
        request['DomainHandle'] = domainHandle
        request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
        request['Prefix'] = 'Gu'
        resp = dce.request(request)
        resp.dump()

    def test_SamrCreateGroupInDomain_SamrDeleteGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateGroupInDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_ACCESS_DENIED"):
            dce.request(request)

        request = samr.SamrDeleteGroup()
        request['GroupHandle'] = domainHandle
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_OBJECT_TYPE_MISMATCH"):
            dce.request(request)

    def test_hSamrCreateGroupInDomain_hSamrDeleteGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_ACCESS_DENIED"):
            samr.hSamrCreateGroupInDomain(dce, domainHandle, self.test_group, samr.GROUP_ALL_ACCESS | samr.DELETE)

        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_OBJECT_TYPE_MISMATCH"):
            samr.hSamrDeleteGroup(dce, domainHandle)

    def test_SamrCreateAliasInDomain_SamrDeleteAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = resp['AliasHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrCreateAliasInDomain_hSamrDeleteAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrCreateAliasInDomain(dce, domainHandle, self.test_group,  samr.GROUP_ALL_ACCESS | samr.DELETE)
        resp.dump()
        resp = samr.hSamrDeleteAlias(dce, resp['AliasHandle'])
        resp.dump()

    def test_SamrCreateUser2InDomain_SamrDeleteUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = self.test_account
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.DELETE
        resp = dce.request(request)
        resp.dump()
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrCreateUser2InDomain_hSamrDeleteUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrCreateUser2InDomain(dce, domainHandle, self.test_account, samr.USER_NORMAL_ACCOUNT,samr.USER_READ_GENERAL | samr.DELETE )
        resp.dump()
        resp = samr.hSamrDeleteUser(dce, resp['UserHandle'])
        resp.dump()

    def test_SamrQueryInformationDomain2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        for domain_info_class in [samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2,
                                  ]:
            request = samr.SamrQueryInformationDomain2()
            request['DomainHandle'] = domainHandle
            request['DomainInformationClass'] = domain_info_class
            resp = dce.request(request)
            resp.dump()

    def test_hSamrQueryInformationDomain2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        for domain_info_class in [samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2,
                                  ]:
            resp = samr.hSamrQueryInformationDomain2(dce, domainHandle, domain_info_class)
            resp.dump()

    def test_hSamrQueryInformationDomain_hSamrSetInformationDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        resp.dump()

        resp['Buffer']['Password']['MaxPasswordAge']['LowPart'] = 11
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()
 
        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        resp2.dump()
        self.assertEqual(11, resp2['Buffer']['Password']['MaxPasswordAge']['LowPart'])

        resp2['Buffer']['Password']['MaxPasswordAge']['LowPart'] = 0
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()
   
        ################################################################################ 
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
        resp.dump()

        resp['Buffer']['General']['ReplicaSourceNodeName'] = self.test_string
        with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_INVALID_INFO_CLASS"):
            samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])

        ################################################################################ 
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
        resp.dump()

        oldData = resp['Buffer']['Logoff']['ForceLogoff']['LowPart'] 

        resp['Buffer']['Logoff']['ForceLogoff']['LowPart'] = 11
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()

        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation)
        resp2.dump()

        self.assertEqual(11, resp2['Buffer']['Logoff']['ForceLogoff']['LowPart'])

        resp2['Buffer']['Logoff']['ForceLogoff']['LowPart'] = oldData
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation)
        resp.dump()

        oldData = resp['Buffer']['Oem']['OemInformation']

        resp['Buffer']['Oem']['OemInformation'] = self.test_string
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()

        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainOemInformation)
        resp2.dump()

        self.assertEqual(self.test_string, resp2['Buffer']['Oem']['OemInformation'])

        resp2['Buffer']['Oem']['OemInformation'] = oldData
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()

        for domain_info_class in [samr.DOMAIN_INFORMATION_CLASS.DomainNameInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainServerRoleInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainStateInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
                                  samr.DOMAIN_INFORMATION_CLASS.DomainModifiedInformation2,
                                  ]:
            resp = samr.hSamrQueryInformationDomain(dce, domainHandle, domain_info_class)
            resp.dump()

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation)
        resp.dump()

        oldData = resp['Buffer']['Replication']['ReplicaSourceNodeName']

        resp['Buffer']['Replication']['ReplicaSourceNodeName'] = self.test_string
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp['Buffer'])
        resp.dump()

        resp2 = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainReplicationInformation)
        resp2.dump()

        self.assertEqual(self.test_string, resp2['Buffer']['Replication']['ReplicaSourceNodeName'])

        resp2['Buffer']['Replication']['ReplicaSourceNodeName'] = oldData
        resp = samr.hSamrSetInformationDomain(dce, domainHandle, resp2['Buffer'])
        resp.dump()

    def test_SamrQueryInformationGroup_SamrSetInformationGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp0 = dce.request(request)
            resp0.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        request = samr.SamrQueryInformationGroup()
        request['GroupHandle'] = resp0['GroupHandle']
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation
        resp = dce.request(request)
        resp.dump()
        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SamrSetInformationGroup()
        req['GroupHandle'] = resp0['GroupHandle']
        req['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        req['Buffer']['tag'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        req['Buffer']['Name']['Name'] = self.test_string
        resp = dce.request(req)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['Name']['Name'])

        req['Buffer']['Name']['Name'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAttributeInformation
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
        resp = dce.request(request)
        resp.dump()
        #self.assertEqual(2, resp['Buffer']['Attribute']['Attributes'])

        req['Buffer']['Attribute']['Attributes'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        resp = dce.request(request)
        resp.dump()

        oldData = resp['Buffer']['AdminComment']['AdminComment']

        req = samr.SamrSetInformationGroup()
        req['GroupHandle'] = resp0['GroupHandle']
        req['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        req['Buffer']['tag'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        req['Buffer']['AdminComment']['AdminComment'] = self.test_string
        resp = dce.request(req)
        resp.dump()

        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupAdminCommentInformation
        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['AdminComment']['AdminComment'])

        req['Buffer']['AdminComment']['AdminComment'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################ 
        request['GroupInformationClass'] = samr.GROUP_INFORMATION_CLASS.GroupReplicationInformation
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQueryInformationGroup_hSamrSetInformationGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        try:
            resp0 = samr.hSamrOpenGroup(dce, domainHandle, samr.GROUP_ALL_ACCESS, samr.DOMAIN_GROUP_RID_USERS)
            resp0.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        resp = samr.hSamrQueryInformationGroup(dce, resp0['GroupHandle'], samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
        resp.dump()
        ################################################################################ 

        resp = samr.hSamrQueryInformationGroup(dce, resp0['GroupHandle'], samr.GROUP_INFORMATION_CLASS.GroupNameInformation)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SAMPR_GROUP_INFO_BUFFER()
        req['tag'] = samr.GROUP_INFORMATION_CLASS.GroupNameInformation
        req['Name']['Name'] = self.test_string
        resp = samr.hSamrSetInformationGroup(dce, resp0['GroupHandle'], req)
        resp.dump()

        resp = samr.hSamrQueryInformationGroup(dce, resp0['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupNameInformation)
        resp.dump()
        self.assertEqual(self.test_string, resp['Buffer']['Name']['Name'])

        req['Name']['Name'] = oldData
        resp = samr.hSamrSetInformationGroup(dce, resp0['GroupHandle'], req)
        resp.dump()

    def test_hSamrQueryInformationAlias_hSamrSetInformationAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        resp4 = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        resp4.dump()

        resp0 = samr.hSamrOpenAlias(dce, domainHandle, aliasId=resp4['Buffer']['Buffer'][0]['RelativeId'])
        resp0.dump()

        resp = samr.hSamrQueryInformationAlias(dce, resp0['AliasHandle'], samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation)
        resp.dump()

        ################################################################################ 
        resp = samr.hSamrQueryInformationAlias(dce, resp0['AliasHandle'], samr.ALIAS_INFORMATION_CLASS.AliasNameInformation)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SAMPR_ALIAS_INFO_BUFFER()
        req['tag'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        req['Name']['Name'] = self.test_string
        resp = samr.hSamrSetInformationAlias(dce, resp0['AliasHandle'], req)
        resp.dump()

        resp = samr.hSamrQueryInformationAlias(dce, resp0['AliasHandle'], samr.ALIAS_INFORMATION_CLASS.AliasNameInformation)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['Name']['Name'])

        req['Name']['Name'] = oldData
        resp = samr.hSamrSetInformationAlias(dce, resp0['AliasHandle'], req)
        resp.dump()

    def test_SamrQueryInformationAlias_SamrSetInformationAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except samr.DCERPCSessionError as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

        resp4.dump()
        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp0 = dce.request(request)
        resp0.dump()

        request = samr.SamrQueryInformationAlias()
        request['AliasHandle'] = resp0['AliasHandle']
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation
        resp = dce.request(request)
        resp.dump()

        ################################################################################ 
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Name']['Name']

        req = samr.SamrSetInformationAlias()
        req['AliasHandle'] = resp0['AliasHandle']
        req['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        req['Buffer']['tag'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        req['Buffer']['Name']['Name'] = self.test_string
        resp = dce.request(req)
        resp.dump()

        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasNameInformation
        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['Name']['Name'])

        req['Buffer']['Name']['Name'] = oldData
        resp = dce.request(req)
        resp.dump()

        ################################################################################
        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['AdminComment']['AdminComment']

        req = samr.SamrSetInformationAlias()
        req['AliasHandle'] = resp0['AliasHandle']
        req['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        req['Buffer']['tag'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        req['Buffer']['AdminComment']['AdminComment'] = self.test_string
        resp = dce.request(req)
        resp.dump()

        request['AliasInformationClass'] = samr.ALIAS_INFORMATION_CLASS.AliasAdminCommentInformation
        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['AdminComment']['AdminComment'])

        req['Buffer']['AdminComment']['AdminComment'] = oldData
        resp = dce.request(req)
        resp.dump()

    def test_SamrQueryInformationUser2_SamrSetInformationUser2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        #request['DesiredAccess'] =  samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_ALL_ACCESS | samr.USER_READ | samr.USER_READ_LOGON 
        request['DesiredAccess'] = \
            samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_WRITE_PREFERENCES | samr.USER_READ_LOGON \
            | samr.USER_READ_ACCOUNT | samr.USER_WRITE_ACCOUNT | samr.USER_CHANGE_PASSWORD | samr.USER_FORCE_PASSWORD_CHANGE  \
            | samr.USER_LIST_GROUPS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION | samr.USER_ALL_ACCESS  \
            | samr.USER_READ | samr.USER_WRITE | samr.USER_EXECUTE

        # Get the user handle for the domain admin user
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationUser2()
        request['UserHandle'] = resp['UserHandle']
        userHandle = resp['UserHandle'] 
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserGeneralInformation
        resp = dce.request(request)
        resp.dump()

        # Set a new user comment and revert it back
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Preferences']['UserComment']

        set_request = samr.SamrSetInformationUser2()
        set_request['UserHandle'] = userHandle
        set_request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        set_request['Buffer'] = resp['Buffer']
        set_request['Buffer']['Preferences']['UserComment'] = self.test_string
        resp = dce.request(set_request)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['Preferences']['UserComment'])

        set_request['Buffer']['Preferences']['UserComment'] = oldData
        resp = dce.request(set_request)
        resp.dump()

        # Get different user info classes
        for user_info_class in [samr.USER_INFORMATION_CLASS.UserLogonInformation,
                                samr.USER_INFORMATION_CLASS.UserLogonHoursInformation,
                                samr.USER_INFORMATION_CLASS.UserAccountInformation,
                                ]:
            request['UserInformationClass'] = user_info_class
            resp = dce.request(request)
            resp.dump()

        # Set a new full name and revert it back
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Name']['FullName']

        set_request = samr.SamrSetInformationUser2()
        set_request['UserHandle'] = userHandle
        set_request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserNameInformation
        set_request['Buffer'] = resp['Buffer']
        set_request['Buffer']['Name']['FullName'] = self.full_name_string
        resp = dce.request(set_request)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.full_name_string, resp['Buffer']['Name']['FullName'])

        set_request['Buffer']['Name']['FullName'] = oldData
        resp = dce.request(set_request)
        resp.dump()

        # Set a new username and revert it back
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        resp = dce.request(request)
        resp.dump()

        oldData = resp['Buffer']['AccountName']['UserName']

        req = samr.SamrSetInformationUser2()
        req['UserHandle'] = userHandle
        req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAccountNameInformation
        req['Buffer'] = resp['Buffer'] 
        req['Buffer']['AccountName']['UserName'] = self.test_string
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['AccountName']['UserName'])

        req['Buffer']['AccountName']['UserName'] = oldData
        resp = dce.request(req)
        resp.dump()

        # Get different user info classes
        for user_info_class in [samr.USER_INFORMATION_CLASS.UserFullNameInformation,
                                samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation,
                                samr.USER_INFORMATION_CLASS.UserHomeInformation,
                                samr.USER_INFORMATION_CLASS.UserScriptInformation,
                                samr.USER_INFORMATION_CLASS.UserProfileInformation,
                                samr.USER_INFORMATION_CLASS.UserAdminCommentInformation,
                                samr.USER_INFORMATION_CLASS.UserWorkStationsInformation,
                                samr.USER_INFORMATION_CLASS.UserControlInformation,
                                samr.USER_INFORMATION_CLASS.UserExpiresInformation,
                                samr.USER_INFORMATION_CLASS.UserParametersInformation,
                                samr.USER_INFORMATION_CLASS.UserAllInformation,
                                ]:
            request['UserInformationClass'] = user_info_class
            resp = dce.request(request)
            resp.dump()

        # Get different user info classes that are internal
        for internal_user_info_class in [samr.USER_INFORMATION_CLASS.UserInternal1Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal4Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal5Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal4InformationNew,
                                         samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
                                         ]:
            request['UserInformationClass'] = internal_user_info_class
            with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_INVALID_INFO_CLASS"):
                dce.request(request)

    def test_hSamrQueryInformationUser2_hSamrSetInformationUser2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        # Get the user handle for the domain admin user
        desiredAccess = \
            samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_WRITE_PREFERENCES | samr.USER_READ_LOGON \
            | samr.USER_READ_ACCOUNT | samr.USER_WRITE_ACCOUNT | samr.USER_CHANGE_PASSWORD | samr.USER_FORCE_PASSWORD_CHANGE  \
            | samr.USER_LIST_GROUPS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION | samr.USER_ALL_ACCESS  \
            | samr.USER_READ | samr.USER_WRITE | samr.USER_EXECUTE
        resp = samr.hSamrOpenUser(dce, domainHandle, desiredAccess, samr.DOMAIN_USER_RID_ADMIN )
        resp.dump()
        userHandle = resp['UserHandle']

        resp = samr.hSamrQueryInformationUser2(dce, userHandle, samr.USER_INFORMATION_CLASS.UserGeneralInformation)
        resp.dump()

        # Set a new user comment and revert it back
        resp = samr.hSamrQueryInformationUser2(dce, userHandle, samr.USER_INFORMATION_CLASS.UserPreferencesInformation)
        resp.dump()
        oldData = resp['Buffer']['Preferences']['UserComment']

        resp['Buffer']['Preferences']['UserComment'] = self.test_string
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle, samr.USER_INFORMATION_CLASS.UserPreferencesInformation)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['Preferences']['UserComment'])

        resp['Buffer']['Preferences']['UserComment'] = oldData
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        # Get different user info classes
        for user_info_class in [samr.USER_INFORMATION_CLASS.UserLogonInformation,
                                samr.USER_INFORMATION_CLASS.UserLogonHoursInformation,
                                samr.USER_INFORMATION_CLASS.UserAccountInformation,
                                ]:
            samr.hSamrQueryInformationUser2(dce, userHandle, user_info_class)

        # Set a new full name and revert it back
        resp = samr.hSamrQueryInformationUser2(dce, userHandle, samr.USER_INFORMATION_CLASS.UserNameInformation)
        resp.dump()
        oldData = resp['Buffer']['Name']['FullName']

        resp['Buffer']['Name']['FullName'] = self.full_name_string
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle,samr.USER_INFORMATION_CLASS.UserNameInformation)
        resp.dump()

        self.assertEqual(self.full_name_string, resp['Buffer']['Name']['FullName'])

        resp['Buffer']['Name']['FullName'] = oldData
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        # Set a new username and revert it back
        resp = samr.hSamrQueryInformationUser2(dce, userHandle, samr.USER_INFORMATION_CLASS.UserAccountNameInformation)
        resp.dump()

        oldData = resp['Buffer']['AccountName']['UserName']

        resp['Buffer']['AccountName']['UserName'] = self.test_string
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        resp = samr.hSamrQueryInformationUser2(dce, userHandle, samr.USER_INFORMATION_CLASS.UserAccountNameInformation)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['AccountName']['UserName'])

        resp['Buffer']['AccountName']['UserName'] = oldData
        resp = samr.hSamrSetInformationUser2(dce, userHandle, resp['Buffer'])
        resp.dump()

        # Get different user info classes
        for user_info_class in [samr.USER_INFORMATION_CLASS.UserFullNameInformation,
                                samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation,
                                samr.USER_INFORMATION_CLASS.UserHomeInformation,
                                samr.USER_INFORMATION_CLASS.UserScriptInformation,
                                samr.USER_INFORMATION_CLASS.UserProfileInformation,
                                samr.USER_INFORMATION_CLASS.UserAdminCommentInformation,
                                samr.USER_INFORMATION_CLASS.UserWorkStationsInformation,
                                samr.USER_INFORMATION_CLASS.UserControlInformation,
                                samr.USER_INFORMATION_CLASS.UserExpiresInformation,
                                samr.USER_INFORMATION_CLASS.UserParametersInformation,
                                samr.USER_INFORMATION_CLASS.UserAllInformation,
                                ]:
            samr.hSamrQueryInformationUser2(dce, userHandle, user_info_class)

        # Get different user info classes that are internal
        for internal_user_info_class in [samr.USER_INFORMATION_CLASS.UserInternal1Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal4Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal5Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal4InformationNew,
                                         samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
                                         ]:
            with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_INVALID_INFO_CLASS"):
                samr.hSamrQueryInformationUser2(dce, userHandle, internal_user_info_class)

    def test_SamrQueryInformationUser_SamrSetInformationUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        # Get the user handle for the domain admin user
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT | samr.USER_ALL_ACCESS | samr.USER_READ
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrQueryInformationUser()
        request['UserHandle'] = resp['UserHandle']
        userHandle = resp['UserHandle']

        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserGeneralInformation
        resp = dce.request(request)
        resp.dump()

        # Set a new user comment and revert it back
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        resp = dce.request(request)
        resp.dump()
        oldData = resp['Buffer']['Preferences']['UserComment']

        req = samr.SamrSetInformationUser()
        req['UserHandle'] = userHandle
        req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
        req['Buffer'] = resp['Buffer'] 
        req['Buffer']['Preferences']['UserComment'] = self.test_string
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        self.assertEqual(self.test_string, resp['Buffer']['Preferences']['UserComment'])

        req['Buffer']['Preferences']['UserComment'] = oldData
        resp = dce.request(req)
        resp.dump()

        # Get different user info classes
        for user_info_class in [samr.USER_INFORMATION_CLASS.UserLogonInformation,
                                samr.USER_INFORMATION_CLASS.UserLogonHoursInformation,
                                samr.USER_INFORMATION_CLASS.UserAccountInformation,
                                samr.USER_INFORMATION_CLASS.UserNameInformation,
                                samr.USER_INFORMATION_CLASS.UserAccountNameInformation,

                                samr.USER_INFORMATION_CLASS.UserFullNameInformation,
                                samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation,
                                samr.USER_INFORMATION_CLASS.UserHomeInformation,
                                samr.USER_INFORMATION_CLASS.UserScriptInformation,
                                samr.USER_INFORMATION_CLASS.UserProfileInformation,
                                samr.USER_INFORMATION_CLASS.UserAdminCommentInformation,
                                samr.USER_INFORMATION_CLASS.UserWorkStationsInformation,
                                samr.USER_INFORMATION_CLASS.UserControlInformation,
                                samr.USER_INFORMATION_CLASS.UserExpiresInformation,
                                samr.USER_INFORMATION_CLASS.UserParametersInformation,
                                samr.USER_INFORMATION_CLASS.UserAllInformation,
                                ]:
            request['UserInformationClass'] = user_info_class
            dce.request(request)

        # Get different user info classes that are internal
        for internal_user_info_class in [samr.USER_INFORMATION_CLASS.UserInternal1Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal4Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal5Information,
                                         samr.USER_INFORMATION_CLASS.UserInternal4InformationNew,
                                         samr.USER_INFORMATION_CLASS.UserInternal5InformationNew
                                         ]:
            request['UserInformationClass'] = internal_user_info_class
            with assertRaisesRegex(self, samr.DCERPCSessionError, "STATUS_INVALID_INFO_CLASS"):
                dce.request(request)

    def test_SamrAddMemberToGroup_SamrRemoveMemberFromGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        resp = dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        request = samr.SamrRemoveMemberFromGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['MemberId'] = samr.DOMAIN_USER_RID_ADMIN
        try:
            resp2 = dce.request(request)
            resp2.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MEMBERS_PRIMARY_GROUP') < 0:
                raise
        request = samr.SamrAddMemberToGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['MemberId'] = samr.DOMAIN_USER_RID_ADMIN
        request['Attributes'] = samr.SE_GROUP_ENABLED_BY_DEFAULT
        try:
            resp2 = dce.request(request)
            resp2.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MEMBER_IN_GROUP') < 0:
                raise

    def test_hSamrAddMemberToGroup_hSamrRemoveMemberFromGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        resp = dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        try:
            resp2 = samr.hSamrRemoveMemberFromGroup(dce, resp['GroupHandle'], samr.DOMAIN_USER_RID_ADMIN)
            resp2.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MEMBERS_PRIMARY_GROUP') < 0:
                raise
        try:
            resp2 = samr.hSamrAddMemberToGroup(dce, resp['GroupHandle'], samr.DOMAIN_USER_RID_ADMIN, samr.SE_GROUP_ENABLED_BY_DEFAULT)
            resp2.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MEMBER_IN_GROUP') < 0:
                raise

    def test_SamrGetMembersInGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        request = samr.SamrGetMembersInGroup()
        request['GroupHandle'] = resp['GroupHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetMembersInGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

        resp = samr.hSamrGetMembersInGroup(dce, resp['GroupHandle'])
        resp.dump()

    def test_SamrGetMembersInAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except samr.DCERPCSessionError as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrGetMembersInAlias()
        request['AliasHandle'] = resp['AliasHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetMembersInAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrEnumerateAliasesInDomain()
        request['DomainHandle'] = domainHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        status = nt_errors.STATUS_MORE_ENTRIES
        while status == nt_errors.STATUS_MORE_ENTRIES:
            try:
                resp4 = dce.request(request)
            except samr.DCERPCSessionError as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    raise 
                resp4 = e.get_packet()
            resp4['Buffer'].dump()
            request['EnumerationContext'] = resp4['EnumerationContext'] 
            status = resp4['ErrorCode']

        request = samr.SamrOpenAlias()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['AliasId'] = resp4['Buffer']['Buffer'][0]['RelativeId']
        resp = dce.request(request)
        resp.dump()

        resp = samr.hSamrGetMembersInAlias(dce, resp['AliasHandle'])
        resp.dump()

    def test_SamrAddMemberToAlias_SamrRemoveMemberFromAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE

        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        dce.request(request)

    def test_hSamrAddMemberToAlias_hSamrRemoveMemberFromAlias(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrCreateAliasInDomain(dce, domainHandle, self.test_group,  samr.GROUP_ALL_ACCESS | samr.DELETE)
        resp.dump()
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE

        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        dce.request(request)

    def test_hSamrAddMultipleMembersToAlias_hSamrRemoveMultipleMembersFromAliass(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        #resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        #resp = samr.hSamrOpenAlias(dce, domainHandle, samr.DELETE, 1257)
        #resp = samr.hSamrDeleteAlias(dce, resp['AliasHandle'])
        resp = samr.hSamrCreateAliasInDomain(dce, domainHandle, self.test_group, samr.GROUP_ALL_ACCESS | samr.DELETE)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        dce.request(request)

    def test_SamrRemoveMemberFromForeignDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE

        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_SPECIAL_ACCOUNT') < 0:
                raise

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        dce.request(request)

    def test_hSamrRemoveMemberFromForeignDomain(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE

        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
        resp3 = dce.request(request)
        resp3.dump()

        # Let's extract the SID and remove the RID from one entry
        sp = resp3['Sid'].formatCanonical()
        domainID = '-'.join(sp.split('-')[:-1])
        adminSID = domainID + '-%d' % samr.DOMAIN_USER_RID_ADMIN
        sid = samr.RPC_SID()
        sid.fromCanonical(adminSID)
        try:
            resp = samr.hSamrRemoveMemberFromForeignDomain(dce, domainHandle, sid)
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_SPECIAL_ACCOUNT') < 0:
                raise

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        dce.request(request)

    def test_SamrGetAliasMembership(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE

        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        dce.request(request)

    def test_hSamrGetAliasMembership(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        #resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        #resp = samr.hSamrOpenAlias(dce, domainHandle, samr.DELETE, 1268)
        #resp = samr.hSamrDeleteAlias(dce, resp['AliasHandle'])

        request = samr.SamrCreateAliasInDomain()
        request['DomainHandle'] = domainHandle
        request['AccountName'] = self.test_group
        request['DesiredAccess'] = samr.GROUP_ALL_ACCESS | samr.DELETE

        resp = dce.request(request)
        aliasHandle = resp['AliasHandle']
        relativeId = resp['RelativeId']
        resp.dump()

        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = relativeId
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
        except Exception:
            request = samr.SamrDeleteAlias()
            request['AliasHandle'] = aliasHandle
            dce.request(request)
            raise

        request = samr.SamrDeleteAlias()
        request['AliasHandle'] = aliasHandle
        dce.request(request)

    def test_SamrSetMemberAttributesOfGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        resp = dce.request(request)

        request = samr.SamrSetMemberAttributesOfGroup()
        request['GroupHandle'] = resp['GroupHandle']
        request['MemberId'] = samr.DOMAIN_USER_RID_ADMIN
        request['Attributes'] = samr.SE_GROUP_ENABLED_BY_DEFAULT
        resp = dce.request(request)
        resp.dump()

    def test_hSamrSetMemberAttributesOfGroup(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrConnect()
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['ServerName'] = self.server_name_string
        dce.request(request)
        request = samr.SamrOpenGroup()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED
        request['GroupId'] = samr.DOMAIN_GROUP_RID_USERS
        resp = dce.request(request)

        resp = samr.hSamrSetMemberAttributesOfGroup(dce, resp['GroupHandle'], samr.DOMAIN_USER_RID_ADMIN, samr.SE_GROUP_ENABLED_BY_DEFAULT)
        resp.dump()

    def test_SamrGetUserDomainPasswordInformation(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)

        request = samr.SamrGetUserDomainPasswordInformation()
        request['UserHandle'] = resp['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetUserDomainPasswordInformation(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.USER_READ_GENERAL | samr.USER_READ_PREFERENCES | samr.USER_READ_ACCOUNT
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        resp = dce.request(request)

        resp = samr.hSamrGetUserDomainPasswordInformation(dce, resp['UserHandle'])
        resp.dump()

    def test_SamrGetDomainPasswordInformation(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrGetDomainPasswordInformation()
        request['Unused'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hSamrGetDomainPasswordInformation(self):
        dce, rpc_transport = self.connect()
        resp = samr.hSamrGetDomainPasswordInformation(dce)
        resp.dump()

    def test_SamrRidToSid(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrRidToSid()
        request['ObjectHandle'] = domainHandle
        request['Rid'] = samr.DOMAIN_USER_RID_ADMIN
        dce.request(request)

    def test_hSamrRidToSid(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrRidToSid(dce, domainHandle, samr.DOMAIN_USER_RID_ADMIN)
        resp.dump()

    def test_SamrSetDSRMPassword(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrSetDSRMPassword()
        request['Unused'] = NULL
        request['UserId'] = samr.DOMAIN_USER_RID_ADMIN
        request['EncryptedNtOwfPassword'] = '\x00'*16
        # calls made to SamrSetDSRMPassword using NCACN_IP_TCP are rejected with RPC_S_ACCESS_DENIED.
        try:
            dce.request(request)
        except Exception as e:
            if self.protocol == 'ncacn_ip_tcp':
                if str(e).find('rpc_s_access_denied') < 0:
                    raise
            elif str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_SamrValidatePassword(self):
        dce, rpc_transport = self.connect()
        request = samr.SamrValidatePassword()
        request['ValidationType'] = samr.PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset
        request['InputArg']['tag'] = samr.PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset
        request['InputArg']['ValidatePasswordResetInput']['InputPersistedFields']['PresentFields'] = samr.SAM_VALIDATE_PASSWORD_HISTORY
        request['InputArg']['ValidatePasswordResetInput']['InputPersistedFields']['PasswordHistory'] = NULL
        request['InputArg']['ValidatePasswordResetInput']['ClearPassword'] = 'AAAAAAAAAAAAAAAA'
        request['InputArg']['ValidatePasswordResetInput']['UserAccountName'] = 'Administrator'
        kk = samr.SamrValidatePassword()
        kk.fromString(request.getData())
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_hSamrValidatePassword(self):
        dce, rpc_transport = self.connect()
        inputArg = samr.SAM_VALIDATE_INPUT_ARG()
        inputArg['tag'] = samr.PASSWORD_POLICY_VALIDATION_TYPE.SamValidatePasswordReset
        inputArg['ValidatePasswordResetInput']['InputPersistedFields']['PresentFields'] = samr.SAM_VALIDATE_PASSWORD_HISTORY
        inputArg['ValidatePasswordResetInput']['InputPersistedFields']['PasswordHistory'] = NULL
        inputArg['ValidatePasswordResetInput']['ClearPassword'] = 'AAAAAAAAAAAAAAAA'
        inputArg['ValidatePasswordResetInput']['UserAccountName'] = 'Administrator'
        try:
            resp = samr.hSamrValidatePassword(dce, inputArg)
            resp.dump()
        except Exception as e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_SamrQuerySecurityObject(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        request = samr.SamrQuerySecurityObject()
        request['ObjectHandle'] = domainHandle
        request['SecurityInformation'] = dtypes.OWNER_SECURITY_INFORMATION | dtypes.GROUP_SECURITY_INFORMATION | dtypes.SACL_SECURITY_INFORMATION | dtypes.DACL_SECURITY_INFORMATION
        resp = dce.request(request)
        resp.dump()

    def test_hSamrQuerySecurityObject(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        resp = samr.hSamrQuerySecurityObject(dce, domainHandle,
                                             dtypes.OWNER_SECURITY_INFORMATION | dtypes.GROUP_SECURITY_INFORMATION | dtypes.SACL_SECURITY_INFORMATION | dtypes.DACL_SECURITY_INFORMATION)
        resp.dump()

    def test_SamrSetSecurityObject(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.username,))
        resp.dump()

        resp = samr.hSamrOpenUser(dce, domainHandle, samr.USER_ALL_ACCESS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION, resp['RelativeIds']['Element'][0]['Data'])
        resp.dump()
        userHandle = resp['UserHandle']
        request = samr.SamrQuerySecurityObject()
        request['ObjectHandle'] = userHandle
        request['SecurityInformation'] = dtypes.GROUP_SECURITY_INFORMATION
        resp = dce.request(request)
        resp.dump()

        request = samr.SamrSetSecurityObject()
        request['ObjectHandle'] = userHandle
        request['SecurityInformation'] = dtypes.GROUP_SECURITY_INFORMATION
        request['SecurityDescriptor'] = resp['SecurityDescriptor'] 

        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_BAD_DESCRIPTOR_FORMAT') <= 0:
                raise

        resp = samr.hSamrCloseHandle(dce, userHandle)
        resp.dump()

    def test_hSamrSetSecurityObject(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.username,))
        resp.dump()

        resp = samr.hSamrOpenUser(dce, domainHandle, samr.USER_ALL_ACCESS | samr.USER_READ_GROUP_INFORMATION | samr.USER_WRITE_GROUP_INFORMATION, resp['RelativeIds']['Element'][0]['Data'])
        resp.dump()
        userHandle = resp['UserHandle']
        resp = samr.hSamrQuerySecurityObject(dce, userHandle, dtypes.GROUP_SECURITY_INFORMATION)
        resp.dump()

        try:
            resp = samr.hSamrSetSecurityObject(dce, userHandle, dtypes.GROUP_SECURITY_INFORMATION,resp['SecurityDescriptor']  )
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_BAD_DESCRIPTOR_FORMAT') <= 0:
                raise

        resp = samr.hSamrCloseHandle(dce, userHandle)
        resp.dump()

    def test_SamrChangePasswordUser(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = self.test_account
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE

        resp0 = dce.request(request)
        resp0.dump()

        oldPwd = ''
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

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
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = self.test_account
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE

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
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)
        # As you can guess by now, target machine must have the Administrator account with password admin
        # NOTE: It's giving me WRONG_PASSWORD  'cause the target test server doesn't hold LM Hashes
        # further testing is needed to verify this call works
        oldPwd = 'admin'
        oldPwdHashLM = ntlm.LMOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        request = samr.SamrOemChangePasswordUser2()
        request['ServerName'] = ''
        request['UserName'] = 'Administrator'
        samUser = samr.SAMPR_USER_PASSWORD()
        samUser['Buffer'] = b'A'*(512-len(newPwd)) + b(newPwd)
        samUser['Length'] = len(newPwd)
        pwdBuff = samUser.getData()

        rc4 = ARC4.new(oldPwdHashLM)
        encBuf = rc4.encrypt(pwdBuff)
        request['NewPasswordEncryptedWithOldLm']['Buffer'] = encBuf
        request['OldLmOwfPasswordEncryptedWithNewLm'] = crypto.SamEncryptNTLMHash(oldPwdHashLM, newPwdHashLM)
        try:
            resp = dce.request(request)
            resp.dump()
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_WRONG_PASSWORD') < 0:
                raise

    def test_SamrUnicodeChangePasswordUser2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = self.test_account
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE

        resp0 = dce.request(request)
        resp0.dump()

        oldPwd = ''
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

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
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = "".join([random.choice(string.ascii_letters) for i in range(15)])
        newPwdHashNT = ntlm.NTOWFv1(newPwd)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        request = samr.SamrUnicodeChangePasswordUser2()
        request['ServerName'] = ''
        request['UserName'] = self.test_account
        samUser = samr.SAMPR_USER_PASSWORD()
        samUser['Buffer'] = b'A'*(512-len(newPwd)*2) + newPwd.encode('utf-16le')
        samUser['Length'] = len(newPwd)*2
        pwdBuff = samUser.getData()

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
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_PASSWORD_RESTRICTION') < 0:
                raise

        # Delete the temp user
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp0['UserHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hSamrUnicodeChangePasswordUser2(self):
        dce, rpc_transport = self.connect()
        domainHandle = self.get_domain_handle(dce)

        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = domainHandle
        request['Name'] = self.test_account
        request['AccountType'] = samr.USER_NORMAL_ACCOUNT
        request['DesiredAccess'] = dtypes.MAXIMUM_ALLOWED | samr.USER_READ_GENERAL | samr.DELETE

        resp0 = dce.request(request)
        resp0.dump()

        oldPwd = ''
        oldPwdHashNT = ntlm.NTOWFv1(oldPwd)
        newPwd = 'ADMIN'
        newPwdHashNT = ntlm.NTOWFv1(newPwd)
        newPwdHashLM = ntlm.LMOWFv1(newPwd)

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
            resp = samr.hSamrUnicodeChangePasswordUser2(dce, '', self.test_account, 'ADMIN', 'betus')
            resp.dump()
        except Exception as e:
            if str(e).find('STATUS_PASSWORD_RESTRICTION') < 0:
                raise

        # Delete the temp user
        request = samr.SamrDeleteUser()
        request['UserHandle'] = resp0['UserHandle']
        resp = dce.request(request)
        resp.dump()


@pytest.mark.remote
class SAMRTestsSMBTransport(SAMRTests, unittest.TestCase):
    protocol = "ncacn_np"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


@pytest.mark.remote
class SAMRTestsSMBTransport64(SAMRTests, unittest.TestCase):
    protocol = "ncacn_np"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


@pytest.mark.remote
class SAMRTestsTCPTransport(SAMRTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


@pytest.mark.remote
class SAMRTestsTCPTransport64(SAMRTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
