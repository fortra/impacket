# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Config utilities
#
#   Helpful enum methods for discovering local admins through SAMR and LSAT
#
# Author:
#   Ronnie Flathers / @ropnop
#
from impacket.dcerpc.v5 import transport, lsat, samr, lsad
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException

class EnumLocalAdmins:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'

    def __getDceBinding(self, strBinding):
        rpc = transport.DCERPCTransportFactory(strBinding)
        rpc.set_smb_connection(self.__smbConnection)
        return rpc.get_dce_rpc()

    def getLocalAdmins(self):
        adminSids = self.__getLocalAdminSids()
        adminNames = self.__resolveSids(adminSids)
        return adminSids, adminNames

    def __getLocalAdminSids(self):
        dce = self.__getDceBinding(self.__samrBinding)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, 'Builtin')
        resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
        domainHandle = resp['DomainHandle']
        resp = samr.hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=544)
        resp = samr.hSamrGetMembersInAlias(dce, resp['AliasHandle'])
        memberSids = []
        for member in resp['Members']['Sids']:
            memberSids.append(member['SidPointer'].formatCanonical())
        dce.disconnect()
        return memberSids

    def __resolveSids(self, sids):
        dce = self.__getDceBinding(self.__lsaBinding)
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
        resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        names = []
        for n, item in enumerate(resp['TranslatedNames']['Names']):
            names.append("{}\\{}".format(resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name']))
        dce.disconnect()
        return names

class EnumDomain:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'

    def enumerateDomain(self):
        domainUsers = self.__getDomainUsers()
        return domainUsers

    def __getDomainUsers(self):
        
        rpc = transport.DCERPCTransportFactory(self.__lsaBinding)
        rpc.set_smb_connection(self.__smbConnection)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        resp2 = lsad.hLsarQueryInformationPolicy2(dce, resp['PolicyHandle'],lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        domainSid = resp2['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
        resolved_rids = []
        maxRidBruteforce = 50000
        batchSize = 5000
        
        for count in range(int(maxRidBruteforce / batchSize + 1)):
            step = count*batchSize
            if step == maxRidBruteforce:
                break
            sids = list()
            for i in range(step, step + batchSize):
                sids.append('%s-%d' % (domainSid,i))
            try:
                lsat.hLsarLookupSids(dce, resp['PolicyHandle'], sids)
            except DCERPCException as e:
                if 'STATUS_NONE_MAPPED' in str(e):
                    continue
                elif 'STATUS_SOME_NOT_MAPPED' in str(e):
                    resp3 = e.get_packet()
                else:
                    break

            for index, user in enumerate(resp3['TranslatedNames']['Names']):
                if user['Use'] != SID_NAME_USE.SidTypeUnknown:
                    resolved_rids.append((('%s-%d' % (domainSid,count + index)), resp3['ReferencedDomains']['Domains'][user['DomainIndex']]['Name'], user['Name'],
                        SID_NAME_USE.enumItems(user['Use']).name))

        dce.disconnect()
        return resolved_rids