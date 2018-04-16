# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Config utilities
#
# Author:
#  Ronnie Flathers / @ropnop
#
# Description:
#     Helpful enum methods for discovering local admins through SAMR and LSAT
# and performin a RID cycle attack through LSAT

from impacket.dcerpc.v5 import transport, lsat, lsad, samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

class EnumLocalAdmins:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__samrBinding = r'ncacn_np:445[\pipe\samr]'
        self.__lsatBinding = r'ncacn_np:445[\pipe\lsarpc]'

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
        resp = samr.hSamrConnect(dce_samr)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrLookupDomainInSamServer(dce_samr, serverHandle, 'Builtin')
        resp = samr.hSamrOpenDomain(dce_samr, serverHandle=serverHandle, domainId=resp['DomainId'])
        domainHandle = resp['DomainHandle']
        resp = samr.hSamrEnumerateAliasesInDomain(dce_samr, domainHandle)
        aliases = {}
        for alias in resp['Buffer']['Buffer']:
            aliases[alias['Name']] =  alias['RelativeId']
        resp = samr.hSamrOpenAlias(dce_samr, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=aliases['Administrators'])
        resp = samr.hSamrGetMembersInAlias(dce_samr, resp['AliasHandle'])
        memberSids = []
        for member in resp['Members']['Sids']:
            memberSids.append(member['SidPointer'].formatCanonical())
        return memberSids

    def __resolveSids(self, sids):
        dce = self.__getDceBinding(self.__lsatBinding)
        dce.connect()
        dce_lsa.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsat.hLsarOpenPolicy2(dce_lsa, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
        resp = lsat.hLsarLookupSids(dce_lsa, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        names = []
        for translatedNames in resp['TranslatedNames']['Names']:
            names.append(translatedNames['Name'])
        return names

class RidCycle:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection




