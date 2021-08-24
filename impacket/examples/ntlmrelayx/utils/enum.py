# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
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
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED


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
