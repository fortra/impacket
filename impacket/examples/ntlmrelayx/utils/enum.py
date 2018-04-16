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
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import SID_NAME_USE


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
        resp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        aliases = {}
        for alias in resp['Buffer']['Buffer']:
            aliases[alias['Name']] =  alias['RelativeId']
        resp = samr.hSamrOpenAlias(dce, domainHandle, desiredAccess=MAXIMUM_ALLOWED, aliasId=aliases['Administrators'])
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
        resp = lsat.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
        resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        names = []
        for n, item in enumerate(resp['TranslatedNames']['Names']):
            names.append("{}\\{}".format(resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name']))
        dce.disconnect()
        return names

class RidCycle:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__lsaBinding = r'ncacn_np:445[\pipe\lsarpc]'

    def __getDceBinding(self, strBinding):
        rpc = transport.DCERPCTransportFactory(strBinding)
        rpc.set_smb_connection(self.__smbConnection)
        return rpc.get_dce_rpc()

    def getDomainSIDs(self, maxRid):
        dce = self.__getDceBinding(self.__lsaBinding)
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsat.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        domainSid =  resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()

        #Code basically lifted from lookupsid.py
        entries = []
        soFar = 0
        SIMULTANEOUS = 1000
        for j in range(maxRid/SIMULTANEOUS+1):
            if (maxRid - soFar) / SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else: 
                sidsToCheck = SIMULTANEOUS
 
            if sidsToCheck == 0:
                break

            sids = list()
            for i in xrange(soFar, soFar+sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException, e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else: 
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    sid = "{}-{}".format(domainSid, soFar+n)
                    domain =  resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
                    name =  item['Name']
                    sidtype =  SID_NAME_USE.enumItems(item['Use']).name
                    entries.append("{},{}\\{},{}".format(sid, domain, name, sidtype))
            soFar += SIMULTANEOUS
        
        dce.disconnect()
        return entries





