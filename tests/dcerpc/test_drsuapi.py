# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   DRSBind
#   (h)DRSDomainControllerInfo
#   (h)DRSCrackNames
#   DRSGetNT4ChangeLog
#   DRSVerifyName
#   DRSGetNCChanges
# Not yet:
#   DRSUnBind
#
from __future__ import division
from __future__ import print_function
import pytest
import unittest
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import drsuapi
from impacket.dcerpc.v5.dtypes import NULL, LPWSTR
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class DRSRTests(DCERPCTests):
    iface_uuid = drsuapi.MSRPC_UUID_DRSUAPI
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    string_binding = r"ncacn_np:{0.machine}[\PIPE\lsass]"

    def bind(self, dce):
        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = drsuapi.DRS_EXT_RECYCLE_BIN
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0
        request['pextClient']['cb'] = len(drs.getData())
        request['pextClient']['rgb'] = list(drs.getData())
        resp = dce.request(request)

        # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
        # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
        ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
            len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt['dwReplEpoch'] != 0:
            # Different epoch, we have to call DRSBind again
            drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
            request['pextClient']['cb'] = len(drs.getData())
            request['pextClient']['rgb'] = list(drs.getData())
            resp = dce.request(request)

        resp2 = drsuapi.hDRSDomainControllerInfo(dce,  resp['phDrs'], self.domain, 2)
        return resp['phDrs'], resp2['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']

    def test_DRSBind(self):
        dce, rpc_transport = self.connect()

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) - 4
        drs['dwFlags'] = 0
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0x1234
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = drsuapi.DRS_EXT_RECYCLE_BIN
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(drs.getData())
        resp = dce.request(request)
        resp.dump()

        extension = drsuapi.DRS_EXTENSIONS_INT(b'\x00'*4 + b''.join(resp['ppextServer']['rgb'])+b'\x00'*4)
        extension.dump()

    def test_DRSDomainControllerInfo(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        request = drsuapi.DRSDomainControllerInfo()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['Domain'] = self.domain + '\x00'
        request['pmsgIn']['V1']['InfoLevel'] = 1

        resp = dce.request(request)
        resp.dump()

        request['pmsgIn']['V1']['InfoLevel'] = 2
        resp = dce.request(request)
        resp.dump()

        request['pmsgIn']['V1']['InfoLevel'] = 3
        resp = dce.request(request)
        resp.dump()

        request['pmsgIn']['V1']['InfoLevel'] = 0xffffffff
        resp = dce.request(request)
        resp.dump()

    def test_hDRSDomainControllerInfo(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 1)
        resp.dump()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 2)
        resp.dump()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 3)
        resp.dump()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 0xffffffff)
        resp.dump()

    def test_DRSCrackNames(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        request = drsuapi.DRSCrackNames()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['CodePage'] = 0
        request['pmsgIn']['V1']['LocaleId'] = 0
        request['pmsgIn']['V1']['dwFlags'] = 0
        request['pmsgIn']['V1']['formatOffered'] = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
        request['pmsgIn']['V1']['formatDesired'] = drsuapi.DS_USER_PRINCIPAL_NAME_FOR_LOGON
        request['pmsgIn']['V1']['cNames'] = 1
        name = LPWSTR()
        #name['Data'] = 'FREEFLY-DC\x00'
        #name['Data'] = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET\x00'
        #name['Data'] = 'CN=FREEFLY-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET\x00'
        name['Data'] = 'Administrator\x00'
        request['pmsgIn']['V1']['rpNames'].append(name)

        resp = dce.request(request)
        resp.dump()

    def test_hDRSCrackNames(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        name = 'Administrator'
        formatOffered = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
        formatDesired = drsuapi.DS_STRING_SID_NAME

        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, formatOffered, formatDesired, (name,))
        resp.dump()

        name = 'CN=NTDS Settings,CN=DC1-WIN2012,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=%s,DC=%s' % (self.domain.split('.')[0],self.domain.split('.')[1])
        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME, (name,))
        resp.dump()

        name = 'CN=NTDS Settings,CN=DC1-WIN2012,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=%s,DC=%s' % (self.domain.split('.')[0],self.domain.split('.')[1])
        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, drsuapi.DS_STRING_SID_NAME, (name,))
        resp.dump()

        name = self.domain.upper()
        #name = ''
        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, drsuapi.DS_LIST_ROLES, drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, (name,))
        resp.dump()

    def test_DRSGetNT4ChangeLog(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        request = drsuapi.DRSGetNT4ChangeLog()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['dwFlags'] = drsuapi.DRS_NT4_CHGLOG_GET_CHANGE_LOG | drsuapi.DRS_NT4_CHGLOG_GET_SERIAL_NUMBERS
        request['pmsgIn']['V1']['PreferredMaximumLength'] = 0x4000
        request['pmsgIn']['V1']['cbRestart'] = 0
        request['pmsgIn']['V1']['pRestart'] = NULL

        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if str(e).find('ERROR_NOT_SUPPORTED') <0:
                raise

    def test_DRSVerifyNames(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        request = drsuapi.DRSVerifyNames()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['dwFlags'] = drsuapi.DRS_VERIFY_DSNAMES
        request['pmsgIn']['V1']['cNames'] = 1
        request['pmsgIn']['V1']['PrefixTable']['pPrefixEntry'] = NULL

        dsName = drsuapi.PDSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''
        name = 'DC=%s,DC=%s' % (self.domain.split('.')[0], self.domain.split('.')[1])

        dsName['NameLen'] = len(name)
        dsName['StringName'] = (name + '\x00')
        dsName['structLen'] = len(dsName.getDataReferent())-4

        request['pmsgIn']['V1']['rpNames'].append(dsName)

        resp = dce.request(request)
        resp.dump()

    @pytest.mark.xfail
    def test_DRSGetNCChanges(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = DsaObjDest
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = DsaObjDest
        #request['pmsgIn']['V8']['pNC'] = NULL

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''
        name = 'DC=%s,DC=%s' % (self.domain.split('.')[0], self.domain.split('.')[1])
        dsName['NameLen'] = len(name)
        dsName['StringName'] = (name + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V8']['pNC'] = dsName

        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_PER_SYNC  #| drsuapi.DRS_CRITICAL_ONLY
        request['pmsgIn']['V8']['cMaxObjects'] = 100
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ | drsuapi.EXOP_REPL_SECRETS

        prefixTable = []
        oid1 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.656') # principalName
        oid2 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.221') #'sAMAccountName'
        oid3 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.90') # 'unicodePwd'
        oid4 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.94') # ntPwdHistory
        oid5 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.160') # lmPwdHistory
        oid6 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.125') # supplementalCreds
        oid7 = drsuapi.MakeAttid(prefixTable, '1.2.840.113556.1.4.146') # objectSid

        request['pmsgIn']['V8']['pPartialAttrSet']['dwVersion'] = 1
        request['pmsgIn']['V8']['pPartialAttrSet']['cAttrs'] = 7
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid1)
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid2)
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid3)
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid4)
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid5)
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid6)
        request['pmsgIn']['V8']['pPartialAttrSet']['rgPartialAttr'].append(oid7)
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(prefixTable)
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = prefixTable

        resp = dce.request(request)
        resp.dump()

        #moreData = 1
        #while moreData > 0:
        #    thisObject = resp['pmsgOut']['V6']['pObjects']
        #    done = False
        #    while not done:
        #        nextObject = thisObject['pNextEntInf']
        #        thisObject['pNextEntInf'] = NULL
        #        thisObject.dump()
        #        print thisObject['Entinf']['pName']['StringName']
        #        thisObject = nextObject
        #        if nextObject == '':
        #            done = True
        #    request['pmsgIn']['V8']['uuidInvocIdSrc'] = resp['pmsgOut']['V6']['uuidInvocIdSrc']
        #    request['pmsgIn']['V8']['usnvecFrom'] = resp['pmsgOut']['V6']['usnvecTo']
        #    resp = dce.request(request)
        #    moreData = resp['pmsgOut']['V6']['fMoreData']
        #print "OBJECTS ", resp['pmsgOut']['V6']['cNumObjects']

    def getMoreData(self, dce, request, resp):
        while resp['pmsgOut']['V6']['fMoreData'] > 0:
            #thisObject = resp['pmsgOut']['V6']['pObjects']
            #done = False
            #while not done:
            #    nextObject = thisObject['pNextEntInf']
            #    thisObject['pNextEntInf'] = NULL
                #thisObject.dump()
                #print '\n'
                #print thisObject['Entinf']['pName']['StringName']
            #    thisObject = nextObject
            #    if nextObject == '':
            #        done = True

            request['pmsgIn']['V10']['uuidInvocIdSrc'] = resp['pmsgOut']['V6']
            request['pmsgIn']['V10']['usnvecFrom'] = resp['pmsgOut']['V6']['usnvecTo']
            resp = dce.request(request)
            resp.dump()
            print('\n')

    @pytest.mark.xfail
    def test_DRSGetNCChanges2(self):
        dce, rpc_transport = self.connect()
        hDrs, DsaObjDest = self.bind(dce)

        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 10

        request['pmsgIn']['tag'] =10
        request['pmsgIn']['V10']['uuidDsaObjDest'] = DsaObjDest
        request['pmsgIn']['V10']['uuidInvocIdSrc'] = drsuapi.NULLGUID
        #request['pmsgIn']['V10']['pNC'] = NULL

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''

        name = 'CN=Schema,CN=Configuration,DC=%s,DC=%s' % (self.domain.split('.')[0], self.domain.split('.')[1])
        dsName['NameLen'] = len(name)
        dsName['StringName'] = (name + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V10']['pNC'] = dsName

        request['pmsgIn']['V10']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V10']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V10']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V10']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_PER_SYNC  | drsuapi.DRS_WRIT_REP | drsuapi.DRS_FULL_SYNC_NOW
        request['pmsgIn']['V10']['cMaxObjects'] = 100
        request['pmsgIn']['V10']['cMaxBytes'] = 0
        request['pmsgIn']['V10']['ulExtendedOp'] = 0
        request['pmsgIn']['V10']['pPartialAttrSet'] = NULL
        request['pmsgIn']['V10']['pPartialAttrSetEx1'] = NULL
        request['pmsgIn']['V10']['PrefixTableDest']['pPrefixEntry'] = NULL
        #request['pmsgIn']['V10']['ulMoreFlags'] = 0
        resp = dce.request(request)
        print(resp['pmsgOut']['V6']['pNC']['StringName'])
        resp.dump()
        print('\n')
        self.getMoreData(dce, request, resp)

        dsName = drsuapi.DSNAME(isNDR64=request._isNDR64)
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''

        name = 'DC=%s,DC=%s' % (self.domain.split('.')[0], self.domain.split('.')[1])
        dsName['NameLen'] = len(name)
        dsName['StringName'] = (name + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V10']['pNC'] = dsName
        resp = dce.request(request)
        print(resp['pmsgOut']['V6']['pNC']['StringName'])
        resp.dump()
        print('\n')
        self.getMoreData(dce, request, resp)

        dsName = drsuapi.DSNAME(isNDR64=request._isNDR64)
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''

        name = 'CN=Configuration,DC=%s,DC=%s' % (self.domain.split('.')[0],self.domain.split('.')[1])
        dsName['NameLen'] = len(name)
        dsName['StringName'] = (name + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V10']['pNC'] = dsName
        resp = dce.request(request)
        print(resp['pmsgOut']['V6']['pNC']['StringName'])
        resp.dump()
        print('\n')
        self.getMoreData(dce, request, resp)

        #while resp['pmsgOut']['V6']['fMoreData'] > 0:
        #    thisObject = resp['pmsgOut']['V6']['pObjects']
        #    done = False
        #    while not done:
        #        nextObject = thisObject['pNextEntInf']
        #        thisObject['pNextEntInf'] = NULL
        #        #thisObject.dump()
        #        #print '\n'
        #        #print thisObject['Entinf']['pName']['StringName']
        #        thisObject = nextObject
        #        if nextObject == '':
        #            done = True
#
#            print "B"*80
#            request['pmsgIn']['V10']['uuidInvocIdSrc'] = resp['pmsgOut']['V6']
#            request['pmsgIn']['V10']['usnvecFrom'] = resp['pmsgOut']['V6']['usnvecTo']
#            resp = dce.request(request)


@pytest.mark.remote
class DRSRTestsSMBTransport(DRSRTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DRSRTestsSMBTransport64(DRSRTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class DRSRTestsTCPTransport(DRSRTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


@pytest.mark.remote
class DRSRTestsTCPTransport64(DRSRTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
