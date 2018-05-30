###############################################################################
#  Tested so far: 
#
# NetrJobEnum
# NetrJobAdd
# NetrJobDel
# NetrJobGetInfo
# hNetrJobEnum
# hNetrJobAdd
# hNetrJobDel
# hNetrJobGetInfo
# SASetAccountInformation
# hSASetAccountInformation
# SASetNSAccountInformation
# hSASetNSAccountInformation
# SAGetNSAccountInformation
# hSAGetNSAccountInformation
# SAGetAccountInformation
# hSAGetAccountInformation
# SchRpcHighestVersion
# hSchRpcHighestVersion
# SchRpcRetrieveTask
# hSchRpcRetrieveTask
# SchRpcCreateFolder
# hSchRpcCreateFolder
# SchRpcDelete
# hSchRpcDelete
# SchRpcEnumFolders
# hSchRpcEnumFolders
# SchRpcEnumTasks
# hSchRpcEnumTasks
# SchRpcEnumInstances
# hSchRpcEnumInstances
# SchRpcRun
# hSchRpcRun
# SchRpcGetInstanceInfo
# hSchRpcGetInstanceInfo
# SchRpcStopInstance
# hSchRpcStopInstance
# SchRpcStop
# hSchRpcStop
# SchRpcRename
# hSchRpcRename
# SchRpcScheduledRuntimes
# hSchRpcScheduledRuntimes
# SchRpcGetLastRunInfo
# hSchRpcGetLastRunInfo
# SchRpcGetTaskInfo
# hSchRpcGetTaskInfo
# SchRpcGetNumberOfMissedRuns
# hSchRpcGetNumberOfMissedRuns
# SchRpcEnableTask
# hSchRpcEnableTask
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import tsch, atsvc, sasec
from impacket.dcerpc.v5.atsvc import AT_INFO
from impacket.dcerpc.v5.dtypes import NULL, LPWSTR
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.system_errors import ERROR_NOT_SUPPORTED


class TSCHTests(unittest.TestCase):
    def connect(self, stringBinding, bindUUID):
        rpctransport = transport.DCERPCTransportFactory(stringBinding )
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(bindUUID, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_NetrJobEnum(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        request = atsvc.NetrJobEnum()
        request['ServerName'] = NULL
        request['pEnumContainer']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

    def test_hNetrJobEnum(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        try:
            resp = atsvc.hNetrJobEnum(dce, NULL, NULL, 0xffffffff)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

    def test_hNetrJobAdd_hNetrJobEnum_hNetrJobDel(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

        resp = atsvc.hNetrJobEnum(dce)
        resp.dump()

        for job in resp['pEnumContainer']['Buffer']:
            resp = atsvc.hNetrJobDel(dce, NULL, job['JobId'], job['JobId'] )
            resp.dump()

    def test_NetrJobAdd_NetrJobEnum_NetrJobDel(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        request = atsvc.NetrJobAdd()
        request['ServerName'] = NULL
        request['pAtInfo']['JobTime'] = NULL
        request['pAtInfo']['DaysOfMonth'] = 0
        request['pAtInfo']['DaysOfWeek'] = 0
        request['pAtInfo']['Flags'] = 0
        request['pAtInfo']['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

        request = atsvc.NetrJobEnum()
        request['ServerName'] = NULL
        request['pEnumContainer']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        resp.dump()

        for job in resp['pEnumContainer']['Buffer']:
            request = atsvc.NetrJobDel()
            request['ServerName'] = NULL
            request['MinJobId'] = job['JobId']
            request['MaxJobId'] = job['JobId']
            resp = dce.request(request)
            resp.dump()

    def test_NetrJobAdd_NetrJobGetInfo_NetrJobDel(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        request = atsvc.NetrJobAdd()
        request['ServerName'] = NULL
        request['pAtInfo']['JobTime'] = NULL
        request['pAtInfo']['DaysOfMonth'] = 0
        request['pAtInfo']['DaysOfWeek'] = 0
        request['pAtInfo']['Flags'] = 0
        request['pAtInfo']['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

        request = atsvc.NetrJobGetInfo()
        request['ServerName'] = NULL
        request['JobId'] = resp['pJobId']
        resp2 = dce.request(request)
        resp2.dump()

        request = atsvc.NetrJobDel()
        request['ServerName'] = NULL
        request['MinJobId'] = resp['pJobId']
        request['MaxJobId'] = resp['pJobId']
        resp = dce.request(request)
        resp.dump()

    def test_hNetrJobAdd_hNetrJobGetInfo_hNetrJobDel(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

        resp2 = atsvc.hNetrJobGetInfo(dce, NULL, resp['pJobId'])
        resp2.dump()

        resp = atsvc.hNetrJobDel(dce, NULL, resp['pJobId'], resp['pJobId'])
        resp.dump()

    def test_SASetAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        request = sasec.SASetAccountInformation()
        request['Handle'] = NULL
        request['pwszJobName'] = 'MyJob.job\x00'
        request['pwszAccount'] = self.username + '\0'
        request['pwszPassword'] = self.password + '\0'
        request['dwJobFlags'] = sasec.TASK_FLAG_RUN_ONLY_IF_LOGGED_ON
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_hSASetAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        try:
            resp = sasec.hSASetAccountInformation(dce, NULL, 'MyJob.job', self.username, self.password, 0)
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_SASetNSAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        request = sasec.SASetNSAccountInformation()
        request['Handle'] = NULL
        request['pwszAccount'] = self.username + '\0'
        request['pwszPassword'] = self.password + '\0'
        resp = dce.request(request)
        resp.dump()

    def test_hSASetNSAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        resp = sasec.hSASetNSAccountInformation(dce, NULL, self.username, self.password)
        resp.dump()

    def test_SAGetNSAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        request = sasec.SAGetNSAccountInformation()
        request['Handle'] = NULL
        request['ccBufferSize'] = 25
        for i in range(request['ccBufferSize'] ):
            request['wszBuffer'].append(0)
        resp = dce.request(request)
        resp.dump()

    def test_hSAGetNSAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        resp = sasec.hSAGetNSAccountInformation(dce, NULL, 25)
        resp.dump()

    def test_SAGetAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        request = sasec.SAGetAccountInformation()
        request['Handle'] = NULL
        request['pwszJobName'] = 'MyJob.job\x00'
        request['ccBufferSize'] = 15
        for i in range(request['ccBufferSize'] ):
            request['wszBuffer'].append(0)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_hSAGetAccountInformation(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, sasec.MSRPC_UUID_SASEC)

        try:
            resp = sasec.hSAGetAccountInformation(dce, NULL, 'MyJob.job', 15)
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_SchRpcHighestVersion(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcHighestVersion()
        resp = dce.request(request)
        resp.dump()

    def test_hSchRpcHighestVersion(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        resp = tsch.hSchRpcHighestVersion(dce)
        resp.dump()

    def tes_SchRpcRegisterTask(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        xml = """
<!-- Task -->
<xs:complexType name="taskType">
<xs:all>
<xs:element name="RegistrationInfo" type="registrationInfoType" minOccurs="0"/>
<xs:element name="Triggers" type="triggersType" minOccurs="0"/>
<xs:element name="Settings" type="settingsType" minOccurs="0"/>
<xs:element name="Data" type="dataType" minOccurs="0"/>
<xs:element name="Principals" type="principalsType" minOccurs="0"/>
<xs:element name="Actions" type="actionsType"/>
</xs:all>
<xs:attribute name="version" type="versionType" use="optional"/> </xs:complexType>\x00
"""
        request = tsch.SchRpcRegisterTask()
        request['path'] =NULL
        request['xml'] = xml
        request['flags'] = 1
        request['sddl'] = NULL
        request['logonType'] = tsch.TASK_LOGON_NONE
        request['cCreds'] = 0
        request['pCreds'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_SchRpcRetrieveTask(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        request = tsch.SchRpcRetrieveTask()
        request['path'] = '\\At%d.job\x00' % jobId
        request['lpcwszLanguagesBuffer'] = '\x00'
        request['pulNumLanguages'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcRetrieveTask(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        try:
            resp = tsch.hSchRpcRetrieveTask(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00')
            resp.dump()
        except Exception, e:
            print e
            pass

    def test_SchRpcCreateFolder_SchRpcEnumFolders_SchRpcDelete(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcCreateFolder()
        request['path'] = '\\Beto\x00'
        request['sddl'] = NULL
        request['flags'] = 0
        resp = dce.request(request)
        resp.dump()

        request = tsch.SchRpcEnumFolders()
        request['path'] = '\\\x00'
        request['flags'] = tsch.TASK_ENUM_HIDDEN
        request['startIndex'] = 0
        request['cRequested'] = 10
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            print e
            pass

        request = tsch.SchRpcDelete()
        request['path'] = '\\Beto\x00'
        request['flags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hSchRpcCreateFolder_hSchRpcEnumFolders_hSchRpcDelete(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        resp = tsch.hSchRpcCreateFolder(dce, '\\Beto')
        resp.dump()

        resp = tsch.hSchRpcEnumFolders(dce, '\\')
        resp.dump()

        resp = tsch.hSchRpcDelete(dce, '\\Beto')
        resp.dump()

    def test_SchRpcEnumTasks(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        request = tsch.SchRpcEnumTasks()
        request['path'] = '\\\x00'
        request['flags'] = tsch.TASK_ENUM_HIDDEN
        request['startIndex'] = 0
        request['cRequested'] = 10
        resp = dce.request(request)
        resp.dump()

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcEnumTasks(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        resp = tsch.hSchRpcEnumTasks(dce, '\\')
        resp.dump()

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcEnumInstances(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcEnumInstances()
        request['path'] = '\\\x00'
        request['flags'] = tsch.TASK_ENUM_HIDDEN
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_hSchRpcEnumInstances(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        try:
            resp = tsch.hSchRpcEnumInstances(dce, '\\')
            resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_SchRpcRun(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        request = tsch.SchRpcRun()
        request['path'] = '\\At%d\x00' % jobId
        #request['cArgs'] = 2
        #arg0 = LPWSTR()
        #arg0['Data'] = 'arg0\x00'
        #arg1 = LPWSTR()
        #arg1['Data'] = 'arg1\x00'
        #request['pArgs'].append(arg0)
        #request['pArgs'].append(arg1)
        request['cArgs'] = 0
        request['pArgs'] = NULL
        request['flags'] = tsch.TASK_RUN_AS_SELF
        request['sessionId'] = 0
        request['user'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            print e
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcRun(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except Exception, e:
            print e
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcGetInstanceInfo(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except Exception, e:
            print e
            pass

        request = tsch.SchRpcGetInstanceInfo()
        request['guid'] = resp['pGuid']
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcGetInstanceInfo(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except Exception, e:
            print e
            pass

        try:
            resp = tsch.hSchRpcGetInstanceInfo(dce, resp['pGuid'])
            resp.dump()
        except Exception, e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcStopInstance(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except Exception, e:
            print e
            pass

        request = tsch.SchRpcStopInstance()
        request['guid'] = resp['pGuid']
        request['flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcStopInstance(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except Exception, e:
            print e
            pass

        try:
            resp = tsch.hSchRpcStopInstance(dce, resp['pGuid'])
            resp.dump()
        except Exception, e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        try:
            resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

    def test_SchRpcStop(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        request = tsch.SchRpcStop()
        request['path'] = '\\At%d\x00' % jobId
        request['flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTION') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcStop(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        dce2, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce2, NULL, atInfo)
            resp.dump()
        except Exception as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcStop(dce, '\\At%d\x00' % jobId)
            resp.dump()
        except Exception, e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTION') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcRename(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        resp = tsch.hSchRpcCreateFolder(dce, '\\Beto')
        resp.dump()

        request = tsch.SchRpcRename()
        request['path'] = '\\Beto\x00'
        request['newName'] = '\\Anita\x00'
        request['flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('E_NOTIMPL') <= 0:
                raise
            pass

        resp = tsch.hSchRpcDelete(dce, '\\Beto')
        resp.dump()

    def test_hSchRpcRename(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        resp = tsch.hSchRpcCreateFolder(dce, '\\Beto')
        resp.dump()

        try:
            resp = tsch.hSchRpcRename(dce, '\\Beto', '\\Anita')
            resp.dump()
        except Exception, e:
            if str(e).find('E_NOTIMPL') <= 0:
                raise
            pass

        resp = tsch.hSchRpcDelete(dce, '\\Beto')
        resp.dump()

    def test_SchRpcScheduledRuntimes(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        request = tsch.SchRpcScheduledRuntimes()
        #request['path'] = '\\BBB\\Beto Task\x00'
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['start'] = NULL
        request['end'] = NULL
        request['flags'] = 0
        request['cRequested'] = 10
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTIO') <= 0 and str(e).find('SCHED_S_TASK_NOT_SCHEDULED') < 0:
                raise
            e.get_packet().dump()
            pass

    def test_hSchRpcScheduledRuntimes(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcScheduledRuntimes()
        #request['path'] = '\\BBB\\Beto Task\x00'
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['start'] = NULL
        request['end'] = NULL
        request['flags'] = 0
        request['cRequested'] = 10
        try:
            resp = tsch.hSchRpcScheduledRuntimes(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', NULL, NULL, 0, 10)
            resp.dump()
        except Exception, e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTIO') <= 0 and str(e).find('SCHED_S_TASK_NOT_SCHEDULED') < 0:
                raise
            e.get_packet().dump()
            pass

    def test_SchRpcGetLastRunInfo(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        request = tsch.SchRpcGetLastRunInfo()
        #request['path'] = '\\BBB\\Beto Task\x00'
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('SCHED_S_TASK_HAS_NOT_RUN') <= 0:
                raise
            pass

    def test_hSchRpcGetLastRunInfo(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag')
            resp.dump()
        except Exception, e:
            if str(e).find('SCHED_S_TASK_HAS_NOT_RUN') <= 0:
                raise
            pass

    def test_SchRpcGetTaskInfo(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        request = tsch.SchRpcGetTaskInfo()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['flags'] = tsch.SCH_FLAG_STATE
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            print e
            pass

    def test_hSchRpcGetTaskInfo(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        try:
            resp = tsch.hSchRpcGetTaskInfo(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', tsch.SCH_FLAG_STATE)
            resp.dump()
        except Exception, e:
            print e
            pass

    def test_SchRpcGetNumberOfMissedRuns(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        request = tsch.SchRpcGetNumberOfMissedRuns()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            print e
            pass

    def test_hSchRpcGetNumberOfMissedRuns(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        try:
            resp = tsch.hSchRpcGetNumberOfMissedRuns(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag')
            resp.dump()
        except Exception, e:
            print e
            pass

    def test_SchRpcEnableTask(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        request = tsch.SchRpcEnableTask()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['enabled'] = 1
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            print e
            pass

    def test_hSchRpcEnableTask(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)
        try:
            resp = tsch.hSchRpcEnableTask(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', True)
            resp.dump()
        except Exception, e:
            print e
            pass

class SMBTransport(TSCHTests):
    def setUp(self):
        TSCHTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBindingAtSvc = r'ncacn_np:%s[\PIPE\atsvc]' % self.machine
        self.stringBindingAtSvc = r'ncacn_np:%s[\PIPE\atsvc]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(TSCHTests):
    def setUp(self):
        TSCHTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')

        self.stringBindingAtSvc = r'ncacn_np:%s[\PIPE\atsvc]' % self.machine
        self.stringBindingAtSvc = r'ncacn_np:%s[\PIPE\atsvc]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
