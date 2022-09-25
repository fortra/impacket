# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)NetrJobEnum
#   (h)NetrJobAdd
#   (h)NetrJobDel
#   (h)NetrJobGetInfo
#   (h)SASetAccountInformation
#   (h)SASetNSAccountInformation
#   (h)SAGetNSAccountInformation
#   (h)SAGetAccountInformation
#   (h)SchRpcHighestVersion
#   (h)SchRpcRetrieveTask
#   (h)SchRpcCreateFolder
#   (h)SchRpcDelete
#   (h)SchRpcEnumFolders
#   (h)SchRpcEnumTasks
#   (h)SchRpcEnumInstances
#   (h)SchRpcRun
#   (h)SchRpcGetInstanceInfo
#   (h)SchRpcStopInstance
#   (h)SchRpcStop
#   (h)SchRpcRename
#   (h)SchRpcScheduledRuntimes
#   (h)SchRpcGetLastRunInfo
#   (h)SchRpcGetTaskInfo
#   (h)SchRpcGetNumberOfMissedRuns
#   (h)SchRpcEnableTask
#
# Not yet:
#   SchRpcRegisterTask
#   SchRpcSetSecurity
#   SchRpcGetSecurity
#
from __future__ import division
from __future__ import print_function

import pytest
import unittest
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import tsch, atsvc, sasec
from impacket.dcerpc.v5.atsvc import AT_INFO
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.system_errors import ERROR_NOT_SUPPORTED


class ATSVCTests(DCERPCTests):
    iface_uuid = atsvc.MSRPC_UUID_ATSVC
    string_binding = r"ncacn_np:{0.machine}[\PIPE\atsvc]"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_NetrJobEnum(self):
        dce, rpc_transport = self.connect()
        request = atsvc.NetrJobEnum()
        request['ServerName'] = NULL
        request['pEnumContainer']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

    def test_hNetrJobEnum(self):
        dce, rpc_transport = self.connect()
        try:
            resp = atsvc.hNetrJobEnum(dce, NULL, NULL, 0xffffffff)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

    def test_hNetrJobAdd_hNetrJobEnum_hNetrJobDel(self):
        dce, rpc_transport = self.connect()
        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
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
        dce, rpc_transport = self.connect()
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
        except atsvc.DCERPCSessionError as e:
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
        dce, rpc_transport = self.connect()
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
        except atsvc.DCERPCSessionError as e:
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
        dce, rpc_transport = self.connect()
        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

        resp2 = atsvc.hNetrJobGetInfo(dce, NULL, resp['pJobId'])
        resp2.dump()

        resp = atsvc.hNetrJobDel(dce, NULL, resp['pJobId'], resp['pJobId'])
        resp.dump()


class SASECTests(DCERPCTests):
    iface_uuid = sasec.MSRPC_UUID_SASEC
    string_binding = r"ncacn_np:{0.machine}[\PIPE\atsvc]"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_SASetAccountInformation(self):
        dce, rpc_transport = self.connect()
        request = sasec.SASetAccountInformation()
        request['Handle'] = NULL
        request['pwszJobName'] = 'MyJob.job\x00'
        request['pwszAccount'] = self.username + '\0'
        request['pwszPassword'] = self.password + '\0'
        request['dwJobFlags'] = sasec.TASK_FLAG_RUN_ONLY_IF_LOGGED_ON
        try:
            resp = dce.request(request)
            resp.dump()
        except sasec.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_hSASetAccountInformation(self):
        dce, rpc_transport = self.connect()
        try:
            resp = sasec.hSASetAccountInformation(dce, NULL, 'MyJob.job', self.username, self.password, 0)
            resp.dump()
        except sasec.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_SASetNSAccountInformation(self):
        dce, rpc_transport = self.connect()
        request = sasec.SASetNSAccountInformation()
        request['Handle'] = NULL
        request['pwszAccount'] = self.username + '\0'
        request['pwszPassword'] = self.password + '\0'
        resp = dce.request(request)
        resp.dump()

    def test_hSASetNSAccountInformation(self):
        dce, rpc_transport = self.connect()
        resp = sasec.hSASetNSAccountInformation(dce, NULL, self.username, self.password)
        resp.dump()

    def test_SAGetNSAccountInformation(self):
        dce, rpc_transport = self.connect()
        request = sasec.SAGetNSAccountInformation()
        request['Handle'] = NULL
        request['ccBufferSize'] = 25
        for i in range(request['ccBufferSize']):
            request['wszBuffer'].append(0)
        resp = dce.request(request)
        resp.dump()

    def test_hSAGetNSAccountInformation(self):
        dce, rpc_transport = self.connect()
        resp = sasec.hSAGetNSAccountInformation(dce, NULL, 25)
        resp.dump()

    def test_SAGetAccountInformation(self):
        dce, rpc_transport = self.connect()
        request = sasec.SAGetAccountInformation()
        request['Handle'] = NULL
        request['pwszJobName'] = 'MyJob.job\x00'
        request['ccBufferSize'] = 15
        for i in range(request['ccBufferSize']):
            request['wszBuffer'].append(0)
        try:
            resp = dce.request(request)
            resp.dump()
        except sasec.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_hSAGetAccountInformation(self):
        dce, rpc_transport = self.connect()
        try:
            resp = sasec.hSAGetAccountInformation(dce, NULL, 'MyJob.job', 15)
            resp.dump()
        except sasec.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise


class TSCHTests(DCERPCTests):
    iface_uuid = tsch.MSRPC_UUID_TSCHS
    string_binding = r"ncacn_np:{0.machine}[\PIPE\atsvc]"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_SchRpcHighestVersion(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcHighestVersion()
        resp = dce.request(request)
        resp.dump()

    def test_hSchRpcHighestVersion(self):
        dce, rpc_transport = self.connect()
        resp = tsch.hSchRpcHighestVersion(dce)
        resp.dump()

    @pytest.mark.skip(reason="Disabled test")
    def test_SchRpcRegisterTask(self):
        dce, rpc_transport = self.connect()
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
        request['path'] = NULL
        request['xml'] = xml
        request['flags'] = 1
        request['sddl'] = NULL
        request['logonType'] = tsch.TASK_LOGON_NONE
        request['cCreds'] = 0
        request['pCreds'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_SchRpcRetrieveTask(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
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
        except tsch.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcRetrieveTask(self):
        dce, rpc_transport = self.connect()
        try:
            resp = tsch.hSchRpcRetrieveTask(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00')
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

    def test_SchRpcCreateFolder_SchRpcEnumFolders_SchRpcDelete(self):
        dce, rpc_transport = self.connect()

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
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        request = tsch.SchRpcDelete()
        request['path'] = '\\Beto\x00'
        request['flags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hSchRpcCreateFolder_hSchRpcEnumFolders_hSchRpcDelete(self):
        dce, rpc_transport = self.connect()

        resp = tsch.hSchRpcCreateFolder(dce, '\\Beto')
        resp.dump()

        resp = tsch.hSchRpcEnumFolders(dce, '\\')
        resp.dump()

        resp = tsch.hSchRpcDelete(dce, '\\Beto')
        resp.dump()

    def test_SchRpcEnumTasks(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
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

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcEnumTasks(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        resp = tsch.hSchRpcEnumTasks(dce, '\\')
        resp.dump()

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcEnumInstances(self):
        dce, rpc_transport = self.connect()

        request = tsch.SchRpcEnumInstances()
        request['path'] = '\\\x00'
        request['flags'] = tsch.TASK_ENUM_HIDDEN
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_hSchRpcEnumInstances(self):
        dce, rpc_transport = self.connect()
        try:
            resp = tsch.hSchRpcEnumInstances(dce, '\\')
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if e.get_error_code() != 0x80070002:
                raise

    def test_SchRpcRun(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        request = tsch.SchRpcRun()
        request['path'] = '\\At%d\x00' % jobId
        request['cArgs'] = 0
        request['pArgs'] = NULL
        request['flags'] = tsch.TASK_RUN_AS_SELF
        request['sessionId'] = 0
        request['user'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcRun(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcGetInstanceInfo(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        request = tsch.SchRpcGetInstanceInfo()
        request['guid'] = resp['pGuid']
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcGetInstanceInfo(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        try:
            resp = tsch.hSchRpcGetInstanceInfo(dce, resp['pGuid'])
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcStopInstance(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        request = tsch.SchRpcStopInstance()
        request['guid'] = resp['pGuid']
        request['flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcStopInstance(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcRun(dce, '\\At%d\x00' % jobId, ('arg0','arg1'))
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

        try:
            resp = tsch.hSchRpcStopInstance(dce, resp['pGuid'])
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('SCHED_E_TASK_NOT_RUNNING') <= 0:
                raise
            pass

        try:
            resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return

    def test_SchRpcStop(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
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
        except tsch.DCERPCSessionError as e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTION') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_hSchRpcStop(self):
        dce, rpc_transport = self.connect()
        dce_2, rpc_transport_2 = self.connect(iface_uuid=atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C vssadmin > %%SYSTEMROOT%%\\Temp\\ANI 2>&1\x00'

        try:
            resp = atsvc.hNetrJobAdd(dce_2, NULL, atInfo)
            resp.dump()
        except atsvc.DCERPCSessionError as e:
            if e.get_error_code() != ERROR_NOT_SUPPORTED:
                raise
            else:
                # OpNum not supported, aborting test
                return
        jobId = resp['pJobId']

        try:
            resp = tsch.hSchRpcStop(dce, '\\At%d\x00' % jobId)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTION') <= 0:
                raise
            pass

        resp = atsvc.hNetrJobDel(dce_2, NULL, jobId, jobId)
        resp.dump()

    def test_SchRpcRename(self):
        dce, rpc_transport = self.connect()
        resp = tsch.hSchRpcCreateFolder(dce, '\\Beto')
        resp.dump()

        request = tsch.SchRpcRename()
        request['path'] = '\\Beto\x00'
        request['newName'] = '\\Anita\x00'
        request['flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('E_NOTIMPL') <= 0:
                raise
            pass

        resp = tsch.hSchRpcDelete(dce, '\\Beto')
        resp.dump()

    def test_hSchRpcRename(self):
        dce, rpc_transport = self.connect()
        resp = tsch.hSchRpcCreateFolder(dce, '\\Beto')
        resp.dump()

        try:
            resp = tsch.hSchRpcRename(dce, '\\Beto', '\\Anita')
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('E_NOTIMPL') <= 0:
                raise
            pass

        resp = tsch.hSchRpcDelete(dce, '\\Beto')
        resp.dump()

    def test_SchRpcScheduledRuntimes(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcScheduledRuntimes()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['start'] = NULL
        request['end'] = NULL
        request['flags'] = 0
        request['cRequested'] = 10
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTIO') <= 0 and str(e).find('SCHED_S_TASK_NOT_SCHEDULED') < 0:
                raise
            e.get_packet().dump()
            pass

    def test_hSchRpcScheduledRuntimes(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcScheduledRuntimes()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['start'] = NULL
        request['end'] = NULL
        request['flags'] = 0
        request['cRequested'] = 10
        try:
            resp = tsch.hSchRpcScheduledRuntimes(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', NULL, NULL, 0, 10)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            # It is actually S_FALSE
            if str(e).find('ERROR_INVALID_FUNCTIO') <= 0 and str(e).find('SCHED_S_TASK_NOT_SCHEDULED') < 0:
                raise
            e.get_packet().dump()
            pass

    def test_SchRpcGetLastRunInfo(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcGetLastRunInfo()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('SCHED_S_TASK_HAS_NOT_RUN') <= 0:
                raise
            pass

    def test_hSchRpcGetLastRunInfo(self):
        dce, rpc_transport = self.connect()
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag')
            resp.dump()
        except tsch.DCERPCSessionError as e:
            if str(e).find('SCHED_S_TASK_HAS_NOT_RUN') <= 0:
                raise
            pass

    def test_SchRpcGetTaskInfo(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcGetTaskInfo()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['flags'] = tsch.SCH_FLAG_STATE
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

    def test_hSchRpcGetTaskInfo(self):
        dce, rpc_transport = self.connect()
        try:
            resp = tsch.hSchRpcGetTaskInfo(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', tsch.SCH_FLAG_STATE)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

    def test_SchRpcGetNumberOfMissedRuns(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcGetNumberOfMissedRuns()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

    def test_hSchRpcGetNumberOfMissedRuns(self):
        dce, rpc_transport = self.connect()
        try:
            resp = tsch.hSchRpcGetNumberOfMissedRuns(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag')
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

    def test_SchRpcEnableTask(self):
        dce, rpc_transport = self.connect()
        request = tsch.SchRpcEnableTask()
        request['path'] = '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\x00'
        request['enabled'] = 1
        try:
            resp = dce.request(request)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass

    def test_hSchRpcEnableTask(self):
        dce, rpc_transport = self.connect()
        try:
            resp = tsch.hSchRpcEnableTask(dce, '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', True)
            resp.dump()
        except tsch.DCERPCSessionError as e:
            print(e)
            pass


@pytest.mark.remote
class ATSVCTestsSMBTransport(ATSVCTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class ATSVCTestsSMBTransport64(ATSVCTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class SASECTestsSMBTransport(SASECTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class SASECTestsSMBTransport64(SASECTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


@pytest.mark.remote
class TSCHTestsSMBTransport(TSCHTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class TSCHTestsSMBTransport64(TSCHTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
