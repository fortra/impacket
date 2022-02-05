# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)NetrConnectionEnum
#   (h)NetrFileEnum
#   (h)NetrFileGetInfo
#   (h)NetrFileClose
#   (h)NetrSessionEnum
#   (h)NetrSessionDel
#   (h)NetrShareAdd
#   (h)NetrShareDel
#   (h)NetrShareEnum
#   (h)NetrShareEnumSticky
#   (h)NetrShareGetInfo
#   (h)NetrShareDelSticky
#   (h)NetrShareDelStart
#   (h)NetrShareDelCommit
#   (h)NetrShareCheck
#   (h)NetrServerGetInfo
#   (h)NetrServerDiskEnum
#   (h)NetrServerStatisticsGet
#   (h)NetrRemoteTOD
#   (h)NetrServerTransportEnum
#   (h)NetrpGetFileSecurity
#   (h)NetrpSetFileSecurity
#   (h)NetprPathType
#   (h)NetprPathCanonicalize
#   (h)NetprPathCompare
#   (h)NetprNameValidate
#   (h)NetprNameCanonicalize
#   (h)NetprNameCompare
#   (h)NetrDfsGetVersion
#   (h)NetrDfsModifyPrefix
#   (h)NetrDfsFixLocalVolume
#   (h)NetrDfsManagerReportSiteInfo
#   (h)NetrServerAliasAdd
#   (h)NetrServerAliasEnum
#   (h)NetrServerAliasDel
#   NetrShareDelEx
#   NetrServerTransportAdd
#   NetrServerTransportDel
#   NetrServerTransportAddEx
#   NetrServerTransportDelEx
#   NetrDfsCreateLocalPartition
#   NetrDfsDeleteLocalPartition
#   NetrDfsSetLocalVolumeState
#   NetrDfsCreateExitPoint
#   NetrDfsDeleteExitPoint
#   NetrShareSetInfo
#
# Not yet:
#   NetrServerSetInfo
#
from __future__ import division
from __future__ import print_function

import pytest
import unittest
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.dtypes import NULL, OWNER_SECURITY_INFORMATION


class SRVSTests(DCERPCTests):
    iface_uuid = srvs.MSRPC_UUID_SRVS
    string_binding = r"ncacn_np:{0.machine}[\PIPE\srvsvc]"
    authn = True

    def test_NetrConnectionEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrConnectionEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['Qualifier'] = 'IPC$\x00'
        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['ConnectInfo']['tag'] = 1
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['ConnectInfo']['tag'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hNetrConnectionEnum(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrConnectionEnum(dce, 'IPC$\x00', 1)
        resp.dump()

        resp = srvs.hNetrConnectionEnum(dce, 'IPC$\x00', 0)
        resp.dump()

    def test_NetrFileEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        resp.dump()
        request['InfoStruct']['Level'] = 3
        request['InfoStruct']['FileInfo']['tag'] = 3
        resp = dce.request(request)
        resp.dump()

    def test_hNetrFileEnum(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrFileEnum(dce, NULL, NULL, 2)
        resp.dump()

        resp = srvs.hNetrFileEnum(dce, NULL, NULL, 3)
        resp.dump()

    def test_NetrFileGetInfo(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrFileGetInfo()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['FileId'] = resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id']
        request['Level'] = 2
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 3
        resp = dce.request(request)
        resp.dump()

    def test_hNetrFileGetInfo(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrFileEnum(dce, NULL, NULL, 2)
        resp.dump()

        resp0 = srvs.hNetrFileGetInfo(dce, resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id'], 2)
        resp0.dump()

        resp = srvs.hNetrFileGetInfo(dce, resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id'], 3)
        resp.dump()

    def test_NetrFileClose(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrFileClose()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['FileId'] = resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id']
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception as e:
            # I might be closing myself ;)
            if str(e).find('STATUS_PIPE_BROKEN') < 0 and str(e).find('STATUS_FILE_CLOSED') < 0 and str(e).find('STATUS_INVALID_HANDLE') < 0 and str(e).find('0x90a') < 0:
                raise

    def test_hNetrFileClose(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrFileEnum(dce, NULL, NULL, 2)
        resp.dump()

        try:
            resp = srvs.hNetrFileClose(dce, resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id'])
            resp.dump()
        except Exception as e:
            # I might be closing myself ;)
            if str(e).find('STATUS_PIPE_BROKEN') < 0 and str(e).find('STATUS_FILE_CLOSED') < 0 and str(e).find('STATUS_INVALID_HANDLE') < 0 and str(e).find('0x90a') < 0:
                raise

    def test_NetrSessionEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrSessionEnum()
        request['ServerName'] = NULL
        request['ClientName'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['SessionInfo']['tag'] = 0
        request['InfoStruct']['SessionInfo']['Level0']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['SessionInfo']['tag'] = 1
        request['InfoStruct']['SessionInfo']['Level1']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['SessionInfo']['tag'] = 2
        request['InfoStruct']['SessionInfo']['Level2']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 10
        request['InfoStruct']['SessionInfo']['tag'] = 10
        request['InfoStruct']['SessionInfo']['Level10']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 502
        request['InfoStruct']['SessionInfo']['tag'] = 502
        request['InfoStruct']['SessionInfo']['Level502']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hNetrSessionEnum(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 0)
        resp.dump()

        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 1)
        resp.dump()

        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 2)
        resp.dump()

        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        resp.dump()

        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 502)
        resp.dump()

    def test_NetrSessionDel(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrSessionEnum()
        request['ServerName'] = NULL
        request['ClientName'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 502
        request['InfoStruct']['SessionInfo']['tag'] = 502
        request['InfoStruct']['SessionInfo']['Level502']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrSessionDel()
        request['ServerName'] = NULL
        request['ClientName'] = resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_cname']
        request['UserName'] = resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_username']
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if e.get_error_code() != 0x908:
                raise

    def test_hNetrSessionDel(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 502)
        resp.dump()

        try:
            resp = srvs.hNetrSessionDel(dce, resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_cname'], resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_username'] )
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if e.get_error_code() != 0x908:
                raise

    def test_NetrShareAdd_NetrShareDel(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareAdd()
        request['ServerName'] = NULL
        request['Level'] = 2
        request['InfoStruct']['tag'] = 2
        request['InfoStruct']['ShareInfo2']['shi2_netname'] = 'BETUSHARE\x00'
        request['InfoStruct']['ShareInfo2']['shi2_type'] = srvs.STYPE_TEMPORARY
        request['InfoStruct']['ShareInfo2']['shi2_remark'] = 'My Remark\x00'
        request['InfoStruct']['ShareInfo2']['shi2_max_uses'] = 0xFFFFFFFF
        request['InfoStruct']['ShareInfo2']['shi2_path'] = 'c:\\\x00'
        request['InfoStruct']['ShareInfo2']['shi2_passwd'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrShareDel()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        resp.dump()

    def test_hNetrShareAdd_hNetrShareDel(self):
        dce, rpc_transport = self.connect()
        shareInfo = srvs.SHARE_INFO_2()
        shareInfo['shi2_netname'] = 'BETUSHARE\x00'
        shareInfo['shi2_type'] = srvs.STYPE_TEMPORARY
        shareInfo['shi2_remark'] = 'My Remark\x00'
        shareInfo['shi2_max_uses'] = 0xFFFFFFFF
        shareInfo['shi2_path'] = 'c:\\\x00'
        shareInfo['shi2_passwd'] = NULL
        resp = srvs.hNetrShareAdd(dce, 2, shareInfo)
        resp.dump()

        resp = srvs.hNetrShareDel(dce, 'BETUSHARE\x00')
        resp.dump()

    def test_NetrShareEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareEnum()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['ShareInfo']['tag'] = 0
        request['InfoStruct']['ShareInfo']['Level0']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 0
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 1
        request['InfoStruct']['ShareInfo']['Level1']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 1
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 2
        request['InfoStruct']['ShareInfo']['Level2']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 2
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 501
        request['InfoStruct']['ShareInfo']['Level501']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 501
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 502
        request['InfoStruct']['ShareInfo']['Level502']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 502
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 503
        request['InfoStruct']['ShareInfo']['Level503']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 503
        resp = dce.request(request)
        resp.dump()

    def test_hNetrShareEnum(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrShareEnum(dce, 0)
        resp.dump()

        resp = srvs.hNetrShareEnum(dce, 1)
        resp.dump()

        resp = srvs.hNetrShareEnum(dce, 2)
        resp.dump()

        resp = srvs.hNetrShareEnum(dce, 501)
        resp.dump()

        resp = srvs.hNetrShareEnum(dce, 502)
        resp.dump()

        resp = srvs.hNetrShareEnum(dce, 503)
        resp.dump()

    def tes_NetrShareEnumSticky(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareEnumSticky()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['ShareInfo']['tag'] = 502
        request['InfoStruct']['ShareInfo']['Level502']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 502
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 503
        request['InfoStruct']['ShareInfo']['Level503']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 503
        resp = dce.request(request)
        resp.dump()

    def tes_hNetrShareEnumSticky(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrShareEnumSticky(dce, 502)
        resp.dump()

        resp = srvs.hNetrShareEnumSticky(dce, 503)
        resp.dump()

    def test_NetrShareGetInfo(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareGetInfo()
        request['ServerName'] = NULL
        request['NetName'] = 'IPC$\x00'
        request['Level'] = 0
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 1
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 2
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 501
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 502
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 503
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 1005
        resp = dce.request(request)
        resp.dump()

    def test_hNetrShareGetInfo(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 0)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 1)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 2)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 501)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 502)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 503)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 1005)
        resp.dump()

    def test_NetrShareSetInfo(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareGetInfo()
        request['ServerName'] = NULL
        request['NetName'] = 'IPC$\x00'
        request['Level'] = 1
        resp = dce.request(request)
        resp.dump()
        oldValue = resp['InfoStruct']['ShareInfo1']['shi1_remark']

        req = srvs.NetrShareSetInfo()
        req['ServerName'] = NULL
        req['NetName'] = 'IPC$\x00'
        req['Level'] = 1
        req['ShareInfo']['tag'] = 1
        req['ShareInfo']['ShareInfo1'] = resp['InfoStruct']['ShareInfo1']
        req['ShareInfo']['ShareInfo1']['shi1_remark'] = 'BETUS\x00'
        resp = dce.request(req)
        resp.dump()

        resp = dce.request(request)
        resp.dump()

        req['ShareInfo']['ShareInfo1']['shi1_remark'] = oldValue
        resp = dce.request(req)
        resp.dump()

    def test_hNetrShareSetInfo(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 1)
        resp.dump()
        oldValue = resp['InfoStruct']['ShareInfo1']['shi1_remark']

        shareInfo = resp['InfoStruct']['ShareInfo1']
        shareInfo['shi1_remark'] = 'BETUS\x00'
        resp = srvs.hNetrShareSetInfo(dce, 'IPC$\x00', 1, shareInfo)
        resp.dump()

        resp = srvs.hNetrShareGetInfo(dce, 'IPC$\x00', 1)
        resp.dump()

        shareInfo['shi1_remark'] = oldValue
        resp = srvs.hNetrShareSetInfo(dce, 'IPC$\x00', 1, shareInfo)
        resp.dump()

    def tes_hNetrShareDelSticky(self):
        dce, rpc_transport = self.connect()

        shareInfo = srvs.SHARE_INFO_2()
        shareInfo['shi2_netname'] = 'BETUSHARE\x00'
        shareInfo['shi2_type'] = 0
        shareInfo['shi2_remark'] = 'My Remark\x00'
        shareInfo['shi2_max_uses'] = 0xFFFFFFFF
        shareInfo['shi2_path'] = 'c:\\\x00'
        shareInfo['shi2_passwd'] = NULL
        resp = srvs.hNetrShareAdd(dce, 2, shareInfo)
        resp.dump()

        resp = srvs.hNetrShareDelSticky(dce, 'BETUSHARE\x00')
        resp.dump()

        resp = srvs.hNetrShareDel(dce, 'BETUSHARE\x00')
        resp.dump()

    def tes_NetrShareDelSticky(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareAdd()
        request['ServerName'] = NULL
        request['Level'] = 2
        request['InfoStruct']['tag'] = 2
        request['InfoStruct']['ShareInfo2']['shi2_netname'] = 'BETUSHARE\x00'
        request['InfoStruct']['ShareInfo2']['shi2_type'] = 0
        request['InfoStruct']['ShareInfo2']['shi2_remark'] = 'My Remark\x00'
        request['InfoStruct']['ShareInfo2']['shi2_max_uses'] = 0xFFFFFFFF
        request['InfoStruct']['ShareInfo2']['shi2_path'] = 'c:\\\x00'
        request['InfoStruct']['ShareInfo2']['shi2_passwd'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrShareDelSticky()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrShareDel()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        resp.dump()

    def test_NetrShareDelStart_NetrShareDelCommit(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareAdd()
        request['ServerName'] = NULL
        request['Level'] = 2
        request['InfoStruct']['tag'] = 2
        request['InfoStruct']['ShareInfo2']['shi2_netname'] = 'BETUSHARE\x00'
        request['InfoStruct']['ShareInfo2']['shi2_type'] = 0
        request['InfoStruct']['ShareInfo2']['shi2_remark'] = 'My Remark\x00'
        request['InfoStruct']['ShareInfo2']['shi2_max_uses'] = 0xFFFFFFFF
        request['InfoStruct']['ShareInfo2']['shi2_path'] = 'c:\\\x00'
        request['InfoStruct']['ShareInfo2']['shi2_passwd'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrShareDelStart()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrShareDelCommit()
        request['ContextHandle'] = resp['ContextHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hNetrShareDelStart_hNetrShareDelCommit(self):
        dce, rpc_transport = self.connect()

        shareInfo = srvs.SHARE_INFO_2()
        shareInfo['shi2_netname'] = 'BETUSHARE\x00'
        shareInfo['shi2_type'] = 0
        shareInfo['shi2_remark'] = 'My Remark\x00'
        shareInfo['shi2_max_uses'] = 0xFFFFFFFF
        shareInfo['shi2_path'] = 'c:\\\x00'
        shareInfo['shi2_passwd'] = NULL
        resp = srvs.hNetrShareAdd(dce, 2, shareInfo)
        resp.dump()

        resp = srvs.hNetrShareDelStart(dce, 'BETUSHARE\x00')
        resp.dump()

        resp = srvs.hNetrShareDelCommit(dce, resp['ContextHandle'])
        resp.dump()

    def test_NetrShareCheck(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareCheck()
        request['ServerName'] = NULL
        request['Device'] = 'C:\\\x00'
        resp = dce.request(request)
        resp.dump()

    def test_hNetrShareCheck(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrShareCheck(dce, 'C:\\\x00')
        resp.dump()

    def test_NetrServerGetInfo(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerGetInfo()
        request['ServerName'] = NULL
        request['Level'] = 100
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 101
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 102
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 103
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 502
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 503
        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerGetInfo(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrServerGetInfo(dce, 100)
        resp.dump()

        resp = srvs.hNetrServerGetInfo(dce, 101)
        resp.dump()

        resp = srvs.hNetrServerGetInfo(dce, 102)
        resp.dump()

        resp = srvs.hNetrServerGetInfo(dce, 103)
        resp.dump()

        resp = srvs.hNetrServerGetInfo(dce, 502)
        resp.dump()

        resp = srvs.hNetrServerGetInfo(dce, 503)
        resp.dump()

    def test_NetrServerDiskEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerDiskEnum()
        request['ServerName'] = NULL
        request['ResumeHandle'] = NULL
        request['Level'] = 0
        request['DiskInfoStruct']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerDiskEnum(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrServerDiskEnum(dce, 0)
        resp.dump()

    def test_NetrServerStatisticsGet(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerStatisticsGet()
        request['ServerName'] = NULL
        request['Service'] = NULL
        request['Level'] = 0
        request['Options'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerStatisticsGet(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrServerStatisticsGet(dce, NULL, 0, 0)
        resp.dump()

    def test_NetrRemoteTOD(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrRemoteTOD()
        request['ServerName'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hNetrRemoteTOD(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrRemoteTOD(dce)
        resp.dump()

    def test_NetrServerTransportEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerTransportEnum()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['XportInfo']['tag'] = 0
        request['InfoStruct']['XportInfo']['Level0']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['XportInfo']['tag'] = 1
        request['InfoStruct']['XportInfo']['Level1']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['XportInfo']['tag'] = 2
        request['InfoStruct']['XportInfo']['Level2']['Buffer'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerTransportEnum(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrServerTransportEnum(dce, 0)
        resp.dump()

        resp = srvs.hNetrServerTransportEnum(dce, 1)
        resp.dump()

        resp = srvs.hNetrServerTransportEnum(dce, 2)
        resp.dump()

    def test_NetrpGetFileSecurity_NetrpSetFileSecurity(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrpGetFileSecurity()
        request['ServerName'] = NULL
        request['ShareName'] = 'C$\x00'
        request['lpFileName'] = '\\Windows\x00'
        request['RequestedInformation'] = OWNER_SECURITY_INFORMATION
        resp = dce.request(request)
        resp.dump()

        req = srvs.NetrpSetFileSecurity()
        req['ServerName'] = NULL
        req['ShareName'] = 'C$\x00'
        req['lpFileName'] = '\\Windows\x00'
        req['SecurityInformation'] = OWNER_SECURITY_INFORMATION
        req['SecurityDescriptor'] = resp['SecurityDescriptor']
        resp = dce.request(req)
        resp.dump()

    def test_hNetrpGetFileSecurity_hNetrpSetFileSecurity(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetrpGetFileSecurity(dce, 'C$\x00',  '\\Windows\x00', OWNER_SECURITY_INFORMATION)

        resp = srvs.hNetrpSetFileSecurity(dce,'C$\x00',  '\\Windows\x00', OWNER_SECURITY_INFORMATION, resp)
        resp.dump()

    def test_NetprPathType(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetprPathType()
        request['ServerName'] = NULL
        request['PathName'] = '\\pagefile.sys\x00'
        request['Flags'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hNetprPathType(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetprPathType(dce, '\\pagefile.sys\x00', 1)
        resp.dump()

    def test_NetprPathCanonicalize(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetprPathCanonicalize()
        request['ServerName'] = NULL
        request['PathName'] = '\\pagefile.sys\x00'
        request['OutbufLen'] = 50
        request['Prefix'] = 'c:\x00'
        request['PathType'] = 0
        request['Flags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hNetprPathCanonicalize(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetprPathCanonicalize(dce, '\\pagefile.sys\x00', 'c:\x00', 50, 0, 0)
        resp.dump()

    def test_NetprPathCompare(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetprPathCompare()
        request['ServerName'] = NULL
        request['PathName1'] = 'c:\\pagefile.sys\x00'
        request['PathName2'] = 'c:\\pagefile.sys\x00'
        request['PathType'] = 0
        request['Flags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hNetprPathCompare(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetprPathCompare(dce, 'c:\\pagefile.sys\x00', 'c:\\pagefile.sys\x00')
        resp.dump()

    def test_NetprNameValidate(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetprNameValidate()
        request['ServerName'] = NULL
        request['Name'] = 'Administrator\x00'
        request['NameType'] = srvs.NAMETYPE_USER
        request['Flags'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hNetprNameValidate(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetprNameValidate(dce, 'Administrator\x00', srvs.NAMETYPE_USER)
        resp.dump()

    def test_NetprNameCanonicalize(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetprNameCanonicalize()
        request['ServerName'] = NULL
        request['Name'] = 'Administrator\x00'
        request['OutbufLen'] = 50
        request['NameType'] = srvs.NAMETYPE_USER
        request['Flags'] = 0x80000000
        resp = dce.request(request)
        resp.dump()

    def test_hNetprNameCanonicalize(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetprNameCanonicalize(dce, 'Administrator\x00', 50, srvs.NAMETYPE_USER, 0x80000000)
        resp.dump()

    def test_NetprNameCompare(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetprNameCompare()
        request['ServerName'] = NULL
        request['Name1'] = 'Administrator\x00'
        request['Name2'] = 'Administrator\x00'
        request['NameType'] = srvs.NAMETYPE_USER
        request['Flags'] = 0x80000000
        resp = dce.request(request)
        resp.dump()

    def test_hNetprNameCompare(self):
        dce, rpc_transport = self.connect()
        resp = srvs.hNetprNameCompare(dce, 'Administrator\x00', 'Administrator\x00', srvs.NAMETYPE_USER, 0x80000000)
        resp.dump()

    def test_NetrDfsGetVersion(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsGetVersion()
        request['ServerName'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if e.get_error_code() != 0x2:
                raise

    def test_hNetrDfsGetVersion(self):
        dce, rpc_transport = self.connect()
        try:
            resp = srvs.hNetrDfsGetVersion(dce)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if e.get_error_code() != 0x2:
                raise

    def test_NetrDfsModifyPrefix(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsModifyPrefix()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if e.get_error_code() != 0x32:
                raise

    def test_NetrDfsFixLocalVolume(self):
        # This one I cannot make it work. It's only supported on w2k and xp
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsFixLocalVolume()
        request['ServerName'] = NULL
        request['VolumeName'] = r'\??\C:\DfsShare'
        request['EntryType'] = srvs.PKT_ENTRY_TYPE_LEAFONLY
        request['ServiceType'] = srvs.DFS_SERVICE_TYPE_LOCAL
        request['StgId'] = 'NONE\x00'
        request['EntryPrefix'] = 'c:\\\x00'
        request['RelationInfo']['Buffer']  = NULL
        request['CreateDisposition'] = srvs.FILE_SUPERSEDE
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCException as e:
            if str(e) != 'rpc_x_bad_stub_data':
                raise

    def test_NetrDfsManagerReportSiteInfo(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsManagerReportSiteInfo()
        request['ServerName'] = NULL
        request['ppSiteInfo'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrServerAliasAdd_NetrServerAliasDel(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerAliasAdd()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['InfoStruct']['tag'] = 0
        request['InfoStruct']['ServerAliasInfo0']['srvai0_alias'] = 'BETOALIAS\x00'
        request['InfoStruct']['ServerAliasInfo0']['srvai0_target'] = '%s\x00' % self.machine
        request['InfoStruct']['ServerAliasInfo0']['srvai0_default'] = 0
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrServerAliasDel()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['InfoStruct']['tag'] = 0
        request['InfoStruct']['ServerAliasInfo0']['srvai0_alias'] = 'BETOALIAS\x00'
        request['InfoStruct']['ServerAliasInfo0']['srvai0_target'] = '%s\x00' % self.machine
        request['InfoStruct']['ServerAliasInfo0']['srvai0_default'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerAliasAdd_hNetrServerAliasDel(self):
        dce, rpc_transport = self.connect()
        aliasInfo = srvs.SERVER_ALIAS_INFO_0()
        aliasInfo['srvai0_alias'] = 'BETOALIAS\x00'
        aliasInfo['srvai0_target'] = '%s\x00' % self.machine
        aliasInfo['srvai0_default'] = 0
        resp = srvs.hNetrServerAliasAdd(dce, 0, aliasInfo)
        resp.dump()

        resp = srvs.hNetrServerAliasDel(dce, 0, aliasInfo)
        resp.dump()

    def test_NetrServerAliasEnum(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerAliasEnum()
        request['ServerName'] = NULL
        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['ServerAliasInfo']['tag'] = 0
        request['InfoStruct']['ServerAliasInfo']['Level0']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if str(e) != 'ERROR_NOT_SUPPORTED':
                raise

    def test_hNetrServerAliasEnum(self):
        dce, rpc_transport = self.connect()
        try:
            resp = srvs.hNetrServerAliasEnum(dce, 0)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            print(e)
            if str(e) != 'ERROR_NOT_SUPPORTED':
                raise

    def test_NetrShareDelEx(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrShareAdd()
        request['ServerName'] = NULL
        request['Level'] = 2
        request['InfoStruct']['tag'] = 2
        request['InfoStruct']['ShareInfo2']['shi2_netname'] = 'BETUSHARE\x00'
        request['InfoStruct']['ShareInfo2']['shi2_type'] = srvs.STYPE_TEMPORARY
        request['InfoStruct']['ShareInfo2']['shi2_remark'] = 'My Remark\x00'
        request['InfoStruct']['ShareInfo2']['shi2_max_uses'] = 0xFFFFFFFF
        request['InfoStruct']['ShareInfo2']['shi2_path'] = 'c:\\\x00'
        request['InfoStruct']['ShareInfo2']['shi2_passwd'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = srvs.NetrShareDelEx()
        request['ServerName'] = NULL
        request['Level'] = 503
        request['ShareInfo']['tag'] = 503
        request['ShareInfo']['ShareInfo503']['shi503_netname'] ='BETUSHARE\x00'
        request['ShareInfo']['ShareInfo503']['shi503_type'] = srvs.STYPE_TEMPORARY
        request['ShareInfo']['ShareInfo503']['shi503_remark'] = 'My Remark\x00'
        request['ShareInfo']['ShareInfo503']['shi503_permissions'] = 0
        request['ShareInfo']['ShareInfo503']['shi503_max_uses'] = 0xFFFFFFFF
        request['ShareInfo']['ShareInfo503']['shi503_current_uses'] = 0
        request['ShareInfo']['ShareInfo503']['shi503_path'] = 'c:\\\x00'
        request['ShareInfo']['ShareInfo503']['shi503_passwd'] = NULL
        request['ShareInfo']['ShareInfo503']['shi503_servername'] = NULL
        request['ShareInfo']['ShareInfo503']['shi503_reserved'] = 0
        request['ShareInfo']['ShareInfo503']['shi503_security_descriptor'] = NULL
        resp = dce.request(request)
        resp.dump()

    def ttt_NetrServerTransportAdd_NetrServerTransportDel(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerTransportAdd()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['Buffer']['svti0_numberofvcs'] = 0
        request['Buffer']['svti0_transportname'] = '\\Device\\NetbiosSmb\x00'
        request['Buffer']['svti0_transportaddress'] = list('%s' % self.machine)
        request['Buffer']['svti0_transportaddresslength'] = len(request['Buffer']['svti0_transportaddress'])
        request['Buffer']['svti0_networkaddress'] = '%s\x00' % self.machine
        resp = dce.request(request)
        resp.dump()

        req = srvs.NetrServerTransportDel()
        req['ServerName'] = NULL
        req['Level'] = 0
        req['Buffer'] = request['Buffer']
        resp = dce.request(req)
        resp.dump()

    def ttt_NetrServerTransportAddEx_NetrServerTransportDelEx(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrServerTransportAddEx()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['Buffer']['tag'] = 0
        request['Buffer']['Transport0']['svti0_numberofvcs'] = 0
        request['Buffer']['Transport0']['svti0_transportname'] = '\\Device\\NetbiosSmb\x00'
        request['Buffer']['Transport0']['svti0_transportaddress'] = list('%s' % self.machine)
        request['Buffer']['Transport0']['svti0_transportaddresslength'] = len(request['Buffer']['Transport0']['svti0_transportaddress'])
        request['Buffer']['Transport0']['svti0_networkaddress'] = '%s\x00' % self.machine
        resp = dce.request(request)
        resp.dump()

        req = srvs.NetrServerTransportDelEx()
        req['ServerName'] = NULL
        req['Level'] = 0
        req['Buffer']['tag'] = 0
        req['Buffer']['Transport0']  = request['Buffer']['Transport0']
        resp = dce.request(req)
        resp.dump()

    def test_NetrDfsCreateLocalPartition(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsCreateLocalPartition()
        request['ServerName'] = NULL
        request['ShareName'] = 'C$\x00'
        #request['EntryUid'] = 0
        request['EntryPrefix'] = 'c:\\\x00'
        request['ShortName'] = 'c:\\betus\x00'
        request['RelationInfo']['Buffer'] = NULL
        request['Force'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDfsDeleteLocalPartition(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsDeleteLocalPartition()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDfsSetLocalVolumeState(self):
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsSetLocalVolumeState()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        request['State'] = 0x80
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDfsCreateExitPoint(self):
        # Cannot make it work, supported only on w2k and xp
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsCreateExitPoint()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        request['Type'] = srvs.PKT_ENTRY_TYPE_LEAFONLY
        request['ShortPrefixLen'] = 50
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCException as e:
            if str(e).find('rpc_x_bad_stub_data') < 0:
                raise

    def test_NetrDfsDeleteExitPoint(self):
        # Cannot make it work, supported only on w2k and xp
        dce, rpc_transport = self.connect()
        request = srvs.NetrDfsDeleteExitPoint()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        request['Type'] = srvs.PKT_ENTRY_TYPE_LEAFONLY
        try:
            resp = dce.request(request)
            resp.dump()
        except srvs.DCERPCSessionError as e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise


@pytest.mark.remote
class SRVSTestsSMBTransport(SRVSTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class SRVSTestsSMBTransport64(SRVSTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
