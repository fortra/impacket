###############################################################################
#  Tested so far: 
#
#  NetrConnectionEnum
#  NetrFileEnum
#  NetrFileGetInfo
#  NetrFileClose
#  NetrSessionEnum
#  NetrSessionDel
#  NetrShareAdd
#  NetrShareDel
#  NetrShareEnum
#  NetrShareEnumSticky
#  NetrShareGetInfo
#  NetrShareDelSticky
#  NetrShareDelStart
#  NetrShareDelCommit
#  NetrShareCheck
#  NetrServerGetInfo
#  NetrServerDiskEnum
#  NetrServerStatisticsGet
#  NetrRemoteTOD
#  NetrServerTransportEnum
#  NetrpGetFileSecurity
#  NetprPathType
#  NetprPathCanonicalize
#  NetprPathCompare
#  NetprNameValidate
#  NetprNameCanonicalize
#  NetprNameCompare
#  NetrDfsGetVersion
#  NetrDfsModifyPrefix
#  NetrDfsFixLocalVolume
#  NetrDfsManagerReportSiteInfo
#  NetrServerAliasAdd
#  NetrServerAliasEnum
#  NetrServerAliasDel
#  NetrShareDelEx
#  NetrServerTransportAdd
#  NetrServerTransportDel
#  NetrServerTransportAddEx
#  NetrServerTransportDelEx
#  NetrDfsCreateLocalPartition
#  NetrDfsDeleteLocalPartition
#  NetrDfsSetLocalVolumeState
#  NetrDfsCreateExitPoint
#  NetrDfsDeleteExitPoint
#  NetrShareSetInfo 
#
#  Not yet:
#
#  NetrServerSetInfo
#
#  Shouldn't dump errors against a win7
#
################################################################################

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, srvs, samr
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.dtypes import *
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import system_errors

class SRVSTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
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
        dce.bind(srvs.MSRPC_UUID_SRVS)

        return dce, rpctransport

    def test_NetrConnectionEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrConnectionEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['Qualifier'] = 'IPC$\x00'
        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['ConnectInfo']['tag'] = 1
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['ConnectInfo']['tag'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetrFileEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()
        request['InfoStruct']['Level'] = 3
        request['InfoStruct']['FileInfo']['tag'] = 3
        resp = dce.request(request)
        #resp.dump()

    def test_NetrFileGetInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrFileGetInfo()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['FileId'] = resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id']
        request['Level'] = 2
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 3
        resp = dce.request(request)
        #resp.dump()

    def test_NetrFileClose(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrFileClose()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['FileId'] = resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id']
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            # I might be closing myself ;)
            if str(e).find('STATUS_PIPE_BROKEN') < 0:
                raise

    def test_NetrSessionEnum(self):
        dce, rpctransport = self.connect()
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
        #resp.dump()

        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['SessionInfo']['tag'] = 1
        request['InfoStruct']['SessionInfo']['Level1']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        return
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['SessionInfo']['tag'] = 2
        request['InfoStruct']['SessionInfo']['Level2']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 10
        request['InfoStruct']['SessionInfo']['tag'] = 10
        request['InfoStruct']['SessionInfo']['Level10']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 502
        request['InfoStruct']['SessionInfo']['tag'] = 502
        request['InfoStruct']['SessionInfo']['Level502']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_NetrSessionDel(self):
        dce, rpctransport = self.connect()
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
        #resp.dump()

        request = srvs.NetrSessionDel()
        request['ServerName'] = NULL
        request['ClientName'] = resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_cname'] 
        request['UserName'] = resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_username'] 
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x908:
                raise

    def test_NetrShareAdd_NetrShareDel(self):
        dce, rpctransport = self.connect()
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
        #resp.dump()

        request = srvs.NetrShareDel()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareEnum()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['ShareInfo']['tag'] = 0
        request['InfoStruct']['ShareInfo']['Level0']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 0
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 1
        request['InfoStruct']['ShareInfo']['Level1']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 1
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 2
        request['InfoStruct']['ShareInfo']['Level2']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 2
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 501
        request['InfoStruct']['ShareInfo']['Level501']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 501
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 502
        request['InfoStruct']['ShareInfo']['Level502']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 503
        request['InfoStruct']['ShareInfo']['Level503']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 503
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareEnumSticky(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareEnumSticky()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['ShareInfo']['tag'] = 502
        request['InfoStruct']['ShareInfo']['Level502']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 503
        request['InfoStruct']['ShareInfo']['Level503']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 503
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareGetInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareGetInfo()
        request['ServerName'] = NULL
        request['NetName'] = 'IPC$\x00'
        request['Level'] = 0
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 1
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 2
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 501
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 503
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 1005
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareSetInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareGetInfo()
        request['ServerName'] = NULL
        request['NetName'] = 'IPC$\x00'
        request['Level'] = 1
        resp = dce.request(request)
        #resp.dump()
        oldValue = resp['InfoStruct']['ShareInfo1']['shi1_remark']

        req = srvs.NetrShareSetInfo()
        req['ServerName'] = NULL
        req['NetName'] = 'IPC$\x00'
        req['Level'] = 1
        req['ShareInfo']['tag'] = 1
        req['ShareInfo']['ShareInfo1'] = resp['InfoStruct']['ShareInfo1']
        req['ShareInfo']['ShareInfo1']['shi1_remark'] = 'BETUS\x00'
        resp = dce.request(req)
        #resp.dump()

        resp = dce.request(request)
        #resp.dump()

        req['ShareInfo']['ShareInfo1']['shi1_remark'] = oldValue
        resp = dce.request(req)
        #resp.dump()



    def test_NetrShareDelSticky(self):
        dce, rpctransport = self.connect()
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
        #resp.dump()

        request = srvs.NetrShareDelSticky()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrShareDel()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareDelStart_NetrShareDelCommit(self):
        dce, rpctransport = self.connect()
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
        #resp.dump()

        request = srvs.NetrShareDelStart()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrShareDelCommit()
        request['ContextHandle'] = resp['ContextHandle']
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareCheck(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareCheck()
        request['ServerName'] = NULL
        request['Device'] = 'C:\\\x00'
        resp = dce.request(request)
        #resp.dump()

    def test_NetrServerGetInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerGetInfo()
        request['ServerName'] = NULL
        request['Level'] = 100
        request['InfoStruct']['tag'] = 100
        request['InfoStruct']['ServerInfo100'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 101
        request['InfoStruct']['tag'] = 101
        request['InfoStruct']['ServerInfo101'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 102
        request['InfoStruct']['tag'] = 102
        request['InfoStruct']['ServerInfo102'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 103
        request['InfoStruct']['tag'] = 103
        request['InfoStruct']['ServerInfo103'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 502
        request['InfoStruct']['tag'] = 502
        request['InfoStruct']['ServerInfo502'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 503
        request['InfoStruct']['tag'] = 503
        request['InfoStruct']['ServerInfo503'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_NetrServerDiskEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerDiskEnum()
        request['ServerName'] = NULL
        request['ResumeHandle'] = NULL
        request['Level'] = 0
        request['DiskInfoStruct']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        #resp.dump()

    def test_NetrServerStatisticsGet(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerStatisticsGet()
        request['ServerName'] = NULL
        request['Service'] = NULL
        request['Level'] = 0
        request['Options'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetrRemoteTOD(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrRemoteTOD()
        request['ServerName'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_NetrServerTransportEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerTransportEnum()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['XportInfo']['tag'] = 0
        request['InfoStruct']['XportInfo']['Level0']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['XportInfo']['tag'] = 1
        request['InfoStruct']['XportInfo']['Level1']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['XportInfo']['tag'] = 2
        request['InfoStruct']['XportInfo']['Level2']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_NetrpGetFileSecurity_NetrpSetFileSecurity(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrpGetFileSecurity()
        request['ServerName'] = NULL
        request['ShareName'] = 'C$\x00'
        request['lpFileName'] = '\\Windows\x00'
        request['RequestedInformation'] = OWNER_SECURITY_INFORMATION
        resp = dce.request(request)
        #resp.dump()

        req = srvs.NetrpSetFileSecurity()
        req['ServerName'] = NULL
        req['ShareName'] = 'C$\x00' 
        req['lpFileName'] = '\\Windows\x00' 
        req['SecurityInformation'] = OWNER_SECURITY_INFORMATION
        req['SecurityDescriptor'] = resp['SecurityDescriptor']
        resp = dce.request(req)
        #resp.dump()


    def test_NetprPathType(self):
        dce, rpctransport = self.connect()
        request = srvs.NetprPathType()
        request['ServerName'] = NULL
        request['PathName'] = '\\pagefile.sys\x00'
        request['Flags'] = 1
        resp = dce.request(request)
        #resp.dump()

    def test_NetprPathCanonicalize(self):
        dce, rpctransport = self.connect()
        request = srvs.NetprPathCanonicalize()
        request['ServerName'] = NULL
        request['PathName'] = '\\pagefile.sys\x00'
        request['OutbufLen'] = 50
        request['Prefix'] = 'c:\x00'
        request['PathType'] = 0
        request['Flags'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetprPathCompare(self):
        dce, rpctransport = self.connect()
        request = srvs.NetprPathCompare()
        request['ServerName'] = NULL
        request['PathName1'] = 'c:\\pagefile.sys\x00'
        request['PathName2'] = 'c:\\pagefile.sys\x00'
        request['PathType'] = 0
        request['Flags'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetprNameValidate(self):
        dce, rpctransport = self.connect()
        request = srvs.NetprNameValidate()
        request['ServerName'] = NULL
        request['Name'] = 'Administrator\x00'
        request['NameType'] = srvs.NAMETYPE_USER
        request['Flags'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetprNameCanonicalize(self):
        dce, rpctransport = self.connect()
        request = srvs.NetprNameCanonicalize()
        request['ServerName'] = NULL
        request['Name'] = 'Administrator\x00'
        request['OutbufLen'] = 50
        request['NameType'] = srvs.NAMETYPE_USER
        request['Flags'] = 0x80000000
        resp = dce.request(request)
        #resp.dump()

    def test_NetprNameCompare(self):
        dce, rpctransport = self.connect()
        request = srvs.NetprNameCompare()
        request['ServerName'] = NULL
        request['Name1'] = 'Administrator\x00'
        request['Name2'] = 'Administrator\x00'
        request['NameType'] = srvs.NAMETYPE_USER
        request['Flags'] = 0x80000000
        resp = dce.request(request)
        #resp.dump()

    def test_NetrDfsGetVersion(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsGetVersion()
        request['ServerName'] = NULL
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x2:
                raise

    def test_NetrDfsModifyPrefix(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsModifyPrefix()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x32:
                raise

    def test_NetrDfsFixLocalVolume(self):
        # This one I cannot make it work. It's only supported on w2k and xp
        dce, rpctransport = self.connect()
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
            #resp.dump()
        except Exception, e:
            if str(e) != 'rpc_x_bad_stub_data':
                raise

    def test_NetrDfsManagerReportSiteInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsManagerReportSiteInfo()
        request['ServerName'] = NULL
        request['ppSiteInfo'] = NULL
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrServerAliasAdd_NetrServerAliasDel(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerAliasAdd()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['InfoStruct']['tag'] = 0
        request['InfoStruct']['ServerAliasInfo0']['srvai0_alias'] = 'BETOALIAS\x00'
        request['InfoStruct']['ServerAliasInfo0']['srvai0_target'] = '%s\x00' % self.machine
        request['InfoStruct']['ServerAliasInfo0']['srvai0_default'] = 0
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrServerAliasDel()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['InfoStruct']['tag'] = 0
        request['InfoStruct']['ServerAliasInfo0']['srvai0_alias'] = 'BETOALIAS\x00'
        request['InfoStruct']['ServerAliasInfo0']['srvai0_target'] = '%s\x00' % self.machine
        request['InfoStruct']['ServerAliasInfo0']['srvai0_default'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetrServerAliasEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerAliasEnum()
        request['ServerName'] = NULL
        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['ServerAliasInfo']['tag'] = 0
        request['InfoStruct']['ServerAliasInfo']['Level0']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e) != 'ERROR_NOT_SUPPORTED':
                raise

    def test_NetrShareDelEx(self):
        dce, rpctransport = self.connect()
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
        #resp.dump()

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
        #resp.dump()

    def test_NetrServerTransportAdd_NetrServerTransportDel(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerTransportAdd()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['Buffer']['svti0_numberofvcs'] = 0
        request['Buffer']['svti0_transportname'] = '\\Device\\NetbiosSmb\x00'
        request['Buffer']['svti0_transportaddress'] = list('%s'% self.machine) 
        request['Buffer']['svti0_transportaddresslength'] = len(request['Buffer']['svti0_transportaddress'])
        request['Buffer']['svti0_networkaddress'] = '%s\x00' % self.machine
        resp = dce.request(request)
        #resp.dump()

        req = srvs.NetrServerTransportDel()
        req['ServerName'] = NULL
        req['Level'] = 0
        req['Buffer'] = request['Buffer'] 
        resp = dce.request(req)
        #resp.dump()
   
    def test_NetrServerTransportAddEx_NetrServerTransportDelEx(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrServerTransportAddEx()
        request['ServerName'] = NULL
        request['Level'] = 0
        request['Buffer']['tag'] = 0
        request['Buffer']['Transport0']['svti0_numberofvcs'] = 0
        request['Buffer']['Transport0']['svti0_transportname'] = '\\Device\\NetbiosSmb\x00'
        request['Buffer']['Transport0']['svti0_transportaddress'] = list('%s'% self.machine) 
        request['Buffer']['Transport0']['svti0_transportaddresslength'] = len(request['Buffer']['Transport0']['svti0_transportaddress'])
        request['Buffer']['Transport0']['svti0_networkaddress'] = '%s\x00' % self.machine
        resp = dce.request(request)
        #resp.dump()

        req = srvs.NetrServerTransportDelEx()
        req['ServerName'] = NULL
        req['Level'] = 0
        req['Buffer']['tag'] = 0
        req['Buffer']['Transport0']  = request['Buffer']['Transport0']
        resp = dce.request(req)
        #resp.dump()

    def test_NetrDfsCreateLocalPartition(self):
        dce, rpctransport = self.connect()
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
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDfsDeleteLocalPartition(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsDeleteLocalPartition()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDfsSetLocalVolumeState(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsSetLocalVolumeState()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        request['State'] = 0x80
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDfsCreateExitPoint(self):
        # Cannot make it work, supported only on w2k and xp
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsCreateExitPoint()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        request['Type'] = srvs.PKT_ENTRY_TYPE_LEAFONLY
        request['ShortPrefixLen'] = 50
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('rpc_x_bad_stub_data') < 0:
                raise

    def test_NetrDfsDeleteExitPoint(self):
        # Cannot make it work, supported only on w2k and xp
        dce, rpctransport = self.connect()
        request = srvs.NetrDfsDeleteExitPoint()
        request['ServerName'] = NULL
        request['Prefix'] = 'c:\\\x00'
        request['Type'] = srvs.PKT_ENTRY_TYPE_LEAFONLY
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise


class SMBTransport(SRVSTests):
    def setUp(self):
        SRVSTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\srvsvc]' % self.machine

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
    unittest.TextTestRunner(verbosity=1).run(suite)
