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
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import tsch, atsvc
from impacket.dcerpc.v5.atsvc import AT_INFO
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


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
        resp = dce.request(request)
        resp.dump()

    def test_hNetrJobEnum(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        resp = atsvc.hNetrJobEnum(dce, NULL, NULL, 0xffffffff)
        resp.dump()

    def test_hNetrJobAdd_hNetrJobEnum_hNetrJobDel(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, atsvc.MSRPC_UUID_ATSVC)

        atInfo = AT_INFO()
        atInfo['JobTime'] = NULL
        atInfo['DaysOfMonth'] = 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags'] = 0
        atInfo['Command'] = '%%COMSPEC%% /C dir > %%SYSTEMROOT%%\\Temp\\BTO\x00'

        resp = atsvc.hNetrJobAdd(dce, NULL, atInfo)
        resp.dump()

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
        resp = dce.request(request)
        resp.dump()

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
        resp = dce.request(request)
        resp.dump()

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

        resp = atsvc.hNetrJobAdd(dce, NULL, atInfo)
        resp.dump()

        resp2 = atsvc.hNetrJobGetInfo(dce, NULL, resp['pJobId'])
        resp2.dump()

        resp = atsvc.hNetrJobDel(dce, NULL, resp['pJobId'], resp['pJobId'])
        resp.dump()


    def tes_SchRpcHighestVersion(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcHighestVersion()
        resp = dce.request(request)
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
<xs:attribute name="version" type="versionType" use="optional"/> </xs:complexType>
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

    def tes_SchRpcEnumFolders(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcEnumFolders()
        request['path'] = '\\\x00'
        request['flags'] = 1
        request['startIndex'] = 0
        request['cRequested'] = 10
        resp = dce.request(request)
        resp.dump()

    def tes_SchRpcEnumTasks(self):
        dce, rpctransport = self.connect(self.stringBindingAtSvc, tsch.MSRPC_UUID_TSCHS)

        request = tsch.SchRpcEnumTasks()
        request['path'] = '\\\x00'
        request['flags'] = 1
        request['startIndex'] = 0
        request['cRequested'] = 10
        resp = dce.request(request)
        resp.dump()

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
