###############################################################################
#  Tested so far: 
# IWbemLevel1Login::EstablishPosition
# IWbemLevel1Login::RequestChallenge 
# IWbemLevel1Login::WBEMLogin 
# IWbemLevel1Login::NTLMLogin 
# IWbemServices::OpenNamespace  
# IWbemServices::ExecQuery
#
# Since DCOM is more high level, I'll always use the helper classes
#
#  Not yet:
#
# IWbemServices::CancelAsyncCall
# IWbemServices::QueryObjectSink
# IWbemServices::GetObject
# IWbemServices::GetObjectAsync
# IWbemServices::PutClass
# IWbemServices::PutClassAsync
# IWbemServices::DeleteClass
# IWbemServices::DeleteClassAsync
# IWbemServices::CreateClassEnum
# IWbemServices::CreateClassEnumAsync
# IWbemServices::PutInstance
# IWbemServices::PutInstanceAsync
# IWbemServices::DeleteInstance
# IWbemServices::DeleteInstanceAsync
# IWbemServices::CreateInstanceEnum
# IWbemServices::CreateInstanceEnumAsync
# IWbemServices::ExecQueryAsync
# IWbemServices::ExecNotificationQuery
# IWbemServices::ExecNotificationQueryAsync
# IWbemServices::ExecMethod
# IWbemServices::ExecMethodAsync
# 
# Shouldn't dump errors against a win7
#
################################################################################

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, dcomrt
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.dtypes import *
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin, generate
from impacket import system_errors, ntlm

class WMITests(unittest.TestCase):
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
        dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.connect()

        return dce, rpctransport

    def tes_activation(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLoginClientID)
        dce.disconnect()
        print iInterface

    def tes_IWbemLevel1Login_EstablishPosition(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        resp = iWbemLevel1Login.EstablishPosition()
        print resp
        dce.disconnect()

    def tes_IWbemLevel1Login_RequestChallenge(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        resp = iWbemLevel1Login.RequestChallenge()
        print resp
        dce.disconnect()

    def tes_IWbemLevel1Login_WBEMLogin(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        resp = iWbemLevel1Login.WBEMLogin()
        print resp
        dce.disconnect()

    def tes_IWbemLevel1Login_NTLMLogin(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        resp = iWbemLevel1Login.NTLMLogin('\\\\%s\\root\\cimv2' % self.machine, NULL, NULL)
        print resp
        dce.disconnect()

    def tes_IWbemServices_OpenNamespace(self):
        # Not working
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./ROOT', NULL, NULL)
        iWbemServices.OpenNamespace('__Namespace')
        print resp
        dce.disconnect()

    def tes_IWbemServices_GetObject(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)

        #iInterface2 = iWbemLevel1Login.RemQueryInterface(1, (wmi.IID_IWbemLoginClientID,))
        #iWbemLoginClientID = wmi.IWbemLoginClientID(iInterface2)
        #iWbemLoginClientID.SetClientInfo('BETS')
        #iWbemLoginClientID.RemRelease()
         
        #print iWbemLevel1Login.EstablishPosition()
        iWbemServices= iWbemLevel1Login.NTLMLogin('\\\\%s\\root\\cimv2' % self.machine, NULL, NULL)
        iWbemLevel1Login.RemRelease()

        classObject,_ = iWbemServices.GetObject('win32_process')
       
        dce.disconnect()

    def test_IWbemServices_ExecQuery(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        #iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_BIOS')
        #iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_NetworkAdapter')
        iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_OperatingSystem')
        iEnumWbemClassObject.Next(0xffffffff,1)
        dce.disconnect()


class TCPTransport(WMITests):
    def setUp(self):
        WMITests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport64(WMITests):
    def setUp(self):
        WMITests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
