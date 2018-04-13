###############################################################################
#  Tested so far: 
# IWbemLevel1Login::EstablishPosition
# IWbemLevel1Login::RequestChallenge 
# IWbemLevel1Login::WBEMLogin 
# IWbemLevel1Login::NTLMLogin 
# IWbemServices::OpenNamespace  
# IWbemServices::ExecQuery
# IWbemServices::GetObject
#
# Since DCOM is more high level, I'll always use the helper classes
#
#  Not yet:
#
# IWbemServices::CancelAsyncCall
# IWbemServices::QueryObjectSink
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
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin, generate
from impacket import system_errors, ntlm

class WMITests(unittest.TestCase):
    def tes_activation(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLoginClientID)
        dcom.disconnect()

    def test_IWbemLevel1Login_EstablishPosition(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        resp = iWbemLevel1Login.EstablishPosition()
        print resp
        dcom.disconnect()

    def test_IWbemLevel1Login_RequestChallenge(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        try:
            resp = iWbemLevel1Login.RequestChallenge()
            print resp
        except Exception, e:
            if str(e).find('WBEM_E_NOT_SUPPORTED') < 0:
                dcom.disconnect()
                raise
        dcom.disconnect()

    def test_IWbemLevel1Login_WBEMLogin(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        try:
            resp = iWbemLevel1Login.WBEMLogin()
            print resp
        except Exception, e:
            if str(e).find('E_NOTIMPL') < 0:
                dcom.disconnect()
                raise
        dcom.disconnect()

    def test_IWbemLevel1Login_NTLMLogin(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        resp = iWbemLevel1Login.NTLMLogin('\\\\%s\\root\\cimv2' % self.machine, NULL, NULL)
        print resp
        dcom.disconnect()

    def tes_IWbemServices_OpenNamespace(self):
        # Not working
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./ROOT', NULL, NULL)
        try:
            resp = iWbemServices.OpenNamespace('__Namespace')
            print resp
        except Exception, e:
            dcom.disconnect()
            raise
        dcom.disconnect()

    def test_IWbemServices_GetObject(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('\\\\%s\\root\\cimv2' % self.machine, NULL, NULL)
        iWbemLevel1Login.RemRelease()

        classObject,_ = iWbemServices.GetObject('Win32_Process')
       
        dcom.disconnect()

    def test_IWbemServices_ExecQuery(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('\\\\%s\\root\\cimv2' % self.machine, NULL, NULL)
        #classes = [ 'Win32_Account', 'Win32_UserAccount', 'Win32_Group', 'Win32_SystemAccount', 'Win32_Service']
        classes = [ 'Win32_Service']
        for classn in classes:
            print "Reading %s " % classn
            try:
                iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from %s' % classn)
                done = False
                while done is False:
                    try:
                        iEnumWbemClassObject.Next(0xffffffff,1)
                    except Exception, e:
                        if str(e).find('S_FALSE') < 0:
                            print e
                        else:
                            done = True
                            pass
            except Exception, e:
                if str(e).find('S_FALSE') < 0:
                    print e
        dcom.disconnect()

    def test_IWbemServices_ExecMethod(self):
        dcom = DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)        
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('\\\\%s\\root\\cimv2' % self.machine, NULL, NULL)

        #classObject,_ = iWbemServices.GetObject('WinMgmts:Win32_LogicalDisk='C:'')
        classObject,_ = iWbemServices.GetObject('Win32_Process')
        obj = classObject.Create('notepad.exe', 'c:\\', None)
        handle = obj.getProperties()['ProcessId']['value']
        
        iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_Process where handle = %s' % handle)
        oooo = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #import time
        #time.sleep(5)
        owner = oooo.Terminate(1)

        #iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_Group where name = "testGroup0"')
        #oooo = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #import time
        #owner = oooo.Rename('testGroup1')

        #iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_Share where name = "Users"')
        #oooo = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #import time
        #owner = oooo.GetAccessMask()
        #print owner.getProperties()

        #iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_Share where name = "Users"')
        #oooo = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #obj = oooo.SetShareInfo(0, 'HOLA BETO', None)

        #classObject,_ = iWbemServices.GetObject('Win32_ShadowCopy')
        #obj = classObject.Create('C:\\', 'ClientAccessible')
        #print obj.getProperties()

        # this one doesn't work
        #classObject,_ = iWbemServices.GetObject('Win32_Service')
        #obj = classObject.Create('BETOSERVICE', 'Beto Service', 'c:\\beto', 16, 0, 'Manual', 0, None, None, None, None, None)
        #print obj.getProperties()

        dcom.disconnect()

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
        if len(self.hashes) > 0:
            self.lmhash, self.nthash = self.hashes.split(':')
        else:
            self.lmhash = ''
            self.nthash = ''

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
        if len(self.hashes) > 0:
            self.lmhash, self.nthash = self.hashes.split(':')
        else:
            self.lmhash = ''
            self.nthash = ''

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
