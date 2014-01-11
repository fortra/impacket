###############################################################################
#  Tested so far: 
#
# OpenClassesRoot
# OpenCurrentUser
# OpenLocalMachine
# OpenPerformanceData
# OpenUsers
# BaseRegCloseKey
# BaseRegCreateKey
# BaseRegDeleteKey
# BaseRegFlushKey
# BaseRegGetKeySecurity
# BaseRegOpenKey
# BaseRegQueryInfoKey
# BaseRegQueryValue
# BaseRegReplaceKey
# BaseRegRestoreKey
# BaseRegSaveKey
# BaseRegSetValue
# 
#  Not yet:
#
# BaseRegEnumValue
# BaseRegEnumKey
# BaseRegLoadKey
# BaseRegSetKeySecurity
#
# Shouldn't dump errors against a win7
#
################################################################################

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dtypes import *
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import nt_errors

class RRPTests(unittest.TestCase):
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
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP, transfer_syntax = self.ts)
        request = rrp.OpenLocalMachine()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED | rrp.KEY_WOW64_32KEY 
        resp = dce.request(request)


        return dce, rpctransport, resp['phKey']

    def test_OpenClassesRoot(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenClassesRoot()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_OpenCurrentUser(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenCurrentUser()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_OpenLocalMachine(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenLocalMachine()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_OpenPerformanceData(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenPerformanceData()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_OpenUsers(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenUsers()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegCloseKey(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.BaseRegCloseKey()
        request['hKey'] = phKey
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegCreateKey_BaseRegSetValue_BaseRegDeleteKey(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenClassesRoot()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED 
        resp = dce.request(request)
        #resp.dump()
        regHandle = resp['phKey']

        request = rrp.BaseRegCreateKey()
        request['hKey'] = regHandle
        request['lpSubKey'] = 'BETO\x00'
        request['lpClass'] = NULL
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        request['lpSecurityAttributes']['RpcSecurityDescriptor']['lpSecurityDescriptor'] = NULL
        request['lpdwDisposition'] = rrp.REG_CREATED_NEW_KEY
        resp = dce.request(request)
        #resp.dump()

        request = rrp.BaseRegSetValue()
        request['hKey'] = resp['phkResult']
        request['lpValueName'] = 'BETO\x00'
        request['dwType'] = rrp.REG_SZ
        request['lpData'] = 'HOLA COMO TE VA\x00'.encode('utf-16le')
        request['cbData'] = len('HOLA COMO TE VA\x00')*2
        
        try: 
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            print e

        request = rrp.BaseRegDeleteKey()
        request['hKey'] = regHandle
        request['lpSubKey'] = 'BETO\x00'
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegEnumKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegEnumKey()
        request['hKey'] = phKey
        request['dwIndex'] = 0
        request['lpNameIn'] = 'Software\x00' 
        request['lpClassIn'] = NULL
        request['lpftLastWriteTime'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_BaseRegEnumValue(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegEnumValue()
        request['hKey'] = phKey
        request['dwIndex'] = 0
        request['lpValueNameIn'] = 'COMPONENTS\\PendingXmlIdentifier\x00'
        request['lpData'] = ' '*100
        request['lpcbData'] = 100
        request['lpcbLen'] = 100
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegFlushKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegFlushKey()
        request['hKey'] = phKey
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegGetKeySecurity(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegGetKeySecurity()
        request['hKey'] = phKey
        request['SecurityInformation'] = OWNER_SECURITY_INFORMATION
        request['pRpcSecurityDescriptorIn']['lpSecurityDescriptor'] = NULL
        request['pRpcSecurityDescriptorIn']['cbInSecurityDescriptor'] = 1024
        #resp.dump()

    def test_BaseRegOpenKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegQueryInfoKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegQueryInfoKey()
        request['hKey'] = phKey
        request['lpClassIn'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegQueryValue(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

        request = rrp.BaseRegQueryValue()
        request['hKey'] = resp['phkResult']
        request['lpValueName'] = 'ProductName\x00'
        request['lpData'] = ' '*100
        request['lpcbData'] = 100
        request['lpcbLen'] = 100
        resp = dce.request(request)
        #resp.dump()

    def test_BaseRegReplaceKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegReplaceKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\x00'
        request['lpNewFile'] = 'SOFTWARE\x00'
        request['lpOldFile'] = 'SOFTWARE\x00'
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_FILE_NOT_FOUND') < 0:
                raise

    def test_BaseRegRestoreKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegRestoreKey()
        request['hKey'] = phKey
        request['lpFile'] = 'SOFTWARE\x00'
        request['Flags'] = rrp.REG_REFRESH_HIVE
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if str(e).find('ERROR_FILE_NOT_FOUND') < 0:
                raise

    def htest_BaseRegSaveKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.OpenCurrentUser()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegSaveKey()
        request['hKey'] = resp['phKey']
        request['lpFile'] = 'BETUSFILE\x00'
        request['pSecurityAttributes'] = NULL
        resp = dce.request(request)
        resp.dump()
        # I gotta remove the file now :s

class SMBTransport(RRPTests):
    def setUp(self):
        RRPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\winreg]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(RRPTests):
    def setUp(self):
        RRPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\winreg]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

class TCPTransport(RRPTests):
    def setUp(self):
        RRPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, rrp.MSRPC_UUID_RRP, protocol = 'ncacn_ip_tcp')


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
