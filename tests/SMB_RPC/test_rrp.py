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
# BaseRegEnumValue
# BaseRegEnumKey
# BaseRegGetVersion
# OpenCurrentConfig
# BaseRegQueryMultipleValues
# BaseRegSaveKeyEx
# OpenPerformanceText
# OpenPerformanceNlsText
# BaseRegQueryMultipleValues2
# BaseRegDeleteKeyEx
# BaseRegLoadKey
# BaseRegUnLoadKey
# BaseRegDeleteValue
# 
#  Not yet:
#
# BaseRegSetKeySecurity
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, rrp, scmr
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, OWNER_SECURITY_INFORMATION
from impacket import ntlm


class RRPTests(unittest.TestCase):
    def connect_scmr(self):
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % self.machine)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        # dce.set_max_fragment_size(32)
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        lpMachineName = 'DUMMY\x00'
        lpDatabaseName = 'ServicesActive\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | \
                        scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | \
                        scmr.SERVICE_ENUMERATE_DEPENDENTS | scmr.SC_MANAGER_ENUMERATE_SERVICE

        resp = scmr.hROpenSCManagerW(dce, lpMachineName, lpDatabaseName, desiredAccess)
        scHandle = resp['lpScHandle']

        return dce, rpctransport, scHandle

    def connect(self):
        if self.rrpStarted is not True:
            dce, rpctransport, scHandle = self.connect_scmr()

            desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | \
                            scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

            resp = scmr.hROpenServiceW(dce, scHandle, 'RemoteRegistry\x00', desiredAccess)
            resp.dump()
            serviceHandle = resp['lpServiceHandle']

            try:
                resp = scmr.hRStartServiceW(dce, serviceHandle )
            except Exception as e:
                if str(e).find('ERROR_SERVICE_ALREADY_RUNNING') >=0:
                    pass
                else:
                    raise
            resp = scmr.hRCloseServiceHandle(dce, scHandle)
            self.rrpStarted = True

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
        resp = rrp.hOpenLocalMachine(dce, MAXIMUM_ALLOWED | rrp.KEY_WOW64_32KEY | rrp.KEY_ENUMERATE_SUB_KEYS)

        return dce, rpctransport, resp['phKey']

    def test_OpenClassesRoot(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenClassesRoot()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_OpenCurrentUser(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenCurrentUser()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_OpenLocalMachine(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenLocalMachine()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_OpenPerformanceData(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenPerformanceData()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_OpenUsers(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenUsers()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_BaseRegCloseKey(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.BaseRegCloseKey()
        request['hKey'] = phKey
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegCreateKey_hBaseRegSetValue_hBaseRegDeleteKey(self):
        dce, rpctransport, phKey = self.connect()
        resp = rrp.hOpenClassesRoot(dce)
        resp.dump()
        regHandle = resp['phKey']

        resp = rrp.hBaseRegCreateKey(dce, regHandle, 'BETO\x00')
        resp.dump()
        phKey = resp['phkResult']

        try: 
            resp = rrp.hBaseRegSetValue(dce, phKey, 'BETO2\x00',  rrp.REG_SZ, 'HOLA COMO TE VA\x00')
            resp.dump()
        except Exception, e:
            print e

        type, data = rrp.hBaseRegQueryValue(dce, phKey, 'BETO2\x00')
        #print data

        resp = rrp.hBaseRegDeleteValue(dce, phKey, 'BETO2\x00')
        resp.dump()

        resp = rrp.hBaseRegDeleteKey(dce, regHandle, 'BETO\x00')
        resp.dump()
        self.assertTrue( 'HOLA COMO TE VA\x00' == data )

    def test_BaseRegCreateKey_BaseRegSetValue_BaseRegDeleteKey(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenClassesRoot()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED 
        resp = dce.request(request)
        resp.dump()
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
        resp.dump()
        phKey = resp['phkResult']

        request = rrp.BaseRegSetValue()
        request['hKey'] = phKey
        request['lpValueName'] = 'BETO\x00'
        request['dwType'] = rrp.REG_SZ
        request['lpData'] = 'HOLA COMO TE VA\x00'.encode('utf-16le')
        request['cbData'] = len('HOLA COMO TE VA\x00')*2
        
        try: 
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            print e

        request = rrp.BaseRegQueryValue()
        request['hKey'] = phKey
        request['lpValueName'] = 'BETO\x00'
        request['lpData'] = ' '*100
        request['lpcbData'] = 100
        request['lpcbLen'] = 100
        resp = dce.request(request)
        resp.dump()
        resData = resp['lpData']

        request = rrp.BaseRegDeleteKey()
        request['hKey'] = regHandle
        request['lpSubKey'] = 'BETO\x00'
        resp = dce.request(request)
        resp.dump()
        self.assertTrue( 'HOLA COMO TE VA\x00' == ''.join(resData).decode('utf-16le'))

    def test_BaseRegEnumKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS
        resp = dce.request(request)

        request = rrp.BaseRegEnumKey()
        request['hKey'] = resp['phkResult']
        request['dwIndex'] = 1
        # I gotta access the fields manually :s
        request.fields['lpNameIn'].fields['MaximumLength'] = 510
        request.fields['lpNameIn'].fields['Data'].fields['Data'].fields['MaximumCount'] = 255
        request['lpClassIn'] = ' '*100
        request['lpftLastWriteTime'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegEnumKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS
        resp = dce.request(request)

        resp = rrp.hBaseRegEnumKey(dce, resp['phkResult'], 1 )
        resp.dump()

    def test_BaseRegEnumValue(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)

        request = rrp.BaseRegEnumValue()
        request['hKey'] = resp['phkResult']
        request['dwIndex'] = 6
        request['lpValueNameIn'] = ' '*100
        request['lpData'] = ' '*100
        request['lpcbData'] = 100
        request['lpcbLen'] = 100
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegEnumValue(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)

        resp = rrp.hBaseRegEnumValue(dce, resp['phkResult'], 7, 10)
        resp.dump()


    def test_BaseRegFlushKey(self):
        dce, rpctransport, phKey = self.connect()

        resp =  rrp.hBaseRegFlushKey(dce,phKey)
        resp.dump()

    def test_BaseRegGetKeySecurity(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hBaseRegGetKeySecurity(dce, phKey, OWNER_SECURITY_INFORMATION)
        resp.dump()

    def test_BaseRegOpenKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegQueryInfoKey(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hBaseRegOpenKey(dce, phKey, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD\x00' )

        resp = rrp.hBaseRegQueryInfoKey(dce,resp['phkResult'])
        resp.dump()

    def test_BaseRegQueryValue(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegQueryValue()
        request['hKey'] = resp['phkResult']
        request['lpValueName'] = 'ProductName\x00'
        request['lpData'] = ' '*100
        request['lpcbData'] = 100
        request['lpcbLen'] = 100
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegQueryValue(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hBaseRegOpenKey(dce, phKey, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00' )
        resp.dump()

        resp = rrp.hBaseRegQueryValue(dce, resp['phkResult'], 'ProductName\x00')
        
    def test_BaseRegReplaceKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegReplaceKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\x00'
        request['lpNewFile'] = 'SOFTWARE\x00'
        request['lpOldFile'] = 'SOFTWARE\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_FILE_NOT_FOUND') < 0:
                raise

    def test_hBaseRegReplaceKey(self):
        dce, rpctransport, phKey = self.connect()

        try:
            resp = rrp.hBaseRegReplaceKey(dce, phKey, 'SOFTWARE\x00', 'SOFTWARE\x00', 'SOFTWARE\x00')
            resp.dump()
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
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_FILE_NOT_FOUND') < 0:
                raise

    def test_hBaseRegRestoreKey(self):
        dce, rpctransport, phKey = self.connect()

        try:
            resp = rrp.hBaseRegRestoreKey(dce, phKey, 'SOFTWARE\x00')
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_FILE_NOT_FOUND') < 0:
                raise

    def test_BaseRegSaveKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.OpenCurrentUser()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegSaveKey()
        request['hKey'] = resp['phKey']
        request['lpFile'] = 'BETUSFILE2\x00'
        request['pSecurityAttributes'] = NULL
        resp = dce.request(request)
        resp.dump()
        # I gotta remove the file now :s
        smb = rpctransport.get_smb_connection()
        smb.deleteFile('ADMIN$', 'System32\\BETUSFILE2')

    def test_hBaseRegSaveKey(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hOpenCurrentUser(dce)
        resp.dump()

        resp = rrp.hBaseRegSaveKey(dce,resp['phKey'],'BETUSFILE2\x00')
        resp.dump()
        # I gotta remove the file now :s
        smb = rpctransport.get_smb_connection()
        smb.deleteFile('ADMIN$', 'System32\\BETUSFILE2')

    def test_BaseRegGetVersion(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegGetVersion()
        request['hKey'] = phKey
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegGetVersion(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hBaseRegGetVersion(dce, phKey)
        resp.dump()

    def test_OpenCurrentConfig(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.OpenCurrentConfig()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_hOpenCurrentConfig(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hOpenCurrentConfig(dce)
        resp.dump()

    def test_BaseRegQueryMultipleValues(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED | rrp.KEY_QUERY_VALUE
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegQueryMultipleValues()

        item1 = rrp.RVALENT()
        item1['ve_valuename'] = 'ProductName\x00'
        item1['ve_valuelen'] = len('ProductName\x00')
        item1['ve_valueptr'] = NULL
        item1['ve_type'] = rrp.REG_SZ
         
        item2 = rrp.RVALENT()
        item2['ve_valuename'] = 'SystemRoot\x00'
        item2['ve_valuelen'] = len('SystemRoot\x00')
        item1['ve_valueptr'] = NULL
        item2['ve_type'] = rrp.REG_SZ

        item3 = rrp.RVALENT()
        item3['ve_valuename'] = 'EditionID\x00'
        item3['ve_valuelen'] = len('EditionID\x00')
        item3['ve_valueptr'] = NULL
        item3['ve_type'] = rrp.REG_SZ

        request['hKey'] = resp['phkResult']
        request['val_listIn'].append(item1)
        request['val_listIn'].append(item2)
        request['val_listIn'].append(item3)
        request['num_vals'] = len(request['val_listIn'])
        request['lpvalueBuf'] = list(' '*128)
        request['ldwTotsize'] = 128
        resp = dce.request(request)
        resp.dump()

    def test_hBaseRegQueryMultipleValues(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hBaseRegOpenKey(dce, phKey, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00')
        resp.dump()


        valueIn = list()
        item1 = {}
        item1['ValueName'] = 'ProductName\x00'
        item1['ValueType'] = rrp.REG_SZ
        valueIn.append(item1)
         
        item2 = {}
        item2['ValueName'] = 'InstallDate\x00'
        item2['ValueType'] = rrp.REG_DWORD
        valueIn.append(item2)

        item3 = {}
        item3['ValueName'] = 'DigitalProductId\x00'
        item3['ValueType'] = rrp.REG_BINARY
        #valueIn.append(item3)

        resp = rrp.hBaseRegQueryMultipleValues(dce, resp['phkResult'], valueIn)
        #print resp

    def test_BaseRegSaveKeyEx(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.OpenCurrentUser()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegSaveKeyEx()
        request['hKey'] = resp['phKey']
        request['lpFile'] = 'BETUSFILE2\x00'
        request['pSecurityAttributes'] = NULL
        request['Flags'] = 4
        resp = dce.request(request)
        resp.dump()
        # I gotta remove the file now :s
        smb = rpctransport.get_smb_connection()
        smb.deleteFile('ADMIN$', 'System32\\BETUSFILE2')

    def test_hBaseRegSaveKeyEx(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hOpenCurrentUser(dce)
        resp.dump()

        resp = rrp.hBaseRegSaveKeyEx(dce, resp['phKey'], 'BETUSFILE2\x00')
        resp.dump()
        # I gotta remove the file now :s
        smb = rpctransport.get_smb_connection()
        smb.deleteFile('ADMIN$', 'System32\\BETUSFILE2')

    def test_OpenPerformanceText(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.OpenPerformanceText()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_hOpenPerformanceText(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hOpenPerformanceText(dce)
        resp.dump()

    def test_OpenPerformanceNlsText(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.OpenPerformanceNlsText()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

    def test_hOpenPerformanceNlsText(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hOpenPerformanceNlsText(dce)
        resp.dump()

    def test_BaseRegQueryMultipleValues2(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED | rrp.KEY_QUERY_VALUE
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegQueryMultipleValues2()

        item1 = rrp.RVALENT()
        item1['ve_valuename'] = 'ProductName\x00'
        item1['ve_valuelen'] = len('ProductName\x00')
        item1['ve_valueptr'] = NULL
        item1['ve_type'] = rrp.REG_SZ
         
        item2 = rrp.RVALENT()
        item2['ve_valuename'] = 'SystemRoot\x00'
        item2['ve_valuelen'] = len('SystemRoot\x00')
        item1['ve_valueptr'] = NULL
        item2['ve_type'] = rrp.REG_SZ

        item3 = rrp.RVALENT()
        item3['ve_valuename'] = 'EditionID\x00'
        item3['ve_valuelen'] = len('EditionID\x00')
        item3['ve_valueptr'] = NULL
        item3['ve_type'] = rrp.REG_SZ

        request['hKey'] = resp['phkResult']
        request['val_listIn'].append(item1)
        request['val_listIn'].append(item2)
        request['val_listIn'].append(item3)
        request['num_vals'] = len(request['val_listIn'])
        request['lpvalueBuf'] = list(' '*128)
        request['ldwTotsize'] = 128
        resp = dce.request(request)
        resp.dump()

    def test_BaseRegDeleteKeyEx(self):
        dce, rpctransport, phKey = self.connect()
        request = rrp.OpenClassesRoot()
        request['ServerName'] = NULL
        request['samDesired'] = MAXIMUM_ALLOWED 
        resp = dce.request(request)
        resp.dump()
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
        resp.dump()
        phKey = resp['phkResult']

        request = rrp.BaseRegDeleteKeyEx()
        request['hKey'] = regHandle
        request['lpSubKey'] = 'BETO\x00'
        request['AccessMask'] = rrp.KEY_WOW64_32KEY
        request['Reserved'] = 0
        resp = dce.request(request)
        resp.dump()

    def test_BaseRegLoadKey_BaseRegUnLoadKey(self):
        dce, rpctransport, phKey = self.connect()

        request = rrp.BaseRegOpenKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'SECURITY\x00'
        request['dwOptions'] = 0x00000001
        request['samDesired'] = MAXIMUM_ALLOWED 
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegSaveKey()
        request['hKey'] = resp['phkResult']
        request['lpFile'] = 'SEC\x00'
        request['pSecurityAttributes'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegLoadKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'BETUS\x00'
        request['lpFile'] = 'SEC\x00'
        resp = dce.request(request)
        resp.dump()

        request = rrp.BaseRegUnLoadKey()
        request['hKey'] = phKey
        request['lpSubKey'] = 'BETUS\x00'
        resp = dce.request(request)
        resp.dump()

        smb = rpctransport.get_smb_connection()
        smb.deleteFile('ADMIN$', 'System32\\SEC')

    def test_hBaseRegLoadKey_hBaseRegUnLoadKey(self):
        dce, rpctransport, phKey = self.connect()

        resp = rrp.hBaseRegOpenKey(dce,phKey, 'SECURITY\x00')
        resp.dump()

        request = rrp.BaseRegSaveKey()
        request['hKey'] = resp['phkResult']
        request['lpFile'] = 'SEC\x00'
        request['pSecurityAttributes'] = NULL
        resp = dce.request(request)
        resp.dump()

        resp = rrp.hBaseRegLoadKey(dce, phKey,'BETUS\x00', 'SEC\x00' )
        resp.dump()

        resp = rrp.hBaseRegUnLoadKey(dce, phKey, 'BETUS\x00')
        resp.dump()

        smb = rpctransport.get_smb_connection()
        smb.deleteFile('ADMIN$', 'System32\\SEC')


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
        self.rrpStarted = False

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
        self.rrpStarted = False

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
        self.rrpStarted = False


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
