################################################################################
#  Tested so far: 
#  RCloseServiceHandleCall
#  RControlService
#  RDeleteService
#  RLockServiceDatabase
#  RQueryServiceObjectSecurity
#  RQueryServiceStatus
#  RUnlockServiceDatabase
#  RNotifyBootConfigStatus
#  RChangeServiceConfigW
#  RCreateServiceW
#  REnumDependentServicesW
#  REnumServicesStatusW
#  ROpenSCManager
#  ROpenServiceW
#  RQueryServiceConfigW
#  RQueryServiceLockStatusW
#  RStartServiceW
#  CRGetServiceDisplayNameW
#  RGetServiceKeyNameW
#  REnumServiceGroupW
#  RChangeServiceConfig2W
#  RQueryServiceConfig2W
#  RQueryServiceStatusEx
#  REnumServicesStatusExW
#  RNotifyServiceStatusChange
#  RGetNotifyResults
#  RCloseNotifyHandle
#  RControlServiceExW
#  RQueryServiceConfigEx
#
#  Not yet:
#
#  RSetServiceObjectSecurity
#  RSetServiceStatus
#  RCreateServiceWOW64W
#  
################################################################################

import sys
import unittest
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin

class SVCCTLTests(unittest.TestCase):
    def changeServiceAndQuery(self, rpc, cbBufSize, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName):

        try:
            resp = rpc.RChangeServiceConfigW( hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName)

            resp = rpc.RQueryServiceConfigW(hService, cbBufSize)
            #resp.dump()
            # Now let's compare all the results
            if dwServiceType != scmr.SERVICE_NO_CHANGE:
                self.assertTrue( resp['lpServiceConfig']['dwServiceType'] == dwServiceType )
            if dwStartType != scmr.SERVICE_NO_CHANGE:
                self.assertTrue( resp['lpServiceConfig']['dwStartType'] == dwStartType )
            if dwErrorControl != scmr.SERVICE_NO_CHANGE:
                self.assertTrue( resp['lpServiceConfig']['dwErrorControl'] == dwErrorControl )
            if lpBinaryPathName != '':
                self.assertTrue( resp['lpServiceConfig']['lpBinaryPathName'] == lpBinaryPathName )
            if lpBinaryPathName != '':
                self.assertTrue( resp['lpServiceConfig']['lpBinaryPathName'] == lpBinaryPathName )
            if lpLoadOrderGroup != '':
                self.assertTrue( resp['lpServiceConfig']['lpLoadOrderGroup'] == lpLoadOrderGroup )
            #if lpDependencies != '':
            #    self.assertTrue( resp['lpServiceConfig']['lpDependencies'] == lpDependencies[:-4]+'/\x00\x00\x00')
            if lpServiceStartName != '':
                self.assertTrue( resp['lpServiceConfig']['lpServiceStartName'] == lpServiceStartName )
            if lpDisplayName != '':
                self.assertTrue( resp['lpServiceConfig']['lpDisplayName'] == lpDisplayName )
            #if lpdwTagId != scmr.SERVICE_NO_CHANGE:
            #    if resp['lpServiceConfig']['dwTagId']['Data'] != lpdwTagId:
            #        print "ERROR %s" % 'lpdwTagId'
        except:
            resp = rpc.RDeleteService(hService)
            raise

    def changeServiceAndQuery2(self, rpc, info, changeDone):
        serviceHandle = info['hService']
        dwInfoLevel = info['Info']['tag']
        cbBuffSize = 0
        request = scmr.RQueryServiceConfig2W()
        request['hService'] = serviceHandle
        request['dwInfoLevel'] = dwInfoLevel
        request['cbBufSize'] = cbBuffSize
        resp = rpc.request(request)
        request['cbBufSize'] = resp['pcbBytesNeeded'] 
        resp = rpc.request(request)
        arrayData = ''.join(resp['lpBuffer'])
        if dwInfoLevel == 1:
           self.assertTrue(arrayData[4:].decode('utf-16le') == changeDone)
        elif dwInfoLevel == 2:
           offset = unpack('<L', arrayData[4:][:4])[0]
           self.assertTrue(arrayData[offset:][:len(changeDone)*2].decode('utf-16le') == changeDone)
        elif dwInfoLevel == 3:
           self.assertTrue( unpack('<L', arrayData)[0] == changeDone)
        elif dwInfoLevel == 4:
           self.assertTrue( unpack('<L', arrayData)[0] == changeDone)
        elif dwInfoLevel == 5:
           self.assertTrue( unpack('<L', arrayData)[0] == changeDone)
        elif dwInfoLevel == 6:
           changeDone = ''.join(changeDone).decode('utf-16le')
           self.assertTrue(arrayData[4:].decode('utf-16le') == changeDone)
        elif dwInfoLevel == 7:
           self.assertTrue( unpack('<L', arrayData)[0] == changeDone)
 
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_dport(self.dport)
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
        dce.bind(scmr.MSRPC_UUID_SVCCTL)
        rpc = scmr.DCERPCSvcCtl(dce)
        lpMachineName = 'DUMMY\x00'
        lpDatabaseName = 'ServicesActive\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS | scmr.SC_MANAGER_ENUMERATE_SERVICE
        
        resp = rpc.ROpenSCManagerW(lpMachineName, lpDatabaseName, desiredAccess)
        scHandle = resp['lpScHandle']

        return rpc, rpctransport, scHandle

    def test_RChangeServiceConfig2W(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpServiceName = 'TESTSVC\x00'
        lpDisplayName = 'DisplayName\x00'
        dwDesiredAccess = scmr.SERVICE_ALL_ACCESS
        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwStartType = scmr.SERVICE_DEMAND_START
        dwErrorControl = scmr.SERVICE_ERROR_NORMAL
        lpBinaryPathName = 'binaryPath\x00'
        lpLoadOrderGroup = ''
        lpdwTagId = ''
        lpDependencies = ''
        dwDependSize = 0
        lpServiceStartName = ''
        lpPassword = ''
        dwPwSize = 0
        resp = rpc.RCreateServiceW(scHandle, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize)
        #resp.dump()
        newHandle = resp['lpServiceHandle'] 
        error = False
        try:
            request = scmr.RChangeServiceConfig2W()
            request['hService'] = newHandle
            request['Info']['tag'] = 1
            request['Info']['psd']['lpDescription'] = u'betobeto\x00'
            resp = rpc.request(request)
            #resp.dump()
            self.changeServiceAndQuery2(rpc, request, request['Info']['psd']['lpDescription'])
            request['Info']['tag'] = 2
            request['Info']['psfa']['lpRebootMsg'] = u'rebootMsg\00'
            request['Info']['psfa']['lpCommand'] = u'lpCommand\00'
            resp = rpc.request(request)
            #resp.dump()
            self.changeServiceAndQuery2(rpc, request, request['Info']['psfa']['lpRebootMsg'])
            request['Info']['tag'] = 3
            request['Info']['psda']['fDelayedAutostart'] = 1
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['psda']['fDelayedAutostart'])
            request['Info']['tag'] = 4
            request['Info']['psfaf']['fFailureActionsOnNonCrashFailures'] = 1
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['psfaf']['fFailureActionsOnNonCrashFailures'])
            request['Info']['tag'] = 5
            request['Info']['pssid']['dwServiceSidType'] = 1
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['pssid']['dwServiceSidType'])
            request['Info']['tag'] = 6
            request['Info']['psrp']['pRequiredPrivileges'] = list(u'SeAssignPrimaryTokenPrivilege\x00\x00'.encode('utf-16le'))
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['psrp']['pRequiredPrivileges'])
            request['Info']['tag'] = 7
            request['Info']['psps']['dwPreshutdownTimeout'] = 22
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['psps']['dwPreshutdownTimeout'])
            request['Info']['tag'] = 8
            #request.dump()
            trigger = scmr.SERVICE_TRIGGER()
            trigger['dwTriggerType'] = scmr.SERVICE_TRIGGER_TYPE_DOMAIN_JOIN
            trigger['dwAction'] = scmr.SERVICE_TRIGGER_ACTION_SERVICE_START
            trigger['pTriggerSubtype'] = string_to_bin(scmr.DOMAIN_JOIN_GUID)
            item = scmr.SERVICE_TRIGGER_SPECIFIC_DATA_ITEM()
            item['dwDataType'] = scmr.SERVICE_TRIGGER_DATA_TYPE_STRING
            item['pData'] = list(u'FREEFLY\x00'.encode('utf-16le'))
            #trigger['pDataItems'].append(item)
            trigger['pDataItems'] = NULL
            request['Info']['psti']['pTriggers'].append(trigger)
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, '\x00')
            request['Info']['tag'] = 9
            request['Info']['pspn']['usPreferredNode'] = 22
            resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['pspn']['usPreferredNode'])
            request['Info']['tag'] = 10
            request['Info']['psri']['eLowestRunLevel'] = 1
            # This one doesn't work
            #resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['psri']['eLowestRunLevel'])
            request['Info']['tag'] = 11
            request['Info']['psma']['fIsManagedAccount'] = 1
            # This one doesn't work
            #resp = rpc.request(request)
            self.changeServiceAndQuery2(rpc, request, request['Info']['psma']['fIsManagedAccount'])

        except Exception, e:
            import traceback
            traceback.print_exc()
            print e
            error = True
            pass

        resp = rpc.RDeleteService(newHandle)
        resp = rpc.RCloseServiceHandle(newHandle)
        resp = rpc.RCloseServiceHandle(scHandle)
        if error:
            self.assertTrue( 1 == 0 )
    
    def test_REnumServicesStatusExW(self):
        rpc, rpctransport, scHandle  = self.connect()

        request = scmr.REnumServicesStatusExW()
        request['hSCManager'] = scHandle
        request['InfoLevel'] = scmr.SC_STATUS_PROCESS_INFO
        request['dwServiceType'] = scmr.SERVICE_WIN32_OWN_PROCESS
        request['dwServiceState'] = scmr.SERVICE_STATE_ALL
        request['lpResumeIndex'] = NULL
        request['pszGroupName'] = NULL
        request['cbBufSize'] = 0
        #request.dump()
        #print "\n"

        # Request again with the right bufSize
        resp = rpc.request(request)
        #resp.dump()
        request['cbBufSize'] = resp['pcbBytesNeeded']
        resp = rpc.request(request)
        #resp.dump()

    def test_RQueryServiceStatusEx(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()

        serviceHandle = resp['lpServiceHandle']
  
        request = scmr.RQueryServiceStatusEx()
        request['hService'] = serviceHandle
        request['InfoLevel'] = scmr.SC_STATUS_PROCESS_INFO
        request['cbBufSize'] = 100

        resp = rpc.request(request)
        array = ''.join(resp['lpBuffer'])
        status = scmr.SERVICE_STATUS_PROCESS(array)
        #status.dump()

    def test_REnumServiceGroupW(self):
        rpc, rpctransport, scHandle  = self.connect()


        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwServiceState = scmr.SERVICE_STATE_ALL
        cbBufSize = 1000
        lpResumeIndex = 0
        pszGroupName = 'RemoteRegistry\x00'

        try:
            resp = rpc.REnumServiceGroupW(scHandle, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex, pszGroupName )
            #resp.dump()
        except Exception, e:
           if str(e).find('ERROR_SERVICE_DOES_NOT_EXISTS') <= 0:
               raise

        resp = rpc.RCloseServiceHandle(scHandle)

    def test_RQueryServiceConfigEx(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpServiceName = 'RemoteRegistry\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RQueryServiceConfigEx()
        request['hService'] = serviceHandle
        request['dwInfoLevel'] = 0x00000008
        #request.dump()

        resp = rpc.request(request)
        #resp.dump()

    def test_RControlServiceExW(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RControlServiceExW()
        request['hService'] = serviceHandle
        request['dwControl'] = scmr.SERVICE_CONTROL_STOP
        request['dwInfoLevel'] = 1
        request['pControlInParams'] = NULL

        resp = rpc.request(request)
        resp.dump()


    def test_RNotifyServiceStatusChange(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RNotifyServiceStatusChange()
        request['hService'] =serviceHandle 
        request['NotifyParams']['tag']  = 1
        request['NotifyParams']['pStatusChangeParam1']['dwNotifyMask'] = scmr.SERVICE_NOTIFY_RUNNING
        request['pClientProcessGuid'] = '0'*16
        #request.dump()
        resp = rpc.request(request)
        #resp.dump()

        request = scmr.RCloseNotifyHandle()
        request['phNotify'] = resp['phNotify']

        resp = rpc.request(request)
        #resp.dump()

        request = scmr.RGetNotifyResults()
        request['hNotify'] = resp['phNotify']

        resp = rpc.request(request)
        #resp.dump()

    def test_RGetServiceDisplayNameW(self):
        rpc, rpctransport, scHandle  = self.connect()

        lpServiceName = 'PlugPlay\x00'
        lpcchBuffer = len(lpServiceName)+100

        resp = rpc.RGetServiceDisplayNameW(scHandle, lpServiceName, lpcchBuffer)

        resp = rpc.RCloseServiceHandle(scHandle)

    def test_RGetServiceKeyNameW(self):
        rpc, rpctransport, scHandle  = self.connect()

        lpDisplayName = 'Plug and Play\x00'
        lpcchBuffer = len(lpDisplayName)+100

        resp = rpc.RGetServiceKeyNameW(scHandle, lpDisplayName, lpcchBuffer)

        resp = rpc.RCloseServiceHandle(scHandle)

    def test_RStartServiceW(self):
        rpc, rpctransport, scHandle  = self.connect()

        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()
        serviceHandle = resp['lpServiceHandle']
  
        try:
            resp = rpc.RStartServiceW(serviceHandle, 3, ['arg1\x00', 'arg2\x00', 'arg3\x00'] )
        except Exception, e:
           if str(e).find('ERROR_SERVICE_ALREADY_RUNNING') <= 0:
               raise
        resp = rpc.RCloseServiceHandle(scHandle)

    def test_RQueryServiceLockStatusW(self):
        rpc, rpctransport, scHandle  = self.connect()

        pcbBytesNeeded = 1000
        resp = rpc.RQueryServiceLockStatusW(scHandle, pcbBytesNeeded)

        resp = rpc.RCloseServiceHandle(scHandle)

    def test_enumservices(self):
        rpc, rpctransport, scHandle  = self.connect()

        #####################
        # EnumServicesStatusW
        dwServiceType = scmr.SERVICE_KERNEL_DRIVER | scmr.SERVICE_FILE_SYSTEM_DRIVER | scmr.SERVICE_WIN32_OWN_PROCESS | scmr.SERVICE_WIN32_SHARE_PROCESS
        dwServiceState = scmr.SERVICE_STATE_ALL
        cbBufSize = 0
        resp = rpc.REnumServicesStatusW(scHandle, dwServiceType, dwServiceState, cbBufSize, 0)
        #resp.dump()
        cbBufSize = resp['pcbBytesNeeded'] 
        resp = rpc.REnumServicesStatusW(scHandle, dwServiceType, dwServiceState, cbBufSize, 0)
        #resp.dump()

        resp = rpc.RCloseServiceHandle(scHandle)

    def test_create_change_delete(self):
        rpc, rpctransport, scHandle  = self.connect()

        #####################
        # Create / Change /  Query / Delete a service
        lpServiceName = 'TESTSVC\x00'
        lpDisplayName = 'DisplayName\x00'
        dwDesiredAccess = scmr.SERVICE_ALL_ACCESS
        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwStartType = scmr.SERVICE_DEMAND_START
        dwErrorControl = scmr.SERVICE_ERROR_NORMAL
        lpBinaryPathName = 'binaryPath\x00'
        lpLoadOrderGroup = ''
        lpdwTagId = ''
        lpDependencies = ''
        dwDependSize = 0
        lpServiceStartName = ''
        lpPassword = ''
        dwPwSize = 0
        resp = rpc.RCreateServiceW(scHandle, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize)
        #resp.dump()
        newHandle = resp['lpServiceHandle'] 

        # Aca hay que chequear cada uno de los items
        cbBufSize = 0
        resp = rpc.RQueryServiceConfigW(newHandle, cbBufSize)
        #resp.dump()
        cbBufSize = resp['pcbBytesNeeded']+100

        # Now that we have cbBufSize, let's start changing everything on the service
        dwServiceType = scmr.SERVICE_WIN32_SHARE_PROCESS
        dwStartType = scmr.SERVICE_NO_CHANGE
        dwErrorControl = scmr.SERVICE_NO_CHANGE
        lpBinaryPathName = ''
        lpLoadOrderGroup = ''
        lpDependencies = ''
        dwDependSize = 0
        lpServiceStartName = ''
        lpPassword = ''
        dwPwSize = 0
        lpDisplayName = ''
        lpdwTagId = ''

        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        dwServiceType = scmr.SERVICE_NO_CHANGE        

        dwStartType = scmr.SERVICE_DISABLED
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        dwStartType = scmr.SERVICE_NO_CHANGE        

        dwErrorControl = scmr.SERVICE_ERROR_SEVERE
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        dwErrorControl = scmr.SERVICE_NO_CHANGE        

        lpBinaryPathName = 'BETOBETO\x00'
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpBinaryPathName = ''

        lpLoadOrderGroup = 'KKKK\x00'
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpLoadOrderGroup = ''

        #lpdwTagId = [0]
        #self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        #lpdwTagId = ''

        lpDependencies = 'RemoteRegistry\x00\x00'.encode('utf-16le')
        dwDependSize = len(lpDependencies)
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpDependencies = ''
        dwDependSize = 0

        lpServiceStartName = '.\\Administrator\x00'
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpServiceStartName = ''

        lpPassword = 'mypwd\x00'.encode('utf-16le')
        s = rpctransport.get_smb_connection()
        key = s.getSessionKey()
        lpPassword = encryptSecret(key, lpPassword)
        dwPwSize = len(lpPassword)
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpPassword = ''
        dwPwSize = 0

        lpDisplayName = 'MANOLO\x00'
        self.changeServiceAndQuery(rpc, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpDisplayName = ''

        resp = rpc.RDeleteService(newHandle)
        resp = rpc.RCloseServiceHandle(newHandle)
        resp = rpc.RCloseServiceHandle(scHandle)

    def test_query(self):
        rpc, rpctransport, scHandle  = self.connect()

        ############################
        # Query Service Status / Enum Dependent
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()

        serviceHandle = resp['lpServiceHandle']
 
        resp = rpc.RQueryServiceStatus(serviceHandle)

        cbBufSize = 0
        resp = rpc.REnumDependentServicesW(serviceHandle, scmr.SERVICE_STATE_ALL,cbBufSize )
        #resp.dump()
        cbBufSize = resp['pcbBytesNeeded']
        resp = rpc.REnumDependentServicesW(serviceHandle, scmr.SERVICE_STATE_ALL,cbBufSize )
        #resp.dump()
        resp = rpc.RCloseServiceHandle(serviceHandle)
        resp = rpc.RCloseServiceHandle(scHandle)

    def test_lock_unlock(self):
        rpc, rpctransport, scHandle  = self.connect()
        
        resp = rpc.RLockServiceDatabase(scHandle)
        lockHandle = resp['lpLock']
        resp = rpc.RUnlockServiceDatabase(lockHandle)

        resp = rpc.RCloseServiceHandle(scHandle)

    def test_query_set_object_security(self):
        rpc, rpctransport, scHandle  = self.connect()
        
        try:
            resp = rpc.RQueryServiceObjectSecurity(scHandle, scmr.DACL_SECURITY_INFORMATION, 0)
            #resp.dump()
        except Exception, e:
           if str(e).find('ERROR_ACCESS_DENIED') <= 0:
               raise
 
        resp = rpc.RCloseServiceHandle(scHandle)

    def test_notify_config(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpMachineName = 'DUMMY\x00'
        
        try:
            resp = rpc.RNotifyBootConfigStatus(lpMachineName, 0x0)
            #resp.dump()
        except scmr.SVCCTLSessionError, e:
           if str(e).find('ERROR_BOOT_ALREADY_ACCEPTED') <= 0:
               raise
 
        resp = rpc.RCloseServiceHandle(scHandle)

    def test_RControlServiceCall(self):
        rpc, rpctransport, scHandle  = self.connect()
        lpServiceName = 'WSearch\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()

        serviceHandle = resp['lpServiceHandle']
 
        try:
            resp = rpc.RControlService(serviceHandle, scmr.SERVICE_CONTROL_STOP)
        except Exception, e:
            print e
            pass

        resp = rpc.RCloseServiceHandle(serviceHandle)
        import time
        time.sleep(1)
        resp = rpc.ROpenServiceW(scHandle, lpServiceName, desiredAccess )
        #resp.dump()

        serviceHandle = resp['lpServiceHandle']

        resp = rpc.RStartServiceW(serviceHandle, 0, '' )
        #resp.dump()
        return 

class SMBTransport(SVCCTLTests):
    def setUp(self):
        SVCCTLTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        self.username = 'test'
        self.domain   = ''
        self.serverName = ''
        self.password = 'test'
        self.machine  = '172.16.123.191'
        self.stringBinding = r'ncacn_np:%s[\pipe\svcctl]' % self.machine
        self.dport = 445
        self.hashes   = ''


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
