###############################################################################
#  Tested so far: 
#  hRCloseServiceHandleCall
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
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser
from struct import unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import scmr, epm
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.uuid import string_to_bin
from impacket import ntlm


class SCMRTests(unittest.TestCase):
    def changeServiceAndQuery(self, dce, cbBufSize, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName):

        try:
            resp = scmr.hRChangeServiceConfigW( dce, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName)

            resp = scmr.hRQueryServiceConfigW(dce, hService)
            resp.dump()
            # Now let's compare all the results
            if dwServiceType != scmr.SERVICE_NO_CHANGE:
                self.assertTrue( resp['lpServiceConfig']['dwServiceType'] == dwServiceType )
            if dwStartType != scmr.SERVICE_NO_CHANGE:
                self.assertTrue( resp['lpServiceConfig']['dwStartType'] == dwStartType )
            if dwErrorControl != scmr.SERVICE_NO_CHANGE:
                self.assertTrue( resp['lpServiceConfig']['dwErrorControl'] == dwErrorControl )
            if lpBinaryPathName != NULL:
                self.assertTrue( resp['lpServiceConfig']['lpBinaryPathName'] == lpBinaryPathName )
            if lpBinaryPathName != NULL:
                self.assertTrue( resp['lpServiceConfig']['lpBinaryPathName'] == lpBinaryPathName )
            if lpLoadOrderGroup != NULL:
                self.assertTrue( resp['lpServiceConfig']['lpLoadOrderGroup'] == lpLoadOrderGroup )
            #if lpDependencies != '':
            #    self.assertTrue( resp['lpServiceConfig']['lpDependencies'] == lpDependencies[:-4]+'/\x00\x00\x00')
            if lpServiceStartName != NULL:
                self.assertTrue( resp['lpServiceConfig']['lpServiceStartName'] == lpServiceStartName )
            if lpDisplayName != NULL:
                self.assertTrue( resp['lpServiceConfig']['lpDisplayName'] == lpDisplayName )
            #if lpdwTagId != scmr.SERVICE_NO_CHANGE:
            #    if resp['lpServiceConfig']['dwTagId']['Data'] != lpdwTagId:
            #        print "ERROR %s" % 'lpdwTagId'
        except:
            resp = scmr.hRDeleteService(dce, hService)
            raise

    def changeServiceAndQuery2(self, dce, info, changeDone):
        serviceHandle = info['hService']
        dwInfoLevel = info['Info']['Union']['tag']
        cbBuffSize = 0
        request = scmr.RQueryServiceConfig2W()
        request['hService'] = serviceHandle
        request['dwInfoLevel'] = dwInfoLevel
        request['cbBufSize'] = cbBuffSize
        try:
            resp = dce.request(request)
        except Exception, e:
            if str(e).find('ERROR_INSUFFICIENT_BUFFER') <= 0:
                raise
            else: 
                resp = e.get_packet()

        request['cbBufSize'] = resp['pcbBytesNeeded'] 
        resp = dce.request(request)
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
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        #dce.set_max_fragment_size(32)
        dce.connect()
        if self.__class__.__name__ == 'TCPTransport':
            dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(scmr.MSRPC_UUID_SCMR)
        #rpc = scmr.DCERPCSvcCtl(dce)
        lpMachineName = 'DUMMY\x00'
        lpDatabaseName = 'ServicesActive\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS | scmr.SC_MANAGER_ENUMERATE_SERVICE
        
        resp = scmr.hROpenSCManagerW(dce,lpMachineName, lpDatabaseName, desiredAccess)
        scHandle = resp['lpScHandle']

        return dce, rpctransport, scHandle

    def test_RChangeServiceConfig2W(self):
        dce, rpctransport, scHandle  = self.connect()
        lpServiceName = 'TESTSVC\x00'
        lpDisplayName = 'DisplayName\x00'
        dwDesiredAccess = scmr.SERVICE_ALL_ACCESS
        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwStartType = scmr.SERVICE_DEMAND_START
        dwErrorControl = scmr.SERVICE_ERROR_NORMAL
        lpBinaryPathName = 'binaryPath\x00'
        lpLoadOrderGroup = NULL
        lpdwTagId = NULL 
        lpDependencies = NULL
        dwDependSize = 0
        lpServiceStartName = NULL
        lpPassword = NULL
        dwPwSize = 0
        resp = scmr.hRCreateServiceW(dce, scHandle, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize)
        resp.dump()
        newHandle = resp['lpServiceHandle'] 
        error = False
        try:
            request = scmr.RChangeServiceConfig2W()
            request['hService'] = newHandle
            request['Info']['dwInfoLevel'] = 1
            request['Info']['Union']['tag'] = 1
            request['Info']['Union']['psd']['lpDescription'] = u'betobeto\x00'
            resp = dce.request(request)
            resp.dump()
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psd']['lpDescription'])
            request['Info']['dwInfoLevel'] = 2
            request['Info']['Union']['tag'] = 2
            request['Info']['Union']['psfa']['lpRebootMsg'] = u'rebootMsg\00'
            request['Info']['Union']['psfa']['lpCommand'] = u'lpCommand\00'
            resp = dce.request(request)
            resp.dump()
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psfa']['lpRebootMsg'])
            request['Info']['dwInfoLevel'] = 3
            request['Info']['Union']['tag'] = 3
            request['Info']['Union']['psda']['fDelayedAutostart'] = 1
            resp = dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psda']['fDelayedAutostart'])
            request['Info']['dwInfoLevel'] = 4
            request['Info']['Union']['tag'] = 4
            request['Info']['Union']['psfaf']['fFailureActionsOnNonCrashFailures'] = 1
            resp = dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psfaf']['fFailureActionsOnNonCrashFailures'])
            request['Info']['dwInfoLevel'] = 5
            request['Info']['Union']['tag'] = 5
            request['Info']['Union']['pssid']['dwServiceSidType'] = 1
            resp = dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['pssid']['dwServiceSidType'])
            request['Info']['dwInfoLevel'] = 6
            request['Info']['Union']['tag'] = 6
            request['Info']['Union']['psrp']['pRequiredPrivileges'] = list(u'SeAssignPrimaryTokenPrivilege\x00\x00'.encode('utf-16le'))
            resp = dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psrp']['pRequiredPrivileges'])
            request['Info']['dwInfoLevel'] = 7
            request['Info']['Union']['tag'] = 7
            request['Info']['Union']['psps']['dwPreshutdownTimeout'] = 22
            resp = dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psps']['dwPreshutdownTimeout'])
            request['Info']['dwInfoLevel'] = 8
            request['Info']['Union']['tag'] = 8
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
            request['Info']['Union']['psti']['pTriggers'].append(trigger)
            resp = dce.request(request)
            #self.changeServiceAndQuery2(dce, request, '\x00')
            request['Info']['dwInfoLevel'] = 9
            request['Info']['Union']['tag'] = 9
            request['Info']['Union']['pspn']['usPreferredNode'] = 22
            # This one doesn't work
            #resp = dce.request(request)
            #self.changeServiceAndQuery2(dce, request, request['Info']['Union']['pspn']['usPreferredNode'])
            request['Info']['dwInfoLevel'] = 10
            request['Info']['Union']['tag'] = 10
            request['Info']['Union']['psri']['eLowestRunLevel'] = 1
            # This one doesn't work
            #resp = dce.request(request)
            #self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psri']['eLowestRunLevel'])
            request['Info']['dwInfoLevel'] = 11
            request['Info']['Union']['tag'] = 11
            request['Info']['Union']['psma']['fIsManagedAccount'] = 1
            # This one doesn't work
            #resp = dce.request(request)
            #self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psma']['fIsManagedAccount'])

        except Exception, e:
            import traceback
            traceback.print_exc()
            print e
            error = True
            pass

        resp = scmr.hRDeleteService(dce, newHandle)
        resp = scmr.hRCloseServiceHandle(dce, newHandle)
        resp = scmr.hRCloseServiceHandle(dce, scHandle)
        if error:
            self.assertTrue( 1 == 0 )
    
    def test_REnumServicesStatusExW(self):
        dce, rpctransport, scHandle  = self.connect()

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
        try:
            resp = dce.request(request)
        except Exception, e:
            if str(e).find('ERROR_MORE_DATA') <= 0:
                raise
            else: 
                resp = e.get_packet()
        resp.dump()
        request['cbBufSize'] = resp['pcbBytesNeeded']
        resp = dce.request(request)
        resp.dump()

    def test_RQueryServiceStatusEx(self):
        dce, rpctransport, scHandle  = self.connect()
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']
  
        request = scmr.RQueryServiceStatusEx()
        request['hService'] = serviceHandle
        request['InfoLevel'] = scmr.SC_STATUS_PROCESS_INFO
        request['cbBufSize'] = 100

        resp = dce.request(request)
        array = ''.join(resp['lpBuffer'])
        status = scmr.SERVICE_STATUS_PROCESS(array)
        #status.dump()

    # ToDo
    def te_REnumServiceGroupW(self):
        dce, rpctransport, scHandle  = self.connect()


        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwServiceState = scmr.SERVICE_STATE_ALL
        cbBufSize = 10
        lpResumeIndex = 0
        pszGroupName = 'RemoteRegistry\x00'

        try:
            resp = scmr.hREnumServiceGroupW(dce, scHandle, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex, pszGroupName )
            resp.dump()
        except Exception, e:
           if str(e).find('ERROR_SERVICE_DOES_NOT_EXISTS') <= 0:
               raise

        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RQueryServiceConfigEx(self):
        dce, rpctransport, scHandle  = self.connect()
        lpServiceName = 'RemoteRegistry\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RQueryServiceConfigEx()
        request['hService'] = serviceHandle
        request['dwInfoLevel'] = 0x00000008
        #request.dump()

        resp = dce.request(request)
        resp.dump()

    # ToDo
    def te_RControlServiceExW(self):
        dce, rpctransport, scHandle  = self.connect()
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RControlServiceExW()
        request['hService'] = serviceHandle
        request['dwControl'] = scmr.SERVICE_CONTROL_STOP
        request['dwInfoLevel'] = 1
        # This is not working, don't know exactly why
        request['pControlInParams']['dwReason'] = 0x20000000
        request['pControlInParams']['pszComment'] = 'nada\x00'
        request['pControlInParams'] = NULL

        resp = dce.request(request)

        resp.dump()

    # ToDo
    def te_RNotifyServiceStatusChange(self):
        dce, rpctransport, scHandle  = self.connect()
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RNotifyServiceStatusChange()
        request['hService'] =serviceHandle 
        request['NotifyParams']['tag']  = 1
        request['NotifyParams']['pStatusChangeParam1']['dwNotifyMask'] = scmr.SERVICE_NOTIFY_RUNNING
        request['pClientProcessGuid'] = '0'*16
        #request.dump()
        resp = dce.request(request)
        resp.dump()

        request = scmr.RCloseNotifyHandle()
        request['phNotify'] = resp['phNotify']

        resp = dce.request(request)
        resp.dump()

        request = scmr.RGetNotifyResults()
        request['hNotify'] = resp['phNotify']

        resp = dce.request(request)
        resp.dump()

    def test_RGetServiceDisplayNameW(self):
        dce, rpctransport, scHandle  = self.connect()

        lpServiceName = 'PlugPlay\x00'
        lpcchBuffer = len(lpServiceName)+100

        resp = scmr.hRGetServiceDisplayNameW(dce, scHandle, lpServiceName, lpcchBuffer)

        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RGetServiceKeyNameW(self):
        dce, rpctransport, scHandle  = self.connect()

        lpDisplayName = 'Plug and Play\x00'
        lpcchBuffer = len(lpDisplayName)+100

        resp = scmr.hRGetServiceKeyNameW(dce, scHandle, lpDisplayName, lpcchBuffer)

        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RStartServiceW(self):
        dce, rpctransport, scHandle  = self.connect()

        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()
        serviceHandle = resp['lpServiceHandle']
  
        try:
            resp = scmr.hRStartServiceW(dce, serviceHandle, 3, ['arg1\x00', 'arg2\x00', 'arg3\x00'] )
        except Exception, e:
           if str(e).find('ERROR_SERVICE_ALREADY_RUNNING') <= 0:
               raise
        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RQueryServiceLockStatusW(self):
        dce, rpctransport, scHandle  = self.connect()

        pcbBytesNeeded = 1000
        resp = scmr.hRQueryServiceLockStatusW(dce, scHandle, pcbBytesNeeded)

        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_enumservices(self):
        dce, rpctransport, scHandle  = self.connect()

        #####################
        # EnumServicesStatusW
        dwServiceType = scmr.SERVICE_KERNEL_DRIVER | scmr.SERVICE_FILE_SYSTEM_DRIVER | scmr.SERVICE_WIN32_OWN_PROCESS | scmr.SERVICE_WIN32_SHARE_PROCESS
        dwServiceState = scmr.SERVICE_STATE_ALL
        cbBufSize = 0
        resp = scmr.hREnumServicesStatusW(dce, scHandle, dwServiceType, dwServiceState)

        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_create_change_delete(self):
        dce, rpctransport, scHandle  = self.connect()

        #####################
        # Create / Change /  Query / Delete a service
        lpServiceName = 'TESTSVC\x00'
        lpDisplayName = 'DisplayName\x00'
        dwDesiredAccess = scmr.SERVICE_ALL_ACCESS
        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwStartType = scmr.SERVICE_DEMAND_START
        dwErrorControl = scmr.SERVICE_ERROR_NORMAL
        lpBinaryPathName = 'binaryPath\x00'
        lpLoadOrderGroup = NULL
        lpdwTagId = NULL
        lpDependencies = NULL
        dwDependSize = 0
        lpServiceStartName = NULL
        lpPassword = NULL
        dwPwSize = 0
        resp = scmr.hRCreateServiceW(dce, scHandle, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize)
        resp.dump()
        newHandle = resp['lpServiceHandle'] 

        # Aca hay que chequear cada uno de los items
        cbBufSize = 0
        try:
            resp = scmr.hRQueryServiceConfigW(dce, newHandle)
        except Exception, e:
            if str(e).find('ERROR_INSUFFICIENT_BUFFER') <= 0:
                raise
            else: 
                resp = e.get_packet()

        resp.dump()
        cbBufSize = resp['pcbBytesNeeded']+100

        # Now that we have cbBufSize, let's start changing everything on the service
        dwServiceType = scmr.SERVICE_WIN32_SHARE_PROCESS
        dwStartType = scmr.SERVICE_NO_CHANGE
        dwErrorControl = scmr.SERVICE_NO_CHANGE
        lpBinaryPathName = NULL
        lpLoadOrderGroup = NULL
        lpDependencies = NULL
        dwDependSize = 0
        lpServiceStartName = NULL
        lpPassword = NULL
        dwPwSize = 0
        lpDisplayName = NULL
        lpdwTagId = NULL

        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        dwServiceType = scmr.SERVICE_NO_CHANGE        

        dwStartType = scmr.SERVICE_DISABLED
        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        dwStartType = scmr.SERVICE_NO_CHANGE        

        dwErrorControl = scmr.SERVICE_ERROR_SEVERE
        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        dwErrorControl = scmr.SERVICE_NO_CHANGE        

        lpBinaryPathName = 'BETOBETO\x00'
        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpBinaryPathName = NULL 

        lpLoadOrderGroup = 'KKKK\x00'
        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpLoadOrderGroup = NULL

        #lpdwTagId = [0]
        #self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        #lpdwTagId = ''

        lpDependencies = 'RemoteRegistry\x00\x00'.encode('utf-16le')
        dwDependSize = len(lpDependencies)
        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpDependencies = NULL
        dwDependSize = 0

        lpServiceStartName = '.\\Administrator\x00'
        self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
        lpServiceStartName = NULL

        if self.__class__.__name__ == 'SMBTransport':
            lpPassword = 'mypwd\x00'.encode('utf-16le')
            s = rpctransport.get_smb_connection()
            key = s.getSessionKey()
            lpPassword = encryptSecret(key, lpPassword)
            dwPwSize = len(lpPassword)
            self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
            lpPassword = NULL
            dwPwSize = 0

            lpDisplayName = 'MANOLO\x00'
            self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
            lpDisplayName = NULL

        resp = scmr.hRDeleteService(dce, newHandle)
        resp = scmr.hRCloseServiceHandle(dce, newHandle)
        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_query(self):
        dce, rpctransport, scHandle  = self.connect()

        ############################
        # Query Service Status / Enum Dependent
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']
 
        resp = scmr.hRQueryServiceStatus(dce, serviceHandle)

        cbBufSize = 0
        try:
            resp = scmr.hREnumDependentServicesW(dce, serviceHandle, scmr.SERVICE_STATE_ALL,cbBufSize )
            resp.dump()
        except scmr.DCERPCSessionError, e:
           if str(e).find('ERROR_MORE_DATA') <= 0:
               raise
           else:
               resp = e.get_packet()

        resp.dump()
        cbBufSize = resp['pcbBytesNeeded']
        resp = scmr.hREnumDependentServicesW(dce, serviceHandle, scmr.SERVICE_STATE_ALL,cbBufSize )
        resp.dump()
        resp = scmr.hRCloseServiceHandle(dce, serviceHandle)
        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_lock_unlock(self):
        dce, rpctransport, scHandle  = self.connect()
        
        resp = scmr.hRLockServiceDatabase(dce, scHandle)
        lockHandle = resp['lpLock']
        resp = scmr.hRUnlockServiceDatabase(dce, lockHandle)

        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_query_set_object_security(self):
        dce, rpctransport, scHandle  = self.connect()
        
        try:
            resp = scmr.hRQueryServiceObjectSecurity(dce, scHandle, scmr.DACL_SECURITY_INFORMATION, 0)
            resp.dump()
        except Exception, e:
           if str(e).find('rpc_s_access_denied') <= 0:
               raise
 
        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def atest_notify_config(self):
        dce, rpctransport, scHandle  = self.connect()
        lpMachineName = 'DUMMY\x00'
        
        try:
            resp = scmr.hRNotifyBootConfigStatus(dce, lpMachineName, 0x0)
            resp.dump()
        except scmr.DCERPCSessionError, e:
           if str(e).find('ERROR_BOOT_ALREADY_ACCEPTED') <= 0:
               raise
 
        resp = scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RControlServiceCall(self):
        dce, rpctransport, scHandle  = self.connect()
        lpServiceName = 'CryptSvc\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']
 
        try:
            req = scmr.RControlService()
            req['hService'] = serviceHandle
            req['dwControl'] = scmr.SERVICE_CONTROL_STOP
            resp = dce.request(req)
        except Exception, e:
            if str(e).find('ERROR_DEPENDENT_SERVICES_RUNNING') < 0 and str(e).find('ERROR_SERVICE_NOT_ACTIVE') < 0:
                raise
            pass

        resp = scmr.hRCloseServiceHandle(dce, serviceHandle)
        import time
        time.sleep(1)
        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']

        try:
            resp = scmr.hRStartServiceW(dce, serviceHandle, 0, NULL )
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_SERVICE_ALREADY_RUNNING') < 0:
                raise
        return 

class SMBTransport(SCMRTests):
    def setUp(self):
        SCMRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\pipe\svcctl]' % self.machine

class TCPTransport(SCMRTests):
    def setUp(self):
        SCMRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        #print epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        self.stringBinding = epm.hept_map(self.machine, scmr.MSRPC_UUID_SCMR, protocol = 'ncacn_ip_tcp')

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        #suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
