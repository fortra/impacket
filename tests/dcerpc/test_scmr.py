# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   ROpenSCManagerW
#   RControlService
#   RDeleteService
#   RLockServiceDatabase
#   RQueryServiceObjectSecurity
#   RQueryServiceStatus
#   RUnlockServiceDatabase
#   RNotifyBootConfigStatus
#   RChangeServiceConfigW
#   RCreateServiceW
#   REnumDependentServicesW
#   REnumServicesStatusW
#   ROpenSCManager
#   ROpenServiceW
#   RQueryServiceConfigW
#   RQueryServiceLockStatusW
#   RStartServiceW
#   CRGetServiceDisplayNameW
#   RGetServiceKeyNameW
#   REnumServiceGroupW
#   RChangeServiceConfig2W
#   RQueryServiceConfig2W
#   RQueryServiceStatusEx
#   REnumServicesStatusExW
#   RNotifyServiceStatusChange
#   RGetNotifyResults
#   RCloseNotifyHandle
#   RControlServiceExW
#   RQueryServiceConfigEx
#
# Not yet:
#   hRCloseServiceHandleCall
#   RSetServiceObjectSecurity
#   RSetServiceStatus
#   RCreateServiceWOW64W
#
import time
import pytest
import unittest
from struct import unpack
from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.uuid import string_to_bin
from impacket import ntlm


class SCMRTests(DCERPCTests):
    iface_uuid = scmr.MSRPC_UUID_SCMR
    authn = True
    
    def get_service_handle(self, dce):
        lpMachineName = 'DUMMY\x00'
        lpDatabaseName = 'ServicesActive\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS | scmr.SC_MANAGER_ENUMERATE_SERVICE
        resp = scmr.hROpenSCManagerW(dce, lpMachineName, lpDatabaseName, desiredAccess)
        scHandle = resp['lpScHandle']
        return scHandle

    def changeServiceAndQuery(self, dce, cbBufSize, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName):
        try:
            resp = scmr.hRChangeServiceConfigW(dce, hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName)
            resp = scmr.hRQueryServiceConfigW(dce, hService)
            resp.dump()
            # Now let's compare all the results
            if dwServiceType != scmr.SERVICE_NO_CHANGE:
                self.assertEqual(resp['lpServiceConfig']['dwServiceType'], dwServiceType)
            if dwStartType != scmr.SERVICE_NO_CHANGE:
                self.assertEqual(resp['lpServiceConfig']['dwStartType'], dwStartType)
            if dwErrorControl != scmr.SERVICE_NO_CHANGE:
                self.assertEqual(resp['lpServiceConfig']['dwErrorControl'], dwErrorControl)
            if lpBinaryPathName != NULL:
                self.assertEqual(resp['lpServiceConfig']['lpBinaryPathName'], lpBinaryPathName)
            if lpBinaryPathName != NULL:
                self.assertEqual(resp['lpServiceConfig']['lpBinaryPathName'], lpBinaryPathName)
            if lpLoadOrderGroup != NULL:
                self.assertEqual(resp['lpServiceConfig']['lpLoadOrderGroup'], lpLoadOrderGroup)
            #if lpDependencies != '':
            #    self.assertEqual( resp['lpServiceConfig']['lpDependencies'], lpDependencies[:-4]+'/\x00\x00\x00')
            if lpServiceStartName != NULL:
                self.assertEqual(resp['lpServiceConfig']['lpServiceStartName'], lpServiceStartName)
            if lpDisplayName != NULL:
                self.assertEqual(resp['lpServiceConfig']['lpDisplayName'], lpDisplayName)
            #if lpdwTagId != scmr.SERVICE_NO_CHANGE:
            #    if resp['lpServiceConfig']['dwTagId']['Data'] != lpdwTagId:
            #        print "ERROR %s" % 'lpdwTagId'
        except Exception:
            scmr.hRDeleteService(dce, hService)
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
        except scmr.DCERPCSessionError as e:
            if str(e).find('ERROR_INSUFFICIENT_BUFFER') <= 0:
                raise
            else: 
                resp = e.get_packet()

        request['cbBufSize'] = resp['pcbBytesNeeded'] 
        resp = dce.request(request)
        arrayData = b''.join(resp['lpBuffer'])
        if dwInfoLevel == 1:
           self.assertEqual(arrayData[4:].decode('utf-16le'), changeDone)
        elif dwInfoLevel == 2:
           offset = unpack('<L', arrayData[4:][:4])[0]
           self.assertEqual(arrayData[offset:][:len(changeDone)*2].decode('utf-16le'), changeDone)
        elif dwInfoLevel == 3:
           self.assertEqual(unpack('<L', arrayData)[0], changeDone)
        elif dwInfoLevel == 4:
           self.assertEqual(unpack('<L', arrayData)[0], changeDone)
        elif dwInfoLevel == 5:
           self.assertEqual(unpack('<L', arrayData)[0], changeDone)
        elif dwInfoLevel == 6:
           changeDone = bytes(changeDone).decode('utf-16le')
           self.assertEqual(arrayData[4:].decode('utf-16le'), changeDone)
        elif dwInfoLevel == 7:
           self.assertEqual(unpack('<L', arrayData)[0], changeDone)

    def open_or_create_service(self, dce, scHandle, service_name, display_name, binary_path_name):

        try:
            desiredAccess = scmr.SERVICE_ALL_ACCESS
            resp = scmr.hROpenServiceW(dce, scHandle, service_name, desiredAccess)
            resp.dump()
            return resp['lpServiceHandle']
        except scmr.DCERPCSessionError as e:
            if e.get_error_code() != 0x424:
                raise

        dwDesiredAccess = scmr.SERVICE_ALL_ACCESS
        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwStartType = scmr.SERVICE_DEMAND_START
        dwErrorControl = scmr.SERVICE_ERROR_NORMAL
        lpLoadOrderGroup = NULL
        lpdwTagId = NULL
        lpDependencies = NULL
        dwDependSize = 0
        lpServiceStartName = NULL
        lpPassword = NULL
        dwPwSize = 0
        resp = scmr.hRCreateServiceW(dce, scHandle, service_name, display_name, dwDesiredAccess,
                                     dwServiceType, dwStartType, dwErrorControl, binary_path_name,
                                     lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize,
                                     lpServiceStartName, lpPassword, dwPwSize)
        return resp['lpServiceHandle']

    def test_RChangeServiceConfig2W(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        newHandle = self.open_or_create_service(dce, scHandle, 'TESTSVC\x00', 'DisplayName\x00', 'binaryPath\x00')
        error = False
        try:
            request = scmr.RChangeServiceConfig2W()
            request['hService'] = newHandle
            request['Info']['dwInfoLevel'] = 1
            request['Info']['Union']['tag'] = 1
            request['Info']['Union']['psd']['lpDescription'] = 'betobeto\x00'
            resp = dce.request(request)
            resp.dump()
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psd']['lpDescription'])
            request['Info']['dwInfoLevel'] = 2
            request['Info']['Union']['tag'] = 2
            request['Info']['Union']['psfa']['lpRebootMsg'] = 'rebootMsg\00'
            request['Info']['Union']['psfa']['lpCommand'] = 'lpCommand\00'
            resp = dce.request(request)
            resp.dump()
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psfa']['lpRebootMsg'])
            request['Info']['dwInfoLevel'] = 3
            request['Info']['Union']['tag'] = 3
            request['Info']['Union']['psda']['fDelayedAutostart'] = 1
            dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psda']['fDelayedAutostart'])
            request['Info']['dwInfoLevel'] = 4
            request['Info']['Union']['tag'] = 4
            request['Info']['Union']['psfaf']['fFailureActionsOnNonCrashFailures'] = 1
            dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psfaf']['fFailureActionsOnNonCrashFailures'])
            request['Info']['dwInfoLevel'] = 5
            request['Info']['Union']['tag'] = 5
            request['Info']['Union']['pssid']['dwServiceSidType'] = 1
            dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['pssid']['dwServiceSidType'])
            request['Info']['dwInfoLevel'] = 6
            request['Info']['Union']['tag'] = 6
            request['Info']['Union']['psrp']['pRequiredPrivileges'] = list('SeAssignPrimaryTokenPrivilege\x00\x00'.encode('utf-16le'))
            dce.request(request)
            self.changeServiceAndQuery2(dce, request, request['Info']['Union']['psrp']['pRequiredPrivileges'])
            request['Info']['dwInfoLevel'] = 7
            request['Info']['Union']['tag'] = 7
            request['Info']['Union']['psps']['dwPreshutdownTimeout'] = 22
            dce.request(request)
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
            item['pData'] = list('FREEFLY\x00'.encode('utf-16le'))
            #trigger['pDataItems'].append(item)
            trigger['pDataItems'] = NULL
            request['Info']['Union']['psti']['pTriggers'].append(trigger)
            dce.request(request)
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

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(e)
            error = True
            pass

        scmr.hRDeleteService(dce, newHandle)
        scmr.hRCloseServiceHandle(dce, newHandle)
        scmr.hRCloseServiceHandle(dce, scHandle)
        if error:
            self.fail()
    
    def test_REnumServicesStatusExW(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        request = scmr.REnumServicesStatusExW()
        request['hSCManager'] = scHandle
        request['InfoLevel'] = scmr.SC_STATUS_PROCESS_INFO
        request['dwServiceType'] = scmr.SERVICE_WIN32_OWN_PROCESS
        request['dwServiceState'] = scmr.SERVICE_STATE_ALL
        request['lpResumeIndex'] = NULL
        request['pszGroupName'] = NULL
        request['cbBufSize'] = 0

        # Request again with the right bufSize
        try:
            resp = dce.request(request)
        except scmr.DCERPCSessionError as e:
            if str(e).find('ERROR_MORE_DATA') <= 0:
                raise
            else: 
                resp = e.get_packet()
        resp.dump()
        request['cbBufSize'] = resp['pcbBytesNeeded']
        resp = dce.request(request)
        resp.dump()

    def test_RQueryServiceStatusEx(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
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
        array = b''.join(resp['lpBuffer'])
        scmr.SERVICE_STATUS_PROCESS(array)

    @pytest.mark.skip(reason="ToDo")
    def test_REnumServiceGroupW(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        
        dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS
        dwServiceState = scmr.SERVICE_STATE_ALL
        cbBufSize = 10
        lpResumeIndex = 0
        pszGroupName = 'RemoteRegistry\x00'

        try:
            resp = scmr.hREnumServiceGroupW(dce, scHandle, dwServiceType, dwServiceState, cbBufSize, lpResumeIndex, pszGroupName )
            resp.dump()
        except scmr.DCERPCSessionError as e:
           if str(e).find('ERROR_SERVICE_DOES_NOT_EXISTS') <= 0:
               raise

        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RQueryServiceConfigEx(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        lpServiceName = 'RemoteRegistry\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()
        serviceHandle = resp['lpServiceHandle']

        request = scmr.RQueryServiceConfigEx()
        request['hService'] = serviceHandle
        request['dwInfoLevel'] = 0x00000008

        resp = dce.request(request)
        resp.dump()

    @pytest.mark.skip(reason="ToDo")
    def test_RControlServiceExW(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
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

    @pytest.mark.skip(reason="ToDo")
    def test_RNotifyServiceStatusChange(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
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
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        lpServiceName = 'PlugPlay\x00'
        lpcchBuffer = len(lpServiceName)+100

        scmr.hRGetServiceDisplayNameW(dce, scHandle, lpServiceName, lpcchBuffer)

        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RGetServiceKeyNameW(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        lpDisplayName = 'Plug and Play\x00'
        lpcchBuffer = len(lpDisplayName)+100

        scmr.hRGetServiceKeyNameW(dce, scHandle, lpDisplayName, lpcchBuffer)

        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RStartServiceW(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()
        serviceHandle = resp['lpServiceHandle']
  
        try:
            scmr.hRStartServiceW(dce, serviceHandle, 3, ['arg1\x00', 'arg2\x00', 'arg3\x00'] )
        except scmr.DCERPCSessionError as e:
           if str(e).find('ERROR_SERVICE_ALREADY_RUNNING') <= 0:
               raise
        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RQueryServiceLockStatusW(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        pcbBytesNeeded = 1000
        scmr.hRQueryServiceLockStatusW(dce, scHandle, pcbBytesNeeded)

        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_enumservices(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        #####################
        # EnumServicesStatusW
        dwServiceType = scmr.SERVICE_KERNEL_DRIVER | scmr.SERVICE_FILE_SYSTEM_DRIVER | scmr.SERVICE_WIN32_OWN_PROCESS | scmr.SERVICE_WIN32_SHARE_PROCESS
        dwServiceState = scmr.SERVICE_STATE_ALL
        scmr.hREnumServicesStatusW(dce, scHandle, dwServiceType, dwServiceState)

        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_create_change_delete(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        #####################
        # Create / Change /  Query / Delete a service
        newHandle = self.open_or_create_service(dce, scHandle, 'TESTSVC\x00', 'DisplayName\x00', 'binaryPath\x00')

        # Aca hay que chequear cada uno de los items
        cbBufSize = 0
        try:
            resp = scmr.hRQueryServiceConfigW(dce, newHandle)
        except scmr.DCERPCSessionError as e:
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
            s = rpc_transport.get_smb_connection()
            key = s.getSessionKey()
            lpPassword = encryptSecret(key, lpPassword)
            dwPwSize = len(lpPassword)
            self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 
            lpPassword = NULL
            dwPwSize = 0

            lpDisplayName = 'MANOLO\x00'
            self.changeServiceAndQuery(dce, cbBufSize, newHandle, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, dwDependSize, lpServiceStartName, lpPassword, dwPwSize, lpDisplayName) 

        scmr.hRDeleteService(dce, newHandle)
        scmr.hRCloseServiceHandle(dce, newHandle)
        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_query(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)

        ############################
        # Query Service Status / Enum Dependent
        lpServiceName = 'PlugPlay\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']
 
        scmr.hRQueryServiceStatus(dce, serviceHandle)

        cbBufSize = 0
        try:
            resp = scmr.hREnumDependentServicesW(dce, serviceHandle, scmr.SERVICE_STATE_ALL,cbBufSize )
            resp.dump()
        except scmr.DCERPCSessionError as e:
           if str(e).find('ERROR_MORE_DATA') <= 0:
               raise
           else:
               resp = e.get_packet()

        resp.dump()
        cbBufSize = resp['pcbBytesNeeded']
        resp = scmr.hREnumDependentServicesW(dce, serviceHandle, scmr.SERVICE_STATE_ALL,cbBufSize )
        resp.dump()
        scmr.hRCloseServiceHandle(dce, serviceHandle)
        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_lock_unlock(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        
        resp = scmr.hRLockServiceDatabase(dce, scHandle)
        lockHandle = resp['lpLock']
        scmr.hRUnlockServiceDatabase(dce, lockHandle)

        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_query_set_object_security(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        try:
            resp = scmr.hRQueryServiceObjectSecurity(dce, scHandle, scmr.DACL_SECURITY_INFORMATION, 0)
            resp.dump()
        except scmr.DCERPCException as e:
           if str(e).find('rpc_s_access_denied') <= 0:
               raise
        scmr.hRCloseServiceHandle(dce, scHandle)

    @pytest.mark.skip(reason="Long running test")
    def test_notify_config(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        lpMachineName = 'DUMMY\x00'
        
        try:
            resp = scmr.hRNotifyBootConfigStatus(dce, lpMachineName, 0x0)
            resp.dump()
        except scmr.DCERPCSessionError as e:
           if str(e).find('ERROR_BOOT_ALREADY_ACCEPTED') <= 0:
               raise
 
        scmr.hRCloseServiceHandle(dce, scHandle)

    def test_RControlServiceCall(self):
        dce, rpc_transport = self.connect()
        scHandle = self.get_service_handle(dce)
        lpServiceName = 'CryptSvc\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS

        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']
 
        try:
            req = scmr.RControlService()
            req['hService'] = serviceHandle
            req['dwControl'] = scmr.SERVICE_CONTROL_STOP
            dce.request(req)
        except scmr.DCERPCSessionError as e:
            if str(e).find('ERROR_DEPENDENT_SERVICES_RUNNING') < 0 and str(e).find('ERROR_SERVICE_NOT_ACTIVE') < 0:
                raise
            pass

        scmr.hRCloseServiceHandle(dce, serviceHandle)
        time.sleep(1)
        resp = scmr.hROpenServiceW(dce, scHandle, lpServiceName, desiredAccess )
        resp.dump()

        serviceHandle = resp['lpServiceHandle']

        try:
            resp = scmr.hRStartServiceW(dce, serviceHandle, 0, NULL )
            resp.dump()
        except scmr.DCERPCSessionError as e:
            if str(e).find('ERROR_SERVICE_ALREADY_RUNNING') < 0:
                raise
        return 


@pytest.mark.remote
class SCMRTestsSMBTransport(SCMRTests, unittest.TestCase):
    string_binding = r"ncacn_np:{0.machine}[\pipe\svcctl]"


@pytest.mark.remote
class SCMRTestsTCPTransport(SCMRTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    authn_level = ntlm.NTLM_AUTH_PKT_PRIVACY
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
