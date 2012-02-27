# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
#
# Description:
#   SVCCTL (Services Control) interface implementation.
#

import array
from struct import *

from impacket import ImpactPacket
from impacket.structure import Structure
from impacket import dcerpc
from impacket.dcerpc import ndrutils, dcerpc

MSRPC_UUID_SVCCTL = '\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03\x02\x00\x00\x00'

# Error Codes 
ERROR_PATH_NOT_FOUND            = 3
ERROR_ACCESS_DENIED             = 5
ERROR_INVALID_HANDLE            = 6
ERROR_INVALID_DATA              = 13
ERROR_INVALID_PARAMETER         = 87
ERROR_INVALID_NAME              = 123
ERROR_SERVICE_ALREADY_RUNNING   = 1056
ERROR_INVALID_SERVICE_ACCOUNT   = 1057
ERROR_SERVICE_DISABLED          = 1058
ERROR_DATABASE_DOES_NOT_EXIST   = 1065
ERROR_SERVICE_LOGON_FAILURE     = 1069
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_SERVICE_EXISTS            = 1073
ERROR_DUPLICATE_SERVICE_NAME    = 1078
ERROR_SHUTDOWN_IN_PROGRESS      = 1115

# Access codes
SERVICE_ALL_ACCESS            = 0X000F01FF
SERVICE_CHANGE_CONFIG         = 0X00000002
SERVICE_ENUMERATE_DEPENDENTS  = 0X00000008
SERVICE_INTERROGATE           = 0X00000080
SERVICE_PAUSE_CONTINUE        = 0X00000040
SERVICE_QUERY_CONFIG          = 0X00000001
SERVICE_QUERY_STATUS          = 0X00000004
SERVICE_START                 = 0X00000010
SERVICE_STOP                  = 0X00000020
SERVICE_USER_DEFINED_CTRL     = 0X00000100
SERVICE_SET_STATUS            = 0X00008000

# Service Types
SERVICE_KERNEL_DRIVER         = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER    = 0x00000002
SERVICE_WIN32_OWN_PROCESS     = 0x00000010
SERVICE_WIN32_SHARE_PROCESS   = 0x00000020
SERVICE_INTERACTIVE_PROCESS   = 0x00000100

# Start Types
SERVICE_BOOT_START            = 0x00000000
SERVICE_SYSTEM_START          = 0x00000001
SERVICE_AUTO_START            = 0x00000002
SERVICE_DEMAND_START          = 0x00000003
SERVICE_DISABLED              = 0x00000004

# Error Control 
SERVICE_ERROR_IGNORE          = 0x00000000
SERVICE_ERROR_NORMAL          = 0x00000001
SERVICE_ERROR_SEVERE          = 0x00000002
SERVICE_ERROR_CRITICAL        = 0x00000003

# Service Control Codes
SERVICE_CONTROL_CONTINUE      = 0x00000003
SERVICE_CONTROL_INTERROGATE   = 0x00000004
SERVICE_CONTROL_PARAMCHANGE   = 0x00000006
SERVICE_CONTROL_PAUSE         = 0x00000002
SERVICE_CONTROL_STOP          = 0x00000001

# Service State
SERVICE_ACTIVE                = 0x00000001
SERVICE_INACTIVE              = 0x00000002
SERVICE_STATE_ALL             = 0x00000003

# Current State
SERVICE_CONTINUE_PENDING      = 0x00000005
SERVICE_PAUSE_PENDING         = 0x00000006
SERVICE_PAUSED                = 0x00000007
SERVICE_RUNNING               = 0x00000004
SERVICE_START_PENDING         = 0x00000002
SERVICE_STOP_PENDING          = 0x00000003
SERVICE_STOPPED               = 0x00000001

class SVCCTLServiceStatus(Structure):
    structure = (
        ('ServiceType','<L'),
        ('CurrentState','<L'),
        ('ControlsAccepted','<L'),
        ('Win32ExitCode','<L'),
        ('ServiceSpecificExitCode','<L'),
        ('CheckPoint','<L'),
        ('WaitHint','<L'),
    )

class SVCCTLQueryServiceConfigW(Structure):
    structure = (
        ('ServiceType','<L'),
        ('StartType','<L'),
        ('ErrorControl','<L'),
        ('pBinaryPathName','<L'),
        ('pLoadOrderGroup','<L'),
        ('TagID','<L'),
        ('pDependencies','<L'),
        ('pServiceStartName','<L'),
        ('pDisplayName','<L'),
    )

class SVCCTLRQueryServiceConfigW(Structure):
    opnum = 17
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('BuffSize','<L=0'),
    )

class SVCCTLRQueryServiceConfigWResponse(Structure):
    structure = (
        ('QueryConfig',':',SVCCTLQueryServiceConfigW),
        ('BufferLen','_-StringsBuffer','self["BufferSize"]'),
        ('StringsBuffer',':'),
        ('BytesNeeded','<L'),
        ('ErrorCode','<L'),
    )

class SVCCTLRQueryServiceStatus(Structure):
    opnum = 6
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
    )


class SVCCTLRDeleteService(Structure):
    opnum = 2
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
    )
 
class SVCCTLRControlService(Structure):
    opnum = 1
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('Control','<L'),
    )

class SVCCTLRControlServiceResponse(Structure):
    alignment = 4
    structure = (
        ('ServiceStatus',':',SVCCTLServiceStatus),
        #('ErrorCode','<L'),
    )

class SVCCTLRStartServiceW(Structure):
    opnum = 19
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('argc','<L=0'),
        ('argv',':'),
    )

class SVCCTLROpenServiceW(Structure):
    opnum = 16
    alignment = 4
    structure = (
        ('SCManager','20s'),
        ('ServiceName',':',ndrutils.NDRStringW),
        ('DesiredAccess','<L'),
    )

class SVCCTLROpenServiceA(Structure):
    opnum = 28
    alignment = 4
    structure = (
        ('SCManager','20s'),
        ('ServiceName',':',ndrutils.NDRStringA),
        ('DesiredAccess','<L'),
    )


class SVCCTLROpenServiceResponse(Structure):
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )

class SVCCTLROpenSCManagerW(Structure):
    opnum = 15
    alignment = 4
    structure = (
        ('MachineName',':',ndrutils.NDRUniqueStringW),
        ('DatabaseName','"\x00'),
        ('DesiredAccess','<L'),
    )

class SVCCTLROpenSCManagerAResponse(Structure):
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )

class SVCCTLRCloseServiceHandle(Structure):
    opnum = 0
    alignment = 4
    structure = (
       ('ContextHandle','20s'),
    )
   
class SVCCTLRCloseServiceHandlerResponse(Structure):
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )

class SVCCTLRCreateServiceW(Structure):
    opnum = 12
    alignment = 4
    structure = (
        ('SCManager','20s'),
        ('ServiceName',':',ndrutils.NDRStringW),
        ('DisplayName',':',ndrutils.NDRUniqueStringW),
        ('DesiredAccess','<L'),
        ('ServiceType','<L'),
        ('StartType','<L'),
        ('ErrorControl','<L'),
        ('BinaryPathName',':',ndrutils.NDRStringW),
        ('LoadOrderGroup','<L=0'),
        ('TagID','<L=0'),
        ('Dependencies','<L=0'),
        ('DependenciesSize','<L=0'),
        #('pServiceStartName','<L-&ServiceStartName'),
        #('ServiceStartName','w'),
        ('ServiceStartName','<L=0'),
        ('Password','<L=0'),
        ('PwSize','<L=0'),
    )
    
 
class SVCCTLRCreateServiceWResponse(Structure):
    alignment = 4
    structure = (
        ('TagID','<L'),
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )

class SVCCTLREnumServicesStatusW(Structure):
    opnum = 14
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('ServiceType','<L'),
        ('ServiceState','<L'),
        ('BuffSize','<L=0'),
        ('pResumeIndex','<L=123'),
        ('ResumeIndex','<L=0'),
    ) 

class SVCCTLREnumServicesStatusWResponse(Structure):
    alignment = 4
    structure = (
        ('BuffSize','<L'),
        ('BufferLen','_-Buffer','self["BuffSize"]'),
        ('Buffer',':'),
        ('BytesNeeded','<L'),
        ('ServicesReturned','<L'),
        ('Dontknow','<L'),
        ('Dontknow','<L'),
        ('ErrorCode','<L'),
    )

# OLD Style structs.. leaving this stuff for compatibility purpose. Don't use these structs/functions anymore

class SVCCTLOpenSCManagerHeader(ImpactPacket.Header):
    OP_NUM = 0x1B

    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLOpenSCManagerHeader.__SIZE)

        self.set_referent_id(0xFFFFFF)
        self.set_access_mask(0xF003F)

        if aBuffer: self.load_header(aBuffer)

    def get_referent_id(self):
        return self.get_long(0, '<')
    def set_referent_id(self, id):
        self.set_long(0, id, '<')

    def get_max_count(self):
        return self.get_long(4, '<')
    def set_max_count(self, num):
        self.set_long(4, num, '<')

    def get_offset(self):
        return self.get_long(8, '<')
    def set_offset(self, num):
        self.set_long(8, num, '<')

    def get_cur_count(self):
        return self.get_long(12, '<')
    def set_cur_count(self, num):
        self.set_long(12, num, '<')

    def get_machine_name(self):
        return self.get_bytes().tostring()[:20]
    def set_machine_name(self, name):
        assert len(name) <= 8
        self.set_max_count(len(name) + 1)
        self.set_cur_count(len(name) + 1)
        self.get_bytes()[16:24] = array.array('B', name + (8 - len(name)) * '\x00')

    def get_access_mask(self):
        return self.get_long(28, '<')
    def set_access_mask(self, mask):
        self.set_long(28, mask, '<')


    def get_header_size(self):
        return SVCCTLOpenSCManagerHeader.__SIZE


class SVCCTLRespOpenSCManagerHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespOpenSCManagerHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SVCCTLRespOpenSCManagerHeader.__SIZE


class SVCCTLOpenServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x1C

    __SIZE = 48


    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLOpenServiceHeader.__SIZE)

        self.set_max_count(9)
        self.set_cur_count(9)
        # Write some unknown fluff.
        self.get_bytes()[40:] = array.array('B', '\x00\x10\x48\x60\xff\x01\x0f\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_max_count(self):
        return self.get_long(20, '<')
    def set_max_count(self, num):
        self.set_long(20, num, '<')

    def get_offset(self):
        return self.get_long(24, '<')
    def set_offset(self, num):
        self.set_long(24, num, '<')

    def get_cur_count(self):
        return self.get_long(28, '<')
    def set_cur_count(self, num):
        self.set_long(28, num, '<')

    def get_service_name(self):
        return self.get_bytes().tostring()[32:40]
    def set_service_name(self, name):
        assert len(name) <= 8
        self.get_bytes()[32:40] = array.array('B', name + (8 - len(name)) * '\x00')


    def get_header_size(self):
        return SVCCTLOpenServiceHeader.__SIZE


class SVCCTLRespOpenServiceHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespOpenServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SVCCTLRespOpenServiceHeader.__SIZE


class SVCCTLCloseServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x0

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLCloseServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:] = array.array('B', handle)


    def get_header_size(self):
        return SVCCTLCloseServiceHeader.__SIZE


class SVCCTLRespCloseServiceHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespCloseServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SVCCTLRespCloseServiceHeader.__SIZE


class SVCCTLCreateServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x18

    __SIZE = 132

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLCreateServiceHeader.__SIZE)

        self.set_name_max_count(9)
        self.set_name_cur_count(9)
        self.set_service_flags(0x110)
        self.set_start_mode(2)
        self.get_bytes()[40:48] = array.array('B', '\x00\x10\x48\x60\xe4\xa3\x40\x00')
        self.get_bytes()[68:76] = array.array('B', '\x00\x00\x00\x00\xff\x01\x0f\x00')
        self.get_bytes()[84:88] = array.array('B', '\x01\x00\x00\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_name_max_count(self):
        return self.get_long(4, '<')
    def set_name_max_count(self, num):
        self.set_long(20, num, '<')
        self.set_long(48, num, '<')

    def get_name_offset(self):
        return self.get_long(8, '<')
    def set_name_offset(self, num):
        self.set_long(24, num, '<')
        self.set_long(52, num, '<')

    def get_name_cur_count(self):
        return self.get_long(12, '<')
    def set_name_cur_count(self, num):
        self.set_long(28, num, '<')
        self.set_long(56, num, '<')

    def get_service_name(self):
        return self.get_bytes().tostring()[32:40]
    def set_service_name(self, name):
        self.get_bytes()[32:40] = array.array('B', name + (8 - len(name)) * '\x00')
        self.get_bytes()[60:68] = array.array('B', name + (8 - len(name)) * '\x00')

    # 0x0000100 = Allow service to interact with desktop (needed by vnc server for example)
    # 0x0000010 = Log as: Local System Account
    def get_service_flags(self):
        return self.get_long(76, '<')
    def set_service_flags(self, flags):
        self.set_long(76, flags, '<')

    # 2 Automatic
    # 3 Manual
    # 4 Disabled
    def get_start_mode(self):
        return self.get_long(80, '<')
    def set_start_mode(self, mode):
        self.set_long(80, mode, '<')

    def get_path_max_count(self):
        return self.get_long(88, '<')
    def set_path_max_count(self, num):
        self.set_long(88, num, '<')

    def get_path_offset(self):
        return self.get_long(92, '<')
    def set_path_offset(self, num):
        self.set_long(92, num, '<')

    def get_path_cur_count(self):
        return self.get_long(96, '<')
    def set_path_cur_count(self, num):
        self.set_long(96, num, '<')

    def get_service_path(self):
        return self.get_bytes().tostring()[100:-32]
    def set_service_path(self, path):
        self.get_bytes()[100:-32] = array.array('B', path)
        self.set_path_max_count(len(path)+1)
        self.set_path_cur_count(len(path)+1)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SVCCTLCreateServiceHeader.__SIZE
        assert var_size > 0
        return SVCCTLCreateServiceHeader.__SIZE + var_size


class SVCCTLRespCreateServiceHeader(ImpactPacket.Header):
    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespCreateServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[4:24]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[4:24] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(24, '<')
    def set_return_code(self, code):
        self.set_long(24, code, '<')


    def get_header_size(self):
        return SVCCTLRespCreateServiceHeader.__SIZE


class SVCCTLDeleteServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x2

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLDeleteServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_header_size(self):
        return SVCCTLDeleteServiceHeader.__SIZE


class SVCCTLRespDeleteServiceHeader(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespDeleteServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return SVCCTLRespDeleteServiceHeader.__SIZE


class SVCCTLStopServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x1

    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLStopServiceHeader.__SIZE)

        # Write some unknown fluff.
        self.get_bytes()[20:] = array.array('B', '\x01\x00\x00\x00')

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_header_size(self):
        return SVCCTLStopServiceHeader.__SIZE


class SVCCTLRespStopServiceHeader(ImpactPacket.Header):
    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespStopServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(28, '<')
    def set_return_code(self, code):
        self.set_long(28, code, '<')


    def get_header_size(self):
        return SVCCTLRespStopServiceHeader.__SIZE


class SVCCTLStartServiceHeader(ImpactPacket.Header):
    OP_NUM = 0x1F

    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLStartServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_arguments(self):
        raise Exception, "method not implemented"
    def set_arguments(self, arguments):
        args_data = apply(pack, ['<' + 'L'*len(arguments)] + map(id, arguments) )
        args_data += reduce(lambda a, b: a+b,
                            map(lambda element: pack('<LLL', len(element)+1, 0, len(element)+1) + element + '\x00' + '\x00' * ((4 - (len(element) + 1) % 4) % 4), arguments),
                            '')
        data = pack('<LLL', len(arguments), id(arguments), len(arguments)) + args_data
        self.get_bytes()[20:] = array.array('B', data)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SVCCTLStartServiceHeader.__SIZE
        assert var_size > 0
        return SVCCTLStartServiceHeader.__SIZE + var_size


class SVCCTLRespStartServiceHeader(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SVCCTLRespStartServiceHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_return_code(self):
        return self.get_long(0, '<')
    def set_return_code(self, code):
        self.set_long(0, code, '<')


    def get_header_size(self):
        return SVCCTLRespStartServiceHeader.__SIZE


class DCERPCSvcCtl:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def open_manager(self):
        hostname = 'IMPACT'
        opensc = SVCCTLOpenSCManagerHeader()
        opensc.set_machine_name(hostname)
        self._dcerpc.send(opensc)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespOpenSCManagerHeader(data)
        return retVal

    def create_service(self, context_handle, service_name, service_path):
        creates = SVCCTLCreateServiceHeader()
        creates.set_context_handle(context_handle)
        creates.set_service_name(service_name)
        creates.set_service_path(service_path)
        self._dcerpc.send(creates)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespCreateServiceHeader(data)
        return retVal

    def close_handle(self, context_handle):
        closeh = SVCCTLCloseServiceHeader()
        closeh.set_context_handle(context_handle)
        self._dcerpc.send(closeh)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespCloseServiceHeader(data)
        return retVal

    def delete_service(self, context_handle):
        deletes = SVCCTLDeleteServiceHeader()
        deletes.set_context_handle(context_handle)
        self._dcerpc.send(deletes)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespDeleteServiceHeader(data)
        return retVal

    def open_service(self, context_handle, service_name):
        opens = SVCCTLOpenServiceHeader()
        opens.set_context_handle(context_handle)
        opens.set_service_name(service_name)
        self._dcerpc.send(opens)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespOpenServiceHeader(data)
        return retVal

    def stop_service(self, context_handle):
        stops = SVCCTLStopServiceHeader()
        stops.set_context_handle(context_handle)
        self._dcerpc.send(stops)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespStopServiceHeader(data)
        return retVal

    def start_service(self, context_handle, arguments):
        starts = SVCCTLStartServiceHeader()
        starts.set_arguments( arguments )
        starts.set_context_handle(context_handle)
        self._dcerpc.send(starts)
        data = self._dcerpc.recv()
        retVal = SVCCTLRespStartServiceHeader(data)
        return retVal

# Use these functions to manipulate services. The previous ones are left for backward compatibility reasons.

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            return answer

    def DeleteService(self, handle):
        deleteService = SVCCTLRDeleteService()
        deleteService['ContextHandle'] = handle
        ans = self.doRequest(deleteService, checkReturn = 1)
        return ans

    def StopService(self, handle):
        controlService = SVCCTLRControlService()
        controlService['ContextHandle'] = handle
        controlService['Control']  = SERVICE_CONTROL_STOP
        ans = self.doRequest(controlService, checkReturn = 1)
        return SVCCTLServiceStatus(ans)
 
    def OpenServiceA(self, handle, name):
        openService = SVCCTLROpenServiceA()
        openService['SCManager'] = handle
        openService['ServiceName'] = ndrutils.NDRStringA()
        openService['ServiceName']['Data'] = (name+'\x00')
        openService['DesiredAccess'] = SERVICE_ALL_ACCESS

        ans = self.doRequest(openService, checkReturn = 1)
        return SVCCTLROpenServiceResponse(ans)

    def OpenServiceW(self, handle, name):
        # We MUST receive Unicode data here
        openService = SVCCTLROpenServiceW()
        openService['SCManager'] = handle
        openService['ServiceName'] = ndrutils.NDRStringW()
        openService['ServiceName']['Data'] = (name+'\x00'.encode('utf-16le'))
        openService['DesiredAccess'] = SERVICE_ALL_ACCESS

        ans = self.doRequest(openService, checkReturn = 1)
        return SVCCTLROpenServiceResponse(ans)

    def StartServiceW(self, handle, arguments = ''):
        # TODO: argv has to be a pointer to a buffer that contains an array
        # of pointers to null-terminated UNICODE strings that are passed as
        # arguments to the service
        startService = SVCCTLRStartServiceW()
        startService['ContextHandle'] = handle
        startService['argc'] = len(arguments)
        if len(arguments) == 0:
           startService['argv'] = '\x00'*4
        else:
           args_data = pack('<LL', id(arguments), len(arguments))
           args_data += apply(pack, ['<' + 'L'*len(arguments)] + map(id, arguments) )
           for i in range(len(arguments)):
               item = ndrutils.NDRStringW()
               item['Data'] = arguments[i]+'\x00'.encode('utf-16le')
               args_data += str(item) 
           startService['argv'] = args_data
        
        ans = self.doRequest(startService, checkReturn = 1)
      
        return ans

    def CreateServiceW(self, handle, serviceName, displayName, binaryPathName):
        # We MUST receive Unicode data here
        createService = SVCCTLRCreateServiceW()
        createService['SCManager']      = handle
        createService['ServiceName']    = ndrutils.NDRStringW()
        createService['ServiceName']['Data']    = (serviceName+'\x00'.encode('utf-16le'))
        createService['DisplayName']    = ndrutils.NDRUniqueStringW()
        createService['DisplayName']['Data']    = (displayName+'\x00'.encode('utf-16le'))
        createService['DesiredAccess']  = SERVICE_ALL_ACCESS
        createService['ServiceType']    = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS
        createService['StartType']      = SERVICE_AUTO_START
        #createService['StartType']      = SERVICE_DEMAND_START
        createService['ErrorControl']   = SERVICE_ERROR_IGNORE
        createService['BinaryPathName'] = ndrutils.NDRStringW()
        createService['BinaryPathName']['Data'] = (binaryPathName+'\x00'.encode('utf-16le'))
        createService['TagID'] = 0
        ans = self.doRequest(createService, checkReturn = 1)
        return SVCCTLRCreateServiceWResponse(ans)

    def OpenSCManagerW(self): 
        openSCManager = SVCCTLROpenSCManagerW()
        openSCManager['MachineName'] = ndrutils.NDRUniqueStringW()
        openSCManager['MachineName']['Data'] = 'DUMMY\x00'.encode('utf-16le')
        openSCManager['DesiredAccess'] = SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS

        ans = self.doRequest(openSCManager, checkReturn = 1)
        return SVCCTLROpenSCManagerAResponse(ans)

    def CloseServiceHandle(self, handle):
        closeHandle = SVCCTLRCloseServiceHandle()
        closeHandle['ContextHandle'] = handle
        ans = self.doRequest(closeHandle, checkReturn = 1)
        return SVCCTLRCloseServiceHandlerResponse(ans)
 
    def EnumServicesStatusW(self, handle, serviceType = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS, serviceState = SERVICE_STATE_ALL ):
        enumServices = SVCCTLREnumServicesStatusW()
        enumServices['ContextHandle'] = handle
        enumServices['ServiceType']   = serviceType
        enumServices['ServiceState']  = serviceState
        enumServices['BuffSize']      = 0x0

        # First packet is to get the buffer size we need to hold the answer
        ans = self.doRequest(enumServices, checkReturn = 0)
        packet = SVCCTLREnumServicesStatusWResponse(ans)
        enumServices['BuffSize']      = packet['BytesNeeded']

        # Now the actual request
        ans = self.doRequest(enumServices, checkReturn = 1)
        packet = SVCCTLREnumServicesStatusWResponse(ans)

        data = packet['Buffer']
        # TODO: There are a few NDR types that I still don't know how they are marshalled... I'm sure this could be done way cleaner..
        index = 0
        enumServicesList = []
        for i in range(packet['ServicesReturned']):
            tmpDict = {}
            serviceNamePtr = unpack('<L',data[index:index+4])[0] 
            index += 4
            displayNamePtr = unpack('<L',data[index:index+4])[0] 
            index += 4
            serviceStatus = SVCCTLServiceStatus(data[index:])
            tmpDict['ServiceType']       = serviceStatus['ServiceType']
            tmpDict['CurrentState']      = serviceStatus['CurrentState']
            tmpDict['ControlsAccepted']  = serviceStatus['ControlsAccepted']
            # Now Parse the strings
            string = data[displayNamePtr:].split('\x00\x00\x00')[0]
            tmpDict['DisplayName'] = string + '\x00'
            string = data[serviceNamePtr:].split('\x00\x00\x00')[0]
            tmpDict['ServiceName'] = string + '\x00'
            enumServicesList.append(tmpDict)
            index += len(serviceStatus)

        return enumServicesList
        

    def QueryServiceStatus(self, handle):
        queryStatus = SVCCTLRQueryServiceStatus()
        queryStatus['ContextHandle'] = handle

        ans = self.doRequest(queryStatus, checkReturn = 1)
        return SVCCTLServiceStatus(ans)

    def QueryServiceConfigW(self, handle):
        class configStrings(Structure):
            structure = (
                ('BinaryPathName',':',ndrutils.NDRStringW),
                ('LoadOrderGroup',':',ndrutils.NDRStringW),
                ('Dependencies',':',ndrutils.NDRStringW),
                ('ServiceStartName',':',ndrutils.NDRStringW),
                ('DisplayName',':',ndrutils.NDRStringW),
            )
        serviceConfig = SVCCTLRQueryServiceConfigW()

        # First packet is to get the buffer size we need to hold the answer
        serviceConfig['ContextHandle'] = handle
        serviceConfig['BuffSize']      = 0
        ans = self.doRequest(serviceConfig, checkReturn = 1)
        packet = SVCCTLRQueryServiceConfigWResponse()
        packet['BufferSize'] = 0
        packet.fromString(ans)

        bytesNeeded =  packet['BytesNeeded']
        serviceConfig['BuffSize'] = bytesNeeded

        # Now the actual request
        ans = self.doRequest(serviceConfig, checkReturn = 1)
        packet = SVCCTLRQueryServiceConfigWResponse()
        packet['BufferSize'] = len(ans) - 36 - 8
        packet.fromString(ans)
        if packet['ErrorCode'] == 0:
            confStr = configStrings(packet['StringsBuffer'])
            packet['QueryConfig']['BinaryPathName'] = confStr['BinaryPathName']['Data']
            packet['QueryConfig']['LoadOrderGroup'] = confStr['LoadOrderGroup']['Data']
            packet['QueryConfig']['Dependencies']   = confStr['Dependencies']['Data']
            packet['QueryConfig']['ServiceStartName'] = confStr['ServiceStartName']['Data']
            packet['QueryConfig']['DisplayName'] = confStr['DisplayName']['Data']

        return packet
 
