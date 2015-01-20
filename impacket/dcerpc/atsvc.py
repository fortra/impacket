################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
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
#   ATSVC implementation of some methods [MS-TSCH]
#

from struct import *
from impacket.structure import Structure
from impacket import dcerpc
from impacket.dcerpc import ndrutils, dcerpc
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_ATSVC = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0'))
MSRPC_UUID_SASEC = uuidtup_to_bin(('378E52B0-C0A9-11CF-822D-00AA0051E40F', '1.0'))
MSRPC_UUID_TSS   = uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C', '1.0'))

# Constants
S_OK                      = 0x00000000
S_FALSE                   = 0x00000001
E_OUTOFMEMORY             = 0x80000002
E_ACCESSDENIED            = 0x80000009
E_INVALIDARG              = 0x80000003
E_FAIL                    = 0x80000008
E_UNEXPECTED              = 0x8000FFFF

# Structures

class AT_INFO(Structure):
    structure = (
        ('JobTime', '<L=0xff'),
        ('DaysOfMonth','<L=0'),
        ('DaysOfWeek','<B=0'),
        ('Flags','<B=0'),
        ('unknown','<H=0xffff'),
        ('Command',':',ndrutils.NDRUniqueStringW),
    )

# Opnums
class ATSVCNetrJobAdd(Structure):
    opnum = 0
    #alignment = 4
    structure = (
        ('ServerName',':',ndrutils.NDRUniqueStringW),
        ('pAtInfo',':',AT_INFO),
    )

class ATSVCNetrJobAddResponse(Structure):
    structure = (
        ('JobID', '<L=0'), 
    )

class ATSVCNetrJobDel(Structure):
    opnum = 1
    structure = (
        ('ServerName',':',ndrutils.NDRUniqueStringW),
        ('MinJobId','<L=0'),
        ('MaxJobId','<L=0'),
    )

class ATSVCNetrJobEnum(Structure):
    opnum = 2
    alignment = 4
    structure = (
        ('ServerName',':',ndrutils.NDRUniqueStringW),
        ('TotalEntries','<L=0'),
        ('pEnumContainer','<L=0'),
        ('PreferredMaximumLength','<L=0xffffffff'),
        ('refId','<L=1'),
        ('ResumeHandle','<L=0xff'),
    )

class ATSVCNetrJobEnumResponse(Structure):
    structure = (
        ('EntriedRead','<L'),
        ('RefId','<L'),
        ('Count','<L'),
        ('Size','_-Entries','len(self.rawData)-7*4'),
        ('Entries',':'),
        ('TotalEntries','<L'),
        ('RedId2','<L'),
        ('ResumeHandle','<L=0xff'),
    )

class ATSVCSchRpcEnumTasks(Structure):
    opnum = 7
    alignment = 4
    structure = (
         ('Path',':',ndrutils.NDRStringW),
         ('Flags','<L'),
         ('StartIndex','<L=0'),
         ('cRequested','<L=1'), 
     )

class ATSVCSchRpcEnumTasksResp(Structure):
    structure = (
        ('pcNames','<L'),
        ('Count','<L'),
        ('RefId','<L'),
        ('Count2','<L'),
        ('TaskName',':',ndrutils.NDRUniqueStringW),
        ('ErrorCode','<L'),
    )

class ATSVCSchRpcRun(Structure):
    opnum = 12
    structure = (
        ('Path',':',ndrutils.NDRStringW),
        ('cArgs','<L=0'),
        ('pArgs','<L=0'),
        ('flags','<L=0'),
        ('sessionId','<L=0'),
        ('user','<L=0'),
    )

class ATSVCSessionError(Exception):
    
    # ToDo: Complete this stuff

    error_messages = {
    }    

    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        key = self.error_code
        if (ATSVCSessionError.error_messages.has_key(key)):
            error_msg_short = ATSVCSessionError.error_messages[key][0]
            error_msg_verbose = ATSVCSessionError.error_messages[key][1] 
            return 'ATSVC SessionError: code: %s - %s - %s' % (str(self.error_code), error_msg_short, error_msg_verbose)
        else:
            return 'ATSVC SessionError: unknown error code: %s' % (str(self.error_code))
    

class DCERPCAtSvc:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                error_code = unpack("<L", answer[-4:])[0]
                raise ATSVCSessionError(error_code)  
        return answer

    def NetrJobAdd(self, serverName, atInfo):
        jobAdd = ATSVCNetrJobAdd()
        jobAdd['ServerName']         = ndrutils.NDRUniqueStringW()
        jobAdd['ServerName']['Data'] = (serverName+'\x00').encode('utf-16le')

        jobAdd['pAtInfo'] = atInfo

        packet = self.doRequest(jobAdd, checkReturn = 1)
        ans = ATSVCNetrJobAddResponse(packet)
        return ans

    def NetrJobDel(self, serverName, minJobId, maxJobId):
        jobDel = ATSVCNetrJobDel()
        jobDel['ServerName']         = ndrutils.NDRUniqueStringW()
        jobDel['ServerName']['Data'] = (serverName+'\x00').encode('utf-16le')
        jobDel['MinJobId'] = minJobId
        jobDel['MaxJobId'] = maxJobId
        packet = self.doRequest(jobDel, checkReturn = 1)
        return packet 

    def NetrJobEnum(self, serverName, resumeHandle = 0x0 ):
        jobEnum = ATSVCNetrJobEnum()
        jobEnum['ServerName']         = ndrutils.NDRUniqueStringW()
        jobEnum['ServerName']['Data'] = (serverName+'\x00').encode('utf-16le')
        jobEnum['ResumeHandle']       = resumeHandle
        packet = self.doRequest(jobEnum, checkReturn = 1)
        ans = ATSVCNetrJobEnumResponse(packet) 
        return ans

    def SchRpcEnumTasks(self, path, startIndex=0, flags=0):
        enumTasks = ATSVCSchRpcEnumTasks()
        enumTasks['Path'] = ndrutils.NDRStringW()
        enumTasks['Path']['Data'] = (path+'\x00').encode('utf-16le')
        enumTasks['StartIndex'] = startIndex
        enumTasks['Flags'] = 0
        packet = self.doRequest(enumTasks, checkReturn = 0)
        ans = ATSVCSchRpcEnumTasksResp(packet)
        return ans

    def SchRpcRun(self, path):
        rpcRun = ATSVCSchRpcRun()
        rpcRun['Path'] = ndrutils.NDRStringW()
        rpcRun['Path']['Data'] = (path+'\x00').encode('utf-16le')
        packet = self.doRequest(rpcRun, checkReturn = 0)
        return packet






