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

# Structures

class AT_INFO(Structure):
    structure = (
        ('JobTime', '<L=0xff'),
        ('DaysOfMonth','<L=0'),
        ('DaysOfWeek','<B=0'),
        ('Flags','<B=0'),
        ('unknown','<H=0'),
        ('Command',':',ndrutils.NDRStringW),
    )

# Opnums
class ATSVCNetrJobAdd(Structure):
    opnum = 0
    alignment = 4
    structure = (
        ('ServerName',':',ndrutils.NDRUniqueStringW),
        ('pAtInfo',':',AT_INFO),
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

         ans = self.doRequest(jobAdd, checkReturn = 1)
         return ans

    def NetrJobEnum(self, serverName, resumeHandle = 0x0 ):
         jobEnum = ATSVCNetrJobEnum()
         jobEnum['ServerName']         = ndrutils.NDRUniqueStringW()
         jobEnum['ServerName']['Data'] = (serverName+'\x00').encode('utf-16le')
         jobEnum['ResumeHandle']       = resumeHandle
         packet = self.doRequest(jobEnum, checkReturn = 1)
         ans = ATSVCNetrJobEnumResponse(packet) 
         return ans


