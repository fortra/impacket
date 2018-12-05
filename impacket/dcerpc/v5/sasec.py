# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-TSCH] SASec Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, WSTR, NULL
from impacket import hresult_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_SASEC  = uuidtup_to_bin(('378E52B0-C0A9-11CF-822D-00AA0051E40F','1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if hresult_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'TSCH SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
SASEC_HANDLE = WSTR
PSASEC_HANDLE = LPWSTR

MAX_BUFFER_SIZE = 273

# 3.2.5.3.4 SASetAccountInformation (Opnum 0)
TASK_FLAG_RUN_ONLY_IF_LOGGED_ON = 0x40000

################################################################################
# STRUCTURES
################################################################################
class WORD_ARRAY(NDRUniConformantArray):
    item = '<H'

################################################################################
# RPC CALLS
################################################################################
# 3.2.5.3.4 SASetAccountInformation (Opnum 0)
class SASetAccountInformation(NDRCALL):
    opnum = 0
    structure = (
        ('Handle', PSASEC_HANDLE),
        ('pwszJobName', WSTR),
        ('pwszAccount', WSTR),
        ('pwszPassword', LPWSTR),
        ('dwJobFlags', DWORD),
    )

class SASetAccountInformationResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.3.5 SASetNSAccountInformation (Opnum 1)
class SASetNSAccountInformation(NDRCALL):
    opnum = 1
    structure = (
        ('Handle', PSASEC_HANDLE),
        ('pwszAccount', LPWSTR),
        ('pwszPassword', LPWSTR),
    )

class SASetNSAccountInformationResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

# 3.2.5.3.6 SAGetNSAccountInformation (Opnum 2)
class SAGetNSAccountInformation(NDRCALL):
    opnum = 2
    structure = (
        ('Handle', PSASEC_HANDLE),
        ('ccBufferSize', DWORD),
        ('wszBuffer', WORD_ARRAY),
    )

class SAGetNSAccountInformationResponse(NDRCALL):
    structure = (
        ('wszBuffer',WORD_ARRAY),
        ('ErrorCode',ULONG),
    )

# 3.2.5.3.7 SAGetAccountInformation (Opnum 3)
class SAGetAccountInformation(NDRCALL):
    opnum = 3
    structure = (
        ('Handle', PSASEC_HANDLE),
        ('pwszJobName', WSTR),
        ('ccBufferSize', DWORD),
        ('wszBuffer', WORD_ARRAY),
    )

class SAGetAccountInformationResponse(NDRCALL):
    structure = (
        ('wszBuffer',WORD_ARRAY),
        ('ErrorCode',ULONG),
    )
################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (SASetAccountInformation, SASetAccountInformationResponse),
 1 : (SASetNSAccountInformation, SASetNSAccountInformationResponse),
 2 : (SAGetNSAccountInformation, SAGetNSAccountInformationResponse),
 3 : (SAGetAccountInformation, SAGetAccountInformationResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def hSASetAccountInformation(dce, handle, pwszJobName, pwszAccount, pwszPassword, dwJobFlags=0):
    request = SASetAccountInformation()
    request['Handle'] = handle
    request['pwszJobName'] = checkNullString(pwszJobName)
    request['pwszAccount'] = checkNullString(pwszAccount)
    request['pwszPassword'] = checkNullString(pwszPassword)
    request['dwJobFlags'] = dwJobFlags
    return dce.request(request)

def hSASetNSAccountInformation(dce, handle, pwszAccount, pwszPassword):
    request = SASetNSAccountInformation()
    request['Handle'] = handle
    request['pwszAccount'] = checkNullString(pwszAccount)
    request['pwszPassword'] = checkNullString(pwszPassword)
    return dce.request(request)

def hSAGetNSAccountInformation(dce, handle, ccBufferSize = MAX_BUFFER_SIZE):
    request = SAGetNSAccountInformation()
    request['Handle'] = handle
    request['ccBufferSize'] = ccBufferSize
    for _ in range(ccBufferSize):
        request['wszBuffer'].append(0)
    return dce.request(request)

def hSAGetAccountInformation(dce, handle, pwszJobName, ccBufferSize = MAX_BUFFER_SIZE):
    request = SAGetAccountInformation()
    request['Handle'] = handle
    request['pwszJobName'] = checkNullString(pwszJobName)
    request['ccBufferSize'] = ccBufferSize
    for _ in range(ccBufferSize):
        request['wszBuffer'].append(0)
    return dce.request(request)