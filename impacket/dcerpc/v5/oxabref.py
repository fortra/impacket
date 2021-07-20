# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-OXABREF]: Address Book Name Service Provider Interface (NSPI) Referral Protocol
#
# Author:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#

from impacket import hresult_errors, mapi_constants
from impacket.dcerpc.v5.dtypes import NULL, STR, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_OXABREF = uuidtup_to_bin(('1544F5E0-613C-11D1-93DF-00C04FD7BD09','1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in mapi_constants.ERROR_MESSAGES:
            error_msg_short = mapi_constants.ERROR_MESSAGES[key]
            return 'OXABREF SessionError: code: 0x%x - %s' % (self.error_code, error_msg_short)
        elif key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'OXABREF SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'OXABREF SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# STRUCTURES
################################################################################
class PUCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', STR),
    )

class PPUCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', PUCHAR_ARRAY),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.1.4.1 RfrGetNewDSA (opnum 0)
class RfrGetNewDSA(NDRCALL):
    opnum = 0
    structure = (
       ('ulFlags', ULONG),
       ('pUserDN', STR),
       ('ppszUnused', PPUCHAR_ARRAY),
       ('ppszServer', PPUCHAR_ARRAY),
    )

class RfrGetNewDSAResponse(NDRCALL):
    structure = (
       ('ppszUnused', PPUCHAR_ARRAY),
       ('ppszServer', PPUCHAR_ARRAY),
    )

# 3.1.4.2 RfrGetFQDNFromServerDN (opnum 1)
class RfrGetFQDNFromServerDN(NDRCALL):
    opnum = 1
    structure = (
       ('ulFlags', ULONG),
       ('cbMailboxServerDN', ULONG),
       ('szMailboxServerDN', STR),
    )

class RfrGetFQDNFromServerDNResponse(NDRCALL):
    structure = (
       ('ppszServerFQDN', PUCHAR_ARRAY),
       ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0   : (RfrGetNewDSA, RfrGetNewDSAResponse),
    1   : (RfrGetFQDNFromServerDN, RfrGetFQDNFromServerDNResponse),
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

def hRfrGetNewDSA(dce, pUserDN=''):
    request = RfrGetNewDSA()
    request['ulFlags'] = 0
    request['pUserDN'] = checkNullString(pUserDN)
    request['ppszUnused'] = NULL
    request['ppszServer'] = '\x00'

    resp = dce.request(request)
    resp['ppszServer'] = resp['ppszServer'][:-1]

    if request['ppszUnused'] != NULL:
        resp['ppszUnused'] = resp['ppszUnused'][:-1]

    return resp

def hRfrGetFQDNFromServerDN(dce, szMailboxServerDN):
    szMailboxServerDN = checkNullString(szMailboxServerDN)
    request = RfrGetFQDNFromServerDN()
    request['ulFlags'] = 0
    request['szMailboxServerDN'] = szMailboxServerDN
    request['cbMailboxServerDN'] = len(szMailboxServerDN)

    resp = dce.request(request)
    resp['ppszServerFQDN'] = resp['ppszServerFQDN'][:-1]

    return resp
