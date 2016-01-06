# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [C706] Remote Management Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/CoreSecurity/impacket/tree/master/impacket/testcases/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.epm import PRPC_IF_ID
from impacket.dcerpc.v5.dtypes import ULONG, DWORD_ARRAY, ULONGLONG
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin
from impacket import nt_errors

MSRPC_UUID_MGMT  = uuidtup_to_bin(('afa8bd80-7d8a-11c9-bef4-08002b102989','1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if nt_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'MGMT SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'MGMT SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

class rpc_if_id_p_t_array(NDRUniConformantArray):
    item = PRPC_IF_ID

class rpc_if_id_vector_t(NDRSTRUCT):
    structure = (
        ('count',ULONG),
        ('if_id',rpc_if_id_p_t_array),
    )
    structure64 = (
        ('count',ULONGLONG),
        ('if_id',rpc_if_id_p_t_array),
    )

class rpc_if_id_vector_p_t(NDRPOINTER):
    referent = (
        ('Data', rpc_if_id_vector_t),
    )

error_status = ULONG
################################################################################
# STRUCTURES
################################################################################

################################################################################
# RPC CALLS
################################################################################
class inq_if_ids(NDRCALL):
    opnum = 0
    structure = (
    )

class inq_if_idsResponse(NDRCALL):
    structure = (
       ('if_id_vector', rpc_if_id_vector_p_t),
       ('status', error_status),
    )

class inq_stats(NDRCALL):
    opnum = 1
    structure = (
       ('count', ULONG),
    )

class inq_statsResponse(NDRCALL):
    structure = (
       ('count', ULONG),
       ('statistics', DWORD_ARRAY),
       ('status', error_status),
    )

class is_server_listening(NDRCALL):
    opnum = 2
    structure = (
    )

class is_server_listeningResponse(NDRCALL):
    structure = (
       ('status', error_status),
    )

class stop_server_listening(NDRCALL):
    opnum = 3
    structure = (
    )

class stop_server_listeningResponse(NDRCALL):
    structure = (
       ('status', error_status),
    )

class inq_princ_name(NDRCALL):
    opnum = 4
    structure = (
       ('authn_proto', ULONG),
       ('princ_name_size', ULONG),
    )

class inq_princ_nameResponse(NDRCALL):
    structure = (
       ('princ_name', NDRUniConformantVaryingArray),
       ('status', error_status),
    )


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (inq_if_ids, inq_if_idsResponse),
 1 : (inq_stats, inq_statsResponse),
 2 : (is_server_listening, is_server_listeningResponse),
 3 : (stop_server_listening, stop_server_listeningResponse),
 4 : (inq_princ_name, inq_princ_nameResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hinq_if_ids(dce):
    request = inq_if_ids()
    return dce.request(request)

def hinq_stats(dce, count = 4):
    request = inq_stats()
    request['count'] = count
    return dce.request(request)

def his_server_listening(dce):
    request = is_server_listening()
    return dce.request(request, checkError=False)

def hstop_server_listening(dce):
    request = stop_server_listening()
    return dce.request(request)

def hinq_princ_name(dce, authn_proto=0, princ_name_size=1):
    request = inq_princ_name()
    request['authn_proto'] = authn_proto
    request['princ_name_size'] = princ_name_size
    return dce.request(request, checkError=False)


