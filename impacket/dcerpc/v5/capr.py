# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-CAPR] Interface implementation
#
#   MS-CAPR as a protocol The Central Access Policy Identifier (ID) Retrieval Protocol enables an administrative tool to query the
#   Central Access Policies (CAPs) configured on a remote computer. It defines only one opnum and thus only one helper function to\
#   to this.
#
# Author: Abdul Mhanni
#
from impacket import nt_errors
from impacket.dcerpc.v5.dtypes import ULONG, NTSTATUS
from impacket.dcerpc.v5.lsat import LSAPR_SID_INFORMATION, PLSAPR_SID_INFORMATION_ARRAY
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_LSACAP = uuidtup_to_bin(('afc07e2e-311c-4435-808c-c483ffeec7c9', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES:
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1]
            return 'CAPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'CAPR SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# STRUCTURES
################################################################################

# 2.2.1.1 LSAPR_WRAPPED_CAPID_SET
class LSAPR_WRAPPED_CAPID_SET(NDRSTRUCT):
    structure = (
        ('Entries', ULONG),
        ('SidInfo', PLSAPR_SID_INFORMATION_ARRAY),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.1.4.1 LsarGetAvailableCAPIDs (Opnum 0)
class LsarGetAvailableCAPIDs(NDRCALL):
    opnum = 0
    structure = (
    )

class LsarGetAvailableCAPIDsResponse(NDRCALL):
    structure = (
        ('WrappedCAPIDs', LSAPR_WRAPPED_CAPID_SET),
        ('ErrorCode', NTSTATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0 : (LsarGetAvailableCAPIDs, LsarGetAvailableCAPIDsResponse),
}

################################################################################
# HELPER FUNCTION
################################################################################
def hLsarGetAvailableCAPIDs(dce):
    request = LsarGetAvailableCAPIDs()
    return dce.request(request)
