# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-BKRP] Interface implementation
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
# Author:
#   Alberto Solino (@agsolino)
#
# ToDo:
#   [ ] 2.2.2 Client-Side-Wrapped Secret
#

from __future__ import division
from __future__ import print_function
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import DWORD, NTSTATUS, GUID, RPC_SID, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin, string_to_bin
from impacket.structure import Structure

MSRPC_UUID_BKRP = uuidtup_to_bin(('3dde7c30-165d-11d1-ab8f-00805f14db40', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'BKRP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'BKRP SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

BACKUPKEY_BACKUP_GUID = string_to_bin("7F752B10-178E-11D1-AB8F-00805F14DB40")
BACKUPKEY_RESTORE_GUID_WIN2K = string_to_bin("7FE94D50-178E-11D1-AB8F-00805F14DB40")
BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = string_to_bin("018FF48A-EABA-40C6-8F6D-72370240E967")
BACKUPKEY_RESTORE_GUID =  string_to_bin("47270C64-2FC7-499B-AC5B-0E37CDCE899A")

################################################################################
# STRUCTURES
################################################################################
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

# 2.2.4.1 Rc4EncryptedPayload Structure
class Rc4EncryptedPayload(Structure):
    structure = (
        ('R3', '32s=""'),
        ('MAC', '20s=""'),
        ('SID', ':', RPC_SID),
        ('Secret', ':'),
    )

# 2.2.4 Secret Wrapped with Symmetric Key
class WRAPPED_SECRET(Structure):
    structure = (
        ('SIGNATURE', '<L=1'),
        ('Payload_Length', '<L=0'),
        ('Ciphertext_Length', '<L=0'),
        ('GUID_of_Wrapping_Key', '16s=""'),
        ('R2', '68s=""'),
        ('_Rc4EncryptedPayload', '_-Rc4EncryptedPayload', 'self["Payload_Length"]'),
        ('Rc4EncryptedPayload', ':'),
    )

################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1 BackuprKey(Opnum 0)
class BackuprKey(NDRCALL):
    opnum = 0
    structure = (
       ('pguidActionAgent', GUID),
       ('pDataIn', BYTE_ARRAY),
       ('cbDataIn', DWORD),
       ('dwParam', DWORD),
    )

class BackuprKeyResponse(NDRCALL):
    structure = (
       ('ppDataOut', PBYTE_ARRAY),
       ('pcbDataOut', DWORD),
       ('ErrorCode', NTSTATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (BackuprKey, BackuprKeyResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hBackuprKey(dce, pguidActionAgent, pDataIn, dwParam=0):
    request = BackuprKey()
    request['pguidActionAgent'] = pguidActionAgent
    request['pDataIn'] = pDataIn
    if pDataIn == NULL:
        request['cbDataIn'] = 0
    else:
        request['cbDataIn'] = len(pDataIn)
    request['dwParam'] = dwParam
    return dce.request(request)
