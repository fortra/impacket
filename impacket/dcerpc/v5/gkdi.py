# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import ULONG, PGUID, LONG, NTSTATUS, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors
from impacket.structure import Structure
from impacket.uuid import uuidtup_to_bin

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'GKDI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'GKDI SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

MSRPC_UUID_GKDI = uuidtup_to_bin(('B9785960-524F-11DF-8B6D-83DCDED72085','1.0'))

################################################################################
# STRUCTURES
################################################################################

# 2.2.1 KDF Parameters
class KDFParameter(Structure):
    structure = (
        ('Unknown1','<L=0'),
        ('Unknown2','<L=0'),
        ('HashLen','<L=0'),
        ('Unknown3','<L=0'),
        ('_HashName','_-HashName', 'self["HashLen"]'),
        ('HashName',':')
    )

# 2.2.2 FFC DH Parameters
class FFCDHParameter(Structure):
    structure = (
        ('Length', '<L=0'),
        ('Magic', '<4s=0'),
        ('KeyLength', '<L=0'),
        ('_FieldOrder','_-FieldOrder', 'self["KeyLength"]'),
        ('FieldOrder',':'),
        ('_Generator','_-Generator', 'self["KeyLength"]'),
        ('Generator',':')
    )

    def dump(self):
        print("[FFCDH PARAMETER]")
        print("Length:\t\t%s" % (self['Length']))
        print("Magic:\t\t%s" % (self['Magic']))
        print("KeyLength:\t\t%s" % (self['KeyLength']))
        print("FieldOrder:\t\t%s" % (self['FieldOrder']))
        print("Generator:\t\t%s" % (self['Generator']))
        print()

# 2.2.3.1 FFC DH Key
class FFCDHKey(Structure):
    structure = (
        ('Magic', '<4s=0'),
        ('KeyLength', '<L=0'),
        ('_FieldOrder','_-FieldOrder', 'self["KeyLength"]'),
        ('FieldOrder',':'),
        ('_Generator','_-Generator', 'self["KeyLength"]'),
        ('Generator',':'),
        ('_PubKey','_-PubKey', 'self["KeyLength"]'),
        ('PubKey',':'),
    )

    def dump(self):
        print("[FFCDH KEY]")
        print("KeyLength:\t\t%s" % (self['KeyLength']))
        print("FieldOrder:\t\t%s" % (self['FieldOrder']))
        print("Generator:\t\t%s" % (self['Generator']))
        print("PubKey:\t\t%s" % (self['PubKey']))
        print()

# 2.2.3.2 ECDH Key
class ECDHKey(Structure):
    structure = (
        ('Magic', '<4s=0'),
        ('KeyLength', '<L=0'),
        ('_XCoordinate','_-XCoordinate', 'self["KeyLength"]'),
        ('XCoordinate',':'),
        ('_YCoordinate','_-YCoordinate', 'self["KeyLength"]'),
        ('YCoordinate',':'),
    )

    def dump(self):
        print("[ECDH KEY]")
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("XCoordinate:\t\t%s" % (self['XCoordinate']))
        print("YCoordinate:\t\t%s" % (self['YCoordinate']))
        print()

# 2.2.4 Group Key Envelope
class GroupKeyEnvelope(Structure):
    structure = (
        ('Version', '<L=0'),
        ('Magic', '<L=0'),
        ('Flags', '<L=0'),
        ('L0Index', '<L=0'),
        ('L1Index', '<L=0'),
        ('L2Index', '<L=0'),
        ('RootKeyId', '16s=b'),
        ('KdfAlgoLength', '<L=0'),
        ('KdfParaLength', '<L=0'),
        ('SecAlgoLength', '<L=0'),
        ('SecParaLength', '<L=0'),
        ('PrivKeyLength', '<L=0'),
        ('PubKeyLength', '<L=0'),
        ('L1KeyLength', '<L=0'),
        ('L2KeyLength', '<L=0'),
        ('DomainLength', '<L=0'),
        ('ForestLength', '<L=0'),
        ('_KdfAlgo','_-KdfAlgo', 'self["KdfAlgoLength"]'),
        ('KdfAlgo',':'),
        ('_KdfPara','_-KdfPara', 'self["KdfParaLength"]'),
        ('KdfPara',':', KDFParameter),
        ('_SecAlgo','_-SecAlgo', 'self["SecAlgoLength"]'),
        ('SecAlgo',':'),
        ('_SecPara','_-SecPara', 'self["SecParaLength"]'),
        ('SecPara',':'),
        ('_Domain','_-Domain', 'self["DomainLength"]'),
        ('Domain',':'),
        ('_Forest','_-Forest', 'self["ForestLength"]'),
        ('Forest',':'),
        ('_L1Key','_-L1Key', 'self["L1KeyLength"]'),
        ('L1Key',':'),
        ('_L2Key','_-L2Key', 'self["L2KeyLength"]'),
        ('L2Key',':'),
    )

    def dump(self):
        print("[GROUP KEY ENVELOPE]")
        print("Version:\t\t%s" % (self['Version']))
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("Flags:\t\t%s" % (self['Flags']))
        print("L0Index:\t\t%s" % (self['L0Index']))
        print("L1Index:\t\t%s" % (self['L1Index']))
        print("L2Index:\t\t%s" % (self['L2Index']))
        print("RootKeyId:\t\t%s" % (self['RootKeyId']))
        print("KdfAlgo:\t\t%s" % (self['KdfAlgo'].decode('utf-16le')))
        print("KdfPara:\t\t%s" % (self['KdfPara']['HashName'].decode('utf-16le')))
        print("SecAlgo:\t\t%s" % (self['SecAlgo'].decode('utf-16le')))
        print("SecPara:\t\t%s" % (self['SecPara']))
        print("PrivKeyLength:\t\t%s" % (self['PrivKeyLength']))
        print("PubKeyLength:\t\t%s" % (self['PubKeyLength']))
        print("Domain:\t\t%s" % (self['Domain'].decode('utf-16le')))
        print("Forest:\t\t%s" % (self['Forest'].decode('utf-16le')))
        print("L1Key:\t\t%s" % (self['L1Key']))
        print("L2Key:\t\t%s" % (self['L2Key']))
        print()
    
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

################################################################################
# RPC CALLS
################################################################################

# 3.1.4.1 GetKey (Opnum 0)
class GkdiRpcGetKey(NDRCALL):
    opnum = 0
    structure = (
        ('cbTargetSD', ULONG),
        ('pbTargetSD', BYTE_ARRAY),
        ('pRootKeyID', PGUID),
        ('L0KeyID', LONG),
        ('L1KeyID', LONG),
        ('L2KeyID', LONG),
    )

class GkdiRpcGetKeyResponse(NDRCALL):
    opnum = 0
    structure = (
        ('pcbOut', ULONG),
        ('pbbOut', PBYTE_ARRAY),
        ('ErrorCode', NTSTATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################

OPNUMS = {
    0   : (GkdiRpcGetKey, GkdiRpcGetKeyResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def GkdiGetKey(dce, target_sd, l0 =-1, l1=-1, l2=-1, root_key_id=NULL):
    request = GkdiRpcGetKey()
    request['cbTargetSD'] = len(target_sd)
    request['pbTargetSD'] = target_sd.getData()
    request['pRootKeyID'] = root_key_id
    request['L0KeyID'] = l0
    request['L1KeyID'] = l1
    request['L2KeyID'] = l2
    return dce.request(request)