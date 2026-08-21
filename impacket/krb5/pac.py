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
#   [MS-PAC] Implementation
#
# Author:
#   Alberto Solino (@agsolino)
#
from binascii import Error as BinasciiError, unhexlify

from impacket.dcerpc.v5.dtypes import ULONG, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT, RPC_SID, SID, LONG64, LPWSTR
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRUNION
from impacket.dcerpc.v5.nrpc import USER_SESSION_KEY, CHAR_FIXED_8_ARRAY, PUCHAR_ARRAY, PRPC_UNICODE_STRING_ARRAY
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.crypto import Key, _checksum_table, Enctype
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.structure import Structure

################################################################################
# CONSTANTS
################################################################################
# From https://msdn.microsoft.com/library/aa302203#msdn_pac_credentials
# and http://diswww.mit.edu/menelaus.mit.edu/cvs-krb5/25862
PAC_LOGON_INFO       = 1
PAC_CREDENTIALS_INFO = 2
PAC_SERVER_CHECKSUM  = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO_TYPE = 10
PAC_DELEGATION_INFO  = 11
PAC_UPN_DNS_INFO     = 12
PAC_CLIENT_CLAIMS_INFO_TYPE = 13
PAC_DEVICE_INFO_TYPE        = 14
PAC_DEVICE_CLAIMS_INFO_TYPE = 15
PAC_ATTRIBUTES_INFO  = 17
PAC_REQUESTOR_INFO   = 18

################################################################################
# STRUCTURES
################################################################################

PISID = PRPC_SID

################################################################################
# [MS-ADTS] 2.2.18 CLAIMS_SET (PAC client/device claims — buffers 13 and 15)
################################################################################
# CLAIM_TYPE (2.2.18.6)
CLAIM_TYPE_INT64   = 1
CLAIM_TYPE_UINT64  = 2
CLAIM_TYPE_STRING  = 3
CLAIM_TYPE_BOOLEAN = 6
# CLAIMS_SOURCE_TYPE (2.2.18.5)
CLAIMS_SOURCE_TYPE_AD          = 1
CLAIMS_SOURCE_TYPE_CERTIFICATE = 2
# CLAIMS_COMPRESSION_FORMAT (2.2.18.4)
CLAIMS_COMPRESSION_FORMAT_NONE        = 0
CLAIMS_COMPRESSION_FORMAT_LZNT1       = 2
CLAIMS_COMPRESSION_FORMAT_XPRESS      = 3
CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF = 4

class CLAIMS_ULONG64(NDRSTRUCT):
    align = 8
    structure = (('Data', '<Q=0'),)
class CLAIMS_UCHAR(NDRSTRUCT):
    align = 1
    structure = (('Data', '<B=0'),)
class CLAIMS_UCHAR_ARRAY(NDRUniConformantArray):
    item = CLAIMS_UCHAR
class PCLAIMS_UCHAR_ARRAY(NDRPOINTER):
    referent = (('Data', CLAIMS_UCHAR_ARRAY),)

class LPWSTR_ARRAY(NDRUniConformantArray):
    item = LPWSTR
class PLPWSTR_ARRAY(NDRPOINTER):
    referent = (('Data', LPWSTR_ARRAY),)
class LONG64_ARRAY(NDRUniConformantArray):
    item = LONG64
class PLONG64_ARRAY(NDRPOINTER):
    referent = (('Data', LONG64_ARRAY),)
class CLAIMS_ULONG64_ARRAY(NDRUniConformantArray):
    item = CLAIMS_ULONG64
class PCLAIMS_ULONG64_ARRAY(NDRPOINTER):
    referent = (('Data', CLAIMS_ULONG64_ARRAY),)

class CLAIM_ENTRY_INT64(NDRSTRUCT):
    structure = (('ValueCount', ULONG), ('Int64Values', PLONG64_ARRAY),)
class CLAIM_ENTRY_UINT64(NDRSTRUCT):
    structure = (('ValueCount', ULONG), ('Uint64Values', PCLAIMS_ULONG64_ARRAY),)
class CLAIM_ENTRY_STRING(NDRSTRUCT):
    structure = (('ValueCount', ULONG), ('StringValues', PLPWSTR_ARRAY),)
class CLAIM_ENTRY_BOOLEAN(NDRSTRUCT):
    structure = (('ValueCount', ULONG), ('BooleanValues', PCLAIMS_ULONG64_ARRAY),)

class CLAIM_ENTRY_VALUES(NDRUNION):
    commonHdr = (('tag', USHORT),)
    union = {
        CLAIM_TYPE_INT64:   ('int64',   CLAIM_ENTRY_INT64),
        CLAIM_TYPE_UINT64:  ('uint64',  CLAIM_ENTRY_UINT64),
        CLAIM_TYPE_STRING:  ('string',  CLAIM_ENTRY_STRING),
        CLAIM_TYPE_BOOLEAN: ('boolean', CLAIM_ENTRY_BOOLEAN),
    }

class CLAIM_ENTRY(NDRSTRUCT):
    structure = (('Id', LPWSTR), ('Values', CLAIM_ENTRY_VALUES),)
class CLAIM_ENTRY_ARRAY(NDRUniConformantArray):
    item = CLAIM_ENTRY
class PCLAIM_ENTRY_ARRAY(NDRPOINTER):
    referent = (('Data', CLAIM_ENTRY_ARRAY),)

class CLAIMS_ARRAY(NDRSTRUCT):
    structure = (('usClaimsSourceType', USHORT), ('ulClaimsCount', ULONG),
                 ('ClaimEntries', PCLAIM_ENTRY_ARRAY),)
class CLAIMS_ARRAY_ARRAY(NDRUniConformantArray):
    item = CLAIMS_ARRAY
class PCLAIMS_ARRAY_ARRAY(NDRPOINTER):
    referent = (('Data', CLAIMS_ARRAY_ARRAY),)

class CLAIMS_SET(NDRSTRUCT):
    structure = (('ulClaimsArrayCount', ULONG), ('ClaimsArrays', PCLAIMS_ARRAY_ARRAY),
                 ('usReservedType', USHORT), ('ulReservedFieldSize', ULONG),
                 ('ReservedField', PCLAIMS_UCHAR_ARRAY),)
class PCLAIMS_SET(NDRPOINTER):
    referent = (('Data', CLAIMS_SET),)
class CLAIMS_SET_TYPE(TypeSerialization1):
    structure = (('Data', PCLAIMS_SET),)

class CLAIMS_SET_METADATA(NDRSTRUCT):
    structure = (('ClaimsSetSize', ULONG), ('ClaimsSet', PCLAIMS_UCHAR_ARRAY),
                 ('usCompressionFormat', USHORT), ('ulUncompressedClaimsSetSize', ULONG),
                 ('usReservedType', USHORT), ('ulReservedFieldSize', ULONG),
                 ('ReservedField', PCLAIMS_UCHAR_ARRAY),)
class PCLAIMS_SET_METADATA(NDRPOINTER):
    referent = (('Data', CLAIMS_SET_METADATA),)
class CLAIMS_SET_METADATA_TYPE(TypeSerialization1):
    structure = (('Data', PCLAIMS_SET_METADATA),)

CLAIM_TYPE_NAME    = {1: 'int64', 2: 'uint64', 3: 'string', 6: 'boolean'}
CLAIMS_SOURCE_NAME = {1: 'AD', 2: 'CERTIFICATE'}

def _claims_parse_ts(cls, blob):
    # TypeSerialization1-wrapped pointer type: flat pass, then referent pass.
    obj = cls()
    obj.fromString(blob)
    obj.fromStringReferents(blob[len(obj.getData()):])
    return obj

def _claims_wstr(x):
    return (x if isinstance(x, str) else x['Data']).rstrip('\x00')

def parse_claims_set(blob):
    """Decode a PAC_CLIENT_CLAIMS_INFO / PAC_DEVICE_CLAIMS_INFO ['Claims'] blob
    (CLAIMS_SET_METADATA -> CLAIMS_SET). Returns a list of
    {'source', 'id', 'type', 'values'} dicts. Raises NotImplementedError if the
    CLAIMS_SET is compressed (XPRESS-Huffman decompression not yet supported)."""
    meta = _claims_parse_ts(CLAIMS_SET_METADATA_TYPE, blob)['Data']
    fmt = meta['usCompressionFormat']
    if fmt != CLAIMS_COMPRESSION_FORMAT_NONE:
        raise NotImplementedError(
            "CLAIMS_SET is compressed (format %d) - decompression not yet supported" % fmt)
    cs_bytes = bytes(u['Data'] for u in meta['ClaimsSet'])
    cs = _claims_parse_ts(CLAIMS_SET_TYPE, cs_bytes)['Data']
    claims = []
    for arr in cs['ClaimsArrays']:
        src = CLAIMS_SOURCE_NAME.get(arr['usClaimsSourceType'], arr['usClaimsSourceType'])
        for ent in arr['ClaimEntries']:
            t = ent['Values']['tag']; u = ent['Values']
            if   t == CLAIM_TYPE_STRING:  vals = [_claims_wstr(x) for x in u['string']['StringValues']]
            elif t == CLAIM_TYPE_INT64:   vals = [x['Data'] for x in u['int64']['Int64Values']]
            elif t == CLAIM_TYPE_UINT64:  vals = [x['Data'] for x in u['uint64']['Uint64Values']]
            elif t == CLAIM_TYPE_BOOLEAN: vals = [bool(x['Data']) for x in u['boolean']['BooleanValues']]
            else: vals = []
            claims.append({'source': src, 'id': _claims_wstr(ent['Id']),
                           'type': CLAIM_TYPE_NAME.get(t, t), 'values': vals})
    return claims

# 2.2.1 KERB_SID_AND_ATTRIBUTES
class KERB_SID_AND_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Sid', PISID),
        ('Attributes', ULONG),
    )

class KERB_SID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
    item = KERB_SID_AND_ATTRIBUTES

class PKERB_SID_AND_ATTRIBUTES_ARRAY(NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

# 2.2.2 GROUP_MEMBERSHIP
from impacket.dcerpc.v5.nrpc import PGROUP_MEMBERSHIP_ARRAY

# 2.2.3 DOMAIN_GROUP_MEMBERSHIP
class DOMAIN_GROUP_MEMBERSHIP(NDRSTRUCT):
    structure = (
        ('DomainId', PISID),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class DOMAIN_GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = DOMAIN_GROUP_MEMBERSHIP

class PDOMAIN_GROUP_MEMBERSHIP_ARRAY(NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

# 2.3 PACTYPE
class PACTYPE(Structure):
    structure = (
        ('cBuffers', '<L=0'),
        ('Version', '<L=0'),
        ('Buffers', ':'),
    )

# 2.4 PAC_INFO_BUFFER
class PAC_INFO_BUFFER(Structure):
    structure = (
        ('ulType', '<L=0'),
        ('cbBufferSize', '<L=0'),
        ('Offset', '<Q=0'),
    )

# 2.5 KERB_VALIDATION_INFO
class KERB_VALIDATION_INFO(NDRSTRUCT):
    structure = (
        ('LogonTime', FILETIME),
        ('LogoffTime', FILETIME),
        ('KickOffTime', FILETIME),
        ('PasswordLastSet', FILETIME),
        ('PasswordCanChange', FILETIME),
        ('PasswordMustChange', FILETIME),
        ('EffectiveName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('LogonScript', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('LogonCount', USHORT),
        ('BadPasswordCount', USHORT),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', RPC_UNICODE_STRING),
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('LogonDomainId', PRPC_SID),

        # Also called Reserved1
        ('LMKey', CHAR_FIXED_8_ARRAY),

        ('UserAccountControl', ULONG),
        ('SubAuthStatus', ULONG),
        ('LastSuccessfulILogon', FILETIME),
        ('LastFailedILogon', FILETIME),
        ('FailedILogonCount', ULONG),
        ('Reserved3', ULONG),

        ('SidCount', ULONG),
        #('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY),
        ('ResourceGroupDomainSid', PISID),
        ('ResourceGroupCount', ULONG),
        ('ResourceGroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class PKERB_VALIDATION_INFO(NDRPOINTER):
    referent = (
        ('Data', KERB_VALIDATION_INFO),
    )

# 2.6.1 PAC_CREDENTIAL_INFO
class PAC_CREDENTIAL_INFO(Structure):
    structure = (
        ('Version', '<L=0'),
        ('EncryptionType', '<L=0'),
        ('SerializedData', ':'),
    )

# 2.6.3 SECPKG_SUPPLEMENTAL_CRED
class SECPKG_SUPPLEMENTAL_CRED(NDRSTRUCT):
    structure = (
        ('PackageName', RPC_UNICODE_STRING),
        ('CredentialSize', ULONG),
        ('Credentials', PUCHAR_ARRAY),
    )

class SECPKG_SUPPLEMENTAL_CRED_ARRAY(NDRUniConformantArray):
    item = SECPKG_SUPPLEMENTAL_CRED

# 2.6.2 PAC_CREDENTIAL_DATA
class PAC_CREDENTIAL_DATA(NDRSTRUCT):
    structure = (
        ('CredentialCount', ULONG),
        ('Credentials', SECPKG_SUPPLEMENTAL_CRED_ARRAY),
    )

# 2.6.4 NTLM_SUPPLEMENTAL_CREDENTIAL
class NTLM_SUPPLEMENTAL_CREDENTIAL(NDRSTRUCT):
    structure = (
        ('Version', ULONG),
        ('Flags', ULONG),
        ('LmPassword', '16s=b""'),
        ('NtPassword', '16s=b""'),
    )

# 2.7 PAC_CLIENT_INFO
class PAC_CLIENT_INFO(Structure):
    structure = (
        ('ClientId', '<Q=0'),
        ('NameLength', '<H=0'),
        ('_Name', '_-Name', 'self["NameLength"]'),
        ('Name', ':'),
    )

# 2.8 PAC_SIGNATURE_DATA
class PAC_SIGNATURE_DATA(Structure):
    structure = (
        ('SignatureType', '<l=0'),
        ('Signature', ':'),
    )

# 2.9 Constrained Delegation Information - S4U_DELEGATION_INFO
class S4U_DELEGATION_INFO(NDRSTRUCT):
    structure = (
        ('S4U2proxyTarget', RPC_UNICODE_STRING),
        ('TransitedListSize', ULONG),
        ('S4UTransitedServices', PRPC_UNICODE_STRING_ARRAY ),
    )

# 2.10 UPN_DNS_INFO
class UPN_DNS_INFO(Structure):
    structure = (
        ('UpnLength', '<H=0'),
        ('UpnOffset', '<H=0'),
        ('DnsDomainNameLength', '<H=0'),
        ('DnsDomainNameOffset', '<H=0'),
        ('Flags', '<L=0')
    )

# 2.10 UPN_DNS_INFO
# Full struct including additional fields (use this structure when S Flag is set)
class UPN_DNS_INFO_FULL(Structure):
    structure = (
        ('UpnLength', '<H=0'),
        ('UpnOffset', '<H=0'),
        ('DnsDomainNameLength', '<H=0'),
        ('DnsDomainNameOffset', '<H=0'),
        ('Flags', '<L=0'),
        ('SamNameLength', '<H=0'),
        ('SamNameOffset', '<H=0'),
        ('SidLength', '<H=0'),
        ('SidOffset', '<H=0'),
    )

# 2.11 PAC_CLIENT_CLAIMS_INFO
class PAC_CLIENT_CLAIMS_INFO(Structure):
    structure = (
        ('Claims', ':'),
    )

# 2.12 PAC_DEVICE_INFO
class PAC_DEVICE_INFO(NDRSTRUCT):
    structure = (
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('AccountDomainId', PISID ),
        ('AccountGroupCount', ULONG ),
        ('AccountGroupIds', PGROUP_MEMBERSHIP_ARRAY ),
        ('SidCount', ULONG ),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY ),
        ('DomainGroupCount', ULONG ),
        ('DomainGroup', PDOMAIN_GROUP_MEMBERSHIP_ARRAY ),
    )

# 2.13 PAC_DEVICE_CLAIMS_INFO
class PAC_DEVICE_CLAIMS_INFO(Structure):
    structure = (
        ('Claims', ':'),
    )

class VALIDATION_INFO(TypeSerialization1):
    structure = (
        ('Data', PKERB_VALIDATION_INFO),
    )

# 2.14 PAC_ATTRIBUTES_INFO
class PAC_ATTRIBUTE_INFO(NDRSTRUCT):
    structure = (
        ('FlagsLength', ULONG),
        ('Flags', ULONG),
    )

# 2.15 PAC_REQUESTOR
class PAC_REQUESTOR(Structure):
    structure = (
        ('UserSid',':',SID),
    )


def get_pad_length(data_length):
    return get_block_length(data_length) - data_length


def get_block_length(data_length):
    return (data_length + 7) // 8 * 8


def _coerce_hex_key(key):
    if key in (None, '', b''):
        return None

    try:
        return unhexlify(key)
    except (TypeError, BinasciiError):
        if isinstance(key, bytes):
            return key
        return key.encode('utf-8')


def _ordered_buffer_types(pac_infos, buffer_order=None):
    ordered_types = []
    seen = set()

    if buffer_order is not None:
        for ul_type in buffer_order:
            if ul_type in pac_infos and ul_type not in seen:
                ordered_types.append(ul_type)
                seen.add(ul_type)

    for ul_type in pac_infos:
        if ul_type not in seen:
            ordered_types.append(ul_type)

    return ordered_types


def build_pac_type(pac_infos, buffer_order=None):
    ordered_types = _ordered_buffer_types(pac_infos, buffer_order)
    offset_data = 8 + len(PAC_INFO_BUFFER().getData()) * len(ordered_types)
    info_buffers = b''
    data_blobs = b''

    for ul_type in ordered_types:
        data = pac_infos[ul_type]

        info_buffer = PAC_INFO_BUFFER()
        info_buffer['ulType'] = ul_type
        info_buffer['cbBufferSize'] = len(data)
        info_buffer['Offset'] = offset_data
        info_buffers += info_buffer.getData()

        data_blobs += data + (b'\x00' * get_pad_length(len(data)))
        offset_data = get_block_length(offset_data + len(data))

    pac_type = PACTYPE()
    pac_type['cBuffers'] = len(ordered_types)
    pac_type['Version'] = 0
    pac_type['Buffers'] = info_buffers + data_blobs
    return pac_type


def _normalize_pac_checksum_type(signature_type, signature_length, aes_key, infer_aes_signature_type):
    if infer_aes_signature_type and aes_key is not None and signature_length == 12:
        if len(aes_key) == 16:
            return constants.ChecksumTypes.hmac_sha1_96_aes128.value
        if len(aes_key) == 32:
            return constants.ChecksumTypes.hmac_sha1_96_aes256.value
    return signature_type


def _get_checksum_context(signature_type, aes_key, nt_hash, checksum_name):
    checksum_function = _checksum_table[signature_type]

    if signature_type == constants.ChecksumTypes.hmac_sha1_96_aes256.value:
        if aes_key is None:
            raise Exception('Missing AES key for %s checksum' % checksum_name)
        return checksum_function, Key(Enctype.AES256, aes_key)
    if signature_type == constants.ChecksumTypes.hmac_sha1_96_aes128.value:
        if aes_key is None:
            raise Exception('Missing AES key for %s checksum' % checksum_name)
        return checksum_function, Key(Enctype.AES128, aes_key)
    if signature_type == constants.ChecksumTypes.hmac_md5.value:
        if nt_hash is None:
            raise Exception('Missing NT hash for %s checksum' % checksum_name)
        return checksum_function, Key(Enctype.RC4, nt_hash)

    raise Exception('Invalid %s checksum type 0x%x' % (checksum_name, signature_type))


def sign_pac(pac_infos, aes_key=None, nt_hash=None, buffer_order=None,
             checksum_salt=constants.KERB_NON_KERB_CKSUM_SALT, infer_aes_signature_type=False):
    if PAC_SERVER_CHECKSUM not in pac_infos:
        raise Exception('PAC_SERVER_CHECKSUM not found! Aborting')
    if PAC_PRIVSVR_CHECKSUM not in pac_infos:
        raise Exception('PAC_PRIVSVR_CHECKSUM not found! Aborting')

    aes_key = _coerce_hex_key(aes_key)
    nt_hash = _coerce_hex_key(nt_hash)

    server_checksum = PAC_SIGNATURE_DATA(pac_infos[PAC_SERVER_CHECKSUM])
    privsvr_checksum = PAC_SIGNATURE_DATA(pac_infos[PAC_PRIVSVR_CHECKSUM])

    server_checksum['SignatureType'] = _normalize_pac_checksum_type(
        server_checksum['SignatureType'], len(bytes(server_checksum['Signature'])), aes_key, infer_aes_signature_type)
    privsvr_checksum['SignatureType'] = _normalize_pac_checksum_type(
        privsvr_checksum['SignatureType'], len(bytes(privsvr_checksum['Signature'])), aes_key, infer_aes_signature_type)

    server_checksum['Signature'] = b'\x00' * len(bytes(server_checksum['Signature']))
    privsvr_checksum['Signature'] = b'\x00' * len(bytes(privsvr_checksum['Signature']))

    pac_infos[PAC_SERVER_CHECKSUM] = server_checksum.getData()
    pac_infos[PAC_PRIVSVR_CHECKSUM] = privsvr_checksum.getData()

    pac_type = build_pac_type(pac_infos, buffer_order=buffer_order)
    blob_to_checksum = pac_type.getData()

    server_checksum_function, server_key = _get_checksum_context(
        server_checksum['SignatureType'], aes_key, nt_hash, 'Server')
    privsvr_checksum_function, privsvr_key = _get_checksum_context(
        privsvr_checksum['SignatureType'], aes_key, nt_hash, 'Priv')

    server_checksum['Signature'] = server_checksum_function.checksum(server_key, checksum_salt, blob_to_checksum)
    privsvr_checksum['Signature'] = privsvr_checksum_function.checksum(
        privsvr_key, checksum_salt, server_checksum['Signature'])

    pac_infos[PAC_SERVER_CHECKSUM] = server_checksum.getData()
    pac_infos[PAC_PRIVSVR_CHECKSUM] = privsvr_checksum.getData()

    return build_pac_type(pac_infos, buffer_order=buffer_order)
