# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-NRPC] Interface implementation
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
from struct import pack
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRPOINTER, NDRUniConformantArray, \
    NDRUniFixedArray, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.dtypes import WSTR, LPWSTR, DWORD, ULONG, USHORT, PGUID, NTSTATUS, NULL, LONG, UCHAR, PRPC_SID, \
    GUID, RPC_UNICODE_STRING, SECURITY_INFORMATION, LPULONG
from impacket import system_errors, nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.samr import OLD_LARGE_INTEGER
from impacket.dcerpc.v5.lsad import PLSA_FOREST_TRUST_INFORMATION
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.structure import Structure
from impacket import ntlm, crypto, LOG
import hmac, hashlib
try:
    from Crypto.Cipher import DES, AES, ARC4
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need PyCrypto")
    LOG.critical("See http://www.pycrypto.org/")

MSRPC_UUID_NRPC = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if system_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'NRPC SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif nt_errors.ERROR_MESSAGES.has_key(key):
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1] 
            return 'NRPC SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'NRPC SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# CONSTANTS
################################################################################
# 2.2.1.2.5 NL_DNS_NAME_INFO
# Type
NlDnsLdapAtSite       = 22
NlDnsGcAtSite         = 25
NlDnsDsaCname         = 28
NlDnsKdcAtSite        = 30
NlDnsDcAtSite         = 32
NlDnsRfc1510KdcAtSite = 34
NlDnsGenericGcAtSite  = 36

# DnsDomainInfoType
NlDnsDomainName      = 1
NlDnsDomainNameAlias = 2
NlDnsForestName      = 3
NlDnsForestNameAlias = 4
NlDnsNdncDomainName  = 5
NlDnsRecordName      = 6

# 2.2.1.3.15 NL_OSVERSIONINFO_V1
# wSuiteMask
VER_SUITE_BACKOFFICE               = 0x00000004
VER_SUITE_BLADE                    = 0x00000400
VER_SUITE_COMPUTE_SERVER           = 0x00004000
VER_SUITE_DATACENTER               = 0x00000080
VER_SUITE_ENTERPRISE               = 0x00000002
VER_SUITE_EMBEDDEDNT               = 0x00000040
VER_SUITE_PERSONAL                 = 0x00000200
VER_SUITE_SINGLEUSERTS             = 0x00000100
VER_SUITE_SMALLBUSINESS            = 0x00000001
VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x00000020
VER_SUITE_STORAGE_SERVER           = 0x00002000
VER_SUITE_TERMINAL                 = 0x00000010

# wProductType
VER_NT_DOMAIN_CONTROLLER = 0x00000002
VER_NT_SERVER            = 0x00000003
VER_NT_WORKSTATION       = 0x00000001

# 2.2.1.4.18 NETLOGON Specific Access Masks
NETLOGON_UAS_LOGON_ACCESS  = 0x0001
NETLOGON_UAS_LOGOFF_ACCESS = 0x0002
NETLOGON_CONTROL_ACCESS    = 0x0004
NETLOGON_QUERY_ACCESS      = 0x0008
NETLOGON_SERVICE_ACCESS    = 0x0010
NETLOGON_FTINFO_ACCESS     = 0x0020
NETLOGON_WKSTA_RPC_ACCESS  = 0x0040

# 3.5.4.9.1 NetrLogonControl2Ex (Opnum 18)
# FunctionCode
NETLOGON_CONTROL_QUERY             = 0x00000001
NETLOGON_CONTROL_REPLICATE         = 0x00000002
NETLOGON_CONTROL_SYNCHRONIZE       = 0x00000003
NETLOGON_CONTROL_PDC_REPLICATE     = 0x00000004
NETLOGON_CONTROL_REDISCOVER        = 0x00000005
NETLOGON_CONTROL_TC_QUERY          = 0x00000006
NETLOGON_CONTROL_TRANSPORT_NOTIFY  = 0x00000007
NETLOGON_CONTROL_FIND_USER         = 0x00000008
NETLOGON_CONTROL_CHANGE_PASSWORD   = 0x00000009
NETLOGON_CONTROL_TC_VERIFY         = 0x0000000A
NETLOGON_CONTROL_FORCE_DNS_REG     = 0x0000000B
NETLOGON_CONTROL_QUERY_DNS_REG     = 0x0000000C
NETLOGON_CONTROL_BACKUP_CHANGE_LOG = 0x0000FFFC
NETLOGON_CONTROL_TRUNCATE_LOG      = 0x0000FFFD
NETLOGON_CONTROL_SET_DBFLAG        = 0x0000FFFE
NETLOGON_CONTROL_BREAKPOINT        = 0x0000FFFF

################################################################################
# STRUCTURES
################################################################################
# 3.5.4.1 RPC Binding Handles for Netlogon Methods
LOGONSRV_HANDLE = WSTR
PLOGONSRV_HANDLE = LPWSTR

# 2.2.1.1.1 CYPHER_BLOCK
class CYPHER_BLOCK(NDRSTRUCT):
    structure = (
        ('Data', '8s=""'),
    )
    def getAlignment(self):
        return 1

NET_API_STATUS = DWORD

# 2.2.1.1.2 STRING
from impacket.dcerpc.v5.lsad import STRING

# 2.2.1.1.3 LM_OWF_PASSWORD
class CYPHER_BLOCK_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return len(CYPHER_BLOCK())*2

class LM_OWF_PASSWORD(NDRSTRUCT):
    structure = (
        ('Data', CYPHER_BLOCK_ARRAY),
    )

# 2.2.1.1.4 NT_OWF_PASSWORD
NT_OWF_PASSWORD = LM_OWF_PASSWORD
ENCRYPTED_NT_OWF_PASSWORD = NT_OWF_PASSWORD

# 2.2.1.3.4 NETLOGON_CREDENTIAL
class UCHAR_FIXED_ARRAY(NDRUniFixedArray):
    align = 1
    def getDataLen(self, data):
        return len(CYPHER_BLOCK())

class NETLOGON_CREDENTIAL(NDRSTRUCT):
    structure = (
        ('Data',UCHAR_FIXED_ARRAY),
    )
    def getAlignment(self):
        return 1

# 2.2.1.1.5 NETLOGON_AUTHENTICATOR
class NETLOGON_AUTHENTICATOR(NDRSTRUCT):
    structure = (
        ('Credential', NETLOGON_CREDENTIAL),
        ('Timestamp', DWORD),
    )

class PNETLOGON_AUTHENTICATOR(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_AUTHENTICATOR),
    )

# 2.2.1.2.1 DOMAIN_CONTROLLER_INFOW
class DOMAIN_CONTROLLER_INFOW(NDRSTRUCT):
    structure = (
        ('DomainControllerName', LPWSTR),
        ('DomainControllerAddress', LPWSTR),
        ('DomainControllerAddressType', ULONG),
        ('DomainGuid', GUID),
        ('DomainName', LPWSTR),
        ('DnsForestName', LPWSTR),
        ('Flags', ULONG),
        ('DcSiteName', LPWSTR),
        ('ClientSiteName', LPWSTR),
    )

class PDOMAIN_CONTROLLER_INFOW(NDRPOINTER):
    referent = (
        ('Data', DOMAIN_CONTROLLER_INFOW),
    )

# 2.2.1.2.2 NL_SITE_NAME_ARRAY
class RPC_UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

class PRPC_UNICODE_STRING_ARRAY(NDRPOINTER):
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    )

class NL_SITE_NAME_ARRAY(NDRSTRUCT):
    structure = (
        ('EntryCount', ULONG),
        ('SiteNames', PRPC_UNICODE_STRING_ARRAY),
    )

class PNL_SITE_NAME_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NL_SITE_NAME_ARRAY),
    )

# 2.2.1.2.3 NL_SITE_NAME_EX_ARRAY
class RPC_UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

class NL_SITE_NAME_EX_ARRAY(NDRSTRUCT):
    structure = (
        ('EntryCount', ULONG),
        ('SiteNames', PRPC_UNICODE_STRING_ARRAY),
        ('SubnetNames', PRPC_UNICODE_STRING_ARRAY),
    )

class PNL_SITE_NAME_EX_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NL_SITE_NAME_EX_ARRAY),
    )

# 2.2.1.2.4 NL_SOCKET_ADDRESS
# 2.2.1.2.4.1 IPv4 Address Structure
class IPv4Address(Structure):
    structure = (
        ('AddressFamily', '<H=0'),
        ('Port', '<H=0'),
        ('Address', '<L=0'),
        ('Padding', '<L=0'),
    )

class UCHAR_ARRAY(NDRUniConformantArray):
    item = 'c'

class PUCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY),
    )

class NL_SOCKET_ADDRESS(NDRSTRUCT):
    structure = (
        ('lpSockaddr', PUCHAR_ARRAY),
        ('iSockaddrLength', ULONG),
    )

class NL_SOCKET_ADDRESS_ARRAY(NDRUniConformantArray):
    item = NL_SOCKET_ADDRESS

# 2.2.1.2.5 NL_DNS_NAME_INFO
class NL_DNS_NAME_INFO(NDRSTRUCT):
    structure = (
        ('Type', ULONG),
        ('DnsDomainInfoType', WSTR),
        ('Priority', ULONG),
        ('Weight', ULONG),
        ('Port', ULONG),
        ('Register', UCHAR),
        ('Status', ULONG),
    )

# 2.2.1.2.6 NL_DNS_NAME_INFO_ARRAY
class NL_DNS_NAME_INFO_ARRAY(NDRUniConformantArray):
    item = NL_DNS_NAME_INFO

class PNL_DNS_NAME_INFO_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NL_DNS_NAME_INFO_ARRAY),
    )

class NL_DNS_NAME_INFO_ARRAY(NDRSTRUCT):
    structure = (
        ('EntryCount', ULONG),
        ('DnsNamesInfo', PNL_DNS_NAME_INFO_ARRAY),
    )

# 2.2.1.3 Secure Channel Establishment and Maintenance Structures
# ToDo

# 2.2.1.3.5 NETLOGON_LSA_POLICY_INFO
class NETLOGON_LSA_POLICY_INFO(NDRSTRUCT):
    structure = (
        ('LsaPolicySize', ULONG),
        ('LsaPolicy', PUCHAR_ARRAY),
    )

class PNETLOGON_LSA_POLICY_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_LSA_POLICY_INFO),
    )

# 2.2.1.3.6 NETLOGON_WORKSTATION_INFO
class NETLOGON_WORKSTATION_INFO(NDRSTRUCT):
    structure = (
        ('LsaPolicy', NETLOGON_LSA_POLICY_INFO),
        ('DnsHostName', LPWSTR),
        ('SiteName', LPWSTR),
        ('Dummy1', LPWSTR),
        ('Dummy2', LPWSTR),
        ('Dummy3', LPWSTR),
        ('Dummy4', LPWSTR),
        ('OsVersion', RPC_UNICODE_STRING),
        ('OsName', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('WorkstationFlags', ULONG),
        ('KerberosSupportedEncryptionTypes', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_WORKSTATION_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_WORKSTATION_INFO),
    )

# 2.2.1.3.7 NL_TRUST_PASSWORD
class WCHAR_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return 512

class NL_TRUST_PASSWORD(NDRSTRUCT):
    structure = (
        ('Buffer', WCHAR_ARRAY),
        ('Length', LPWSTR),
    )

# 2.2.1.3.8 NL_PASSWORD_VERSION
class NL_PASSWORD_VERSION(NDRSTRUCT):
    structure = (
        ('ReservedField', ULONG),
        ('PasswordVersionNumber', ULONG),
        ('PasswordVersionPresent', ULONG),
    )

# 2.2.1.3.9 NETLOGON_WORKSTATION_INFORMATION
class NETLOGON_WORKSTATION_INFORMATION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('WorkstationInfo', PNETLOGON_WORKSTATION_INFO),
        2 : ('LsaPolicyInfo', PNETLOGON_LSA_POLICY_INFO),
    }

# 2.2.1.3.10 NETLOGON_ONE_DOMAIN_INFO
class NETLOGON_ONE_DOMAIN_INFO(NDRSTRUCT):
    structure = (
        ('DomainName', RPC_UNICODE_STRING),
        ('DnsDomainName', RPC_UNICODE_STRING),
        ('DnsForestName', RPC_UNICODE_STRING),
        ('DomainGuid', GUID),
        ('DomainSid', PRPC_SID),
        ('TrustExtension', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class NETLOGON_ONE_DOMAIN_INFO_ARRAY(NDRUniConformantArray):
    item = NETLOGON_ONE_DOMAIN_INFO

class PNETLOGON_ONE_DOMAIN_INFO_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_ONE_DOMAIN_INFO_ARRAY),
    )

# 2.2.1.3.11 NETLOGON_DOMAIN_INFO
class NETLOGON_DOMAIN_INFO(NDRSTRUCT):
    structure = (
        ('PrimaryDomain', NETLOGON_ONE_DOMAIN_INFO),
        ('TrustedDomainCount', ULONG),
        ('TrustedDomains', PNETLOGON_ONE_DOMAIN_INFO_ARRAY),
        ('LsaPolicy', NETLOGON_LSA_POLICY_INFO),
        ('DnsHostNameInDs', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('WorkstationFlags', ULONG),
        ('SupportedEncTypes', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DOMAIN_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DOMAIN_INFO),
    )

# 2.2.1.3.12 NETLOGON_DOMAIN_INFORMATION
class NETLOGON_DOMAIN_INFORMATION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('DomainInfo', PNETLOGON_DOMAIN_INFO),
        2 : ('LsaPolicyInfo', PNETLOGON_LSA_POLICY_INFO),
    }

# 2.2.1.3.13 NETLOGON_SECURE_CHANNEL_TYPE
class NETLOGON_SECURE_CHANNEL_TYPE(NDRENUM):
    class enumItems(Enum):
        NullSecureChannel             = 0
        MsvApSecureChannel            = 1
        WorkstationSecureChannel      = 2
        TrustedDnsDomainSecureChannel = 3
        TrustedDomainSecureChannel    = 4
        UasServerSecureChannel        = 5
        ServerSecureChannel           = 6
        CdcServerSecureChannel        = 7

# 2.2.1.3.14 NETLOGON_CAPABILITIES
class NETLOGON_CAPABILITIES(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('ServerCapabilities', ULONG),
    }

# 2.2.1.3.15 NL_OSVERSIONINFO_V1
class UCHAR_FIXED_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return 128

class NL_OSVERSIONINFO_V1(NDRSTRUCT):
    structure = (
        ('dwOSVersionInfoSize', DWORD),
        ('dwMajorVersion', DWORD),
        ('dwMinorVersion', DWORD),
        ('dwBuildNumber', DWORD),
        ('dwPlatformId', DWORD),
        ('szCSDVersion', UCHAR_FIXED_ARRAY),
        ('wServicePackMajor', USHORT),
        ('wServicePackMinor', USHORT),
        ('wSuiteMask', USHORT),
        ('wProductType', UCHAR),
        ('wReserved', UCHAR),
    )

class PNL_OSVERSIONINFO_V1(NDRPOINTER):
    referent = (
        ('Data', NL_OSVERSIONINFO_V1),
    )

# 2.2.1.3.16 NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1
class PLPWSTR(NDRPOINTER):
    referent = (
        ('Data', LPWSTR),
    )

class NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1(NDRSTRUCT):
    structure = (
        ('ClientDnsHostName', PLPWSTR),
        ('OsVersionInfo', PNL_OSVERSIONINFO_V1),
        ('OsName', PLPWSTR),
    )

# 2.2.1.3.17 NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES
class NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('V1', NL_IN_CHAIN_SET_CLIENT_ATTRIBUTES_V1),
    }

# 2.2.1.3.18 NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1
class NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1(NDRSTRUCT):
    structure = (
        ('HubName', PLPWSTR),
        ('OldDnsHostName', PLPWSTR),
        ('SupportedEncTypes', LPULONG),
    )

# 2.2.1.3.19 NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES
class NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('V1', NL_OUT_CHAIN_SET_CLIENT_ATTRIBUTES_V1),
    }

# 2.2.1.4.1 LM_CHALLENGE
class CHAR_FIXED_8_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return 8

class LM_CHALLENGE(NDRSTRUCT):
    structure = (
        ('Data', CHAR_FIXED_8_ARRAY),
    )

# 2.2.1.4.15 NETLOGON_LOGON_IDENTITY_INFO
class NETLOGON_LOGON_IDENTITY_INFO(NDRSTRUCT):
    structure = (
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('ParameterControl', ULONG),
        ('Reserved', OLD_LARGE_INTEGER),
        ('UserName', RPC_UNICODE_STRING),
        ('Workstation', RPC_UNICODE_STRING),
    )

class PNETLOGON_LOGON_IDENTITY_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_LOGON_IDENTITY_INFO),
    )

# 2.2.1.4.2 NETLOGON_GENERIC_INFO
class NETLOGON_GENERIC_INFO(NDRSTRUCT):
    structure = (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('PackageName', RPC_UNICODE_STRING),
        ('DataLength', ULONG),
        ('LogonData', PUCHAR_ARRAY),
    )

class PNETLOGON_GENERIC_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_GENERIC_INFO),
    )

# 2.2.1.4.3 NETLOGON_INTERACTIVE_INFO
class NETLOGON_INTERACTIVE_INFO(NDRSTRUCT):
    structure = (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('LmOwfPassword', LM_OWF_PASSWORD),
        ('NtOwfPassword', NT_OWF_PASSWORD),
    )

class PNETLOGON_INTERACTIVE_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_INTERACTIVE_INFO),
    )

# 2.2.1.4.4 NETLOGON_SERVICE_INFO
class NETLOGON_SERVICE_INFO(NDRSTRUCT):
    structure = (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('LmOwfPassword', LM_OWF_PASSWORD),
        ('NtOwfPassword', NT_OWF_PASSWORD),
    )

class PNETLOGON_SERVICE_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_SERVICE_INFO),
    )

# 2.2.1.4.5 NETLOGON_NETWORK_INFO
class NETLOGON_NETWORK_INFO(NDRSTRUCT):
    structure = (
        ('Identity', NETLOGON_LOGON_IDENTITY_INFO),
        ('LmChallenge', LM_CHALLENGE),
        ('NtChallengeResponse', STRING),
        ('LmChallengeResponse', STRING),
    )

class PNETLOGON_NETWORK_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_NETWORK_INFO),
    )

# 2.2.1.4.16 NETLOGON_LOGON_INFO_CLASS
class NETLOGON_LOGON_INFO_CLASS(NDRENUM):
    class enumItems(Enum):
        NetlogonInteractiveInformation           = 1
        NetlogonNetworkInformation               = 2
        NetlogonServiceInformation               = 3
        NetlogonGenericInformation               = 4
        NetlogonInteractiveTransitiveInformation = 5
        NetlogonNetworkTransitiveInformation     = 6
        NetlogonServiceTransitiveInformation     = 7

# 2.2.1.4.6 NETLOGON_LEVEL
class NETLOGON_LEVEL(NDRUNION):
    union = {
        NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation           : ('LogonInteractive', PNETLOGON_INTERACTIVE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveTransitiveInformation : ('LogonInteractiveTransitive', PNETLOGON_INTERACTIVE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonServiceInformation               : ('LogonService', PNETLOGON_SERVICE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonServiceTransitiveInformation     : ('LogonServiceTransitive', PNETLOGON_SERVICE_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkInformation               : ('LogonNetwork', PNETLOGON_NETWORK_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation     : ('LogonNetworkTransitive', PNETLOGON_NETWORK_INFO),
        NETLOGON_LOGON_INFO_CLASS.NetlogonGenericInformation               : ('LogonGeneric', PNETLOGON_GENERIC_INFO),
    }

# 2.2.1.4.7 NETLOGON_SID_AND_ATTRIBUTES
class NETLOGON_SID_AND_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Sid', PRPC_SID),
        ('Attributes', ULONG),
    )

# 2.2.1.4.8 NETLOGON_VALIDATION_GENERIC_INFO2
class NETLOGON_VALIDATION_GENERIC_INFO2(NDRSTRUCT):
    structure = (
        ('DataLength', ULONG),
        ('ValidationData', PUCHAR_ARRAY),
    )

class PNETLOGON_VALIDATION_GENERIC_INFO2(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_VALIDATION_GENERIC_INFO2),
    )

# 2.2.1.4.9 USER_SESSION_KEY
USER_SESSION_KEY = LM_OWF_PASSWORD

# 2.2.1.4.10 GROUP_MEMBERSHIP
class GROUP_MEMBERSHIP(NDRSTRUCT):
    structure = (
        ('RelativeId', ULONG),
        ('Attributes', ULONG),
    )

class GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = GROUP_MEMBERSHIP

class PGROUP_MEMBERSHIP_ARRAY(NDRPOINTER):
    referent = (
        ('Data', GROUP_MEMBERSHIP_ARRAY),
    )

# 2.2.1.4.11 NETLOGON_VALIDATION_SAM_INFO
class LONG_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return 4*10

class NETLOGON_VALIDATION_SAM_INFO(NDRSTRUCT):
    structure = (
        ('LogonTime', OLD_LARGE_INTEGER),
        ('LogoffTime', OLD_LARGE_INTEGER),
        ('KickOffTime', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
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
        ('ExpansionRoom', LONG_ARRAY),
    )

class PNETLOGON_VALIDATION_SAM_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_VALIDATION_SAM_INFO),
    )

# 2.2.1.4.12 NETLOGON_VALIDATION_SAM_INFO2
class NETLOGON_SID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
    item = NETLOGON_SID_AND_ATTRIBUTES

class PNETLOGON_SID_AND_ATTRIBUTES_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_SID_AND_ATTRIBUTES_ARRAY),
    )

class NETLOGON_VALIDATION_SAM_INFO2(NDRSTRUCT):
    structure = (
        ('LogonTime', OLD_LARGE_INTEGER),
        ('LogoffTime', OLD_LARGE_INTEGER),
        ('KickOffTime', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
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
        ('ExpansionRoom', LONG_ARRAY),
        ('SidCount', ULONG),
        ('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
    )

class PNETLOGON_VALIDATION_SAM_INFO2(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_VALIDATION_SAM_INFO2),
    )

# 2.2.1.4.13 NETLOGON_VALIDATION_SAM_INFO4
class NETLOGON_VALIDATION_SAM_INFO4(NDRSTRUCT):
    structure = (
        ('LogonTime', OLD_LARGE_INTEGER),
        ('LogoffTime', OLD_LARGE_INTEGER),
        ('KickOffTime', OLD_LARGE_INTEGER),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('PasswordCanChange', OLD_LARGE_INTEGER),
        ('PasswordMustChange', OLD_LARGE_INTEGER),
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

        ('LMKey', CHAR_FIXED_8_ARRAY),
        ('UserAccountControl', ULONG),
        ('SubAuthStatus', ULONG),
        ('LastSuccessfulILogon', OLD_LARGE_INTEGER),
        ('LastFailedILogon', OLD_LARGE_INTEGER),
        ('FailedILogonCount', ULONG),
        ('Reserved4', ULONG),

        ('SidCount', ULONG),
        ('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
        ('DnsLogonDomainName', RPC_UNICODE_STRING),
        ('Upn', RPC_UNICODE_STRING),
        ('ExpansionString1', RPC_UNICODE_STRING),
        ('ExpansionString2', RPC_UNICODE_STRING),
        ('ExpansionString3', RPC_UNICODE_STRING),
        ('ExpansionString4', RPC_UNICODE_STRING),
        ('ExpansionString5', RPC_UNICODE_STRING),
        ('ExpansionString6', RPC_UNICODE_STRING),
        ('ExpansionString7', RPC_UNICODE_STRING),
        ('ExpansionString8', RPC_UNICODE_STRING),
        ('ExpansionString9', RPC_UNICODE_STRING),
        ('ExpansionString10', RPC_UNICODE_STRING),
    )

class PNETLOGON_VALIDATION_SAM_INFO4(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_VALIDATION_SAM_INFO4),
    )

# 2.2.1.4.17 NETLOGON_VALIDATION_INFO_CLASS
class NETLOGON_VALIDATION_INFO_CLASS(NDRENUM):
    class enumItems(Enum):
        NetlogonValidationUasInfo      = 1
        NetlogonValidationSamInfo      = 2
        NetlogonValidationSamInfo2     = 3
        NetlogonValidationGenericInfo  = 4
        NetlogonValidationGenericInfo2 = 5
        NetlogonValidationSamInfo4     = 6

# 2.2.1.4.14 NETLOGON_VALIDATION
class NETLOGON_VALIDATION(NDRUNION):
    union = {
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo     : ('ValidationSam', PNETLOGON_VALIDATION_SAM_INFO),
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo2    : ('ValidationSam2', PNETLOGON_VALIDATION_SAM_INFO2),
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationGenericInfo2: ('ValidationGeneric2', PNETLOGON_VALIDATION_GENERIC_INFO2),
        NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4    : ('ValidationSam4', PNETLOGON_VALIDATION_SAM_INFO4),
    }

# 2.2.1.5.2 NLPR_QUOTA_LIMITS
class NLPR_QUOTA_LIMITS(NDRSTRUCT):
    structure = (
        ('PagedPoolLimit', ULONG),
        ('NonPagedPoolLimit', ULONG),
        ('MinimumWorkingSetSize', ULONG),
        ('MaximumWorkingSetSize', ULONG),
        ('PagefileLimit', ULONG),
        ('Reserved', OLD_LARGE_INTEGER),
    )

# 2.2.1.5.3 NETLOGON_DELTA_ACCOUNTS
class ULONG_ARRAY(NDRUniConformantArray):
    item = ULONG

class PULONG_ARRAY(NDRPOINTER):
    referent = (
        ('Data', ULONG_ARRAY),
    )

class NETLOGON_DELTA_ACCOUNTS(NDRSTRUCT):
    structure = (
        ('PrivilegeEntries', ULONG),
        ('PrivilegeControl', ULONG),
        ('PrivilegeAttributes', PULONG_ARRAY),
        ('PrivilegeNames', PRPC_UNICODE_STRING_ARRAY),
        ('QuotaLimits', NLPR_QUOTA_LIMITS),
        ('SystemAccessFlags', ULONG),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_ACCOUNTS(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_ACCOUNTS),
    )

# 2.2.1.5.5 NLPR_SID_INFORMATION
class NLPR_SID_INFORMATION(NDRSTRUCT):
    structure = (
        ('SidPointer', PRPC_SID),
    )

# 2.2.1.5.6 NLPR_SID_ARRAY
class NLPR_SID_INFORMATION_ARRAY(NDRUniConformantArray):
    item = NLPR_SID_INFORMATION

class PNLPR_SID_INFORMATION_ARRAY(NDRPOINTER):
    referent = (
        ('Data', NLPR_SID_INFORMATION_ARRAY),
    )

class NLPR_SID_ARRAY(NDRSTRUCT):
    referent = (
        ('Count', ULONG),
        ('Sids', PNLPR_SID_INFORMATION_ARRAY),
    )

# 2.2.1.5.7 NETLOGON_DELTA_ALIAS_MEMBER
class NETLOGON_DELTA_ALIAS_MEMBER(NDRSTRUCT):
    structure = (
        ('Members', NLPR_SID_ARRAY),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_ALIAS_MEMBER(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_ALIAS_MEMBER),
    )

# 2.2.1.5.8 NETLOGON_DELTA_DELETE_GROUP
class NETLOGON_DELTA_DELETE_GROUP(NDRSTRUCT):
    structure = (
        ('AccountName', LPWSTR),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_DELETE_GROUP(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_DELETE_GROUP),
    )

# 2.2.1.5.9 NETLOGON_DELTA_DELETE_USER
class NETLOGON_DELTA_DELETE_USER(NDRSTRUCT):
    structure = (
        ('AccountName', LPWSTR),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_DELETE_USER(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_DELETE_USER),
    )

# 2.2.1.5.10 NETLOGON_DELTA_DOMAIN
class NETLOGON_DELTA_DOMAIN(NDRSTRUCT):
    structure = (
        ('DomainName', RPC_UNICODE_STRING),
        ('OemInformation', RPC_UNICODE_STRING),
        ('ForceLogoff', OLD_LARGE_INTEGER),
        ('MinPasswordLength', USHORT),
        ('PasswordHistoryLength', USHORT),
        ('MaxPasswordAge', OLD_LARGE_INTEGER),
        ('MinPasswordAge', OLD_LARGE_INTEGER),
        ('DomainModifiedCount', OLD_LARGE_INTEGER),
        ('DomainCreationTime', OLD_LARGE_INTEGER),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DomainLockoutInformation', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('PasswordProperties', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )
        
class PNETLOGON_DELTA_DOMAIN(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_DOMAIN),
    )

# 2.2.1.5.13 NETLOGON_DELTA_GROUP
class NETLOGON_DELTA_GROUP(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING),
        ('RelativeId', ULONG),
        ('Attributes', ULONG),
        ('AdminComment', RPC_UNICODE_STRING),
        ('SecurityInformation', USHORT),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', SECURITY_INFORMATION),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_GROUP(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_GROUP),
    )

# 2.2.1.5.24 NETLOGON_RENAME_GROUP
class NETLOGON_RENAME_GROUP(NDRSTRUCT):
    structure = (
        ('OldName', RPC_UNICODE_STRING),
        ('NewName', RPC_UNICODE_STRING),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_RENAME_GROUP(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_RENAME_GROUP),
    )

# 2.2.1.5.14 NLPR_LOGON_HOURS
from impacket.dcerpc.v5.samr import SAMPR_LOGON_HOURS
NLPR_LOGON_HOURS = SAMPR_LOGON_HOURS

# 2.2.1.5.15 NLPR_USER_PRIVATE_INFO
class NLPR_USER_PRIVATE_INFO(NDRSTRUCT):
    structure = (
        ('SensitiveData', UCHAR),
        ('DataLength', ULONG),
        ('Data', PUCHAR_ARRAY),
    )

# 2.2.1.5.16 NETLOGON_DELTA_USER
class NETLOGON_DELTA_USER(NDRSTRUCT):
    structure = (
        ('UserName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('ScriptPath', RPC_UNICODE_STRING),
        ('AdminComment', RPC_UNICODE_STRING),
        ('WorkStations', RPC_UNICODE_STRING),
        ('LastLogon', OLD_LARGE_INTEGER),
        ('LastLogoff', OLD_LARGE_INTEGER),
        ('LogonHours', NLPR_LOGON_HOURS),
        ('BadPasswordCount', USHORT),
        ('LogonCount', USHORT),
        ('PasswordLastSet', OLD_LARGE_INTEGER),
        ('AccountExpires', OLD_LARGE_INTEGER),
        ('UserAccountControl', ULONG),
        ('EncryptedNtOwfPassword', PUCHAR_ARRAY),
        ('EncryptedLmOwfPassword', PUCHAR_ARRAY),
        ('NtPasswordPresent', UCHAR),
        ('LmPasswordPresent', UCHAR),
        ('PasswordExpired', UCHAR),
        ('UserComment', RPC_UNICODE_STRING),
        ('Parameters', RPC_UNICODE_STRING),
        ('CountryCode', USHORT),
        ('CodePage', USHORT),
        ('PrivateData', NLPR_USER_PRIVATE_INFO),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_USER(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_USER),
    )

# 2.2.1.5.25 NETLOGON_RENAME_USER
class NETLOGON_RENAME_USER(NDRSTRUCT):
    structure = (
        ('OldName', RPC_UNICODE_STRING),
        ('NewName', RPC_UNICODE_STRING),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_RENAME_USER(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_RENAME_USER),
    )

# 2.2.1.5.17 NETLOGON_DELTA_GROUP_MEMBER
class NETLOGON_DELTA_GROUP_MEMBER(NDRSTRUCT):
    structure = (
        ('Members', PULONG_ARRAY),
        ('Attributes', PULONG_ARRAY),
        ('MemberCount', ULONG),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_GROUP_MEMBER(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_GROUP_MEMBER),
    )

# 2.2.1.5.4 NETLOGON_DELTA_ALIAS
class NETLOGON_DELTA_ALIAS(NDRSTRUCT):
    structure = (
        ('Name', RPC_UNICODE_STRING),
        ('RelativeId', ULONG),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('Comment', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_ALIAS(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_ALIAS),
    )

# 2.2.1.5.23 NETLOGON_RENAME_ALIAS
class NETLOGON_RENAME_ALIAS(NDRSTRUCT):
    structure = (
        ('OldName', RPC_UNICODE_STRING),
        ('NewName', RPC_UNICODE_STRING),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_RENAME_ALIAS(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_RENAME_ALIAS),
    )

# 2.2.1.5.19 NETLOGON_DELTA_POLICY
class NETLOGON_DELTA_POLICY(NDRSTRUCT):
    structure = (
        ('MaximumLogSize', ULONG),
        ('AuditRetentionPeriod', OLD_LARGE_INTEGER),
        ('AuditingMode', UCHAR),
        ('MaximumAuditEventCount', ULONG),
        ('EventAuditingOptions', PULONG_ARRAY),
        ('PrimaryDomainName', RPC_UNICODE_STRING),
        ('PrimaryDomainSid', PRPC_SID),
        ('QuotaLimits', NLPR_QUOTA_LIMITS),
        ('ModifiedId', OLD_LARGE_INTEGER),
        ('DatabaseCreationTime', OLD_LARGE_INTEGER),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_POLICY(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_POLICY),
    )

# 2.2.1.5.22 NETLOGON_DELTA_TRUSTED_DOMAINS
class NETLOGON_DELTA_TRUSTED_DOMAINS(NDRSTRUCT):
    structure = (
        ('DomainName', RPC_UNICODE_STRING),
        ('NumControllerEntries', ULONG),
        ('ControllerNames', PRPC_UNICODE_STRING_ARRAY),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_TRUSTED_DOMAINS(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_TRUSTED_DOMAINS),
    )

# 2.2.1.5.20 NLPR_CR_CIPHER_VALUE
class UCHAR_ARRAY2(NDRUniConformantVaryingArray):
    item = UCHAR

class PUCHAR_ARRAY2(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY2),
    )

class NLPR_CR_CIPHER_VALUE(NDRSTRUCT):
    structure = (
        ('Length', ULONG),
        ('MaximumLength', ULONG),
        ('Buffer', PUCHAR_ARRAY2),
    )

# 2.2.1.5.21 NETLOGON_DELTA_SECRET
class NETLOGON_DELTA_SECRET(NDRSTRUCT):
    structure = (
        ('CurrentValue', NLPR_CR_CIPHER_VALUE),
        ('CurrentValueSetTime', OLD_LARGE_INTEGER),
        ('OldValue', NLPR_CR_CIPHER_VALUE),
        ('OldValueSetTime', OLD_LARGE_INTEGER),
        ('SecurityInformation', SECURITY_INFORMATION),
        ('SecuritySize', ULONG),
        ('SecurityDescriptor', PUCHAR_ARRAY),
        ('DummyString1', RPC_UNICODE_STRING),
        ('DummyString2', RPC_UNICODE_STRING),
        ('DummyString3', RPC_UNICODE_STRING),
        ('DummyString4', RPC_UNICODE_STRING),
        ('DummyLong1', ULONG),
        ('DummyLong2', ULONG),
        ('DummyLong3', ULONG),
        ('DummyLong4', ULONG),
    )

class PNETLOGON_DELTA_SECRET(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_DELTA_SECRET),
    )

# 2.2.1.5.26 NLPR_MODIFIED_COUNT
class NLPR_MODIFIED_COUNT(NDRSTRUCT):
    structure = (
        ('ModifiedCount', OLD_LARGE_INTEGER),
    )

class PNLPR_MODIFIED_COUNT(NDRPOINTER):
    referent = (
        ('Data', NLPR_MODIFIED_COUNT),
    )

# 2.2.1.5.28 NETLOGON_DELTA_TYPE
class NETLOGON_DELTA_TYPE(NDRENUM):
    class enumItems(Enum):
        AddOrChangeDomain     = 1
        AddOrChangeGroup      = 2
        DeleteGroup           = 3
        RenameGroup           = 4
        AddOrChangeUser       = 5
        DeleteUser            = 6
        RenameUser            = 7
        ChangeGroupMembership = 8
        AddOrChangeAlias      = 9
        DeleteAlias           = 10
        RenameAlias           = 11
        ChangeAliasMembership = 12
        AddOrChangeLsaPolicy  = 13
        AddOrChangeLsaTDomain = 14
        DeleteLsaTDomain      = 15
        AddOrChangeLsaAccount = 16
        DeleteLsaAccount      = 17
        AddOrChangeLsaSecret  = 18
        DeleteLsaSecret       = 19
        DeleteGroupByName     = 20
        DeleteUserByName      = 21
        SerialNumberSkip      = 22

# 2.2.1.5.27 NETLOGON_DELTA_UNION
class NETLOGON_DELTA_UNION(NDRUNION):
    union = {
        NETLOGON_DELTA_TYPE.AddOrChangeDomain     : ('DeltaDomain', PNETLOGON_DELTA_DOMAIN),
        NETLOGON_DELTA_TYPE.AddOrChangeGroup      : ('DeltaGroup', PNETLOGON_DELTA_GROUP),
        NETLOGON_DELTA_TYPE.RenameGroup           : ('DeltaRenameGroup', PNETLOGON_DELTA_RENAME_GROUP),
        NETLOGON_DELTA_TYPE.AddOrChangeUser       : ('DeltaUser', PNETLOGON_DELTA_USER),
        NETLOGON_DELTA_TYPE.RenameUser            : ('DeltaRenameUser', PNETLOGON_DELTA_RENAME_USER),
        NETLOGON_DELTA_TYPE.ChangeGroupMembership : ('DeltaGroupMember', PNETLOGON_DELTA_GROUP_MEMBER),
        NETLOGON_DELTA_TYPE.AddOrChangeAlias      : ('DeltaAlias', PNETLOGON_DELTA_ALIAS),
        NETLOGON_DELTA_TYPE.RenameAlias           : ('DeltaRenameAlias', PNETLOGON_DELTA_RENAME_ALIAS),
        NETLOGON_DELTA_TYPE.ChangeAliasMembership : ('DeltaAliasMember', PNETLOGON_DELTA_ALIAS_MEMBER),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaPolicy  : ('DeltaPolicy', PNETLOGON_DELTA_POLICY),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaTDomain : ('DeltaTDomains', PNETLOGON_DELTA_TRUSTED_DOMAINS),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaAccount : ('DeltaAccounts', PNETLOGON_DELTA_ACCOUNTS),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaSecret  : ('DeltaSecret', PNETLOGON_DELTA_SECRET),
        NETLOGON_DELTA_TYPE.DeleteGroupByName     : ('DeltaDeleteGroup', PNETLOGON_DELTA_DELETE_GROUP),
        NETLOGON_DELTA_TYPE.DeleteUserByName      : ('DeltaDeleteUser', PNETLOGON_DELTA_DELETE_USER),
        NETLOGON_DELTA_TYPE.SerialNumberSkip      : ('DeltaSerialNumberSkip', PNLPR_MODIFIED_COUNT),
    }

# 2.2.1.5.18 NETLOGON_DELTA_ID_UNION
class NETLOGON_DELTA_ID_UNION(NDRUNION):
    union = {
        NETLOGON_DELTA_TYPE.AddOrChangeDomain     : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeGroup      : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteGroup           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.RenameGroup           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeUser       : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteUser            : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.RenameUser            : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.ChangeGroupMembership : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeAlias      : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteAlias           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.RenameAlias           : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.ChangeAliasMembership : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteGroupByName     : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.DeleteUserByName      : ('Rid', ULONG),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaPolicy  : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaTDomain : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.DeleteLsaTDomain      : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaAccount : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.DeleteLsaAccount      : ('Sid', PRPC_SID),
        NETLOGON_DELTA_TYPE.AddOrChangeLsaSecret  : ('Name', LPWSTR),
        NETLOGON_DELTA_TYPE.DeleteLsaSecret       : ('Name', LPWSTR),
    }

# 2.2.1.5.11 NETLOGON_DELTA_ENUM
class NETLOGON_DELTA_ENUM(NDRSTRUCT):
    structure = (
        ('DeltaType', NETLOGON_DELTA_TYPE),
        ('DeltaID', NETLOGON_DELTA_ID_UNION),
        ('DeltaUnion', NETLOGON_DELTA_UNION),
    )

# 2.2.1.5.12 NETLOGON_DELTA_ENUM_ARRAY
class NETLOGON_DELTA_ENUM_ARRAY_ARRAY(NDRUniConformantArray):
    item = NETLOGON_DELTA_ENUM

class PNETLOGON_DELTA_ENUM_ARRAY_ARRAY(NDRSTRUCT):
    referent = (
        ('Data', NETLOGON_DELTA_ENUM_ARRAY_ARRAY),
    )

class PNETLOGON_DELTA_ENUM_ARRAY(NDRPOINTER):
    structure = (
        ('CountReturned', DWORD),
        ('Deltas', PNETLOGON_DELTA_ENUM_ARRAY_ARRAY),
    )

# 2.2.1.5.29 SYNC_STATE
class SYNC_STATE(NDRENUM):
    class enumItems(Enum):
        NormalState          = 0
        DomainState          = 1
        GroupState           = 2
        UasBuiltInGroupState = 3
        UserState            = 4
        GroupMemberState     = 5
        AliasState           = 6
        AliasMemberState     = 7
        SamDoneState         = 8

# 2.2.1.6.1 DOMAIN_NAME_BUFFER
class DOMAIN_NAME_BUFFER(NDRSTRUCT):
    structure = (
        ('DomainNameByteCount', ULONG),
        ('DomainNames', PUCHAR_ARRAY),
    )

# 2.2.1.6.2 DS_DOMAIN_TRUSTSW
class DS_DOMAIN_TRUSTSW(NDRSTRUCT):
    structure = (
        ('NetbiosDomainName', LPWSTR),
        ('DnsDomainName', LPWSTR),
        ('Flags', ULONG),
        ('ParentIndex', ULONG),
        ('TrustType', ULONG),
        ('TrustAttributes', ULONG),
        ('DomainSid', PRPC_SID),
        ('DomainGuid', GUID),
    )

# 2.2.1.6.3 NETLOGON_TRUSTED_DOMAIN_ARRAY
class DS_DOMAIN_TRUSTSW_ARRAY(NDRUniConformantArray):
    item = DS_DOMAIN_TRUSTSW

class PDS_DOMAIN_TRUSTSW_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DS_DOMAIN_TRUSTSW_ARRAY),
    )

class NETLOGON_TRUSTED_DOMAIN_ARRAY(NDRSTRUCT):
    structure = (
        ('DomainCount', DWORD),
        ('Domains', PDS_DOMAIN_TRUSTSW_ARRAY),
    )

# 2.2.1.6.4 NL_GENERIC_RPC_DATA
class NL_GENERIC_RPC_DATA(NDRSTRUCT):
    structure = (
        ('UlongEntryCount', ULONG),
        ('UlongData', PULONG_ARRAY),
        ('UnicodeStringEntryCount', ULONG),
        ('UnicodeStringData', PRPC_UNICODE_STRING_ARRAY),
    )

class PNL_GENERIC_RPC_DATA(NDRPOINTER):
    referent = (
        ('Data', NL_GENERIC_RPC_DATA),
    )

# 2.2.1.7.1 NETLOGON_CONTROL_DATA_INFORMATION
class NETLOGON_CONTROL_DATA_INFORMATION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        5 : ('TrustedDomainName', LPWSTR),
        6 : ('TrustedDomainName', LPWSTR),
        9 : ('TrustedDomainName', LPWSTR),
        10 : ('TrustedDomainName', LPWSTR),
        65534 : ('DebugFlag', DWORD),
        8: ('UserName', LPWSTR),
    }

# 2.2.1.7.2 NETLOGON_INFO_1
class NETLOGON_INFO_1(NDRSTRUCT):
    structure = (
        ('netlog1_flags', DWORD),
        ('netlog1_pdc_connection_status', NET_API_STATUS),
    )

class PNETLOGON_INFO_1(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_INFO_1),
    )

# 2.2.1.7.3 NETLOGON_INFO_2
class NETLOGON_INFO_2(NDRSTRUCT):
    structure = (
        ('netlog2_flags', DWORD),
        ('netlog2_pdc_connection_status', NET_API_STATUS),
        ('netlog2_trusted_dc_name', LPWSTR),
        ('netlog2_tc_connection_status', NET_API_STATUS),
    )

class PNETLOGON_INFO_2(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_INFO_2),
    )

# 2.2.1.7.4 NETLOGON_INFO_3
class NETLOGON_INFO_3(NDRSTRUCT):
    structure = (
        ('netlog3_flags', DWORD),
        ('netlog3_logon_attempts', DWORD),
        ('netlog3_reserved1', DWORD),
        ('netlog3_reserved2', DWORD),
        ('netlog3_reserved3', DWORD),
        ('netlog3_reserved4', DWORD),
        ('netlog3_reserved5', DWORD),
    )

class PNETLOGON_INFO_3(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_INFO_3),
    )

# 2.2.1.7.5 NETLOGON_INFO_4
class NETLOGON_INFO_4(NDRSTRUCT):
    structure = (
        ('netlog4_trusted_dc_name', LPWSTR),
        ('netlog4_trusted_domain_name', LPWSTR),
    )

class PNETLOGON_INFO_4(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_INFO_4),
    )

# 2.2.1.7.6 NETLOGON_CONTROL_QUERY_INFORMATION
class NETLOGON_CONTROL_QUERY_INFORMATION(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('NetlogonInfo1', PNETLOGON_INFO_1),
        2 : ('NetlogonInfo2', PNETLOGON_INFO_2),
        3 : ('NetlogonInfo3', PNETLOGON_INFO_3),
        4 : ('NetlogonInfo4', PNETLOGON_INFO_4),
    }

# 2.2.1.8.1 NETLOGON_VALIDATION_UAS_INFO
class NETLOGON_VALIDATION_UAS_INFO(NDRSTRUCT):
    structure = (
        ('usrlog1_eff_name', DWORD),
        ('usrlog1_priv', DWORD),
        ('usrlog1_auth_flags', DWORD),
        ('usrlog1_num_logons', DWORD),
        ('usrlog1_bad_pw_count', DWORD),
        ('usrlog1_last_logon', DWORD),
        ('usrlog1_last_logoff', DWORD),
        ('usrlog1_logoff_time', DWORD),
        ('usrlog1_kickoff_time', DWORD),
        ('usrlog1_password_age', DWORD),
        ('usrlog1_pw_can_change', DWORD),
        ('usrlog1_pw_must_change', DWORD),
        ('usrlog1_computer', LPWSTR),
        ('usrlog1_domain', LPWSTR),
        ('usrlog1_script_path', LPWSTR),
        ('usrlog1_reserved1', DWORD),
    )

class PNETLOGON_VALIDATION_UAS_INFO(NDRPOINTER):
    referent = (
        ('Data', NETLOGON_VALIDATION_UAS_INFO),
    )

# 2.2.1.8.2 NETLOGON_LOGOFF_UAS_INFO
class NETLOGON_LOGOFF_UAS_INFO(NDRSTRUCT):
    structure = (
        ('Duration', DWORD),
        ('LogonCount', USHORT),
    )

# 2.2.1.8.3 UAS_INFO_0
class UAS_INFO_0(NDRSTRUCT):
    structure = (
        ('ComputerName', '16s=""'),
        ('TimeCreated', ULONG),
        ('SerialNumber', ULONG),
    )
    def getAlignment(self):
        return 4

# 2.2.1.8.4 NETLOGON_DUMMY1
class NETLOGON_DUMMY1(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        1 : ('Dummy', ULONG),
    }

# 3.5.4.8.2 NetrLogonComputeServerDigest (Opnum 24)
class CHAR_FIXED_16_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return 16


################################################################################
# SSPI
################################################################################
# Constants
NL_AUTH_MESSAGE_NETBIOS_DOMAIN        = 0x1
NL_AUTH_MESSAGE_NETBIOS_HOST          = 0x2
NL_AUTH_MESSAGE_DNS_DOMAIN            = 0x4
NL_AUTH_MESSAGE_DNS_HOST              = 0x8
NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8     = 0x10

NL_AUTH_MESSAGE_REQUEST               = 0x0
NL_AUTH_MESSAGE_RESPONSE              = 0x1

NL_SIGNATURE_HMAC_MD5    = 0x77
NL_SIGNATURE_HMAC_SHA256 = 0x13
NL_SEAL_NOT_ENCRYPTED    = 0xffff
NL_SEAL_RC4              = 0x7A
NL_SEAL_AES128           = 0x1A

# Structures
class NL_AUTH_MESSAGE(Structure):
    structure = (
        ('MessageType','<L=0'),
        ('Flags','<L=0'),
        ('Buffer',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Buffer'] = '\x00'*4

class NL_AUTH_SIGNATURE(Structure):
    structure = (
        ('SignatureAlgorithm','<H=0'),
        ('SealAlgorithm','<H=0'),
        ('Pad','<H=0xffff'),
        ('Flags','<H=0'),
        ('SequenceNumber','8s=""'),
        ('Checksum','8s=""'),
        ('_Confounder','_-Confounder','8'),
        ('Confounder',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Confounder'] = ''

class NL_AUTH_SHA2_SIGNATURE(Structure):
    structure = (
        ('SignatureAlgorithm','<H=0'),
        ('SealAlgorithm','<H=0'),
        ('Pad','<H=0xffff'),
        ('Flags','<H=0'),
        ('SequenceNumber','8s=""'),
        ('Checksum','32s=""'),
        ('_Confounder','_-Confounder','8'),
        ('Confounder',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Confounder'] = ''

# Section 3.1.4.4.2
def ComputeNetlogonCredential(inputData, Sk):
    k1 = Sk[:7]
    k3 = crypto.transformKey(k1)
    k2 = Sk[7:14]
    k4 = crypto.transformKey(k2)
    Crypt1 = DES.new(k3, DES.MODE_ECB)
    Crypt2 = DES.new(k4, DES.MODE_ECB)
    cipherText = Crypt1.encrypt(inputData)
    return Crypt2.encrypt(cipherText)

# Section 3.1.4.4.1
def ComputeNetlogonCredentialAES(inputData, Sk):
    IV='\x00'*16
    Crypt1 = AES.new(Sk, AES.MODE_CFB, IV)
    return Crypt1.encrypt(inputData)

# Section 3.1.4.3.1
def ComputeSessionKeyAES(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = None):
    # added the ability to receive hashes already
    if sharedSecretHash is None:
        M4SS = ntlm.NTOWFv1(sharedSecret)
    else:
        M4SS = sharedSecretHash

    hm = hmac.new(key=M4SS, digestmod=hashlib.sha256)
    hm.update(clientChallenge)
    hm.update(serverChallenge)
    sessionKey = hm.digest()

    return sessionKey[:16]

# 3.1.4.3.2 Strong-key Session-Key
def ComputeSessionKeyStrongKey(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = None):
    # added the ability to receive hashes already

    if sharedSecretHash is None:
        M4SS = ntlm.NTOWFv1(sharedSecret)
    else:
        M4SS = sharedSecretHash

    md5 = hashlib.new('md5')
    md5.update('\x00'*4)
    md5.update(clientChallenge)
    md5.update(serverChallenge)
    finalMD5 = md5.digest()
    hm = hmac.new(M4SS) 
    hm.update(finalMD5)
    return hm.digest()

def deriveSequenceNumber(sequenceNum):
    sequenceLow = sequenceNum & 0xffffffff
    sequenceHigh = (sequenceNum >> 32) & 0xffffffff
    sequenceHigh |= 0x80000000

    res = pack('>L', sequenceLow)
    res += pack('>L', sequenceHigh)
    return res

def ComputeNetlogonSignatureAES(authSignature, message, confounder, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 7
    hm = hmac.new(key=sessionKey, digestmod=hashlib.sha256)
    hm.update(str(authSignature)[:8])
    # If no confidentiality requested, it should be ''
    hm.update(confounder)
    hm.update(str(message))
    return hm.digest()[:8]+'\x00'*24

def ComputeNetlogonSignatureMD5(authSignature, message, confounder, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 7
    md5 = hashlib.new('md5')
    md5.update('\x00'*4)
    md5.update(str(authSignature)[:8])
    # If no confidentiality requested, it should be ''
    md5.update(confounder)
    md5.update(str(message))
    finalMD5 = md5.digest()
    hm = hmac.new(sessionKey)
    hm.update(finalMD5)
    return hm.digest()[:8]

def encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9

    hm = hmac.new(sessionKey)
    hm.update('\x00'*4)
    hm2 = hmac.new(hm.digest())
    hm2.update(checkSum)
    encryptionKey = hm2.digest()

    cipher = ARC4.new(encryptionKey)
    return cipher.encrypt(sequenceNum)

def decryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.2, point 5

    return encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey)

def encryptSequenceNumberAES(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.encrypt(sequenceNum)

def decryptSequenceNumberAES(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.decrypt(sequenceNum)

def SIGN(data, confounder, sequenceNum, key, aes = False):
    if aes is False:
        signature = NL_AUTH_SIGNATURE()
        signature['SignatureAlgorithm'] = NL_SIGNATURE_HMAC_MD5
        if confounder == '':
            signature['SealAlgorithm'] = NL_SEAL_NOT_ENCRYPTED
        else:
            signature['SealAlgorithm'] = NL_SEAL_RC4
        signature['Checksum'] = ComputeNetlogonSignatureMD5(signature, data, confounder, key)
        signature['SequenceNumber'] = encryptSequenceNumberRC4(deriveSequenceNumber(sequenceNum), signature['Checksum'], key)
        return signature
    else:
        signature = NL_AUTH_SIGNATURE()
        signature['SignatureAlgorithm'] = NL_SIGNATURE_HMAC_SHA256
        if confounder == '':
            signature['SealAlgorithm'] = NL_SEAL_NOT_ENCRYPTED
        else:
            signature['SealAlgorithm'] = NL_SEAL_AES128
        signature['Checksum'] = ComputeNetlogonSignatureAES(signature, data, confounder, key)
        signature['SequenceNumber'] = encryptSequenceNumberAES(deriveSequenceNumber(sequenceNum), signature['Checksum'], key)
        return signature

def SEAL(data, confounder, sequenceNum, key, aes = False):
    signature = SIGN(data, confounder, sequenceNum, key, aes)
    sequenceNum = deriveSequenceNumber(sequenceNum)
    XorKey = []
    for i in key:
       XorKey.append(chr(ord(i) ^ 0xf0))

    XorKey = ''.join(XorKey)
    if aes is False:
        hm = hmac.new(XorKey)
        hm.update('\x00'*4)
        hm2 = hmac.new(hm.digest())
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(confounder)
        cipher = ARC4.new(encryptionKey)
        encrypted = cipher.encrypt(data)

        signature['Confounder'] = cfounder

        return encrypted, signature
    else:
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.encrypt(confounder)
        encrypted = cipher.encrypt(data)

        signature['Confounder'] = cfounder

        return encrypted, signature
        
def UNSEAL(data, auth_data, key, aes = False):
    auth_data = NL_AUTH_SIGNATURE(auth_data)
    XorKey = []
    for i in key:
       XorKey.append(chr(ord(i) ^ 0xf0))

    XorKey = ''.join(XorKey)
    if aes is False:
        sequenceNum = decryptSequenceNumberRC4(auth_data['SequenceNumber'], auth_data['Checksum'],  key)
        hm = hmac.new(XorKey)
        hm.update('\x00'*4)
        hm2 = hmac.new(hm.digest())
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(auth_data['Confounder'])
        cipher = ARC4.new(encryptionKey)
        plain = cipher.encrypt(data)

        return plain, cfounder
    else:
        sequenceNum = decryptSequenceNumberAES(auth_data['SequenceNumber'], auth_data['Checksum'],  key)
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.decrypt(auth_data['Confounder'])
        plain = cipher.decrypt(data)
        return plain, cfounder
        
    
def getSSPType1(workstation='', domain='', signingRequired=False):
    auth = NL_AUTH_MESSAGE()
    auth['Flags'] = 0
    auth['Buffer'] = ''
    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_DOMAIN 
    if domain != '':
        auth['Buffer'] = auth['Buffer'] + domain + '\x00'
    else:
        auth['Buffer'] += 'WORKGROUP\x00'

    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_HOST 
    if workstation != '':
        auth['Buffer'] = auth['Buffer'] + workstation + '\x00'
    else:
        auth['Buffer'] += 'MYHOST\x00'

    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8 
    if workstation != '':
        auth['Buffer'] += pack('<B',len(workstation)) + workstation + '\x00'
    else:
        auth['Buffer'] += '\x06MYHOST\x00'

    return auth

################################################################################
# RPC CALLS
################################################################################
# 3.5.4.3.1 DsrGetDcNameEx2 (Opnum 34)
class DsrGetDcNameEx2(NDRCALL):
    opnum = 34
    structure = (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('AccountName', LPWSTR),
       ('AllowableAccountControlBits', ULONG),
       ('DomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('SiteName',LPWSTR),
       ('Flags',ULONG),
    )

class DsrGetDcNameEx2Response(NDRCALL):
    structure = (
       ('DomainControllerInfo',PDOMAIN_CONTROLLER_INFOW),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.2 DsrGetDcNameEx (Opnum 27)
class DsrGetDcNameEx(NDRCALL):
    opnum = 27
    structure = (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('SiteName',LPWSTR),
       ('Flags',ULONG),
    )

class DsrGetDcNameExResponse(NDRCALL):
    structure = (
       ('DomainControllerInfo',PDOMAIN_CONTROLLER_INFOW),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.3 DsrGetDcName (Opnum 20)
class DsrGetDcName(NDRCALL):
    opnum = 20
    structure = (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('SiteGuid',PGUID),
       ('Flags',ULONG),
    )

class DsrGetDcNameResponse(NDRCALL):
    structure = (
       ('DomainControllerInfo',PDOMAIN_CONTROLLER_INFOW),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.4 NetrGetDCName (Opnum 11)
class NetrGetDCName(NDRCALL):
    opnum = 11
    structure = (
       ('ServerName',LOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
    )

class NetrGetDCNameResponse(NDRCALL):
    structure = (
       ('Buffer',LPWSTR),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.5 NetrGetAnyDCName (Opnum 13)
class NetrGetAnyDCName(NDRCALL):
    opnum = 13
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
    )

class NetrGetAnyDCNameResponse(NDRCALL):
    structure = (
       ('Buffer',LPWSTR),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.6 DsrGetSiteName (Opnum 28)
class DsrGetSiteName(NDRCALL):
    opnum = 28
    structure = (
       ('ComputerName',PLOGONSRV_HANDLE),
    )

class DsrGetSiteNameResponse(NDRCALL):
    structure = (
       ('SiteName',LPWSTR),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.7 DsrGetDcSiteCoverageW (Opnum 38)
class DsrGetDcSiteCoverageW(NDRCALL):
    opnum = 38
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
    )

class DsrGetDcSiteCoverageWResponse(NDRCALL):
    structure = (
       ('SiteNames',PNL_SITE_NAME_ARRAY),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.8 DsrAddressToSiteNamesW (Opnum 33)
class DsrAddressToSiteNamesW(NDRCALL):
    opnum = 33
    structure = (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('EntryCount',ULONG),
       ('SocketAddresses',NL_SOCKET_ADDRESS_ARRAY),
    )

class DsrAddressToSiteNamesWResponse(NDRCALL):
    structure = (
       ('SiteNames',PNL_SITE_NAME_ARRAY),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.9 DsrAddressToSiteNamesExW (Opnum 37)
class DsrAddressToSiteNamesExW(NDRCALL):
    opnum = 37
    structure = (
       ('ComputerName',PLOGONSRV_HANDLE),
       ('EntryCount',ULONG),
       ('SocketAddresses',NL_SOCKET_ADDRESS_ARRAY),
    )

class DsrAddressToSiteNamesExWResponse(NDRCALL):
    structure = (
       ('SiteNames',PNL_SITE_NAME_EX_ARRAY),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.10 DsrDeregisterDnsHostRecords (Opnum 41)
class DsrDeregisterDnsHostRecords(NDRCALL):
    opnum = 41
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DnsDomainName',LPWSTR),
       ('DomainGuid',PGUID),
       ('DsaGuid',PGUID),
       ('DnsHostName',WSTR),
    )

class DsrDeregisterDnsHostRecordsResponse(NDRCALL):
    structure = (
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.3.11 DSRUpdateReadOnlyServerDnsRecords (Opnum 48)
class DSRUpdateReadOnlyServerDnsRecords(NDRCALL):
    opnum = 48
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('SiteName',LPWSTR),
       ('DnsTtl',ULONG),
       ('DnsNames',NL_DNS_NAME_INFO_ARRAY),
    )

class DSRUpdateReadOnlyServerDnsRecordsResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DnsNames',NL_DNS_NAME_INFO_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.1 NetrServerReqChallenge (Opnum 4)
class NetrServerReqChallenge(NDRCALL):
    opnum = 4
    structure = (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('ClientChallenge',NETLOGON_CREDENTIAL),
    )

class NetrServerReqChallengeResponse(NDRCALL):
    structure = (
       ('ServerChallenge',NETLOGON_CREDENTIAL),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.2 NetrServerAuthenticate3 (Opnum 26)
class NetrServerAuthenticate3(NDRCALL):
    opnum = 26
    structure = (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('ClientCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
    )

class NetrServerAuthenticate3Response(NDRCALL):
    structure = (
       ('ServerCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
       ('AccountRid',ULONG),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.3 NetrServerAuthenticate2 (Opnum 15)
class NetrServerAuthenticate2(NDRCALL):
    opnum = 15
    structure = (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('ClientCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
    )

class NetrServerAuthenticate2Response(NDRCALL):
    structure = (
       ('ServerCredential',NETLOGON_CREDENTIAL),
       ('NegotiateFlags',ULONG),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.4 NetrServerAuthenticate (Opnum 5)
class NetrServerAuthenticate(NDRCALL):
    opnum = 5
    structure = (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('ClientCredential',NETLOGON_CREDENTIAL),
    )

class NetrServerAuthenticateResponse(NDRCALL):
    structure = (
       ('ServerCredential',NETLOGON_CREDENTIAL),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.5 NetrServerPasswordSet2 (Opnum 30)

# 3.5.4.4.6 NetrServerPasswordSet (Opnum 6)

# 3.5.4.4.7 NetrServerPasswordGet (Opnum 31)
class NetrServerPasswordGet(NDRCALL):
    opnum = 31
    structure = (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('AccountType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
    )

class NetrServerPasswordGetResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('EncryptedNtOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.8 NetrServerTrustPasswordsGet (Opnum 42)
class NetrServerTrustPasswordsGet(NDRCALL):
    opnum = 42
    structure = (
       ('TrustedDcName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
    )

class NetrServerTrustPasswordsGetResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('EncryptedNewOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('EncryptedOldOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.9 NetrLogonGetDomainInfo (Opnum 29)
class NetrLogonGetDomainInfo(NDRCALL):
    opnum = 29
    structure = (
       ('ServerName',LOGONSRV_HANDLE),
       ('ComputerName',LPWSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('Level',DWORD),
       ('WkstaBuffer',NETLOGON_WORKSTATION_INFORMATION),
    )

class NetrLogonGetDomainInfoResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DomBuffer',NETLOGON_DOMAIN_INFORMATION),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.10 NetrLogonGetCapabilities (Opnum 21)
class NetrLogonGetCapabilities(NDRCALL):
    opnum = 21
    structure = (
       ('ServerName',LOGONSRV_HANDLE),
       ('ComputerName',LPWSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('QueryLevel',DWORD),
    )

class NetrLogonGetCapabilitiesResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ServerCapabilities',NETLOGON_CAPABILITIES),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.4.11 NetrChainSetClientAttributes (Opnum 49)

# 3.5.4.5.1 NetrLogonSamLogonEx (Opnum 39)
class NetrLogonSamLogonEx(NDRCALL):
    opnum = 39
    structure = (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
       ('ValidationLevel',NETLOGON_VALIDATION_INFO_CLASS),
       ('ExtraFlags',ULONG),
    )

class NetrLogonSamLogonExResponse(NDRCALL):
    structure = (
       ('ValidationInformation',NETLOGON_VALIDATION),
       ('Authoritative',UCHAR),
       ('ExtraFlags',ULONG),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.5.2 NetrLogonSamLogonWithFlags (Opnum 45)
class NetrLogonSamLogonWithFlags(NDRCALL):
    opnum = 45
    structure = (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('Authenticator',PNETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
       ('ValidationLevel',NETLOGON_VALIDATION_INFO_CLASS),
       ('ExtraFlags',ULONG),
    )

class NetrLogonSamLogonWithFlagsResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('ValidationInformation',NETLOGON_VALIDATION),
       ('Authoritative',UCHAR),
       ('ExtraFlags',ULONG),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.5.3 NetrLogonSamLogon (Opnum 2)
class NetrLogonSamLogon(NDRCALL):
    opnum = 2
    structure = (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('Authenticator',PNETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
       ('ValidationLevel',NETLOGON_VALIDATION_INFO_CLASS),
    )

class NetrLogonSamLogonResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('ValidationInformation',NETLOGON_VALIDATION),
       ('Authoritative',UCHAR),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.5.4 NetrLogonSamLogoff (Opnum 3)
class NetrLogonSamLogoff(NDRCALL):
    opnum = 3
    structure = (
       ('LogonServer',LPWSTR),
       ('ComputerName',LPWSTR),
       ('Authenticator',PNETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('LogonLevel',NETLOGON_LOGON_INFO_CLASS),
       ('LogonInformation',NETLOGON_LEVEL),
    )

class NetrLogonSamLogoffResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',PNETLOGON_AUTHENTICATOR),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.6.1 NetrDatabaseDeltas (Opnum 7)
class NetrDatabaseDeltas(NDRCALL):
    opnum = 7
    structure = (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DatabaseID',DWORD),
       ('DomainModifiedCount',NLPR_MODIFIED_COUNT),
       ('PreferredMaximumLength',DWORD),
    )

class NetrDatabaseDeltasResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DomainModifiedCount',NLPR_MODIFIED_COUNT),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.6.2 NetrDatabaseSync2 (Opnum 16)
class NetrDatabaseSync2(NDRCALL):
    opnum = 16
    structure = (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DatabaseID',DWORD),
       ('RestartState',SYNC_STATE),
       ('SyncContext',ULONG),
       ('PreferredMaximumLength',DWORD),
    )

class NetrDatabaseSync2Response(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('SyncContext',ULONG),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.6.3 NetrDatabaseSync (Opnum 8)
class NetrDatabaseSync(NDRCALL):
    opnum = 8
    structure = (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DatabaseID',DWORD),
       ('SyncContext',ULONG),
       ('PreferredMaximumLength',DWORD),
    )

class NetrDatabaseSyncResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('SyncContext',ULONG),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.6.4 NetrDatabaseRedo (Opnum 17)
class NetrDatabaseRedo(NDRCALL):
    opnum = 17
    structure = (
       ('PrimaryName',LOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ChangeLogEntry',PUCHAR_ARRAY),
       ('ChangeLogEntrySize',DWORD),
    )

class NetrDatabaseRedoResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('DeltaArray',PNETLOGON_DELTA_ENUM_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.7.1 DsrEnumerateDomainTrusts (Opnum 40)
class DsrEnumerateDomainTrusts(NDRCALL):
    opnum = 40
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('Flags',ULONG),
    )

class DsrEnumerateDomainTrustsResponse(NDRCALL):
    structure = (
       ('Domains',NETLOGON_TRUSTED_DOMAIN_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.7.2 NetrEnumerateTrustedDomainsEx (Opnum 36)
class NetrEnumerateTrustedDomainsEx(NDRCALL):
    opnum = 36
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
    )

class NetrEnumerateTrustedDomainsExResponse(NDRCALL):
    structure = (
       ('Domains',NETLOGON_TRUSTED_DOMAIN_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.7.3 NetrEnumerateTrustedDomains (Opnum 19)
class NetrEnumerateTrustedDomains(NDRCALL):
    opnum = 19
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
    )

class NetrEnumerateTrustedDomainsResponse(NDRCALL):
    structure = (
       ('DomainNameBuffer',DOMAIN_NAME_BUFFER),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.7.4 NetrGetForestTrustInformation (Opnum 44)
class NetrGetForestTrustInformation(NDRCALL):
    opnum = 44
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('Flags',DWORD),
    )

class NetrGetForestTrustInformationResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ForestTrustInfo',PLSA_FOREST_TRUST_INFORMATION),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.7.5 DsrGetForestTrustInformation (Opnum 43)
class DsrGetForestTrustInformation(NDRCALL):
    opnum = 43
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('TrustedDomainName',LPWSTR),
       ('Flags',DWORD),
    )

class DsrGetForestTrustInformationResponse(NDRCALL):
    structure = (
       ('ForestTrustInfo',PLSA_FOREST_TRUST_INFORMATION),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.7.6 NetrServerGetTrustInfo (Opnum 46)
class NetrServerGetTrustInfo(NDRCALL):
    opnum = 46
    structure = (
       ('TrustedDcName',PLOGONSRV_HANDLE),
       ('AccountName',WSTR),
       ('SecureChannelType',NETLOGON_SECURE_CHANNEL_TYPE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
    )

class NetrServerGetTrustInfoResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('EncryptedNewOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('EncryptedOldOwfPassword',ENCRYPTED_NT_OWF_PASSWORD),
       ('TrustInfo',PNL_GENERIC_RPC_DATA),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.8.1 NetrLogonGetTrustRid (Opnum 23)
class NetrLogonGetTrustRid(NDRCALL):
    opnum = 23
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
    )

class NetrLogonGetTrustRidResponse(NDRCALL):
    structure = (
       ('Rid',ULONG),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.8.2 NetrLogonComputeServerDigest (Opnum 24)
class NetrLogonComputeServerDigest(NDRCALL):
    opnum = 24
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('Rid',ULONG),
       ('Message',UCHAR_ARRAY),
       ('MessageSize',ULONG),
    )

class NetrLogonComputeServerDigestResponse(NDRCALL):
    structure = (
       ('NewMessageDigest',CHAR_FIXED_16_ARRAY),
       ('OldMessageDigest',CHAR_FIXED_16_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.8.3 NetrLogonComputeClientDigest (Opnum 25)
class NetrLogonComputeClientDigest(NDRCALL):
    opnum = 25
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('DomainName',LPWSTR),
       ('Message',UCHAR_ARRAY),
       ('MessageSize',ULONG),
    )

class NetrLogonComputeClientDigestResponse(NDRCALL):
    structure = (
       ('NewMessageDigest',CHAR_FIXED_16_ARRAY),
       ('OldMessageDigest',CHAR_FIXED_16_ARRAY),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.8.4 NetrLogonSendToSam (Opnum 32)
class NetrLogonSendToSam(NDRCALL):
    opnum = 32
    structure = (
       ('PrimaryName',PLOGONSRV_HANDLE),
       ('ComputerName',WSTR),
       ('Authenticator',NETLOGON_AUTHENTICATOR),
       ('OpaqueBuffer',UCHAR_ARRAY),
       ('OpaqueBufferSize',ULONG),
    )

class NetrLogonSendToSamResponse(NDRCALL):
    structure = (
       ('ReturnAuthenticator',NETLOGON_AUTHENTICATOR),
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.8.5 NetrLogonSetServiceBits (Opnum 22)
class NetrLogonSetServiceBits(NDRCALL):
    opnum = 22
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('ServiceBitsOfInterest',DWORD),
       ('ServiceBits',DWORD),
    )

class NetrLogonSetServiceBitsResponse(NDRCALL):
    structure = (
       ('ErrorCode',NTSTATUS),
    )

# 3.5.4.8.6 NetrLogonGetTimeServiceParentDomain (Opnum 35)
class NetrLogonGetTimeServiceParentDomain(NDRCALL):
    opnum = 35
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
    )

class NetrLogonGetTimeServiceParentDomainResponse(NDRCALL):
    structure = (
       ('DomainName',LPWSTR),
       ('PdcSameSite',LONG),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.9.1 NetrLogonControl2Ex (Opnum 18)
class NetrLogonControl2Ex(NDRCALL):
    opnum = 18
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('FunctionCode',DWORD),
       ('QueryLevel',DWORD),
       ('Data',NETLOGON_CONTROL_DATA_INFORMATION),
    )

class NetrLogonControl2ExResponse(NDRCALL):
    structure = (
       ('Buffer',NETLOGON_CONTROL_DATA_INFORMATION),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.9.2 NetrLogonControl2 (Opnum 14)
class NetrLogonControl2(NDRCALL):
    opnum = 14
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('FunctionCode',DWORD),
       ('QueryLevel',DWORD),
       ('Data',NETLOGON_CONTROL_DATA_INFORMATION),
    )

class NetrLogonControl2Response(NDRCALL):
    structure = (
       ('Buffer',NETLOGON_CONTROL_DATA_INFORMATION),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.9.3 NetrLogonControl (Opnum 12)
class NetrLogonControl(NDRCALL):
    opnum = 12
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('FunctionCode',DWORD),
       ('QueryLevel',DWORD),
       ('Data',NETLOGON_CONTROL_DATA_INFORMATION),
    )

class NetrLogonControlResponse(NDRCALL):
    structure = (
       ('Buffer',NETLOGON_CONTROL_DATA_INFORMATION),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.10.1 NetrLogonUasLogon (Opnum 0)
class NetrLogonUasLogon(NDRCALL):
    opnum = 0
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('UserName',WSTR),
       ('Workstation',WSTR),
    )

class NetrLogonUasLogonResponse(NDRCALL):
    structure = (
       ('ValidationInformation',PNETLOGON_VALIDATION_UAS_INFO),
       ('ErrorCode',NET_API_STATUS),
    )

# 3.5.4.10.2 NetrLogonUasLogoff (Opnum 1)
class NetrLogonUasLogoff(NDRCALL):
    opnum = 1
    structure = (
       ('ServerName',PLOGONSRV_HANDLE),
       ('UserName',WSTR),
       ('Workstation',WSTR),
    )

class NetrLogonUasLogoffResponse(NDRCALL):
    structure = (
       ('LogoffInformation',NETLOGON_LOGOFF_UAS_INFO),
       ('ErrorCode',NET_API_STATUS),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (NetrLogonUasLogon, NetrLogonUasLogonResponse),
 1 : (NetrLogonUasLogoff, NetrLogonUasLogoffResponse),
 2 : (NetrLogonSamLogon, NetrLogonSamLogonResponse),
 3 : (NetrLogonSamLogoff, NetrLogonSamLogoffResponse),
 4 : (NetrServerReqChallenge, NetrServerReqChallengeResponse),
 5 : (NetrServerAuthenticate, NetrServerAuthenticateResponse),
# 6 : (NetrServerPasswordSet, NetrServerPasswordSetResponse),
 7 : (NetrDatabaseDeltas, NetrDatabaseDeltasResponse),
 8 : (NetrDatabaseSync, NetrDatabaseSyncResponse),
# 9 : (NetrAccountDeltas, NetrAccountDeltasResponse),
# 10 : (NetrAccountSync, NetrAccountSyncResponse),
 11 : (NetrGetDCName, NetrGetDCNameResponse),
 12 : (NetrLogonControl, NetrLogonControlResponse),
 13 : (NetrGetAnyDCName, NetrGetAnyDCNameResponse),
 14 : (NetrLogonControl2, NetrLogonControl2Response),
 15 : (NetrServerAuthenticate2, NetrServerAuthenticate2Response),
 16 : (NetrDatabaseSync2, NetrDatabaseSync2Response),
 17 : (NetrDatabaseRedo, NetrDatabaseRedoResponse),
 18 : (NetrLogonControl2Ex, NetrLogonControl2ExResponse),
 19 : (NetrEnumerateTrustedDomains, NetrEnumerateTrustedDomainsResponse),
 20 : (DsrGetDcName, DsrGetDcNameResponse),
 21 : (NetrLogonGetCapabilities, NetrLogonGetCapabilitiesResponse),
 22 : (NetrLogonSetServiceBits, NetrLogonSetServiceBitsResponse),
 23 : (NetrLogonGetTrustRid, NetrLogonGetTrustRidResponse),
 24 : (NetrLogonComputeServerDigest, NetrLogonComputeServerDigestResponse),
 25 : (NetrLogonComputeClientDigest, NetrLogonComputeClientDigestResponse),
 26 : (NetrServerAuthenticate3, NetrServerAuthenticate3Response),
 27 : (DsrGetDcNameEx, DsrGetDcNameExResponse),
 28 : (DsrGetSiteName, DsrGetSiteNameResponse),
 29 : (NetrLogonGetDomainInfo, NetrLogonGetDomainInfoResponse),
# 30 : (NetrServerPasswordSet2, NetrServerPasswordSet2Response),
 31 : (NetrServerPasswordGet, NetrServerPasswordGetResponse),
 32 : (NetrLogonSendToSam, NetrLogonSendToSamResponse),
 33 : (DsrAddressToSiteNamesW, DsrAddressToSiteNamesWResponse),
 34 : (DsrGetDcNameEx2, DsrGetDcNameEx2Response),
 35 : (NetrLogonGetTimeServiceParentDomain, NetrLogonGetTimeServiceParentDomainResponse),
 36 : (NetrEnumerateTrustedDomainsEx, NetrEnumerateTrustedDomainsExResponse),
 37 : (DsrAddressToSiteNamesExW, DsrAddressToSiteNamesExWResponse),
 38 : (DsrGetDcSiteCoverageW, DsrGetDcSiteCoverageWResponse),
 39 : (NetrLogonSamLogonEx, NetrLogonSamLogonExResponse),
 40 : (DsrEnumerateDomainTrusts, DsrEnumerateDomainTrustsResponse),
 41 : (DsrDeregisterDnsHostRecords, DsrDeregisterDnsHostRecordsResponse),
 42 : (NetrServerTrustPasswordsGet, NetrServerTrustPasswordsGetResponse),
 43 : (DsrGetForestTrustInformation, DsrGetForestTrustInformationResponse),
 44 : (NetrGetForestTrustInformation, NetrGetForestTrustInformationResponse),
 45 : (NetrLogonSamLogonWithFlags, NetrLogonSamLogonWithFlagsResponse),
 46 : (NetrServerGetTrustInfo, NetrServerGetTrustInfoResponse),
# 48 : (DsrUpdateReadOnlyServerDnsRecords, DsrUpdateReadOnlyServerDnsRecordsResponse),
# 49 : (NetrChainSetClientAttributes, NetrChainSetClientAttributesResponse),
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

def hNetrServerReqChallenge(dce, primaryName, computerName, clientChallenge):
    request = NetrServerReqChallenge()
    request['PrimaryName'] = checkNullString(primaryName)
    request['ComputerName'] = checkNullString(computerName)
    request['ClientChallenge'] = clientChallenge
    return dce.request(request)

def hNetrServerAuthenticate3(dce, primaryName, accountName, secureChannelType, computerName, clientCredential, negotiateFlags):
    request = NetrServerAuthenticate3()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ClientCredential'] = clientCredential
    request['ComputerName'] = checkNullString(computerName)
    request['NegotiateFlags'] = negotiateFlags
    return dce.request(request)

def hDsrGetDcNameEx2(dce, computerName, accountName, allowableAccountControlBits, domainName, domainGuid, siteName, flags):
    request = DsrGetDcNameEx2()
    request['ComputerName'] = checkNullString(computerName)
    request['AccountName'] = checkNullString(accountName)
    request['AllowableAccountControlBits'] = allowableAccountControlBits
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteName'] = checkNullString(siteName)
    request['Flags'] = flags
    return dce.request(request)

def hDsrGetDcNameEx(dce, computerName, domainName, domainGuid, siteName, flags):
    request = DsrGetDcNameEx()
    request['ComputerName'] = checkNullString(computerName)
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteName'] = siteName
    request['Flags'] = flags
    return dce.request(request)

def hDsrGetDcName(dce, computerName, domainName, domainGuid, siteGuid, flags):
    request = DsrGetDcName()
    request['ComputerName'] = checkNullString(computerName)
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteGuid'] = siteGuid
    request['Flags'] = flags
    return dce.request(request)

def hNetrGetAnyDCName(dce, serverName, domainName):
    request = NetrGetAnyDCName()
    request['ServerName'] = checkNullString(serverName)
    request['DomainName'] = checkNullString(domainName)
    return dce.request(request)

def hNetrGetDCName(dce, serverName, domainName):
    request = NetrGetDCName()
    request['ServerName'] = checkNullString(serverName)
    request['DomainName'] = checkNullString(domainName)
    return dce.request(request)

def hDsrGetSiteName(dce, computerName):
    request = DsrGetSiteName()
    request['ComputerName'] = checkNullString(computerName)
    return dce.request(request)

def hDsrGetDcSiteCoverageW(dce, serverName):
    request = DsrGetDcSiteCoverageW()
    request['ServerName'] = checkNullString(serverName)
    return dce.request(request)

def hNetrServerAuthenticate2(dce, primaryName, accountName, secureChannelType, computerName, clientCredential, negotiateFlags):
    request = NetrServerAuthenticate2()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ClientCredential'] = clientCredential
    request['ComputerName'] = checkNullString(computerName)
    request['NegotiateFlags'] = negotiateFlags
    return dce.request(request)

def hNetrServerAuthenticate(dce, primaryName, accountName, secureChannelType, computerName, clientCredential):
    request = NetrServerAuthenticate()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ClientCredential'] = clientCredential
    request['ComputerName'] = checkNullString(computerName)
    return dce.request(request)

def hNetrServerPasswordGet(dce, primaryName, accountName, accountType, computerName, authenticator):
    request = NetrServerPasswordGet()
    request['PrimaryName'] = checkNullString(primaryName)
    request['AccountName'] = checkNullString(accountName)
    request['AccountType'] = accountType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    return dce.request(request)

def hNetrServerTrustPasswordsGet(dce, trustedDcName, accountName, secureChannelType, computerName, authenticator):
    request = NetrServerTrustPasswordsGet()
    request['TrustedDcName'] = checkNullString(trustedDcName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    return dce.request(request)

def hNetrLogonGetDomainInfo(dce, serverName, computerName, authenticator, returnAuthenticator=0, level=1):
    request = NetrLogonGetDomainInfo()
    request['ServerName'] = checkNullString(serverName)
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    if returnAuthenticator == 0:
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
    else:
        request['ReturnAuthenticator'] = returnAuthenticator

    request['Level'] = 1
    if level == 1:
        request['WkstaBuffer']['tag'] = 1
        request['WkstaBuffer']['WorkstationInfo']['DnsHostName'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['SiteName'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['OsName'] = ''
        request['WkstaBuffer']['WorkstationInfo']['Dummy1'] = NULL 
        request['WkstaBuffer']['WorkstationInfo']['Dummy2'] = NULL  
        request['WkstaBuffer']['WorkstationInfo']['Dummy3'] = NULL 
        request['WkstaBuffer']['WorkstationInfo']['Dummy4'] = NULL  
    else:
        request['WkstaBuffer']['tag'] = 2
        request['WkstaBuffer']['LsaPolicyInfo']['LsaPolicy'] = NULL
    return dce.request(request)

def hNetrLogonGetCapabilities(dce, serverName, computerName, authenticator, returnAuthenticator=0, queryLevel=1):
    request = NetrLogonGetCapabilities()
    request['ServerName'] = checkNullString(serverName)
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    if returnAuthenticator == 0:
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
    else:
        request['ReturnAuthenticator'] = returnAuthenticator
    request['QueryLevel'] = queryLevel
    return dce.request(request)

def hNetrServerGetTrustInfo(dce, trustedDcName, accountName, secureChannelType, computerName, authenticator):
    request = NetrServerGetTrustInfo()
    request['TrustedDcName'] = checkNullString(trustedDcName)
    request['AccountName'] = checkNullString(accountName)
    request['SecureChannelType'] = secureChannelType
    request['ComputerName'] = checkNullString(computerName)
    request['Authenticator'] = authenticator
    return dce.request(request)



