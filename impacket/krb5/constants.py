# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   Constants for krb5.asn1 package. I took them out from the RFC plus
#   some data from [MS-KILE] as well. 
#
#

from impacket.dcerpc.v5.enum import Enum

def encodeFlags(flags):
    finalFlags = list()

    for i in range(0,32):
        finalFlags.append(0,)


    for f in flags:
        finalFlags[f] = 1

    return finalFlags

class ApplicationTagNumbers(Enum):
    Ticket         = 1
    Authenticator  = 2
    EncTicketPart  = 3
    AS_REQ         = 10
    AS_REP         = 11
    TGS_REQ        = 12
    TGS_REP        = 13
    AP_REQ         = 14
    AP_REP         = 15
    RESERVED16     = 16
    RESERVED17     = 17
    KRB_SAFE       = 20
    KRB_PRIV       = 21
    KRB_CRED       = 22
    EncASRepPart   = 25
    EncTGSRepPart  = 26
    EncApRepPart   = 27
    EncKrbPrivPart = 28 
    EncKrbCredPart = 29
    KRB_ERROR      = 30

class PrincipalNameType(Enum):
    NT_UNKNOWN        = 0 
    NT_PRINCIPAL      = 1
    NT_SRV_INST       = 2
    NT_SRV_HST        = 3
    NT_SRV_XHST       = 4
    NT_UID            = 5
    NT_X500_PRINCIPAL = 6
    NT_SMTP_NAME      = 7
    NT_ENTERPRISE     = 10

class PreAuthenticationDataTypes(Enum):
    PA_TGS_REQ                 = 1
    PA_ENC_TIMESTAMP           = 2
    PA_PW_SALT                 = 3
    PA_ENC_UNIX_TIME           = 5
    PA_SANDIA_SECUREID         = 6
    PA_SESAME                  = 7
    PA_OSF_DCE                 = 8
    PA_CYBERSAFE_SECUREID      = 9
    PA_AFS3_SALT               = 10
    PA_ETYPE_INFO              = 11
    PA_SAM_CHALLENGE           = 12
    PA_SAM_RESPONSE            = 13
    PA_PK_AS_REQ_OLD           = 14
    PA_PK_AS_REP_OLD           = 15
    PA_PK_AS_REQ               = 16
    PA_PK_AS_REP               = 17
    PA_ETYPE_INFO2             = 19
    PA_USE_SPECIFIED_KVNO      = 20
    PA_SAM_REDIRECT            = 21
    PA_GET_FROM_TYPED_DATA     = 22
    TD_PADATA                  = 22
    PA_SAM_ETYPE_INFO          = 23
    PA_ALT_PRINC               = 24
    PA_SAM_CHALLENGE2          = 30
    PA_SAM_RESPONSE2           = 31
    PA_EXTRA_TGT               = 41
    TD_PKINIT_CMS_CERTIFICATES = 101
    TD_KRB_PRINCIPAL           = 102
    TD_KRB_REALM               = 103
    TD_TRUSTED_CERTIFIERS      = 104
    TD_CERTIFICATE_INDEX       = 105
    TD_APP_DEFINED_ERROR       = 106
    TD_REQ_NONCE               = 107
    TD_REQ_SEQ                 = 108
    PA_PAC_REQUEST             = 128
    PA_FOR_USER                = 129
    PA_FX_COOKIE               = 133 
    PA_FX_FAST                 = 136
    PA_FX_ERROR                = 137
    PA_ENCRYPTED_CHALLENGE     = 138
    PA_SUPPORTED_ENCTYPES      = 165
    PA_PAC_OPTIONS             = 167

class AddressType(Enum):
    IPv4            = 2
    Directional     = 3
    ChaosNet        = 5
    XNS             = 6
    ISO             = 7
    DECNET_Phase_IV = 12
    AppleTalk_DDP   = 16
    NetBios         = 20
    IPv6            = 24

# 3.1.5.9 Key Usage Numbers
KERB_NON_KERB_SALT       = 16
KERB_NON_KERB_CKSUM_SALT = 17

# 7.5.4.  Authorization Data Types
class AuthorizationDataType(Enum):
    AD_IF_RELEVANT                     = 1
    AD_INTENDED_FOR_SERVER             = 2
    AD_INTENDED_FOR_APPLICATION_CLASS  = 3
    AD_KDC_ISSUED                      = 4
    AD_AND_OR                          = 5
    AD_MANDATORY_TICKET_EXTENSIONS     = 6
    AD_IN_TICKET_EXTENSIONS            = 7
    AD_MANDATORY_FOR_KDC               = 8
    #Reserved values                    = 9-63
    OSF_DCE                            = 64
    SESAME                             = 65
    AD_OSF_DCE_PKI_CERTID              = 66 
    AD_WIN2K_PAC                       = 128 
    AD_ETYPE_NEGOTIATION               = 129 

# 7.5.5.  Transited Encoding Types
class TransitedEncodingTypes(Enum):
    DOMAIN_X500_COMPRESS = 1

# 7.5.6.  Protocol Version Number
class ProtocolVersionNumber(Enum):
    pvno = 5

# 7.5.7.  Kerberos Message Types
class KerberosMessageTypes(Enum):
    KRB_AS_REQ      = 10    # Request for initial authentication
    KRB_AS_REP      = 11    # Response to KRB_AS_REQ request
    KRB_TGS_REQ     = 12    # Request for authentication based on TGT
    KRB_TGS_REP     = 13    # Response to KRB_TGS_REQ request
    KRB_AP_REQ      = 14    # Application request to server
    KRB_AP_REP      = 15    # Response to KRB_AP_REQ_MUTUAL
    KRB_RESERVED16  = 16    # Reserved for user-to-user krb_tgt_request
    KRB_RESERVED17  = 17    # Reserved for user-to-user krb_tgt_reply
    KRB_SAFE        = 20    # Safe (checksummed) application message
    KRB_PRIV        = 21    # Private (encrypted) application message
    KRB_CRED        = 22    # Private (encrypted) message to forward
                            # credentials
    KRB_ERROR       = 30    # Error response

# 7.5.8.  Name Types
class NameTypes(Enum):
    KRB_NT_UNKNOWN        = 0    # Name type not known
    KRB_NT_PRINCIPAL      = 1    # Just the name of the principal as in DCE,
                                 # or for users
    KRB_NT_SRV_INST       = 2    # Service and other unique instance (krbtgt)
    KRB_NT_SRV_HST        = 3    # Service with host name as instance
                                 # (telnet, rcommands)
    KRB_NT_SRV_XHST       = 4    # Service with host as remaining components
    KRB_NT_UID            = 5    # Unique ID
    KRB_NT_X500_PRINCIPAL = 6    # Encoded X.509 Distinguished name [RFC2253]
    KRB_NT_SMTP_NAME      = 7    # Name in form of SMTP email name
                                 # (e.g., user@example.com)
    KRB_NT_ENTERPRISE     = 10   #   Enterprise name; may be mapped to
                                 # principal name

# 7.5.9.  Error Codes
class ErrorCodes(Enum):
    KDC_ERR_NONE                           = 0  # No error
    KDC_ERR_NAME_EXP                       = 1  # Client's entry in database
                                                # has expired
    KDC_ERR_SERVICE_EXP                    = 2  # Server's entry in database
                                                # has expired
    KDC_ERR_BAD_PVNO                       = 3  # Requested protocol version
                                                # number not supported
    KDC_ERR_C_OLD_MAST_KVNO                = 4  # Client's key encrypted in
                                                # old master key
    KDC_ERR_S_OLD_MAST_KVNO                = 5  # Server's key encrypted in
                                                # old master key
    KDC_ERR_C_PRINCIPAL_UNKNOWN            = 6  # Client not found in
                                                # Kerberos database
    KDC_ERR_S_PRINCIPAL_UNKNOWN            = 7  # Server not found in
                                                # Kerberos database
    KDC_ERR_PRINCIPAL_NOT_UNIQUE           = 8  # Multiple principal entries
                                                # in database
    KDC_ERR_NULL_KEY                       = 9  # The client or server has a
                                                # null key
    KDC_ERR_CANNOT_POSTDATE               = 10  # Ticket not eligible for
                                                # postdating
    KDC_ERR_NEVER_VALID                   = 11  # Requested starttime is
                                                # later than end time
    KDC_ERR_POLICY                        = 12  # KDC policy rejects request
    KDC_ERR_BADOPTION                     = 13  # KDC cannot accommodate
                                                # requested option
    KDC_ERR_ETYPE_NOSUPP                  = 14  # KDC has no support for
                                                # encryption type
    KDC_ERR_SUMTYPE_NOSUPP                = 15  # KDC has no support for
                                                # checksum type
    KDC_ERR_PADATA_TYPE_NOSUPP            = 16  # KDC has no support for
                                                # padata type
    KDC_ERR_TRTYPE_NOSUPP                 = 17  # KDC has no support for
                                                # transited type
    KDC_ERR_CLIENT_REVOKED                = 18  # Clients credentials have
                                                # been revoked
    KDC_ERR_SERVICE_REVOKED               = 19  # Credentials for server have
                                                # been revoked
    KDC_ERR_TGT_REVOKED                   = 20  # TGT has been revoked
    KDC_ERR_CLIENT_NOTYET                 = 21  # Client not yet valid; try
                                                # again later
    KDC_ERR_SERVICE_NOTYET                = 22  # Server not yet valid; try
                                                # again later
    KDC_ERR_KEY_EXPIRED                   = 23  # Password has expired;
                                                # change password to reset
    KDC_ERR_PREAUTH_FAILED                = 24  # Pre-authentication
                                                # information was invalid
    KDC_ERR_PREAUTH_REQUIRED              = 25  # Additional pre-
                                                # authentication required
    KDC_ERR_SERVER_NOMATCH                = 26  # Requested server and ticket
                                                # don't match
    KDC_ERR_MUST_USE_USER2USER            = 27  # Server principal valid for
                                                # user2user only
    KDC_ERR_PATH_NOT_ACCEPTED             = 28  # KDC Policy rejects
                                                # transited path
    KDC_ERR_SVC_UNAVAILABLE               = 29  # A service is not available
    KRB_AP_ERR_BAD_INTEGRITY              = 31  # Integrity check on
                                                # decrypted field failed
    KRB_AP_ERR_TKT_EXPIRED                = 32  # Ticket expired
    KRB_AP_ERR_TKT_NYV                    = 33  # Ticket not yet valid
    KRB_AP_ERR_REPEAT                     = 34  # Request is a replay
    KRB_AP_ERR_NOT_US                     = 35  # The ticket isn't for us
    KRB_AP_ERR_BADMATCH                   = 36  # Ticket and authenticator
                                                # don't match
    KRB_AP_ERR_SKEW                       = 37  # Clock skew too great
    KRB_AP_ERR_BADADDR                    = 38  # Incorrect net address
    KRB_AP_ERR_BADVERSION                 = 39  # Protocol version mismatch
    KRB_AP_ERR_MSG_TYPE                   = 40  # Invalid msg type
    KRB_AP_ERR_MODIFIED                   = 41  # Message stream modified
    KRB_AP_ERR_BADORDER                   = 42  # Message out of order
    KRB_AP_ERR_BADKEYVER                  = 44  # Specified version of key is
                                                # not available
    KRB_AP_ERR_NOKEY                      = 45  # Service key not available
    KRB_AP_ERR_MUT_FAIL                   = 46  # Mutual authentication
                                                # failed
    KRB_AP_ERR_BADDIRECTION               = 47  # Incorrect message direction
    KRB_AP_ERR_METHOD                     = 48  # Alternative authentication
                                                # method required
    KRB_AP_ERR_BADSEQ                     = 49  # Incorrect sequence number
                                                # in message
    KRB_AP_ERR_INAPP_CKSUM                = 50  # Inappropriate type of
                                                # checksum in message
    KRB_AP_PATH_NOT_ACCEPTED              = 51  # Policy rejects transited
                                                # path
    KRB_ERR_RESPONSE_TOO_BIG              = 52  # Response too big for UDP;
                                                # retry with TCP
    KRB_ERR_GENERIC                       = 60  # Generic error (description
                                                # in e-text)
    KRB_ERR_FIELD_TOOLONG                 = 61  # Field is too long for this
                                                # implementation
    KDC_ERROR_CLIENT_NOT_TRUSTED          = 62  # Reserved for PKINIT
    KDC_ERROR_KDC_NOT_TRUSTED             = 63  # Reserved for PKINIT
    KDC_ERROR_INVALID_SIG                 = 64  # Reserved for PKINIT
    KDC_ERR_KEY_TOO_WEAK                  = 65  # Reserved for PKINIT
    KDC_ERR_CERTIFICATE_MISMATCH          = 66  # Reserved for PKINIT
    KRB_AP_ERR_NO_TGT                     = 67  # No TGT available to
                                                # validate USER-TO-USER
    KDC_ERR_WRONG_REALM                   = 68  # Reserved for future use
    KRB_AP_ERR_USER_TO_USER_REQUIRED      = 69  # Ticket must be for
                                                # USER-TO-USER
    KDC_ERR_CANT_VERIFY_CERTIFICATE       = 70  # Reserved for PKINIT
    KDC_ERR_INVALID_CERTIFICATE           = 71  # Reserved for PKINIT
    KDC_ERR_REVOKED_CERTIFICATE           = 72  # Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNKNOWN     = 73  # Reserved for PKINIT
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74  # Reserved for PKINIT
    KDC_ERR_CLIENT_NAME_MISMATCH          = 75  # Reserved for PKINIT
    KDC_ERR_KDC_NAME_MISMATCH             = 76  # Reserved for PKINIT
 
ERROR_MESSAGES = {
    0  : ('KDC_ERR_NONE', 'No error'),
    1  : ('KDC_ERR_NAME_EXP', 'Client\'s entry in database has expired'),
    2  : ('KDC_ERR_SERVICE_EXP', 'Server\'s entry in database has expired'),
    3  : ('KDC_ERR_BAD_PVNO', 'Requested protocol version number not supported'),
    4  : ('KDC_ERR_C_OLD_MAST_KVNO', 'Client\'s key encrypted in old master key'),
    5  : ('KDC_ERR_S_OLD_MAST_KVNO', 'Server\'s key encrypted in old master key'),
    6  : ('KDC_ERR_C_PRINCIPAL_UNKNOWN', 'Client not found in Kerberos database'),
    7  : ('KDC_ERR_S_PRINCIPAL_UNKNOWN', 'Server not found in Kerberos database'),
    8  : ('KDC_ERR_PRINCIPAL_NOT_UNIQUE', 'Multiple principal entries in database'),
    9  : ('KDC_ERR_NULL_KEY', 'The client or server has a null key'),
    10 : ('KDC_ERR_CANNOT_POSTDATE', 'Ticket not eligible for postdating'),
    11 : ('KDC_ERR_NEVER_VALID', 'Requested starttime is later than end time'),
    12 : ('KDC_ERR_POLICY', 'KDC policy rejects request'),
    13 : ('KDC_ERR_BADOPTION', 'KDC cannot accommodate requested option'),
    14 : ('KDC_ERR_ETYPE_NOSUPP', 'KDC has no support for encryption type'),
    15 : ('KDC_ERR_SUMTYPE_NOSUPP', 'KDC has no support for checksum type'),
    16 : ('KDC_ERR_PADATA_TYPE_NOSUPP', 'KDC has no support for padata type'),
    17 : ('KDC_ERR_TRTYPE_NOSUPP', 'KDC has no support for transited type'),
    18 : ('KDC_ERR_CLIENT_REVOKED', 'Clients credentials have been revoked'),
    19 : ('KDC_ERR_SERVICE_REVOKED', 'Credentials for server have been revoked'),
    20 : ('KDC_ERR_TGT_REVOKED', 'TGT has been revoked'),
    21 : ('KDC_ERR_CLIENT_NOTYET', 'Client not yet valid; try again later'),
    22 : ('KDC_ERR_SERVICE_NOTYET', 'Server not yet valid; try again later'),
    23 : ('KDC_ERR_KEY_EXPIRED', 'Password has expired; change password to reset'),
    24 : ('KDC_ERR_PREAUTH_FAILED', 'Pre-authentication information was invalid'),
    25 : ('KDC_ERR_PREAUTH_REQUIRED', 'Additional pre-authentication required'),
    26 : ('KDC_ERR_SERVER_NOMATCH', 'Requested server and ticket don\'t match'),
    27 : ('KDC_ERR_MUST_USE_USER2USER', 'Server principal valid for user2user only'),
    28 : ('KDC_ERR_PATH_NOT_ACCEPTED', 'KDC Policy rejects transited path'),
    29 : ('KDC_ERR_SVC_UNAVAILABLE', 'A service is not available'),
    31 : ('KRB_AP_ERR_BAD_INTEGRITY', 'Integrity check on decrypted field failed'),
    32 : ('KRB_AP_ERR_TKT_EXPIRED', 'Ticket expired'),
    33 : ('KRB_AP_ERR_TKT_NYV', 'Ticket not yet valid'),
    34 : ('KRB_AP_ERR_REPEAT', 'Request is a replay'),
    35 : ('KRB_AP_ERR_NOT_US', 'The ticket isn\'t for us'),
    36 : ('KRB_AP_ERR_BADMATCH', 'Ticket and authenticator don\'t match'),
    37 : ('KRB_AP_ERR_SKEW', 'Clock skew too great'),
    38 : ('KRB_AP_ERR_BADADDR', 'Incorrect net address'),
    39 : ('KRB_AP_ERR_BADVERSION', 'Protocol version mismatch'),
    40 : ('KRB_AP_ERR_MSG_TYPE', 'Invalid msg type'),
    41 : ('KRB_AP_ERR_MODIFIED', 'Message stream modified'),
    42 : ('KRB_AP_ERR_BADORDER', 'Message out of order'),
    44 : ('KRB_AP_ERR_BADKEYVER', 'Specified version of key is not available'),
    45 : ('KRB_AP_ERR_NOKEY', 'Service key not available'),
    46 : ('KRB_AP_ERR_MUT_FAIL', 'Mutual authentication failed'),
    47 : ('KRB_AP_ERR_BADDIRECTION', 'Incorrect message direction'),
    48 : ('KRB_AP_ERR_METHOD', 'Alternative authentication method required'),
    49 : ('KRB_AP_ERR_BADSEQ', 'Incorrect sequence number in message'),
    50 : ('KRB_AP_ERR_INAPP_CKSUM', 'Inappropriate type of checksum in message'),
    51 : ('KRB_AP_PATH_NOT_ACCEPTED', 'Policy rejects transited path'),
    52 : ('KRB_ERR_RESPONSE_TOO_BIG', 'Response too big for UDP; retry with TCP'),
    60 : ('KRB_ERR_GENERIC', 'Generic error (description in e-text)'),
    61 : ('KRB_ERR_FIELD_TOOLONG', 'Field is too long for this implementation'),
    62 : ('KDC_ERROR_CLIENT_NOT_TRUSTED', 'Reserved for PKINIT'),
    63 : ('KDC_ERROR_KDC_NOT_TRUSTED', 'Reserved for PKINIT'),
    64 : ('KDC_ERROR_INVALID_SIG', 'Reserved for PKINIT'),
    65 : ('KDC_ERR_KEY_TOO_WEAK', 'Reserved for PKINIT'),
    66 : ('KDC_ERR_CERTIFICATE_MISMATCH', 'Reserved for PKINIT'),
    67 : ('KRB_AP_ERR_NO_TGT', 'No TGT available to validate USER-TO-USER'),
    68 : ('KDC_ERR_WRONG_REALM', 'Reserved for future use'),
    69 : ('KRB_AP_ERR_USER_TO_USER_REQUIRED', 'Ticket must be for USER-TO-USER'),
    70 : ('KDC_ERR_CANT_VERIFY_CERTIFICATE', 'Reserved for PKINIT'),
    71 : ('KDC_ERR_INVALID_CERTIFICATE', 'Reserved for PKINIT'),
    72 : ('KDC_ERR_REVOKED_CERTIFICATE', 'Reserved for PKINIT'),
    73 : ('KDC_ERR_REVOCATION_STATUS_UNKNOWN', 'Reserved for PKINIT'),
    74 : ('KDC_ERR_REVOCATION_STATUS_UNAVAILABLE', 'Reserved for PKINIT'),
    75 : ('KDC_ERR_CLIENT_NAME_MISMATCH', 'Reserved for PKINIT'),
    76 : ('KDC_ERR_KDC_NAME_MISMATCH', 'Reserved for PKINIT'),
}
 
class TicketFlags(Enum):
    reserved                 = 0
    forwardable              = 1
    forwarded                = 2
    proxiable                = 3
    proxy                    = 4
    may_postdate             = 5
    postdated                = 6
    invalid                  = 7
    renewable                = 8
    initial                  = 9
    pre_authent              = 10
    hw_authent               = 11
    transited_policy_checked = 12
    ok_as_delegate           = 13
    enc_pa_rep               = 15
    anonymous                = 16

class KDCOptions(Enum):
    reserved                = 0
    forwardable             = 1
    forwarded               = 2
    proxiable               = 3
    proxy                   = 4
    allow_postdate          = 5
    postdated               = 6
    unused7                 = 7
    renewable               = 8
    unused9                 = 9
    unused10                = 10
    opt_hardware_auth       = 11
    unused12                = 12
    unused13                = 13
    cname_in_addl_tkt       = 14
    canonicalize            = 15
    disable_transited_check = 26
    renewable_ok            = 27
    enc_tkt_in_skey         = 28
    renew                   = 30
    validate                = 31

class APOptions(Enum):
    reserved        = 0
    use_session_key = 1
    mutual_required = 2

class EncryptionTypes(Enum):
    des_cbc_crc                  = 1
    des_cbc_md4                  = 2
    des_cbc_md5                  = 3
    _reserved_4                  = 4
    des3_cbc_md5                 = 5
    _reserved_6                  = 6
    des3_cbc_sha1                = 7
    dsaWithSHA1_CmsOID           = 9
    md5WithRSAEncryption_CmsOID  = 10
    sha1WithRSAEncryption_CmsOID = 11
    rc2CBC_EnvOID                = 12
    rsaEncryption_EnvOID         = 13
    rsaES_OAEP_ENV_OID           = 14
    des_ede3_cbc_Env_OID         = 15
    des3_cbc_sha1_kd             = 16
    aes128_cts_hmac_sha1_96      = 17
    aes256_cts_hmac_sha1_96      = 18
    rc4_hmac                     = 23
    rc4_hmac_exp                 = 24
    subkey_keymaterial           = 65

class ChecksumTypes(Enum):
    rsa_md5_des       = 8
    rsa_md4_des       = 4
    hmac_md5          = -138
    hmac_sha1_des3_kd = 12
    hmac_sha1_96_aes128 = 15
    hmac_sha1_96_aes256 = 16
