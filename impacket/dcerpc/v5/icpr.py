# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-ICPR] Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file.
#   Helper functions start with "h"<name of the call>.
#
# Author:
#   Sylvain Heiniger @(sploutchy) / Compass Security (https://www.compass-security.com)
#   based on the code of Oliver Lyak (@ly4k_)
#
# TODO:
#   - Testcases
#
import base64
from typing import List

from impacket import hresult_errors, LOG
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import DCERPC_v5, DCERPCException
from impacket.krb5 import constants
from impacket.uuid import uuidtup_to_bin


MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))

"""
// RFC 4556
77: "KDC_ERR_INCONSISTENT_KEY_PURPOSE"
78: "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED"
79: "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED"
80: "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED"
81: "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED"
 // RFC 6113
90: "KDC_ERR_PREAUTH_EXPIRED"
91: "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED"
92: "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET"
93: "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS"
"""

KRB5_ERROR_MESSAGES = constants.ERROR_MESSAGES
if 77 not in KRB5_ERROR_MESSAGES:
    KRB5_ERROR_MESSAGES.update(
        {
            77: (
                "KDC_ERR_INCONSISTENT_KEY_PURPOSE",
                "Certificate cannot be used for PKINIT client authentication",
            ),
            78: (
                "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED",
                "Digest algorithm for the public key in the certificate is not acceptable by the KDC",
            ),
            79: (
                "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED",
                "The paChecksum filed in the request is not present",
            ),
            80: (
                "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED",
                "The digest algorithm used by the id-pkinit-authData is not acceptable by the KDC",
            ),
            81: (
                "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED",
                "The KDC does not support the public key encryption key delivery method",
            ),
            90: (
                "KDC_ERR_PREAUTH_EXPIRED",
                "The conversation is too old and needs to restart",
            ),
            91: (
                "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
                "Additional pre-authentication required",
            ),
            92: (
                "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET",
                "KDC cannot accommodate requested padata element",
            ),
            93: ("KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS", "Unknown critical option"),
        }
    )


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        self.error_code &= 0xFFFFFFFF
        error_msg = translate_error_code(self.error_code)
        return "RequestSessionError: %s" % error_msg


################################################################################
# STRUCTURES
################################################################################
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
# [MS-WCCE] 2.2.2.2
class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (
        ("dwFlags", DWORD),
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pctbAttribs", CERTTRANSBLOB),
        ("pctbRequest", CERTTRANSBLOB),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequestResponse(NDRCALL):
    structure = (
        ("pdwRequestId", DWORD),
        ("pdwDisposition", ULONG),
        ("pctbCert", CERTTRANSBLOB),
        ("pctbEncodedCert", CERTTRANSBLOB),
        ("pctbDispositionMessage", CERTTRANSBLOB),
    )

################################################################################
# HELPER FUNCTIONS
################################################################################
@staticmethod
def translate_error_code(error_code: int) -> str:
    error_code &= 0xFFFFFFFF
    if error_code in hresult_errors.ERROR_MESSAGES:
        error_msg_short = hresult_errors.ERROR_MESSAGES[error_code][0]
        error_msg_verbose = hresult_errors.ERROR_MESSAGES[error_code][1]
        return "code: 0x%x - %s - %s" % (
            error_code,
            error_msg_short,
            error_msg_verbose,
        )
    else:
        return "unknown error code: 0x%x" % error_code

@staticmethod
def hCertServerRequest(
    dce: DCERPC_v5,
    csr: bytes,
    attributes: List[str],
    request_id: int = 0,
    ca: str = ""
) -> str:
    attribs = checkNullString("\n".join(attributes)).encode("utf-16le")
    pctb_attribs = CERTTRANSBLOB()
    pctb_attribs["cb"] = len(attribs)
    pctb_attribs["pb"] = attribs

    pctb_request = CERTTRANSBLOB()
    pctb_request["cb"] = len(csr)
    pctb_request["pb"] = csr

    request = CertServerRequest()
    request["dwFlags"] = 0
    request["pwszAuthority"] = checkNullString(ca)
    request["pdwRequestId"] = request_id
    request["pctbAttribs"] = pctb_attribs
    request["pctbRequest"] = pctb_request

    response = dce.request(request)

    error_code = response["pdwDisposition"]
    request_id = response["pdwRequestId"]

    if error_code == 3:
        LOG.info("Successfully requested certificate")
    else:
        if error_code == 5:
            LOG.warning("Certificate request is pending approval")
        else:
            error_msg = translate_error_code(error_code)
            if "unknown error code" in error_msg:
                LOG.error(
                    "Got unknown error while trying to request certificate: (%s): %s"
                    % (
                        error_msg,
                        b"".join(response["pctbDispositionMessage"]["pb"]).decode(
                            "utf-16le"
                        ),
                    )
                )
            else:
                LOG.error(
                    "Got error while trying to request certificate: %s" % error_msg
                )

    LOG.info("Request ID is %d" % request_id)

    return b"".join(response["pctbEncodedCert"]["pb"])
