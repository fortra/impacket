#!/usr/bin/env python
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
#   This script is a collection of functions to change or reset the password of
#   a user via various protocols. It supports:
#   - MS-SAMR over SMB or RPC transport (NetUserChangePassword and NetUserSetInfo protocols)
#   - Kerberos change-password and reset-password protocols
#   - LDAP password change and reset
#
#   The last documented mechanism (XACT-SMB) is not implemented.
#
#   A password change can usually be initiated when the previous password (or its
#   hash) is known, by the account itself or any other user.
#   A password reset requires additional permissions and may in some case bypass
#   password policies.
#
#   Tradeoff of the different protocols:
#   - MS-SAMR over SMB: (smbpasswd)
#       * SMB communication with the server or domain controller is required
#       * Can perform password change when the current password is expired
#       * Supports plaintext password and NTLM hashes as the new password value
#       * If provided as plaintext, password policy is enforced
#       * If using NTLM hashes, the new password is flagged as expired
#       * If using password reset with a NTLM hash, password policy and history is ignored
#       * When using hashes for change or reset, Kerberos keys are not created
#   - MS-SAMR over MS-RPC:
#       * RPC communication over TCP/135 and random ports
#       * Cannot get a handle on user object with default AD configuration:
#           - cannot use hSamrChangePasswordUser to change password with hashes only
#           - cannot use hSamrSetInformationUser to reset the password
#       * Password policy is enforced
#   - Kerberos Change Password: (kpasswd)
#       * Must use Kerberos authentication
#       * Must have a valid TGT/key or valid password for the user
#       * Must provide the new password as plaintext
#       * Password policy is enforced
#   - Kerberos Set Password:
#       * Must use Kerberos authentication
#       * Must have a valid TGT/key or valid password for the admin
#       * Must provide the new password as plaintext
#   - LDAP password change:
#       * The server must support TLS. If the DC is misconfigured, you cannot connect
#       * Must provide the old and new passwords as plaintext
#       * Password policy is enforced
#   - LDAP password set:
#       * The server must support TLS. If the DC is misconfigured, you cannot connect
#       * Must provide the new password as plaintext
#
#   Examples:
#     SAMR protocol over SMB transport to change passwords (like smbpasswd, -protocol smb-samr is implied)
#       changepasswd.py j.doe@192.168.1.11
#       changepasswd.py contoso.local/j.doe@DC1 -hashes :fc525c9683e8fe067095ba2ddc971889
#       changepasswd.py -protocol smb-samr contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#       changepasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb
#       changepasswd.py contoso.local/j.doe@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb -k -no-pass
#
#     SAMR protocol over SMB transport to reset passwords (like smbpasswd, -protocol smb-samr is implied)
#       changepasswd.py -reset contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#               -altuser administrator -altpass 'Adm1nPassw0rd!'
#       changepasswd.py -reset -protocol smb-samr contoso.local/j.doe:'Passw0rd!'@DC1
#               -newhashes :126502da14a98b58f2c319b81b3a49cb -altuser CONTOSO/administrator -altpass 'Adm1nPassw0rd!'
#       changepasswd.py -reset SRV01/administrator:'Passw0rd!'@10.10.13.37 -newhashes :126502da14a98b58f2c319b81b3a49cb
#               -altuser CONTOSO/SrvAdm -althash 6fe945ead39a7a6a2091001d98a913ab
#       changepasswd.py -reset SRV01/administrator:'Passw0rd!'@10.10.13.37 -newhashes :126502da14a98b58f2c319b81b3a49cb
#               -altuser CONTOSO/DomAdm -k -no-pass
#
#     SAMR protocol over MS-RPC transport to change passwords
#       changepasswd.py -protocol rpc-samr contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#
#     Kerberos Change Password protocol (like kpasswd) (-newhashes is not supported and -k is implied)
#       changepasswd.py -protocol kpasswd contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#
#     Kerberos Reset Password protocol (like kpasswd) (-newhashes is not supported and -k is implied)
#       changepasswd.py -reset -protocol kpasswd contoso.local/j.doe@DC1 -newpass 'N3wPassw0rd!'
#               -altuser CONTOSO/SrvAdm
#
#     LDAP password change (like ldappasswd) (-newhashes is not supported)
#       changepasswd.py -p ldap contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#       changepasswd.py -p ldap -k contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#
#     LDAP password set (-newhashes is not supported)
#       changepasswd.py -reset -p ldap contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#               -altuser administrator -althash 6fe945ead39a7a6a2091001d98a913ab
#       changepasswd.py -reset -p ldap -k contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#               -altuser CONTOSO/SrvAdm -k -no-pass
#
#
# This script is based on smbpasswd.py.
#
# Authors:
#   @snovvcrash
#   @alef-burzmali
#   @bransh
#   @Oddvarmoe
#   @p0dalirius
#
# References:
#   https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/password-change-mechanisms
#   [MS-SAMR] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880
#   [MS-SAMR] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476
#   [MS-SAMR] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/538222f7-1b89-4811-949a-0eac62e38dce
#   [LDAP] https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/change-windows-active-directory-user-password
#   [KPASSWD] https://www.rfc-editor.org/rfc/rfc3244.txt
#   https://snovvcrash.github.io/2020/10/31/pretending-to-be-smbpasswd-with-impacket.html
#   https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/
#   https://github.com/samba-team/samba/blob/master/source3/utils/smbpasswd.c
#   https://github.com/fortra/impacket/pull/381
#   https://github.com/fortra/impacket/pull/1189
#   https://github.com/fortra/impacket/pull/1304
#

import argparse
import logging
import sys

from getpass import getpass

from impacket import version
from impacket.dcerpc.v5 import transport, samr, epm
from impacket.krb5 import kerberosv5, kpasswd
from impacket.ldap import ldap, ldapasn1

from impacket.examples import logger
from impacket.examples.utils import parse_target, EMPTY_LM_HASH

import OpenSSL

class PasswordHandler:
    """Generic interface for all the password protocols supported by this script"""

    def __init__(
        self,
        address,
        domain="",
        authUsername="",
        authPassword="",
        authPwdHashLM="",
        authPwdHashNT="",
        doKerberos=False,
        aesKey="",
        kdcHost=None,
    ):
        """
        Instantiate password change or reset with the credentials of the account making the changes.
        It can be the target user, or a privileged account.

        :param string address:  IP address or hostname of the server or domain controller where the password will be changed
        :param string domain:   AD domain where the password will be changed
        :param string username: account that will attempt the password change or reset on the target(s)
        :param string password: password of the account that will attempt the password change
        :param string pwdHashLM: LM hash of the account that will attempt the password change
        :param string pwdHashNT: NT hash of the account that will attempt the password change
        :param bool doKerberos: use Kerberos authentication instead of NTLM
        :param string aesKey:   AES key for Kerberos authentication
        :param string kdcHost:  KDC host
        """

        self.address = address
        self.domain = domain
        self.username = authUsername
        self.password = authPassword
        self.pwdHashLM = authPwdHashLM
        self.pwdHashNT = authPwdHashNT
        self.doKerberos = doKerberos
        self.aesKey = aesKey
        self.kdcHost = kdcHost

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        """Implementation of a password change"""
        raise NotImplementedError

    def changePassword(
        self,
        targetUsername=None,
        targetDomain=None,
        oldPassword=None,
        newPassword="",
        oldPwdHashLM=None,
        oldPwdHashNT=None,
        newPwdHashLM="",
        newPwdHashNT="",
    ):
        """
        Change the password of a target account, knowing the previous password.

        :param string targetUsername: account whose password will be changed, if different from the user performing the change
        :param string targetDomain:   domain of the account
        :param string oldPassword:    current password
        :param string newPassword:    new password
        :param string oldPwdHashLM:   current password, as LM hash
        :param string oldPwdHashMT:   current password, as NT hash
        :param string newPwdHashLM:   new password, as LM hash
        :param string newPwdHashMT:   new password, as NT hash

        :return bool success
        """

        if targetUsername is None:
            # changing self
            targetUsername = self.username

            if targetDomain is None:
                targetDomain = self.domain
            if oldPassword is None:
                oldPassword = self.password
            if oldPwdHashLM is None:
                oldPwdHashLM = self.pwdHashLM
            if oldPwdHashNT is None:
                oldPwdHashNT = self.pwdHashNT

        logging.info(f"Changing the password of {targetDomain}\\{targetUsername}")
        return self._changePassword(
            targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
        )

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        """Implementation of a password set"""
        raise NotImplementedError

    def setPassword(self, targetUsername, targetDomain=None, newPassword="", newPwdHashLM="", newPwdHashNT=""):
        """
        Set or Reset the password of a target account, with privileges.

        :param string targetUsername:   account whose password will be changed
        :param string targetDomain:     domain of the account
        :param string newPassword:      new password
        :param string newPwdHashLM:     new password, as LM hash
        :param string newPwdHashMT:     new password, as NT hash

        :return bool success
        """

        if targetDomain is None:
            targetDomain = self.domain

        logging.info(f"Setting the password of {targetDomain}\\{targetUsername} as {self.domain}\\{self.username}")
        return self._setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT)


class KPassword(PasswordHandler):
    """Use Kerberos Change-Password or Set-Password protocols (rfc3244) to change passwords"""

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        if targetUsername != self.username:
            logging.critical("KPassword does not support changing the password of another user (try setPassword instead)")
            return False

        if not newPassword:
            logging.critical("KPassword requires the new password as plaintext")
            return False

        try:
            logging.debug(
                (
                    targetUsername,
                    targetDomain,
                    newPassword,
                    oldPassword,
                    oldPwdHashLM,
                    oldPwdHashNT,
                    self.aesKey,
                    self.kdcHost,
                )
            )
            kpasswd.changePassword(
                targetUsername,
                targetDomain,
                newPassword,
                oldPassword,
                oldPwdHashLM,
                oldPwdHashNT,
                aesKey=self.aesKey,
                kdcHost=self.kdcHost,
            )
        except (kerberosv5.KerberosError, kpasswd.KPasswdError) as e:
            logging.error(f"Password not changed: {e}")
            return False

        logging.info("Password was changed successfully.")
        return True

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        if not newPassword:
            logging.critical("KPassword requires the new password as plaintext")
            return False

        try:
            kpasswd.setPassword(
                self.username,
                self.domain,
                targetUsername,
                targetDomain,
                newPassword,
                self.password,
                self.pwdHashLM,
                self.pwdHashNT,
                aesKey=self.aesKey,
                kdcHost=self.kdcHost,
            )
        except (kerberosv5.KerberosError, kpasswd.KPasswdError) as e:
            logging.error(f"Password not changed for {targetDomain}\\{targetUsername}: {e}")
            return False

        logging.info(f"Password was set successfully for {targetDomain}\\{targetUsername}.")
        return True


class SamrPassword(PasswordHandler):
    """Use MS-SAMR protocol to change or reset the password of a user"""

    # our binding with SAMR
    dce = None
    anonymous = False

    def rpctransport(self):
        """
        Return a new transport for our RPC/DCE.

        :return rpc: RPC transport instance
        """
        raise NotImplementedError

    def authenticate(self, anonymous=False):
        """
        Instantiate a new transport and try to authenticate

        :param bool anonymous: Attempt a null binding
        :return dce: DCE/RPC, bound to SAMR
        """

        rpctransport = self.rpctransport()

        if hasattr(rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            if anonymous:
                rpctransport.set_credentials(username="", password="", domain="", lmhash="", nthash="", aesKey="")
            else:
                rpctransport.set_credentials(
                    self.username,
                    self.password,
                    self.domain,
                    self.pwdHashLM,
                    self.pwdHashNT,
                    aesKey=self.aesKey,
                )

        if anonymous:
            self.anonymous = True
            rpctransport.set_kerberos(False, None)
        else:
            self.anonymous = False
            rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

        as_user = "null session" if anonymous else f"{self.domain}\\{self.username}"
        logging.info(f"Connecting to DCE/RPC as {as_user}")

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        dce.bind(samr.MSRPC_UUID_SAMR)
        logging.debug("Successfully bound to SAMR")
        return dce

    def connect(self, retry_if_expired=False):
        """
        Connect to SAMR using our transport protocol.

        This method must instantiate self.dce

        :param bool retry_if_expired: Retry as null binding if our password is expired
        :return bool: success
        """

        if self.dce:
            # Already connected
            return True

        try:
            self.dce = self.authenticate(anonymous=False)

        except Exception as e:
            if any(msg in str(e) for msg in ("STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED")):
                if retry_if_expired:
                    logging.warning("Password is expired or must be changed, trying to bind with a null session.")
                    self.dce = self.authenticate(anonymous=True)
                else:
                    logging.critical(
                        "Cannot set new NTLM hashes when current password is expired. Provide a plaintext value for the "
                        "new password."
                    )
                    logging.debug(str(e))
                    return False
            elif "STATUS_LOGON_FAILURE" in str(e):
                logging.critical("Authentication failure when connecting to RPC: wrong credentials?")
                logging.debug(str(e))
                return False
            elif "STATUS_ACCOUNT_RESTRICTION" in str(e):
                logging.critical(
                    "Account restriction: username and credentials are valid, but some other restriction prevents"
                    "authentication, like 'Protected Users' group or time-of-day restriction"
                )
                logging.debug(str(e))
                return False
            elif "STATUS_ACCOUNT_DISABLED" in str(e):
                logging.critical("The account is currently disabled.")
                logging.debug(str(e))
                return False
            else:
                raise e

        return True

    def hSamrOpenUser(self, username):
        """Open an handle on the target user"""
        try:
            serverHandle = samr.hSamrConnect(self.dce, self.address + "\x00")["ServerHandle"]
            domainSID = samr.hSamrLookupDomainInSamServer(self.dce, serverHandle, self.domain)["DomainId"]
            domainHandle = samr.hSamrOpenDomain(self.dce, serverHandle, domainId=domainSID)["DomainHandle"]
            userRID = samr.hSamrLookupNamesInDomain(self.dce, domainHandle, (username,))["RelativeIds"]["Element"][0]
            userHandle = samr.hSamrOpenUser(self.dce, domainHandle, userId=userRID)["UserHandle"]
        except Exception as e:
            if "STATUS_NO_SUCH_DOMAIN" in str(e):
                logging.critical(
                    "Wrong realm. Try to set the domain name for the target user account explicitly in format "
                    "DOMAIN/username."
                )
                logging.debug(str(e))
                return False
            elif self.anonymous and "STATUS_ACCESS_DENIED" in str(e):
                logging.critical(
                    "Our anonymous session cannot get a handle to the target user. "
                    "Retry with a user whose password is not expired."
                )
                logging.debug(str(e))
                return False
            elif "STATUS_ACCESS_DENIED" in str(e):
                logging.critical("Access denied")
                logging.debug(str(e))
                return False
            else:
                raise e

        return userHandle

    def _SamrWrapper(self, samrProcedure, *args, _change=True, **kwargs):
        """
        Handles common errors when changing/resetting the password, regardless of the procedure

        :param callable samrProcedure: Function that will send the SAMR call
                                args and kwargs are passed verbatim
        :param bool _change:    Used for more precise error reporting,
                                True if it is a password change, False if it is a reset
        """
        logging.debug(f"Sending SAMR call {samrProcedure.__name__}")
        try:
            resp = samrProcedure(self.dce, *args, **kwargs)
        except Exception as e:
            if "STATUS_PASSWORD_RESTRICTION" in str(e):
                logging.critical(
                    "Some password update rule has been violated. For example, the password history policy may prohibit the "
                    "use of recent passwords or the password may not meet length criteria."
                )
                logging.debug(str(e))
                return False
            elif "STATUS_ACCESS_DENIED" in str(e):
                if _change:
                    logging.critical("Target user is not allowed to change their own password")
                else:
                    logging.critical(f"{self.domain}\\{self.username} user is not allowed to set the password of the target")
                logging.debug(str(e))
                return False
            else:
                raise e

        if resp["ErrorCode"] == 0:
            logging.info("Password was changed successfully.")
            return True

        logging.error("Non-zero return code, something weird happened.")
        resp.dump()
        return False

    def hSamrUnicodeChangePasswordUser2(
        self, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        return self._SamrWrapper(
            samr.hSamrUnicodeChangePasswordUser2,
            "\x00",
            username,
            oldPassword,
            newPassword,
            oldPwdHashLM,
            oldPwdHashNT,
            _change=True,
        )

    def hSamrChangePasswordUser(
        self, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        userHandle = self.hSamrOpenUser(username)
        if not userHandle:
            return False

        return self._SamrWrapper(
            samr.hSamrChangePasswordUser,
            userHandle,
            oldPassword=oldPassword,
            newPassword=newPassword,
            oldPwdHashNT=oldPwdHashNT,
            newPwdHashLM=newPwdHashLM,
            newPwdHashNT=newPwdHashNT,
            _change=True,
        )

    def hSamrSetInformationUser(self, username, newPassword, newPwdHashLM, newPwdHashNT):
        userHandle = self.hSamrOpenUser(username)
        if not userHandle:
            return False

        return self._SamrWrapper(samr.hSamrSetNTInternal1, userHandle, newPassword, newPwdHashNT, _change=False)

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        if not self.connect(retry_if_expired=True):
            return False

        if newPassword:
            # If using a plaintext value for the new password
            return self.hSamrUnicodeChangePasswordUser2(
                targetUsername, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, "", ""
            )
        else:
            # If using NTLM hashes for the new password
            res = self.hSamrChangePasswordUser(
                targetUsername, oldPassword, "", oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
            )
            if res:
                logging.warning("User might need to change their password at next logon because we set hashes (unless password never expires is set).")
            return res

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        if not self.connect(retry_if_expired=False):
            return False

        # If resetting the password with admin privileges
        res = self.hSamrSetInformationUser(targetUsername, newPassword, newPwdHashLM, newPwdHashNT)
        if res:
            logging.warning("User no longer has valid AES keys for Kerberos, until they change their password again.")
        return res


class RpcPassword(SamrPassword):
    def rpctransport(self):
        stringBinding = epm.hept_map(self.address, samr.MSRPC_UUID_SAMR, protocol="ncacn_ip_tcp")
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.setRemoteHost(self.address)
        return rpctransport

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        if not newPassword:
            logging.warning(
                "MS-RPC transport requires new password in plaintext in default Active Directory configuration. Trying anyway."
            )
        return super()._changePassword(
            targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
        )

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        logging.warning(
            "MS-RPC transport does not allow password reset in default Active Directory configuration. Trying anyway."
        )
        return super()._setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT)


class SmbPassword(SamrPassword):
    def rpctransport(self):
        return transport.SMBTransport(self.address, filename=r"\samr")


class LdapPassword(PasswordHandler):
    """Use LDAP to change or reset a user's password"""

    ldapConnection = None
    baseDN = None

    def connect(self, targetDomain):
        """Connect to LDAPS with the credentials provided in __init__"""

        if self.ldapConnection:
            return True

        ldapURI = "ldaps://" + self.address
        self.baseDN = "DC=" + ",DC=".join(targetDomain.split("."))

        logging.debug(f"Connecting to {ldapURI} as {self.domain}\\{self.username}")
        try:
            ldapConnection = ldap.LDAPConnection(ldapURI, self.baseDN, self.address)
            if not self.doKerberos:
                ldapConnection.login(self.username, self.password, self.domain, self.pwdHashLM, self.pwdHashNT)
            else:
                ldapConnection.kerberosLogin(
                    self.username,
                    self.password,
                    self.domain,
                    self.pwdHashLM,
                    self.pwdHashNT,
                    self.aesKey,
                    kdcHost=self.kdcHost,
                )
        except (ldap.LDAPSessionError, OpenSSL.SSL.SysCallError) as e:
            logging.error(f"Cannot connect to {ldapURI} as {self.domain}\\{self.username}: {e}")
            return False

        self.ldapConnection = ldapConnection
        return True

    def encodeLdapPassword(self, password):
        """
        Encode the password according to Microsoft's specifications

        Password must be surrounded by quotes and UTF-16 encoded
        """
        return f'"{password}"'.encode("utf-16-le")

    def findTargetDN(self, targetUsername, targetDomain):
        """Find the DN of the targeted user"""

        answers = self.ldapConnection.search(
            searchFilter=f"(sAMAccountName={targetUsername})",
            searchBase=self.baseDN,
            attributes=("distinguishedName",),
        )

        # return the DN of the first item
        for item in answers:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                # skipping references to other partitions
                continue

            return str(item["objectName"])

    def _modifyPassword(self, change, targetUsername, targetDomain, oldPasswordEncoded, newPasswordEncoded):
        if not self.connect(targetDomain):
            return False

        targetDN = self.findTargetDN(targetUsername, targetDomain)
        if not targetDN:
            logging.critical("Could not find the target user in LDAP")
            return False

        logging.debug(f"Found target distinguishedName: {targetDN}")

        # Build our Modify request
        request = ldapasn1.ModifyRequest()
        request["object"] = targetDN

        if change:
            request["changes"][0]["operation"] = ldapasn1.Operation("delete")
            request["changes"][0]["modification"]["type"] = "unicodePwd"
            request["changes"][0]["modification"]["vals"][0] = oldPasswordEncoded
            request["changes"][1]["operation"] = ldapasn1.Operation("add")
            request["changes"][1]["modification"]["type"] = "unicodePwd"
            request["changes"][1]["modification"]["vals"][0] = newPasswordEncoded
        else:
            request["changes"][0]["operation"] = ldapasn1.Operation("replace")
            request["changes"][0]["modification"]["type"] = "unicodePwd"
            request["changes"][0]["modification"]["vals"][0] = newPasswordEncoded

        logging.debug(f"Sending: {str(request)}")

        response = self.ldapConnection.sendReceive(request)[0]

        logging.debug(f"Receiving: {str(response)}")

        resultCode = int(response["protocolOp"]["modifyResponse"]["resultCode"])
        result = str(ldapasn1.ResultCode(resultCode))
        diagMessage = str(response["protocolOp"]["modifyResponse"]["diagnosticMessage"])

        if result == "success":
            logging.info(f"Password was changed successfully for {targetDN}")
            return True

        if result == "constraintViolation":
            logging.error(
                f"Could not change the password of {targetDN}, possibly due to the password "
                "policy or an invalid oldPassword."
            )
        elif result == "insufficientAccessRights":
            logging.error(f"Could not set the password of {targetDN}, {self.domain}\\{self.username} has insufficient rights")
        else:
            logging.error(f"Could not change the password of {targetDN}. {result}: {diagMessage}")

        return False

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        """
        Change the password of a user.

        Must send a delete operation with the oldPassword and an add
        operation with the newPassword in the same modify request.
        """

        if not oldPassword or not newPassword:
            logging.critical("LDAP requires the old and new passwords in plaintext")
            return False

        oldPasswordEncoded = self.encodeLdapPassword(oldPassword)
        newPasswordEncoded = self.encodeLdapPassword(newPassword)
        return self._modifyPassword(True, targetUsername, targetDomain, oldPasswordEncoded, newPasswordEncoded)

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        """
        Set the password of a user.

        Must send a modify operation with the newPassword (must have privileges).
        """

        if not newPassword:
            logging.critical("LDAP requires the new password in plaintext")
            return False

        newPasswordEncoded = self.encodeLdapPassword(newPassword)
        return self._modifyPassword(False, targetUsername, targetDomain, None, newPasswordEncoded)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Change or reset passwords over different protocols.",
    )

    parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<hostname or address>")
    parser.add_argument("-ts", action="store_true", help="adds timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")

    group = parser.add_argument_group("New credentials for target")
    exgroup = group.add_mutually_exclusive_group()
    exgroup.add_argument("-newpass", action="store", default=None, help="new password")
    exgroup.add_argument(
        "-newhashes",
        action="store",
        default=None,
        metavar="LMHASH:NTHASH",
        help="new NTLM hashes, format is NTHASH or LMHASH:NTHASH",
    )

    group = parser.add_argument_group("Authentication (target user whose password is changed)")
    group.add_argument(
        "-hashes", action="store", default=None, metavar="LMHASH:NTHASH", help="NTLM hashes, format is NTHASH or LMHASH:NTHASH"
    )
    group.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful for Kerberos, -k)")

    group = parser.add_argument_group("Authentication (optional, privileged user performing the change)")
    group.add_argument("-altuser", action="store", default=None, help="Alternative username")
    exgroup = group.add_mutually_exclusive_group()
    exgroup.add_argument("-altpass", action="store", default=None, help="Alternative password")
    exgroup.add_argument(
        "-althash", "-althashes", action="store", default=None, help="Alternative NT hash, format is NTHASH or LMHASH:NTHASH"
    )

    group = parser.add_argument_group("Method of operations")
    group.add_argument(
        "-protocol",
        "-p",
        action="store",
        help="Protocol to use for password change/reset",
        default="smb-samr",
        choices=(
            "smb-samr",
            "rpc-samr",
            "kpasswd",
            "ldap",
        ),
    )
    group.add_argument(
        "-reset",
        "-admin",
        action="store_true",
        help="Try to reset the password with privileges (may bypass some password policies)",
    )

    group = parser.add_argument_group(
        "Kerberos authentication", description="Applicable to the authenticating user (-altuser if defined, else target)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help=(
            "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. "
            "If valid credentials cannot be found, it will use the ones specified in the command line"
        ),
    )
    group.add_argument(
        "-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)"
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller, for Kerberos. If omitted it will use the domain part (FQDN) specified "
            "in the target parameter"
        ),
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


if __name__ == "__main__":
    print(version.BANNER)

    options = parse_args()
    logger.init(options.ts, options.debug)

    handlers = {
        "kpasswd": KPassword,
        "rpc-samr": RpcPassword,
        "smb-samr": SmbPassword,
        "ldap": LdapPassword,
    }

    try:
        PasswordProtocol = handlers[options.protocol]
    except KeyError:
        logging.critical(f"Unsupported password protocol {options.protocol}")
        sys.exit(1)

    # Parse account whose password is changed
    targetDomain, targetUsername, oldPassword, address = parse_target(options.target)

    if not targetDomain:
        if options.protocol in ("rpc-samr", "smb-samr"):
            targetDomain = "Builtin"
        else:
            targetDomain = address

    if options.hashes is not None:
        try:
            oldPwdHashLM, oldPwdHashNT = options.hashes.split(":")
        except ValueError:
            oldPwdHashLM = EMPTY_LM_HASH
            oldPwdHashNT = options.hashes
    else:
        oldPwdHashLM = ""
        oldPwdHashNT = ""

    if oldPassword == "" and oldPwdHashNT == "":
        if options.reset:
            pass  # no need for old one when we reset
        elif options.no_pass:
            logging.info("Current password not given: will use KRB5CCNAME")
        else:
            try:
                oldPassword = getpass("Current password: ")
            except KeyboardInterrupt:
                print()
                logging.warning("Cancelled")
                sys.exit(130)

    if options.newhashes is not None:
        newPassword = ""
        try:
            newPwdHashLM, newPwdHashNT = options.newhashes.split(":")
            if not newPwdHashLM:
                newPwdHashLM = EMPTY_LM_HASH
        except ValueError:
            newPwdHashLM = EMPTY_LM_HASH
            newPwdHashNT = options.newhashes
    else:
        newPwdHashLM = ""
        newPwdHashNT = ""
        if options.newpass is None:
            try:
                newPassword = getpass("New password: ")
                if newPassword != getpass("Retype new password: "):
                    logging.critical("Passwords do not match, try again.")
                    sys.exit(1)
            except KeyboardInterrupt:
                print()
                logging.warning("Cancelled")
                sys.exit(130)
        else:
            newPassword = options.newpass

    # Parse account of password changer
    if options.altuser is not None:
        try:
            authDomain, authUsername = options.altuser.split("/")
        except ValueError:
            authDomain = targetDomain
            authUsername = options.altuser

        if options.althash is not None:
            try:
                authPwdHashLM, authPwdHashNT = options.althash.split(":")
            except ValueError:
                authPwdHashLM = ""
                authPwdHashNT = options.althash
        else:
            authPwdHashLM = ""
            authPwdHashNT = ""

        authPassword = ""
        if options.altpass is not None:
            authPassword = options.altpass

        if options.altpass is None and options.althash is None and not options.no_pass:
            logging.critical(
                "Please, provide either alternative password (-altpass) or NT hash (-althash) for authentication, "
                "or specify -no-pass if you rely on Kerberos only"
            )
            sys.exit(1)
    else:
        authDomain = targetDomain
        authUsername = targetUsername
        authPassword = oldPassword
        authPwdHashLM = oldPwdHashLM
        authPwdHashNT = oldPwdHashNT

    doKerberos = options.k
    if options.protocol == "kpasswd" and not doKerberos:
        logging.debug("Using the KPassword protocol implies Kerberos authentication (-k)")
        doKerberos = True

    # Create a password management session
    handler = PasswordProtocol(
        address,
        authDomain,
        authUsername,
        authPassword,
        authPwdHashLM,
        authPwdHashNT,
        doKerberos,
        options.aesKey,
        kdcHost=options.dc_ip,
    )

    # Attempt the password change/reset
    if options.reset:
        ret = handler.setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT)
    else:
        if (authDomain, authUsername) != (targetDomain, targetUsername):
            logging.warning(
                f"Attempting to *change* the password of {targetDomain}/{targetUsername} as {authDomain}/{authUsername}. "
                "You may want to use '-reset' to *reset* the password of the target."
            )

        ret = handler.changePassword(
            targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
        )

    if ret:
        sys.exit(0)
    else:
        sys.exit(1)
