#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script is an alternative to kpasswd tool and intended to be used
#   for changing or setting passwords remotely over the Kerberos Change
#   Password protocol as extended by Microsoft (RFC 3244).
#   A user can change their own password. The old cleartext or TGT is
#   required to do so. The new password must be specified in cleartext and
#   the password policy is enforced.
#   A user can reset the password of another account. The user needs the
#   permission to do so, but does not need to know the old password.
#
#   Examples:
#       kpasswd.py j.doe@192.168.1.11
#       kpasswd.py contoso.local/j.doe@DC1 -hashes :fc525c9683e8fe067095ba2ddc971889
#       kpasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#       kpasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -reset  -newpass 'N3wPassw0rd!'
#       kpasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -reset a.victim -newpass 'N3wPassw0rd!'
#
# Author:
#   @alefburzmali
#
# References:
#   https://www.rfc-editor.org/rfc/rfc3244.txt
#

import sys
import logging
from getpass import getpass
from argparse import ArgumentParser

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials, parse_target
from impacket.krb5.kpasswd import changePassword, setPassword, KPasswdError


class KPasswd:

    def __init__(self, domain, username, oldPassword, oldPwdHashLM, oldPwdHashNT, aesKey='', kdcHost=None):
        self.domain = domain
        self.username = username
        self.oldPassword = oldPassword
        self.oldPwdHashLM = oldPwdHashLM
        self.oldPwdHashNT = oldPwdHashNT
        self.kdcHost = kdcHost
        self.aesKey = aesKey    

    def changePassword(self, newPassword):
        logging.info('Changing the password of {}\\{}'.format(self.domain, self.username))
        try:
            changePassword(self.username, self.domain, newPassword, self.oldPassword, self.oldPwdHashLM, self.oldPwdHashNT, self.aesKey, kdcHost=self.kdcHost)
        except KPasswdError as e:
            logging.error("Password not changed: {}".format(e))
        else:
            logging.info('Password was changed successfully.')

    def setPassword(self, targetDomain, targetName, newPassword):
        if not targetDomain:
            targetDomain = self.domain

        logging.info('Setting the password of {}\\{}'.format(targetDomain, targetName))
        try:
            setPassword(self.username, self.domain, targetName, targetDomain, newPassword, self.oldPassword, self.oldPwdHashLM, self.oldPwdHashNT, self.aesKey, kdcHost=self.kdcHost)
        except KPasswdError as e:
            logging.error("Password not changed for {}\\{}: {}".format(targetDomain, targetName, e))
        else:
            logging.info('Password was set successfully for {}\\{}.'.format(targetDomain, targetName))


def init_logger(options):
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


def parse_args():
    parser = ArgumentParser(description='Change password via Kerberos Change Password (KPASSWD).'
                                        'Use Kerberos authentication. Grabs credentials from ccache file '
                                        '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                                        ' the ones specified in the command line')

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@<dcName or address>]')
    parser.add_argument('-reset', action='store', help='[[domain/]username]')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='turn DEBUG output ON')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-newpass', action='store', default=None, help='new password')
                                                                        
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', default=None, metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    return parser.parse_args()


if __name__ == '__main__':
    print(version.BANNER)

    options = parse_args()
    init_logger(options)

    domain, username, oldPassword, kdcHost = parse_target(options.target)

    if options.hashes is not None:
        try:
            oldPwdHashLM, oldPwdHashNT = options.hashes.split(':')
        except ValueError:
            logging.critical('Wrong hashes string format. For more information run with --help option.')
            sys.exit(1)
    else:
        oldPwdHashLM = ''
        oldPwdHashNT = ''

    if oldPassword == '' and oldPwdHashNT == '':
        logging.info("Current password not given: will use KRB5CCNAME")

    if options.newpass is None:
        newPassword = getpass('New KRB password: ')
        if newPassword != getpass('Retype new KRB password: '):
            logging.critical('Passwords do not match, try again.')
            sys.exit(1)
    else:
        newPassword = options.newpass

    kpasswd = KPasswd(domain, username, oldPassword, oldPwdHashLM, oldPwdHashNT, options.aesKey, kdcHost=kdcHost)
    if options.reset:
        targetDomain, targetUser, _ = parse_credentials(options.reset)
        kpasswd.setPassword(targetDomain, targetUser, newPassword)
    else:
        kpasswd.changePassword(newPassword)
