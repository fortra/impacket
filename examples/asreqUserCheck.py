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
#   This script performs user enumeration via Kerberos AS-REQ (Authentication Service Request).
#   It sends AS-REQ messages without preauthentication data to determine if usernames exist
#   in Active Directory without incrementing badPwdCount since no password is provided.
#
#   The KDC's response reveals whether a user exists based on error codes:
#     - KDC_ERR_PREAUTH_REQUIRED (25): User exists and is active
#     - KDC_ERR_C_PRINCIPAL_UNKNOWN (6): User does not exist
#     - KDC_ERR_CLIENT_REVOKED: User exists but account is disabled
#
#   This technique is useful for:
#     - Username enumeration without authentication
#     - Validating user lists without triggering account lockouts
#     - Identifying disabled accounts
#
#   Note: This is a reconnaissance technique. Use responsibly and only on authorized targets.
#
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import sys
import multiprocessing
import threading
import queue
import time

from pyasn1.codec.der import encoder

from impacket import version
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal


class KerberosUserEnum:
    def __init__(self, domain, users_file=None, kdc_host=None, threads=10, output_file=None):
        """
        Initialize the Kerberos user enumerator.

        Args:
            domain (str): Target Active Directory domain (e.g., 'CORP.LOCAL')
            users_file (str): Path to file containing usernames (one per line)
            kdc_host (str): IP address or FQDN of the KDC (Domain Controller)
            threads (int): Number of threads for concurrent enumeration
            output_file (str): Path to save valid users
        """
        self.__domain = domain.upper()
        self.__users_file = users_file
        self.__kdc_host = kdc_host
        self.__threads = threads
        self.__output_file = output_file
        self.__usernames = []
        self.__lock = threading.Lock()
        self.__valid_users = []
        self.__disabled_users = []
        self.__invalid_users = []
        self.__error_users = []
        self.__checked = 0
        self.__stop_event = threading.Event()
        self.__start_time = None

    def load_usernames(self):
        """Load usernames from the provided file."""
        if self.__users_file:
            try:
                with open(self.__users_file, 'r') as f:
                    self.__usernames = [line.strip() for line in f if line.strip()]
                logging.debug('Loaded %d usernames from %s' % (len(self.__usernames), self.__users_file))
            except IOError as e:
                logging.error('Error reading users file: %s' % e)
                sys.exit(1)
        return self.__usernames

    def kerberos_asreq_user_check(self, username):
        """
        Check if a username exists in Active Directory via Kerberos AS-REQ enumeration.

        This function sends a Kerberos AS-REQ (Authentication Service Request) with
        no preauthentication data. The KDC's response reveals whether the user exists
        without incrementing badPwdCount since no password is provided.

        KDC Response Codes:
            - KDC_ERR_PREAUTH_REQUIRED (25): User exists (preauth required)
            - KDC_ERR_C_PRINCIPAL_UNKNOWN (6): User does not exist
            - KDC_ERR_CLIENT_REVOKED: User account is disabled
            - Other errors: Various account/policy issues

        Args:
            username (str): Username to check (without domain)

        Returns:
            str: Status of the user check
                - "valid": User exists and is active
                - "disabled": User exists but account is disabled
                - "invalid": User does not exist
                - "wrong_realm": Wrong domain/realm
                - "error:<message>": Other error occurred
        """
        try:
            # Build the principal name
            client_principal = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )

            # Build AS-REQ
            as_req = AS_REQ()

            # Set domain
            as_req['pvno'] = 5
            as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

            # Request body
            req_body = seq_set(as_req, 'req-body')

            # KDC Options - request forwardable and renewable tickets
            opts = []
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)
            opts.append(constants.KDCOptions.renewable_ok.value)
            req_body['kdc-options'] = constants.encodeFlags(opts)

            # Set client principal
            seq_set(req_body, 'cname', client_principal.components_to_asn1)
            req_body['realm'] = self.__domain

            # Set server principal (krbtgt)
            server_principal = Principal(
                'krbtgt/%s' % self.__domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            seq_set(req_body, 'sname', server_principal.components_to_asn1)

            now = datetime.datetime.now(datetime.timezone.utc)

            req_body['till'] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
            req_body['rtime'] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
            req_body['nonce'] = random.getrandbits(31)

            # Set encryption types - prefer AES
            supported_ciphers = (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                constants.EncryptionTypes.rc4_hmac.value,
            )
            seq_set_iter(req_body, 'etype', supported_ciphers)

            # No preauthentication data (this is key for enumeration)
            # We deliberately don't include PA-DATA to trigger preauth required response

            # Encode and send the request
            message = encoder.encode(as_req)

            try:
                sendReceive(message, self.__domain, self.__kdc_host)
            except KerberosError as e:
                # Analyze the error code to determine user status
                error_code = e.getErrorCode()

                if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                    # User exists! (KDC requires preauthentication)
                    return 'valid'

                elif error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                    # User does not exist
                    return 'invalid'

                elif error_code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                    # User exists but account is disabled
                    return 'disabled'

                elif error_code == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value:
                    return 'wrong_realm'

                else:
                    # Other Kerberos error
                    try:
                        error_name = constants.ErrorCodes(error_code).name
                    except:
                        error_name = str(error_code)
                    return 'error:krb_%s' % error_name

            # If we get an AS-REP without error, user exists (very rare without preauth)
            return 'valid'

        except TimeoutError:
            return 'error:timeout'
        except OSError as e:
            return 'error:socket_%s' % e
        except Exception as e:
            return 'error:%s' % e

    def enumerate_users(self):
        """
        Enumerate all loaded usernames and display results using threading.
        """
        if not self.__usernames:
            logging.error('No usernames to enumerate. Use -usersfile option.')
            return

        logging.info('Total usernames to test: %d' % len(self.__usernames))
        logging.info('Using %d threads' % self.__threads)
        print()

        # Start timing
        self.__start_time = time.time()

        # Create queue with all usernames
        username_queue = queue.Queue()
        for username in self.__usernames:
            username_queue.put(username)

        # Create and start daemon threads
        threads = []
        for _ in range(self.__threads):
            t = threading.Thread(target=self._worker, args=(username_queue,))
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for queue to be empty or keyboard interrupt
        try:
            username_queue.join()
        except KeyboardInterrupt:
            self.__stop_event.set()
            raise

        self._print_summary()
        self._save_results()

    def _worker(self, username_queue):
        """
        Worker thread that processes usernames from the queue.

        Args:
            username_queue: Queue containing usernames to check
        """
        while not self.__stop_event.is_set():
            try:
                username = username_queue.get(timeout=0.1)
            except queue.Empty:
                break

            try:
                self._check_user_threadsafe(username)
            except Exception as exc:
                logging.error('%s generated an exception: %s' % (username, exc))
            finally:
                username_queue.task_done()

    def _check_user_threadsafe(self, username):
        """
        Thread-safe wrapper for checking a single user.

        Args:
            username (str): Username to check
        """
        status = self.kerberos_asreq_user_check(username)

        with self.__lock:
            self.__checked += 1
            if status == 'valid':
                # Clear progress bar before printing result
                if not logging.getLogger().isEnabledFor(logging.DEBUG):
                    sys.stdout.write('\r' + ' ' * 120 + '\r')
                    sys.stdout.flush()
                print('[+] %s' % username)
                self.__valid_users.append(username)
            elif status == 'disabled':
                # Clear progress bar before printing result
                if not logging.getLogger().isEnabledFor(logging.DEBUG):
                    sys.stdout.write('\r' + ' ' * 120 + '\r')
                    sys.stdout.flush()
                print('[!] %s (disabled)' % username)
                self.__disabled_users.append(username)
            elif status == 'invalid':
                logging.debug('[-] %s - does not exist' % username)
                self.__invalid_users.append(username)
            else:
                logging.debug('%s - %s' % (username, status))
                self.__error_users.append((username, status))

            # Update progress indicator
            self._update_progress()

    def _update_progress(self):
        """Update progress bar on the same line."""
        total = len(self.__usernames)
        checked = self.__checked
        percent = (checked * 100) // total
        bar_length = 40
        filled = (checked * bar_length) // total
        bar = '=' * filled + '-' * (bar_length - filled)

        # Calculate time remaining
        if checked > 0 and self.__start_time:
            elapsed = time.time() - self.__start_time
            avg_time = elapsed / checked
            remaining = int(avg_time * (total - checked))
            eta = '%02d:%02d:%02d' % (remaining // 3600, (remaining % 3600) // 60, remaining % 60)
        else:
            eta = '--:--:--'

        # Only show progress if not in debug mode (to avoid cluttering debug output)
        if not logging.getLogger().isEnabledFor(logging.DEBUG):
            sys.stdout.write('\r[%s] %d%% (%d/%d) | Valid: %d | Disabled: %d | ETA: %s' %
                           (bar, percent, checked, total,
                            len(self.__valid_users), len(self.__disabled_users), eta))
            sys.stdout.flush()

    def _print_summary(self):
        """Print enumeration summary."""
        # Clear the progress bar line
        if not logging.getLogger().isEnabledFor(logging.DEBUG):
            sys.stdout.write('\r' + ' ' * 110 + '\r')
            sys.stdout.flush()

        print()
        if self.__valid_users:
            print('Valid users: %d' % len(self.__valid_users))
        if self.__disabled_users:
            print('Disabled accounts: %d' % len(self.__disabled_users))
        if self.__error_users:
            print('Errors: %d' % len(self.__error_users))

    def _save_results(self):
        """Save valid users to output file if specified."""
        if self.__output_file and self.__valid_users:
            try:
                with open(self.__output_file, 'w') as f:
                    for user in sorted(self.__valid_users):
                        f.write('%s\n' % user)
                logging.debug('Valid users saved to %s' % self.__output_file)
            except IOError as e:
                logging.error('Error writing output file: %s' % e)

    def check_single_user(self, username):
        """
        Check a single username and display result.

        Args:
            username (str): Username to check
        """
        status = self.kerberos_asreq_user_check(username)

        if status == 'valid':
            print('[+] %s' % username)
        elif status == 'disabled':
            print('[!] %s (disabled)' % username)
        elif status == 'invalid':
            print('[-] %s' % username)
        elif status == 'wrong_realm':
            logging.error('Wrong realm for domain %s' % self.__domain)
        else:
            logging.error('%s - %s' % (username, status))

    def run(self):
        """
        Main execution method.
        """
        if self.__users_file:
            self.load_usernames()
            self.enumerate_users()


# Process command-line arguments
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True,
        description='Kerberos AS-REQ User Enumeration - Check if usernames exist in Active Directory '
                   'without triggering account lockouts or incrementing badPwdCount.'
    )

    parser.add_argument('domain', action='store', help='Target domain (e.g., CORP.LOCAL or corp.local)')
    parser.add_argument('-u', '--username', action='store', metavar='USERNAME',
                       help='Single username to check')
    parser.add_argument('-usersfile', action='store', metavar='FILE',
                       help='File containing usernames to enumerate (one per line)')
    parser.add_argument('-o', '--output-file', action='store', metavar='FILE', dest='output_file',
                       help='Output file to save valid usernames (one per line)')
    parser.add_argument('--threads', action='store', metavar='NUM', default='auto',
                       help='Number of threads (default: auto - uses CPU count * 2, max 50)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', dest='dc_ip',
                      help='IP Address of the domain controller (KDC). If omitted, '
                           'the domain part will be used to locate the KDC via DNS')

    parser.add_argument('-ts', action='store_true', help='Add timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    if len(sys.argv) == 1:
        parser.print_help()
        print('\nExamples:')
        print('\n  Single user check:')
        print('    kerberosUserEnum.py CORP.LOCAL -u john.doe -dc-ip 192.168.1.10')
        print('\n  Multiple users from file:')
        print('    kerberosUserEnum.py CORP.LOCAL -usersfile users.txt -dc-ip 192.168.1.10')
        print('\n  Save valid users to file:')
        print('    kerberosUserEnum.py CORP.LOCAL -usersfile users.txt -o valid_users.txt')
        print('\n  Custom thread count:')
        print('    kerberosUserEnum.py CORP.LOCAL -usersfile users.txt --threads 20')
        print('\n  Auto-detect DC via DNS:')
        print('    kerberosUserEnum.py CORP.LOCAL -usersfile users.txt')
        print('\nNote: This tool performs reconnaissance without authentication.')
        print('      Use only on authorized targets.')
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    if not options.username and not options.usersfile:
        logging.critical('Either -u or -usersfile must be specified!')
        sys.exit(1)

    if options.username and options.usersfile:
        logging.critical('Cannot specify both -u and -usersfile. Choose one.')
        sys.exit(1)

    # Determine thread count
    if options.username:
        threads = 1  # Single user doesn't need threading
    else:
        if options.threads == 'auto':
            threads = min(multiprocessing.cpu_count() * 2, 50)
        else:
            try:
                threads = int(options.threads)
                if threads < 1:
                    logging.critical('Thread count must be at least 1')
                    sys.exit(1)
            except ValueError:
                logging.critical('Invalid thread count. Use a number or "auto"')
                sys.exit(1)

    logging.info("Using Kerberos AS-REQ messages without preauthentication data to determine if usernames exist.")
    print()

    try:
        if options.username:
            # Single user check
            enumerator = KerberosUserEnum(
                domain=options.domain,
                kdc_host=options.dc_ip,
                threads=1,
                output_file=None
            )
            enumerator.check_single_user(options.username)
        else:

            # Multiple users from file
            enumerator = KerberosUserEnum(
                domain=options.domain,
                users_file=options.usersfile,
                kdc_host=options.dc_ip,
                threads=threads,
                output_file=options.output_file
            )
            enumerator.run()

    except KeyboardInterrupt:
        print('\n[!] User interrupted execution')
        sys.exit(1)
    except Exception as e:
        if options.debug:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)
