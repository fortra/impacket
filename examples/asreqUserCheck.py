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
# Author:
#   @n3rada
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


def load_usernames(users_file):
    """
    Load usernames from the provided file.

    Args:
        users_file (str): Path to file containing usernames (one per line)

    Returns:
        list: List of usernames
    """
    try:
        with open(users_file, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
        logging.debug("Loaded %d usernames from %s" % (len(usernames), users_file))
        return usernames
    except IOError as e:
        logging.error("Error reading users file: %s" % e)
        return []


def kerberos_asreq_user_check(username: str, domain: str, kdc_host: str = None):
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
        domain (str): Target Active Directory domain (e.g., 'CORP.LOCAL')
        kdc_host (str): IP address or FQDN of the KDC (Domain Controller)

    Returns:
        dict: Dictionary containing check results with the following keys:
            - username (str): The username that was checked
            - exists (bool): Whether the user exists in the domain
            - enabled (bool|None): Whether the account is enabled (None if user doesn't exist)
            - status (str): Status code - "valid", "disabled", "invalid", "wrong_realm", or "error"
            - error (str|None): Error message if status is "error", None otherwise
            - error_code (int|None): Kerberos error code if applicable
    """
    try:
        # Build the principal name
        client_principal = Principal(
            username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        # Build AS-REQ
        as_req = AS_REQ()

        # Set domain
        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        # Request body
        req_body = seq_set(as_req, "req-body")

        # KDC Options - request forwardable and renewable tickets
        opts = []
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.renewable_ok.value)
        req_body["kdc-options"] = constants.encodeFlags(opts)

        # Set client principal
        seq_set(req_body, "cname", client_principal.components_to_asn1)
        req_body["realm"] = domain.upper()

        # Set server principal (krbtgt)
        server_principal = Principal(
            "krbtgt/%s" % domain.upper(),
            type=constants.PrincipalNameType.NT_PRINCIPAL.value,
        )
        seq_set(req_body, "sname", server_principal.components_to_asn1)

        now = datetime.datetime.now(datetime.timezone.utc)

        req_body["till"] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
        req_body["rtime"] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
        req_body["nonce"] = random.getrandbits(31)

        # Set encryption types - prefer AES
        supported_ciphers = (
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.rc4_hmac.value,
        )
        seq_set_iter(req_body, "etype", supported_ciphers)

        # No preauthentication data (this is key for enumeration)
        # We deliberately don't include PA-DATA to trigger preauth required response

        # Encode and send the request
        message = encoder.encode(as_req)

        try:
            sendReceive(message, domain.upper(), kdc_host)
        except KerberosError as e:
            # Analyze the error code to determine user status
            error_code = e.getErrorCode()

            if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                # User exists! (KDC requires preauthentication)
                return {
                    "username": username,
                    "exists": True,
                    "enabled": True,
                    "status": "valid",
                    "error": None,
                    "error_code": error_code,
                }

            if error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                # User does not exist
                return {
                    "username": username,
                    "exists": False,
                    "enabled": None,
                    "status": "invalid",
                    "error": None,
                    "error_code": error_code,
                }

            if error_code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                # User exists but account is disabled
                return {
                    "username": username,
                    "exists": True,
                    "enabled": False,
                    "status": "disabled",
                    "error": None,
                    "error_code": error_code,
                }

            if error_code == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value:
                return {
                    "username": username,
                    "exists": False,
                    "enabled": None,
                    "status": "wrong_realm",
                    "error": "Wrong realm/domain",
                    "error_code": error_code,
                }

            # Other Kerberos error
            try:
                error_name = constants.ErrorCodes(error_code).name
            except:
                error_name = str(error_code)
            return {
                "username": username,
                "exists": None,
                "enabled": None,
                "status": "error",
                "error": "krb_%s" % error_name,
                "error_code": error_code,
            }

        # If we get an AS-REP without error, user exists (very rare without preauth)
        return {
            "username": username,
            "exists": True,
            "enabled": True,
            "status": "valid",
            "error": None,
            "error_code": None,
        }

    except TimeoutError:
        return {
            "username": username,
            "exists": None,
            "enabled": None,
            "status": "error",
            "error": "timeout",
            "error_code": None,
        }
    except OSError as e:
        return {
            "username": username,
            "exists": None,
            "enabled": None,
            "status": "error",
            "error": "socket_%s" % e,
            "error_code": None,
        }
    except Exception as e:
        return {
            "username": username,
            "exists": None,
            "enabled": None,
            "status": "error",
            "error": str(e),
            "error_code": None,
        }


def check_user_threadsafe(username, domain, kdc_host, shared_state, lock):
    """
    Thread-safe wrapper for checking a single user.

    Args:
        username (str): Username to check
        domain (str): Target domain
        kdc_host (str): KDC host address
        shared_state (dict): Shared state dictionary containing results and counters
        lock (threading.Lock): Lock for thread-safe updates
    """
    result = kerberos_asreq_user_check(username, domain, kdc_host)

    with lock:
        shared_state["checked"] += 1
        status = result["status"]

        if status == "valid":
            # Clear progress bar before printing result
            if not logging.getLogger().isEnabledFor(logging.DEBUG):
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
            print("[+] %s" % username)
            shared_state["valid_users"].append(username)
        elif status == "disabled":
            # Clear progress bar before printing result
            if not logging.getLogger().isEnabledFor(logging.DEBUG):
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()
            print("[!] %s (disabled)" % username)
            shared_state["disabled_users"].append(username)
        elif status == "invalid":
            logging.debug("[-] %s - does not exist" % username)
            shared_state["invalid_users"].append(username)
        else:
            error_msg = result.get("error", "unknown error")
            logging.debug("%s - %s" % (username, error_msg))
            shared_state["error_users"].append((username, error_msg))

        # Update progress indicator
        update_progress(shared_state)


def worker(username_queue, domain, kdc_host, shared_state, lock, stop_event):
    """
    Worker thread that processes usernames from the queue.

    Args:
        username_queue (queue.Queue): Queue containing usernames to check
        domain (str): Target domain
        kdc_host (str): KDC host address
        shared_state (dict): Shared state dictionary
        lock (threading.Lock): Lock for thread-safe updates
        stop_event (threading.Event): Event to signal stopping
    """
    while not stop_event.is_set():
        try:
            username = username_queue.get(timeout=0.1)
        except queue.Empty:
            break

        try:
            check_user_threadsafe(username, domain, kdc_host, shared_state, lock)
        except Exception as exc:
            logging.error("%s generated an exception: %s" % (username, exc))
        finally:
            username_queue.task_done()


def update_progress(shared_state):
    """
    Update progress bar on the same line.

    Args:
        shared_state (dict): Shared state dictionary containing progress info
    """
    total = shared_state["total"]
    checked = shared_state["checked"]
    percent = (checked * 100) // total if total > 0 else 0
    bar_length = 40
    filled = (checked * bar_length) // total if total > 0 else 0
    bar = "=" * filled + "-" * (bar_length - filled)

    # Calculate time remaining
    if checked > 0 and shared_state["start_time"]:
        elapsed = time.time() - shared_state["start_time"]
        avg_time = elapsed / checked
        remaining = int(avg_time * (total - checked))
        eta = "%02d:%02d:%02d" % (
            remaining // 3600,
            (remaining % 3600) // 60,
            remaining % 60,
        )
    else:
        eta = "--:--:--"

    # Only show progress if not in debug mode (to avoid cluttering debug output)
    if not logging.getLogger().isEnabledFor(logging.DEBUG):
        sys.stdout.write(
            "\r[%s] %d%% (%d/%d) | Valid: %d | Disabled: %d | ETA: %s"
            % (
                bar,
                percent,
                checked,
                total,
                len(shared_state["valid_users"]),
                len(shared_state["disabled_users"]),
                eta,
            )
        )
        sys.stdout.flush()


def print_summary(shared_state):
    """
    Print enumeration summary.

    Args:
        shared_state (dict): Shared state dictionary containing results
    """
    # Clear the progress bar line
    if not logging.getLogger().isEnabledFor(logging.DEBUG):
        sys.stdout.write("\r" + " " * 110 + "\r")
        sys.stdout.flush()

    print()
    if shared_state["valid_users"]:
        print("Valid users: %d" % len(shared_state["valid_users"]))
    if shared_state["disabled_users"]:
        print("Disabled accounts: %d" % len(shared_state["disabled_users"]))
    if shared_state["error_users"]:
        print("Errors: %d" % len(shared_state["error_users"]))


def save_results(output_file, valid_users):
    """
    Save valid users to output file if specified.

    Args:
        output_file (str): Path to output file
        valid_users (list): List of valid usernames
    """
    if output_file and valid_users:
        try:
            with open(output_file, "w") as f:
                for user in sorted(valid_users):
                    f.write("%s\n" % user)
            logging.debug("Valid users saved to %s" % output_file)
        except IOError as e:
            logging.error("Error writing output file: %s" % e)


def enumerate_users(usernames, domain, kdc_host=None, threads=10, output_file=None):
    """
    Enumerate all usernames and display results using threading.

    Args:
        usernames (list): List of usernames to check
        domain (str): Target domain
        kdc_host (str): KDC host address
        threads (int): Number of threads for concurrent enumeration
        output_file (str): Path to save valid users

    Returns:
        dict: Dictionary containing enumeration results
    """
    if not usernames:
        logging.error("No usernames to enumerate.")
        return None

    logging.info("Total usernames to test: %d" % len(usernames))
    logging.info("Using %d threads" % threads)
    print()

    # Initialize shared state
    shared_state = {
        "total": len(usernames),
        "checked": 0,
        "valid_users": [],
        "disabled_users": [],
        "invalid_users": [],
        "error_users": [],
        "start_time": time.time(),
    }

    lock = threading.Lock()
    stop_event = threading.Event()

    # Create queue with all usernames
    username_queue = queue.Queue()
    for username in usernames:
        username_queue.put(username)

    # Create and start daemon threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(
            target=worker,
            args=(username_queue, domain, kdc_host, shared_state, lock, stop_event),
        )
        t.daemon = True
        t.start()
        thread_list.append(t)

    # Wait for queue to be empty or keyboard interrupt
    try:
        username_queue.join()
    except KeyboardInterrupt:
        stop_event.set()
        raise

    print_summary(shared_state)
    save_results(output_file, shared_state["valid_users"])

    return shared_state


def check_single_user(username, domain, kdc_host=None):
    """
    Check a single username and display result.

    Args:
        username (str): Username to check
        domain (str): Target domain
        kdc_host (str): KDC host address

    Returns:
        dict: Result dictionary from kerberos_asreq_user_check
    """
    result = kerberos_asreq_user_check(username, domain, kdc_host)
    status = result["status"]

    if status == "valid":
        print("[+] %s" % username)
        return result

    if status == "disabled":
        print("[!] %s (disabled)" % username)
        return result

    if status == "invalid":
        print("[-] %s" % username)
        return result

    if status == "wrong_realm":
        logging.error("Wrong realm for domain %s" % domain)
        return result

    error_msg = result.get("error", "unknown error")
    logging.error("%s - %s" % (username, error_msg))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asreqUserCheck",
        add_help=True,
        description="Kerberos AS-REQ User Enumeration - Check if usernames exist in Active Directory "
        "without triggering account lockouts or incrementing badPwdCount.",
    )

    parser.add_argument(
        "domain", action="store", help="Target domain (e.g., CORP.LOCAL or corp.local)"
    )
    parser.add_argument(
        "-u",
        "--username",
        action="store",
        metavar="USERNAME",
        help="Single username to check",
    )
    parser.add_argument(
        "-usersfile",
        action="store",
        metavar="FILE",
        help="File containing usernames to enumerate (one per line)",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        action="store",
        metavar="FILE",
        dest="output_file",
        help="Output file to save valid usernames (one per line)",
    )
    parser.add_argument(
        "--threads",
        action="store",
        metavar="NUM",
        default="auto",
        help="Number of threads (default: auto - uses CPU count * 2, max 50)",
    )

    group = parser.add_argument_group("connection")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        dest="dc_ip",
        help="IP Address of the domain controller (KDC). If omitted, "
        "the domain part will be used to locate the KDC via DNS",
    )

    parser.add_argument(
        "-ts", action="store_true", help="Add timestamp to every logging output"
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    return parser


def main():
    """
    Main execution function.

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    print(version.BANNER)

    parser = build_parser()
    options = parser.parse_args()

    # Show help if no cli args provided
    if len(sys.argv) <= 1:
        parser.print_help()
        return 1

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    if not options.username and not options.usersfile:
        logging.critical("Either -u or -usersfile must be specified!")
        return 1

    if options.username and options.usersfile:
        logging.critical("Cannot specify both -u and -usersfile. Choose one.")
        return 1

    # Determine thread count
    if options.username:
        threads = 1  # Single user doesn't need threading
    else:
        if options.threads == "auto":
            threads = min(multiprocessing.cpu_count() * 2, 50)
        else:
            try:
                threads = int(options.threads)
                if threads < 1:
                    logging.critical("Thread count must be at least 1")
                    return 1
            except ValueError:
                logging.critical('Invalid thread count. Use a number or "auto"')
                return 1

    logging.info(
        "Using Kerberos AS-REQ messages without preauthentication data to determine if usernames exist."
    )
    print()

    try:
        if options.username:
            # Single user check
            check_single_user(options.username, options.domain, options.dc_ip)
        else:
            # Multiple users from file
            usernames = load_usernames(options.usersfile)
            if not usernames:
                return 1
            enumerate_users(
                usernames, options.domain, options.dc_ip, threads, options.output_file
            )

        return 0

    except KeyboardInterrupt:
        print("\n[!] User interrupted execution")
        return 1
    except Exception as e:
        if options.debug:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
