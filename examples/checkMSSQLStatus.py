#!/usr/bin/env python3
# coding: utf-8
"""
mssql_cbt_check.py
Check whether Channel Binding Token (CBT) is enforced on a MSSQL server.

Usage:
    mssql_cbt_check.py [domain/]username[:password]@target [-port PORT] [-debug]

Writen by @Defte_
"""
from __future__ import print_function

import sys
import logging
import argparse
from getpass import getpass

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.tds import MSSQL, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF


class MSQLCBTCheck:
    def __init__(self, options, username, password, domain, target):
        self.username = username
        self.password = password
        self.domain = domain
        self.target = target
        self.port = int(options.port)
        self.options = options

    def _new_conn(self):
        conn = MSSQL(self.target, self.port, "")
        conn.connect()
        return conn

    def _login(self, conn, cbt):
        opts = self.options
        if opts.k:
            return conn.kerberosLogin(
                None,
                self.username,
                self.password,
                self.domain,
                opts.hashes,
                opts.aesKey,
                opts.dc_ip,
                None,
                None,
                useCache=True,
                cbt_fake_value=cbt,
            )
        else:
            return conn.login(
                None,
                self.username,
                self.password,
                self.domain,
                opts.hashes,
                useWindowsAuth=True,
                cbt_fake_value=cbt,
            )

    def run(self):
        print(f"[*] Checking Channel Binding status on: {self.target}:{self.port}")

        try:
            conn = self._new_conn()
            prelogin_resp = conn.preLogin()
            enc = prelogin_resp["Encryption"]
            if not enc == TDS_ENCRYPT_REQ and not enc == TDS_ENCRYPT_OFF:
                print("[!] Encryption not activated nor required. Channel Binding off.")
                conn.disconnect()
                return
        except Exception as e:
            logging.debug(f"preLogin failed: {e}")
            print("[-] Prelogin failed, cannot check MSSQL status.")
            return
        
        print("\n[*] First try: TDS computes the real Channel Binding Token (cbt=None)")
        try:
            conn = self._new_conn()
            first_ok = self._login(conn, cbt=None)
            conn.disconnect()
        except Exception as e:
            logging.debug(f"First try exception: {e}")
            first_ok = False
        print(f" Result: {'Success' if first_ok else 'Failure'}")

        print("\n[*] Second try: invalid Channel Binding Token (cbt='')")
        try:
            conn = self._new_conn()
            second_ok = self._login(conn, cbt=b'')
            conn.disconnect()
        except Exception as e:
            logging.debug(f"Second try exception: {e}")
            second_ok = False
        print(f" Result: {'Success' if second_ok else 'Failure'}")

        if first_ok and second_ok:
            print("\n[+] The two authentications succeded. Channel Binding not required (CBT not enforced).")
        elif first_ok and not second_ok:
            print("\n[!] First authentication succeded, second failed. Channel Binding required (CBT enforced).")
        elif not first_ok and not second_ok:
            print("\n[!] The two authentications failed, invalid credentials.")

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', default=1433, help='Port MSSQL (default: 1433)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output', dest='timestamp')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', metavar='LMHASH:NTHASH', help='NTLM hashes')
    group.add_argument('-no-pass', action='store_true', help="Don't ask for password (useful with -k)")
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication (ccache via KRB5CCNAME)')
    group.add_argument('-aesKey', metavar='hex key', help='AES key for Kerberos (128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', metavar='ip address', help='IP of the domain controller')
    group.add_argument('-target-ip', metavar='ip address', help='IP of the target (overrides target name resolution)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.timestamp, options.debug)

    domain, username, password, target = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.target_ip:
        target = options.target_ip

    if options.aesKey:
        options.k = True

    if password == '' and username != '' and not options.hashes and not options.no_pass and not options.aesKey:
        password = getpass("Password: ")

    try:
        MSQLCBTCheck(options, username, password, domain, target).run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
