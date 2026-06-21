#!/usr/bin/env python3
#
# Description:
#   Implementation of ldap_shell.py, an interactive ldap client. 
#
# Author:
#   Andreas Vikerup (@vikerup)
#

import argparse
import atexit
import logging
import sys
from getpass import getpass
from pathlib import Path

from impacket import version
from impacket.examples import logger
from impacket.examples.ldap_shell import LdapShell
from impacket.examples.utils import EMPTY_LM_HASH, init_ldap_session, parse_target
import ldapdomaindump
from ldapdomaindump import reportWriter as _ReportWriter


class FakeShell:
    def __init__(self):
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self._readline = None
        self._history_file = None
        self._init_line_editing()

    def _init_line_editing(self):
        if not self.stdin.isatty():
            return

        try:
            import readline
        except ImportError:
            return

        self._readline = readline
        history_path = Path.home() / '.impacket_ldap_shell_history'

        try:
            readline.read_history_file(str(history_path))
        except (FileNotFoundError, OSError):
            pass

        readline.parse_and_bind('set editing-mode emacs')
        readline.parse_and_bind('set enable-meta-key on')
        readline.parse_and_bind('tab: complete')

        self._history_file = history_path
        atexit.register(self._persist_history)

    def _persist_history(self):
        if self._readline is None or self._history_file is None:
            return
        try:
            self._readline.write_history_file(str(self._history_file))
        except OSError:
            pass

    def close(self):
        self._persist_history()


def _ensure_safe_report_writer():
    if getattr(_ReportWriter, '_impacket_safe_patch', False):
        return

    def safe_format_string(self, value):
        from datetime import datetime

        if isinstance(value, datetime):
            try:
                return value.strftime('%x %X')
            except ValueError:
                return '0'
        if isinstance(value, (bytes, bytearray)):
            return value.decode('utf-8', errors='ignore')
        if isinstance(value, str):
            return value
        if isinstance(value, int):
            return str(value)
        if value is None:
            return ''
        return str(value)

    def safe_html_escape(self, html):
        if isinstance(html, (bytes, bytearray)):
            html = html.decode('utf-8', errors='ignore')
        elif not isinstance(html, str):
            html = str(html)
        return (html.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("'", "&#39;")
                    .replace('"', "&quot;"))

    _ReportWriter.formatString = safe_format_string
    _ReportWriter.htmlescape = safe_html_escape
    _ReportWriter._impacket_safe_patch = True


class DomainDumper:
    def __init__(self, ldap_server, ldap_session, base_path, root):
        _ensure_safe_report_writer()
        config = ldapdomaindump.domainDumpConfig()
        if base_path is not None:
            config.basepath = base_path
        self._dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, config, root)

    def domainDump(self):
        self._dumper.domainDump()

    @property
    def root(self):
        return self._dumper.root

    @root.setter
    def root(self, value):
        self._dumper.root = value


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description='Interactive LDAP shell using impacket\'s helpers')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<target>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    auth_group = parser.add_argument_group('authentication')
    auth_group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    auth_group.add_argument('-no-pass', action='store_true', help="don't ask for password (useful for -k)")
    auth_group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                           '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                           'cannot be found, it will use the ones specified in the command '
                                                           'line')
    auth_group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication '
                                                                              '(128 or 256 bits)')

    conn_group = parser.add_argument_group('connection')
    conn_group.add_argument('-dc-ip', action='store', metavar='ip address',
                            help='IP Address or hostname of the domain controller (KDC) for Kerberos. If omitted it will '
                                 'use the target portion of the connection string')
    conn_group.add_argument('-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    conn_group.add_argument('-dump-dir', action='store', metavar='path', default='.',
                            help='Directory where domain dump files will be stored (default: current directory)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts, options.debug)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''
    if username is None:
        username = ''
    if password is None:
        password = ''

    dc_ip = options.dc_ip
    dc_host = None
    if options.k:
        if dc_ip is None and address is not None:
            dc_host = address
    else:
        if dc_ip is None and address is not None:
            dc_ip = address

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        password = getpass('Password:')

    if options.aesKey is not None:
        options.k = True

    if options.no_pass:
        password = ''

    if options.hashes is not None:
        try:
            lmhash, nthash = options.hashes.split(':')
        except ValueError:
            logging.error('Hashes must be supplied in LMHASH:NTHASH format')
            sys.exit(1)
        if lmhash == '':
            lmhash = EMPTY_LM_HASH
    else:
        lmhash = ''
        nthash = ''

    console = None
    try:
        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, options.k,
                                                      dc_ip, dc_host, options.aesKey, options.ldaps)
        server_info = ldap_session.server.info if ldap_session else None
        root_dn = None
        if server_info is not None:
            other = server_info.other or {}
            default_nc = other.get('defaultNamingContext')
            if default_nc:
                root_dn = default_nc[0]

        if root_dn is None:
            logging.error('Could not determine defaultNamingContext from the LDAP server')
            sys.exit(1)

        console = FakeShell()
        domain_dumper = DomainDumper(ldap_server, ldap_session, options.dump_dir, root_dn)
        shell = LdapShell(console, domain_dumper, ldap_session)
        shell.use_rawinput = True
        shell.cmdloop()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
    finally:
        if console is not None:
            console.close()

if __name__ == "__main__":
    main()
