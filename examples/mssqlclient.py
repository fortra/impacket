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
#   [MS-TDS] & [MC-SQLR] example.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure
#

import argparse
import sys
import logging

from impacket.examples import logger
from impacket.examples.mssqlshell import SQLSHELL
from impacket.examples.utils import parse_target
from impacket import version, tds


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default=False, help='whether or not to use Windows '
                                                                                  'Authentication (default False)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-show', action='store_true', help='show the queries')
    parser.add_argument('-command', action='extend', nargs='*', help='Commands to execute in the SQL shell. Multiple commands can be passed.')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the SQL shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar = "ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    ms_sql = tds.MSSQL(options.target_ip, int(options.port), remoteName)
    ms_sql.connect()
    try:
        if options.k is True:
            res = ms_sql.kerberosLogin(options.db, username, password, domain, options.hashes, options.aesKey,
                                       kdcHost=options.dc_ip)
        else:
            res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
        ms_sql.printReplies()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))
        res = False
    if res is True:
        shell = SQLSHELL(ms_sql, options.show)
        if options.file:
            for line in options.file.readlines():
                print("SQL> %s" % line, end=' ')
                shell.onecmd(line)
        elif options.command:
            for c in options.command:
                print("SQL> %s" % c)
                shell.onecmd(c)
        else:
            shell.cmdloop()
    ms_sql.disconnect()
