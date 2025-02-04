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
from impacket.examples.utils import parse_credentials, parse_target
from impacket import version, tds


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default=False, help='whether or not to use Windows '
                                                                                  'Authentication (default False)')
    parser.add_argument('-named-pipe', action='store', default=False, help='Connect to the specified SMB named pipe')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-show', action='store_true', help='show the queries')
    parser.add_argument('-command', action='extend', nargs='*', help='Commands to execute in the SQL shell. Multiple commands can be passed.')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the SQL shell')

    parser.add_argument('--host-name', action='store', default='', help='HostName property to use when connecting to the MSSQLServer')
    parser.add_argument('--app-name', action='store', default='', help='AppName property to use when connecting to the MSSQLServer')
    parser.add_argument('--client-interface-name', action='store', default='', help='CltIntName property to use when connecting to the MSSQLServer')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-auth-smb', action="store", metavar='[domain/]username[:password]',
                       help='SMB NTLM credentials for named pipe transport when different from SQL credentials. '
                            'With -windows-auth or -k over a named pipe, this Windows identity becomes the '
                            'effective SQL login')
    group.add_argument('-hashes-smb', action="store", metavar="LMHASH:NTHASH",
                       help='SMB NTLM hashes for named pipe transport, format is LMHASH:NTHASH')
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

    group = parser.add_argument_group('SOCKS Proxy Options')
    group.add_argument('-socks', action='store_true', default=False,
                        help='Use a SOCKS proxy for the connection')
    group.add_argument('-socks-address', default='127.0.0.1', help='SOCKS5 server address')
    group.add_argument('-socks-port', default=1080, type=int, help='SOCKS5 server port')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    # Relay connections through a socks proxy
    if (options.socks):
        logging.info('Relaying connections through SOCKS proxy (%s:%s)', options.socks_address, options.socks_port)
        import socket
        import socks

        socks.set_default_proxy(socks.SOCKS5, options.socks_address, options.socks_port)
        socket.socket = socks.socksocket

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

    if options.named_pipe and options.auth_smb is not None and (options.windows_auth or options.k):
        logging.warning(
            "SQL Server uses the SMB-authenticated Windows identity for Windows authentication over named pipes. "
            "The identity supplied in the target may not become the effective SQL login."
        )

    smb_domain = None
    smb_username = None
    smb_password = None
    if options.auth_smb is not None:
        smb_domain, smb_username, smb_password = parse_credentials(options.auth_smb)
        if smb_domain is None:
            smb_domain = ''
        if smb_password == '' and smb_username != '' and options.hashes_smb is None and options.no_pass is False:
            from getpass import getpass
            smb_password = getpass("SMB Password:")

    ms_sql = tds.MSSQL(
        options.target_ip,
        port=int(options.port),
        remoteName=remoteName,
        remoteHost=options.target_ip,
        pipe_name=options.named_pipe,
        workstation_id=options.host_name,
        application_name=options.app_name,
        client_interface_name=options.client_interface_name
    )

    ms_sql.connect()
    try:
        if options.k is True:
            res = ms_sql.kerberosLogin(
                options.db,
                username,
                password,
                domain,
                options.hashes,
                options.aesKey,
                kdcHost=options.dc_ip,
                smbUsername=smb_username,
                smbPassword=smb_password,
                smbDomain=smb_domain,
                smbHashes=options.hashes_smb,
            )
        else:
            res = ms_sql.login(
                options.db, username, password, domain, options.hashes, options.windows_auth,
                smbUsername=smb_username, smbPassword=smb_password, smbDomain=smb_domain, smbHashes=options.hashes_smb
            )
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
