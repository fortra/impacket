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
#   Mini shell using some of the SMB functionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.examples.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_21, SMB2_DIALECT_311
from impacket.smb import SMB_DIALECT

def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-inputfile', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
    parser.add_argument('-outputfile', action='store', help='Output file to log smbclient actions in')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-smb-version', choices=['1', '2', '3'], help='SMB version to negotiate')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.smb_version is not None:
        smb_versions = (
            (SMB_DIALECT, '1'),
            (SMB2_DIALECT_21, '2'),
            (SMB2_DIALECT_311, '3')
        )
        options.smb_version = [version[0] for version in smb_versions if version[1] == options.smb_version][0]

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port), preferredDialect=options.smb_version)
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        shell = MiniImpacketShell(smbClient, None, options.outputfile)

        if options.outputfile is not None:
            f = open(options.outputfile, 'a')
            f.write('=' * 20 + '\n' + options.target_ip + '\n' + '=' * 20 + '\n')
            f.close()

        if options.inputfile is not None:
            logging.info("Executing commands from %s" % options.inputfile.name)
            for line in options.inputfile.readlines():
                if line[0] != '#':
                    print("# %s" % line, end=' ')
                    shell.onecmd(line)
                else:
                    print(line, end=' ')
        else:
            shell.cmdloop()

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

if __name__ == "__main__":
    main()
