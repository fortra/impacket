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
import io
import sys
import logging
import argparse
import random
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.examples.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection


def list_shares(smbClient):
    try:
        shares = smbClient.listShares()
        return [
            share['shi1_netname'][:-1].strip() for share in shares
        ]
    except Exception as e:
        logging.error("Failed to list shares: %s" % str(e))
        return []


def check_share_permissions(smbClient, share_name, no_write_check=False):
    result = {"share": share_name, "READ": None, "WRITE": None, "DELETE": None}

    try:
        # Read access test
        logging.debug("Trying to connect to '%s'" % share_name)
        smbClient.connectTree(share_name)
        result["READ"] = True

        if not no_write_check:
            try:
                # Write access test
                test_file = ".tmp%d" % random.randint(0, 0xFFFFFFFF)
                logging.debug("Trying to create a test file '%s'" % test_file)
                smbClient.putFile(share_name, test_file, io.BytesIO(b'TESTDATA').read)
                result["WRITE"] = True
                logging.debug("Successfully created a test file '%s'" % test_file)

                try:
                    # Delete access test
                    logging.debug("Trying to delete the test file '%s'" % test_file)
                    smbClient.deleteFile(share_name, test_file)
                    result["DELETE"] = True
                    logging.debug("Successfully deleted the test file '%s'" % test_file)
                except Exception as e:
                    result["DELETE"] = False
                    logging.debug("Failed to perform delete check for share '%s': %s" % (share_name, str(e)))
                    logging.error("Failed to delete test file '%s'" % test_file)

            except Exception as e:
                result["WRITE"] = False
                logging.debug("Failed to perform write check for share '%s': %s" % (share_name, str(e)))

    except Exception as e:
        result["READ"] = False
        logging.debug("Failed to access share '%s': %s" % (share_name, str(e)))

    return result

def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-inputfile', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
    parser.add_argument('-outputfile', action='store', help='Output file to log smbclient actions in')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-check-access', nargs='?', const='ALL', metavar='SHARE[,SHARE...]', help='Check permissions for specified shares (use ALL for all shares)')
    parser.add_argument('-no-write-check', action='store_true', help='Skip write/delete permission checks')

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
    logger.init(options.ts, options.debug)

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

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        if options.check_access:
            if options.check_access.upper() == 'ALL':
                logging.debug("Listing all shares")
                shares = list_shares(smbClient)
            else:
                shares = [share.strip() for share in options.check_access.split(',')]

            logging.debug("Shares to check: %s" % ','.join(shares))

            for share_name in shares:
                access = check_share_permissions(smbClient, share_name, options.no_write_check)
                logging.info(
                    "Share '%s' (%s)" % (
                        share_name,
                        ", ".join(
                            "%s: %s" % (key, value)
                            for key, value in access.items()
                            if key != 'share' and value is not None
                        )
                    )
                )

            sys.exit(0)

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
