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
#   Utility for viewing and setting Windows file ACLs. It allows you to add or
#   delete permissions for users or groups, much like the Windows icacls
#   binary or the Samba smbcacls tool.
#
# Author:
#   Gefen Altshuler (@gaffner)
#

from __future__ import division
from __future__ import print_function
import argparse
import sys
import logging

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.acl import SMBFileACL


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description="Utility for viewing and setting Windows file ACLs. It allows you to add or "
                                                 "delete permissions for users or groups, much like the Windows icacls "
                                                 "binary or the Samba smbcacls tool.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-share', action='store', help='share name to connect to', required=True)
    parser.add_argument('-file-path', action='store', help='file path to view or change permissions', required=True)
    parser.add_argument('-target-user', action='store', help='target user/group to change permissions for (empty for viewing)',
                        default=None)
    parser.add_argument('-action', action='store', choices=['grant', 'revoke', 'delete'],
                        help='Action to perform: grant (add permissions), revoke (remove permissions), '
                             'delete (remove entire ACE)')
    parser.add_argument('-permissions', action='store', 
                        help='Permissions in the format of <permission char>,<permission char>. '
                             'Example: R,W (required for grant/revoke actions).\n'
                             'Supported Permissions:\n'
                             '  R - Read\n'
                             '  W - Write\n'
                             '  X - Execute\n'
                             '  D - Delete\n'
                             '  F - Full Control',
                        default=None)
    parser.add_argument('-ts', action='store_true', help='\nadds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                        'cannot be found, it will use the ones specified in the command '
                                                        'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                           '(128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) '
                            'specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv) == 1:
        parser.print_help()
        print("\nExamples:")
        print("\tView the permissions of a file")
        print("\t  python smbcacls.py -share MyShare -file-path MyFile.txt domain.net/user:password@192.168.1.10\n")
        print("\tGrant read and write permissions to the user Guest")
        print("\t  python smbcacls.py -share MyShare -file-path MyFile.txt -target-user Guest -action grant -permissions R,W domain.net/user:password@192.168.1.10\n")
        print("\tRevoke write permission from the user Guest")
        print("\t  python smbcacls.py -share MyShare -file-path MyFile.txt -target-user Guest -action revoke -permissions W domain.net/user:password@192.168.1.10\n")
        print("\tDelete all permissions from the user Guest (remove ACE)")
        print("\t  python smbcacls.py -share MyShare -file-path MyFile.txt -target-user Guest -action delete domain.net/user:password@192.168.1.10\n")
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    if options.debug:
        logging.getLogger('impacket').setLevel(logging.DEBUG)
    else:
        logging.getLogger('impacket').setLevel(logging.INFO)

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
        file_acl = SMBFileACL(options.target_ip, address, username, password, domain, lmhash, nthash,
                              options.aesKey, options.k, options.dc_ip)

        # Modification operation
        if options.target_user:
            # Validate action is specified
            if not options.action:
                logging.error('Action (-action) is required when modifying permissions for a user/group')
                sys.exit(1)
            
            # Validate permissions are provided for actions that need them
            if options.action in ['grant', 'revoke'] and not options.permissions:
                logging.error(f'Permissions (-permissions) are required for action: {options.action}')
                sys.exit(1)
            
            # Warn if permissions are provided for delete action (they will be ignored)
            if options.action == 'delete' and options.permissions:
                logging.warning('Permissions specified for delete action will be ignored')
            
            logging.info('Performing %s action for user/group "%s" on %s', options.action, options.target_user, options.file_path)
            file_acl.set_permissions(options.share, options.file_path, options.target_user, options.permissions, options.action)
            logging.info('Successfully processed %s', options.file_path)
        # Query operation
        else:
            logging.info('Querying permissions on %s', options.file_path)
            print(file_acl.get_permissions(options.share, options.file_path))

        file_acl.close_connection()

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
