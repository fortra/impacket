#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Simple SMB Server example.
#
# Author:
#   Alberto Solino (@agsolino)
#

import sys
import argparse
import logging

from impacket.examples import logger
from impacket import smbserver, version
from impacket.ntlm import compute_lmhash, compute_nthash

if __name__ == '__main__':

    # Init the example's logger theme
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "This script will launch a SMB Server and add a "
                                     "share specified as an argument. You need to be root in order to bind to port 445. "
                                     "For optional authentication, it is possible to specify username and password or the NTLM hash. "
                                     "Example: smbserver.py -comment 'My share' TMP /tmp")

    parser.add_argument('shareName', action='store', help='name of the share to add')
    parser.add_argument('sharePath', action='store', help='path of the share to add')
    parser.add_argument('-comment', action='store', help='share\'s comment to display when asked for shares')
    parser.add_argument('-username', action="store", help='Username to authenticate clients')
    parser.add_argument('-password', action="store", help='Password for the Username')
    parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes for the Username, format is LMHASH:NTHASH')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ip', '--interface-address', action='store', default='0.0.0.0', help='ip address of listening interface')
    parser.add_argument('-port', action='store', default='445', help='TCP port for listening incoming connections (default 445)')
    parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.critical(str(e))
       sys.exit(1)

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.comment is None:
        comment = ''
    else:
        comment = options.comment

    server = smbserver.SimpleSMBServer(listenAddress=options.interface_address, listenPort=int(options.port))

    server.addShare(options.shareName.upper(), options.sharePath, comment)
    server.setSMB2Support(options.smb2support)

    # If a user was specified, let's add it to the credentials for the SMBServer. If no user is specified, anonymous
    # connections will be allowed
    if options.username is not None:
        # we either need a password or hashes, if not, ask
        if options.password is None and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")
            # Let's convert to hashes
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
        elif options.password is not None:
            lmhash = compute_lmhash(options.password)
            nthash = compute_nthash(options.password)
        else:
            lmhash, nthash = options.hashes.split(':')

        server.addCredential(options.username, 0, lmhash, nthash)

    # Here you can set a custom SMB challenge in hex format
    # If empty defaults to '4141414141414141'
    # (remember: must be 16 hex bytes long)
    # e.g. server.setSMBChallenge('12345678abcdef00')
    server.setSMBChallenge('')

    # If you don't want log to stdout, comment the following line
    # If you want log dumped to a file, enter the filename
    server.setLogFile('')

    # Rock and roll
    server.start()
