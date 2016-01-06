#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Simple SMB Server example.
#
# Author:
#  Alberto Solino (@agsolino)
#

import sys
import argparse
import logging

from impacket.examples import logger
from impacket import smbserver, version

if __name__ == '__main__':

    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "This script will launch a SMB Server and add a share specified as an argument. You need to be root in order to bind to port 445. No authentication will be enforced. Example: smbserver.py -comment 'My share' TMP /tmp")

    parser.add_argument('shareName', action='store', help='name of the share to add')
    parser.add_argument('sharePath', action='store', help='path of the share to add')
    parser.add_argument('-comment', action='store', help='share\'s comment to display when asked for shares')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception, e:
       logging.critical(str(e))
       sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.comment is None:
        comment = ''
    else:
        comment = options.comment

    server = smbserver.SimpleSMBServer()

    server.addShare(options.shareName.upper(), options.sharePath, comment)
    server.setSMB2Support(options.smb2support)
   
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

