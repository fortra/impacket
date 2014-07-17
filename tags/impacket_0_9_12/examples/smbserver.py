#!/usr/bin/python
# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Simple SMB Server example.
#
# Author:
#  Alberto Solino <beto@coresecurity.com>
#

import sys
import argparse
from impacket import smbserver, version

if __name__ == '__main__':

    print version.BANNER

    parser = argparse.ArgumentParser(add_help = False, description = "This script will launch a SMB Server and add a share specified as an argument. You need to be root in order to bind to port 445. No authentication will be enforced. Example: smbserver.py -comment 'My share' TMP /tmp")

    parser.add_argument('shareName', action='store', help='name of the share to add')
    parser.add_argument('sharePath', action='store', help='path of the share to add')
    parser.add_argument('-comment', action='store', help='share\'s comment to display when asked for shares')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception, e:
       print e
       sys.exit(1)

    if options.comment is None:
        comment = ''
    else:
        comment = options.comment

    server = smbserver.SimpleSMBServer()

    server.addShare(options.shareName.upper(), options.sharePath, comment)

    # If you don't want log to stdout, comment the following line
    # If you want log dumped to a file, enter the filename
    server.setLogFile('')

    # Rock and roll
    server.start()

