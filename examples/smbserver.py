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

from impacket import smbserver

server = smbserver.SimpleSMBServer()
server.addShare('MYSHARE', '/tmp', 'MyComment')

# If you don't want log to stdout, comment the following line
# If you want log dumped to a file, enter the filename
server.setLogFile('')

# Rock and roll
server.start()
