#!/usr/bin/python
# Copyright (c) 2003-2011 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id: sniff.py 17 2003-10-27 17:36:57Z jkohen $
#
# Simple SMB Server, check smb.conf for details
#
# Author:
#  Alberto Solino <beto@coresecurity.com>
#

from impacket import smbserver

server = smbserver.SMBSERVER(('0.0.0.0',445))
server.processConfigFile('smb.conf')
server.serve_forever()
