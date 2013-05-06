#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Simple SRVSVC DCERPC Server, to be used by the SMBServer
#
# Author:
#  Alberto Solino <beto@coresecurity.com>
#
from impacket.dcerpc import srvsvcserver

srv = srvsvcserver.SRVSVCServer()
srv.setListenPort(4344)
srv.processConfigFile('./smb.conf')
srv.run()
