#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# ATSVC example for some functions implemented
#
# Author:
#  Alberto Solino (bethus@gmail.com)
#
# Reference for:
#  DCE/RPC for ATSVC

import socket
import string
import sys
import types

from impacket import uuid, ntlm
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, ndrutils, atsvc
from struct import unpack

class ATSVC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\atsvc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\atsvc]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = ''):
        if not protocols:
            protocols = ATSVC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols


    def play(self, addr):

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = ATSVC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password)

            try:
                entries = self.doStuff(rpctransport)
            except Exception, e:
                print 'Protocol failed: %s' % e
            else:
                # Got a response. No need for further iterations.
                break


    def doStuff(self, rpctransport):
        dce = dcerpc.DCERPC_v5(rpctransport)

        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_max_fragment_size(16)
        dce.bind(atsvc.MSRPC_UUID_ATSVC)
        at = atsvc.DCERPCAtSvc(dce)

        # Check [MS-TSCH] Section 2.3.4
        atInfo = atsvc.AT_INFO()
        atInfo['JobTime']            = 0
        atInfo['DaysOfMonth']        = 0
        atInfo['DaysOfWeek']         = 0
        atInfo['Flags']              = 0
        atInfo['Command']            = ndrutils.NDRUniqueStringW()
        atInfo['Command']['Data']    = ('calc.exe\x00').encode('utf-16le')

        # Remember to remove it on the target server ;)
        resp = at.NetrJobAdd(('\\\\%s'% rpctransport.get_dip()),atInfo)

        resp = at.NetrJobEnum(rpctransport.get_dip())

        # ToDo: Parse this struct.. Should be easy
        resp.dump()

        dce.disconnect()


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % ATSVC.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        dumper = ATSVC(sys.argv[2:], username, password)
    else:
        dumper = ATSVC(username = username, password = password)
    dumper.play(address)
