#!/usr/bin/python
# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: DCE/RPC WKSSVC examples, playing with the functions Implemented
#
# Author:
#  Alberto Solino 
#
# Reference for:
#  DCE/RPC.

import socket
import string
import sys
import types

from impacket import uuid
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, wkssvc


class WKSSVCException(Exception):
    pass

class WKSSVCstuff:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\wkssvc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\wkssvc]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = ''):
        if not protocols:
            protocols = WKSSVCstuff.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols


    def doStuff(self, addr):

        encoding = sys.getdefaultencoding()

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = WKSSVCstuff.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            rpctransport = transport.SMBTransport(addr, port, r'\wkssvc', self.__username, self.__password)

            try:
                entries = self.__fetchData(rpctransport)
            except Exception, e:
                print 'Protocol failed: %s' % e
                raise
            else:
                # Got a response. No need for further iterations.
                break


    def __fetchData(self, rpctransport):
        dce = dcerpc.DCERPC_v5(rpctransport)

        encoding = sys.getdefaultencoding()
        entries = []

        dce.connect()
        dce.bind(wkssvc.MSRPC_UUID_WKSSVC)
        wkssvc_dce = wkssvc.DCERPCWksSvc(dce)

        try:
            print 'Retrieving mac address for %s' % rpctransport.get_dip()
            resp = wkssvc_dce.NetrWkstaTransportEnum(rpctransport.get_dip())
            for i in range(resp['Count']):
                print 'TransportName: %s' % resp['Array'][i]['TransportName']['Data'].decode('utf-16le')
                print 'TransportAddress: %s' % resp['Array'][i]['TransportAddress']['Data'].decode('utf-16le')
        except WKSSVCException, e:
            print "Error: %s" % e

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % WKSSVCstuff.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        dumper = WKSSVCstuff(sys.argv[2:], username, password)
    else:
        dumper = WKSSVCstuff(username = username, password = password)
    dumper.doStuff(address)
