#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
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

from impacket import uuid, version
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, wkssvc
import argparse


class WKSSVCException(Exception):
    pass

class WKSSVCstuff:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\wkssvc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\wkssvc]', 445),
        }


    def __init__(self, username, password, domain, hashes=None, protocols= None):
        if not protocols:
            protocols = WKSSVCstuff.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def doStuff(self, addr):

        encoding = sys.getdefaultencoding()

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = WKSSVCstuff.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            rpctransport = transport.SMBTransport(addr, port, r'\wkssvc', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

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
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('protocol', choices=WKSSVCstuff.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    dumper = WKSSVCstuff(username, password, domain, options.hashes, options.protocol)
    dumper.doStuff(address)
