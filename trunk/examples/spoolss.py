#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# SPOOLSS example for some functions implemented
#
# Author:
#  Alberto Solino (bethus@gmail.com)
#
# Reference for:
#  DCE/RPC for SPOOLSS

import socket
import string
import sys
import types

from impacket import uuid, ntlm, version
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, printer
from struct import unpack

import argparse

class SPOOLSS:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\spoolss]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\spoolss]', 445),
        }


    def __init__(self, username, password, domain, hashes, protocols):
        if not protocols:
            protocols = SPOOLSS.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = SPOOLSS.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

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
        dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_max_fragment_size(16)
        dce.bind(printer.MSRPC_UUID_SPOOLSS)
        rpcspool = printer.PrintSpooler(dce)
        resp = rpcspool.enumPrinters('\x00',0x2, level=1)
        data = resp['PrinterEnum']
        index = 0 
        for i in range(resp['cReturned']):
            # skip the flags
            flags = unpack('<L',data[index:index+4])[0]
            index += 4
            description = unpack('<L',data[index:index+4])[0]
            index += 4
            name = unpack('<L',data[index:index+4])[0]
            index += 4
            comment = unpack('<L',data[index:index+4])[0]
            index += 4
            # Yes.. still don't know why.. offsets are 0x10*i away from the actual data
            description = data[(description+16*i):].split('\x00\x00')[0]
            name = data[(name+16*i):].split('\x00\x00')[0]
            comment = data[(comment+16*i):].split('\x00\x00')[0]
            print "flags: 0x%x\nname:[%s]\ndescription:[%s]\ncomment:[%s]\n" %(flags,name,description,comment)
            
        #resp = rpcspool.enumPorts()
        #resp.dump()

        dce.disconnect()


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('protocol', choices=SPOOLSS.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if domain is None:
        domain = ''

    dumper = SPOOLSS(username, password, domain, options.hashes, options.protocol)
    dumper.play(address)
