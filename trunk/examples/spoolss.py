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

from impacket import uuid, ntlm
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, printer
from struct import unpack

class SPOOLSS:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\spoolss]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\spoolss]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = ''):
        if not protocols:
            protocols = SPOOLSS.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols


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
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % SPOOLSS.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        dumper = SPOOLSS(sys.argv[2:], username, password)
    else:
        dumper = SPOOLSS(username = username, password = password)
    dumper.play(address)
