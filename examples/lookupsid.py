#!/usr/bin/python
# Copyright (c) 2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# DCE/RPC lookup sid example
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

from impacket import uuid, ntlm
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, lsarpc

class LSALookupSid:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\lsarpc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\lsarpc]', 445),
        '135/TCP': (r'ncacn_ip_tcp:%s', 135),
        }


    def __init__(self, protocols = None,
                 username = '', password = ''):
        if not protocols:
            protocols = RPCDump.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols


    def dump(self, addr):

        print 'Brute forcing SIDs from %s' % addr

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = LSALookupSid.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password)

            try:
                entries = self.__fetchList(rpctransport)
            except Exception, e:
                print 'Protocol failed: %s' % str(e)
                raise
            else:
                # Got a response. No need for further iterations.
                break


        # Display results.


    def __fetchList(self, rpctransport):
        # UDP only works over DCE/RPC version 4.
        if isinstance(rpctransport, transport.UDPTransport):
            dce = dcerpc_v4.DCERPC_v4(rpctransport)
        else:
            dce = dcerpc.DCERPC_v5(rpctransport)

        entries = []
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_max_fragment_size(1)
        dce.bind(lsarpc.MSRPC_UUID_LSARPC)
        rpc = lsarpc.DCERPCLsarpc(dce)

        resp = rpc.LsarOpenPolicy2(rpctransport.get_dip())

        try:
          resp2 = rpc.LsarQueryInformationPolicy2(resp['ContextHandle'], lsarpc.POLICY_ACCOUNT_DOMAIN_INFORMATION)
          print "%s - %s" % (resp2.formatDict()['name'], resp2.formatDict()['sid'].formatCanonical())
        except Exception, e:
          print e 
          raise

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % LSALookupSid.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        lookup = LSALookupSid(sys.argv[2:], username, password)
    else:
        lookup = LSALookupSid(username = username, password = password)
    lookup.dump(address)
