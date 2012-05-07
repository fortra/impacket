#!/usr/bin/python
# Copyright (c) 2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# DCE/RPC lookup sid brute forcer example
#
# Author:
#  Alberto Solino
#
# Reference for:
#  DCE/RPC LSARPC

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
                 username = '', password = '', maxRid = 4000):
        if not protocols:
            protocols = LSALookupSid.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols
        self.__maxRid = int(maxRid)


    def dump(self, addr):

        print 'Brute forcing SIDs at %s' % addr

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
                entries = self.__bruteForce(rpctransport, self.__maxRid)
            except Exception, e:
                print 'Protocol failed: %s' % str(e)
                raise
            else:
                # Got a response. No need for further iterations.
                break

    def __bruteForce(self, rpctransport, maxRid):
        # UDP only works over DCE/RPC version 4.
        if isinstance(rpctransport, transport.UDPTransport):
            dce = dcerpc_v4.DCERPC_v4(rpctransport)
        else:
            dce = dcerpc.DCERPC_v5(rpctransport)

        entries = []
        dce.connect()

        # Want encryption? Uncomment next line
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        #dce.set_max_fragment_size(32)

        dce.bind(lsarpc.MSRPC_UUID_LSARPC)
        rpc = lsarpc.DCERPCLsarpc(dce)

        resp = rpc.LsarOpenPolicy2(rpctransport.get_dip())

        try:
          resp2 = rpc.LsarQueryInformationPolicy2(resp['ContextHandle'], lsarpc.POLICY_ACCOUNT_DOMAIN_INFORMATION)
          rootsid = resp2.formatDict()['sid'].formatCanonical()
        except Exception, e:
          print e 
        l = []

        for i in range(500,maxRid):
            res = rpc.LsarLookupSids(resp['ContextHandle'], [rootsid + '-%d' % i])
            # If SOME_NOT_MAPPED or SUCCESS, let's extract data
            if res['ErrorCode'] == 0: 
                item =  res.formatDict()
                print "%d: %s\\%s (%d)" % (i, item[0]['domain'], item[0]['names'][0], item[0]['types'][0])

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 2:
        print "Usage: %s [username[:password]@]<address> <maxRid> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % LSALookupSid.KNOWN_PROTOCOLS.keys()
        print "<maxRid>: Max Rid to check (starts at 500)"
        print "Username and password are only required for certain transports, eg. SMB."
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        lookup = LSALookupSid(sys.argv[3:], username, password, sys.argv[2])
    else:
        lookup = LSALookupSid(username = username, password = password, maxRid = sys.argv[2])

    lookup.dump(address)
