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

from impacket import uuid, ntlm, version
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, lsarpc
import argparse

class LSALookupSid:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\lsarpc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\lsarpc]', 445),
        '135/TCP': (r'ncacn_ip_tcp:%s', 135),
        }

    def __init__(self, username, password, domain, protocols = None,
                 hashes = None, maxRid=4000):
        if not protocols:
            protocols = LSALookupSid.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__maxRid = int(maxRid)
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

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
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

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

        resp = rpc.LsarOpenPolicy2(rpctransport.get_dip(), access_mask=0x02000000)

        try:
          resp2 = rpc.LsarQueryInformationPolicy2(resp['ContextHandle'], lsarpc.POLICY_ACCOUNT_DOMAIN_INFORMATION)
          rootsid = resp2.formatDict()['sid'].formatCanonical()
        except Exception, e:
          print e 

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
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('maxRid', action='store', default = '4000', nargs='?', help='max Rid to check (default 4000)')
    parser.add_argument('protocol', choices=LSALookupSid.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')

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

    lookup = LSALookupSid(username, password, domain, options.protocol, options.hashes, options.maxRid)
    lookup.dump(address)
