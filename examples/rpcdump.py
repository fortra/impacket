#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# DCE/RPC endpoint mapper dumper.
#
# Author:
#  Javier Kohen <jkohen@coresecurity.com>
#  Alberto Solino <beto@coresecurity.com>
#
# Reference for:
#  DCE/RPC.

import sys
import logging
import argparse

from impacket.examples import logger
from impacket import uuid, version
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc import  ndrutils


class RPCDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\epmapper]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\epmapper]', 445),
        '135/TCP': (r'ncacn_ip_tcp:%s', 135),
        }


    def __init__(self, protocols = None,
                 username = '', password = '', domain='', hashes = None):
        if not protocols:
            protocols = RPCDump.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, addr):
        """Dumps the list of endpoints registered with the mapper
        listening at addr. Addr is a valid host name or IP address in
        string format.
        """

        logging.info('Retrieving endpoint list from %s' % addr)

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = RPCDump.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            logging.info("Trying protocol %s..." % protocol)
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

            try:
                entries = self.__fetchList(rpctransport)
            except Exception, e:
                logging.critical('Protocol failed: %s' % e)
            else:
                # Got a response. No need for further iterations.
                break


        # Display results.

        endpoints = {}
        # Let's groups the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry['tower']['Floors'], rpctransport.get_dip())
            tmpUUID = str(entry['tower']['Floors'][0])
            if endpoints.has_key(tmpUUID) is not True:
                endpoints[tmpUUID] = {}
                endpoints[tmpUUID]['Bindings'] = list()
            if ndrutils.KNOWN_UUIDS.has_key(uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]):
                endpoints[tmpUUID]['EXE'] = ndrutils.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
            else:
                endpoints[tmpUUID]['EXE'] = 'N/A'
            endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1]
            endpoints[tmpUUID]['Bindings'].append(binding)

            if epm.KNOWN_PROTOCOLS.has_key(tmpUUID[:36]):
                endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
            else:
                endpoints[tmpUUID]['Protocol'] = "N/A"
            #print "Transfer Syntax: %s" % entry['Tower']['Floors'][1]
     
        for endpoint in endpoints.keys():
            print "Protocol: %s " % endpoints[endpoint]['Protocol']
            print "Provider: %s " % endpoints[endpoint]['EXE']
            print "UUID    : %s %s" % (endpoint, endpoints[endpoint]['annotation'])
            print "Bindings: "
            for binding in endpoints[endpoint]['Bindings']:
                print "          %s" % binding
            print ""

        if entries:
            num = len(entries)
            if 1 == num:
                logging.info('Received one endpoint.')
            else:
                logging.info('Received %d endpoints.' % num)
        else:
            logging.info('No endpoints found.')


    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        #dce.bind(epm.MSRPC_UUID_PORTMAP)
        #rpcepm = epm.DCERPCEpm(dce)

        resp = epm.hept_lookup(None, dce=dce)

        dce.disconnect()

        return resp


# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Dumps the remote RPC enpoints information.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('protocol', choices=RPCDump.KNOWN_PROTOCOLS.keys(), nargs='?', default='135/TCP', help='transport protocol (default 135/TCP)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    dumper = RPCDump(options.protocol, username, password, domain, options.hashes)

    dumper.dump(address)
