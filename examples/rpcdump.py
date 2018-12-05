#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
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

class RPCDump:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s',             'set_host': False},
        139: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]', 'set_host': True}
        }

    def __init__(self, username = '', password = '', domain='', hashes = None, port=135):

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__port = port
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):
        """Dumps the list of endpoints registered with the mapper
        listening at addr. remoteName is a valid host name or IP
        address in string format.
        """

        logging.info('Retrieving endpoint list from %s' % remoteName)

        entries = []

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception, e:
            logging.critical('Protocol failed: %s' % e)

        # Display results.

        endpoints = {}
        # Let's groups the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry['tower']['Floors'], rpctransport.getRemoteHost())
            tmpUUID = str(entry['tower']['Floors'][0])
            if endpoints.has_key(tmpUUID) is not True:
                endpoints[tmpUUID] = {}
                endpoints[tmpUUID]['Bindings'] = list()
            if epm.KNOWN_UUIDS.has_key(uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]):
                endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
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

    group = parser.add_argument_group('connection')

    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                       'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                       'name and you cannot resolve it')
    group.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='135', metavar="destination port",
                       help='Destination port to connect to SMB Server')

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
    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    dumper = RPCDump(username, password, domain, options.hashes, int(options.port))

    dumper.dump(remoteName, options.target_ip)
