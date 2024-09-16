#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2024 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script allows you to clear specific windows eventlog channel on a remote host.
#
# Author:
#   Alex Romero (@NtAlexio2)
#
# Reference for:
#   [MS-EVEN6]
#
# ToDo:
#   [ ] add more features and other requests
# 

import sys
import logging
import argparse
import logging
from impacket import version
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5 import even6
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY

class Eventlog:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                 channelName=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__channelName = channelName

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def clear(self, addr):
        stringbinding = self.__get_endpoint(addr)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.__do_clear(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

    def __get_endpoint(self, target):
        return hept_map(target, even6.MSRPC_UUID_EVEN6, protocol='ncacn_ip_tcp')

    def __do_clear(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(even6.MSRPC_UUID_EVEN6)

        resp = even6.hEvtRpcRegisterControllableOperation(dce)
        logging.info("EvtRpcRegisterControllableOperation - OK")

        even6.hEvtRpcClearLog(dce, resp['Handle'], self.__channelName)
        logging.info("EvtRpcClearLog - OK")

        even6.hEvtRpcClose(dce, resp['Handle'])
        logging.info("EvtRpcClose - OK")



# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-clear', action='store', type=str, metavar="CHANNEL", help='clears event records of given channel (example: Security)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. '
                                         'If omitted it will use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    channel_name = options.clear
    eventlog = Eventlog(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                           channel_name)
    eventlog.clear(address)
