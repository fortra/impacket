#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   DCE/RPC targeted lookup name or SID example
#
# Author:
#   @snovvcrash
#
# Reference for:
#   DCE/RPC [MS-LSAT]
#

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
from pathlib import Path

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, lsad, lsat
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED


class LsaLookupNames:

    KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
    }

    def __init__(self, domain='', username='', password='', hashes=None, port=None):
        self.__domain = domain
        self.__username = username
        self.__password = password

        self.__lmhash = self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

        self.__port = port
        self.__dce = None

    def connect(self, remoteName, remoteHost):
        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        self.__dce = rpctransport.get_dce_rpc()
        self.__dce.connect()
        self.__dce.bind(lsat.MSRPC_UUID_LSAT)

    def resolve(self, remoteName, remoteHost, usernames):
        self.connect(remoteName, remoteHost)
        for name in usernames:
            try:
                if name.startswith('S-1-5-21-'):
                    username = self.lookupSid(name)
                    logging.info('{0}: {1}'.format(name, username))
                else:
                    userSid = self.lookupName(name)
                    logging.info('{0}: {1}'.format(name, userSid.formatCanonical()))
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if 'STATUS_NONE_MAPPED' in str(e):
                    logging.error('Name or SID not found: {0}'.format(name))
                else:
                    logging.error('{0}: {1}'.format(name, str(e)))

        self.__dce.disconnect()

    def lookupName(self, name):
        policyHandle = lsad.hLsarOpenPolicy2(self.__dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)['PolicyHandle']
        resp = lsat.hLsarLookupNames3(self.__dce, policyHandle, (name,))
        lsad.hLsarClose(self.__dce, policyHandle)
        return resp['TranslatedSids']['Sids'][0]['Sid']

    def lookupSid(self, sid):
        policyHandle = lsad.hLsarOpenPolicy2(self.__dce)['PolicyHandle']
        resp = lsat.hLsarLookupSids2(self.__dce, policyHandle, (sid,))
        lsad.hLsarClose(self.__dce, policyHandle)
        return resp['TranslatedNames']['Names'][0]['Name']


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser()
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('usernames', action='store', nargs='+', help='Username(s) or SID(s) to resolve (can also be a file path)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password (useful when proxying through ntlmrelayx)')

    group = parser.add_argument_group('connection')
    group.add_argument('-target-ip', action='store', metavar='IP_ADDRESS',
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar='destination port',
                       help='Destination port to connect to SMB Server')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    options = parser.parse_args()

    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass('Password:')

    if options.target_ip is None:
        options.target_ip = remoteName

    usernames = []
    for name in options.usernames:
        if Path(name).exists():
            with open(name, 'r') as f:
                usernames += f.read().strip().splitlines()
        else:
            usernames.append(name)

    lookup = LsaLookupNames(domain, username, password, options.hashes, int(options.port))
    lookup.resolve(remoteName, options.target_ip, usernames)
