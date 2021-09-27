#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will connect against a target (or list of targets) machine/s and gather the OS architecture type
#   installed.
#   The trick has been discovered many years ago and is actually documented by Microsoft here:
#     https://msdn.microsoft.com/en-us/library/cc243948.aspx#Appendix_A_53
#   and doesn't require any authentication at all.
#
#   Have in mind this trick will *not* work if the target system is running Samba. Don't know what happens with macOS.
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   RPCRT, NDR
#

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys

from impacket import version
from impacket.examples import logger
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP


class TARGETARCH:
    def __init__(self, options):
        self.__machinesList = list()
        self.__options = options
        self.NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

    def run(self):
        if self.__options.targets is not None:
            for line in self.__options.targets.readlines():
                self.__machinesList.append(line.strip(' \r\n'))
        else:
            self.__machinesList.append(self.__options.target)

        logging.info('Gathering OS architecture for %d machines' % len(self.__machinesList))
        logging.info('Socket connect timeout set to %s secs' % self.__options.timeout)

        for machine in self.__machinesList:
            try:
                stringBinding = r'ncacn_ip_tcp:%s[135]' % machine
                transport = DCERPCTransportFactory(stringBinding)
                transport.set_connect_timeout(int(self.__options.timeout))
                dce = transport.get_dce_rpc()
                dce.connect()
                try:
                    dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=self.NDR64Syntax)
                except DCERPCException as e:
                    if str(e).find('syntaxes_not_supported') >= 0:
                        print('%s is 32-bit' % machine)
                    else:
                        logging.error(str(e))
                        pass
                else:
                    print('%s is 64-bit' % machine)

                dce.disconnect()
            except Exception as e:
                #import traceback
                #traceback.print_exc()
                logging.error('%s: %s' % (machine, str(e)))

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Gets the target system's OS architecture version")
    parser.add_argument('-target', action='store', help='<targetName or address>')
    parser.add_argument('-targets', type=argparse.FileType('r'), help='input file with targets system to query Arch '
                        'from (one per line). ')
    parser.add_argument('-timeout', action='store', default='2', help='socket timeout out when connecting to the target (default 2 sec)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.target is None and options.targets is None:
        logging.error('You have to specify a target!')
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        getArch = TARGETARCH(options)
        getArch.run()
    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
    sys.exit(0)
