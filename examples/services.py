#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-SCMR] services common functions for manipulating services
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   DCE/RPC.
#
# TODO:
#   [ ] Check errors
#

from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging
import codecs

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret


class SVCCTL:

    def __init__(self, username, password, domain, options, port=445):
        self.__username = username
        self.__password = password
        self.__options = options
        self.__port = port
        self.__action = options.action.upper()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def run(self, remoteName, remoteHost):

        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doStuff(rpctransport)

    def doStuff(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        #dce.set_credentials(self.__username, self.__password)
        dce.connect()
        #dce.set_max_fragment_size(1)
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.bind(scmr.MSRPC_UUID_SCMR)
        #rpc = svcctl.DCERPCSvcCtl(dce)
        rpc = dce
        ans = scmr.hROpenSCManagerW(rpc)
        scManagerHandle = ans['lpScHandle']
        if self.__action != 'LIST' and self.__action != 'CREATE':
            ans = scmr.hROpenServiceW(rpc, scManagerHandle, self.__options.name+'\x00')
            serviceHandle = ans['lpServiceHandle']

        if self.__action == 'START':
            logging.info("Starting service %s" % self.__options.name)
            scmr.hRStartServiceW(rpc, serviceHandle)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        elif self.__action == 'STOP':
            logging.info("Stopping service %s" % self.__options.name)
            scmr.hRControlService(rpc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        elif self.__action == 'DELETE':
            logging.info("Deleting service %s" % self.__options.name)
            scmr.hRDeleteService(rpc, serviceHandle)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        elif self.__action == 'CONFIG':
            logging.info("Querying service config for %s" % self.__options.name)
            resp = scmr.hRQueryServiceConfigW(rpc, serviceHandle)
            print("TYPE              : %2d - " % resp['lpServiceConfig']['dwServiceType'], end=' ')
            if resp['lpServiceConfig']['dwServiceType'] & 0x1:
                print("SERVICE_KERNEL_DRIVER ", end=' ')
            if resp['lpServiceConfig']['dwServiceType'] & 0x2:
                print("SERVICE_FILE_SYSTEM_DRIVER ", end=' ')
            if resp['lpServiceConfig']['dwServiceType'] & 0x10:
                print("SERVICE_WIN32_OWN_PROCESS ", end=' ')
            if resp['lpServiceConfig']['dwServiceType'] & 0x20:
                print("SERVICE_WIN32_SHARE_PROCESS ", end=' ')
            if resp['lpServiceConfig']['dwServiceType'] & 0x100:
                print("SERVICE_INTERACTIVE_PROCESS ", end=' ')
            print("")
            print("START_TYPE        : %2d - " % resp['lpServiceConfig']['dwStartType'], end=' ')
            if resp['lpServiceConfig']['dwStartType'] == 0x0:
                print("BOOT START")
            elif resp['lpServiceConfig']['dwStartType'] == 0x1:
                print("SYSTEM START")
            elif resp['lpServiceConfig']['dwStartType'] == 0x2:
                print("AUTO START")
            elif resp['lpServiceConfig']['dwStartType'] == 0x3:
                print("DEMAND START")
            elif resp['lpServiceConfig']['dwStartType'] == 0x4:
                print("DISABLED")
            else:
                print("UNKNOWN")

            print("ERROR_CONTROL     : %2d - " % resp['lpServiceConfig']['dwErrorControl'], end=' ')
            if resp['lpServiceConfig']['dwErrorControl'] == 0x0:
                print("IGNORE")
            elif resp['lpServiceConfig']['dwErrorControl'] == 0x1:
                print("NORMAL")
            elif resp['lpServiceConfig']['dwErrorControl'] == 0x2:
                print("SEVERE")
            elif resp['lpServiceConfig']['dwErrorControl'] == 0x3:
                print("CRITICAL")
            else:
                print("UNKNOWN")
            print("BINARY_PATH_NAME  : %s" % resp['lpServiceConfig']['lpBinaryPathName'][:-1])
            print("LOAD_ORDER_GROUP  : %s" % resp['lpServiceConfig']['lpLoadOrderGroup'][:-1])
            print("TAG               : %d" % resp['lpServiceConfig']['dwTagId'])
            print("DISPLAY_NAME      : %s" % resp['lpServiceConfig']['lpDisplayName'][:-1])
            print("DEPENDENCIES      : %s" % resp['lpServiceConfig']['lpDependencies'][:-1])
            print("SERVICE_START_NAME: %s" % resp['lpServiceConfig']['lpServiceStartName'][:-1])
        elif self.__action == 'STATUS':
            print("Querying status for %s" % self.__options.name)
            resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
            print("%30s - " % self.__options.name, end=' ')
            state = resp['lpServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_CONTINUE_PENDING:
               print("CONTINUE PENDING")
            elif state == scmr.SERVICE_PAUSE_PENDING:
               print("PAUSE PENDING")
            elif state == scmr.SERVICE_PAUSED:
               print("PAUSED")
            elif state == scmr.SERVICE_RUNNING:
               print("RUNNING")
            elif state == scmr.SERVICE_START_PENDING:
               print("START PENDING")
            elif state == scmr.SERVICE_STOP_PENDING:
               print("STOP PENDING")
            elif state == scmr.SERVICE_STOPPED:
               print("STOPPED")
            else:
               print("UNKNOWN")
        elif self.__action == 'LIST':
            logging.info("Listing services available on target")
            #resp = rpc.EnumServicesStatusW(scManagerHandle, svcctl.SERVICE_WIN32_SHARE_PROCESS )
            #resp = rpc.EnumServicesStatusW(scManagerHandle, svcctl.SERVICE_WIN32_OWN_PROCESS )
            #resp = rpc.EnumServicesStatusW(scManagerHandle, serviceType = svcctl.SERVICE_FILE_SYSTEM_DRIVER, serviceState = svcctl.SERVICE_STATE_ALL )
            resp = scmr.hREnumServicesStatusW(rpc, scManagerHandle)
            for i in range(len(resp)):
                print("%30s - %70s - " % (resp[i]['lpServiceName'][:-1], resp[i]['lpDisplayName'][:-1]), end=' ')
                state = resp[i]['ServiceStatus']['dwCurrentState']
                if state == scmr.SERVICE_CONTINUE_PENDING:
                   print("CONTINUE PENDING")
                elif state == scmr.SERVICE_PAUSE_PENDING:
                   print("PAUSE PENDING")
                elif state == scmr.SERVICE_PAUSED:
                   print("PAUSED")
                elif state == scmr.SERVICE_RUNNING:
                   print("RUNNING")
                elif state == scmr.SERVICE_START_PENDING:
                   print("START PENDING")
                elif state == scmr.SERVICE_STOP_PENDING:
                   print("STOP PENDING")
                elif state == scmr.SERVICE_STOPPED:
                   print("STOPPED")
                else:
                   print("UNKNOWN")
            print("Total Services: %d" % len(resp))
        elif self.__action == 'CREATE':
            logging.info("Creating service %s" % self.__options.name)
            scmr.hRCreateServiceW(rpc, scManagerHandle, self.__options.name + '\x00', self.__options.display + '\x00',
                                  lpBinaryPathName=self.__options.path + '\x00')
        elif self.__action == 'CHANGE':
            logging.info("Changing service config for %s" % self.__options.name)
            if self.__options.start_type is not None:
                start_type = int(self.__options.start_type)
            else:
                start_type = scmr.SERVICE_NO_CHANGE
            if self.__options.service_type is not None:
                service_type = int(self.__options.service_type)
            else:
                service_type = scmr.SERVICE_NO_CHANGE

            if self.__options.display is not None:
                display = self.__options.display + '\x00'
            else:
                display = NULL
 
            if self.__options.path is not None:
                path = self.__options.path + '\x00'
            else:
                path = NULL
 
            if self.__options.start_name is not None:
                start_name = self.__options.start_name + '\x00'
            else:
                start_name = NULL 

            if self.__options.password is not None:
                s = rpctransport.get_smb_connection()
                key = s.getSessionKey()
                try:
                    password = (self.__options.password+'\x00').encode('utf-16le')
                except UnicodeDecodeError:
                    import sys
                    password = (self.__options.password+'\x00').decode(sys.getfilesystemencoding()).encode('utf-16le')
                password = encryptSecret(key, password)
            else:
                password = NULL
 

            #resp = scmr.hRChangeServiceConfigW(rpc, serviceHandle,  display, path, service_type, start_type, start_name, password)
            scmr.hRChangeServiceConfigW(rpc, serviceHandle, service_type, start_type, scmr.SERVICE_ERROR_IGNORE, path,
                                        NULL, NULL, NULL, 0, start_name, password, 0, display)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        else:
            logging.error("Unknown action %s" % self.__action)

        scmr.hRCloseServiceHandle(rpc, scManagerHandle)

        dce.disconnect()

        return 


# Process command-line arguments.
if __name__ == '__main__':

    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Windows Service manipulation script.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    subparsers = parser.add_subparsers(help='actions', dest='action')
 
    # A start command
    start_parser = subparsers.add_parser('start', help='starts the service')
    start_parser.add_argument('-name', action='store', required=True, help='service name')

    # A stop command
    stop_parser = subparsers.add_parser('stop', help='stops the service')
    stop_parser.add_argument('-name', action='store', required=True, help='service name')

    # A delete command
    delete_parser = subparsers.add_parser('delete', help='deletes the service')
    delete_parser.add_argument('-name', action='store', required=True, help='service name')

    # A status command
    status_parser = subparsers.add_parser('status', help='returns service status')
    status_parser.add_argument('-name', action='store', required=True, help='service name')

    # A config command
    config_parser = subparsers.add_parser('config', help='returns service configuration')
    config_parser.add_argument('-name', action='store', required=True, help='service name')

    # A list command
    list_parser = subparsers.add_parser('list', help='list available services')

    # A create command
    create_parser = subparsers.add_parser('create', help='create a service')
    create_parser.add_argument('-name', action='store', required=True, help='service name')
    create_parser.add_argument('-display', action='store', required=True, help='display name')
    create_parser.add_argument('-path', action='store', required=True, help='binary path')

    # A change command
    create_parser = subparsers.add_parser('change', help='change a service configuration')
    create_parser.add_argument('-name', action='store', required=True, help='service name')
    create_parser.add_argument('-display', action='store', required=False, help='display name')
    create_parser.add_argument('-path', action='store', required=False, help='binary path')
    create_parser.add_argument('-service_type', action='store', required=False, help='service type')
    create_parser.add_argument('-start_type', action='store', required=False, help='service start type')
    create_parser.add_argument('-start_name', action='store', required=False, help='string that specifies the name of '
                               'the account under which the service should run')
    create_parser.add_argument('-password', action='store', required=False, help='string that contains the password of '
                               'the account whose name was specified by the start_name parameter')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store',metavar = "ip address", help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                       'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                       'name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
 
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

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    services = SVCCTL(username, password, domain, options, int(options.port))
    try:
        services.run(remoteName, options.target_ip)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
