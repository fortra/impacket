#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Ping MS-RPC interfaces to scan for those that are vulnerable to NTLM relay. Need to supply the uuid list in format:
# 12345778-1234-abcd-ef00-0123456789ac v1.0
#
#
# Author:
#  Eyal Karni (@eyalk5) - CrowdStrike

from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging
import codecs

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, scmr ,epm
from impacket.examples.ntlmrelayx.clients.rpcrelayclient import MYDCERPC_v5
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_CONNECT
from impacket.dcerpc.v5.epm import uuidtup_to_bin
from collections import defaultdict
from impacket.system_errors import ERROR_MESSAGES


TRANSLATE_ERR ={
    'rpc_x_bad_stub_data': "Vulnerable Interfaces:",
    'rpc_s_access_denied': "Protected Interfaces:",
    'nca_s_unsupported_type ': 'Inconclusive Interfaces:',
    'ConnectionReset': 'Failed Connections:',
    0x16C9A0D6: 'Interfaces that are not mapped:'

}


class PingInterface:
    def __init__(self, username, password, domain, options, uuid):
        self.__username = username
        self.__password = password
        self.__options = options
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.uuid = uuidtup_to_bin((uuid[0], uuid[1]))

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def run(self, remoteHost):
        try:
            return self.run_internal(remoteHost)
        except (DCERPCException,ConnectionResetError) as e:
            logging.debug('Got error:' + str(e))
            if type(e)==ConnectionResetError:
                return 'ConnectionReset'
            return e.error_code if (e.error_code != None) else str(e)
        except Exception as e:
            logging.error('Unexpected error:',e)
            return str(e)



    def run_internal(self, remoteHost):
        stringBinding = epm.hept_map(remoteHost, self.uuid, protocol='ncacn_ip_tcp')
        logging.debug('String Binding %s' % stringBinding)
        rpcTransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpcTransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpcTransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        rpcTransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        return self.doStuff(rpcTransport)

    def doStuff(self, rpcTransport):
        dce = MYDCERPC_v5(rpcTransport)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        dce.bind(self.uuid)
        scmr.hROpenSCManagerW(dce) # This is just a randomly chosen call. We send garbage to most interfaces.
        return 0


def get_err_str(err):
    return err.strip() if type(err) == str else 'err ' + hex(err)


def enumerate_interfaces(username, password, domain, options):
    logging.debug('Started enumeration on %s' % remoteName)

    uuid_by_err_dict = defaultdict(list)

    for uuidLine in open(options.uuid_list, 'rt'):
        uuidLine = str(uuidLine).replace('\n', '')
        if uuidLine == '':
            continue
        uuid = uuidLine.split(' ')
        uuid[1] = uuid[1].replace('v', '')
        logging.debug("Trying uuid " + uuidLine)
        ping = PingInterface(username, password, domain, options, uuid)
        err = ping.run( options.target_ip)
        uuid_by_err_dict[err] += [uuidLine]

    logging.debug('Ended enumeration on %s' % options.target_ip)

    print('*************** Results ***************** \n')

    for errorCode, uuidList in uuid_by_err_dict.items():
        default_err = '\nInterfaces returned %s:' % (
            get_err_str(errorCode) if errorCode not in ERROR_MESSAGES else ERROR_MESSAGES[errorCode][0])
        print(TRANSLATE_ERR.get(errorCode, default_err))
        if len(uuidList) > 0:
            print('\n\t' + '\n\t'.join(uuidList) + '\n')

if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Ping MS-RPC interfaces to scan for those that are vulnerable to NTLM relay.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

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

    requiredNamed = parser.add_argument_group('required named arguments')

    requiredNamed.add_argument('--uuid-list', action='store',
                               help='file containing list of UUIDs in the form: UUID version', required=True)

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

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    enumerate_interfaces(username, password, domain, options)

