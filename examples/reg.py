import argparse
import codecs
import logging
import sys

from impacket import version
from impacket.dcerpc.v5 import transport, rrp
from impacket.examples import logger


class RegHandler:

    def __init__(self, username, password, domain, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__action = options.action.upper()
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        # It's possible that this is defined somewhere, but I couldn't find where
        self.__regValues = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD'}
        self.__keyName = self.__options.name

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def run(self, addr):
        # Try all requested protocols until one works.
        stringbinding = r'ncacn_np:%s[\PIPE\winreg]' % addr

        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        try:
            self.do_stuff(rpctransport)
        except Exception, e:
            # import traceback
            # traceback.print_exc()
            logging.critical(str(e))

    def do_stuff(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        rpc = dce
        if self.__action == 'QUERY':
            self.query(rpc, self.__options.name)

    def query(self, rpc, key_name):
        ans = rrp.hOpenLocalMachine(rpc)
        ans2 = rrp.hBaseRegOpenKey(rpc, ans['phKey'], key_name, 1, rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
        if self.__options.v:
            print key_name
            ans3 = rrp.hBaseRegQueryValue(rpc, ans2['phkResult'], self.__options.v)
            print self.__options.v + '\t' + self.__regValues.get(ans3[0], 'KEY_NOT_FOUND') + '\t' + str(ans3[1])
        elif self.__options.s:
            self.__print_all_subkeys_and_entries(rpc, ans2['phkResult'], 0)
        else:
            print key_name
            self.__print_key_values(rpc, ans2['phkResult'])
            i = 0
            while True:
                try:
                    key = rrp.hBaseRegEnumKey(rpc, ans2['phkResult'], i)
                    print key_name + '\\' + key['lpNameOut']
                    i += 1
                except Exception:
                    break
            # ans5 = rrp.hBaseRegGetVersion(rpc, ans2['phkResult'])
        # ans3 = rrp.hBaseRegEnumKey(rpc, ans2['phkResult'], 0)

    def __print_key_values(self, rpc, key_handler):
        i = 0
        while True:
            try:
                ans4 = rrp.hBaseRegEnumValue(rpc, key_handler, i)
                lp_value_name = ans4['lpValueNameOut']
                lp_type = ans4['lpType']
                lp_data = ans4['lpData']
                data = self.__parse_lp_data(lp_type, lp_data)
                print '\t' + lp_value_name + '\t' + self.__regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t', data
                i += 1
            except Exception, e:
                # e.get_packet().dump()
                # logging.critical(str(e))
                break

    def __print_all_subkeys_and_entries(self, rpc, key_handler, index):
        try:
            subkey = rrp.hBaseRegEnumKey(rpc, key_handler, index)
            ans = rrp.hBaseRegOpenKey(rpc, key_handler, subkey['lpNameOut'], 1,
                                      rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
            self.__keyName += subkey['lpNameOut'] + '\\'
            print self.__keyName
            self.__print_key_values(rpc, ans['phkResult'])
            self.__print_all_subkeys_and_entries(rpc, ans['phkResult'], 0)
            # name = self.__keyName[:self.__keyName.rfind('\\')]
            # self.__keyName = name[:name.rfind('\\')]
            self.__keyName = self.__options.name
            self.__print_all_subkeys_and_entries(rpc, key_handler, index + 1)
            # self.__keyName = self.__options.name
        except:
            return

    def __parse_lp_data(self, lp_type, lp_data):
        if self.__regValues.get(lp_type) == 'REG_DWORD':
            return ord(lp_data[0])
        elif self.__regValues.get(lp_type) == 'REG_BINARY':
            j_data = ''.join(lp_data)
            return ''.join('{:02x}'.format(ord(c)) for c in j_data)
        return ''.join(lp_data)


if __name__ == '__main__':

    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print version.BANNER

    parser = argparse.ArgumentParser(add_help=True, description="Windows Register manipulation script.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    subparsers = parser.add_subparsers(help='actions', dest='action')

    # An add command
    start_parser = subparsers.add_parser('add', help='Adds a new subkey or entry to the registry.')
    # start_parser.add_argument('-name', action='store', required=True, help='service name')

    # A compare command
    stop_parser = subparsers.add_parser('compare', help='Compares specified registry subkeys or entries')
    # stop_parser.add_argument('-name', action='store', required=True, help='service name')

    # A copy command
    delete_parser = subparsers.add_parser('copy', help='Copies a registry entry to a specified location in the remote '
                                                       'computer')
    # delete_parser.add_argument('-name', action='copy', required=True, help='service name')

    # A export command
    status_parser = subparsers.add_parser('export', help='Creates a copy of specified subkeys, entries, and values into'
                                                         'a file')
    # status_parser.add_argument('-name', action='store', required=True, help='service name')

    # A import command
    config_parser = subparsers.add_parser('import', help='Copies a file containing exported registry subkeys, entries, '
                                                         'and values into the remote computer\'s registry')
    # config_parser.add_argument('-name', action='store', required=True, help='service name')

    # A load command
    list_parser = subparsers.add_parser('load', help='Writes saved subkeys and entries back to a different subkey in '
                                                     'the registry.')

    # A query command
    create_parser = subparsers.add_parser('query', help='Returns a list of the next tier of subkeys and entries that '
                                                        'are located under a specified subkey in the registry.')
    create_parser.add_argument('-name', action='store', required=True, help='Key name')
    create_parser.add_argument('-v', action='store', required=False, help='Returns a specific entry and its value')
    create_parser.add_argument('-s', action='store', required=False, help='Returns all subkeys and entries in all '
                                                                          'tiers')

    # A change command
    # create_parser = subparsers.add_parser('restore', help='change a service configuration')
    # create_parser.add_argument('-name', action='store', required=True, help='service name')
    # create_parser.add_argument('-display', action='store', required=False, help='display name')
    # create_parser.add_argument('-path', action='store', required=False, help='binary path')
    # create_parser.add_argument('-service_type', action='store', required=False, help='service type')
    # create_parser.add_argument('-start_type', action='store', required=False, help='service start type')
    # create_parser.add_argument('-start_name', action='store', required=False,
    #                            help='string that specifies the name of the account under which the service should run')
    # create_parser.add_argument('-password', action='store', required=False,
    #                            help='string that contains the password of the account whose name was specified by the start_name parameter')

    # A save command
    save_parser = subparsers.add_parser('save', help='Saves a copy of specified subkeys, entries, and values of the '
                                                     'registry in a specified file.')

    # An unload command
    unload_parser = subparsers.add_parser('unload', help='Removes a section of the registry that was loaded using the '
                                                         'reg load operation.')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key",
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    services = RegHandler(username, password, domain, options)
    try:
        services.run(address)
    except Exception, e:
        logging.error(str(e))