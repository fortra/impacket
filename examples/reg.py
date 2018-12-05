#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Remote registry manipulation tool.
#              The idea is to provide similar functionality as the REG.EXE Windows utility.
#
# e.g:
#    ./reg.py Administrator:password@targetMachine query -keyName HKLM\\Software\\Microsoft\\WBEM -s
#
# Author:
#  Manuel Porto (@manuporto)
#  Alberto Solino (@agsolino)
#
# Reference for: [MS-RRP]
#
import argparse
import codecs
import logging
import sys
import time
from struct import unpack

from impacket import version
from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt
from impacket.examples import logger
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.winregistry import hexdump
from impacket.smbconnection import SMBConnection


class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5 * 60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__regHandle = None

        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__scmr = None

    def getRRP(self):
        return self.__rrp

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('Service %s is in stopped state' % self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is already running' % self.__serviceName)
            self.__shouldStop = False
            self.__started = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logging.info('Service %s is disabled, enabling it' % self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x3)
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            logging.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x4)

    def finish(self):
        self.__restore()
        if self.__rrp is not None:
            self.__rrp.disconnect()
        if self.__scmr is not None:
            self.__scmr.disconnect()


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
        self.__smbConnection = None
        self.__remoteOps = None

        # It's possible that this is defined somewhere, but I couldn't find where
        self.__regValues = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD',
                            5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD'}

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self, remoteName, remoteHost):
        self.__smbConnection = SMBConnection(remoteName, remoteHost, sess_port=int(self.__options.port))

        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def run(self, remoteName, remoteHost):
        self.connect(remoteName, remoteHost)
        self.__remoteOps = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)

        try:
            self.__remoteOps.enableRegistry()
        except Exception, e:
            logging.debug(str(e))
            logging.warning('Cannot check RemoteRegistry status. Hoping it is started...')
            self.__remoteOps.connectWinReg()

        try:
            dce = self.__remoteOps.getRRP()

            if self.__action == 'QUERY':
                self.query(dce, self.__options.keyName)
            else:
                logging.error('Method %s not implemented yet!' % self.__action)
        except (Exception, KeyboardInterrupt), e:
            # import traceback
            # traceback.print_exc()
            logging.critical(str(e))
        finally:
            if self.__remoteOps:
                self.__remoteOps.finish()

    def query(self, dce, keyName):
        # Let's strip the root key
        try:
            rootKey = keyName.split('\\')[0]
            subKey = '\\'.join(keyName.split('\\')[1:])
        except Exception:
            raise Exception('Error parsing keyName %s' % keyName)

        if rootKey.upper() == 'HKLM':
            ans = rrp.hOpenLocalMachine(dce)
        elif rootKey.upper() == 'HKU':
            ans = rrp.hOpenCurrentUser(dce)
        elif rootKey.upper() == 'HKCR':
            ans = rrp.hOpenClassesRoot(dce)
        else:
            raise Exception('Invalid root key %s ' % rootKey)

        hRootKey = ans['phKey']

        ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey,
                                   samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)

        if self.__options.v:
            print keyName
            value = rrp.hBaseRegQueryValue(dce, ans2['phkResult'], self.__options.v)
            print '\t' + self.__options.v + '\t' + self.__regValues.get(value[0], 'KEY_NOT_FOUND') + '\t', str(value[1])
        elif self.__options.ve:
            print keyName
            value = rrp.hBaseRegQueryValue(dce, ans2['phkResult'], '')
            print '\t' + '(Default)' + '\t' + self.__regValues.get(value[0], 'KEY_NOT_FOUND') + '\t', str(value[1])
        elif self.__options.s:
            self.__print_all_subkeys_and_entries(dce, subKey + '\\', ans2['phkResult'], 0)
        else:
            print keyName
            self.__print_key_values(dce, ans2['phkResult'])
            i = 0
            while True:
                try:
                    key = rrp.hBaseRegEnumKey(dce, ans2['phkResult'], i)
                    print keyName + '\\' + key['lpNameOut'][:-1]
                    i += 1
                except Exception:
                    break
                    # ans5 = rrp.hBaseRegGetVersion(rpc, ans2['phkResult'])
                    # ans3 = rrp.hBaseRegEnumKey(rpc, ans2['phkResult'], 0)

    def __print_key_values(self, rpc, keyHandler):
        i = 0
        while True:
            try:
                ans4 = rrp.hBaseRegEnumValue(rpc, keyHandler, i)
                lp_value_name = ans4['lpValueNameOut'][:-1]
                if len(lp_value_name) == 0:
                    lp_value_name = '(Default)'
                lp_type = ans4['lpType']
                lp_data = ''.join(ans4['lpData'])
                print '\t' + lp_value_name + '\t' + self.__regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t',
                self.__parse_lp_data(lp_type, lp_data)
                i += 1
            except rrp.DCERPCSessionError, e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break

    def __print_all_subkeys_and_entries(self, rpc, keyName, keyHandler, index):
        index = 0
        while True:
            try:
                subkey = rrp.hBaseRegEnumKey(rpc, keyHandler, index)
                index += 1
                ans = rrp.hBaseRegOpenKey(rpc, keyHandler, subkey['lpNameOut'],
                                          samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
                newKeyName = keyName + subkey['lpNameOut'][:-1] + '\\'
                print newKeyName
                self.__print_key_values(rpc, ans['phkResult'])
                self.__print_all_subkeys_and_entries(rpc, newKeyName, ans['phkResult'], 0)
            except rrp.DCERPCSessionError, e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
            except rpcrt.DCERPCException, e:
                if str(e).find('access_denied') >= 0:
                    logging.error('Cannot access subkey %s, bypassing it' % subkey['lpNameOut'][:-1])
                    continue
                elif str(e).find('rpc_x_bad_stub_data') >= 0:
                    logging.error('Fault call, cannot retrieve value for %s, bypassing it' % subkey['lpNameOut'][:-1])
                    return
                raise

    @staticmethod
    def __parse_lp_data(valueType, valueData):
        try:
            if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
                if type(valueData) is int:
                    print 'NULL'
                else:
                    print "%s" % (valueData.decode('utf-16le')[:-1])
            elif valueType == rrp.REG_BINARY:
                print ''
                hexdump(valueData, '\t')
            elif valueType == rrp.REG_DWORD:
                print "0x%x" % (unpack('<L', valueData)[0])
            elif valueType == rrp.REG_QWORD:
                print "0x%x" % (unpack('<Q', valueData)[0])
            elif valueType == rrp.REG_NONE:
                try:
                    if len(valueData) > 1:
                        print ''
                        hexdump(valueData, '\t')
                    else:
                        print " NULL"
                except:
                    print " NULL"
            elif valueType == rrp.REG_MULTI_SZ:
                print "%s" % (valueData.decode('utf-16le')[:-2])
            else:
                print "Unknown Type 0x%x!" % valueType
                hexdump(valueData)
        except Exception, e:
            logging.debug('Exception thrown when printing reg value %s', str(e))
            print 'Invalid data'
            pass


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

    # A query command
    query_parser = subparsers.add_parser('query', help='Returns a list of the next tier of subkeys and entries that '
                                                       'are located under a specified subkey in the registry.')
    query_parser.add_argument('-keyName', action='store', required=True,
                              help='Specifies the full path of the subkey. The '
                                   'keyName must include a valid root key. Valid root keys for the local computer are: HKLM,'
                                   ' HKU.')
    query_parser.add_argument('-v', action='store', metavar="VALUENAME", required=False, help='Specifies the registry '
                           'value name that is to be queried. If omitted, all value names for keyName are returned. ')
    query_parser.add_argument('-ve', action='store_true', default=False, required=False, help='Queries for the default '
                                                                         'value or empty value name')
    query_parser.add_argument('-s', action='store_true', default=False, help='Specifies to query all subkeys and value '
                                                                             'names recursively.')

    # An add command
    # add_parser = subparsers.add_parser('add', help='Adds a new subkey or entry to the registry')

    # An delete command
    # delete_parser = subparsers.add_parser('delete', help='Deletes a subkey or entries from the registry')

    # A copy command
    # copy_parser = subparsers.add_parser('copy', help='Copies a registry entry to a specified location in the remote '
    #                                                   'computer')

    # A save command
    # save_parser = subparsers.add_parser('save', help='Saves a copy of specified subkeys, entries, and values of the '
    #                                                 'registry in a specified file.')

    # A load command
    # load_parser = subparsers.add_parser('load', help='Writes saved subkeys and entries back to a different subkey in '
    #                                                 'the registry.')

    # An unload command
    # unload_parser = subparsers.add_parser('unload', help='Removes a section of the registry that was loaded using the '
    #                                                     'reg load operation.')

    # A compare command
    # compare_parser = subparsers.add_parser('compare', help='Compares specified registry subkeys or entries')

    # A export command
    # status_parser = subparsers.add_parser('export', help='Creates a copy of specified subkeys, entries, and values into'
    #                                                     'a file')

    # A import command
    # import_parser = subparsers.add_parser('import', help='Copies a file containing exported registry subkeys, entries, '
    #                                                     'and values into the remote computer\'s registry')


    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on '
                            'target parameters. If valid credentials cannot be found, it will use the ones specified '
                            'in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key",
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    regHandler = RegHandler(username, password, domain, options)
    try:
        regHandler.run(remoteName, options.target_ip)
    except Exception, e:
        logging.error(str(e))
