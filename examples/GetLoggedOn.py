#!/usr/bin/python3
from __future__ import division
from __future__ import print_function
import re
import codecs
import logging
import time
import argparse
import sys
from impacket import version
from impacket.dcerpc.v5 import transport, rrp, scmr,lsat, lsad
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException


class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5 * 60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__scmr = None

    def getRRP(self):
        return self.__rrp

    def connectWinReg(self):
        try:
            rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
            rpc.set_smb_connection(self.__smbConnection)
            self.__rrp = rpc.get_dce_rpc()
            self.__rrp.connect()
            self.__rrp.bind(rrp.MSRPC_UUID_RRP)
        except:
            logging.warning("Trying to start the Remote Registry...")    

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


class Check:
    def __init__(self, username, password, domain, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.__smbConnection = None
        self.__remoteOps = None
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
       
        logging.warning('Cannot check RemoteRegistry status. Hoping it is started...')
        
        # We try to enable the registry. It will fail the first time but that's okay, it will fail but still will start the service.
        self.__remoteOps.connectWinReg()
        
        # Lil sleep to wait for the service to start correctly 
        time.sleep(0.5)
        try:
            # Connect via WinReg - Second connection, this will work now coz service has been already started 
            sidRegex = "^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"
            self.__remoteOps.connectWinReg()
            dce = self.__remoteOps.getRRP()
            
            # Open HKU
            resp = rrp.hOpenUsers(dce)
            hKey = resp['phKey']
            users = list()
            index = 1
            while True:
                try:
                    resp = rrp.hBaseRegEnumKey(dce, hKey, index)
                    userSid = resp['lpNameOut'].rstrip('\0')
                    res = re.match(sidRegex, userSid)
                    if res:
                        users.append(userSid)
                    index += 1
                except:
                    break

            rrp.hBaseRegCloseKey(dce, hKey)
            dce.disconnect()

            # Resolve UserSid
            lsaRpcBinding = r'ncacn_np:%s[\pipe\lsarpc]'
            rpc = transport.DCERPCTransportFactory(lsaRpcBinding)
            rpc.set_smb_connection(self.__smbConnection)
            dce = rpc.get_dce_rpc()
            dce.connect()
            
            dce.bind(lsat.MSRPC_UUID_LSAT)
            
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp['PolicyHandle']

            
            try:
                resp = lsat.hLsarLookupSids(dce, policyHandle, users,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    pass
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else: 
                    raise
            if resp['TranslatedNames']['Names'] == []:
                logging.error("No one is currently logged")
            else:
                for item in resp['TranslatedNames']['Names']:
                    if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                        logging.info("User %s\\%s is logged on: %s" % (
                        resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'],remoteHost))
            dce.disconnect()
            


        except (Exception, KeyboardInterrupt) as e:
            #import traceback
            #traceback.print_exc()
            logging.critical(str(e))
        finally:
            if self.__remoteOps:
                self.__remoteOps.finish()



if __name__ == '__main__':

    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Windows Logon Checker.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
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
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    regHandler = Check(username, password, domain, options)
    try:
        regHandler.run(remoteName, options.target_ip)
    except Exception as e:
        #import traceback
        #traceback.print_exc()
        logging.error(str(e))
