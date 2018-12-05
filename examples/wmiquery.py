#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: [MS-WMI] example. It allows to issue WQL queries and
#              get description of the objects.
#
#              e.g.: select name from win32_account
#              e.g.: describe win32_process
# 
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCOM
#
import argparse
import sys
import os
import logging

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_NONE

if __name__ == '__main__':
    import cmd

    class WMIQUERY(cmd.Cmd):
        def __init__(self, iWbemServices):
            cmd.Cmd.__init__(self)
            self.iWbemServices = iWbemServices
            self.prompt = 'WQL> '
            self.intro = '[!] Press help for extra shell commands'

        def do_help(self, line):
            print """
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     describe {class}           - describes class
     ! {cmd}                    - executes a local shell cmd
     """ 

        def do_shell(self, s):
            os.system(s)

        def do_describe(self, sClass):
            sClass = sClass.strip('\n')
            if sClass[-1:] == ';':
                sClass = sClass[:-1]
            try:
                iObject, _ = self.iWbemServices.GetObject(sClass)
                iObject.printInformation()
                iObject.RemRelease()
            except Exception, e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(str(e))

        def do_lcd(self, s):
            if s == '':
                print os.getcwd()
            else:
                os.chdir(s)
    
        def printReply(self, iEnum):
            printHeader = True
            while True:
                try:
                    pEnum = iEnum.Next(0xffffffff,1)[0]
                    record = pEnum.getProperties()
                    if printHeader is True:
                        print '|',
                        for col in record:
                            print '%s |' % col,
                        print
                        printHeader = False
                    print '|', 
                    for key in record:
                        if type(record[key]['value']) is list:
                            for item in record[key]['value']:
                                print item,
                            print ' |',
                        else:
                            print '%s |' % record[key]['value'],
                    print 
                except Exception, e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('S_FALSE') < 0:
                        raise
                    else:
                        break
            iEnum.RemRelease() 

        def default(self, line):
            line = line.strip('\n')
            if line[-1:] == ';':
                line = line[:-1]
            try:
                iEnumWbemClassObject = self.iWbemServices.ExecQuery(line.strip('\n'))
                self.printReply(iEnumWbemClassObject)
                iEnumWbemClassObject.RemRelease()
            except Exception, e:
                logging.error(str(e))
         
        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Executes WQL queries and gets object descriptions "
                                                                    "using Windows Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-namespace', action='store', default='//./root/cimv2', help='namespace name (default //./root/cimv2)')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the WQL shell')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy','default'], nargs='?', default='default',
                       help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                            '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                            'privacy level by default)')

    if len(sys.argv)==1:
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

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        dcom = DCOMConnection(address, username, password, domain, lmhash, nthash, options.aesKey, oxidResolver=True,
                              doKerberos=options.k, kdcHost=options.dc_ip)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin(options.namespace, NULL, NULL)
        if options.rpc_auth_level == 'privacy':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        elif options.rpc_auth_level == 'integrity':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

        iWbemLevel1Login.RemRelease()

        shell = WMIQUERY(iWbemServices)
        if options.file is None:
            shell.cmdloop()
        else:
            for line in options.file.readlines():
                print "WQL> %s" % line,
                shell.onecmd(line)

        iWbemServices.RemRelease()
        dcom.disconnect()
    except Exception, e:
        logging.error(str(e))
        try:
            dcom.disconnect()
        except:
            pass

