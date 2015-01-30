#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
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
from impacket import version, ntlm
from impacket.dcerpc.v5 import transport, dcomrt
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
import argparse
import sys
import os

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
                #import traceback
                #print traceback.print_exc()
                print e

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
                        print '%s |' % record[key]['value'],
                    print 
                except Exception, e:
                    #import traceback
                    #print traceback.print_exc()
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
                print str(e)
         
        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-namespace', action='store', default='//./root/cimv2', help='namespace name (default //./root/cimv2)')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the WQL shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

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

    dcom = DCOMConnection(address, username, password, domain, lmhash, nthash, options.aesKey, oxidResolver = True, doKerberos=options.k)

    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    iWbemServices= iWbemLevel1Login.NTLMLogin(options.namespace, NULL, NULL)
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
