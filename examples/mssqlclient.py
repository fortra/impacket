#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: [MS-TDS] & [MC-SQLR] example.
#
# Author:
#  Alberto Solino (beto@coresecurity.com/@agsolino)
#
# Reference for:
#  Structure
#


from impacket import version, tds
from impacket.examples import logger
import argparse
import sys
import string
import os

if __name__ == '__main__':
    import cmd

    class SQLSHELL(cmd.Cmd):
        def __init__(self, SQL):
            cmd.Cmd.__init__(self)
            self.sql = SQL
            self.prompt = 'SQL> '
            self.intro = '[!] Press help for extra shell commands'

        def do_help(self, line):
            print """
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     ! {cmd}                    - executes a local shell cmd
     """ 

        def do_shell(self, s):
            os.system(s)

        def do_xp_cmdshell(self, s):
            try:
                replies = self.sql.sql_query("exec master..xp_cmdshell '%s'" % s)
                self.sql.printReplies()
                self.sql.colMeta[0]['TypeData'] = 80*2
                self.sql.printRows()
            except Exception, e:
                pass

        def do_lcd(self, s):
            if s == '':
                print os.getcwd()
            else:
                os.chdir(s)
    
        def do_enable_xp_cmdshell(self, line):
            try:
                replies = self.sql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except Exception, e:
                pass

        def do_disable_xp_cmdshell(self, line):
            try:
                replies = self.sql.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except Exception, e:
                pass

        def default(self, line):
            try:
                replies = self.sql.sql_query(line)
                self.sql.printReplies()
                self.sql.printRows()
            except Exception, e:
                pass
         
        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default = 'False', help='whether or not to use Windows Authentication (default False)')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the SQL shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    ms_sql = tds.MSSQL(address, string.atoi(options.port))
    ms_sql.connect()
    res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
    ms_sql.printReplies()
    if res == True:
        shell = SQLSHELL(ms_sql)
        if options.file is None:
            shell.cmdloop()
        else:
            for line in options.file.readlines():
                print "SQL> %s" % line,
                shell.onecmd(line)
    ms_sql.disconnect()
