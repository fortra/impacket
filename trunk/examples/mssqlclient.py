#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
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
#  Alberto Solino (beto@coresecurity.com)
#
# Reference for:
#  Structure
#


from impacket import version, tds
import argparse
import sys
import string

if __name__ == '__main__':
    import cmd

    class SQLSHELL(cmd.Cmd):
        def __init__(self, SQL):
            cmd.Cmd.__init__(self)
            self.sql = SQL
            self.prompt = 'SQL> '

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

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store', choices=['True','False'], default = 'False', help='whether or not to use Windows Authentication (default False)')
    

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
    if options.windows_auth == 'True':
        win_auth = True
    else:
        win_auth = False

    ms_sql = tds.MSSQL(address, string.atoi(options.port))
    ms_sql.connect()
    res = ms_sql.login(options.db, username, password, domain, options.hashes, win_auth)
    ms_sql.printReplies()
    if res == True:
        shell = SQLSHELL(ms_sql)
        shell.cmdloop()
    ms_sql.disconnect()
