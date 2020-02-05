#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: [MS-TDS] & [MC-SQLR] example.
#
# Author:
#  Alberto Solino (beto@coresecurity.com/@agsolino)
#
# Reference for:
#  Structure
#

from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging

from impacket.examples import logger
from impacket import version, tds

if __name__ == '__main__':
    import cmd

    class SQLSHELL(cmd.Cmd):
        def __init__(self, SQL):
            cmd.Cmd.__init__(self)
            self.sql = SQL
            self.prompt = 'SQL> '
            self.intro = '[!] Press help for extra shell commands'

        def do_help(self, line):
            print("""
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     """) 

        def do_shell(self, s):
            os.system(s)

        def do_xp_cmdshell(self, s):
            try:
                self.sql.sql_query("exec master..xp_cmdshell '%s'" % s)
                self.sql.printReplies()
                self.sql.colMeta[0]['TypeData'] = 80*2
                self.sql.printRows()
            except:
                pass

        def sp_start_job(self, s):
            try:
                self.sql.sql_query("DECLARE @job NVARCHAR(100);"
                                   "SET @job='IdxDefrag'+CONVERT(NVARCHAR(36),NEWID());"
                                   "EXEC msdb..sp_add_job @job_name=@job,@description='INDEXDEFRAG',"
                                   "@owner_login_name='sa',@delete_level=3;"
                                   "EXEC msdb..sp_add_jobstep @job_name=@job,@step_id=1,@step_name='Defragmentation',"
                                   "@subsystem='CMDEXEC',@command='%s',@on_success_action=1;"
                                   "EXEC msdb..sp_add_jobserver @job_name=@job;"
                                   "EXEC msdb..sp_start_job @job_name=@job;" % s)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_lcd(self, s):
            if s == '':
                print(os.getcwd())
            else:
                os.chdir(s)
    
        def do_enable_xp_cmdshell(self, line):
            try:
                self.sql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                                   "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_disable_xp_cmdshell(self, line):
            try:
                self.sql.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure "
                                   "'show advanced options', 0 ;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def default(self, line):
            try:
                self.sql.sql_query(line)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass
         
        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default = 'False', help='whether or not to use Windows '
                                                                                      'Authentication (default False)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the SQL shell')

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

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
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

    ms_sql = tds.MSSQL(address, int(options.port))
    ms_sql.connect()
    try:
        if options.k is True:
            res = ms_sql.kerberosLogin(options.db, username, password, domain, options.hashes, options.aesKey,
                                       kdcHost=options.dc_ip)
        else:
            res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
        ms_sql.printReplies()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))
        res = False
    if res is True:
        shell = SQLSHELL(ms_sql)
        if options.file is None:
            shell.cmdloop()
        else:
            for line in options.file.readlines():
                print("SQL> %s" % line, end=' ')
                shell.onecmd(line)
    ms_sql.disconnect()
