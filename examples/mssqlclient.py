#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-TDS] & [MC-SQLR] example.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure
#

from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, tds

if __name__ == '__main__':
    import cmd

    class SQLSHELL(cmd.Cmd):
        def __init__(self, SQL, show_queries=False):
            cmd.Cmd.__init__(self)
            self.sql = SQL
            self.show_queries = show_queries
            self.at = []
            self.set_prompt()
            self.intro = '[!] Press help for extra shell commands'

        def do_help(self, line):
            print("""
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     enum_db                    - enum databases
     enum_links                 - enum linked servers
     enum_impersonate           - check logins that can be impersonate
     enum_logins                - enum login users
     enum_users                 - enum current db users
     enum_owner                 - enum db owner
     exec_as_user {user}        - impersonate with execute as user
     exec_as_login {login}      - impersonate with execute as login
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     xp_dirtree {path}          - executes xp_dirtree on the path
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
     ! {cmd}                    - executes a local shell cmd
     show_query                 - show query
     mask_query                 - mask query
     """)

        def postcmd(self, stop, line):
            self.set_prompt()
            return stop

        def set_prompt(self):
            try:
                row = self.sql_query('select system_user + SPACE(2) + current_user as "username"', False)
                username_prompt = row[0]['username']
            except:
                username_prompt = '-'
            if self.at is not None and len(self.at) > 0:
                at_prompt = ''
                for (at, prefix) in self.at:
                    at_prompt += '>' + at
                self.prompt = 'SQL %s (%s@%s)> ' % (at_prompt, username_prompt, self.sql.currentDB)
            else:
                self.prompt = 'SQL (%s@%s)> ' % (username_prompt, self.sql.currentDB)

        def do_show_query(self, s):
            self.show_queries = True

        def do_mask_query(self, s):
            self.show_queries = False

        def execute_as(self, exec_as):
            if self.at is not None and len(self.at) > 0:
                (at, prefix) = self.at[-1:][0]
                self.at = self.at[:-1]
                self.at.append((at, exec_as))
            else:
                self.sql_query(exec_as)
                self.sql.printReplies()

        def do_exec_as_login(self, s):
            exec_as = "execute as login='%s';" % s
            self.execute_as(exec_as)

        def do_exec_as_user(self, s):
            exec_as = "execute as user='%s';" % s
            self.execute_as(exec_as)

        def do_use_link(self, s):
            if s == 'localhost':
                self.at = []
            elif s == '..':
                self.at = self.at[:-1]
            else:
                self.at.append((s, ''))
                row = self.sql_query('select system_user as "username"')
                self.sql.printReplies()
                if len(row) < 1:
                    self.at = self.at[:-1]

        def sql_query(self, query, show=True):
            if self.at is not None and len(self.at) > 0:
                for (linked_server, prefix) in self.at[::-1]:
                    query = "EXEC ('" + prefix.replace("'", "''") + query.replace("'", "''") + "') AT " + linked_server
            if self.show_queries and show:
                print('[%%] %s' % query)
            return self.sql.sql_query(query)

        def do_shell(self, s):
            os.system(s)

        def do_xp_dirtree(self, s):
            try:
                self.sql_query("exec master.sys.xp_dirtree '%s',1,1" % s)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_xp_cmdshell(self, s):
            try:
                self.sql_query("exec master..xp_cmdshell '%s'" % s)
                self.sql.printReplies()
                self.sql.colMeta[0]['TypeData'] = 80*2
                self.sql.printRows()
            except:
                pass

        def do_sp_start_job(self, s):
            try:
                self.sql_query("DECLARE @job NVARCHAR(100);"
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
                self.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                                   "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_disable_xp_cmdshell(self, line):
            try:
                self.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure "
                               "'show advanced options', 0 ;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_enum_links(self, line):
            self.sql_query("EXEC sp_linkedservers")
            self.sql.printReplies()
            self.sql.printRows()
            self.sql_query("EXEC sp_helplinkedsrvlogin")
            self.sql.printReplies()
            self.sql.printRows()

        def do_enum_users(self, line):
            self.sql_query("EXEC sp_helpuser")
            self.sql.printReplies()
            self.sql.printRows()

        def do_enum_db(self, line):
            try:
                self.sql_query("select name, is_trustworthy_on from sys.databases")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_enum_owner(self, line):
            try:
                self.sql_query("SELECT name [Database], suser_sname(owner_sid) [Owner] FROM sys.databases")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_enum_impersonate(self, line):
            try:
                self.sql_query("select name from sys.databases")
                result = []
                for row in self.sql.rows:
                    result_rows = self.sql_query("use " + row['name'] + "; SELECT 'USER' as 'execute as', DB_NAME() "
                                                                        "AS 'database',pe.permission_name,"
                                                                        "pe.state_desc, pr.name AS 'grantee', "
                                                                        "pr2.name AS 'grantor' "
                                                                        "FROM sys.database_permissions pe "
                                                                        "JOIN sys.database_principals pr ON "
                                                                        "  pe.grantee_principal_id = pr.principal_Id "
                                                                        "JOIN sys.database_principals pr2 ON "
                                                                        "  pe.grantor_principal_id = pr2.principal_Id "
                                                                        "WHERE pe.type = 'IM'")
                    if result_rows:
                        result.extend(result_rows)
                result_rows = self.sql_query("SELECT 'LOGIN' as 'execute as', '' AS 'database',pe.permission_name,"
                                             "pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' "
                                             "FROM sys.server_permissions pe JOIN sys.server_principals pr "
                                             "  ON pe.grantee_principal_id = pr.principal_Id "
                                             "JOIN sys.server_principals pr2 "
                                             "  ON pe.grantor_principal_id = pr2.principal_Id "
                                             "WHERE pe.type = 'IM'")
                result.extend(result_rows)
                self.sql.printReplies()
                self.sql.rows = result
                self.sql.printRows()
            except:
                pass

        def do_enum_logins(self, line):
            try:
                self.sql_query("select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin, "
                               "sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, "
                               "sl.bulkadmin from  master.sys.server_principals r left join master.sys.syslogins sl "
                               "on sl.sid = r.sid where r.type in ('S','E','X','U','G')")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def default(self, line):
            try:
                self.sql_query(line)
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
    parser.add_argument('-windows-auth', action='store_true', default=False, help='whether or not to use Windows '
                                                                                  'Authentication (default False)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-show', action='store_true', help='show the queries')
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

    domain, username, password, address = parse_target(options.target)

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
        shell = SQLSHELL(ms_sql, options.show)
        if options.file is None:
            shell.cmdloop()
        else:
            for line in options.file.readlines():
                print("SQL> %s" % line, end=' ')
                shell.onecmd(line)
    ms_sql.disconnect()
