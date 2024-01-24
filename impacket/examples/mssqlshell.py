#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
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

import os
import cmd
import sys

def handle_lastError(f):
    def wrapper(*args):
        try:
            f(*args)
        finally:
            if(args[0].sql.lastError):
                print(args[0].sql.lastError)
    return wrapper

class SQLSHELL(cmd.Cmd):
    def __init__(self, SQL, show_queries=False, tcpShell=None):
        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

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
    enum_impersonate           - check logins that can be impersonated
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

    @handle_lastError
    def do_exec_as_login(self, s):
        exec_as = "execute as login='%s';" % s
        self.execute_as(exec_as)

    @handle_lastError
    def do_exec_as_user(self, s):
        exec_as = "execute as user='%s';" % s
        self.execute_as(exec_as)

    @handle_lastError
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

    @handle_lastError
    def do_xp_dirtree(self, s):
        try:
            self.sql_query("exec master.sys.xp_dirtree '%s',1,1" % s)
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    @handle_lastError
    def do_xp_cmdshell(self, s):
        try:
            self.sql_query("exec master..xp_cmdshell '%s'" % s)
            self.sql.printReplies()
            self.sql.colMeta[0]['TypeData'] = 80*2
            self.sql.printRows()
        except:
            pass

    @handle_lastError
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

    @handle_lastError
    def do_enable_xp_cmdshell(self, line):
        try:
            self.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                                "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    @handle_lastError
    def do_disable_xp_cmdshell(self, line):
        try:
            self.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure "
                            "'show advanced options', 0 ;RECONFIGURE;")
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    @handle_lastError
    def do_enum_links(self, line):
        self.sql_query("EXEC sp_linkedservers")
        self.sql.printReplies()
        self.sql.printRows()
        self.sql_query("EXEC sp_helplinkedsrvlogin")
        self.sql.printReplies()
        self.sql.printRows()

    @handle_lastError
    def do_enum_users(self, line):
        self.sql_query("EXEC sp_helpuser")
        self.sql.printReplies()
        self.sql.printRows()

    @handle_lastError
    def do_enum_db(self, line):
        try:
            self.sql_query("select name, is_trustworthy_on from sys.databases")
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    @handle_lastError
    def do_enum_owner(self, line):
        try:
            self.sql_query("SELECT name [Database], suser_sname(owner_sid) [Owner] FROM sys.databases")
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    @handle_lastError
    def do_enum_impersonate(self, line):
        old_db = self.sql.currentDB
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
        finally:
            self.sql_query("use " + old_db)

    @handle_lastError
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

    @handle_lastError
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
        if self.shell is not None:
            self.shell.close()
        return True