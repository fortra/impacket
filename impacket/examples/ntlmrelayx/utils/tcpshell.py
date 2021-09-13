# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   TCP interactive shell
#
#   Launches a TCP shell for interactive use of clients
#   after successful relaying
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
import socket
#Default listen port
port = 11000
class TcpShell:
    def __init__(self):
        global port
        self.port = port
        #Increase the default port for the next attack
        port += 1

    def listen(self):
        #Set up the listening socket
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #Bind on localhost
        serversocket.bind(('127.0.0.1', self.port))
        #Don't allow a backlog
        serversocket.listen(0)
        self.connection, host = serversocket.accept()
        #Create file objects from the socket
        self.stdin = self.connection.makefile("r")
        self.stdout = self.connection.makefile("w")

    def close(self):
        self.stdout.close()
        self.stdin.close()
        self.connection.close()
