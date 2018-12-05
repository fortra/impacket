# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# TCP interactive shell
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#     Launches a TCP shell for interactive use of clients
# after successful relaying
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
        #Create a file object from the socket
        self.socketfile = self.connection.makefile()