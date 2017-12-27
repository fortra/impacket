#!/usr/bin/env python
# Copyright (c) 2013-2017 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the HTTP Protocol
#
# Author:
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  A simple SOCKS server that proxies a connection to relayed HTTP connections
#
# ToDo:
#
import struct
import random
import logging
import base64

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay
from impacket.ntlm import NTLMAuthChallengeResponse

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSocksRelay"
EOL = '\r\n'

class HTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'HTTP Socks Plugin'
    PLUGIN_SCHEME = 'HTTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        pass

    def skipAuthentication(self):
        # See if the user provided authentication
        data = self.socksSocket.recv(self.packetSize)
        # Get headers from data
        headerDict = self.getHeaders(data)
        try:
            creds = headerDict['authorization']
            if 'Basic' not in creds:
                raise KeyError()
            basicAuth = base64.b64decode(creds[7:])
            self.username = basicAuth.split(':')[0].upper()

            # Check if we have a connection for the user
            if self.activeRelays.has_key(self.username):
                # Check the connection is not inUse
                if self.activeRelays[self.username]['inUse'] is True:
                    LOG.error('HTTP: Connection for %s@%s(%s) is being used at the moment!' % (
                        self.username, self.targetHost, self.targetPort))
                    return False
                else:
                    LOG.info('HTTP: Proxying client session for %s@%s(%s)' % (
                        self.username, self.targetHost, self.targetPort))
                    self.session = self.activeRelays[self.username]['client']
            else:
                LOG.error('HTTP: No session for %s@%s(%s) available' % (
                    self.username, self.targetHost, self.targetPort))
                return False

        except KeyError:
            # User didn't provide authentication yet, prompt for it
            LOG.debug('No authentication provided, prompting for basic authentication')
            reply = ['HTTP/1.1 401 Unauthorized','WWW-Authenticate: Basic realm="ntlmrelayx - provide a DOMAIN/username"','Connection: close','','']
            self.socksSocket.send(EOL.join(reply))
            self.socksSocket.close()
            return False

        # When we are here, we have a session
        # Point our socket to the sock attribute of HTTPConnection 
        # (contained in the session), which contains the socket
        self.relaySocket = self.session.sock
        # Send the initial request to the server
        tosend = self.prepareRequest(data)
        self.relaySocket.send(tosend)
        # Send the response back to the client
        self.transferResponse()
        return True

    def getHeaders(self, data):
        # Get the headers from the request, ignore first "header"
        # since this is the HTTP method, identifier, version
        headerSize = data.find(EOL+EOL)
        headers = data[:headerSize].split(EOL)[1:]
        headerDict = {hdrKey.split(':')[0].lower():hdrKey.split(':', 1)[1] for hdrKey in headers}
        return headerDict

    def transferResponse(self):
        data = self.relaySocket.recv(self.packetSize)
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers['content-length'].strip())
            readSize = self.packetSize
            # Make sure we send the entire response, but don't keep it in memory
            self.socksSocket.send(data)
            while readSize < bodySize + headerSize + 4:
                data = self.relaySocket.recv(self.packetSize)
                readSize += len(data)
                self.socksSocket.send(data)
        except KeyError:
            # No body in the response, send as-is
            self.socksSocket.send(data)

    def prepareRequest(self, data):
        # Parse the HTTP data, removing headers that break stuff
        response = []
        for part in data.split(EOL):
            # This means end of headers, stop parsing here
            if part == '':
                break
            # Remove the Basic authentication header
            if 'authorization' in part.lower():
                continue
            # Don't close the connection
            if 'connection: close' in part.lower():
                response.append('Connection: Keep-Alive')
                continue
            # If we are here it means we want to keep the header
            response.append(part)
        # Append the body
        response.append('')
        response.append(data.split(EOL+EOL)[1])
        return EOL.join(response)


    def tunnelConnection(self):
        while True:
            data = self.socksSocket.recv(self.packetSize)
            # If this returns with an empty string, it means the socket was closed
            if data == '':
                return
            # Pass the request to the server
            tosend = self.prepareRequest(data)
            self.relaySocket.send(tosend)
            # Send the response back to the client
            self.transferResponse()

    @staticmethod
    def keepAlive(connection):
        # Do a HEAD for favicon.ico
        connection.request('HEAD','/favicon.ico')
        connection.getresponse()

