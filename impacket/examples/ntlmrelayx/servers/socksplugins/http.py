# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
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
            basicAuth = base64.b64decode(creds[6:])
            self.username = basicAuth.split(':')[0].upper()
            if '@' in self.username:
                # Workaround for clients which specify users with the full FQDN
                # such as ruler
                user, domain = self.username.split('@', 1)
                # Currently we only use the first part of the FQDN
                # this might break stuff on tools that do use an FQDN
                # where the domain NETBIOS name is not equal to the part
                # before the first .
                self.username = '%s/%s' % (domain.split('.')[0], user)

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
                    self.session = self.activeRelays[self.username]['protocolClient'].session
            else:
                LOG.error('HTTP: No session for %s@%s(%s) available' % (
                    self.username, self.targetHost, self.targetPort))
                return False

        except KeyError:
            # User didn't provide authentication yet, prompt for it
            LOG.debug('No authentication provided, prompting for basic authentication')
            reply = ['HTTP/1.1 401 Unauthorized','WWW-Authenticate: Basic realm="ntlmrelayx - provide a DOMAIN/username"','Connection: close','','']
            self.socksSocket.send(EOL.join(reply))
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
        headerDict = {hdrKey.split(':')[0].lower():hdrKey.split(':', 1)[1][1:] for hdrKey in headers}
        return headerDict

    def transferResponse(self):
        data = self.relaySocket.recv(self.packetSize)
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers['content-length'])
            readSize = len(data)
            # Make sure we send the entire response, but don't keep it in memory
            self.socksSocket.send(data)
            while readSize < bodySize + headerSize + 4:
                data = self.relaySocket.recv(self.packetSize)
                readSize += len(data)
                self.socksSocket.send(data)
        except KeyError:
            try:
                if headers['transfer-encoding'] == 'chunked':
                    # Chunked transfer-encoding, bah
                    LOG.debug('Server sent chunked encoding - transferring')
                    self.transferChunked(data, headers)
                else:
                    # No body in the response, send as-is
                    self.socksSocket.send(data)
            except KeyError:
                # No body in the response, send as-is
                self.socksSocket.send(data)

    def transferChunked(self, data, headers):
        headerSize = data.find(EOL+EOL)

        self.socksSocket.send(data[:headerSize + 4])

        body = data[headerSize + 4:]
        # Size of the chunk
        datasize = int(body[:body.find(EOL)], 16)
        while datasize > 0:
            # Size of the total body
            bodySize = body.find(EOL) + 2 + datasize + 2
            readSize = len(body)
            # Make sure we send the entire response, but don't keep it in memory
            self.socksSocket.send(body)
            while readSize < bodySize:
                maxReadSize = bodySize - readSize
                body = self.relaySocket.recv(min(self.packetSize, maxReadSize))
                readSize += len(body)
                self.socksSocket.send(body)
            body = self.relaySocket.recv(self.packetSize)
            datasize = int(body[:body.find(EOL)], 16)
        LOG.debug('Last chunk received - exiting chunked transfer')
        self.socksSocket.send(body)

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
        senddata = EOL.join(response)

        # Check if the body is larger than 1 packet
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        body = data[headerSize+4:]
        try:
            bodySize = int(headers['content-length'])
            readSize = len(data)
            while readSize < bodySize + headerSize + 4:
                data = self.socksSocket.recv(self.packetSize)
                readSize += len(data)
                senddata += data
        except KeyError:
            # No body, could be a simple GET or a POST without body
            # no need to check if we already have the full packet
            pass
        return senddata


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



