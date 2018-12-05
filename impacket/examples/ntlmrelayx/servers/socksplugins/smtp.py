# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the SMTP Protocol
#
# Author:
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  A simple SOCKS server that proxies a connection to relayed SMTP connections
#
# ToDo:
#
import logging
import base64

from smtplib import SMTP
from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "SMTPSocksRelay"
EOL = '\r\n'

class SMTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'SMTP Socks Plugin'
    PLUGIN_SCHEME = 'SMTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192

    @staticmethod
    def getProtocolPort():
        return 25

    def getServerEhlo(self):
        for key in self.activeRelays.keys():
            if key != 'data' and key != 'scheme':
                if self.activeRelays[key].has_key('protocolClient'):
                    return self.activeRelays[key]['protocolClient'].session.ehlo_resp

    def initConnection(self):
        pass

    def skipAuthentication(self):
        self.socksSocket.send('220 Microsoft ESMTP MAIL Service ready'+EOL)

        # Next should be the client sending the EHLO command
        cmd, params = self.recvPacketClient().split(' ',1)
        if cmd.upper() == 'EHLO':
            clientcapabilities = self.getServerEhlo().split('\n')
            # Don't offer these AUTH options so the client won't use them
            # also don't offer STARTTLS since that will break things
            blacklist = ['X-EXPS GSSAPI NTLM', 'STARTTLS', 'AUTH NTLM']
            for cap in blacklist:
                if cap in clientcapabilities:
                    clientcapabilities.remove(cap)

            # Offer PLAIN auth for specifying the username
            if 'AUTH PLAIN' not in clientcapabilities:
                clientcapabilities.append('AUTH PLAIN')
            # Offer LOGIN for specifying the username
            if 'AUTH LOGIN' not in clientcapabilities:
                clientcapabilities.append('AUTH LOGIN')

            LOG.debug('SMTP: Sending mirrored capabilities from server: %s' % ', '.join(clientcapabilities))
            # Prepare capabilities
            delim = EOL+'250-'
            caps = delim.join(clientcapabilities[:-1]) + EOL + '250 ' + clientcapabilities[-1] + EOL
            self.socksSocket.send('250-%s' % caps)
        else:
            LOG.error('SMTP: Socks plugin expected EHLO command, but got: %s %s' % (cmd, params))
            return False
        # next
        cmd, params = self.recvPacketClient().split(' ', 1)
        args = params.split(' ')
        if cmd.upper() == 'AUTH' and args[0] == 'LOGIN':
            # OK, ask for their username
            self.socksSocket.send('334 VXNlcm5hbWU6'+EOL)
            # Client will now send their AUTH
            data = self.socksSocket.recv(self.packetSize)
            # This contains base64(username), decode
            creds = base64.b64decode(data.strip())
            self.username = creds.upper()
            # Client will now send the password, we don't care for it but receive it anyway
            self.socksSocket.send('334 UGFzc3dvcmQ6'+EOL)
            data = self.socksSocket.recv(self.packetSize)
        elif cmd.upper() == 'AUTH' and args[0] == 'PLAIN':
            # Simple login
            # This contains base64(\x00username\x00password), decode and split
            creds = base64.b64decode(args[1].strip())
            self.username = creds.split('\x00')[1].upper()
        else:
            LOG.error('SMTP: Socks plugin expected AUTH PLAIN or AUTH LOGIN command, but got: %s %s' % (cmd, params))
            return False

        # Check if we have a connection for the user
        if self.activeRelays.has_key(self.username):
            # Check the connection is not inUse
            if self.activeRelays[self.username]['inUse'] is True:
                LOG.error('SMTP: Connection for %s@%s(%s) is being used at the moment!' % (
                    self.username, self.targetHost, self.targetPort))
                return False
            else:
                LOG.info('SMTP: Proxying client session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session
        else:
            LOG.error('SMTP: No session for %s@%s(%s) available' % (
                self.username, self.targetHost, self.targetPort))
            return False

        # We arrived here, that means all is OK
        self.socksSocket.send('235 2.7.0 Authentication successful%s' % EOL)
        self.relaySocket = self.session.sock
        self.relaySocketFile = self.session.file
        return True

    def tunnelConnection(self):
        doneIndicator = EOL+'.'+EOL
        while True:
            data = self.socksSocket.recv(self.packetSize)
            # If this returns with an empty string, it means the socket was closed
            if data == '':
                return
            info = data.strip().split(' ')
            # See if a QUIT command was sent, in which case we want to close
            # the connection to the client but keep the relayed connection alive
            if info[0].upper() == 'QUIT':
                LOG.debug('Client sent QUIT command, closing socks connection to client')
                self.socksSocket.send('221 2.0.0 Service closing transmission channel%s' % EOL)
                return
            self.relaySocket.send(data)
            data = self.relaySocket.recv(self.packetSize)
            self.socksSocket.send(data)
            if info[0].upper() == 'DATA':
                LOG.debug('SMTP Socks entering DATA transfer mode')
                # DATA transfer, forward to the server till done
                while data[-5:] != doneIndicator:
                    prevdata = data
                    data = self.socksSocket.recv(self.packetSize)
                    self.relaySocket.send(data)
                    if len(data) < 5:
                        # This can happen, the .CRLF will be in a packet after the first CRLF
                        # we stitch them back together for analysis
                        data = prevdata + data
                LOG.debug('SMTP Socks DATA transfer mode finished')
                # DATA done, forward server reply
                data = self.relaySocket.recv(self.packetSize)
                self.socksSocket.send(data)

    def recvPacketClient(self):
        data = self.socksSocket.recv(self.packetSize)
        return data

