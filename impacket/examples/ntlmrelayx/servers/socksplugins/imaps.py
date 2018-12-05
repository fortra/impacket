# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the IMAPS Protocol
#
# Author:
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  A simple SOCKS server that proxies a connection to relayed IMAPS connections
#
# ToDo:
#
from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksplugins.imap import IMAPSocksRelay
from impacket.examples.ntlmrelayx.utils.ssl import SSLServerMixin
from OpenSSL import SSL

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "IMAPSSocksRelay"
EOL = '\r\n'

class IMAPSSocksRelay(SSLServerMixin, IMAPSocksRelay):
    PLUGIN_NAME = 'IMAPS Socks Plugin'
    PLUGIN_SCHEME = 'IMAPS'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        IMAPSocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 993

    def skipAuthentication(self):
        LOG.debug('Wrapping IMAP client connection in TLS/SSL')
        self.wrapClientConnection()
        try:
            if not IMAPSocksRelay.skipAuthentication(self):
                # Shut down TLS connection
                self.socksSocket.shutdown()
                return False
        except Exception, e:
            LOG.debug('IMAPS: %s' % str(e))
            return False
        # Change our outgoing socket to the SSL object of IMAP4_SSL
        self.relaySocket = self.session.sslobj
        return True

    def tunnelConnection(self):
        keyword = ''
        tag = ''
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
            except SSL.ZeroReturnError:
                # The SSL connection was closed, return
                break
            # Set the new keyword, unless it is false, then break out of the function
            result = self.processTunnelData(keyword, tag, data)
            if result is False:
                break
            # If its not false, it's a tuple with the keyword and tag
            keyword, tag = result

        if tag != '':
            # Store the tag in the session so we can continue
            tag = int(tag)
            if self.idleState is True:
                self.relaySocket.sendall('DONE%s' % EOL)
                self.relaySocketFile.readline()

            if self.shouldClose:
                tag += 1
                self.relaySocket.sendall('%s CLOSE%s' % (tag, EOL))
                self.relaySocketFile.readline()

            self.session.tagnum = tag + 1
