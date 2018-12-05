# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the HTTPS Protocol
#
# Author:
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  A simple SOCKS server that proxies a connection to relayed HTTPS connections
#
# ToDo:
#

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksplugins.http import HTTPSocksRelay
from impacket.examples.ntlmrelayx.utils.ssl import SSLServerMixin
from OpenSSL import SSL

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSSocksRelay"
EOL = '\r\n'

class HTTPSSocksRelay(SSLServerMixin, HTTPSocksRelay):
    PLUGIN_NAME = 'HTTPS Socks Plugin'
    PLUGIN_SCHEME = 'HTTPS'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        HTTPSocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 443

    def skipAuthentication(self):
        LOG.debug('Wrapping client connection in TLS/SSL')
        self.wrapClientConnection()
        if not HTTPSocksRelay.skipAuthentication(self):
            # Shut down TLS connection
            self.socksSocket.shutdown()
            return False
        return True

    def tunnelConnection(self):
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
            except SSL.ZeroReturnError:
                # The SSL connection was closed, return
                return
            # Pass the request to the server
            tosend = self.prepareRequest(data)
            self.relaySocket.send(tosend)
            # Send the response back to the client
            self.transferResponse()
