import select
from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksplugins.ldap import LDAPSocksRelay
from impacket.examples.ntlmrelayx.utils.ssl import SSLServerMixin
from OpenSSL import SSL

PLUGIN_CLASS = "LDAPSSocksRelay"

class LDAPSSocksRelay(SSLServerMixin, LDAPSocksRelay):
    PLUGIN_NAME = 'LDAPS Socks Plugin'
    PLUGIN_SCHEME = 'LDAPS'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        LDAPSocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 636

    def skipAuthentication(self):
        LOG.debug('Wrapping client connection in TLS/SSL')
        self.wrapClientConnection()

        # Skip authentication using the same technique as LDAP
        try:
            if not LDAPSocksRelay.skipAuthentication(self):
                # Shut down TLS connection
                self.socksSocket.shutdown()
                return False
        except SSL.SysCallError:
            LOG.warning('Cannot wrap client socket in TLS/SSL')
            return False

        return True

    def wait_for_data(self, socket1, socket2):
        rready = []

        if socket1.pending():
            rready.append(socket1)
        if socket2.pending():
            rready.append(socket2)

        if not rready:
            rready, _, exc = select.select([socket1, socket2], [], [])

        return rready
