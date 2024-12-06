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
        if not LDAPSocksRelay.skipAuthentication(self):
            # Shut down TLS connection
            self.socksSocket.shutdown()
            return False

        return True
    
    def recv_from_send_to(self, recv_from, send_to, recv_from_is_server: bool):
        '''
        Simple helper that receives data on the recv_from socket and sends it to send_to socket.

        - The recv_from_is_server allows to properly stop the relay when the server closes connection.
        - This method is called by the tunnelConnection method implemented for LDAPSocksRelay, it is
        redefined here to support TLS.
        '''

        while not self.stop_event.is_set():
            if recv_from.pending() == 0 and not select.select([recv_from], [], [], 1.0)[0]:
                # No data ready to be read from recv_from
                continue

            try:
                data = recv_from.recv(LDAPSocksRelay.MSG_SIZE)
            except Exception:
                if recv_from_is_server:
                    self.server_is_gone = True

                self.stop_event.set()
                return

            LOG.debug(f'Received {len(data)} bytes from {"server" if recv_from_is_server else "client"}')

            if data == b'':
                if recv_from_is_server:
                    self.server_is_gone = True

                self.stop_event.set()
                return
            
            try:
                send_to.send(data)
            except Exception:
                if not recv_from_is_server:
                    self.server_is_gone = True

                self.stop_event.set()
                return

