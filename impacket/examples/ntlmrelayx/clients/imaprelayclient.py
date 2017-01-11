#!/usr/bin/env python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description: 
# IMAP client for relaying NTLMSSP authentication to mailservers, for example Exchange
#
import logging
import imaplib
import base64

class IMAPRelayClient:
    def __init__(self, target):
        # Target comes as protocol://target:port
        self.target = target
        proto, host, port = target.split(':')
        host = host[2:]
        if int(port) == 993 or proto.upper() == 'IMAPS':
            self.session = imaplib.IMAP4_SSL(host,int(port))
        else:
            #assume non-ssl IMAP
            self.session = imaplib.IMAP4(host,port)
        if 'AUTH=NTLM' not in self.session.capabilities:
            logging.error('IMAP server does not support NTLM authentication!')
            return False
        self.authtag = self.session._new_tag()
        self.lastresult = None

    def sendNegotiate(self,negotiateMessage):
        #Negotiate auth
        negotiate = base64.b64encode(negotiateMessage)
        self.session.send('%s AUTHENTICATE NTLM%s' % (self.authtag,imaplib.CRLF))
        resp = self.session.readline().strip()
        if resp != '+':
            logging.error('IMAP Client error, expected continuation (+), got %s ' % resp)
            return False
        else:
            self.session.send(negotiate + imaplib.CRLF)
        try:
            serverChallengeBase64 = self.session.readline().strip()[2:] #first two chars are the continuation and space char
            serverChallenge = base64.b64decode(serverChallengeBase64)
            return serverChallenge
        except (IndexError, KeyError, AttributeError):
            logging.error('No NTLM challenge returned from IMAP server')

    def sendAuth(self,authenticateMessageBlob, serverChallenge=None):
        #Send auth
        auth = base64.b64encode(authenticateMessageBlob)
        self.session.send(auth + imaplib.CRLF)
        typ, data = self.session._get_tagged_response(self.authtag)
        if typ == 'OK':
            self.session.state = 'AUTH'
            return True
        else:
            logging.info('Auth failed - IMAP server said: %s' % ' '.join(data))
            return False

    #SMB Relay server needs this
    @staticmethod
    def get_encryption_key():
        return None