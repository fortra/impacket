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
# HTTP(s) client for relaying NTLMSSP authentication to webservers
#
import logging
import re
import ssl
from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64

class HTTPRelayClient:
    def __init__(self, target):
        # Target comes as protocol://target:port/path
        self.target = target
        proto, host, path = target.split(':')
        host = host[2:]
        self.path = '/' + path.split('/', 1)[1]
        if proto.lower() == 'https':
            #Create unverified (insecure) context
            try:
                uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                self.session = HTTPSConnection(host,context=uv_context)
            except AttributeError:
                #This does not exist on python < 2.7.11
                self.session = HTTPSConnection(host)
        else:
            self.session = HTTPConnection(host)
        self.lastresult = None

    def sendNegotiate(self,negotiateMessage):
        #Check if server wants auth
        self.session.request('GET', self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            logging.info('Status code returned: %d. Authentication does not seem required for URL' % res.status)
        try:
            if 'NTLM' not in res.getheader('WWW-Authenticate'):
                logging.error('NTLM Auth not offered by URL, offered protocols: %s' % res.getheader('WWW-Authenticate'))
                return False
        except KeyError:
            logging.error('No authentication requested by the server for url %s' % self.target)
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
            return serverChallenge
        except (IndexError, KeyError, AttributeError):
            logging.error('No NTLM challenge returned from server')

    def sendAuth(self,authenticateMessageBlob, serverChallenge=None):
        #Negotiate auth
        auth = base64.b64encode(authenticateMessageBlob)
        headers = {'Authorization':'NTLM %s' % auth}
        self.session.request('GET', self.path,headers=headers)
        res = self.session.getresponse()
        if res.status == 401:
            return False
        else:
            logging.info('HTTP server returned error code %d, treating as a succesful login' % res.status)
            #Cache this
            self.lastresult = res.read()
            return True

    #SMB Relay server needs this
    @staticmethod
    def get_encryption_key():
        return None