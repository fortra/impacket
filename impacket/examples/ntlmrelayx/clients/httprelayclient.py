#!/usr/bin/python
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
import requests
import base64

class HTTPRelayClient:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.lastresult = None

    def sendNegotiate(self,negotiateMessage):
        #Check if server wants auth
        res = self.session.get(self.target)
        if res.status_code != 401:
            logging.info('Status code returned: %d. Authentication does not seem required for URL' % res.status_code)
        try:
            if 'NTLM' not in res.headers['WWW-Authenticate']:
                logging.error('NTLM Auth not offered by URL, offered protocols: %s' % res.headers['WWW-Authenticate'])
                return False
        except KeyError:
            logging.error('No authentication requested by the server for url %s' % self.target)
            return False
        #Negotiate auth
        negotiate = base64.b64encode(negotiateMessage)
        headers = {'Authorization':'NTLM %s' % negotiate}
        res = self.session.get(self.target,headers=headers)
        try:
            serverChallenge = base64.b64decode(res.headers['WWW-Authenticate'][5:])
            return serverChallenge
        except (IndexError, KeyError):
            logging.error('No NTLM challenge returned from server')

    def sendAuth(self,authenticateMessageBlob, serverChallenge=None):
        #Negotiate auth
        auth = base64.b64encode(authenticateMessageBlob)
        headers = {'Authorization':'NTLM %s' % auth}
        res = self.session.get(self.target,headers=headers)
        if res.status_code == 401:
            return False
        else:
            logging.info('HTTP server returned error code %d, treating as a succesful login' % res.status_code)
            #Cache this
            self.lastresult = res
            return True

    #SMB Relay server needs this
    @staticmethod
    def get_encryption_key():
        return None