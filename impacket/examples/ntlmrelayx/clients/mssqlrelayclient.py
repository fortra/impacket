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
# MSSQL client for relaying NTLMSSP authentication to MSSQL servers
#
import logging
import random
import string

from impacket import tds
from impacket.tds import DummyPrint, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF, TDS_PRE_LOGIN, TDS_LOGIN, TDS_INIT_LANG_FATAL, \
    TDS_ODBC_ON, TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN7, TDS_SSPI, TDS_LOGINACK_TOKEN

try:
    import OpenSSL
    from OpenSSL import SSL, crypto
except Exception:
    logging.critical("pyOpenSSL is not installed, can't continue")

class MSSQLRelayClient(tds.MSSQL):
    def __init__(self, address, port=1433, rowsPrinter=DummyPrint()):
        tds.MSSQL.__init__(self,address, port, rowsPrinter)
        self.resp = None

    def init_connection(self):
        self.connect()
        #This is copied from tds.py
        resp = self.preLogin()
        if resp['Encryption'] == TDS_ENCRYPT_REQ or resp['Encryption'] == TDS_ENCRYPT_OFF:
            logging.info("Encryption required, switching to TLS")

            # Switching to TLS now
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            ctx.set_cipher_list('RC4')
            tls = SSL.Connection(ctx,None)
            tls.set_connect_state()
            while True:
                try:
                    tls.do_handshake()
                except SSL.WantReadError:
                    data = tls.bio_read(4096)
                    self.sendTDS(TDS_PRE_LOGIN, data,0)
                    tds = self.recvTDS()
                    tls.bio_write(tds['Data'])
                else:
                    break

            # SSL and TLS limitation: Secure Socket Layer (SSL) and its replacement, 
            # Transport Layer Security(TLS), limit data fragments to 16k in size.
            self.packetSize = 16*1024-1
            self.tlsSocket = tls
        self.resp = resp

    def sendNegotiate(self,negotiateMessage):
        self.init_connection()
        #Also partly copied from tds.py
        login = TDS_LOGIN()

        login['HostName'] = (''.join([random.choice(string.letters) for _ in range(8)])).encode('utf-16le')
        login['AppName']  = (''.join([random.choice(string.letters) for _ in range(8)])).encode('utf-16le')
        login['ServerName'] = self.server.encode('utf-16le')
        login['CltIntName']  = login['AppName']
        login['ClientPID'] = random.randint(0,1024)
        login['PacketSize'] = self.packetSize
        login['OptionFlags2'] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON    
        login['OptionFlags2'] |= TDS_INTEGRATED_SECURITY_ON
        # NTLMSSP Negotiate
        auth = negotiateMessage
        login['SSPI'] = str(auth)

        login['Length'] = len(str(login))

        # Send the NTLMSSP Negotiate
        self.sendTDS(TDS_LOGIN7, str(login))

        # According to the spects, if encryption is not required, we must encrypt just 
        # the first Login packet :-o 
        if self.resp['Encryption'] == TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds = self.recvTDS()
        return tds['Data'][3:]

    def sendAuth(self,authenticateMessageBlob, serverChallenge=None):
        #Also partly copied from tds.py
        self.sendTDS(TDS_SSPI, str(authenticateMessageBlob))
        tds = self.recvTDS()
        self.replies = self.parseReply(tds['Data'])
        if self.replies.has_key(TDS_LOGINACK_TOKEN):
            #Once we are here, there is a full connection and we can
            #do whatever the current user has rights to do
            return True
        else:
            return False

    #SMB Relay server needs this
    @staticmethod
    def get_encryption_key():
        return None