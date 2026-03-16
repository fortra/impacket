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
#   MSSQL (TDS) Protocol Client
#   MSSQL client for relaying NTLMSSP authentication to MSSQL servers
#
# Author:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Aurélien Chalot (@Defte_) rework the TLS handshake as in tds.py
#
# ToDo:
#   [ ] Handle SQL Authentication
#

import struct
import random
import string

from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.tds import MSSQL, DummyPrint, TDS_ENCRYPT_OFF, \
    TDS_LOGIN, TDS_INIT_LANG_FATAL, TDS_ODBC_ON, \
    TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN7, TDS_SSPI, TDS_LOGINACK_TOKEN
from impacket.ntlm import NTLMAuthChallenge
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASS = "MSSQLRelayClient"

class MYMSSQL(MSSQL):
    def __init__(self, address, port=1433, rowsPrinter=DummyPrint()):
        MSSQL.__init__(self, address, port, rowsPrinter)
        self.resp = None
        self.sessionData = {}

    def initConnection(self):
        self.connect()
        self.resp = self._negotiate_encryption()
        return True

    def sendNegotiate(self, negotiateMessage):
        login = TDS_LOGIN()

        login['HostName'] = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode('utf-16le')
        login['AppName']  = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode('utf-16le')
        login['ServerName'] = self.server.encode('utf-16le')
        login['CltIntName']  = login['AppName']
        login['ClientPID'] = random.randint(0, 1024)
        login['PacketSize'] = self.packetSize
        login['OptionFlags2'] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON | TDS_INTEGRATED_SECURITY_ON

        # NTLMSSP Negotiate
        login['SSPI'] = negotiateMessage
        login['Length'] = len(login.getData())

        # Send the NTLMSSP Negotiate
        self.sendTDS(TDS_LOGIN7, login.getData())

        # According to the specs, if encryption is not required, we must encrypt just
        # the first Login packet :-o
        # In TDS 8.0 mode, the socket is already TLS-wrapped, so we don't touch tlsSocket
        if not self.tds8 and self.resp['Encryption'] == TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds = self.recvTDS()
        self.sessionData['NTLM_CHALLENGE'] = tds

        challenge = NTLMAuthChallenge()
        challenge.fromString(tds['Data'][3:])

        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if struct.unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        self.sendTDS(TDS_SSPI, token)
        tds = self.recvTDS()
        self.replies = self.parseReply(tds['Data'])
        if TDS_LOGINACK_TOKEN in self.replies:
            self.sessionData['AUTH_ANSWER'] = tds
            return None, STATUS_SUCCESS
        else:
            self.printReplies()
            return None, STATUS_ACCESS_DENIED

    def close(self):
        return self.disconnect()


class MSSQLRelayClient(ProtocolClient):
    PLUGIN_NAME = "MSSQL"

    def __init__(self, serverConfig, targetHost, targetPort=1433, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, targetHost, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity

        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None

    def initConnection(self):
        self.session = MYMSSQL(self.targetHost, self.targetPort)
        self.session.initConnection()
        return True

    def keepAlive(self):
        # Don't know yet what needs to be done for TDS
        pass

    def killConnection(self):
        if self.session is not None:
            self.session.disconnect()
            self.session = None

    def sendNegotiate(self, negotiateMessage):
        return self.session.sendNegotiate(negotiateMessage)

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        self.sessionData = self.session.sessionData
        return self.session.sendAuth(authenticateMessageBlob, serverChallenge)

    # Delegate methods used by MSSQLAttack
    def sql_query(self, query):
        return self.session.batch(query)

    def printReplies(self):
        return self.session.printReplies()

    def printRows(self):
        return self.session.printRows()
