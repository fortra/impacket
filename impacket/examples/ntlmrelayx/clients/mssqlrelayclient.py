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

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.tds import MSSQL, DummyPrint, TDS_ENCRYPT_OFF, TDS_ENCRYPT_REQ, TDS_ENCRYPT_ON, \
    TDS_ENCRYPT_STRICT, TDS_LOGIN, TDS_INIT_LANG_FATAL, TDS_ODBC_ON, \
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

        # Use a short timeout for the initial preLogin — if the server requires
        # TDS 8.0 (Force Strict Encryption = Yes), it will silently close the
        # connection or never respond to a plain TDS preLogin.
        original_timeout = self.socket.gettimeout()
        self.socket.settimeout(5)

        try:
            resp = self.preLogin()
            self.socket.settimeout(original_timeout)
        except Exception as e:
            # Plain TDS preLogin failed — server likely requires TDS 8.0
            LOG.debug("(MSSQL) Plain TDS preLogin failed (%s: %s), trying TDS 8.0" % (type(e).__name__, e))
            try:
                self.disconnect()
            except Exception:
                pass
            self.connect()
            self._setup_tds8()
            resp = self.preLogin()
            self.resp = resp
            return True

        # Handle server encryption response
        if resp['Encryption'] == TDS_ENCRYPT_STRICT:
            # Server requires TDS 8.0 strict encryption — reconnect with TLS
            LOG.info("(MSSQL) Server requires TDS 8.0 (ENCRYPT_STRICT), reconnecting with TLS")
            self.disconnect()
            self.connect()
            self._setup_tds8()
            resp = self.preLogin()
        elif resp['Encryption'] in (TDS_ENCRYPT_REQ, TDS_ENCRYPT_ON, TDS_ENCRYPT_OFF):
            # TDS spec requires TLS for the login exchange even with ENCRYPT_OFF.
            # With ENCRYPT_OFF, TLS is dropped after the first login packet (handled in sendNegotiate).
            # With ENCRYPT_REQ/ENCRYPT_ON, TLS stays active for the entire session.
            LOG.info("(MSSQL) Encryption required, switching to TLS")
            self.set_tls_context()

        self.resp = resp
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
