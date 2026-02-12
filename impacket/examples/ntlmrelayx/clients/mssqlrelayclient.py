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

import ssl
import struct
import random
import string
import socket

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.tds import MSSQL, DummyPrint, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF, TDS_ENCRYPT_ON, TDS_ENCRYPT_NOT_SUP, \
    TDS_ENCRYPT_STRICT, TDS_PRE_LOGIN, TDS_PRELOGIN, TDS_LOGIN, TDS_INIT_LANG_FATAL, TDS_ODBC_ON, \
    TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN7, TDS_SSPI, TDS_LOGINACK_TOKEN
from impacket.mssql.version import MSSQL_VERSION
from impacket.ntlm import NTLMAuthChallenge
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASS = "MSSQLRelayClient"

class MYMSSQL(MSSQL):
    def __init__(self, address, port=1433, rowsPrinter=DummyPrint()):
        MSSQL.__init__(self, address, port, rowsPrinter)
        self.resp = None
        self.sessionData = {}
        self.tds8 = False

    def _setup_tds8(self):
        """Wrap the TCP socket in TLS for TDS 8.0 strict encryption."""
        LOG.debug("(TDS8) Setting up TDS 8.0 strict encryption")
        context = ssl.SSLContext()
        context.set_ciphers('ALL:@SECLEVEL=0')
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["tds/8.0"])
        LOG.debug("(TDS8) Wrapping socket with TLS (server: %s)" % self.server)
        self.socket = context.wrap_socket(self.socket, server_hostname=self.server)
        self.tds8 = True
        self.packetSize = 16 * 1024 - 1
        LOG.info("(TDS8) TDS 8.0 TLS connection established")

    def initConnection(self):
        LOG.debug("(MSSQL) Initiating MSSQL connection to %s:%d" % (self.server, self.port))

        # Start with plain TDS and negotiate encryption
        self.connect()
        LOG.debug("(MSSQL) TCP connection established")

        # Send initial preLogin with ENCRYPT_OFF (support encryption but don't require it)
        prelogin = TDS_PRELOGIN()
        prelogin["Version"] = b"\x08\x00\x01\x55\x00\x00"
        prelogin["Encryption"] = TDS_ENCRYPT_OFF
        prelogin["ThreadID"] = struct.pack("<L", random.randint(0, 65535))
        prelogin["Instance"] = b"MSSQLServer\x00"

        LOG.debug("(MSSQL) Sending preLogin packet (ENCRYPT_OFF)")
        try:
            self.sendTDS(TDS_PRE_LOGIN, prelogin.getData(), 0)
            LOG.debug("(MSSQL) Waiting for preLogin response...")
            tds = self.recvTDS()
            resp = TDS_PRELOGIN(tds["Data"])
            self.mssql_version = MSSQL_VERSION(resp["Version"])
            LOG.debug("(MSSQL) Received preLogin response, Encryption=%d" % resp['Encryption'])
        except Exception as e:
            # Plain TDS prelogin failed — server likely requires TDS 8.0 from the start
            LOG.debug("(MSSQL) Plain TDS prelogin failed (%s: %s), trying TDS 8.0" % (type(e).__name__, e))
            try:
                self.disconnect()
            except:
                pass
            self.connect()
            self._setup_tds8()
            resp = self.preLogin()
            LOG.debug("(MSSQL) TDS 8.0 preLogin successful, Encryption=%d" % resp['Encryption'])
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
            LOG.debug("(MSSQL) TDS 8.0 preLogin successful")
        elif resp['Encryption'] in (TDS_ENCRYPT_REQ, TDS_ENCRYPT_ON):
            # Server requires encryption, use STARTTLS (TLS inside TDS packets via MemoryBIO)
            LOG.info("(MSSQL) Encryption required, switching to TLS (STARTTLS)")
            # Creates a TLS context
            context = ssl.SSLContext()
            context.set_ciphers('ALL:@SECLEVEL=0')
            context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            context.verify_mode = ssl.CERT_NONE

            # Here comes the important part, MSSQL server does not expect a raw TLS socket
            # Instead it expects TDS packets to be sent in which TLS data is embedded
            # Something like TDS_PACKET["Data"] = TLS_ENCRYPTED(data)
            # To setup such a TLS tunnel inside another program, we need to use a STARTTLS like mechanism
            # Which relies on MemoryBIO that are used to send data to the TLS context and receive data from it as well
            # IN_BIO is where we send data to be encrypted and sent to the MSSQL server
            in_bio = ssl.MemoryBIO()
            # OUT_BIO is where we read data sent by the MSSQL server inside a TDS packet
            out_bio = ssl.MemoryBIO()

            # Now we can create the TLS object that will be used to manage handshake and data processing
            tls = context.wrap_bio(in_bio, out_bio)

            # So first let's handshake with the remote MSSQL server
            LOG.debug("(MSSQL) Starting STARTTLS handshake")
            while True:
                try:
                    # This sends the TLS client hello
                    tls.do_handshake()
                except ssl.SSLWantReadError:
                    # If we get a SSLWantReadError then it means the server received enough data and want to send some to us
                    # So we read the data sent by the server and we send it back to it inside a TDS_PRE_LOGIN packet
                    # That's the actual TLS server hello
                    data = out_bio.read(4096)
                    LOG.debug("(MSSQL) Sending TLS handshake data (%d bytes)" % len(data))
                    self.sendTDS(TDS_PRE_LOGIN, data, 0)

                    # Now we read data one more time to extract the final TLS message
                    tds_packet = self.recvTDS(4096)
                    tls_data = tds_packet["Data"]

                    # And we send that data to the in_bio object to complete the handshake
                    LOG.debug("(MSSQL) Received TLS handshake data (%d bytes)" % len(tls_data))
                    in_bio.write(tls_data)
                else:
                    LOG.debug("(MSSQL) STARTTLS handshake complete")
                    break

            # At this point the TLS context is set up so we just store object inside the MSSQL class
            # That will be used to encrypt/decrypt data and send them to the MSSQL server
            self.packetSize = 16 * 1024 - 1
            self.tlsSocket = tls
            self.in_bio = in_bio
            self.out_bio = out_bio

        LOG.debug("(MSSQL) initConnection() complete")
        self.resp = resp
        return True

    def sendNegotiate(self,negotiateMessage):
        #Also partly copied from tds.py
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
        LOG.debug("(MSSQL) sendNegotiate: TDS8=%s, PacketSize=%d, Encryption=%d, tlsSocket=%s" %
                  (self.tds8, self.packetSize, self.resp['Encryption'], self.tlsSocket is not None))
        self.sendTDS(TDS_LOGIN7, login.getData())

        # According to the specs, if encryption is not required, we must encrypt just
        # the first Login packet :-o
        # In TDS 8.0 mode, the socket is already TLS-wrapped, so we don't use tlsSocket
        if not self.tds8 and self.resp['Encryption'] == TDS_ENCRYPT_OFF:
            LOG.debug("(MSSQL) Disabling tlsSocket after first login packet")
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

        LOG.debug("(MSSQL) sendAuth: TDS8=%s, tlsSocket=%s" % (self.tds8, self.tlsSocket is not None))
        self.sendTDS(TDS_SSPI, token)
        tds = self.recvTDS()
        LOG.debug("(MSSQL) sendAuth: received %d bytes" % len(tds['Data']))
        self.replies = self.parseReply(tds['Data'])
        if TDS_LOGINACK_TOKEN in self.replies:
            #Once we are here, there is a full connection and we can
            #do whatever the current user has rights to do
            self.sessionData['AUTH_ANSWER'] = tds
            LOG.debug("(MSSQL) Authentication successful")
            return None, STATUS_SUCCESS
        else:
            LOG.debug("(MSSQL) Authentication failed")
            self.printReplies()
            return None, STATUS_ACCESS_DENIED

    def sendTDS(self, packetType, data, packetID=1):
        LOG.debug("(MSSQL) sendTDS: type=0x%02x, size=%d, TDS8=%s, tlsSocket=%s" %
                  (packetType, len(data), self.tds8, self.tlsSocket is not None))
        return super().sendTDS(packetType, data, packetID)

    def recvTDS(self, packetSize=None):
        LOG.debug("(MSSQL) recvTDS: TDS8=%s, tlsSocket=%s" % (self.tds8, self.tlsSocket is not None))
        result = super().recvTDS(packetSize)
        LOG.debug("(MSSQL) recvTDS: received type=0x%02x, size=%d" % (result['Type'], len(result['Data'])))
        if len(result['Data']) > 0:
            LOG.debug("(MSSQL) recvTDS: first 16 bytes: %s" % result['Data'][:16].hex())
        return result

    def sql_query(self, cmd, tuplemode=False, wait=True):
        """Override sql_query (alias for batch) to add ALL_HEADERS for TDS 8.0"""
        return self.batch(cmd, tuplemode, wait)

    def batch(self, cmd, tuplemode=False, wait=True):
        """Override batch to add ALL_HEADERS for TDS 8.0"""
        LOG.debug("(MSSQL) batch() called: TDS8=%s, cmd='%s'" % (self.tds8, cmd[:50]))
        if self.tds8:
            # TDS 8.0 requires ALL_HEADERS section before SQL text
            # Minimal ALL_HEADERS with transaction descriptor
            from impacket.tds import TDS_SQL_BATCH

            self.rows = []
            self.colMeta = []
            self.lastError = False

            # Build ALL_HEADERS
            # Format: [TotalLength:DWORD][HeaderLength:DWORD][HeaderType:WORD][TransactionDescriptor:QWORD][OutstandingRequestCount:DWORD]
            all_headers = struct.pack('<I', 22)  # Total length of ALL_HEADERS (22 bytes)
            all_headers += struct.pack('<I', 18)  # Length of this header (18 bytes)
            all_headers += struct.pack('<H', 2)   # Header type 2 = Transaction Descriptor
            all_headers += struct.pack('<Q', 0)   # Transaction descriptor (0 = no transaction)
            all_headers += struct.pack('<I', 1)   # Outstanding request count

            # Append SQL text as UTF-16LE
            sql_text = (cmd + "\r\n").encode("utf-16le")
            packet_data = all_headers + sql_text

            LOG.debug("(MSSQL) Sending SQL_BATCH with ALL_HEADERS (%d bytes total)" % len(packet_data))
            self.sendTDS(TDS_SQL_BATCH, packet_data)

            if wait:
                tds = self.recvTDS()
                self.replies = self.parseReply(tds["Data"], tuplemode)
                return self.rows
            else:
                return True
        else:
            # Use parent's batch method for non-TDS8
            return super().batch(cmd, tuplemode, wait)

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
        LOG.debug("(MSSQLRelayClient) initConnection() called for %s:%d" % (self.targetHost, self.targetPort))
        self.session = MYMSSQL(self.targetHost, self.targetPort)
        LOG.debug("(MSSQLRelayClient) MYMSSQL instance created, calling session.initConnection()")
        self.session.initConnection()
        LOG.debug("(MSSQLRelayClient) initConnection() complete")
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
        LOG.debug("(MSSQLRelayClient) sql_query() delegating to session.batch()")
        return self.session.batch(query)

    def printReplies(self):
        return self.session.printReplies()

    def printRows(self):
        return self.session.printRows()
