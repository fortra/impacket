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
import random
import string
from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.tds import MSSQL, DummyPrint, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF, TDS_PRE_LOGIN, TDS_LOGIN, TDS_INIT_LANG_FATAL, \
    TDS_ODBC_ON, TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN7, TDS_SSPI, TDS_LOGINACK_TOKEN
from impacket.ntlm import NTLMAuthChallenge
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASS = "MSSQLRelayClient"

class MYMSSQL(MSSQL):
    def __init__(self, address, port=1433, rowsPrinter=DummyPrint()):
        MSSQL.__init__(self,address, port, rowsPrinter)
        self.resp = None
        self.sessionData = {}

    def initConnection(self):
        self.connect()
        #This is copied from tds.py
        resp = self.preLogin()
        if resp['Encryption'] == TDS_ENCRYPT_REQ or resp['Encryption'] == TDS_ENCRYPT_OFF:
            LOG.info("Encryption required, switching to TLS")
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
            # OUT_BIO is where we read data send by the MSSQL server inside a TDS packet
            out_bio = ssl.MemoryBIO()

            # Now we can create the TLS object that will be used to manage handshake and data processing
            tls = context.wrap_bio(in_bio, out_bio)

            # So first let's handshake with the remote MSSQL server
            while True:
                try:
                    # This sends the TLS client hello
                    tls.do_handshake()
                except ssl.SSLWantReadError:
                    # If we get a SSLWantReadError then it means the server received enough data and want to send some to us
                    # So we read the data sent by the server and we send it back to it inside a TDS_PRE_LOGIN packet
                    # That's the actual TLS server hello
                    data = out_bio.read(4096)
                    self.sendTDS(TDS_PRE_LOGIN, data, 0)

                    # Now we read data one more time to extract the final TLS message
                    tds_packet = self.recvTDS(4096)
                    tls_data = tds_packet["Data"]

                    # And we send that data to the in_bio object to complete the handshake
                    in_bio.write(tls_data)
                else:
                    break              

            # At this point the TLS context is set up so we just store object inside the MSSQL class
            # That will be used to encryp/decrpt data and send them to the MSSQL server
            self.packetSize = 16 * 1024 - 1
            self.tlsSocket = tls
            self.in_bio = in_bio
            self.out_bio = out_bio
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
        self.sendTDS(TDS_LOGIN7, login.getData())

        # According to the specs, if encryption is not required, we must encrypt just
        # the first Login packet :-o
        if self.resp['Encryption'] == TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds = self.recvTDS()
        self.sessionData['NTLM_CHALLENGE'] = tds

        challenge = NTLMAuthChallenge()
        challenge.fromString(tds['Data'][3:])

        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        self.sendTDS(TDS_SSPI, token)
        tds = self.recvTDS()
        self.replies = self.parseReply(tds['Data'])
        if TDS_LOGINACK_TOKEN in self.replies:
            #Once we are here, there is a full connection and we can
            #do whatever the current user has rights to do
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
