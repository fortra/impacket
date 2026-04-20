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
#   A Socks Proxy for the MSSQL Protocol
#
#   A simple SOCKS server that proxy connection to relayed connections
#
# Author:
#   Alberto Solino (@agsolino)
#

import os
import socket
import struct
import random
import ssl
import tempfile

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay
from impacket.examples.ntlmrelayx.utils.ssl import generateImpacketCert
from impacket.tds import TDSPacket, TDS_STATUS_NORMAL, TDS_STATUS_EOM, TDS_PRE_LOGIN, TDS_ENCRYPT_NOT_SUP, TDS_TABULAR, \
    TDS_LOGIN, TDS_LOGIN7, TDS_PRELOGIN, TDS_INTEGRATED_SECURITY_ON, TDS_SQL_BATCH, TDS_ENCRYPT_STRICT
from impacket.ntlm import NTLMAuthChallengeResponse
try:
    from OpenSSL import SSL
except:
    LOG.critical("pyOpenSSL is not installed, can't continue")
    raise

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "MSSQLSocksRelay"

class MSSQLSocksRelay(SocksRelay):
    PLUGIN_NAME = 'MSSQL Socks Plugin'
    PLUGIN_SCHEME = 'MSSQL'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.isSSL = False
        self.tlsSocket = None
        self.packetSize = 32763
        self.session = None
        self.client_tds8 = False

    @staticmethod
    def getProtocolPort():
        return 1433

    def initConnection(self):
        pass

    def _backend_requires_tds8(self):
        for user, relay in self.activeRelays.items():
            if user in ('data', 'scheme'):
                continue
            session = getattr(relay.get('protocolClient'), 'session', None)
            if getattr(session, 'tds8', False):
                return True
        return False

    def _get_prelogin_encryption(self):
        if self.client_tds8 or self._backend_requires_tds8():
            return TDS_ENCRYPT_STRICT
        return TDS_ENCRYPT_NOT_SUP

    def _wrap_client_connection_for_tds8(self):
        cert_path = os.path.join(tempfile.gettempdir(), 'impacket-mssql-socks.pem')
        if not os.path.exists(cert_path):
            generateImpacketCert(cert_path)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.set_ciphers('ALL:@SECLEVEL=0')
        context.set_alpn_protocols(['tds/8.0'])
        context.load_cert_chain(cert_path)
        self.socksSocket = context.wrap_socket(self.socksSocket, server_side=True)
        self.client_tds8 = True

    def _maybe_switch_client_to_tds8(self):
        if not self._backend_requires_tds8():
            return

        first_byte = self.socksSocket.recv(1, socket.MSG_PEEK)
        if first_byte and first_byte[:1] == b'\x16':
            self._wrap_client_connection_for_tds8()

    def _should_wrap_sql_batch_for_backend(self):
        return getattr(self.session, 'tds8', False) and not self.client_tds8

    def skipAuthentication(self):
        self._maybe_switch_client_to_tds8()

        # 1. First packet should be a TDS_PRELOGIN()
        tds = self.recvTDS()
        if tds['Type'] != TDS_PRE_LOGIN:
            # Unexpected packet
            LOG.debug('Unexpected packet type %d instead of TDS_PRE_LOGIN' % tds['Type'])
            return False

        prelogin = TDS_PRELOGIN()
        prelogin['Version'] = b"\x08\x00\x01\x55\x00\x00"
        prelogin['Encryption'] = self._get_prelogin_encryption()
        prelogin['ThreadID'] = struct.pack('<L',random.randint(0,65535))
        prelogin['Instance'] = b'\x00'

        # Answering who we are
        self.sendTDS(TDS_TABULAR, prelogin.getData(), 0)

        if prelogin['Encryption'] == TDS_ENCRYPT_STRICT and not self.client_tds8:
            return False

        # 2. Packet should be a TDS_LOGIN
        tds = self.recvTDS()

        if tds['Type'] != TDS_LOGIN7:
            # Unexpected packet
            LOG.debug('Unexpected packet type %d instead of TDS_LOGIN' % tds['Type'])
            return False

        login = TDS_LOGIN()
        login.fromString(tds['Data'])
        if login['OptionFlags2'] & TDS_INTEGRATED_SECURITY_ON:
            # Windows Authentication enabled
            # Send the resp we've got from the original relay
            TDSResponse = self.sessionData['NTLM_CHALLENGE']
            self.sendTDS(TDSResponse['Type'], TDSResponse['Data'], 0)

            # Here we should get the NTLM_AUTHENTICATE
            tds = self.recvTDS()
            authenticateMessage = NTLMAuthChallengeResponse()
            authenticateMessage.fromString(tds['Data'])
            self.username = authenticateMessage['user_name']
            try:
                self.username = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                      authenticateMessage['user_name'].decode('utf-16le'))).upper()
            except UnicodeDecodeError:
                # Not Unicode encoded?
                self.username = ('%s/%s' % (authenticateMessage['domain_name'], authenticateMessage['user_name'])).upper()

        else:
            if login['UserName'].find('/') >=0:
                try:
                    self.username = login['UserName'].upper().decode('utf-16le')
                except UnicodeDecodeError:
                    # Not Unicode encoded?
                    self.username = login['UserName'].upper()

            else:
                try:
                    self.username = ('/%s' % login['UserName'].decode('utf-16le')).upper()
                except UnicodeDecodeError:
                    # Not Unicode encoded?
                    self.username = ('/%s' % login['UserName']).upper()

        # Check if we have a connection for the user
        if self.username in self.activeRelays:
            # Check the connection is not inUse
            if self.activeRelays[self.username]['inUse'] is True:
                LOG.error('MSSQL: Connection for %s@%s(%s) is being used at the moment!' % (
                    self.username, self.targetHost, self.targetPort))
                return False
            else:
                LOG.info('MSSQL: Proxying client session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.sessionData = self.activeRelays[self.username].get('data', self.sessionData)
                self.session = self.activeRelays[self.username]['protocolClient'].session
        else:
            LOG.error('MSSQL: No session for %s@%s(%s) available' % (
                self.username, self.targetHost, self.targetPort))
            return False

        # We have a session relayed, let's answer back with the data
        if login['OptionFlags2'] & TDS_INTEGRATED_SECURITY_ON:
            TDSResponse = self.sessionData['AUTH_ANSWER']
            self.sendTDS(TDSResponse['Type'], TDSResponse['Data'], 0)
        else:
            TDSResponse = self.sessionData['AUTH_ANSWER']
            self.sendTDS(TDSResponse['Type'], TDSResponse['Data'], 0)

        return True

    def tunnelConnection(self):
        # For the rest of the remaining packets, we should just read and send. Except when trying to log out,
        # that's forbidden! ;)
        try:
            while True:
                # 1. Get Data from client
                tds = self.recvTDS()
                packet_data = tds['Data']
                if tds['Type'] == TDS_SQL_BATCH and self._should_wrap_sql_batch_for_backend():
                    # Legacy local clients do not add TDS 8.0 ALL_HEADERS themselves,
                    # so strict backend sessions still need the header injected here.
                    packet_data = self.session._wrap_sql_batch_data(packet_data)
                # 2. Send it to the relayed session
                self.session.sendTDS(tds['Type'], packet_data, 0)
                # 3. Get the target's answer
                tds = self.session.recvTDS()
                # 4. Send it back to the client
                self.sendTDS(tds['Type'], tds['Data'], 0)
        except EOFError:
            pass
        except Exception:
            # Probably an error here
            LOG.debug('Exception:', exc_info=True)

        return True

    def sendTDS(self, packetType, data, packetID = 1):
        if (len(data)-8) > self.packetSize:
            remaining = data[self.packetSize-8:]
            tds = TDSPacket()
            tds['Type'] = packetType
            tds['Status'] = TDS_STATUS_NORMAL
            tds['PacketID'] = packetID
            tds['Data'] = data[:self.packetSize-8]
            self.socketSendall(tds.getData())

            while len(remaining) > (self.packetSize-8):
                packetID += 1
                tds['PacketID'] = packetID
                tds['Data'] = remaining[:self.packetSize-8]
                self.socketSendall(tds.getData())
                remaining = remaining[self.packetSize-8:]
            data = remaining
            packetID+=1

        tds = TDSPacket()
        tds['Type'] = packetType
        tds['Status'] = TDS_STATUS_EOM
        tds['PacketID'] = packetID
        tds['Data'] = data
        self.socketSendall(tds.getData())

    def socketSendall(self,data):
        if self.tlsSocket is None:
            return self.socksSocket.sendall(data)
        else:
            self.tlsSocket.sendall(data)
            dd = self.tlsSocket.bio_read(self.packetSize)
            return self.socksSocket.sendall(dd)

    def socketRecv(self, packetSize):
        data = self.socksSocket.recv(packetSize)
        if self.tlsSocket is not None:
            dd = b''
            self.tlsSocket.bio_write(data)
            while True:
                try:
                    dd += self.tlsSocket.read(packetSize)
                except SSL.WantReadError:
                    data2 = self.socksSocket.recv(packetSize - len(data) )
                    self.tlsSocket.bio_write(data2)
                    pass
                else:
                    data = dd
                    break
        return data

    def recvTDS(self, packetSize=None):
        # Do reassembly here
        if packetSize is None:
            packetSize = self.packetSize
        packet_data = self.socketRecv(packetSize)
        if not packet_data:
            raise EOFError('MSSQL SOCKS client closed connection')
        packet = TDSPacket(packet_data)
        status = packet['Status']
        packetLen = packet['Length'] - 8
        while packetLen > len(packet['Data']):
            data = self.socketRecv(packetSize)
            packet['Data'] += data

        remaining = None
        if packetLen < len(packet['Data']):
            remaining = packet['Data'][packetLen:]
            packet['Data'] = packet['Data'][:packetLen]

        while status != TDS_STATUS_EOM:
            if remaining is not None:
                tmpPacket = TDSPacket(remaining)
            else:
                packet_data = self.socketRecv(packetSize)
                if not packet_data:
                    raise EOFError('MSSQL SOCKS client closed connection')
                tmpPacket = TDSPacket(packet_data)

            packetLen = tmpPacket['Length'] - 8
            while packetLen > len(tmpPacket['Data']):
                data = self.socketRecv(packetSize)
                tmpPacket['Data'] += data

            remaining = None
            if packetLen < len(tmpPacket['Data']):
                remaining = tmpPacket['Data'][packetLen:]
                tmpPacket['Data'] = tmpPacket['Data'][:packetLen]

            status = tmpPacket['Status']
            packet['Data'] += tmpPacket['Data']
            packet['Length'] += tmpPacket['Length'] - 8

        # print packet['Length']
        return packet
