# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A Socks Proxy for the MSSQL Protocol
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#  A simple SOCKS server that proxy connection to relayed connections
#
# ToDo:
#

import struct
import random
import logging

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay
from impacket.tds import TDSPacket, TDS_STATUS_NORMAL, TDS_STATUS_EOM, TDS_PRE_LOGIN, TDS_ENCRYPT_NOT_SUP, TDS_TABULAR, TDS_LOGIN, TDS_LOGIN7, TDS_PRELOGIN, TDS_INTEGRATED_SECURITY_ON
from impacket.ntlm import NTLMAuthChallengeResponse
try:
    import OpenSSL
    from OpenSSL import SSL, crypto
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

    @staticmethod
    def getProtocolPort():
        return 1433

    def initConnection(self):
        pass

    def skipAuthentication(self):

        # 1. First packet should be a TDS_PRELOGIN()
        tds = self.recvTDS()
        if tds['Type'] != TDS_PRE_LOGIN:
            # Unexpected packet
            LOG.debug('Unexpected packet type %d instead of TDS_PRE_LOGIN' % tds['Type'])
            return False

        prelogin = TDS_PRELOGIN()
        prelogin['Version'] = "\x08\x00\x01\x55\x00\x00"
        prelogin['Encryption'] = TDS_ENCRYPT_NOT_SUP
        prelogin['ThreadID'] = struct.pack('<L',random.randint(0,65535))
        prelogin['Instance'] = '\x00'

        # Answering who we are
        self.sendTDS(TDS_TABULAR, str(prelogin), 0)

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
        if self.activeRelays.has_key(self.username):
            # Check the connection is not inUse
            if self.activeRelays[self.username]['inUse'] is True:
                LOG.error('MSSQL: Connection for %s@%s(%s) is being used at the moment!' % (
                    self.username, self.targetHost, self.targetPort))
                return False
            else:
                LOG.info('MSSQL: Proxying client session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
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
                # 2. Send it to the relayed session
                self.session.sendTDS(tds['Type'], tds['Data'], 0)
                # 3. Get the target's answer
                tds = self.session.recvTDS()
                # 4. Send it back to the client
                self.sendTDS(tds['Type'], tds['Data'], 0)
        except Exception, e:
            # Probably an error here
            if LOG.level == logging.DEBUG:
                import traceback
                traceback.print_exc()

        return True

    def sendTDS(self, packetType, data, packetID = 1):
        if (len(data)-8) > self.packetSize:
            remaining = data[self.packetSize-8:]
            tds = TDSPacket()
            tds['Type'] = packetType
            tds['Status'] = TDS_STATUS_NORMAL
            tds['PacketID'] = packetID
            tds['Data'] = data[:self.packetSize-8]
            self.socketSendall(str(tds))

            while len(remaining) > (self.packetSize-8):
                packetID += 1
                tds['PacketID'] = packetID
                tds['Data'] = remaining[:self.packetSize-8]
                self.socketSendall(str(tds))
                remaining = remaining[self.packetSize-8:]
            data = remaining
            packetID+=1

        tds = TDSPacket()
        tds['Type'] = packetType
        tds['Status'] = TDS_STATUS_EOM
        tds['PacketID'] = packetID
        tds['Data'] = data
        self.socketSendall(str(tds))

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
            dd = ''
            self.tlsSocket.bio_write(data)
            while True:
                try:
                    dd += self.tlsSocket.read(packetSize)
                except SSL.WantReadError:
                    data2 = self.socket.recv(packetSize - len(data) )
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
        packet = TDSPacket(self.socketRecv(packetSize))
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
                tmpPacket = TDSPacket(self.socketRecv(packetSize))

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


