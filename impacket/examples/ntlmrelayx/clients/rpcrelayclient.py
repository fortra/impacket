# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Authors:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#   Based on @agsolino and @_dirkjan code
#

from struct import unpack

from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge
from impacket.spnego import SPNEGO_NegTokenResp

from impacket.dcerpc.v5 import transport, rpcrt, epm, tsch
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rpcrt import DCERPC_v5, MSRPCBind, CtxItem, MSRPCHeader, SEC_TRAILER, MSRPCBindAck, \
    MSRPCRespHeader, MSRPCBindNak, DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_CONNECT, \
    rpc_status_codes, rpc_provider_reason

PROTOCOL_CLIENT_CLASS = "RPCRelayClient"

class RPCRelayClientException(Exception):
    pass

class MYDCERPC_v5(DCERPC_v5):
    def __init__(self, transport):
        DCERPC_v5.__init__(self, transport)

    def sendBindType1(self, iface_uuid, auth_data):
        bind = MSRPCBind()

        item = CtxItem()
        item['AbstractSyntax'] = iface_uuid
        item['TransferSyntax'] = self.transfer_syntax
        item['ContextID'] = 0
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = rpcrt.MSRPC_BIND
        packet['pduData'] = bind.getData()
        packet['call_id'] = 0

        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
        sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_CONNECT
        sec_trailer['auth_ctx_id'] = 79231

        pad = (4 - (len(packet.get_packet()) % 4)) % 4
        if pad != 0:
           packet['pduData'] += b'\xFF' * pad
           sec_trailer['auth_pad_len'] = pad

        packet['sec_trailer'] = sec_trailer
        packet['auth_data'] = auth_data

        self._transport.send(packet.get_packet())

        s = self._transport.recv()

        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0 #mmm why not None?

        if resp['type'] == rpcrt.MSRPC_BINDACK or resp['type'] == rpcrt.MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(resp.getData())
        elif resp['type'] == rpcrt.MSRPC_BINDNAK or resp['type'] == rpcrt.MSRPC_FAULT:
            if resp['type'] == rpcrt.MSRPC_FAULT:
                resp = MSRPCRespHeader(resp.getData())
                status_code = unpack('<L', resp['pduData'][:4])[0]
            else:
                resp = MSRPCBindNak(resp['pduData'])
                status_code = resp['RejectedReason']
            if status_code in rpc_status_codes:
                raise DCERPCException(error_code = status_code)
            elif status_code in rpc_provider_reason:
                raise DCERPCException("Bind context rejected: %s" % rpc_provider_reason[status_code])
            else:
                raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)
        else:
            raise DCERPCException('Unknown DCE RPC packet type received: %d' % resp['type'])

        self.set_max_tfrag(bindResp['max_rfrag'])

        return bindResp

    def sendBindType3(self, auth_data):
        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
        sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_CONNECT
        sec_trailer['auth_ctx_id'] = 79231

        auth3 = MSRPCHeader()
        auth3['type'] = rpcrt.MSRPC_AUTH3

        # pad (4 bytes): Can be set to any arbitrary value when set and MUST be
        # ignored on receipt. The pad field MUST be immediately followed by a
        # sec_trailer structure whose layout, location, and alignment are as
        # specified in section 2.2.2.11
        auth3['pduData'] = b'    '
        auth3['sec_trailer'] = sec_trailer
        auth3['auth_data'] = auth_data
        auth3['call_id'] = 0

        self._transport.send(auth3.get_packet(), forceWriteAndx = 1)

class DummyOp(NDRCALL):
    opnum = 255
    structure = (
    )

class RPCRelayClient(ProtocolClient):
    PLUGIN_NAME = "RPC"

    def __init__(self, serverConfig, target, targetPort=None, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

        # TODO: support relaying RPC to different endpoints (e.g. DCOM, SpoolSS)
        # TODO: create a single LOG interface for ntlmrelayx to provide a user info which message/error to which thread belongs
        self.endpoint = serverConfig.rpc_mode

        if self.endpoint == "TSCH":
            self.endpoint_uuid = tsch.MSRPC_UUID_TSCHS
        else:
            raise NotImplementedError("Not implemented!")

        if self.serverConfig.rpc_use_smb:
            if self.endpoint == "TSCH":
                self.stringbinding = "ncacn_np:%s[\\pipe\\atsvc]" % target.netloc
            else:
                raise NotImplementedError("Not implemented!")
        else:
            LOG.debug("Connecting to ncacn_ip_tcp:%s[135] to determine %s stringbinding" % (target.netloc, self.endpoint))
            self.stringbinding = epm.hept_map(target.netloc, self.endpoint_uuid, protocol='ncacn_ip_tcp')

        LOG.debug("%s stringbinding is %s" % (self.endpoint, self.stringbinding))

    def initConnection(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringbinding)

        if self.serverConfig.rpc_use_smb:
            LOG.info("Authenticating to smb://%s:%d with creds provided in cmdline" % (self.target.netloc, self.serverConfig.rpc_smb_port))
            rpctransport.set_credentials(self.serverConfig.smbuser, self.serverConfig.smbpass, self.serverConfig.smbdomain, \
                self.serverConfig.smblmhash, self.serverConfig.smbnthash)
            rpctransport.set_dport(self.serverConfig.rpc_smb_port)

        self.session = MYDCERPC_v5(rpctransport)
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        self.session.connect()

        if self.serverConfig.rpc_use_smb:
            LOG.info("Authentication to smb://%s:%d succeeded" % (self.target.netloc, self.serverConfig.rpc_smb_port))

        return True

    def sendNegotiate(self, auth_data):
        bindResp = self.session.sendBindType1(self.endpoint_uuid, auth_data)

        challenge = NTLMAuthChallenge()
        challenge.fromString(bindResp['auth_data'])

        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            auth_data = respToken2['ResponseToken']
        else:
            auth_data = authenticateMessageBlob

        self.session.sendBindType3(auth_data)

        try:
            req = DummyOp()
            self.session.request(req)
        except DCERPCException as e:
            if 'nca_s_op_rng_error' in str(e) or 'RPC_E_INVALID_HEADER' in str(e):
                return None, STATUS_SUCCESS
            elif 'rpc_s_access_denied' in str(e):
                return None, STATUS_ACCESS_DENIED
            else:
                LOG.info("Unexpected rpc code received from %s: %s" % (self.stringbinding, str(e)))
                return None, STATUS_ACCESS_DENIED

    def killConnection(self):
        if self.session is not None:
            self.session.get_rpc_transport().disconnect()
            self.session = None

    def keepAlive(self):
        try:
            req = DummyOp()
            self.session.request(req)
        except DCERPCException as e:
            if 'nca_s_op_rng_error' not in str(e) or 'RPC_E_INVALID_HEADER' not in str(e):
                raise
