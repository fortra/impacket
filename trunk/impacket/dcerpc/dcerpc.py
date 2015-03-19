################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Partial C706.pdf + [MS-RPCE] implementation
#
# ToDo: 
# [ ] Take out all the security provider stuff out of here (e.g. RPC_C_AUTHN_WINNT)
#     and put it elsewhere. This will make the coder cleaner and easier to add 
#     more SSP (e.g. NETLOGON)
# 

from binascii import a2b_hex
from Crypto.Cipher import ARC4

from impacket import ntlm
from impacket.structure import Structure,pack,unpack
from impacket import uuid
from impacket.uuid import uuidtup_to_bin, generate, stringver_to_bin

# MS/RPC Constants
MSRPC_REQUEST   = 0x00
MSRPC_PING      = 0x01
MSRPC_RESPONSE  = 0x02
MSRPC_FAULT     = 0x03
MSRPC_WORKING   = 0x04
MSRPC_NOCALL    = 0x05
MSRPC_REJECT    = 0x06
MSRPC_ACK       = 0x07
MSRPC_CL_CANCEL = 0x08
MSRPC_FACK      = 0x09
MSRPC_CANCELACK = 0x0A
MSRPC_BIND      = 0x0B
MSRPC_BINDACK   = 0x0C
MSRPC_BINDNAK   = 0x0D
MSRPC_ALTERCTX  = 0x0E
MSRPC_ALTERCTX_R= 0x0F
MSRPC_AUTH3     = 0x10
MSRPC_SHUTDOWN  = 0x11
MSRPC_CO_CANCEL = 0x12
MSRPC_ORPHANED  = 0x13

# MS/RPC Packet Flags
MSRPC_FIRSTFRAG     = 0x01
MSRPC_LASTFRAG      = 0x02

# For PDU types bind, bind_ack, alter_context, and
# alter_context_resp, this flag MUST be interpreted as PFC_SUPPORT_HEADER_SIGN
MSRPC_SUPPORT_SIGN  = 0x04

#For the
#remaining PDU types, this flag MUST be interpreted as PFC_PENDING_CANCEL.
MSRPC_PENDING_CANCEL= 0x04

MSRPC_NOTAFRAG      = 0x04
MSRPC_RECRESPOND    = 0x08
MSRPC_NOMULTIPLEX   = 0x10
MSRPC_NOTFORIDEMP   = 0x20
MSRPC_NOTFORBCAST   = 0x40
MSRPC_NOUUID        = 0x80

# Auth Types - Security Providers
RPC_C_AUTHN_NONE          = 0x00
RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
RPC_C_AUTHN_WINNT         = 0x0A
RPC_C_AUTHN_GSS_SCHANNEL  = 0x0E
RPC_C_AUTHN_GSS_KERBEROS  = 0x10
RPC_C_AUTHN_NETLOGON      = 0x44
RPC_C_AUTHN_DEFAULT       = 0xFF

# Auth Levels
RPC_C_AUTHN_LEVEL_NONE          = 1
RPC_C_AUTHN_LEVEL_CONNECT       = 2
RPC_C_AUTHN_LEVEL_CALL          = 3
RPC_C_AUTHN_LEVEL_PKT           = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6

#Reasons for rejection of a context element, included in bind_ack result reason
rpc_provider_reason = {
    0       : 'reason_not_specified',
    1       : 'abstract_syntax_not_supported',
    2       : 'proposed_transfer_syntaxes_not_supported',
    3       : 'local_limit_exceeded',
    4       : 'protocol_version_not_specified',
    8       : 'authentication_type_not_recognized',
    9       : 'invalid_checksum'
}

MSRPC_CONT_RESULT_ACCEPT = 0
MSRPC_CONT_RESULT_USER_REJECT = 1
MSRPC_CONT_RESULT_PROV_REJECT = 2

#Results of a presentation context negotiation
rpc_cont_def_result = {
    0       : 'acceptance',
    1       : 'user_rejection',
    2       : 'provider_rejection'
}

#status codes, references:
#http://msdn.microsoft.com/library/default.asp?url=/library/en-us/rpc/rpc/rpc_return_values.asp
#http://msdn.microsoft.com/library/default.asp?url=/library/en-us/randz/protocol/common_return_values.asp
#winerror.h
#http://www.opengroup.org/onlinepubs/9629399/apdxn.htm

rpc_status_codes = {
    0x00000005L : 'rpc_s_access_denied',
    0x00000008L : 'Authentication type not recognized',
    0x000006D8L : 'rpc_fault_cant_perform', 
    0x000006C6L : 'rpc_x_invalid_bound',                # the arrays bound are invalid
    0x000006E4L : 'rpc_s_cannot_support: The requested operation is not supported.',               # some operation is not supported
    0x000006F7L : 'rpc_x_bad_stub_data',                # the stub data is invalid, doesn't match with the IDL definition
    0x1C010001L : 'nca_s_comm_failure',                 # unable to get response from server:
    0x1C010002L : 'nca_s_op_rng_error',                 # bad operation number in call
    0x1C010003L : 'nca_s_unk_if',                       # unknown interface
    0x1C010006L : 'nca_s_wrong_boot_time',              # client passed server wrong server boot time
    0x1C010009L : 'nca_s_you_crashed',                  # a restarted server called back a client
    0x1C01000BL : 'nca_s_proto_error',                  # someone messed up the protocol
    0x1C010013L : 'nca_s_out_args_too_big ',            # output args too big
    0x1C010014L : 'nca_s_server_too_busy',              # server is too busy to handle call
    0x1C010015L : 'nca_s_fault_string_too_long',        # string argument longer than declared max len
    0x1C010017L : 'nca_s_unsupported_type ',            # no implementation of generic operation for object
    0x1C000001L : 'nca_s_fault_int_div_by_zero',
    0x1C000002L : 'nca_s_fault_addr_error ',
    0x1C000003L : 'nca_s_fault_fp_div_zero',
    0x1C000004L : 'nca_s_fault_fp_underflow',
    0x1C000005L : 'nca_s_fault_fp_overflow',
    0x1C000006L : 'nca_s_fault_invalid_tag',
    0x1C000007L : 'nca_s_fault_invalid_bound ',
    0x1C000008L : 'nca_s_rpc_version_mismatch',
    0x1C000009L : 'nca_s_unspec_reject ',
    0x1C00000AL : 'nca_s_bad_actid',
    0x1C00000BL : 'nca_s_who_are_you_failed',
    0x1C00000CL : 'nca_s_manager_not_entered ',
    0x1C00000DL : 'nca_s_fault_cancel',
    0x1C00000EL : 'nca_s_fault_ill_inst',
    0x1C00000FL : 'nca_s_fault_fp_error',
    0x1C000010L : 'nca_s_fault_int_overflow',
    0x1C000012L : 'nca_s_fault_unspec',
    0x1C000013L : 'nca_s_fault_remote_comm_failure ',
    0x1C000014L : 'nca_s_fault_pipe_empty ',
    0x1C000015L : 'nca_s_fault_pipe_closed',
    0x1C000016L : 'nca_s_fault_pipe_order ',
    0x1C000017L : 'nca_s_fault_pipe_discipline',
    0x1C000018L : 'nca_s_fault_pipe_comm_error',
    0x1C000019L : 'nca_s_fault_pipe_memory',
    0x1C00001AL : 'nca_s_fault_context_mismatch ',
    0x1C00001BL : 'nca_s_fault_remote_no_memory ',
    0x1C00001CL : 'nca_s_invalid_pres_context_id',
    0x1C00001DL : 'nca_s_unsupported_authn_level',
    0x1C00001FL : 'nca_s_invalid_checksum ',
    0x1C000020L : 'nca_s_invalid_crc',
    0x1C000021L : 'nca_s_fault_user_defined',
    0x1C000022L : 'nca_s_fault_tx_open_failed',
    0x1C000023L : 'nca_s_fault_codeset_conv_error',
    0x1C000024L : 'nca_s_fault_object_not_found ',
    0x1C000025L : 'nca_s_fault_no_client_stub'
}

class Exception(Exception):
    pass

# Context Item
class CtxItem(Structure):
    structure = (
        ('ContextID','<H=0'),
        ('TransItems','B=0'),
        ('Pad','B=0'),
        ('AbstractSyntax','20s=""'),
        ('TransferSyntax','20s=""'),
    )

class CtxItemResult(Structure):
    structure = (
        ('Result','<H=0'),
        ('Reason','<H=0'),
        ('TransferSyntax','20s=""'),
    )

class SEC_TRAILER(Structure):
    commonHdr = (
        ('auth_type', 'B=10'),
        ('auth_level','B=0'),
        ('auth_pad_len','B=0'),
        ('auth_rsvrd','B=0'),
        ('auth_ctx_id','<L=747920'),
    )

class MSRPCHeader(Structure):
    _SIZE = 16
    commonHdr = ( 
        ('ver_major','B=5'),                              # 0
        ('ver_minor','B=0'),                              # 1
        ('type','B=0'),                                   # 2
        ('flags','B=0'),                                  # 3
        ('representation','<L=0x10'),                     # 4
        ('frag_len','<H=self._SIZE+len(pduData)+len(pad)+len(sec_trailer)+len(auth_data)'),  # 8
        ('auth_len','<H=len(auth_data)'),                 # 10
        ('call_id','<L=1'),                               # 12    <-- Common up to here (including this)
    )

    structure = ( 
        ('dataLen','_-pduData','self["frag_len"]-self["auth_len"]-self._SIZE-(8 if self["auth_len"] > 0 else 0)'),  
        ('pduData',':'),                                
        ('_pad', '_-pad','(4 - ((self._SIZE + len(self["pduData"])) & 3) & 3)'),
        ('pad', ':'),
        ('_sec_trailer', '_-sec_trailer', '8 if self["auth_len"] > 0 else 0'),
        ('sec_trailer',':'),
        ('auth_dataLen','_-auth_data','self["auth_len"]'),
        ('auth_data',':'),
    )

    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self,data, alignment)
        if data is None:
            self['ver_major'] = 5
            self['ver_minor'] = 0
            self['flags'] = MSRPC_FIRSTFRAG | MSRPC_LASTFRAG 
            self['type'] = MSRPC_REQUEST
            self.__frag_len_set = 0
            self['auth_len'] = 0
            self['pduData'] = ''
            self['auth_data'] = ''
            self['sec_trailer'] = ''
            self['pad'] = ''

    def get_header_size(self):
        return self._SIZE

    def get_packet(self):
        if self['auth_data'] != '':
            self['auth_len'] = len(self['auth_data'])
        # The sec_trailer structure MUST be 4-byte aligned with respect to 
        # the beginning of the PDU. Padding octets MUST be used to align the 
        # sec_trailer structure if its natural beginning is not already 4-byte aligned
        ##self['pad'] = '\xAA' * (4 - ((self._SIZE + len(self['pduData'])) & 3) & 3)

        return self.getData()

class MSRPCRequestHeader(MSRPCHeader):
    _SIZE = 24
    commonHdr = MSRPCHeader.commonHdr + ( 
        ('alloc_hint','<L=0'),                            # 16
        ('ctx_id','<H=0'),                                # 20
        ('op_num','<H=0'),                                # 22
    )

    def __init__(self, data = None, alignment = 0):
        MSRPCHeader.__init__(self, data, alignment)
        if data is None:
           self['type'] = MSRPC_REQUEST
           self['ctx_id'] = 0

class MSRPCRespHeader(MSRPCHeader):
    _SIZE = 24
    commonHdr = MSRPCHeader.commonHdr + ( 
        ('alloc_hint','<L=0'),                          # 16   
        ('ctx_id','<H=0'),                              # 20
        ('cancel_count','<B=0'),                        # 22
        ('padding','<B=0'),                             # 23
    )

    def __init__(self, aBuffer = None, alignment = 0):
        MSRPCHeader.__init__(self, aBuffer, alignment)
        if aBuffer is None:
            self['type'] = MSRPC_RESPONSE
            self['ctx_id'] = 0

class MSRPCBind(Structure):
    _CTX_ITEM_LEN = len(CtxItem())
    structure = ( 
        ('max_tfrag','<H=4280'),
        ('max_rfrag','<H=4280'),
        ('assoc_group','<L=0'),
        ('ctx_num','B=0'),
        ('Reserved','B=0'),
        ('Reserved2','<H=0'),
        ('_ctx_items', '_-ctx_items', 'self["ctx_num"]*self._CTX_ITEM_LEN'),
        ('ctx_items',':'),
    )
 
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['max_tfrag'] = 4280
            self['max_rfrag'] = 4280
            self['assoc_group'] = 0
            self['ctx_num'] = 1
            self['ctx_items'] = ''
        self.__ctx_items = []

    def addCtxItem(self, item):
        self.__ctx_items.append(item)
    
    def getData(self):
        self['ctx_num'] = len(self.__ctx_items)
        for i in self.__ctx_items:
            self['ctx_items'] += i.getData()
        return Structure.getData(self)

class MSRPCBindAck(Structure):
    _SIZE = 26 # Up to SecondaryAddr
    _CTX_ITEM_LEN = len(CtxItemResult())
    commonHdr = ( 
        ('ver_major','B=5'),                            # 0
        ('ver_minor','B=0'),                            # 1
        ('type','B=0'),                                 # 2
        ('flags','B=0'),                                # 3
        ('representation','<L=0x10'),                   # 4
        ('frag_len','<H=0'),                            # 8
        ('auth_len','<H=0'),                            # 10
        ('call_id','<L=1'),                             # 12    <-- Common up to here (including this)
    )
    structure = ( 
        ('max_tfrag','<H=0'),
        ('max_rfrag','<H=0'),
        ('assoc_group','<L=0'),
        ('SecondaryAddrLen','<H&SecondaryAddr'), 
        ('SecondaryAddr','z'),                          # Optional if SecondaryAddrLen == 0
        ('PadLen','_-Pad','(4-((self["SecondaryAddrLen"]+self._SIZE) % 4))%4'),
        ('Pad',':'),
        ('ctx_num','B=0'),
        ('Reserved','B=0'),
        ('Reserved2','<H=0'),
        ('_ctx_items','_-ctx_items','self["ctx_num"]*self._CTX_ITEM_LEN'),
        ('ctx_items',':'),
        ('_sec_trailer', '_-sec_trailer', '8 if self["auth_len"] > 0 else 0'),
        ('sec_trailer',':'),
        ('auth_dataLen','_-auth_data','self["auth_len"]'),
        ('auth_data',':'),
    )
    def __init__(self, data = None, alignment = 0):
        self.__ctx_items = []
        Structure.__init__(self,data,alignment)
        if data is None:
            self['Pad'] = ''
            self['ctx_items'] = ''
            self['sec_trailer'] = ''
            self['auth_data'] = ''

    def getCtxItems(self):
        return self.__ctx_items

    def getCtxItem(self,index):
        return self.__ctx_items[index-1]

    def fromString(self, data):
        Structure.fromString(self,data)
        # Parse the ctx_items
        data = self['ctx_items']
        for i in range(self['ctx_num']):
            item = CtxItemResult(data)
            self.__ctx_items.append(item)
            data = data[len(item):]
            
class MSRPCBindNak(Structure):
    structure = ( 
        ('RejectedReason','<H=0'),
        ('SupportedVersions',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self,data,alignment)
        if data is None:
            self['SupportedVersions'] = ''

class DCERPC:
    _max_ctx = 0
    def __init__(self,transport):
        self._transport = transport
        self.set_ctx_id(0)
        self._max_frag = None
        self.set_default_max_fragment_size()

    def set_ctx_id(self, ctx_id):
        self._ctx = ctx_id

    def connect(self):
        return self._transport.connect()

    def disconnect(self):
        return self._transport.disconnect()

    def set_max_fragment_size(self, fragment_size):
        # -1 is default fragment size: 0 for v5, 1300 y pico for v4
        #  0 is don't fragment
        #    other values are max fragment size
        if fragment_size == -1:
            self.set_default_max_fragment_size()
        else:
            self._max_frag = fragment_size

    def set_default_max_fragment_size(self):
        # default is 0: don'fragment. v4 will override this method
        self._max_frag = 0

    def send(self, data): raise RuntimeError, 'virtual method. Not implemented in subclass'
    def recv(self): raise RuntimeError, 'virtual method. Not implemented in subclass'
    def alter_ctx(self, newUID, bogus_binds = ''): raise RuntimeError, 'virtual method. Not implemented in subclass'
    def set_credentials(self, username, password, domain = '', lmhash = '', nthash = '', aesKey='', TGT=None, TGS=None): pass
    def set_auth_level(self, auth_level): pass
    def set_auth_type(self, auth_type, callback = None): pass
    def get_idempotent(self): return 0
    def set_idempotent(self, flag): pass
    def call(self, function, body):
        return self.send(DCERPC_RawCall(function, str(body)))

class DCERPC_v5(DCERPC):
    def __init__(self, transport):
        DCERPC.__init__(self, transport)
        self.__auth_level = RPC_C_AUTHN_LEVEL_NONE
        self.__auth_type = RPC_C_AUTHN_WINNT
        self.__auth_type_callback = None
        # Flags of the authenticated session. We will need them throughout the connection
        self.__auth_flags = 0
        self.__username = None
        self.__password = None
        self.__domain = ''
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = ''
        self.__TGT    = None
        self.__TGS    = None
        
        self.__clientSigningKey = ''
        self.__serverSigningKey = ''
        self.__clientSealingKey = ''
        self.__clientSealingHandle = ''
        self.__serverSealingKey = ''
        self.__serverSealingHandle = ''
        self.__sequence = 0   

        self.__callid = 1
        self._ctx = 0

    def set_session_key(self, session_key):
        self.__sessionKey = session_key

    def set_auth_level(self, auth_level):
        # auth level is ntlm.NTLM_AUTH_*
        self.__auth_level = auth_level

    def set_auth_type(self, auth_type, callback = None):
        self.__auth_type = auth_type
        self.__auth_type_callback = callback

    def set_max_tfrag(self, size):
        self.__max_xmit_size = size
    
    def set_credentials(self, username, password, domain = '', lmhash = '', nthash = '', aesKey='', TGT=None, TGS=None):
        self.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        self.__username = username
        self.__password = password
        self.__domain   = domain
        self.__aesKey   = aesKey
        self.__TGT      = TGT
        self.__TGS      = TGS
        if ( lmhash != '' or nthash != ''):
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try: # just in case they were converted already
                self.__lmhash = a2b_hex(lmhash)
                self.__nthash = a2b_hex(nthash)
            except:
                self.__lmhash = lmhash
                self.__nthash = nthash
                pass

    def bind(self, uuid, alter = 0, bogus_binds = 0):
        bind = MSRPCBind()
        # Standard NDR Representation
        NDRSyntax   = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        # NDR 64
        NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0') 
        #item['TransferSyntax']['Version'] = 1
        ctx = self._ctx
        for i in range(bogus_binds):
            item = CtxItem()
            item['ContextID'] = ctx
            item['TransItems'] = 1
            item['ContextID'] = ctx
            # We generate random UUIDs for bogus binds
            item['AbstractSyntax'] = generate() + stringver_to_bin('2.0')
            item['TransferSyntax'] = uuidtup_to_bin(NDRSyntax)
            bind.addCtxItem(item)
            self._ctx += 1
            ctx += 1

        # The true one :)
        item = CtxItem()
        item['AbstractSyntax'] = uuid
        item['TransferSyntax'] = uuidtup_to_bin(NDRSyntax)
        item['ContextID'] = ctx
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = MSRPC_BIND
        packet['pduData'] = str(bind)
        packet['call_id'] = self.__callid

        if alter:
            packet['type'] = MSRPC_ALTERCTX

        if (self.__auth_level != RPC_C_AUTHN_LEVEL_NONE):
            if (self.__username is None) or (self.__password is None):
                self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__TGT, self.__TGS = self._transport.get_credentials()
            if self.__auth_type == RPC_C_AUTHN_WINNT:
                auth = ntlm.getNTLMSSPType1('', self.__domain, signingRequired = True, use_ntlmv2 = self._transport.doesSupportNTLMv2())
            elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                from impacket.dcerpc import netlogon
                auth = netlogon.getSSPType1(self.__username[:-1], self.__domain, signingRequired = True)

            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type']   = self.__auth_type
            sec_trailer['auth_level']  = self.__auth_level
            sec_trailer['auth_ctx_id'] = self._ctx + 79231 

            pad = (4 - (len(packet.get_packet()) % 4)) % 4
            if pad != 0:
               packet['pduData'] = packet['pduData'] + '\xFF'*pad
               sec_trailer['auth_pad_len']=pad

            packet['sec_trailer'] = sec_trailer
            packet['auth_data'] = str(auth)

        self._transport.send(packet.get_packet())

        s = self._transport.recv()

        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0 #mmm why not None?

        if resp['type'] == MSRPC_BINDACK or resp['type'] == MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(str(resp))
        elif resp['type'] == MSRPC_BINDNAK:
            resp = MSRPCBindNak(resp['pduData'])
            status_code = resp['RejectedReason']
            if rpc_status_codes.has_key(status_code):
                raise Exception(rpc_status_codes[status_code], resp)
            elif rpc_provider_reason.has_key(status_code):
                raise Exception("Bind context rejected: %s" % rpc_provider_reason[status_code])
            else:
                raise Exception('Unknown DCE RPC fault status code: %.8x' % status_code, resp)
        else:
            raise Exception('Unknown DCE RPC packet type received: %d' % resp['type'])

        # check ack results for each context, except for the bogus ones
        for ctx in range(bogus_binds+1,bindResp['ctx_num']+1):
            result = bindResp.getCtxItem(ctx)['Result']
            if result != 0:
                msg = "Bind context %d rejected: " % ctx
                msg += rpc_cont_def_result.get(result, 'Unknown DCE RPC context result code: %.4x' % result)
                msg += "; "
                reason = bindResp.getCtxItem(ctx)['Reason']
                msg += rpc_provider_reason.get(reason, 'Unknown reason code: %.4x' % reason)
                if (result, reason) == (2, 1): # provider_rejection, abstract syntax not supported
                    msg += " (this usually means the interface isn't listening on the given endpoint)"
                raise Exception(msg, resp)

        self.__max_xmit_size = bindResp['max_tfrag']

        if self.__auth_level != RPC_C_AUTHN_LEVEL_NONE:
            if self.__auth_type == RPC_C_AUTHN_WINNT:
                response, randomSessionKey = ntlm.getNTLMSSPType3(auth, bindResp['auth_data'], self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, use_ntlmv2 = self._transport.doesSupportNTLMv2())
                self.__flags = response['flags']
            elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                response = None

            self.__sequence = 0

            if self.__auth_level in (RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY):
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NTLM2_KEY:
                        self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey)
                        self.__serverSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey,"Server")
                        self.__clientSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey)
                        self.__serverSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey,"Server")
                        # Preparing the keys handle states
                        cipher3 = ARC4.new(self.__clientSealingKey)
                        self.__clientSealingHandle = cipher3.encrypt
                        cipher4 = ARC4.new(self.__serverSealingKey)
                        self.__serverSealingHandle = cipher4.encrypt
                    else:
                        # Same key for everything
                        self.__clientSigningKey = randomSessionKey
                        self.__serverSigningKey = randomSessionKey
                        self.__clientSealingKey = randomSessionKey
                        self.__serverSealingKey = randomSessionKey
                        cipher = ARC4.new(self.__clientSigningKey)
                        self.__clientSealingHandle = cipher.encrypt
                        self.__serverSealingHandle = cipher.encrypt
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    pass

            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type'] = self.__auth_type
            sec_trailer['auth_level'] = self.__auth_level
            sec_trailer['auth_ctx_id'] = self._ctx + 79231 

            if response is not None:
                auth3 = MSRPCHeader()
                auth3['type'] = MSRPC_AUTH3
                # pad (4 bytes): Can be set to any arbitrary value when set and MUST be 
                # ignored on receipt. The pad field MUST be immediately followed by a 
                # sec_trailer structure whose layout, location, and alignment are as 
                # specified in section 2.2.2.11
                auth3['pduData'] = '    '
                auth3['sec_trailer'] = sec_trailer
                auth3['auth_data'] = str(response)

                # Use the same call_id
                self.__callid = resp['call_id']
                auth3['call_id'] = self.__callid
                self._transport.send(auth3.get_packet(), forceWriteAndx = 1)

            self.__callid += 1

        return resp     # means packet is signed, if verifier is wrong it fails

    def _transport_send(self, rpc_packet, forceWriteAndx = 0, forceRecv = 0):
        rpc_packet['ctx_id'] = self._ctx
        if self.__auth_level in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
            # Dummy verifier, just for the calculations
            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type'] = self.__auth_type
            sec_trailer['auth_level'] = self.__auth_level
            sec_trailer['auth_pad_len'] = 0
            sec_trailer['auth_ctx_id'] = self._ctx + 79231 

            pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
            if pad != 0:
               rpc_packet['pduData'] = rpc_packet['pduData'] + '\xBB'*pad
               sec_trailer['auth_pad_len']=pad

            rpc_packet['sec_trailer'] = str(sec_trailer)
            rpc_packet['auth_data'] = ' '*16

            plain_data = rpc_packet['pduData']
            if self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NTLM2_KEY:
                        # When NTLM2 is on, we sign the whole pdu, but encrypt just
                        # the data, not the dcerpc header. Weird..
                        sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                               self.__clientSigningKey, 
                               self.__clientSealingKey,  
                               rpc_packet.get_packet()[:-16], 
                               plain_data, 
                               self.__sequence, 
                               self.__clientSealingHandle)
                    else:
                        sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                               self.__clientSigningKey, 
                               self.__clientSealingKey,  
                               plain_data, 
                               plain_data, 
                               self.__sequence, 
                               self.__clientSealingHandle)
                    rpc_packet['pduData'] = sealedMessage
            else: 
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NTLM2_KEY:
                        # Interesting thing.. with NTLM2, what is is signed is the 
                        # whole PDU, not just the data
                        signature =  ntlm.SIGN(self.__flags, 
                               self.__clientSigningKey, 
                               rpc_packet.get_packet()[:-16], 
                               self.__sequence, 
                               self.__clientSealingHandle)
                    else:
                        signature =  ntlm.SIGN(self.__flags, 
                               self.__clientSigningKey, 
                               plain_data, 
                               self.__sequence, 
                               self.__clientSealingHandle)
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    from impacket.dcerpc import netlogon
                    signature = netlogon.SIGN(rpc_packet.get_packet()[:-16], self.__sequence, '', self.__sessionKey)

            rpc_packet['sec_trailer'] = str(sec_trailer)
            rpc_packet['auth_data'] = str(signature)

            self.__sequence += 1

        self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)

    def send(self, data):
        if isinstance(data, MSRPCHeader) is not True:
            # Must be an Impacket, transform to structure
            data = DCERPC_RawCall(data.OP_NUM, data.get_packet())

        data['ctx_id'] = self._ctx
        data['call_id'] = self.__callid

        max_frag = self._max_frag
        if len(data['pduData']) > self.__max_xmit_size - 32:
            max_frag = self.__max_xmit_size - 32    # XXX: 32 is a safe margin for auth data

        if self._max_frag:
            max_frag = min(max_frag, self._max_frag)
        if max_frag and len(data['pduData']) > 0:
            packet = data['pduData']
            offset = 0
            rawcall = DCERPC_RawCall(data['op_num'])

            while 1:
                toSend = packet[offset:offset+max_frag]
                if not toSend:
                    break
                flags = 0
                if offset == 0:
                    flags |= MSRPC_FIRSTFRAG
                offset += len(toSend)
                if offset == len(packet):
                    flags |= MSRPC_LASTFRAG
                data['flags'] = flags
                data['pduData'] = toSend
                self._transport_send(data, forceWriteAndx = 1, forceRecv = flags & MSRPC_LASTFRAG)
        else:
            self._transport_send(data)
        self.__callid += 1

    def recv(self):
        finished = False
        forceRecv = 0
        retAnswer = ''
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for 
            # TCP/UDP Transports
            self.response_data = self._transport.recv(forceRecv, count=MSRPCRespHeader._SIZE)
            self.response_header = MSRPCRespHeader(self.response_data)
            # Ok, there might be situation, especially with large packets, that 
            # the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while ( len(self.response_data) < self.response_header['frag_len'] ):
               self.response_data += self._transport.recv(forceRecv, count=(self.response_header['frag_len']-len(self.response_data)))

            off = self.response_header.get_header_size()

            if self.response_header['type'] == MSRPC_FAULT and self.response_header['frag_len'] >= off+4:
                status_code = unpack("<L",self.response_data[off:off+4])[0]
                if rpc_status_codes.has_key(status_code):
                    raise Exception(rpc_status_codes[status_code])
                else:
                    raise Exception('Unknown DCE RPC fault status code: %.8x' % status_code)

            if self.response_header['flags'] & MSRPC_LASTFRAG:
                # No need to reassembly DCERPC
                finished = True
            else:
                # Forcing Read Recv, we need more packets!
                forceRecv = 1

            answer = self.response_data[off:]
            auth_len = self.response_header['auth_len']
            if auth_len:
                auth_len += 8
                auth_data = answer[-auth_len:]
                sec_trailer = SEC_TRAILER(data = auth_data)
                answer = answer[:-auth_len]

                if sec_trailer['auth_level'] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                    if self.__auth_type == RPC_C_AUTHN_WINNT:
                        if self.__flags & ntlm.NTLMSSP_NTLM2_KEY:
                            # TODO: FIX THIS, it's not calculating the signature well
                            # Since I'm not testing it we don't care... yet
                            answer, signature =  ntlm.SEAL(self.__flags, 
                                    self.__serverSigningKey, 
                                    self.__serverSealingKey,  
                                    answer, 
                                    answer, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                        else:
                            answer, signature = ntlm.SEAL(self.__flags, 
                                    self.__serverSigningKey, 
                                    self.__serverSealingKey, 
                                    answer, 
                                    answer, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                            self.__sequence += 1
                else:
                    if self.__auth_type == RPC_C_AUTHN_WINNT:
                        ntlmssp = auth_data[12:]
                        if self.__flags & ntlm.NTLMSSP_NTLM2_KEY:
                            signature =  ntlm.SIGN(self.__flags, 
                                    self.__serverSigningKey, 
                                    answer, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                        else:
                            signature = ntlm.SIGN(self.__flags, 
                                    self.__serverSigningKey, 
                                    ntlmssp, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                            # Yes.. NTLM2 doesn't increment sequence when receiving
                            # the packet :P
                            self.__sequence += 1
                
                if sec_trailer['auth_pad_len']:
                    answer = answer[:-sec_trailer['auth_pad_len']]
              
            retAnswer += answer
        return retAnswer

    def alter_ctx(self, newUID, bogus_binds = 0):
        answer = self.__class__(self._transport)

        answer.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__TGT, self.__TGS )
        answer.set_auth_type(self.__auth_type)
        answer.set_auth_level(self.__auth_level)

        self._max_ctx += 1
        answer.set_ctx_id(self._max_ctx)
        answer.__callid = self.__callid
        
        answer.bind(newUID, alter = 1, bogus_binds = bogus_binds)
        return answer

class DCERPC_RawCall(MSRPCRequestHeader):
    def __init__(self, op_num, data = ''):
        MSRPCRequestHeader.__init__(self)
        self['op_num'] = op_num
        self['pduData'] = data

    def setData(self, data):
        self['pduData'] = data
