# Copyright (c) 2003-2006 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#

import array
from binascii import crc32
try:
    from Crypto.Cipher import ARC4
    from Crypto.Hash import MD4
    POW = None
except Exception:
    try:
        import POW
    except Exception:
	print "WARNING: Crypto package not found. Some features will fail."

from impacket import ntlm
from impacket import ImpactPacket
from impacket.structure import Structure,pack,unpack

# MS/RPC Constants
MSRPC_REQUEST   = 0x00
MSRPC_RESPONSE  = 0x02
MSRPC_FAULT     = 0x03
MSRPC_ACK       = 0x07
MSRPC_BIND      = 0x0B
MSRPC_BINDACK   = 0x0C
MSRPC_BINDNAK   = 0x0D
MSRPC_ALTERCTX  = 0x0E
MSRPC_AUTH3     = 0x10

# MS/RPC Packet Flags
MSRPC_FIRSTFRAG = 0x01
MSRPC_LASTFRAG  = 0x02
MSRPC_NOTAFRAG  = 0x04
MSRPC_RECRESPOND= 0x08
MSRPC_NOMULTIPLEX = 0x10
MSRPC_NOTFORIDEMP = 0x20
MSRPC_NOTFORBCAST = 0x40
MSRPC_NOUUID    = 0x80


#Reasons for rejection of a context element, included in bind_ack result reason
rpc_provider_reason = {
    0       : 'reason_not_specified',
    1       : 'abstract_syntax_not_supported',
    2       : 'proposed_transfer_syntaxes_not_supported',
    3       : 'local_limit_exceeded'
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
    0x000006C6L : 'rpc_x_invalid_bound',                # the arrays bound are invalid
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

class MSRPCArray:
    def __init__(self, id=0, len=0, size=0):
        self._length = len
        self._size = size
        self._id = id
        self._max_len = 0
        self._offset = 0
        self._length2 = 0
        self._name = ''

    def set_max_len(self, n):
        self._max_len = n
    def set_offset(self, n):
        self._offset = n
    def set_length2(self, n):
        self._length2 = n
    def get_size(self):
        return self._size
    def set_name(self, n):
        self._name = n
    def get_name(self):
        return self._name
    def get_id(self):
        return self._id
    def rawData(self):
        return pack('<HHLLLL', self._length, self._size, 0x12345678, self._max_len, self._offset, self._length2) + self._name.encode('utf-16le')

class MSRPCNameArray:
    def __init__(self, data = None):
        self._count = 0
        self._max_count = 0
        self._elements = []

        if data: self.load(data)

    def load(self, data):
        ptr = unpack('<L', data[:4])[0]
        index = 4
        if 0 == ptr: # No data. May be a bug in certain versions of Samba.
            return

        self._count, _, self._max_count = unpack('<LLL', data[index:index+12])
        index += 12

        # Read each object's header.
        for i in range(0, self._count):
            aindex, length, size, _ = unpack('<LHHL', data[index:index+12])
            self._elements.append(MSRPCArray(aindex, length, size))
            index += 12

        # Read the objects themselves.
        for element in self._elements:
            max_len, offset, curlen = unpack('<LLL', data[index:index+12])
            index += 12
            element.set_name(unicode(data[index:index+2*curlen], 'utf-16le'))
            element.set_max_len(max_len)
            element.set_offset(offset)
            element.set_length2(curlen)
            index += 2*curlen
            if curlen & 0x1: index += 2 # Skip padding.

    def elements(self):
        return self._elements

    def rawData(self):
        ret = pack('<LLLL', 0x74747474, self._count, 0x47474747, self._max_count)
        pos_ret = []
        for i in xrange(0, self._count):
            ret += pack('<L', self._elements[i].get_id())
            data = self._elements[i].rawData()
            ret += data[:8]
            pos_ret += data[8:]

        return ret + pos_ret

class MSRPCHeader(ImpactPacket.Header):
    _SIZE = 16
    commonHdr = ( # not used, just for doc and future use
        ('ver_major','B'),                              # 0
        ('ver_minor','B'),                              # 1
        ('type','B=MSRPC_REQUEST'),                     # 2
        ('flags','B=MSRPC_FIRSTFRAG | MSRPC_LASTFRAG'), # 3
        ('represntation','<L=0x10'),                    # 4
        ('frag_len','<H=24+len(data)+len(auth_data)'),  # 8
        ('auth_len','<H=len(auth_data)-8'),             # 10
        ('call_id','<L=1'),                             # 12    <-- Common up to here (including this)
    )

    structure = ( # not used, just for documentation and future use
        ('data',':'),                                   # 24
        ('auth_data',':'),
    )

    def __init__(self, aBuffer = None, endianness = '<'):
        ImpactPacket.Header.__init__(self, self._SIZE)

        self.endianness = endianness
        self.set_version((5, 0))
        self.set_flags(MSRPC_FIRSTFRAG | MSRPC_LASTFRAG)
        if endianness == '<':
            self.set_representation(0x10)
        else:
            self.set_representation(0x0)
        self.__frag_len_set = 0
        self.set_auth_len(0)
        self.set_call_id(1)
        self.set_auth_data('')

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, self.endianness)
    def set_representation(self, representation):
        self.set_long(4, representation, self.endianness)

    def get_frag_len(self):
        return self.get_word(8, self.endianness)
    def set_frag_len(self, len):
        self.__frag_len_set == 1
        self.set_word(8, len, self.endianness)

    def get_auth_len(self):
        return self.get_word(10, self.endianness)
    def set_auth_len(self, len):
        self.set_word(10, len, self.endianness)
    def set_auth_data(self, data):
        self._auth_data = data

    def get_call_id(self):
        return self.get_long(12, self.endianness)
    def set_call_id(self, id):
        self.set_long(12, id, self.endianness)

    def get_header_size(self):
        return self._SIZE

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            self.set_op_num(self.child().OP_NUM)

    def set_alloc_hint(self, hint):
        pass

    def get_packet(self):
        if self._auth_data:
            self.set_auth_len(len(self._auth_data)-8)

        if self.child():
            contents_size = self.child().get_size()
        else:
            contents_size = 0

        contents_size += len(self._auth_data)
        if not self.__frag_len_set:
            self.set_frag_len(self.get_header_size() + contents_size)
        self.set_alloc_hint(contents_size)
        return ImpactPacket.Header.get_packet(self)+self._auth_data

class MSRPCRequestHeader(MSRPCHeader):
    _SIZE = 24

    structure = (  # not used, just for documentation and future use
        ('alloc_hint','<L=frag_len'),                   # 16
        ('ctx_id','<H=0'),                              # 20
        ('op_num','<H'),                                # 22
        ('data',':'),                                   # 24
        ('auth_data',':'),
    )

    def __init__(self, aBuffer = None, endianness = '<'):
        MSRPCHeader.__init__(self, aBuffer = aBuffer, endianness = endianness)
        self.set_type(MSRPC_REQUEST)
        self.set_ctx_id(0)
        self.set_alloc_hint(0)

    def get_alloc_hint(self):
        return self.get_long(16, self.endianness)
    def set_alloc_hint(self, len):
        self.set_long(16, len, self.endianness)

    def get_ctx_id(self):
        return self.get_word(20, self.endianness)
    def set_ctx_id(self, id):
        self.set_word(20, id, self.endianness)

    def get_op_num(self):
        return self.get_word(22, self.endianness)
    def set_op_num(self, op):
        self.set_word(22, op, self.endianness)

class MSRPCRespHeader(MSRPCHeader):
    _SIZE = 24

    structure = ( # not used, just for documentation and future use
        ('alloc_hint','<L=frag_len'),                   # 16    <-- Common up to here (including this)
        ('ctx_id','<H=0'),                              # 20
        ('cancel_count','<B'),                          # 22
        ('padding','<B=0'),                             # 23
        ('data',':'),                                   # 24
        ('auth_data',':'),
    )

    def __init__(self, aBuffer = None, endianness = '<'):
        MSRPCHeader.__init__(self, aBuffer = aBuffer, endianness = endianness)
        self.set_type(MSRPC_RESPONSE)
        self.set_ctx_id(0)
        self.set_alloc_hint(0)

    def get_alloc_hint(self):
        return self.get_long(16, self.endianness)
    def set_alloc_hint(self, len):
        self.set_long(16, len, self.endianness)

    def get_ctx_id(self):
        return self.get_word(20, self.endianness)
    def set_ctx_id(self, id):
        self.set_word(20, id, self.endianness)

    def get_cancel_count(self):
        return self.get_byte(22)

class MSRPCBind(MSRPCHeader):
    _SIZE = 72-44

    structure = ( # not used, just for documentation and future use
        ('max_tfrag','<H=4280'),
        ('max_rfrag','<H=4280'),
        ('assoc_group','<L=0'),
        ('ctx_num','B'),
    )
 
    def __init__(self, aBuffer = None, endianness = '<'):
        MSRPCHeader.__init__(self, aBuffer = aBuffer, endianness = endianness)

        self.set_type(MSRPC_BIND)
        self.set_max_tfrag(4280)
        self.set_max_rfrag(4280)
        self.set_assoc_group(0)
        self.set_ctx_num(1)

    def get_max_tfrag(self):
        return self.get_word(16, self.endianness)
    def set_max_tfrag(self, size):
        self.set_word(16, size, self.endianness)

    def get_max_rfrag(self):
        return self.get_word(18, self.endianness)
    def set_max_rfrag(self, size):
        self.set_word(18, size, self.endianness)

    def get_assoc_group(self):
        return self.get_long(20, self.endianness)
    def set_assoc_group(self, id):
        self.set_long(20, id, self.endianness)

    def get_ctx_num(self):
        return self.get_byte(24)
    def set_ctx_num(self, num):
        self._SIZE = 28+num*44
        self.set_byte(24, num)

    # --- next fields repeated for each interface to bind to
    def get_ctx_id(self, index = 0):
        return self.get_word(28+44*index, self.endianness)
    def set_ctx_id(self, id, index = 0):
        self.set_word(28+44*index, id, self.endianness)

    def get_trans_num(self, index = 0):
        return self.get_byte(30+44*index)
    def set_trans_num(self, op, index = 0):
        self.set_byte(30+44*index, op)
        self.set_byte(31+44*index, 0)

    def get_if_binuuid(self, index = 0):
        return self.get_bytes().tolist()[32+44*index:32+44*index+16]
    def set_if_binuuid(self, binuuid, index = 0):
        self.get_bytes()[32+44*index:32+len(binuuid)+44*index] = array.array('B', binuuid)

    def set_if_ver(self,ver,minor, index = 0):
        self.set_word(48+44*index, ver, self.endianness)
        self.set_word(50+44*index, minor, self.endianness)
    def get_if_ver(self, index = 0):
        return self.get_word(48+44*index, self.endianness)
    def get_if_ver_minor(self, index = 0):
        return self.get_word(50+44*index, self.endianness)
        
    def get_xfer_syntax_binuuid(self, index = 0):
        return self.get_bytes().tolist()[52+44*index:52+44*index+16]
    def set_xfer_syntax_binuuid(self, binuuid, index = 0):
        self.get_bytes()[52+44*index:52+len(binuuid)+44*index] = array.array('B', binuuid)
    
    def set_xfer_syntax_ver(self,ver, index = 0):
        self.set_long(68+44*index, ver, self.endianness)
    def get_xfer_syntax_ver(self, index = 0):
        self.get_long(68+44*index, ver, self.endianness)
        
class MSRPCBindAck(ImpactPacket.Header):
    _SIZE = 56

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, self._SIZE)

        self.set_type(MSRPC_BINDACK)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')
    def get_auth_data(self):
        data = self.get_bytes()
        return data[-self.get_auth_len()-8:]

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_max_tfrag(self):
        return self.get_word(16, '<')
    def set_max_tfrag(self, size):
        self.set_word(16, size, '<')

    def get_max_rfrag(self):
        return self.get_word(18, '<')
    def set_max_rfrag(self, size):
        self.set_word(18, size, '<')

    def get_assoc_group(self):
        return self.get_long(20, '<')
    def set_assoc_group(self, id):
        self.set_long(20, id, '<')

    def get_secondary_addr_len(self):
        return self.get_word(24, '<')
    def set_secondary_addr_len(self, len):
        self.set_word(24, len, '<')

    def get_secondary_addr(self):
        return self.get_bytes().tolist()[26:26+self.get_secondary_addr_len()]
    def set_secondary_addr(self, addr):
        self.get_bytes()[26:26+self.get_secondary_addr_len()] = array.array('B', addr)
        self.set_secondary_addr_len(len(addr))

    def _get_results_offset(self):
        answer = 26+self.get_secondary_addr_len()
        answer +=3
        answer -= answer % 4
        return answer+2
    
    def get_results_num(self):
        return self.get_byte(self._get_results_offset()-2)
    def set_results_num(self, num):
        self.set_byte(self._get_results_offset()-2, num)

    def get_result(self, index = 0):
        return self.get_word(self._get_results_offset()+2*index, '<' )
    def set_result(self, res, index = 0):
        self.set_word(self._get_results_offset()+2*index, '<' )

    def get_xfer_syntax_binuuid(self):
        return self.get_bytes().tolist()[-20:]
    def set_xfer_syntax_binuuid(self, binuuid):
        assert 20 == len(binuuid)
        self.get_bytes()[-20:] = array.array('B', binuuid)


    def get_header_size(self):
        var_size = len(self.get_bytes()) - self._SIZE
        # assert var_size > 0
        return self._SIZE + var_size

    def contains(self, aHeader):
        ImpactPacket.Header.contains(self, aHeader)
        if self.child():
            contents_size = self.child().get_size()
            self.set_op_num(self.child().OP_NUM)
            self.set_frag_len(self.get_header_size() + contents_size)
            self.set_alloc_hint(contents_size)

class MSRPCBindNak(ImpactPacket.Header):
    _SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, self._SIZE)

        self.set_type(MSRPC_BINDNAK)

        if aBuffer: self.load_header(aBuffer)

    def get_version(self):
        """ This method returns a tuple in (major, minor) form."""
        return (self.get_byte(0), self.get_byte(1))
    def set_version(self, version):
        """ This method takes a tuple in (major, minor) form."""
        self.set_byte(0, version[0])
        self.set_byte(1, version[1])

    def get_type(self):
        return self.get_byte(2)
    def set_type(self, type):
        self.set_byte(2, type)

    def get_flags(self):
        return self.get_byte(3)
    def set_flags(self, flags):
        self.set_byte(3, flags)

    def get_representation(self):
        return self.get_long(4, '<')
    def set_representation(self, representation):
        self.set_long(4, representation, '<')

    def get_frag_len(self):
        return self.get_word(8, '<')
    def set_frag_len(self, len):
        self.set_word(8, len, '<')

    def get_auth_len(self):
        return self.get_word(10, '<')
    def set_auth_len(self, len):
        self.set_word(10, len, '<')

    def get_call_id(self):
        return self.get_long(12, '<')
    def set_call_id(self, id):
        self.set_long(12, id, '<')

    def get_reason(self):
        return self.get_word(16, '<')
    def set_reason(self, reason):
        self.set_word(16, reason, '<')

    def get_assoc_group(self):
        return self.get_long(20, '<')
    def set_assoc_group(self, id):
        self.set_long(20, id, '<')


    def get_header_size(self):
        return self._SIZE

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
    def set_credentials(self, username, password): pass
    def set_auth_level(self, auth_level): pass
    def get_idempotent(self): return 0
    def set_idempotent(self, flag): pass
    def call(self, function, body):
        return self.send(DCERPC_RawCall(function, str(body)))

class DCERPC_v5(DCERPC):
    endianness = '<'
    def __init__(self, transport):
        DCERPC.__init__(self, transport)
        self.__auth_level = ntlm.NTLM_AUTH_NONE
        self.__username = None
        self.__password = None
        
    def set_auth_level(self, auth_level):
        # auth level is ntlm.NTLM_AUTH_*
        self.__auth_level = auth_level

    def set_credentials(self, username, password):
        self.set_auth_level(ntlm.NTLM_AUTH_CONNECT)
        # self.set_auth_level(ntlm.NTLM_AUTH_CALL)
        # self.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        # self.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        self.__username = username
        self.__password = password

    def bind(self, uuid, alter = 0, bogus_binds = 0):
        bind = MSRPCBind(endianness = self.endianness)

        syntax = '\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'

        if self.endianness == '>':
            syntax = unpack('<LHHBB6s', syntax)
            syntax = pack('>LHHBB6s', *syntax)

            uuid = list(unpack('<LHHBB6sHH', uuid))

            uuid[-1] ^= uuid[-2]
            uuid[-2] ^= uuid[-1]
            uuid[-1] ^= uuid[-2]
            
            uuid = pack('>LHHBB6sHH', *uuid)

        ctx = 0
        for i in range(bogus_binds):
            bind.set_ctx_id(self._ctx, index = ctx)
            bind.set_trans_num(1, index = ctx)
            bind.set_if_binuuid('A'*20, index = ctx)
            bind.set_xfer_syntax_binuuid(syntax, index = ctx)
            bind.set_xfer_syntax_ver(2, index = ctx)

            self._ctx += 1
            ctx += 1

        bind.set_ctx_id(self._ctx, index = ctx)
        bind.set_trans_num(1, index = ctx)
        bind.set_if_binuuid(uuid,index = ctx)
        bind.set_xfer_syntax_binuuid(syntax, index = ctx)
        bind.set_xfer_syntax_ver(2, index = ctx)

        bind.set_ctx_num(ctx+1)

        if alter:
            bind.set_type(MSRPC_ALTERCTX)

        if (self.__auth_level != ntlm.NTLM_AUTH_NONE):
            if (self.__username is None) or (self.__password is None):
                self.__username, self.__password, nth, lmh = self._transport.get_credentials()
            auth = ntlm.NTLMAuthNegotiate()
            auth['auth_level']  = self.__auth_level
            auth['auth_ctx_id'] = self._ctx + 79231 
            bind.set_auth_data(str(auth))

        self._transport.send(bind.get_packet())

        s = self._transport.recv()
        if s != 0:
            resp = MSRPCBindAck(s)
        else:
            return 0 #mmm why not None?

        if resp.get_type() == MSRPC_BINDNAK:
            resp = MSRPCBindNak(s)
            status_code = resp.get_reason()
            if rpc_status_codes.has_key(status_code):
                raise Exception(rpc_status_codes[status_code], resp)
            else:
                raise Exception('Unknown DCE RPC fault status code: %.8x' % status_code, resp)
            
        self.__max_xmit_size = resp.get_max_tfrag()

        if self.__auth_level != ntlm.NTLM_AUTH_NONE:
            authResp = ntlm.NTLMAuthChallenge(data = resp.get_auth_data().tostring())
            self._ntlm_challenge = authResp['challenge']
            response = ntlm.NTLMAuthChallengeResponse(self.__username,self.__password, self._ntlm_challenge)
            response['auth_ctx_id'] = self._ctx + 79231 
            response['auth_level'] = self.__auth_level

            if self.__auth_level in (ntlm.NTLM_AUTH_CONNECT, ntlm.NTLM_AUTH_PKT_INTEGRITY, ntlm.NTLM_AUTH_PKT_PRIVACY):
                if self.__password:
                    key = ntlm.compute_nthash(self.__password)
                    if POW:
                        hash = POW.Digest(POW.MD4_DIGEST)
                    else:
                        hash = MD4.new()
                    hash.update(key)
                    key = hash.digest()
                else:
                    key = '\x00'*16

	    if POW:
		cipher = POW.Symmetric(POW.RC4)
		cipher.encryptInit(key)
		self.cipher_encrypt = cipher.update
	    else:
		cipher = ARC4.new(key)
		self.cipher_encrypt = cipher.encrypt

	    if response['flags'] & ntlm.NTLMSSP_KEY_EXCHANGE:
		session_key = 'A'*16     # XXX Generate random session key
		response['session_key'] = self.cipher_encrypt(session_key)
		if POW:
		    cipher = POW.Symmetric(POW.RC4)
		    cipher.encryptInit(session_key)
		    self.cipher_encrypt = cipher.update
		else:
		    cipher = ARC4.new(session_key)
		    self.cipher_encrypt = cipher.encrypt

	    self.sequence = 0

	    auth3 = MSRPCHeader()
	    auth3.set_type(MSRPC_AUTH3)
	    auth3.set_auth_data(str(response))
	    self._transport.send(auth3.get_packet(), forceWriteAndx = 1)

        return resp     # means packet is signed, if verifier is wrong it fails

    def _transport_send(self, rpc_packet, forceWriteAndx = 0, forceRecv = 0):
        if self.__auth_level == ntlm.NTLM_AUTH_CALL:
            if rpc_packet.get_type() == MSRPC_REQUEST:
                response = ntlm.NTLMAuthChallengeResponse(self.__username,self.__password, self._ntlm_challenge)
                response['auth_ctx_id'] = self._ctx + 79231 
                response['auth_level'] = self.__auth_level
                rpc_packet.set_auth_data(str(response))
                
        if self.__auth_level in [ntlm.NTLM_AUTH_PKT_INTEGRITY, ntlm.NTLM_AUTH_PKT_PRIVACY]:
            verifier = ntlm.NTLMAuthVerifier()
            verifier['auth_level'] = self.__auth_level
            verifier['auth_ctx_id'] = self._ctx + 79231 
            verifier['data'] = ' '*12
            rpc_packet.set_auth_data(str(verifier))

            rpc_call = rpc_packet.child()
            if self.__auth_level == ntlm.NTLM_AUTH_PKT_PRIVACY:
                data = DCERPC_RawCall(rpc_call.OP_NUM)
                data.setData(self.cipher_encrypt(rpc_call.get_packet()))
                rpc_packet.contains(data)
            
            crc = crc32(rpc_call.get_packet())
            data = pack('<LLL',0,crc,self.sequence)     # XXX 0 can be anything: randomize
            data = self.cipher_encrypt(data)
            verifier['data'] = data
            rpc_packet.set_auth_data(str(verifier))

            self.sequence += 1

        self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)

    def send(self, data):
        # This endianness does necesary have to be the same as the one used in the bind
        # however, the endianness of the stub data MUST be the same as the one in the bind
        # i.e. the endianness on the next call could be hardcoded to any
        rpc = MSRPCRequestHeader(endianness = self.endianness)

        rpc.set_ctx_id(self._ctx)

        max_frag = self._max_frag

        if data.get_size() > self.__max_xmit_size - 32:
            max_frag = self.__max_xmit_size - 32    # XXX: 32 is a safe margin for auth data

        if self._max_frag:
            max_frag = min(max_frag, self._max_frag)

        if max_frag:
            packet = str(data.get_bytes().tostring())
            offset = 0
            rawcall = DCERPC_RawCall(data.OP_NUM)

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
                rpc.set_flags(flags)

                rawcall.setData(toSend)
                rpc.contains(rawcall)
                self._transport_send(rpc, forceWriteAndx = 1, forceRecv = flags & MSRPC_LASTFRAG)
        else:
            rpc.contains(data)
            self._transport_send(rpc)

    def recv(self):
        self.response_data = self._transport.recv()
        self.response_header = MSRPCRespHeader(self.response_data)
        off = self.response_header.get_header_size()
        if self.response_header.get_type() == MSRPC_FAULT and self.response_header.get_frag_len() >= off+4:
            status_code = unpack("<L",self.response_data[off:off+4])[0]
            if rpc_status_codes.has_key(status_code):
                raise Exception(rpc_status_codes[status_code])
            else:
                raise Exception('Unknown DCE RPC fault status code: %.8x' % status_code)
        answer = self.response_data[off:]
        auth_len = self.response_header.get_auth_len()
        if auth_len:
            auth_len += 8
            auth_data = answer[-auth_len:]
            ntlmssp   = ntlm.NTLMAuthHeader(data = auth_data)
            answer = answer[:-auth_len]

            if ntlmssp['auth_level'] == ntlm.NTLM_AUTH_PKT_PRIVACY:
                answer = self.cipher_encrypt(answer)

            if ntlmssp['auth_pad_len']:
                answer = answer[:-ntlmssp['auth_pad_len']]

            if ntlmssp['auth_level'] in [ntlm.NTLM_AUTH_PKT_INTEGRITY, ntlm.NTLM_AUTH_PKT_PRIVACY]:
                ntlmssp = ntlm.NTLMAuthVerifier(data = auth_data)
                data = self.cipher_encrypt(ntlmssp['data'])
                zero, crc, sequence = unpack('<LLL', data)
                self.sequence = sequence + 1

        return answer

    def alter_ctx(self, newUID, bogus_binds = 0):
        answer = self.__class__(self._transport)

        answer.set_credentials(self.__username, self.__password)
        answer.set_auth_level(self.__auth_level)

        self._max_ctx += 1
        answer.set_ctx_id(self._max_ctx)
        
        answer.bind(newUID, alter = 1, bogus_binds = bogus_binds)
        return answer

class DCERPC_RawCall(ImpactPacket.Header):
    def __init__(self, op_num, data = ''):
        self.OP_NUM = op_num
        ImpactPacket.Header.__init__(self)
        self.setData(data)

    def setData(self, data):
        self.get_bytes()[:] = array.array('B', data)

    def get_header_size(self):
        return len(self.get_bytes())


