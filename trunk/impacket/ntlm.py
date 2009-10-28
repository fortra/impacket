# Copyright (c) 2003-2006 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
import base64
import array
import struct
from impacket.structure import Structure

try:
    POW = None
    from Crypto.Cipher import DES
    from Crypto.Hash import MD4
except Exception:
    try:
        import POW
    except Exception:
        pass

NTLM_AUTH_NONE          = 1
NTLM_AUTH_CONNECT       = 2
NTLM_AUTH_CALL          = 3
NTLM_AUTH_PKT           = 4
NTLM_AUTH_PKT_INTEGRITY = 5
NTLM_AUTH_PKT_PRIVACY   = 6

NTLMSSP_KEY_56       = 0x80000000
NTLMSSP_KEY_EXCHANGE = 0x40000000
NTLMSSP_KEY_128      = 0x20000000
# NTLMSSP_           = 0x10000000
# NTLMSSP_           = 0x08000000
# NTLMSSP_           = 0x04000000
NTLMSSP_VERSION      = 0x02000000
# NTLMSSP_           = 0x01000000
NTLMSSP_TARGET_INFO  = 0x00800000
# NTLMSSP_           = 0x00400000
# NTLMSSP_           = 0x00200000
# NTLMSSP_           = 0x00100000
NTLMSSP_NTLM2_KEY    = 0x00080000
NTLMSSP_CHALL_NOT_NT = 0x00040000
NTLMSSP_CHALL_ACCEPT = 0x00020000
NTLMSSP_CHALL_INIT   = 0x00010000
NTLMSSP_ALWAYS_SIGN  = 0x00008000       # forces the other end to sign packets
NTLMSSP_LOCAL_CALL   = 0x00004000
NTLMSSP_WORKSTATION  = 0x00002000
NTLMSSP_DOMAIN       = 0x00001000
# NTLMSSP_           = 0x00000800
# NTLMSSP_           = 0x00000400
NTLMSSP_NTLM_KEY     = 0x00000200
NTLMSSP_NETWARE      = 0x00000100
NTLMSSP_LM_KEY       = 0x00000080
NTLMSSP_DATAGRAM     = 0x00000040
NTLMSSP_SEAL         = 0x00000020
NTLMSSP_SIGN         = 0x00000010       # means packet is signed, if verifier is wrong it fails
# NTLMSSP_           = 0x00000008
NTLMSSP_TARGET       = 0x00000004
NTLMSSP_OEM          = 0x00000002
NTLMSSP_UNICODE      = 0x00000001

class NTLMAuthHeader(Structure):
    commonHdr = (
        ('auth_type', 'B=10'),
        ('auth_level','B'),
        ('auth_pad_len','B=0'),
        ('auth_rsvrd','"\x00'),
        ('auth_ctx_id','<L=747920'),
        )
    structure = (
        ('data',':'),
    )

    def get_os_version(self):
        if self['os_version'] == '':
            return None
        else:
            mayor_v = struct.unpack('B',self['os_version'][0])[0]
            minor_v = struct.unpack('B',self['os_version'][1])[0]
            build_v = struct.unpack('H',self['os_version'][2:4])
            return (mayor_v,minor_v,build_v)

class NTLMAuthNegotiate(NTLMAuthHeader):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=1'),
        ('flags','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('host_len','<H-host_name'),
        ('host_maxlen','<H-host_name'),
        ('host_offset','<L'),
        ('host_name',':'),
        ('domain_name',':'))
                                                                                
    def __init__(self):
        NTLMAuthHeader.__init__(self)
        self['flags']= (
               NTLMSSP_KEY_128     |
               NTLMSSP_KEY_EXCHANGE|
               # NTLMSSP_LM_KEY      |
               NTLMSSP_NTLM_KEY    |
               NTLMSSP_UNICODE     |
               # NTLMSSP_ALWAYS_SIGN |
               NTLMSSP_SIGN        |
               NTLMSSP_SEAL        |
               # NTLMSSP_TARGET      |
               0)
        self['host_name']=''
        self['domain_name']=''
    
    def __str__(self):
        self['host_offset']=32
        self['domain_offset']=32+len(self['host_name'])
        return NTLMAuthHeader.__str__(self)

    def fromString(self,data):
        Structure.fromString(self,data)

        domain_offset = self['domain_offset']
        domain_end    = self['domain_len'] + domain_offset
        self['domain_name'] = data[ domain_offset : domain_end ]

        host_offset = self['host_offset']
        host_end    = self['host_len'] + host_offset
        self['host_name'] = data[ host_offset : host_end ]

        hasOsInfo = self['flags'] & NTLMSSP_VERSION
        if len(data) >= 36 and hasOsInfo:
            self['os_version'] = data[32:36]
        else:
            self['os_version'] = ''


class NTLMAuthChallenge(Structure):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=2'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L=40'),
        ('flags','<L=0'),
        ('challenge','8s'),
        ('reserved','"\x00\x00\x00\x00\x00\x00\x00\x00'),
        ('domain_name',':'))#,


class NTLMAuthChallengeResponse(NTLMAuthHeader):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=3'),
        ('lanman_len','<H-lanman'),
        ('lanman_max_len','<H-lanman'),
        ('lanman_offset','<L'),
        ('ntlm_len','<H-ntlm'),
        ('ntlm_max_len','<H-ntlm'),
        ('ntlm_offset','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('user_len','<H-user_name'),
        ('user_max_len','<H-user_name'),
        ('user_offset','<L'),
        ('host_len','<H-host_name'),
        ('host_max_len','<H-host_name'),
        ('host_offset','<L'),
        ('session_key_len','<H-session_key'),
        ('session_key_max_len','<H-session_key'),
        ('session_key_offset','<L'),
        ('flags','<L'),
        ('domain_name',':'),
        ('user_name',':'),
        ('host_name',':'),
        ('lanman',':'),
        ('ntlm',':'),
        ('session_key',':'))

    def __init__(self, username = '', password = '', challenge = ''):
        NTLMAuthHeader.__init__(self)
        self['session_key']=''
        self['user_name']=username.encode('utf-16le')
        self['domain_name']='' #"CLON".encode('utf-16le')
        self['host_name']='' #"BETS".encode('utf-16le')
        self['flags'] = (   #authResp['flags']
                # we think (beto & gera) that his flags force a memory conten leakage when a windows 2000 answers using uninitializaed verifiers
           NTLMSSP_KEY_128     |
           NTLMSSP_KEY_EXCHANGE|
           # NTLMSSP_LM_KEY      |
           NTLMSSP_NTLM_KEY    |
           NTLMSSP_UNICODE     |
           # NTLMSSP_ALWAYS_SIGN |
           NTLMSSP_SIGN        |
           NTLMSSP_SEAL        |
           # NTLMSSP_TARGET      |
           0)
        # Here we do the stuff
        if username and password:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            self['lanman']=get_ntlmv1_response(lmhash, challenge)
            self['ntlm']=get_ntlmv1_response(nthash, challenge)    # This is not used for LM_KEY nor NTLM_KEY
        else:
            self['lanman'] = ''
            self['ntlm'] = ''
            if not self['host_name']:
                self['host_name'] = 'NULL'.encode('utf-16le')      # for NULL session there must be a hostname
                                                                                
    def __str__(self):
        self['domain_offset']=64
        self['user_offset']=64+len(self['domain_name'])
        self['host_offset']=self['user_offset']+len(self['user_name'])
        self['lanman_offset']=self['host_offset']+len(self['host_name'])
        self['ntlm_offset']=self['lanman_offset']+len(self['lanman'])
        self['session_key_offset']=self['ntlm_offset']+len(self['ntlm'])
        return NTLMAuthHeader.__str__(self)

    def fromString(self,data):
        NTLMAuthHeader.fromString(self,data)

        domain_offset = self['domain_offset']
        domain_end = self['domain_len'] + domain_offset
        self['domain_name'] = array.array('u', data[ domain_offset : domain_end ]).tounicode()

        host_offset = self['host_offset']
        host_end    = self['host_len'] + host_offset
        self['host_name'] = array.array('u', data[ host_offset: host_end ]).tounicode()

        user_offset = self['user_offset']
        user_end    = self['user_len'] + user_offset
        self['user_name'] = array.array('u', data[ user_offset: user_end ]).tounicode()

        ntlm_offset = self['ntlm_offset'] 
        ntlm_end    = self['ntlm_len'] + ntlm_offset 
        self['ntlm'] = data[ ntlm_offset : ntlm_end ]

        lanman_offset = self['lanman_offset'] 
        lanman_end    = self['lanman_len'] + lanman_offset
        self['lanman'] = data[ lanman_offset : lanman_end]

        if len(data) >= 36: 
            self['os_version'] = data[32:36]
        else:
            self['os_version'] = ''

                                                                                
class ImpacketStructure(Structure):
    def set_parent(self, other):
        self.parent = other

    def get_packet(self):
        return str(self)

    def get_size(self):
        return len(self)

class NTLMAuthVerifier(NTLMAuthHeader):
    structure = (
        ('version','<L=1'),
        ('data','12s'),
        # ('_zero','<L=0'),
        # ('crc','<L=0'),
        # ('sequence','<L=0'),
    )

KNOWN_DES_INPUT = "KGS!@#$%"

def __expand_DES_key( key):
    # Expand the key from a 7-byte password key into a 8-byte DES key
    key  = key[:7]
    key += '\x00'*(7-len(key))
    s = chr(((ord(key[0]) >> 1) & 0x7f) << 1)
    s = s + chr(((ord(key[0]) & 0x01) << 6 | ((ord(key[1]) >> 2) & 0x3f)) << 1)
    s = s + chr(((ord(key[1]) & 0x03) << 5 | ((ord(key[2]) >> 3) & 0x1f)) << 1)
    s = s + chr(((ord(key[2]) & 0x07) << 4 | ((ord(key[3]) >> 4) & 0x0f)) << 1)
    s = s + chr(((ord(key[3]) & 0x0f) << 3 | ((ord(key[4]) >> 5) & 0x07)) << 1)
    s = s + chr(((ord(key[4]) & 0x1f) << 2 | ((ord(key[5]) >> 6) & 0x03)) << 1)
    s = s + chr(((ord(key[5]) & 0x3f) << 1 | ((ord(key[6]) >> 7) & 0x01)) << 1)
    s = s + chr((ord(key[6]) & 0x7f) << 1)
    return s

def __DES_block(key, msg):
    if POW:
        cipher = POW.Symmetric(POW.DES_ECB)
        cipher.encryptInit(__expand_DES_key(key))
        return cipher.update(msg)
    else:
        cipher = DES.new(__expand_DES_key(key),DES.MODE_ECB)
        return cipher.encrypt(msg)

def ntlmssp_DES_encrypt(key, challenge):
    answer  = __DES_block(key[:7], challenge)
    answer += __DES_block(key[7:14], challenge)
    answer += __DES_block(key[14:], challenge)
    return answer

def compute_lmhash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    password = password.upper()
    lmhash  = __DES_block(password[:7], KNOWN_DES_INPUT)
    lmhash += __DES_block(password[7:14], KNOWN_DES_INPUT)
    return lmhash

def compute_nthash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    password = unicode(password).encode('utf_16le')
    if POW:
        hash = POW.Digest(POW.MD4_DIGEST)
    else:        
        hash = MD4.new()
    hash.update(password)
    return hash.digest()

def get_ntlmv1_response(key, challenge):
    return ntlmssp_DES_encrypt(key, challenge)


class NTLM_HTTP(object):
    '''Parent class for NTLM HTTP classes.'''
    MSG_TYPE = None

    @classmethod
    def get_instace(cls,msg_64):
        msg = None
        msg_type = 0
        if msg_64 != '':
            msg = base64.b64decode(msg_64[5:]) # Remove the 'NTLM '
            msg_type = ord(msg[8])
    
        for _cls in NTLM_HTTP.__subclasses__():
            if msg_type == _cls.MSG_TYPE:
                instance = _cls()
                instance.fromString(msg)
                return instance

    
class NTLM_HTTP_AuthRequired(NTLM_HTTP):
    commonHdr = ()
    # Message 0 means the first HTTP request e.g. 'GET /bla.png'
    MSG_TYPE = 0

    def fromString(self,data): 
        pass


class NTLM_HTTP_AuthNegotiate(NTLM_HTTP, NTLMAuthNegotiate):
    commonHdr = ()
    MSG_TYPE = 1

    def __init__(self):
        NTLMAuthNegotiate.__init__(self)


class NTLM_HTTP_AuthChallengeResponse(NTLM_HTTP, NTLMAuthChallengeResponse):
    commonHdr = ()
    MSG_TYPE = 3

    def __init__(self):
        NTLMAuthChallengeResponse.__init__(self)

