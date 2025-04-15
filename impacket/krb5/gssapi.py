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
#   RFC 1964 Partial Implementation
#   RFC 4757 Partial Implementation
#   RFC 4121 Partial Implementation
#   RFC 3962 Partial Implementation
#
# Author:
#   Alberto Solino (@agsolino)
#
import struct
import random
import string
from six import b

from Cryptodome.Hash import HMAC, MD5
from Cryptodome.Cipher import ARC4

from impacket.structure import Structure
from impacket.krb5 import constants, crypto

# Our random number generator
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

# Constants
GSS_C_DCE_STYLE     = 0x1000
GSS_C_DELEG_FLAG    = 1
GSS_C_MUTUAL_FLAG   = 2
GSS_C_REPLAY_FLAG   = 4
GSS_C_SEQUENCE_FLAG = 8
GSS_C_CONF_FLAG     = 0x10
GSS_C_INTEG_FLAG    = 0x20

# Mic Semantics
GSS_HMAC = 0x11
# Wrap Semantics
GSS_RC4  = 0x10

# 2.  Key Derivation for Per-Message Tokens
KG_USAGE_ACCEPTOR_SEAL  = 22
KG_USAGE_ACCEPTOR_SIGN  = 23
KG_USAGE_INITIATOR_SEAL = 24
KG_USAGE_INITIATOR_SIGN = 25

KRB5_AP_REQ = struct.pack('<H', 0x1)

# Kerberos OID: 1.2.840.113554.1.2.2
KRB_OID = b'\x06\t*\x86H\x86\xf7\x12\x01\x02\x02'

class MechIndepToken():
    
    def __init__(self, data=None, oid=KRB_OID):
        self.data = data
        self.token_oid = oid
    
    @staticmethod
    def from_bytes(data=None):
        if data[0:1] != b'\x60':
            raise Exception('Incorrect token data!')
        data = data[1:]
        length, data = MechIndepToken.get_length(data)
        token_data = data[0:length]
        oid_length, data = MechIndepToken.get_length(token_data[1:])
        token_oid = token_data[0:oid_length+2]
        data = token_data[oid_length+2:]
        return MechIndepToken(data, token_oid)

    @staticmethod
    def get_length(data):
        if data[0] < 128:
            return data[0], data
        else:
            bytes_count = data[0] - 128
            return int.from_bytes(data[1:1+bytes_count], byteorder='big', signed=False), data[1+bytes_count:]

    @staticmethod
    def encode_length(length):
        if length < 128:
            return length.to_bytes(1, byteorder = 'big', signed = False)
        else:
            lb = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return (128+len(lb)).to_bytes(1, byteorder = 'big', signed = False) + lb

    def to_bytes(self):
        temp = self.token_oid + self.data
        temp = b'\x60' + self.encode_length(len(temp)) + temp
        return temp[:-len(self.data)], self.data

# 1.1.1. Initial Token - Checksum field
class CheckSumField(Structure):
    structure = (
        ('Lgth','<L=16'),
        ('Bnd','16s=b""'),
        ('Flags','<L=0'),
    )

def GSSAPI(cipher):
    if cipher.enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        return GSSAPI_AES256()
    if cipher.enctype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        return GSSAPI_AES128()
    elif cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
        return GSSAPI_RC4()
    else:
        raise Exception('Unsupported etype 0x%x' % cipher.enctype)

# 7.2.   GSS-API MIC Semantics
class GSSAPI_RC4:
    # 1.2.1. Per-message Tokens - MIC
    class MIC(Structure):
        structure = (
            ('TOK_ID','<H=0x0101'),
            ('SGN_ALG','<H=0'),
            ('Filler','<L=0xffffffff'),
            ('SND_SEQ','8s=b""'),
            ('SGN_CKSUM','8s=b""'),
        )

    # 1.2.2. Per-message Tokens - Wrap
    class WRAP(Structure):
        structure = (
            ('TOK_ID','<H=0x0102'),
            ('SGN_ALG','<H=0'),
            ('SEAL_ALG','<H=0'),
            ('Filler','<H=0xffff'),
            ('SND_SEQ','8s=b""'),
            ('SGN_CKSUM','8s=b""'),
            ('Confounder','8s=b""'),
        )

    def GSS_GetMIC(self, sessionKey, data, sequenceNumber, direction = 'init'):
        GSS_GETMIC_HEADER = b'\x60\x23\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
        token = self.MIC()

        # Let's pad the data
        pad = (4 - (len(data) % 4)) & 0x3
        padStr = b(chr(pad)) * pad
        data += padStr
 
        token['SGN_ALG'] = GSS_HMAC
        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\xff'*4

        Ksign = HMAC.new(sessionKey.contents, b'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new( struct.pack('<L',15) + token.getData()[:8] + data).digest()
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()
        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()
        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])
        finalData = GSS_GETMIC_HEADER + token.getData()
        return finalData
   
    def GSS_Wrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        # Damn inacurate RFC, useful info from here
        # https://social.msdn.microsoft.com/Forums/en-US/fb98e8f4-e697-4652-bcb7-604e027e14cc/gsswrap-token-size-kerberos-and-rc4hmac?forum=os_windowsprotocols
        # and here
        # http://www.rfc-editor.org/errata_search.php?rfc=4757
        GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
        token = self.WRAP()

        # Let's pad the data
        pad = (8 - (len(data) % 8)) & 0x7
        padStr = b(chr(pad)) * pad
        data += padStr

        token['SGN_ALG'] = GSS_HMAC
        token['SEAL_ALG'] = GSS_RC4

        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\xff'*4

        # Random confounder :)
        token['Confounder'] = b(''.join([rand.choice(string.ascii_letters) for _ in range(8)]))

        Ksign = HMAC.new(sessionKey.contents, b'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new(struct.pack('<L',13) + token.getData()[:8] + token['Confounder'] + data).digest()

        Klocal = bytearray()
        from builtins import bytes
        for n in bytes(sessionKey.contents):
            Klocal.append( n ^ 0xF0)

        Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt,struct.pack('>L', sequenceNumber), MD5).digest()
        
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()

        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()

        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])

        if authData is not None:
            from impacket.dcerpc.v5.rpcrt import SEC_TRAILER
            wrap = self.WRAP(authData[len(SEC_TRAILER()) + len(GSS_WRAP_HEADER):])
            snd_seq = wrap['SND_SEQ']

            Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
            Kseq = HMAC.new(Kseq, wrap['SGN_CKSUM'], MD5).digest()

            snd_seq = ARC4.new(Kseq).encrypt(wrap['SND_SEQ'])
 
            Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
            Kcrypt = HMAC.new(Kcrypt,snd_seq[:4], MD5).digest()
            rc4 = ARC4.new(Kcrypt)
            cipherText = rc4.decrypt(token['Confounder'] + data)[8:]
        elif encrypt is True:
            rc4 = ARC4.new(Kcrypt)
            token['Confounder'] = rc4.encrypt(token['Confounder'])
            cipherText = rc4.encrypt(data)
        else:
            cipherText = data

        finalData = GSS_WRAP_HEADER + token.getData()
        return cipherText, finalData

    def GSS_Unwrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        return self.GSS_Wrap(sessionKey, data, sequenceNumber, direction, encrypt, authData)

    def GSS_Wrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True):
       
        if encrypt:
            data += b'\x01'

        token = self.WRAP()
        token['SGN_ALG'] = GSS_HMAC
        token['SEAL_ALG'] = GSS_RC4

        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\xff'*4

        # Random confounder :)
        token['Confounder'] = b(''.join([rand.choice(string.ascii_letters) for _ in range(8)]))

        Ksign = HMAC.new(sessionKey.contents, b'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new(struct.pack('<L',13) + token.getData()[:8] + token['Confounder'] + data).digest()

        Klocal = bytearray()
        from builtins import bytes
        for n in bytes(sessionKey.contents):
            Klocal.append( n ^ 0xF0)

        Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt,struct.pack('>L', sequenceNumber), MD5).digest()
        
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()

        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()

        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])

        if encrypt is False:
            sspi_wrap = MechIndepToken.from_bytes(data)

            wrap = self.WRAP(sspi_wrap.data[:32])
            data = sspi_wrap.data[32:]
            
            Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
            Kseq = HMAC.new(Kseq, wrap['SGN_CKSUM'], MD5).digest()

            snd_seq = ARC4.new(Kseq).encrypt(wrap['SND_SEQ'])

            Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
            Kcrypt = HMAC.new(Kcrypt,snd_seq[:4], MD5).digest()
            rc4 = ARC4.new(Kcrypt)
            cipherText = rc4.decrypt(token['Confounder'] + data)[8:]
            return cipherText[:-1], None
        
        elif encrypt is True:
            rc4 = ARC4.new(Kcrypt)
            token['Confounder'] = rc4.encrypt(token['Confounder'])
            cipherText = rc4.encrypt(data)
            finalData, cipherText = MechIndepToken(token.getData() + cipherText, KRB_OID).to_bytes()
            return cipherText, finalData

    def GSS_Unwrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init'):
        return self.GSS_Wrap_LDAP(sessionKey, data, sequenceNumber, direction, encrypt=False)

class GSSAPI_AES():
    checkSumProfile = None
    cipherType = None

    class MIC(Structure):
        structure = (
            ('TOK_ID','>H=0x0404'),
            ('Flags','B=0'),
            ('Filler0','B=0xff'),
            ('Filler','>L=0xffffffff'),
            ('SND_SEQ','8s=b""'),
            ('SGN_CKSUM','12s=b""'),
        )

    # 1.2.2. Per-message Tokens - Wrap
    class WRAP(Structure):
        structure = (
            ('TOK_ID','>H=0x0504'),
            ('Flags','B=0'),
            ('Filler','B=0xff'),
            ('EC','>H=0'),
            ('RRC','>H=0'),
            ('SND_SEQ','8s=b""'),
        )

    def GSS_GetMIC(self, sessionKey, data, sequenceNumber, direction = 'init'):
        token = self.MIC()

        # Let's pad the data
        pad = (4 - (len(data) % 4)) & 0x3
        padStr = chr(pad) * pad
        data += padStr

        checkSumProfile = self.checkSumProfile()

        token['Flags'] = 4
        token['SND_SEQ'] = struct.pack('>Q',sequenceNumber)
        token['SGN_CKSUM'] = checkSumProfile.checksum(sessionKey, KG_USAGE_INITIATOR_SIGN, data + token.getData()[:16])
 
        return token.getData()
   
    def rotate(self, data, numBytes):
        numBytes %= len(data)
        left = len(data) - numBytes
        result = data[left:] + data[:left]
        return result

    def unrotate(self, data, numBytes):
        numBytes %= len(data)
        result = data[numBytes:] + data[:numBytes]
        return result
        
    def GSS_Wrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True):
        token = self.WRAP()

        cipher = self.cipherType()

        # Let's pad the data
        pad = (cipher.blocksize - (len(data) % cipher.blocksize)) & 15
        padStr = b'\xFF' * pad
        data += padStr

        # The RRC field ([RFC4121] section 4.2.5) is 12 if no encryption is requested or 28 if encryption 
        # is requested. The RRC field is chosen such that all the data can be encrypted in place.
        rrc = 28

        token['Flags'] = 6
        token['EC'] = pad
        token['RRC'] = 0
        token['SND_SEQ'] = struct.pack('>Q',sequenceNumber)

        cipherText = cipher.encrypt(sessionKey, KG_USAGE_INITIATOR_SEAL,  data + token.getData(), None)
        token['RRC'] = rrc

        cipherText = self.rotate(cipherText, token['RRC'] + token['EC'])

        #nn = self.unrotate(cipherText, token['RRC'] + token['EC'])
        ret1 = cipherText[len(self.WRAP()) + token['RRC'] + token['EC']:]
        ret2 = token.getData() + cipherText[:len(self.WRAP()) + token['RRC'] + token['EC']]

        return ret1, ret2

    def GSS_Unwrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        from impacket.dcerpc.v5.rpcrt import SEC_TRAILER

        cipher = self.cipherType()
        token = self.WRAP(authData[len(SEC_TRAILER()):])

        rotated = authData[len(self.WRAP())+len(SEC_TRAILER()):] + data
 
        cipherText = self.unrotate(rotated, token['RRC'] + token['EC'])
        plainText = cipher.decrypt(sessionKey, KG_USAGE_ACCEPTOR_SEAL,  cipherText)

        return plainText[:-(token['EC']+len(self.WRAP()))], None

    def GSS_Wrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, use_padding=False):
        token = self.WRAP()

        cipher = self.cipherType()

        pad = 0
        if use_padding:
        # Let's pad the data
            pad = (cipher.blocksize - (len(data) % cipher.blocksize)) & 15
            padStr = b'\xFF' * pad
            data += padStr

        # The RRC field ([RFC4121] section 4.2.5) is 12 if no encryption is requested or 28 if encryption 
        # is requested. The RRC field is chosen such that all the data can be encrypted in place.
        rrc = 28

        token['Flags'] = 6
        token['EC'] = pad
        token['RRC'] = 0
        token['SND_SEQ'] = struct.pack('>Q',sequenceNumber)

        cipherText = cipher.encrypt(sessionKey, KG_USAGE_INITIATOR_SEAL,  data + token.getData(), None)
        token['RRC'] = rrc

        cipherText = self.rotate(cipherText, token['RRC'] + token['EC'])

        #nn = self.unrotate(cipherText, token['RRC'] + token['EC'])
        # ret1 = cipherText[len(self.WRAP()) + token['RRC'] + token['EC']:]
        # ret2 = token.getData() + cipherText[:len(self.WRAP()) + token['RRC'] + token['EC']]
        ret1 = cipherText
        ret2 = token.getData()

        return ret1, ret2

    def GSS_Unwrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init'):

        cipher = self.cipherType()
        token = self.WRAP(data[:16])

        rotated = data[16:]
 
        cipherText = self.unrotate(rotated, token['RRC'] + token['EC'])
        plainText = cipher.decrypt(sessionKey, KG_USAGE_ACCEPTOR_SEAL,  cipherText)

        return plainText[:-(token['EC']+ 16)], None

class GSSAPI_AES256(GSSAPI_AES):
    checkSumProfile = crypto._SHA1AES256
    cipherType = crypto._AES256CTS

class GSSAPI_AES128(GSSAPI_AES):
    checkSumProfile = crypto._SHA1AES128
    cipherType = crypto._AES128CTS
