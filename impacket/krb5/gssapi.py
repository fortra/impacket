# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino (bethus@gmail.com, @agsolino)
#
# Description:
#   RFC 1964 Partial Implementation
#   RFC 4757 Partial Implementation
#   RFC 3962 Partial Implementation

import sys
import struct
from pyasn1.codec.der import decoder, encoder
from Crypto.Hash import HMAC, MD5
from Crypto.Cipher import ARC4
from impacket.structure import Structure
from impacket.winregistry import hexdump

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

# 1.1.1. Initial Token - Checksum field
class CheckSumField(Structure):
    structure = (
        ('Lgth','<L=16'),
        ('Bnd','16s=""'),
        ('Flags','<L=0'),
    )

# 1.2.1. Per-message Tokens - MIC
class MIC(Structure):
    structure = (
        ('TOK_ID','<H=0x0101'),
        ('SGN_ALG','<H=0'),
        ('Filler','<L=0xffffffff'),
        ('SND_SEQ','8s=""'),
        ('SGN_CKSUM','8s=""'),
    )

# 1.2.2. Per-message Tokens - Wrap
class WRAP(Structure):
    structure = (
        ('TOK_ID','<H=0x0102'),
        ('SGN_ALG','<H=0'),
        ('SEAL_ALG','<H=0'),
        ('Filler','<H=0xffff'),
        ('SND_SEQ','8s=""'),
        ('SGN_CKSUM','8s=""'),
        ('Confounder','8s=""'),
    )


# 7.2.   GSS-API MIC Semantics
class GSSAPI_RC4():
    def GSS_GetMIC(self, sessionKey, data, sequenceNumber, direction = 'init'):
        token = MIC()

        # Let's pad the data
        pad = (8 - (len(data) % 8)) & 0x7
        padStr = chr(pad) * pad
        data = data + padStr
 
        token['SGN_ALG'] = GSS_HMAC
        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + '\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + '\xff'*4

        Ksign = HMAC.new(sessionKey.contents, 'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new( struct.pack('<L',15) + str(token)[:8] + data).digest()
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()
        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()
        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])
        finalData = '\x60\x23\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02' + token.getData()
        return finalData
   
    def GSS_Wrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        # Damn inacurate RFC, useful info from here
        # https://social.msdn.microsoft.com/Forums/en-US/fb98e8f4-e697-4652-bcb7-604e027e14cc/gsswrap-token-size-kerberos-and-rc4hmac?forum=os_windowsprotocols
        # and here
        # http://www.rfc-editor.org/errata_search.php?rfc=4757
        token = WRAP()

        # Let's pad the data
        pad = (8 - (len(data) % 8)) & 0x7
        padStr = chr(pad) * pad
        data = data + padStr

        token['SGN_ALG'] = GSS_HMAC
        token['SEAL_ALG'] = GSS_RC4

        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + '\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + '\xff'*4

        # Random confounder :)
        token['Confounder'] = '12345678'

        Ksign = HMAC.new(sessionKey.contents, 'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new(struct.pack('<L',13) + str(token)[:8] + token['Confounder'] + data).digest()
        Klocal = ''
        for n in sessionKey.contents:
            Klocal +=  chr(ord(n) ^ 0xF0)
 
        Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt,struct.pack('>L', sequenceNumber), MD5).digest()
        
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()

        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()

        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])

        if authData is not None:
            wrap = WRAP(authData[21:])
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

        finalData = '\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02' + token.getData()
        return cipherText, finalData

