# Copyright (c) 2003-2012 CORE Security Technologies:
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import base64
import array
import struct
import calendar
import time
import hashlib
import random
import string
import binascii
from impacket.structure import Structure
from impacket import LOG

# This is important. NTLMv2 is not negotiated by the client or server. 
# It is used if set locally on both sides. Change this item if you don't want to use 
# NTLMv2 by default and fall back to NTLMv1 (with EXTENDED_SESSION_SECURITY or not)
# Check the following links:
# http://davenport.sourceforge.net/ntlm.html
# http://blogs.msdn.com/b/openspecification/archive/2010/04/20/ntlm-keys-and-sundry-stuff.aspx
# http://social.msdn.microsoft.com/Forums/en-US/os_interopscenarios/thread/c8f488ed-1b96-4e06-bd65-390aa41138d1/
# So I'm setting a global variable to control this, this can also be set programmatically

USE_NTLMv2 = True # if false will fall back to NTLMv1 (or NTLMv1 with ESS a.k.a NTLM2)

def computeResponse(flags, serverChallenge, clientChallenge,  serverName, domain, user, password, lmhash = '', nthash = '', use_ntlmv2 = USE_NTLMv2):
    if use_ntlmv2:
       return computeResponseNTLMv2(flags, serverChallenge, clientChallenge,  serverName, domain, user, password, lmhash, nthash, use_ntlmv2 = use_ntlmv2)
    else:
       return computeResponseNTLMv1(flags, serverChallenge, clientChallenge,  serverName, domain, user, password, lmhash, nthash, use_ntlmv2 = use_ntlmv2)
try:
    POW = None
    from Crypto.Cipher import ARC4
    from Crypto.Cipher import DES
    from Crypto.Hash import MD4
except Exception:
    try:
        import POW
    except Exception:
        LOG.critical("Warning: You don't have any crypto installed. You need PyCrypto")
        LOG.critical("See http://www.pycrypto.org/")

NTLM_AUTH_NONE          = 1
NTLM_AUTH_CONNECT       = 2
NTLM_AUTH_CALL          = 3
NTLM_AUTH_PKT           = 4
NTLM_AUTH_PKT_INTEGRITY = 5
NTLM_AUTH_PKT_PRIVACY   = 6

NTLMSSP_KEY_56             = 0x80000000
NTLMSSP_KEY_EXCHANGE       = 0x40000000
NTLMSSP_KEY_128            = 0x20000000
# NTLMSSP_                 = 0x10000000
# NTLMSSP_                 = 0x08000000
# NTLMSSP_                 = 0x04000000
NTLMSSP_VERSION            = 0x02000000
# NTLMSSP_                 = 0x01000000
NTLMSSP_TARGET_INFO        = 0x00800000
# NTLMSSP_                 = 0x00200000
# NTLMSSP_                 = 0x00100000
NTLMSSP_NTLM2_KEY          = 0x00080000
NTLMSSP_NOT_NT_KEY         = 0x00400000
NTLMSSP_CHALL_NOT_NT       = 0x00040000
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_CHALL_INIT         = 0x00010000
NTLMSSP_ALWAYS_SIGN        = 0x00008000       # forces the other end to sign packets
NTLMSSP_LOCAL_CALL         = 0x00004000
NTLMSSP_WORKSTATION        = 0x00002000
NTLMSSP_DOMAIN             = 0x00001000
# NTLMSSP_                 = 0x00000800
# NTLMSSP_                 = 0x00000400
NTLMSSP_NTLM_KEY           = 0x00000200
NTLMSSP_NETWARE            = 0x00000100
NTLMSSP_LM_KEY             = 0x00000080
NTLMSSP_DATAGRAM           = 0x00000040
NTLMSSP_SEAL               = 0x00000020
NTLMSSP_SIGN               = 0x00000010       # means packet is signed, if verifier is wrong it fails
# NTLMSSP_                 = 0x00000008
NTLMSSP_TARGET             = 0x00000004
NTLMSSP_OEM                = 0x00000002
NTLMSSP_UNICODE            = 0x00000001

# AV_PAIR constants
NTLMSSP_AV_EOL              = 0x00
NTLMSSP_AV_HOSTNAME         = 0x01
NTLMSSP_AV_DOMAINNAME       = 0x02
NTLMSSP_AV_DNS_HOSTNAME     = 0x03
NTLMSSP_AV_DNS_DOMAINNAME   = 0x04
NTLMSSP_AV_DNS_TREENAME     = 0x05
NTLMSSP_AV_FLAGS            = 0x06
NTLMSSP_AV_TIME             = 0x07
NTLMSSP_AV_RESTRICTIONS     = 0x08
NTLMSSP_AV_TARGET_NAME      = 0x09
NTLMSSP_AV_CHANNEL_BINDINGS = 0x0a

class AV_PAIRS():
    def __init__(self, data = None):
        self.fields = {}
        if data is not None:
            self.fromString(data)

    def __setitem__(self,key,value):
        self.fields[key] = (len(value),value)

    def __getitem__(self, key):
        if self.fields.has_key(key):
           return self.fields[key]
        return None

    def __delitem__(self, key):
        del self.fields[key]

    def __len__(self):
        return len(self.getData())

    def __str__(self):
        return len(self.getData())

    def fromString(self, data):
        tInfo = data
        fType = 0xff
        while fType is not NTLMSSP_AV_EOL:
            fType = struct.unpack('<H',tInfo[:struct.calcsize('<H')])[0]
            tInfo = tInfo[struct.calcsize('<H'):]
            length = struct.unpack('<H',tInfo[:struct.calcsize('<H')])[0]
            tInfo = tInfo[struct.calcsize('<H'):]
            content = tInfo[:length]
            self.fields[fType]=(length,content)
            tInfo = tInfo[length:]

    def dump(self):
        for i in self.fields.keys():
            print "%s: {%r}" % (i,self[i])

    def getData(self):
        if self.fields.has_key(NTLMSSP_AV_EOL):
            del self.fields[NTLMSSP_AV_EOL]
        ans = ''
        for i in self.fields.keys():
            ans+= struct.pack('<HH', i, self[i][0])
            ans+= self[i][1]
 
        # end with a NTLMSSP_AV_EOL
        ans += struct.pack('<HH', NTLMSSP_AV_EOL, 0)

        return ans

class NTLMAuthMixin:
    def get_os_version(self):
        if self['os_version'] == '':
            return None
        else:
            mayor_v = struct.unpack('B',self['os_version'][0])[0]
            minor_v = struct.unpack('B',self['os_version'][1])[0]
            build_v = struct.unpack('H',self['os_version'][2:4])
            return (mayor_v,minor_v,build_v)
        
class NTLMAuthNegotiate(Structure, NTLMAuthMixin):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=1'),
        ('flags','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L=0'),
        ('host_len','<H-host_name'),
        ('host_maxlen','<H-host_name'),
        ('host_offset','<L=0'),
        ('os_version',':'),
        ('host_name',':'),
        ('domain_name',':'))
                                                                                
    def __init__(self):
        Structure.__init__(self)
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
        self['os_version']=''
    
    def getData(self):
        if len(self.fields['host_name']) > 0:
            self['flags'] |= NTLMSSP_WORKSTATION
        if len(self.fields['domain_name']) > 0:
            self['flags'] |= NTLMSSP_DOMAIN
        if len(self.fields['os_version']) > 0:
            self['flags'] |= NTLMSSP_VERSION
        if (self['flags'] & NTLMSSP_VERSION) == NTLMSSP_VERSION:
            version_len = 8
        else:
            version_len = 0
        if (self['flags'] & NTLMSSP_WORKSTATION) == NTLMSSP_WORKSTATION:
            self['host_offset']=32 + version_len
        if (self['flags'] & NTLMSSP_DOMAIN) == NTLMSSP_DOMAIN:
            self['domain_offset']=32+len(self['host_name']) + version_len
        return Structure.getData(self)

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
            self['os_version'] = data[32:40]
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
        ('reserved','8s=""'),
        ('TargetInfoFields_len','<H-TargetInfoFields'),
        ('TargetInfoFields_max_len','<H-TargetInfoFields'),
        ('TargetInfoFields_offset','<L'),
        ('VersionLen','_-Version','self.checkVersion(self["flags"])'), 
        ('Version',':'),
        ('domain_name',':'),
        ('TargetInfoFields',':'))

    def checkVersion(self, flags):
        if flags is not None:
           if flags & NTLMSSP_VERSION == 0:
              return 0
        return 8

    def getData(self):
        if self['TargetInfoFields'] is not None and type(self['TargetInfoFields']) is not str:
            raw_av_fields = self['TargetInfoFields'].getData()
            self['TargetInfoFields'] = raw_av_fields
        return Structure.getData(self)

    def fromString(self,data):
        Structure.fromString(self,data)
        # Just in case there's more data after the TargetInfoFields
        self['TargetInfoFields'] = self['TargetInfoFields'][:self['TargetInfoFields_len']]
        # We gotta process the TargetInfoFields
        #if self['TargetInfoFields_len'] > 0:
        #    av_pairs = AV_PAIRS(self['TargetInfoFields'][:self['TargetInfoFields_len']]) 
        #    self['TargetInfoFields'] = av_pairs

        return self
        
class NTLMAuthChallengeResponse(Structure, NTLMAuthMixin):

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
        ('VersionLen','_-Version','self.checkVersion(self["flags"])'), 
        ('Version',':=""'),
        ('MICLen','_-MIC','self.checkMIC(self["flags"])'),
        ('MIC',':=""'),
        ('domain_name',':'),
        ('user_name',':'),
        ('host_name',':'),
        ('lanman',':'),
        ('ntlm',':'),
        ('session_key',':'))

    def __init__(self, username = '', password = '', challenge = '', lmhash = '', nthash = '', flags = 0):
        Structure.__init__(self)
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
        if username and ( lmhash != '' or nthash != ''):            
            self['lanman'] = get_ntlmv1_response(lmhash, challenge)
            self['ntlm'] = get_ntlmv1_response(nthash, challenge)
        elif (username and password):
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            self['lanman']=get_ntlmv1_response(lmhash, challenge)
            self['ntlm']=get_ntlmv1_response(nthash, challenge)    # This is not used for LM_KEY nor NTLM_KEY
        else:
            self['lanman'] = ''
            self['ntlm'] = ''
            if not self['host_name']:
                self['host_name'] = 'NULL'.encode('utf-16le')      # for NULL session there must be a hostname

    def checkVersion(self, flags):
        if flags is not None:
           if flags & NTLMSSP_VERSION == 0:
              return 0
        return 8

    def checkMIC(self, flags):
        # TODO: Find a proper way to check the MIC is in there
        if flags is not None:
           if flags & NTLMSSP_VERSION == 0:
              return 0
        return 16
                                                                                
    def getData(self):
        self['domain_offset']=64+self.checkMIC(self["flags"])+self.checkVersion(self["flags"])
        self['user_offset']=64+self.checkMIC(self["flags"])+self.checkVersion(self["flags"])+len(self['domain_name'])
        self['host_offset']=self['user_offset']+len(self['user_name'])
        self['lanman_offset']=self['host_offset']+len(self['host_name'])
        self['ntlm_offset']=self['lanman_offset']+len(self['lanman'])
        self['session_key_offset']=self['ntlm_offset']+len(self['ntlm'])
        return Structure.getData(self)

    def fromString(self,data):
        Structure.fromString(self,data)
        # [MS-NLMP] page 27
        # Payload data can be present in any order within the Payload field, 
        # with variable-length padding before or after the data

        domain_offset = self['domain_offset']
        domain_end = self['domain_len'] + domain_offset
        self['domain_name'] = data[ domain_offset : domain_end ]

        host_offset = self['host_offset']
        host_end    = self['host_len'] + host_offset
        self['host_name'] = data[ host_offset: host_end ]

        user_offset = self['user_offset']
        user_end    = self['user_len'] + user_offset
        self['user_name'] = data[ user_offset: user_end ]

        ntlm_offset = self['ntlm_offset'] 
        ntlm_end    = self['ntlm_len'] + ntlm_offset 
        self['ntlm'] = data[ ntlm_offset : ntlm_end ]

        lanman_offset = self['lanman_offset'] 
        lanman_end    = self['lanman_len'] + lanman_offset
        self['lanman'] = data[ lanman_offset : lanman_end]

        #if len(data) >= 36: 
        #    self['os_version'] = data[32:36]
        #else:
        #    self['os_version'] = ''

class ImpacketStructure(Structure):
    def set_parent(self, other):
        self.parent = other

    def get_packet(self):
        return str(self)

    def get_size(self):
        return len(self)

class ExtendedOrNotMessageSignature(Structure):
    def __init__(self, flags = 0, **kargs):
        if flags & NTLMSSP_NTLM2_KEY:
            self.structure = self.extendedMessageSignature
        else:
            self.structure = self.MessageSignature
        return Structure.__init__(self, **kargs)

class NTLMMessageSignature(ExtendedOrNotMessageSignature):
      extendedMessageSignature = (
          ('Version','<L=1'),
          ('Checksum','<q'),
          ('SeqNum','<i'),
      )

      MessageSignature = (
          ('Version','<L=1'),
          ('RandomPad','<i=0'),
          ('Checksum','<i'),
          ('SeqNum','<i'),
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

# High level functions to use NTLMSSP

def getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    # Let's prepare a Type 1 NTLMSSP Message
    auth = NTLMAuthNegotiate()
    auth['flags']=0
    if signingRequired:
       auth['flags'] = NTLMSSP_KEY_EXCHANGE | NTLMSSP_SIGN | NTLMSSP_ALWAYS_SIGN | NTLMSSP_SEAL
    if use_ntlmv2:
       auth['flags'] |= NTLMSSP_TARGET_INFO
    auth['flags'] |= NTLMSSP_NTLM_KEY | NTLMSSP_NTLM2_KEY | NTLMSSP_UNICODE | NTLMSSP_TARGET |  NTLMSSP_KEY_128 | NTLMSSP_KEY_56 
    auth['domain_name'] = domain
    return auth

def getNTLMSSPType3(type1, type2, user, password, domain, lmhash = '', nthash = '', use_ntlmv2 = USE_NTLMv2):

    ntlmChallenge = NTLMAuthChallenge(type2)

    # Let's start with the original flags sent in the type1 message
    responseFlags = type1['flags']

    # Token received and parsed. Depending on the authentication 
    # method we will create a valid ChallengeResponse
    ntlmChallengeResponse = NTLMAuthChallengeResponse(user, password, ntlmChallenge['challenge'])

    clientChallenge = "".join([random.choice(string.digits+string.letters) for i in xrange(8)])

    serverName = ntlmChallenge['TargetInfoFields']

    ntResponse, lmResponse, sessionBaseKey = computeResponse(ntlmChallenge['flags'], ntlmChallenge['challenge'], clientChallenge, serverName, domain, user, password, lmhash, nthash, use_ntlmv2 )

    # Let's check the return flags
    if (ntlmChallenge['flags'] & NTLMSSP_NTLM2_KEY) == 0:
        # No extended session security, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NTLM2_KEY
    if (ntlmChallenge['flags'] & NTLMSSP_KEY_128 ) == 0:
        # No support for 128 key len, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_KEY_128
    if (ntlmChallenge['flags'] & NTLMSSP_KEY_EXCHANGE) == 0:
        # No key exchange supported, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_KEY_EXCHANGE
    if (ntlmChallenge['flags'] & NTLMSSP_SEAL) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_SEAL
    if (ntlmChallenge['flags'] & NTLMSSP_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_SIGN
    if (ntlmChallenge['flags'] & NTLMSSP_ALWAYS_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_ALWAYS_SIGN

    keyExchangeKey = KXKEY(ntlmChallenge['flags'],sessionBaseKey, lmResponse, ntlmChallenge['challenge'], password, lmhash, nthash,use_ntlmv2)

    # Special case for anonymous login
    if user == '' and password == '' and lmhash == '' and nthash == '':
      keyExchangeKey = '\x00'*16

    # If we set up key exchange, let's fill the right variables
    if ntlmChallenge['flags'] & NTLMSSP_KEY_EXCHANGE:
       # not exactly what I call random tho :\
       # exportedSessionKey = this is the key we should use to sign
       exportedSessionKey = "".join([random.choice(string.digits+string.letters) for i in xrange(16)])
       #exportedSessionKey = "A"*16
       #print "keyExchangeKey %r" % keyExchangeKey
       # Let's generate the right session key based on the challenge flags
       #if responseFlags & NTLMSSP_NTLM2_KEY:
           # Extended session security enabled
       #    if responseFlags & NTLMSSP_KEY_128:
               # Full key
       #        exportedSessionKey = exportedSessionKey
       #    elif responseFlags & NTLMSSP_KEY_56:
               # Only 56-bit key
       #        exportedSessionKey = exportedSessionKey[:7]
       #    else:
       #        exportedSessionKey = exportedSessionKey[:5]
       #elif responseFlags & NTLMSSP_KEY_56:
           # No extended session security, just 56 bits key
       #    exportedSessionKey = exportedSessionKey[:7] + '\xa0'
       #else:
       #    exportedSessionKey = exportedSessionKey[:5] + '\xe5\x38\xb0'

       encryptedRandomSessionKey = generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey)
    else:
       encryptedRandomSessionKey = None
       # [MS-NLMP] page 46
       exportedSessionKey        = keyExchangeKey

    ntlmChallengeResponse['flags'] = responseFlags
    ntlmChallengeResponse['domain_name'] = domain.encode('utf-16le')
    ntlmChallengeResponse['lanman'] = lmResponse
    ntlmChallengeResponse['ntlm'] = ntResponse
    if encryptedRandomSessionKey is not None: 
        ntlmChallengeResponse['session_key'] = encryptedRandomSessionKey

    return ntlmChallengeResponse, exportedSessionKey


# NTLMv1 Algorithm

def generateSessionKeyV1(password, lmhash, nthash):
    if POW:
        hash = POW.Digest(POW.MD4_DIGEST)
    else:        
        hash = MD4.new()
    hash.update(NTOWFv1(password, lmhash, nthash))
    return hash.digest()
    
def computeResponseNTLMv1(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='', nthash='', use_ntlmv2 = USE_NTLMv2):
    if (user == '' and password == ''): 
        # Special case for anonymous authentication
        lmResponse = ''
        ntResponse = ''
    else:
        lmhash = LMOWFv1(password, lmhash, nthash)
        nthash = NTOWFv1(password, lmhash, nthash)
        if flags & NTLMSSP_LM_KEY:
           ntResponse = ''
           lmResponse = get_ntlmv1_response(lmhash, serverChallenge)
        elif flags & NTLMSSP_NTLM2_KEY:
           md5 = hashlib.new('md5')
           chall = (serverChallenge + clientChallenge)
           md5.update(chall)
           ntResponse = ntlmssp_DES_encrypt(nthash, md5.digest()[:8])
           lmResponse = clientChallenge + '\x00'*16
        else:
           ntResponse = get_ntlmv1_response(nthash,serverChallenge)
           lmResponse = get_ntlmv1_response(lmhash, serverChallenge)
   
    sessionBaseKey = generateSessionKeyV1(password, lmhash, nthash)
    return ntResponse, lmResponse, sessionBaseKey

def compute_lmhash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    password = password.upper()
    lmhash  = __DES_block(password[:7], KNOWN_DES_INPUT)
    lmhash += __DES_block(password[7:14], KNOWN_DES_INPUT)
    return lmhash

def NTOWFv1(password, lmhash = '', nthash=''):
    if nthash != '':
       return nthash
    return compute_nthash(password)   

def LMOWFv1(password, lmhash = '', nthash=''):
    if lmhash != '':
       return lmhash
    return compute_lmhash(password)

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

# NTLMv2 Algorithm - as described in MS-NLMP Section 3.3.2

# Crypto Stuff

def MAC(flags, handle, signingKey, seqNum, message):
   # [MS-NLMP] Section 3.4.4
   # Returns the right messageSignature depending on the flags
   messageSignature = NTLMMessageSignature(flags)
   if flags & NTLMSSP_NTLM2_KEY:
       if flags & NTLMSSP_KEY_EXCHANGE:
           messageSignature['Version'] = 1
           messageSignature['Checksum'] = struct.unpack('<q',handle(hmac_md5(signingKey, struct.pack('<i',seqNum)+message)[:8]))[0]
           messageSignature['SeqNum'] = seqNum
           seqNum += 1
       else:
           messageSignature['Version'] = 1
           messageSignature['Checksum'] = struct.unpack('<q',hmac_md5(signingKey, struct.pack('<i',seqNum)+message)[:8])[0]
           messageSignature['SeqNum'] = seqNum
           seqNum += 1
   else:
       messageSignature['Version'] = 1
       messageSignature['Checksum'] = struct.pack('<i',binascii.crc32(message))
       messageSignature['RandomPad'] = 0
       messageSignature['RandomPad'] = handle(struct.pack('<i',messageSignature['RandomPad']))
       messageSignature['Checksum'] = struct.unpack('<i',handle(messageSignature['Checksum']))[0]
       messageSignature['SeqNum'] = handle('\x00\x00\x00\x00')
       messageSignature['SeqNum'] = struct.unpack('<i',messageSignature['SeqNum'])[0] ^ seqNum
       messageSignature['RandomPad'] = 0
       
   return messageSignature

def SEAL(flags, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, handle):
   sealedMessage = handle(messageToEncrypt)
   signature = MAC(flags, handle, signingKey, seqNum, messageToSign)
   return sealedMessage, signature

def SIGN(flags, signingKey, message, seqNum, handle):
   return MAC(flags, handle, signingKey, seqNum, message)

def SIGNKEY(flags, randomSessionKey, mode = 'Client'):
   if flags & NTLMSSP_NTLM2_KEY:
       if mode == 'Client':
           md5 = hashlib.new('md5')
           md5.update(randomSessionKey + "session key to client-to-server signing key magic constant\x00")
           signKey = md5.digest()
       else:
           md5 = hashlib.new('md5')
           md5.update(randomSessionKey + "session key to server-to-client signing key magic constant\x00")
           signKey = md5.digest()
   else:
       signKey = None
   return signKey

def SEALKEY(flags, randomSessionKey, mode = 'Client'):
   if flags & NTLMSSP_NTLM2_KEY:
       if flags & NTLMSSP_KEY_128:
           sealKey = randomSessionKey
       elif flags & NTLMSSP_KEY_56:
           sealKey = randomSessionKey[:7]
       else:
           sealKey = randomSessionKey[:5]

       if mode == 'Client':
               md5 = hashlib.new('md5')
               md5.update(sealKey + 'session key to client-to-server sealing key magic constant\x00')
               sealKey = md5.digest()
       else:
               md5 = hashlib.new('md5')
               md5.update(sealKey + 'session key to server-to-client sealing key magic constant\x00')
               sealKey = md5.digest()

   elif flags & NTLMSSP_KEY_56:
       sealKey = randomSessionKey[:7] + '\xa0'
   else:
       sealKey = randomSessionKey[:5] + '\xe5\x38\xb0'

   return sealKey


def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
   if POW:
       cipher = POW.Symmetric(POW.RC4)
       cipher.encryptInit(keyExchangeKey)
       cipher_encrypt = cipher.update
   else:
       cipher = ARC4.new(keyExchangeKey)
       cipher_encrypt = cipher.encrypt

   sessionKey = cipher_encrypt(exportedSessionKey)
   return sessionKey

def KXKEY(flags, sessionBaseKey, lmChallengeResponse, serverChallenge, password, lmhash, nthash, use_ntlmv2 = USE_NTLMv2):
   if use_ntlmv2:
       return sessionBaseKey

   if flags & NTLMSSP_NTLM2_KEY:
       if flags & NTLMSSP_NTLM_KEY: 
          keyExchangeKey = hmac_md5(sessionBaseKey, serverChallenge + lmChallengeResponse[:8])
       else:
          keyExchangeKey = sessionBaseKey
   elif flags & NTLMSSP_NTLM_KEY:
       if flags & NTLMSSP_LM_KEY:
          keyExchangeKey = __DES_block(LMOWFv1(password,lmhash)[:7], lmChallengeResponse[:8]) + __DES_block(LMOWFv1(password,lmhash)[7] + '\xBD\xBD\xBD\xBD\xBD\xBD', lmChallengeResponse[:8])
       elif flags & NTLMSSP_NOT_NT_KEY:
          keyExchangeKey = LMOWFv1(password,lmhash)[:8] + '\x00'*8
       else:
          keyExchangeKey = sessionBaseKey
   else:
       raise "Can't create a valid KXKEY!"

   return keyExchangeKey
      
def hmac_md5(key, data):
    if POW:
        h = POW.Hmac(POW.MD5_DIGEST, key)
        h.update(data)
        result = h.mac()
    else:
        import hmac
        h = hmac.new(key)
        h.update(data)
        result = h.digest()
    return result

def NTOWFv2( user, password, domain, hash = ''):
    if hash != '':
       theHash = hash 
    else:
       theHash = compute_nthash(password)
    return hmac_md5(theHash, user.upper().encode('utf-16le') + domain.encode('utf-16le'))

def LMOWFv2( user, password, domain, lmhash = ''):
    return NTOWFv2( user, password, domain, lmhash)


def computeResponseNTLMv2(flags, serverChallenge, clientChallenge,  serverName, domain, user, password, lmhash = '', nthash = '', use_ntlmv2 = USE_NTLMv2):

    responseServerVersion = '\x01'
    hiResponseServerVersion = '\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)
    responseKeyLM = LMOWFv2(user, password, domain, lmhash)

    # If you're running test-ntlm, comment the following lines and uncoment the ones that are commented. Don't forget to turn it back after the tests!
    ######################
    av_pairs = AV_PAIRS(serverName)
    # In order to support SPN target name validation, we have to add this to the serverName av_pairs. Otherwise we will get access denied
    # This is set at Local Security Policy -> Local Policies -> Security Options -> Server SPN target name validation level
    av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
    if av_pairs[NTLMSSP_AV_TIME] is not None:
       aTime = av_pairs[NTLMSSP_AV_TIME][1]
    else:
       aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )
       #aTime = '\x00'*8
       av_pairs[NTLMSSP_AV_TIME] = aTime
    serverName = av_pairs.getData()
          
    ######################
    #aTime = '\x00'*8
    ######################
    temp = responseServerVersion + hiResponseServerVersion + '\x00' * 6 + aTime + clientChallenge + '\x00' * 4 + serverName + '\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    if (user == '' and password == ''):
        # Special case for anonymous authentication
        ntChallengeResponse = ''
        lmChallengeResponse = ''

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

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

