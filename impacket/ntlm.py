# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

from __future__ import division
from __future__ import print_function
import base64
import struct
import calendar
import time
import hashlib
import random
import string
import binascii
from six import b

from impacket.structure import Structure
from impacket import LOG


# This is important. NTLMv2 is not negotiated by the client or server. 
# It is used if set locally on both sides. Change this item if you don't want to use 
# NTLMv2 by default and fall back to NTLMv1 (with EXTENDED_SESSION_SECURITY or not)
# Check the following links:
# https://davenport.sourceforge.io/ntlm.html
# https://blogs.msdn.microsoft.com/openspecification/2010/04/19/ntlm-keys-and-sundry-stuff/
# https://social.msdn.microsoft.com/Forums/c8f488ed-1b96-4e06-bd65-390aa41138d1/msnlmp-msntht-determining-ntlm-v1-or-v2-in-http-authentication?forum=os_specifications
# So I'm setting a global variable to control this, this can also be set programmatically

USE_NTLMv2 = True # if false will fall back to NTLMv1 (or NTLMv1 with ESS a.k.a NTLM2)
TEST_CASE = False # Only set to True when running Test Cases


def computeResponse(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='', nthash='',
                    use_ntlmv2=USE_NTLMv2):
    if use_ntlmv2:
        return computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password,
                                     lmhash, nthash, use_ntlmv2=use_ntlmv2)
    else:
        return computeResponseNTLMv1(flags, serverChallenge, clientChallenge, serverName, domain, user, password,
                                     lmhash, nthash, use_ntlmv2=use_ntlmv2)
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

NTLM_AUTH_NONE          = 1
NTLM_AUTH_CONNECT       = 2
NTLM_AUTH_CALL          = 3
NTLM_AUTH_PKT           = 4
NTLM_AUTH_PKT_INTEGRITY = 5
NTLM_AUTH_PKT_PRIVACY   = 6

# If set, requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN
# with NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_56 to
# the client in the CHALLENGE_MESSAGE. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128
# are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be
# returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_56 if it is
# supported. An alternate name for this field is NTLMSSP_NEGOTIATE_56.
NTLMSSP_NEGOTIATE_56                       = 0x80000000

# If set, requests an explicit key exchange. This capability SHOULD be used because it improves security for message
# integrity or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1, and 3.2.5.2.2 for details. An alternate name for
# this field is NTLMSSP_NEGOTIATE_KEY_EXCH.
NTLMSSP_NEGOTIATE_KEY_EXCH                 = 0x40000000

# If set, requests 128-bit session key negotiation. An alternate name for this field is NTLMSSP_NEGOTIATE_128.
# If the client sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE, the server MUST return
# NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if the client sets NTLMSSP_NEGOTIATE_SEAL or
# NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are
# requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be
# returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_128 if it
# is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_128
NTLMSSP_NEGOTIATE_128                      = 0x20000000

NTLMSSP_RESERVED_1                         = 0x10000000
NTLMSSP_RESERVED_2                         = 0x08000000
NTLMSSP_RESERVED_3                         = 0x04000000

# If set, requests the protocol version number. The data corresponding to this flag is provided in the Version field
# of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and the AUTHENTICATE_MESSAGE.<22> An alternate name for this field
# is NTLMSSP_NEGOTIATE_VERSION
NTLMSSP_NEGOTIATE_VERSION                  = 0x02000000
NTLMSSP_RESERVED_4                         = 0x01000000

# If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE (section 2.2.1.2) are populated.
# An alternate name for this field is NTLMSSP_NEGOTIATE_TARGET_INFO.
NTLMSSP_NEGOTIATE_TARGET_INFO              = 0x00800000

# If set, requests the usage of the LMOWF (section 3.3). An alternate name for this field is
# NTLMSSP_REQUEST_NON_NT_SESSION_KEY.
NTLMSSP_REQUEST_NON_NT_SESSION_KEY         = 0x00400000
NTLMSSP_RESERVED_5                         = 0x00200000

# If set, requests an identify level token. An alternate name for this field is NTLMSSP_NEGOTIATE_IDENTIFY
NTLMSSP_NEGOTIATE_IDENTIFY                 = 0x00100000

# If set, requests usage of the NTLM v2 session security. NTLM v2 session security is a misnomer because it is not
# NTLM v2. It is NTLM v1 using the extended session security that is also in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
# and NTLMSSP_NEGOTIATE_LM_KEY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the
# client. NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be
# used, and extended session security signing and sealing requires support from the client and the server in order to
# be used.<23> An alternate name for this field is NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_NTLM2                    = 0x00080000
NTLMSSP_TARGET_TYPE_SHARE                  = 0x00040000

# If set, TargetName MUST be a server name. The data corresponding to this flag is provided by the server in the
# TargetName field of the CHALLENGE_MESSAGE. If this bit is set, then NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set.
# This flag MUST be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field
# is NTLMSSP_TARGET_TYPE_SERVER
NTLMSSP_TARGET_TYPE_SERVER                 = 0x00020000

# If set, TargetName MUST be a domain name. The data corresponding to this flag is provided by the server in the
# TargetName field of the CHALLENGE_MESSAGE. If set, then NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST
# be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is
# NTLMSSP_TARGET_TYPE_DOMAIN.
NTLMSSP_TARGET_TYPE_DOMAIN                 = 0x00010000

# If set, requests the presence of a signature block on all messages. NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the
# NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. NTLMSSP_NEGOTIATE_ALWAYS_SIGN is overridden
# by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL, if they are supported. An alternate name for this field is
# NTLMSSP_NEGOTIATE_ALWAYS_SIGN.
NTLMSSP_NEGOTIATE_ALWAYS_SIGN              = 0x00008000       # forces the other end to sign packets
NTLMSSP_RESERVED_6                         = 0x00004000

# This flag indicates whether the Workstation field is present. If this flag is not set, the Workstation field MUST be
# ignored. If this flag is set, the length field of the Workstation field specifies whether the workstation name is
# nonempty or not.<24> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000

# If set, the domain name is provided (section 2.2.1.1).<25> An alternate name for this field is
# NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 0x00001000

# If set, the connection SHOULD be anonymous
NTLMSSP_NEGOTIATE_ANONYMOUS                = 0x00000800

# If set, LM authentication is not allowed and only NT authentication is used.
NTLMSSP_NEGOTIATE_NT_ONLY                  = 0x00000400

# If set, requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST be set in the
# NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is
# NTLMSSP_NEGOTIATE_NTLM
NTLMSSP_NEGOTIATE_NTLM                     = 0x00000200
NTLMSSP_RESERVED_8                         = 0x00000100

# If set, requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY and
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be
# returned to the client. NTLM v2 authentication session key generation MUST be supported by both the client and the
# DC in order to be used, and extended session security signing and sealing requires support from the client and the
# server to be used. An alternate name for this field is NTLMSSP_NEGOTIATE_LM_KEY.
NTLMSSP_NEGOTIATE_LM_KEY                   = 0x00000080

# If set, requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCH
# MUST always be set in the AUTHENTICATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate
# name for this field is NTLMSSP_NEGOTIATE_DATAGRAM.
NTLMSSP_NEGOTIATE_DATAGRAM                 = 0x00000040

# If set, requests session key negotiation for message confidentiality. If the client sends NTLMSSP_NEGOTIATE_SEAL to
# the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the
# CHALLENGE_MESSAGE. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and
# NTLMSSP_NEGOTIATE_128, if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_SEAL.
NTLMSSP_NEGOTIATE_SEAL                     = 0x00000020

# If set, requests session key negotiation for message signatures. If the client sends NTLMSSP_NEGOTIATE_SIGN to the
# server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE.
# An alternate name for this field is NTLMSSP_NEGOTIATE_SIGN.
NTLMSSP_NEGOTIATE_SIGN                     = 0x00000010       # means packet is signed, if verifier is wrong it fails
NTLMSSP_RESERVED_9                         = 0x00000008

# If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied. An alternate name for this
# field is NTLMSSP_REQUEST_TARGET.
NTLMSSP_REQUEST_TARGET                     = 0x00000004

# If set, requests OEM character set encoding. An alternate name for this field is NTLM_NEGOTIATE_OEM. See bit A for
# details.
NTLM_NEGOTIATE_OEM                         = 0x00000002

# If set, requests Unicode character set encoding. An alternate name for this field is NTLMSSP_NEGOTIATE_UNICODE.
NTLMSSP_NEGOTIATE_UNICODE                  = 0x00000001

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

class AV_PAIRS:
    def __init__(self, data = None):
        self.fields = {}
        if data is not None:
            self.fromString(data)

    def __setitem__(self,key,value):
        self.fields[key] = (len(value),value)

    def __getitem__(self, key):
        if key in self.fields:
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
        for i in list(self.fields.keys()):
            print("%s: {%r}" % (i,self[i]))

    def getData(self):
        if NTLMSSP_AV_EOL in self.fields:
            del self.fields[NTLMSSP_AV_EOL]
        ans = b''
        for i in list(self.fields.keys()):
            ans+= struct.pack('<HH', i, self[i][0])
            ans+= self[i][1]
 
        # end with a NTLMSSP_AV_EOL
        ans += struct.pack('<HH', NTLMSSP_AV_EOL, 0)

        return ans

# [MS-NLMP] 2.2.2.10 VERSION
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
class VERSION(Structure):
    NTLMSSP_REVISION_W2K3 = 0x0F

    structure = (
        ('ProductMajorVersion', '<B=0'),
        ('ProductMinorVersion', '<B=0'),
        ('ProductBuild', '<H=0'),
        ('Reserved', '3s=""'),
        ('NTLMRevisionCurrent', '<B=self.NTLMSSP_REVISION_W2K3'),
    )

class NTLMAuthNegotiate(Structure):

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
               NTLMSSP_NEGOTIATE_128     |
               NTLMSSP_NEGOTIATE_KEY_EXCH|
               # NTLMSSP_LM_KEY      |
               NTLMSSP_NEGOTIATE_NTLM    |
               NTLMSSP_NEGOTIATE_UNICODE     |
               # NTLMSSP_ALWAYS_SIGN |
               NTLMSSP_NEGOTIATE_SIGN        |
               NTLMSSP_NEGOTIATE_SEAL        |
               # NTLMSSP_TARGET      |
               0)
        self['host_name']=''
        self['domain_name']=''
        self['os_version']=''
        self._workstation = ''

    def setWorkstation(self, workstation):
        self._workstation = workstation

    def getWorkstation(self):
        return self._workstation

    def __hasNegotiateVersion(self):
        return (self['flags'] & NTLMSSP_NEGOTIATE_VERSION) == NTLMSSP_NEGOTIATE_VERSION

    def getData(self):
        if len(self.fields['host_name']) > 0:
            self['flags'] |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        if len(self.fields['domain_name']) > 0:
            self['flags'] |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
        version_len = len(self.fields['os_version'])
        if version_len > 0:
            self['flags'] |= NTLMSSP_NEGOTIATE_VERSION
        elif self.__hasNegotiateVersion():
            raise Exception('Must provide the os_version field if the NTLMSSP_NEGOTIATE_VERSION flag is set')
        if (self['flags'] & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) == NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED:
            self['host_offset']=32 + version_len
        if (self['flags'] & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) == NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED:
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

        if len(data) >= 36 and self.__hasNegotiateVersion():
            self['os_version'] = VERSION(data[32:])
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

    @staticmethod
    def checkVersion(flags):
        if flags is not None:
           if flags & NTLMSSP_NEGOTIATE_VERSION == 0:
              return 0
        return 8

    def getData(self):
        if self['TargetInfoFields'] is not None and type(self['TargetInfoFields']) is not bytes:
            raw_av_fields = self['TargetInfoFields'].getData()
            self['TargetInfoFields'] = raw_av_fields
        return Structure.getData(self)

    def fromString(self,data):
        Structure.fromString(self,data)
        self['domain_name'] = data[self['domain_offset']:][:self['domain_len']]
        self['TargetInfoFields'] = data[self['TargetInfoFields_offset']:][:self['TargetInfoFields_len']]
        return self
        
class NTLMAuthChallengeResponse(Structure):

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
            # we think (beto & gera) that his flags force a memory conten leakage when a windows 2000 answers using
            # uninitializaed verifiers
           NTLMSSP_NEGOTIATE_128     |
           NTLMSSP_NEGOTIATE_KEY_EXCH|
           # NTLMSSP_LM_KEY      |
           NTLMSSP_NEGOTIATE_NTLM    |
           NTLMSSP_NEGOTIATE_UNICODE     |
           # NTLMSSP_ALWAYS_SIGN |
           NTLMSSP_NEGOTIATE_SIGN        |
           NTLMSSP_NEGOTIATE_SEAL        |
           # NTLMSSP_TARGET      |
           0)
        # Here we do the stuff
        if username and ( lmhash != '' or nthash != ''):            
            self['lanman'] = get_ntlmv1_response(lmhash, challenge)
            self['ntlm'] = get_ntlmv1_response(nthash, challenge)
        elif username and password:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            self['lanman']=get_ntlmv1_response(lmhash, challenge)
            self['ntlm']=get_ntlmv1_response(nthash, challenge)    # This is not used for LM_KEY nor NTLM_KEY
        else:
            self['lanman'] = ''
            self['ntlm'] = ''
            if not self['host_name']:
                self['host_name'] = 'NULL'.encode('utf-16le')      # for NULL session there must be a hostname

    @staticmethod
    def checkVersion(flags):
        if flags is not None:
           if flags & NTLMSSP_NEGOTIATE_VERSION == 0:
              return 0
        return 8

    @staticmethod
    def checkMIC(flags):
        # TODO: Find a proper way to check the MIC is in there
        if flags is not None:
           if flags & NTLMSSP_NEGOTIATE_VERSION == 0:
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

class ImpacketStructure(Structure):
    def set_parent(self, other):
        self.parent = other

    def get_packet(self):
        return str(self)

    def get_size(self):
        return len(self)

class ExtendedOrNotMessageSignature(Structure):
    def __init__(self, flags = 0, **kargs):
        if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.structure = self.extendedMessageSignature
        else:
            self.structure = self.MessageSignature
        return Structure.__init__(self, **kargs)

class NTLMMessageSignature(ExtendedOrNotMessageSignature):
      extendedMessageSignature = (
          ('Version','<L=1'),
          ('Checksum','<q'),
          ('SeqNum','<I'),
      )

      MessageSignature = (
          ('Version','<L=1'),
          ('RandomPad','<I=0'),
          ('Checksum','<I'),
          ('SeqNum','<I'),
      )

KNOWN_DES_INPUT = b"KGS!@#$%"

def __expand_DES_key(key):
    # Expand the key from a 7-byte password key into a 8-byte DES key
    if not isinstance(key, bytes):
        key = bytes(key)
    key  = bytearray(key[:7]).ljust(7, b'\x00')
    s = bytearray()
    s.append(((key[0] >> 1) & 0x7f) << 1)
    s.append(((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
    s.append(((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
    s.append(((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
    s.append(((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
    s.append(((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
    s.append(((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
    s.append((key[6] & 0x7f) << 1)
    return bytes(s)

def __DES_block(key, msg):
    cipher = DES.new(__expand_DES_key(key),DES.MODE_ECB)
    return cipher.encrypt(msg)

def ntlmssp_DES_encrypt(key, challenge):
    answer  = __DES_block(key[:7], challenge)
    answer += __DES_block(key[7:14], challenge)
    answer += __DES_block(key[14:], challenge)
    return answer

# High level functions to use NTLMSSP

def getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    # Let's do some encoding checks before moving on. Kind of dirty, but found effective when dealing with
    # international characters.
    import sys
    encoding = sys.getfilesystemencoding()
    if encoding is not None:
        try:
            workstation.encode('utf-16le')
        except:
            workstation = workstation.decode(encoding)
        try:
            domain.encode('utf-16le')
        except:
            domain = domain.decode(encoding)

    # Let's prepare a Type 1 NTLMSSP Message
    auth = NTLMAuthNegotiate()
    auth['flags']=0
    if signingRequired:
       auth['flags'] = NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                       NTLMSSP_NEGOTIATE_SEAL
    if use_ntlmv2:
       auth['flags'] |= NTLMSSP_NEGOTIATE_TARGET_INFO
    auth['flags'] |= NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_UNICODE | \
                     NTLMSSP_REQUEST_TARGET |  NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56

    # We're not adding workstation / domain fields this time. Normally Windows clients don't add such information but,
    # we will save the workstation name to be used later.
    auth.setWorkstation(workstation)

    return auth

def getNTLMSSPType3(type1, type2, user, password, domain, lmhash = '', nthash = '', use_ntlmv2 = USE_NTLMv2):

    # Safety check in case somebody sent password = None.. That's not allowed. Setting it to '' and hope for the best.
    if password is None:
        password = ''

    # Let's do some encoding checks before moving on. Kind of dirty, but found effective when dealing with
    # international characters.
    import sys
    encoding = sys.getfilesystemencoding()
    if encoding is not None:
        try:
            user.encode('utf-16le')
        except:
            user = user.decode(encoding)
        try:
            password.encode('utf-16le')
        except:
            password = password.decode(encoding)
        try:
            domain.encode('utf-16le')
        except:
            domain = user.decode(encoding)

    ntlmChallenge = NTLMAuthChallenge(type2)

    # Let's start with the original flags sent in the type1 message
    responseFlags = type1['flags']

    # Token received and parsed. Depending on the authentication 
    # method we will create a valid ChallengeResponse
    ntlmChallengeResponse = NTLMAuthChallengeResponse(user, password, ntlmChallenge['challenge'])

    clientChallenge = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(8)]))

    serverName = ntlmChallenge['TargetInfoFields']

    ntResponse, lmResponse, sessionBaseKey = computeResponse(ntlmChallenge['flags'], ntlmChallenge['challenge'],
                                                             clientChallenge, serverName, domain, user, password,
                                                             lmhash, nthash, use_ntlmv2)

    # Let's check the return flags
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) == 0:
        # No extended session security, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_128 ) == 0:
        # No support for 128 key len, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_128
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH) == 0:
        # No key exchange supported, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_KEY_EXCH
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_SEAL) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SEAL
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SIGN
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_ALWAYS_SIGN

    keyExchangeKey = KXKEY(ntlmChallenge['flags'], sessionBaseKey, lmResponse, ntlmChallenge['challenge'], password,
                           lmhash, nthash, use_ntlmv2)

    # Special case for anonymous login
    if user == '' and password == '' and lmhash == '' and nthash == '':
      keyExchangeKey = b'\x00'*16

    # If we set up key exchange, let's fill the right variables
    if ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH:
       # not exactly what I call random tho :\
       # exportedSessionKey = this is the key we should use to sign
       exportedSessionKey = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(16)]))
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
    ntlmChallengeResponse['host_name'] = type1.getWorkstation().encode('utf-16le')
    if lmResponse == '':
        ntlmChallengeResponse['lanman'] = b'\x00'
    else:
        ntlmChallengeResponse['lanman'] = lmResponse
    ntlmChallengeResponse['ntlm'] = ntResponse
    if encryptedRandomSessionKey is not None: 
        ntlmChallengeResponse['session_key'] = encryptedRandomSessionKey

    return ntlmChallengeResponse, exportedSessionKey


# NTLMv1 Algorithm

def generateSessionKeyV1(password, lmhash, nthash):
    hash = MD4.new()
    hash.update(NTOWFv1(password, lmhash, nthash))
    return hash.digest()


def computeResponseNTLMv1(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                          nthash='', use_ntlmv2=USE_NTLMv2):
    if user == '' and password == '':
        # Special case for anonymous authentication
        lmResponse = ''
        ntResponse = ''
    else:
        lmhash = LMOWFv1(password, lmhash, nthash)
        nthash = NTOWFv1(password, lmhash, nthash)
        if flags & NTLMSSP_NEGOTIATE_LM_KEY:
           ntResponse = ''
           lmResponse = get_ntlmv1_response(lmhash, serverChallenge)
        elif flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
           md5 = hashlib.new('md5')
           chall = (serverChallenge + clientChallenge)
           md5.update(chall)
           ntResponse = ntlmssp_DES_encrypt(nthash, md5.digest()[:8])
           lmResponse = clientChallenge + b'\x00'*16
        else:
           ntResponse = get_ntlmv1_response(nthash,serverChallenge)
           lmResponse = get_ntlmv1_response(lmhash, serverChallenge)
   
    sessionBaseKey = generateSessionKeyV1(password, lmhash, nthash)
    return ntResponse, lmResponse, sessionBaseKey

def compute_lmhash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    password = password.upper()
    lmhash  = __DES_block(b(password[:7]), KNOWN_DES_INPUT)
    lmhash += __DES_block(b(password[7:14]), KNOWN_DES_INPUT)
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
    try:
        password = str(password).encode('utf_16le')
    except UnicodeDecodeError:
        import sys
        password = password.decode(sys.getfilesystemencoding()).encode('utf_16le')

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
   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if flags & NTLMSSP_NEGOTIATE_KEY_EXCH:
           messageSignature['Version'] = 1
           messageSignature['Checksum'] = \
           struct.unpack('<q', handle(hmac_md5(signingKey, struct.pack('<i', seqNum) + message)[:8]))[0]
           messageSignature['SeqNum'] = seqNum
           seqNum += 1
       else:
           messageSignature['Version'] = 1
           messageSignature['Checksum'] = struct.unpack('<q',hmac_md5(signingKey, struct.pack('<i',seqNum)+message)[:8])[0]
           messageSignature['SeqNum'] = seqNum
           seqNum += 1
   else:
       messageSignature['Version'] = 1
       messageSignature['Checksum'] = struct.pack('<I',binascii.crc32(message)& 0xFFFFFFFF)
       messageSignature['RandomPad'] = 0
       messageSignature['RandomPad'] = handle(struct.pack('<I',messageSignature['RandomPad']))
       messageSignature['Checksum'] = struct.unpack('<I',handle(messageSignature['Checksum']))[0]
       messageSignature['SeqNum'] = handle(b'\x00\x00\x00\x00')
       messageSignature['SeqNum'] = struct.unpack('<I',messageSignature['SeqNum'])[0] ^ seqNum
       messageSignature['RandomPad'] = 0
       
   return messageSignature

def SEAL(flags, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, handle):
   sealedMessage = handle(messageToEncrypt)
   signature = MAC(flags, handle, signingKey, seqNum, messageToSign)
   return sealedMessage, signature

def SIGN(flags, signingKey, message, seqNum, handle):
   return MAC(flags, handle, signingKey, seqNum, message)

def SIGNKEY(flags, randomSessionKey, mode = 'Client'):
   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if mode == 'Client':
           md5 = hashlib.new('md5')
           md5.update(randomSessionKey + b"session key to client-to-server signing key magic constant\x00")
           signKey = md5.digest()
       else:
           md5 = hashlib.new('md5')
           md5.update(randomSessionKey + b"session key to server-to-client signing key magic constant\x00")
           signKey = md5.digest()
   else:
       signKey = None
   return signKey

def SEALKEY(flags, randomSessionKey, mode = 'Client'):
   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if flags & NTLMSSP_NEGOTIATE_128:
           sealKey = randomSessionKey
       elif flags & NTLMSSP_NEGOTIATE_56:
           sealKey = randomSessionKey[:7]
       else:
           sealKey = randomSessionKey[:5]

       if mode == 'Client':
               md5 = hashlib.new('md5')
               md5.update(sealKey + b'session key to client-to-server sealing key magic constant\x00')
               sealKey = md5.digest()
       else:
               md5 = hashlib.new('md5')
               md5.update(sealKey + b'session key to server-to-client sealing key magic constant\x00')
               sealKey = md5.digest()

   elif flags & NTLMSSP_NEGOTIATE_56:
       sealKey = randomSessionKey[:7] + b'\xa0'
   else:
       sealKey = randomSessionKey[:5] + b'\xe5\x38\xb0'

   return sealKey


def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
   cipher = ARC4.new(keyExchangeKey)
   cipher_encrypt = cipher.encrypt

   sessionKey = cipher_encrypt(exportedSessionKey)
   return sessionKey

def KXKEY(flags, sessionBaseKey, lmChallengeResponse, serverChallenge, password, lmhash, nthash, use_ntlmv2 = USE_NTLMv2):
   if use_ntlmv2:
       return sessionBaseKey

   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if flags & NTLMSSP_NEGOTIATE_NTLM:
          keyExchangeKey = hmac_md5(sessionBaseKey, serverChallenge + lmChallengeResponse[:8])
       else:
          keyExchangeKey = sessionBaseKey
   elif flags & NTLMSSP_NEGOTIATE_NTLM:
       if flags & NTLMSSP_NEGOTIATE_LM_KEY:
           keyExchangeKey = __DES_block(LMOWFv1(password, lmhash)[:7], lmChallengeResponse[:8]) + __DES_block(
               LMOWFv1(password, lmhash)[7] + b'\xBD\xBD\xBD\xBD\xBD\xBD', lmChallengeResponse[:8])
       elif flags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY:
          keyExchangeKey = LMOWFv1(password,lmhash)[:8] + b'\x00'*8
       else:
          keyExchangeKey = sessionBaseKey
   else:
       raise Exception("Can't create a valid KXKEY!")

   return keyExchangeKey
      
def hmac_md5(key, data):
    import hmac
    h = hmac.new(key, digestmod=hashlib.md5)
    h.update(data)
    return h.digest()

def NTOWFv2( user, password, domain, hash = ''):
    if hash != '':
       theHash = hash 
    else:
       theHash = compute_nthash(password)
    return hmac_md5(theHash, user.upper().encode('utf-16le') + domain.encode('utf-16le'))

def LMOWFv2( user, password, domain, lmhash = ''):
    return NTOWFv2( user, password, domain, lmhash)


def computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                          nthash='', use_ntlmv2=USE_NTLMv2):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = AV_PAIRS(serverName)
    # In order to support SPN target name validation, we have to add this to the serverName av_pairs. Otherwise we will
    # get access denied
    # This is set at Local Security Policy -> Local Policies -> Security Options -> Server SPN target name validation
    # level
    if TEST_CASE is False:
        av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
        if av_pairs[NTLMSSP_AV_TIME] is not None:
           aTime = av_pairs[NTLMSSP_AV_TIME][1]
        else:
           aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )
           av_pairs[NTLMSSP_AV_TIME] = aTime
        serverName = av_pairs.getData()
    else:
        aTime = b'\x00'*8

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    if user == '' and password == '':
        # Special case for anonymous authentication
        ntChallengeResponse = ''
        lmChallengeResponse = ''

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

class NTLM_HTTP(object):
    # Parent class for NTLM HTTP classes.
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
