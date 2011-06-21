from impacket import ntlm
import struct
# Hexdump packets

import string
def pretty_print(x):
    if x in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
       return x
    else:
       return '.'

def hexdump(data):
    x=str(data)
    strLen = len(x)
    i = 0
    while i < strLen:
        print "%04x  " % i,
        for j in range(16):
            if i+j < strLen:
                print "%02X" % ord(x[i+j]),
            else:
                print "  ",
            if j%16 == 7:
                print "",
        print " ",
        print ''.join(pretty_print(x) for x in x[i:i+16] )
        i += 16



# Common values

user = "User"
domain = "Domain"
password = "Password"
serverName = "Server"
workstationName = "COMPUTER"
randomSessionKey = "U"*16
time = "\x00"*8
clientChallenge = "\xaa"*8
serverChallenge = "\x01\x23\x45\x67\x89\xab\xcd\xef"
flags =  ntlm.NTLMSSP_KEY_EXCHANGE | ntlm.NTLMSSP_KEY_56 | ntlm.NTLMSSP_KEY_128 | ntlm.NTLMSSP_VERSION | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_ALWAYS_SIGN | ntlm.NTLMSSP_NTLM_KEY | ntlm.NTLMSSP_SEAL | ntlm.NTLMSSP_SIGN | ntlm.NTLMSSP_OEM | ntlm.NTLMSSP_UNICODE

print "Flags"
hexdump(struct.pack('<L',flags))
print "####### 4.2.2 NTLMv1 Authentication"
ntlm.USE_NTLMv2 = False
print "4.2.2.1 LMOWFv1()"
hexdump(ntlm.LMOWFv1(password))
print "\n"
print "4.2.2.1.2 NTOWFv1()"
hexdump(ntlm.NTOWFv1(password))
print "\n"
print "4.2.2.1.3 Session Base Key and Key Exchange Key"
lmResponse, ntResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(long(flags), serverChallenge, clientChallenge, user, password)
hexdump(sessionBaseKey)
print "\n"
print "4.2.2.2.1 NTLMv1 Response"
hexdump(ntResponse)
print "\n"
print "4.2.2.2.2 LMv1 Response"
hexdump(lmResponse)
print "\n"
print "4.2.2.2.2 LMv1 Response with NTLMSSP_NEGOTIATE_LM_KEY set"
flags2 = flags | ntlm.NTLMSSP_LM_KEY
#hexdump(struct.pack('<L',flags2))
lmResponse, ntResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(long(flags2), serverChallenge, clientChallenge, user, password)
hexdump(lmResponse)
print "\n"
print "4.2.2.2.3 Encrypted Session Key "
lmResponse, ntResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(long(flags), serverChallenge, clientChallenge, user, password)
keyExchangeKey = ntlm.KXKEY(flags, sessionBaseKey, lmResponse, serverChallenge, password,'','')
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
hexdump(encryptedSessionKey)
print "\n"
print "4.2.2.2.3 Encrypted Session Key (NTLMSSP_NON_NT_KEY)"
flags2 = flags | ntlm.NTLMSSP_NOT_NT_KEY
#hexdump(struct.pack('<L',flags2))
keyExchangeKey = ntlm.KXKEY(flags2, sessionBaseKey, lmResponse, serverChallenge, password,'','')
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
hexdump(encryptedSessionKey)
print "\n"
print "4.2.2.2.3 Encrypted Session Key (NTLMSSP_LM_KEY)"
flags2 = flags | ntlm.NTLMSSP_LM_KEY
#hexdump(struct.pack('<L',flags2))
keyExchangeKey = ntlm.KXKEY(flags2, sessionBaseKey, lmResponse, serverChallenge, password,'','')
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
hexdump(encryptedSessionKey)
print "\n"
print "4.2.2.3 AUTHENTICATE MESSAGE"
lmResponse, ntResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(long(flags), serverChallenge, clientChallenge, user, password)
keyExchangeKey = ntlm.KXKEY(flags, sessionBaseKey, lmResponse, serverChallenge, password,'','')
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(user, password, serverChallenge)
ntlmChallengeResponse['flags'] = flags2
ntlmChallengeResponse['host_name'] = workstationName.encode('utf-16le')
ntlmChallengeResponse['domain_name'] = domain.encode('utf-16le')
ntlmChallengeResponse['lanman'] = lmResponse
ntlmChallengeResponse['ntlm'] = ntResponse
ntlmChallengeResponse['session_key'] = encryptedSessionKey
hexdump(str(ntlmChallengeResponse))
print "\n"

print "####### 4.2.3 NTLMv1 with Client Challenge"
flags =  ntlm.NTLMSSP_KEY_56 | ntlm.NTLMSSP_VERSION | ntlm.NTLMSSP_NTLM2_KEY | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_ALWAYS_SIGN | ntlm.NTLMSSP_NTLM_KEY | ntlm.NTLMSSP_SEAL | ntlm.NTLMSSP_SIGN | ntlm.NTLMSSP_OEM | ntlm.NTLMSSP_UNICODE
print "Flags"
hexdump(struct.pack('<L',flags))
print "\n"
print "4.2.3.1.1 NTOWFv1(password)"
hexdump(ntlm.NTOWFv1(password))
print "\n"
print "4.2.3.1.2 Session Base Key"
lmResponse, ntResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(long(flags), serverChallenge, clientChallenge, user, password)
hexdump(sessionBaseKey)
print "\n"
print "4.2.3.1.3 Key Exchange Key"
keyExchangeKey = ntlm.KXKEY(flags, sessionBaseKey, lmResponse, serverChallenge, password,'','')
hexdump(keyExchangeKey)
print "\n"

print "4.2.3.2.1 LMv1 Response"
hexdump(lmResponse)
print "\n"

print "4.2.3.2.2 NTLMv1 Response"
hexdump(ntResponse)
print "\n"
print "AUTHENTICATE MESSAGE"
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(user, password, serverChallenge)
ntlmChallengeResponse['flags'] = flags2
ntlmChallengeResponse['host_name'] = workstationName.encode('utf-16le')
ntlmChallengeResponse['domain_name'] = domain.encode('utf-16le')
ntlmChallengeResponse['lanman'] = lmResponse
ntlmChallengeResponse['ntlm'] = ntResponse
hexdump(str(ntlmChallengeResponse))
print "\n"

print "####### 4.2.4 NTLMv2 Authentication"
ntlm.USE_NTLMv2 = True
serverName = '\x02\x00\x0c\x00\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x01\x00\x0c\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x00\x00\x00\x00'
# Still the aTime won't be set to zero. that must be changed in ntlm.computeResponseNTLM2. Gotta make this more automated

flags =  ntlm.NTLMSSP_KEY_EXCHANGE | ntlm.NTLMSSP_KEY_56 | ntlm.NTLMSSP_KEY_128 | ntlm.NTLMSSP_VERSION | ntlm.NTLMSSP_TARGET_INFO | ntlm.NTLMSSP_NTLM2_KEY | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_ALWAYS_SIGN | ntlm.NTLMSSP_NTLM_KEY | ntlm.NTLMSSP_SEAL | ntlm.NTLMSSP_SIGN | ntlm.NTLMSSP_OEM | ntlm.NTLMSSP_UNICODE
print "Flags"
hexdump(struct.pack('<L',flags))
print "\n"
av_pairs = ntlm.AV_PAIRS()
av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = serverName.encode('utf-16le')
av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = domain.encode('utf-16le')
print "AV PAIRS"
hexdump(av_pairs.getData())
print "\n"
print "4.2.4.1.1 NTOWFv2 and LMOWFv2"
hexdump(ntlm.NTOWFv2(user,password,domain))
print "\n"
hexdump(ntlm.LMOWFv2(user,password,domain))
print "\n"
print "4.2.4.1.2 Session Base Key"
ntResponse, lmResponse, sessionBaseKey = ntlm.computeResponseNTLMv2(serverChallenge, clientChallenge, av_pairs, domain, user, password, '', '' )
hexdump(sessionBaseKey)
print "\n"

print "4.2.4.2.1 LMv2 Response"
hexdump(lmResponse)
print "\n"
print "4.2.4.2.2 NTLMv2 Response"
hexdump(ntResponse)
print "\n"
print "4.2.4.2.3 Encrypted Session Key"
keyExchangeKey = ntlm.KXKEY(flags, sessionBaseKey, lmResponse, serverChallenge, password,'','')
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
hexdump(encryptedSessionKey)
print "\n"

print "AUTHENTICATE MESSAGE"
encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,randomSessionKey)
ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(user, password, serverChallenge)
ntlmChallengeResponse['flags'] = flags
ntlmChallengeResponse['host_name'] = workstationName.encode('utf-16le')
ntlmChallengeResponse['domain_name'] = domain.encode('utf-16le')
ntlmChallengeResponse['lanman'] = lmResponse
ntlmChallengeResponse['ntlm'] = ntResponse
ntlmChallengeResponse['session_key'] = encryptedSessionKey
hexdump(str(ntlmChallengeResponse))
print "\n"
