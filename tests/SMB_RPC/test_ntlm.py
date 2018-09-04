from __future__ import print_function
import unittest
import struct

from impacket import ntlm
from impacket.structure import hexdump

# Common values

class NTLMTests(unittest.TestCase):
    def setUp(self):
        # Turn test case mode on
        ntlm.TEST_CASE = True
        self.user = "User"
        self.domain = "Domain"
        self.password = "Password"
        self.serverName = "Server"
        self.workstationName = "COMPUTER"
        self.randomSessionKey = "U"*16
        self.time = "\x00"*8
        self.clientChallenge = "\xaa"*8
        self.serverChallenge = "\x01\x23\x45\x67\x89\xab\xcd\xef"
        self.flags =  ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH | ntlm.NTLMSSP_NEGOTIATE_56 | ntlm.NTLMSSP_NEGOTIATE_128 | ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_NEGOTIATE_SEAL | ntlm.NTLMSSP_NEGOTIATE_SIGN | ntlm.NTLM_NEGOTIATE_OEM | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        self.seqNum = 0
        self.nonce = '\x00' * 4
        self.plaintext = 'Plaintext'.encode('utf-16le')

        print("## BEFORE RUNNING THESE TESTS")
        print("Don't forget to set up aTime = '\\x00'*8 in computeResponseNTLMv2 otherwise the results won't be right. ")
        print("Look for that in ntlm.py and uncomment the lines, comment the other ones and don't forget to revert everything back whenever finished testing")
        print("Flags")
        hexdump(struct.pack('<L',self.flags))

    def test_ntlmv1(self):
        print("####### 4.2.2 NTLMv1 Authentication")
        ntlm.USE_NTLMv2 = False
        print("4.2.2.1 LMOWFv1()")
        res = ntlm.LMOWFv1(self.password)
        print(repr(res))
        hexdump(res)
        self.assertTrue(res==bytearray(b'\xe5,\xacgA\x9a\x9a"J;\x10\x8f?\xa6\xcbm'))
        print("\n")
        print("4.2.2.1.2 NTOWFv1()")
        res = ntlm.NTOWFv1(self.password)
        hexdump(res)
        self.assertTrue(res==bytearray(b'\xa4\xf4\x9c\x40\x65\x10\xbd\xca\xb6\x82\x4e\xe7\xc3\x0f\xd8\x52'))
        print("\n")
        print("4.2.2.1.3 Session Base Key and Key Exchange Key")
        ntResponse, lmResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(int(self.flags), self.serverChallenge,
                                                                             self.clientChallenge, self.serverName,
                                                                             self.domain, self.user, self.password, '', '')
        hexdump(sessionBaseKey)
        self.assertTrue(sessionBaseKey==bytearray(b'\xD8\x72\x62\xB0\xCD\xE4\xB1\xCB\x74\x99\xBE\xCC\xCD\xF1\x07\x84'))
        print("\n")
        print("4.2.2.2.1 NTLMv1 Response")
        hexdump(ntResponse)
        self.assertTrue(ntResponse==bytearray(b'\x67\xC4\x30\x11\xF3\x02\x98\xA2\xAD\x35\xEC\xE6\x4F\x16\x33\x1C\x44\xBD\xBE\xD9\x27\x84\x1F\x94'))
        print("\n")
        print("4.2.2.2.2 LMv1 Response")
        hexdump(lmResponse)
        self.assertTrue(lmResponse==bytearray(b'\x98\xDE\xF7\xB8\x7F\x88\xAA\x5D\xAF\xE2\xDF\x77\x96\x88\xA1\x72\xde\xf1\x1c\x7d\x5c\xcd\xef\x13'))
        print("\n")
        print("4.2.2.2.2 LMv1 Response with NTLMSSP_NEGOTIATE_LM_KEY set")
        flags2 = self.flags
        #flags2 = flags | ntlm.NTLMSSP_LM_KEY
        #hexdump(struct.pack('<L',flags2))
        ntResponse, lmResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(int(flags2), self.serverChallenge,
                                                self.clientChallenge, self.serverName, self.domain, self.user,
                                                self.password, '', '')
        hexdump(lmResponse)
        print("\n")
        print("4.2.2.2.3 Encrypted Session Key ")
        ntResponse, lmResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(int(self.flags), self.serverChallenge,
                                        self.clientChallenge, self.serverName, self.domain, self.user, self.password, '', '')
        keyExchangeKey = ntlm.KXKEY(self.flags, sessionBaseKey, lmResponse, self.serverChallenge, self.password,'','')
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        hexdump(encryptedSessionKey)
        self.assertTrue(encryptedSessionKey==bytearray(b'\x51\x88\x22\xB1\xB3\xF3\x50\xC8\x95\x86\x82\xEC\xBB\x3E\x3C\xB7'))
        print("\n")
        print("4.2.2.2.3 Encrypted Session Key (NTLMSSP_NON_NT_KEY)")
        flags2 = self.flags | ntlm.NTLMSSP_REQUEST_NON_NT_SESSION_KEY
        keyExchangeKey = ntlm.KXKEY(flags2, sessionBaseKey, lmResponse, self.serverChallenge, self.password,'','')
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        hexdump(encryptedSessionKey)
        #ToDo Fix this
        #self.assertTrue(encryptedSessionKey==bytearray(b'\x74\x52\xca\x55\xc2\x25\xa1\xca\x04\xb4\x8f\xae\x32\xcf\x56\xfc'))
        print("\n")
        print("4.2.2.2.3 Encrypted Session Key (NTLMSSP_LM_KEY)")
        flags2 = self.flags | ntlm.NTLMSSP_NEGOTIATE_LM_KEY
        #hexdump(struct.pack('<L',flags2))
        keyExchangeKey = ntlm.KXKEY(flags2, sessionBaseKey, lmResponse, self.serverChallenge, self.password,'','')
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        hexdump(encryptedSessionKey)
        #ToDo Fix this
        #self.assertTrue(encryptedSessionKey==bytearray(b'\x4c\xd7\xbb\x57\xd6\x97\xef\x9b\x54\x9f\x02\xb8\xf9\xb3\x78\x64')
        print("\n")
        print("4.2.2.3 AUTHENTICATE MESSAGE")
        ntResponse, lmResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(int(self.flags), self.serverChallenge,
                                                self.clientChallenge, self.serverName, self.domain, self.user, self.password, '', '')
        keyExchangeKey = ntlm.KXKEY(self.flags, sessionBaseKey, lmResponse, self.serverChallenge, self.password,'','')
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(self.user, self.password, self.serverChallenge)
        ntlmChallengeResponse['flags'] = flags2
        ntlmChallengeResponse['host_name'] = self.workstationName.encode('utf-16le')
        ntlmChallengeResponse['domain_name'] = self.domain.encode('utf-16le')
        ntlmChallengeResponse['lanman'] = lmResponse
        ntlmChallengeResponse['ntlm'] = ntResponse
        ntlmChallengeResponse['session_key'] = encryptedSessionKey
        hexdump(ntlmChallengeResponse.getData())
        self.assertTrue(ntlmChallengeResponse.getData()==bytearray(b'NTLMSSP\x00\x03\x00\x00\x00\x18\x00\x18\x00|\x00\x00\x00\x18\x00\x18\x00\x94\x00\x00\x00\x0c\x00\x0c\x00X\x00\x00\x00\x08\x00\x08\x00d\x00\x00\x00\x10\x00\x10\x00l\x00\x00\x00\x10\x00\x10\x00\xac\x00\x00\x00\xb3\x82\x02\xe2D\x00o\x00m\x00a\x00i\x00n\x00U\x00s\x00e\x00r\x00C\x00O\x00M\x00P\x00U\x00T\x00E\x00R\x00\x98\xde\xf7\xb8\x7f\x88\xaa]\xaf\xe2\xdfw\x96\x88\xa1r\xde\xf1\x1c}\\\xcd\xef\x13g\xc40\x11\xf3\x02\x98\xa2\xad5\xec\xe6O\x163\x1cD\xbd\xbe\xd9\'\x84\x1f\x94Q\x88"\xb1\xb3\xf3P\xc8\x95\x86\x82\xec\xbb><\xb7'))
        print("\n")

        print("4.2.2.4 GSS_WrapEx")
        print("Output of SEAL()")
        from Cryptodome.Cipher import ARC4
        cipher = ARC4.new(self.randomSessionKey)
        handle = cipher.encrypt
        print("Plaintext")
        hexdump(self.plaintext)
        print("\n")
        sealedMsg, signature = ntlm.SEAL(self.flags, self.nonce, self.nonce, self.plaintext, self.plaintext, self.seqNum, handle)
        #signature = ntlm.SIGN(flags, nonce, plaintext, seqNum, handle)
        hexdump(sealedMsg)
        self.assertTrue(sealedMsg==bytearray(b'V\xfe\x04\xd8a\xf91\x9a\xf0\xd7#\x8a.;ME\x7f\xb8'))
        print("\n")
        hexdump(signature.getData())
        self.assertTrue(signature.getData()==bytearray(b'\x01\x00\x00\x00\x00\x00\x00\x00\t\xdc\xd1\xdf.E\x9d6'))
        print("\n")

        print("####### 4.2.3 NTLMv1 with Client Challenge")
        flags =  ntlm.NTLMSSP_NEGOTIATE_56 | ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY \
                 | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | ntlm.NTLMSSP_NEGOTIATE_NTLM |\
                 ntlm.NTLMSSP_NEGOTIATE_SEAL | ntlm.NTLMSSP_NEGOTIATE_SIGN | ntlm.NTLM_NEGOTIATE_OEM | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        print("Flags")
        hexdump(struct.pack('<L',flags))
        print("\n")
        print("4.2.3.1.1 NTOWFv1(password)")
        hexdump(ntlm.NTOWFv1(self.password))
        print("\n")
        print("4.2.3.1.2 Session Base Key")
        ntResponse, lmResponse, sessionBaseKey  = ntlm.computeResponseNTLMv1(int(flags), self.serverChallenge, self.clientChallenge,
                                                                            self.serverName, self.domain, self.user, self.password, '', '')
        hexdump(sessionBaseKey)
        self.assertTrue(sessionBaseKey==bytearray(b'\xd8rb\xb0\xcd\xe4\xb1\xcbt\x99\xbe\xcc\xcd\xf1\x07\x84'))
        print("\n")
        print("4.2.3.1.3 Key Exchange Key")
        keyExchangeKey = ntlm.KXKEY(flags, sessionBaseKey, lmResponse, self.serverChallenge, self.password,'','')
        hexdump(keyExchangeKey)
        # ToDo: Fix this
        #self.assertTrue(keyExchangeKey==bytearray(b'\xeb\x93\x42\x9a\x8b\xd9\x52\xf8\xb8\x9c\x55\xb8\x7f\x47\x5e\xdc'))
        print("\n")

        print("4.2.3.2.1 LMv1 Response")
        hexdump(lmResponse)
        #self.assertTrue(lmResponse==bytearray(b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
        print("\n")

        print("4.2.3.2.2 NTLMv1 Response")
        hexdump(ntResponse)
        # ToDo: Fix this
        #self.assertTrue(ntResponse==bytearray(b'\x75\x37\xf8\x03\xae\x36\x71\x28\xca\x45\x82\x04\xbd\xe7\xca\xf8\x1e\x97\xed\x26\x83\x26\x72\x32'))
        print("\n")
        print("AUTHENTICATE MESSAGE")
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(self.user, self.password, self.serverChallenge)
        ntlmChallengeResponse['flags'] = flags2
        ntlmChallengeResponse['host_name'] = self.workstationName.encode('utf-16le')
        ntlmChallengeResponse['domain_name'] = self.domain.encode('utf-16le')
        ntlmChallengeResponse['lanman'] = lmResponse
        ntlmChallengeResponse['ntlm'] = ntResponse
        hexdump(ntlmChallengeResponse.getData())
        self.assertTrue(ntlmChallengeResponse.getData()==bytearray(b'NTLMSSP\x00\x03\x00\x00\x00\x18\x00\x18\x00|\x00\x00\x00\x18\x00\x18\x00\x94\x00\x00\x00\x0c\x00\x0c\x00X\x00\x00\x00\x08\x00\x08\x00d\x00\x00\x00\x10\x00\x10\x00l\x00\x00\x00\x00\x00\x00\x00\xac\x00\x00\x00\xb3\x82\x02\xe2D\x00o\x00m\x00a\x00i\x00n\x00U\x00s\x00e\x00r\x00C\x00O\x00M\x00P\x00U\x00T\x00E\x00R\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00u7\xf8\x03\xae6q(\xcaE\x82\x04\xbd\xe7\xca\xf8\x1e\x97\xed&\x83&r2'))

        print("\n")
        print("4.2.3.4 GSS_WrapEx")
        print("Plaintext")
        hexdump(self.plaintext)
        print("\n")
        print("Output of SEAL()")

        exportedSessionKey = keyExchangeKey
        clientSigningKey = ntlm.SIGNKEY(flags, exportedSessionKey)
        serverSigningKey = ntlm.SIGNKEY(flags, exportedSessionKey, "Server")
        clientSealingKey = ntlm.SEALKEY(flags, exportedSessionKey)
        serverSealingKey = ntlm.SEALKEY(flags, exportedSessionKey, "Server")

        from Cryptodome.Cipher import ARC4
        cipher = ARC4.new(clientSigningKey)
        client_signing_h = cipher.encrypt

        cipher2 = ARC4.new(clientSealingKey)
        client_sealing_h = cipher2.encrypt
        print("SEALKEY()")
        hexdump(clientSealingKey)
        print("\n")
        print("SIGNKEY()")
        hexdump(clientSigningKey)
        print("\n")
        print("Sealed Data")
        sealedMsg, signature = ntlm.SEAL(flags, clientSealingKey, clientSigningKey,
                                         self.plaintext, self.plaintext, self.seqNum, client_sealing_h)
        #signature = ntlm.SIGN(flags, clientSigningKey, plaintext, seqNum, client_sealing_h)
        hexdump(sealedMsg)
        # ToDo: Fix this
        #self.assertTrue(ntResponse==bytearray(b'\xa0\x23\x72\xf6\x53\x02\x73\xf3\xaa\x1e\xb9\x01\x90\xce\x52\x00\xc9\x9d'))
        print("\n")
        print("Signature")
        hexdump(signature.getData())
        # ToDo: Fix this
        #self.assertTrue(ntResponse==bytearray(b'\x01\x00\x00\x00\xff\x2a\xeb\x52\xf6\x81\x79\x3a\x00\x00\x00\x00')
        print("\n")

    def test_ntlmv2(self):
        print("####### 4.2.4 NTLMv2 Authentication")
        ntlm.USE_NTLMv2 = True
        serverName = '\x02\x00\x0c\x00\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x01\x00\x0c\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x00\x00\x00\x00'
        # Still the aTime won't be set to zero. that must be changed in ntlm.computeResponseNTLM2. Gotta make this more automated

        flags = ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH | ntlm.NTLMSSP_NEGOTIATE_56 | ntlm.NTLMSSP_NEGOTIATE_128 | \
                ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | \
                ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | ntlm.NTLMSSP_TARGET_TYPE_SERVER | \
                ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_NEGOTIATE_SEAL | \
                ntlm.NTLMSSP_NEGOTIATE_SIGN | ntlm.NTLM_NEGOTIATE_OEM | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        print("Flags")
        hexdump(struct.pack('<L',flags))
        print("\n")
        print("4.2.4.1.1 NTOWFv2 and LMOWFv2")
        res = ntlm.NTOWFv2(self.user,self.password,self.domain)
        hexdump(res)
        self.assertTrue(res==bytearray(b'\x0c\x86\x8a@;\xfdz\x93\xa3\x00\x1e\xf2.\xf0.?'))
        print("\n")
        print("\n")
        print("4.2.4.1.2 Session Base Key")
        ntResponse, lmResponse, sessionBaseKey = ntlm.computeResponseNTLMv2(flags, self.serverChallenge,
                            self.clientChallenge, serverName, self.domain, self.user, self.password, '', '' )
        hexdump(sessionBaseKey)
        self.assertTrue(sessionBaseKey==bytearray(b'\x8d\xe4\x0c\xca\xdb\xc1\x4a\x82\xf1\x5c\xb0\xad\x0d\xe9\x5c\xa3'))
        print("\n")

        print("4.2.4.2.1 LMv2 Response")
        hexdump(lmResponse)
        self.assertTrue(lmResponse==bytearray(b'\x86\xc3P\x97\xac\x9c\xec\x10%TvJW\xcc\xcc\x19\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'))
        print("\n")
        print("4.2.4.2.2 NTLMv2 Response")
        hexdump(ntResponse[:16])
        self.assertTrue(ntResponse[:16]==bytearray(b'\x68\xcd\x0a\xb8\x51\xe5\x1c\x96\xaa\xbc\x92\x7b\xeb\xef\x6a\x1c'))
        print("\n")
        print("4.2.4.2.3 Encrypted Session Key")
        keyExchangeKey = ntlm.KXKEY(flags, sessionBaseKey, lmResponse, self.serverChallenge, self.password,'','')
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        hexdump(encryptedSessionKey)
        self.assertTrue(encryptedSessionKey==bytearray(b'\xC5\xDA\xD2\x54\x4F\xC9\x79\x90\x94\xCE\x1C\xE9\x0B\xC9\xD0\x3E'))
        print("\n")

        print("AUTHENTICATE MESSAGE")
        encryptedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey,self.randomSessionKey)
        ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(self.user, self.password, self.serverChallenge)
        ntlmChallengeResponse['flags'] = flags
        ntlmChallengeResponse['host_name'] = self.workstationName.encode('utf-16le')
        ntlmChallengeResponse['domain_name'] = self.domain.encode('utf-16le')
        ntlmChallengeResponse['lanman'] = lmResponse
        ntlmChallengeResponse['ntlm'] = ntResponse
        ntlmChallengeResponse['session_key'] = encryptedSessionKey
        hexdump(ntlmChallengeResponse.getData())
        self.assertTrue(ntlmChallengeResponse.getData()==bytearray(b'NTLMSSP\x00\x03\x00\x00\x00\x18\x00\x18\x00|\x00\x00\x00T\x00T\x00\x94\x00\x00\x00\x0c\x00\x0c\x00X\x00\x00\x00\x08\x00\x08\x00d\x00\x00\x00\x10\x00\x10\x00l\x00\x00\x00\x10\x00\x10\x00\xe8\x00\x00\x003\x82\x8a\xe2D\x00o\x00m\x00a\x00i\x00n\x00U\x00s\x00e\x00r\x00C\x00O\x00M\x00P\x00U\x00T\x00E\x00R\x00\x86\xc3P\x97\xac\x9c\xec\x10%TvJW\xcc\xcc\x19\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaah\xcd\n\xb8Q\xe5\x1c\x96\xaa\xbc\x92{\xeb\xefj\x1c\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x02\x00\x0c\x00D\x00o\x00m\x00a\x00i\x00n\x00\x01\x00\x0c\x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\xda\xd2TO\xc9y\x90\x94\xce\x1c\xe9\x0b\xc9\xd0>'))
        print("\n")
        print("4.2.4.4 GSS_WrapEx")
        print("Plaintext")
        hexdump(self.plaintext)
        print("\n")
        print("Output of SEAL()")

        exportedSessionKey = self.randomSessionKey
        clientSigningKey = ntlm.SIGNKEY(flags, exportedSessionKey)
        serverSigningKey = ntlm.SIGNKEY(flags, exportedSessionKey, "Server")
        clientSealingKey = ntlm.SEALKEY(flags, exportedSessionKey)
        serverSealingKey = ntlm.SEALKEY(flags, exportedSessionKey, "Server")

        from Cryptodome.Cipher import ARC4
        cipher = ARC4.new(clientSigningKey)
        client_signing_h = cipher.encrypt

        cipher2 = ARC4.new(clientSealingKey)
        client_sealing_h = cipher2.encrypt
        print("SEALKEY()")
        hexdump(clientSealingKey)
        self.assertTrue(clientSealingKey==bytearray(b'Y\xf6\x00\x97<\xc4\x96\n%H\n|\x19nLX'))
        print("\n")
        print("SIGNKEY()")
        hexdump(clientSigningKey)
        self.assertTrue(clientSigningKey==bytearray(b'G\x88\xdc\x86\x1bG\x82\xf3]C\xfd\x98\xfe\x1a-9'))
        print("\n")
        print("Sealed Data")
        sealedMsg, signature = ntlm.SEAL(flags, clientSealingKey, clientSigningKey,
                                         self.plaintext, self.plaintext, self.seqNum, client_sealing_h)
        #signature = ntlm.SIGN(flags, clientSigningKey, plaintext, seqNum, client_sealing_h)
        hexdump(sealedMsg)
        self.assertTrue(sealedMsg==bytearray(b'T\xe5\x01e\xbf\x196\xdc\x99` \xc1\x81\x1b\x0f\x06\xfb_'))
        print("\n")
        print("Signature")
        hexdump(signature.getData())
        self.assertTrue(signature.getData()==bytearray(b'\x01\x00\x00\x00\x00\xc1a\xa1\x1e@\x03\x9f\x00\x00\x00\x00'))
        #print (repr(bytearray(str(signature))))
        #raise
        print("\n")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(NTLMTests)
    unittest.TextTestRunner(verbosity=1).run(suite)