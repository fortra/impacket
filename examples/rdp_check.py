#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description: [MS-RDPBCGR] and [MS-CREDSSP] partial implementation 
#              just to reach CredSSP auth. This example test whether
#              an account is valid on the target host.
#
# ToDo:
#    [x] Manage to grab the server's SSL key so we can finalize the whole
#        authentication process (check [MS-CSSP] section 3.1.5)
#

from struct import pack, unpack

from impacket.examples import logger
from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode

TDPU_CONNECTION_REQUEST  = 0xe0
TPDU_CONNECTION_CONFIRM  = 0xd0
TDPU_DATA                = 0xf0
TPDU_REJECT              = 0x50
TPDU_DATA_ACK            = 0x60

# RDP_NEG_REQ constants
TYPE_RDP_NEG_REQ = 1
PROTOCOL_RDP     = 0
PROTOCOL_SSL     = 1
PROTOCOL_HYBRID  = 2

# RDP_NEG_RSP constants
TYPE_RDP_NEG_RSP = 2
EXTENDED_CLIENT_DATA_SUPPORTED = 1
DYNVC_GFX_PROTOCOL_SUPPORTED   = 2

# RDP_NEG_FAILURE constants
TYPE_RDP_NEG_FAILURE                  = 3
SSL_REQUIRED_BY_SERVER                = 1
SSL_NOT_ALLOWED_BY_SERVER             = 2
SSL_CERT_NOT_ON_SERVER                = 3
INCONSISTENT_FLAGS                    = 4
HYBRID_REQUIRED_BY_SERVER             = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6

class TPKT(Structure):
    commonHdr = (
        ('Version','B=3'),
        ('Reserved','B=0'),
        ('Length','>H=len(TPDU)+4'),
        ('_TPDU','_-TPDU','self["Length"]-4'),
        ('TPDU',':=""'),
    )

class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator','B=len(VariablePart)+1'),
        ('Code','B=0'),
        ('VariablePart',':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['VariablePart']=''

class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF','<H=0'),
        ('SRC-REF','<H=0'),
        ('CLASS-OPTION','B=0'),
        ('Type','B=0'),
        ('Flags','B=0'),
        ('Length','<H=8'),
    )

class DATA_TPDU(Structure):
    commonHdr = (
        ('EOT','B=0x80'),
        ('UserData',':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['UserData'] =''


class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols','<L'),
    )
    def __init__(self,data=None):
        CR_TPDU.__init__(self,data)
        if data is None:
            self['Type'] = TYPE_RDP_NEG_REQ

class RDP_NEG_RSP(CR_TPDU):
    structure = (
        ('selectedProtocols','<L'),
    )

class RDP_NEG_FAILURE(CR_TPDU):
    structure = (
        ('failureCode','<L'),
    )

class TSPasswordCreds(GSSAPI):
# TSPasswordCreds ::= SEQUENCE {
#         domainName  [0] OCTET STRING,
#         userName    [1] OCTET STRING,
#         password    [2] OCTET STRING
# }
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']
  
   def getData(self):
       ans = pack('B', ASN1_SEQUENCE)
       ans += asn1encode( pack('B', 0xa0) +
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['domainName'].encode('utf-16le'))) +
              pack('B', 0xa1) + 
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['userName'].encode('utf-16le'))) +
              pack('B', 0xa2) + 
              asn1encode( pack('B', ASN1_OCTET_STRING) + 
              asn1encode( self['password'].encode('utf-16le'))) )
       return ans 

class TSCredentials(GSSAPI):
# TSCredentials ::= SEQUENCE {
#        credType    [0] INTEGER,
#        credentials [1] OCTET STRING
# }
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']

   def getData(self):
     # Let's pack the credentials field
     credentials =  pack('B',0xa1) 
     credentials += asn1encode(pack('B',ASN1_OCTET_STRING) +
                    asn1encode(self['credentials']))

     ans = pack('B',ASN1_SEQUENCE) 
     ans += asn1encode( pack('B', 0xa0) +
            asn1encode( pack('B', 0x02) + 
            asn1encode( pack('B', self['credType']))) +
            credentials)
     return ans

class TSRequest(GSSAPI):
# TSRequest ::= SEQUENCE {
#	version     [0] INTEGER,
#       negoTokens  [1] NegoData OPTIONAL,
#       authInfo    [2] OCTET STRING OPTIONAL,
#	pubKeyAuth  [3] OCTET STRING OPTIONAL,
#}
#
# NegoData ::= SEQUENCE OF SEQUENCE {
#        negoToken [0] OCTET STRING
#}
#

   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']
       
   def fromString(self, data = None):
       next_byte = unpack('B',data[:1])[0]
       if next_byte != ASN1_SEQUENCE:
           raise Exception('SEQUENCE expected! (%x)' % next_byte)
       data = data[1:]
       decode_data, total_bytes = asn1decode(data) 

       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte !=  0xa0:
            raise Exception('0xa0 tag not found %x' % next_byte)
       decode_data = decode_data[1:]
       next_bytes, total_bytes = asn1decode(decode_data)                
       # The INTEGER tag must be here
       if unpack('B',next_bytes[0])[0] != 0x02:
           raise Exception('INTEGER tag not found %r' % next_byte)
       next_byte, _ = asn1decode(next_bytes[1:])
       self['Version'] = unpack('B',next_byte)[0]
       decode_data = decode_data[total_bytes:]
       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte == 0xa1:
           # We found the negoData token
           decode_data, total_bytes = asn1decode(decode_data[1:])
       
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           decode_data, total_bytes = asn1decode(decode_data[1:])

           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           decode_data, total_bytes = asn1decode(decode_data[1:])

           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != 0xa0:
               raise Exception('0xa0 tag not found %r' % next_byte)
           decode_data, total_bytes = asn1decode(decode_data[1:])
   
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           # the rest should be the data
           self['NegoData'] = decode_data2
           decode_data = decode_data[total_bytes+1:]

       if next_byte == 0xa2:
           # ToDo: Check all this
           # We found the authInfo token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           self['authInfo'] = decode_data2
           decode_data = decode_data[total_bytes+1:]

       if next_byte == 0xa3:
           # ToDo: Check all this
           # We found the pubKeyAuth token
           decode_data, total_bytes = asn1decode(decode_data[1:])
           next_byte = unpack('B',decode_data[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           self['pubKeyAuth'] = decode_data2

   def getData(self):
     # Do we have pubKeyAuth?
     if self.fields.has_key('pubKeyAuth'):
         pubKeyAuth = pack('B',0xa3)
         pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['pubKeyAuth']))
     else:
         pubKeyAuth = ''

     if self.fields.has_key('authInfo'):
         authInfo = pack('B',0xa2)
         authInfo+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['authInfo']))
     else: 
         authInfo = ''

     if self.fields.has_key('NegoData'):
         negoData = pack('B',0xa1) 
         negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) + 
                    asn1encode(pack('B', 0xa0) + 
                    asn1encode(pack('B', ASN1_OCTET_STRING) + 
                    asn1encode(self['NegoData'])))))
     else:
         negoData = ''
     ans = pack('B', ASN1_SEQUENCE)
     ans += asn1encode(pack('B',0xa0) + 
            asn1encode(pack('B',0x02) + asn1encode(pack('B',0x02))) +
            negoData + authInfo + pubKeyAuth)
     
     return ans

if __name__ == '__main__':

    import socket
    import argparse
    import sys
    import logging
    from binascii import a2b_hex
    from Cryptodome.Cipher import ARC4
    from impacket import ntlm, version
    try:
        import OpenSSL
        from OpenSSL import SSL, crypto
    except:
        logging.critical("pyOpenSSL is not installed, can't continue")
        sys.exit(1)
    

    class SPNEGOCipher:
        def __init__(self, flags, randomSessionKey):
            self.__flags = flags
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
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
                self.__clientSealingKey = randomSessionKey
                cipher = ARC4.new(self.__clientSigningKey)
                self.__clientSealingHandle = cipher.encrypt
                self.__serverSealingHandle = cipher.encrypt
            self.__sequence = 0

        def encrypt(self, plain_data):
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                # When NTLM2 is on, we sign the whole pdu, but encrypt just
                # the data, not the dcerpc header. Weird..
                sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                       self.__clientSigningKey, 
                       self.__clientSealingKey,  
                       plain_data, 
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

            self.__sequence += 1

            return signature, sealedMessage

        def decrypt(self, answer):
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
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

            return signature, answer

    def check_rdp(host, username, password, domain, hashes = None):

       if hashes is not None:
           lmhash, nthash = hashes.split(':')
           lmhash = a2b_hex(lmhash)
           nthash = a2b_hex(nthash)

       else:
           lmhash = ''
           nthash = ''

       tpkt = TPKT()
       tpdu = TPDU()
       rdp_neg = RDP_NEG_REQ()
       rdp_neg['Type'] = TYPE_RDP_NEG_REQ
       rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID | PROTOCOL_SSL
       tpdu['VariablePart'] = str(rdp_neg)
       tpdu['Code'] = TDPU_CONNECTION_REQUEST
       tpkt['TPDU'] = str(tpdu)
   
       s = socket.socket()
       s.connect((host,3389))
       s.sendall(str(tpkt))
       pkt = s.recv(8192)
       tpkt.fromString(pkt)
       tpdu.fromString(tpkt['TPDU'])
       cr_tpdu = CR_TPDU(tpdu['VariablePart'])
       if cr_tpdu['Type'] == TYPE_RDP_NEG_FAILURE:
           rdp_failure = RDP_NEG_FAILURE(tpdu['VariablePart'])
           rdp_failure.dump()
           logging.error("Server doesn't support PROTOCOL_HYBRID, hence we can't use CredSSP to check credentials")
           return
       else:
           rdp_neg.fromString(tpdu['VariablePart'])

       # Since we were accepted to talk PROTOCOL_HYBRID, below is its implementation

       # 1. The CredSSP client and CredSSP server first complete the TLS handshake, 
       # as specified in [RFC2246]. After the handshake is complete, all subsequent 
       # CredSSP Protocol messages are encrypted by the TLS channel. 
       # The CredSSP Protocol does not extend the TLS wire protocol. As part of the TLS 
       # handshake, the CredSSP server does not request the client's X.509 certificate 
       # (thus far, the client is anonymous). Also, the CredSSP Protocol does not require 
       # the client to have a commonly trusted certification authority root with the 
       # CredSSP server. Thus, the CredSSP server MAY use, for example, 
       # a self-signed X.509 certificate.

       # Switching to TLS now
       ctx = SSL.Context(SSL.TLSv1_2_METHOD)
       ctx.set_cipher_list('RC4,AES')
       tls = SSL.Connection(ctx,s)
       tls.set_connect_state()
       tls.do_handshake()

       # If you want to use Python internal ssl, uncomment this and comment 
       # the previous lines
       #tls = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, ciphers='RC4')

       # 2. Over the encrypted TLS channel, the SPNEGO handshake between the client 
       # and server completes mutual authentication and establishes an encryption key 
       # that is used by the SPNEGO confidentiality services, as specified in [RFC4178]. 
       # All SPNEGO tokens as well as the underlying encryption algorithms are opaque to 
       # the calling application (the CredSSP client and CredSSP server). 
       # The wire protocol for SPNEGO is specified in [MS-SPNG].
       # The SPNEGO tokens exchanged between the client and the server are encapsulated 
       # in the negoTokens field of the TSRequest structure. Both the client and the 
       # server use this structure as many times as necessary to complete the SPNEGO 
       # exchange.<9>
       #
       # Note During this phase of the protocol, the OPTIONAL authInfo field is omitted 
       # from the TSRequest structure by the client and server; the OPTIONAL pubKeyAuth 
       # field is omitted by the client unless the client is sending the last SPNEGO token. 
       # If the client is sending the last SPNEGO token, the TSRequest structure MUST have 
       # both the negoToken and the pubKeyAuth fields filled in.

       # NTLMSSP stuff
       auth = ntlm.getNTLMSSPType1('','',True, use_ntlmv2 = True)

       ts_request = TSRequest()
       ts_request['NegoData'] = str(auth)

       tls.send(ts_request.getData())
       buff = tls.recv(4096)
       ts_request.fromString(buff)

   
       # 3. The client encrypts the public key it received from the server (contained 
       # in the X.509 certificate) in the TLS handshake from step 1, by using the 
       # confidentiality support of SPNEGO. The public key that is encrypted is the 
       # ASN.1-encoded SubjectPublicKey sub-field of SubjectPublicKeyInfo from the X.509 
       # certificate, as specified in [RFC3280] section 4.1. The encrypted key is 
       # encapsulated in the pubKeyAuth field of the TSRequest structure and is sent over 
       # the TLS channel to the server. 
       #
       # Note During this phase of the protocol, the OPTIONAL authInfo field is omitted 
       # from the TSRequest structure; the client MUST send its last SPNEGO token to the 
       # server in the negoTokens field (see step 2) along with the encrypted public key 
       # in the pubKeyAuth field.

       # Last SPNEGO token calculation
       #ntlmChallenge = ntlm.NTLMAuthChallenge(ts_request['NegoData'])
       type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], username, password, domain, lmhash, nthash, use_ntlmv2 = True)

       # Get server public key
       server_cert =  tls.get_peer_certificate()
       pkey = server_cert.get_pubkey()
       dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)

       # Fix up due to PyOpenSSL lack for exporting public keys
       dump = dump[7:]
       dump = '\x30'+ asn1encode(dump)

       cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
       signature, cripted_key = cipher.encrypt(dump)
       ts_request['NegoData'] = str(type3)
       ts_request['pubKeyAuth'] = str(signature) + cripted_key

       try:
           # Sending the Type 3 NTLM blob
           tls.send(ts_request.getData())
           # The other end is waiting for the pubKeyAuth field, but looks like it's
           # not needed to check whether authentication worked.
           # If auth is unsuccessful, it throws an exception with the previous send().
           # If auth is successful, the server waits for the pubKeyAuth and doesn't answer 
           # anything. So, I'm sending garbage so the server returns an error. 
           # Luckily, it's a different error so we can determine whether or not auth worked ;)
           buff = tls.recv(1024)
       except Exception, err:
           if str(err).find("denied") > 0:
               logging.error("Access Denied")
           else:
               logging.error(err)
           return

       # 4. After the server receives the public key in step 3, it first verifies that 
       # it has the same public key that it used as part of the TLS handshake in step 1. 
       # The server then adds 1 to the first byte representing the public key (the ASN.1 
       # structure corresponding to the SubjectPublicKey field, as described in step 3) 
       # and encrypts the binary result by using the SPNEGO encryption services. 
       # Due to the addition of 1 to the binary data, and encryption of the data as a binary 
       # structure, the resulting value may not be valid ASN.1-encoded values. 
       # The encrypted binary data is encapsulated in the pubKeyAuth field of the TSRequest 
       # structure and is sent over the encrypted TLS channel to the client. 
       # The addition of 1 to the first byte of the public key is performed so that the 
       # client-generated pubKeyAuth message cannot be replayed back to the client by an 
       # attacker.
       #
       # Note During this phase of the protocol, the OPTIONAL authInfo and negoTokens 
       # fields are omitted from the TSRequest structure.

       ts_request = TSRequest(buff)

       # Now we're decrypting the certificate + 1 sent by the server. Not worth checking ;)
       signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'][16:])

       # 5. After the client successfully verifies server authenticity by performing a 
       # binary comparison of the data from step 4 to that of the data representing 
       # the public key from the server's X.509 certificate (as specified in [RFC3280], 
       # section 4.1), it encrypts the user's credentials (either password or smart card 
       # PIN) by using the SPNEGO encryption services. The resulting value is 
       # encapsulated in the authInfo field of the TSRequest structure and sent over 
       # the encrypted TLS channel to the server.
       # The TSCredentials structure within the authInfo field of the TSRequest 
       # structure MAY contain either a TSPasswordCreds or a TSSmartCardCreds structure, 
       # but MUST NOT contain both.
       #
       # Note During this phase of the protocol, the OPTIONAL pubKeyAuth and negoTokens 
       # fields are omitted from the TSRequest structure.
       tsp = TSPasswordCreds()
       tsp['domainName'] = domain
       tsp['userName']   = username
       tsp['password']   = password
       tsc = TSCredentials()
       tsc['credType'] = 1 # TSPasswordCreds
       tsc['credentials'] = tsp.getData()

       signature, cripted_creds = cipher.encrypt(tsc.getData())
       ts_request = TSRequest()
       ts_request['authInfo'] = str(signature) + cripted_creds
       tls.send(ts_request.getData())
       tls.close()
       logging.info("Access Granted")

    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Test whether an account is valid on the target "
                                                                    "host using the RDP protocol.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    check_rdp(address, username, password, domain, options.hashes)
