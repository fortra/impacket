#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-CSSP] Credential Security Support Provider (CredSSP) Protocol partial implementation
#
# Author:
#  Alberto Solino (@agsolino)
#

from struct import pack, unpack

from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode

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
       if unpack('B',next_bytes[0:1])[0] != 0x02:
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
     if 'pubKeyAuth' in self.fields:
         pubKeyAuth = pack('B',0xa3)
         pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['pubKeyAuth']))
     else:
         pubKeyAuth = b''

     if 'authInfo' in self.fields:
         authInfo = pack('B',0xa2)
         authInfo+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['authInfo']))
     else: 
         authInfo = b''

     if 'NegoData' in self.fields:
         negoData = pack('B',0xa1) 
         negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) + 
                    asn1encode(pack('B', 0xa0) + 
                    asn1encode(pack('B', ASN1_OCTET_STRING) + 
                    asn1encode(self['NegoData'])))))
     else:
         negoData = b''
     ans = pack('B', ASN1_SEQUENCE)
     ans += asn1encode(pack('B',0xa0) + 
            asn1encode(pack('B',0x02) + asn1encode(pack('B',0x02))) +
            negoData + authInfo + pubKeyAuth)

     return ans
