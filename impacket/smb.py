# Copyright (c) 2003-2011 CORE Security Technologies)
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Copyright (C) 2001 Michael Teo <michaelteo@bigfoot.com>
# smb.py - SMB/CIFS library
#
# This software is provided 'as-is', without any express or implied warranty. 
# In no event will the author be held liable for any damages arising from the 
# use of this software.
#
# Permission is granted to anyone to use this software for any purpose, 
# including commercial applications, and to alter it and redistribute it 
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not 
#    claim that you wrote the original software. If you use this software 
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
# 2. Altered source versions must be plainly marked as such, and must not be 
#    misrepresented as being the original software.
#
# 3. This notice cannot be removed or altered from any source distribution.
#
# Altered source done by Alberto Solino

# Todo:
# [ ] Try [SMB]transport fragmentation using Transact requests
# [ ] Try other methods of doing write (write_raw, transact2, write, write_and_unlock, write_and_close, write_mpx)
# [-] Try replacements for SMB_COM_NT_CREATE_ANDX  (CREATE, T_TRANSACT_CREATE, OPEN_ANDX works
# [x] Fix forceWriteAndx, which needs to send a RecvRequest, because recv() will not send it
# [x] Fix Recv() when using RecvAndx and the answer comes splet in several packets
# [ ] Try [SMB]transport fragmentation with overlaping segments
# [ ] Try [SMB]transport fragmentation with out of order segments
# [x] Do chained AndX requests
# [ ] Transform the rest of the calls to structure

import os, sys, socket, string, re, select, errno
import nmb
import types
from binascii import a2b_hex
import ntlm
import random
import datetime, time
from random import randint
from struct import *
from dcerpc import samr
import struct
from structure import Structure

# For signing
import hashlib

unicode_support = 0
unicode_convert = 1

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

# Shared Device Type
SHARED_DISK                      = 0x00
SHARED_PRINT_QUEUE               = 0x01
SHARED_DEVICE                    = 0x02
SHARED_IPC                       = 0x03

# Extended attributes mask
ATTR_ARCHIVE                     = 0x020
ATTR_COMPRESSED                  = 0x800
ATTR_NORMAL                      = 0x080
ATTR_HIDDEN                      = 0x002
ATTR_READONLY                    = 0x001
ATTR_TEMPORARY                   = 0x100
ATTR_DIRECTORY                   = 0x010
ATTR_SYSTEM                      = 0x004

# Service Type
SERVICE_DISK                     = 'A:'
SERVICE_PRINTER                  = 'LPT1:'
SERVICE_IPC                      = 'IPC'
SERVICE_COMM                     = 'COMM'
SERVICE_ANY                      = '?????'

# Server Type (Can be used to mask with SMBMachine.get_type() or SMBDomain.get_type())
SV_TYPE_WORKSTATION              = 0x00000001
SV_TYPE_SERVER                   = 0x00000002
SV_TYPE_SQLSERVER                = 0x00000004
SV_TYPE_DOMAIN_CTRL              = 0x00000008
SV_TYPE_DOMAIN_BAKCTRL           = 0x00000010
SV_TYPE_TIME_SOURCE              = 0x00000020
SV_TYPE_AFP                      = 0x00000040
SV_TYPE_NOVELL                   = 0x00000080
SV_TYPE_DOMAIN_MEMBER            = 0x00000100
SV_TYPE_PRINTQ_SERVER            = 0x00000200
SV_TYPE_DIALIN_SERVER            = 0x00000400
SV_TYPE_XENIX_SERVER             = 0x00000800
SV_TYPE_NT                       = 0x00001000
SV_TYPE_WFW                      = 0x00002000
SV_TYPE_SERVER_NT                = 0x00004000
SV_TYPE_POTENTIAL_BROWSER        = 0x00010000
SV_TYPE_BACKUP_BROWSER           = 0x00020000
SV_TYPE_MASTER_BROWSER           = 0x00040000
SV_TYPE_DOMAIN_MASTER            = 0x00080000
SV_TYPE_LOCAL_LIST_ONLY          = 0x40000000
SV_TYPE_DOMAIN_ENUM              = 0x80000000

# Options values for SMB.stor_file and SMB.retr_file
SMB_O_CREAT                      = 0x10   # Create the file if file does not exists. Otherwise, operation fails.
SMB_O_EXCL                       = 0x00   # When used with SMB_O_CREAT, operation fails if file exists. Cannot be used with SMB_O_OPEN.
SMB_O_OPEN                       = 0x01   # Open the file if the file exists
SMB_O_TRUNC                      = 0x02   # Truncate the file if the file exists

# Share Access Mode
SMB_SHARE_COMPAT                 = 0x00
SMB_SHARE_DENY_EXCL              = 0x10
SMB_SHARE_DENY_WRITE             = 0x20
SMB_SHARE_DENY_READEXEC          = 0x30
SMB_SHARE_DENY_NONE              = 0x40
SMB_ACCESS_READ                  = 0x00
SMB_ACCESS_WRITE                 = 0x01
SMB_ACCESS_READWRITE             = 0x02
SMB_ACCESS_EXEC                  = 0x03

TRANS_DISCONNECT_TID             = 1
TRANS_NO_RESPONSE                = 2

STATUS_SUCCESS                   = 0x00000000
STATUS_LOGON_FAILURE             = 0xC000006D
STATUS_LOGON_TYPE_NOT_GRANTED    = 0xC000015B
MAX_TFRAG_SIZE                   = 5840
EVASION_NONE                     = 0
EVASION_LOW                      = 1
EVASION_HIGH                     = 2
EVASION_MAX                      = 3
RPC_X_BAD_STUB_DATA              = 0x6F7

# SMB_FILE_ATTRIBUTES

SMB_FILE_ATTRIBUTE_NORMAL        = 0x0000
SMB_FILE_ATTRIBUTE_READONLY      = 0x0001
SMB_FILE_ATTRIBUTE_HIDDEN        = 0x0002
SMB_FILE_ATTRIBUTE_SYSTEM        = 0x0004
SMB_FILE_ATTRIBUTE_VOLUME        = 0x0008
SMB_FILE_ATTRIBUTE_DIRECORY      = 0x0010
SMB_FILE_ATTRIBUTE_ARCHIVE       = 0x0020
SMB_SEARCH_ATTRIBUTE_READONLY    = 0x0100
SMB_SEARCH_ATTRIBUTE_HIDDEN      = 0x0200
SMB_SEARCH_ATTRIBUTE_SYSTEM      = 0x0400
SMB_SEARCH_ATTRIBUTE_DIRECTORY   = 0x1000
SMB_SEARCH_ATTRIBUTE_ARCHIVE     = 0x2000

# Session SetupAndX Action flags
SMB_SETUP_GUEST                  = 0x01
SMB_SETUP_USE_LANMAN_KEY         = 0x02

# QUERY_INFORMATION levels
SMB_INFO_ALLOCATION              = 0x0001
SMB_INFO_VOLUME                  = 0x0002
SMB_QUERY_FS_VOLUME_INFO         = 0x0102
SMB_QUERY_FS_SIZE_INFO           = 0x0103
SMB_QUERY_FILE_EA_INFO           = 0x0103
SMB_QUERY_FS_DEVICE_INFO         = 0x0104
SMB_QUERY_FS_ATTRIBUTE_INFO      = 0x0105
SMB_QUERY_FILE_BASIC_INFO        = 0x0101
SMB_QUERY_FILE_STANDARD_INFO     = 0x0102
SMB_QUERY_FILE_ALL_INFO          = 0x0107

# SET_INFORMATION levels
SMB_SET_FILE_DISPOSITION_INFO    = 0x0102
SMB_SET_FILE_BASIC_INFO          = 0x0101
SMB_SET_FILE_END_OF_FILE_INFO    = 0x0104


# File System Attributes
FILE_CASE_SENSITIVE_SEARCH       = 0x00000001
FILE_CASE_PRESERVED_NAMES        = 0x00000002
FILE_UNICODE_ON_DISK             = 0x00000004
FILE_PERSISTENT_ACLS             = 0x00000008
FILE_FILE_COMPRESSION            = 0x00000010
FILE_VOLUME_IS_COMPRESSED        = 0x00008000

# FIND_FIRST2 flags and levels
SMB_FIND_CLOSE_AFTER_REQUEST     = 0x0001
SMB_FIND_CLOSE_AT_EOS            = 0x0002
SMB_FIND_RETURN_RESUME_KEYS      = 0x0004
SMB_FIND_CONTINUE_FROM_LAST      = 0x0008
SMB_FIND_WITH_BACKUP_INTENT      = 0x0010

FILE_DIRECTORY_FILE              = 0x00000001
FILE_DELETE_ON_CLOSE             = 0x00001000
FILE_NON_DIRECTORY_FILE          = 0x00000040

SMB_FIND_INFO_STANDARD           = 0x0001
SMB_FIND_FILE_DIRECTORY_INFO     = 0x0101
SMB_FIND_FILE_FULL_DIRECTORY_INFO= 0x0102
SMB_FIND_FILE_BOTH_DIRECTORY_INFO= 0x0104

# DesiredAccess flags
FILE_READ_DATA                   = 0x00000001
FILE_WRITE_DATA                  = 0x00000002
FILE_APPEND_DATA                 = 0x00000004
FILE_EXECUTE                     = 0x00000020
MAXIMUM_ALLOWED                  = 0200000000
GENERIC_ALL                      = 0x10000000
GENERIC_EXECUTE                  = 0x20000000
GENERIC_WRITE                    = 0x40000000
GENERIC_READ                     = 0x80000000

# ShareAccess flags
FILE_SHARE_NONE                  = 0x00000000
FILE_SHARE_READ                  = 0x00000001
FILE_SHARE_WRITE                 = 0x00000002
FILE_SHARE_DELETE                = 0x00000004

# CreateDisposition flags
FILE_SUPERSEDE                  = 0x00000000
FILE_OPEN                       = 0x00000001
FILE_CREATE                     = 0x00000002
FILE_OPEN_IF                    = 0x00000003
FILE_OVERWRITE                  = 0x00000004
FILE_OVERWRITE_IF               = 0x00000005

############### GSS Stuff ################
GSS_API_SPNEGO_UUID              = '\x2b\x06\x01\x05\x05\x02' 
ASN1_SEQUENCE                    = 0x30
ASN1_SEQUENCE                    = 0x30
ASN1_AID                         = 0x60
ASN1_OID                         = 0x06
ASN1_OCTET_STRING                = 0x04
ASN1_MECH_TYPE                   = 0xa0
ASN1_MECH_TOKEN                  = 0xa2
ASN1_SUPPORTED_MECH              = 0xa1
ASN1_RESPONSE_TOKEN              = 0xa2
ASN1_ENUMERATED                  = 0x0a
MechTypes = {
'+\x06\x01\x04\x01\x827\x02\x02\x1e': 'SNMPv2-SMI::enterprises.311.2.2.30',
'+\x06\x01\x04\x01\x827\x02\x02\n': 'NTLMSSP - Microsoft NTLM Security Support Provider',
'*\x86H\x82\xf7\x12\x01\x02\x02': 'MS KRB5 - Microsoft Kerberos 5',
'*\x86H\x86\xf7\x12\x01\x02\x02': 'KRB5 - Kerberos 5',
'*\x86H\x86\xf7\x12\x01\x02\x02\x03': 'KRB5 - Kerberos 5 - User to User'
}
TypesMech = dict((v,k) for k, v in MechTypes.iteritems())

def asn1encode(data = ''):
        #res = asn1.SEQUENCE(str).encode()
        #import binascii
        #print '\nalex asn1encode str: %s\n' % binascii.hexlify(str)
        if len(data) >= 0 and len(data) <= 0x7F:
            res = pack('B', len(data)) + data
        elif len(data) >= 0x80 and len(data) <= 0xFF:
            res = pack('BB', 0x81, len(data)) + data
        elif len(data) >= 0x100 and len(data) <= 0xFFFF:
            res = pack('!BH', 0x82, len(data)) + data
        elif len(data) >= 0x10000 and len(data) <= 0xffffff:
            res = pack('!BBH', 0x83, len(data) >> 16, len(data) & 0xFFFF) + data
        elif len(data) >= 0x1000000 and len(data) <= 0xffffffff:
            res = pack('!BL', 0x84, len(data)) + data
        else:
            raise Exception('Error in asn1encode')
        return str(res)

def asn1decode(data = ''):
        len1 = unpack('B', data[:1])[0]
        data = data[1:]
        if len1 == 0x81:
            pad = calcsize('B')
            len2 = unpack('B',data[:pad])[0]
            data = data[pad:]
            ans = data[:len2]
        elif len1 == 0x82:
            pad = calcsize('H')
            len2 = unpack('!H', data[:pad])[0]
            data = data[pad:]
            ans = data[:len2]
        elif len1 == 0x83:
            pad = calcsize('B') + calcsize('!H')
            len2, len3 = unpack('!BH', data[:pad])
            data = data[pad:]
            ans = data[:len2 << 16 + len3]
        elif len1 == 0x84:
            pad = calcsize('!L')
            len2 = unpack('!L', data[:pad])[0]
            data = data[pad:]
            ans = data[:len2]
        # 1 byte length, string <= 0x7F
	else:
            pad = 0
            ans = data[:len1]
        return ans, len(ans)+pad+1

class GSSAPI():
# Generic GSSAPI Header Format 
    def __init__(self, data = None):
        self.fields = {}
        self['UUID'] = GSS_API_SPNEGO_UUID
        if data:
             self.fromString(data)
        pass

    def __setitem__(self,key,value):
        self.fields[key] = value

    def __getitem__(self, key):
        return self.fields[key]

    def __delitem__(self, key):
        del self.fields[key]

    def __len__(self):
        return len(self.getData())

    def __str__(self):
        return len(self.getData())

    def fromString(self, data = None):
       	# Manual parse of the GSSAPI Header Format
        # It should be something like
        # AID = 0x60 TAG, BER Length
        # OID = 0x06 TAG
        # GSSAPI OID
        # UUID data (BER Encoded)
        # Payload
        next_byte = unpack('B',data[:1])[0]
        if next_byte != ASN1_AID:
            raise Exception('Unknown AID=%x' % next_byte)
        data = data[1:]
        decode_data, total_bytes = asn1decode(data) 
        # Now we should have a OID tag
       	next_byte = unpack('B',decode_data[:1])[0]
        if next_byte !=  ASN1_OID:
            raise Exception('OID tag not found %x' % next_byte)
        decode_data = decode_data[1:]
        # Now the OID contents, should be SPNEGO UUID
        uuid, total_bytes = asn1decode(decode_data)                
        self['OID'] = uuid
        # the rest should be the data
        self['Payload'] = decode_data[total_bytes:]
        #pass
        
    def dump(self):
        for i in self.fields.keys():
            print "%s: {%r}" % (i,self[i])

    def getData(self):
        ans = pack('B',ASN1_AID)
        ans += asn1encode(
               pack('B',ASN1_OID) + 
               asn1encode(self['UUID']) +
               self['Payload'] )
        return ans

class SPNEGO_NegTokenResp():
    # http://tools.ietf.org/html/rfc4178#page-9
    # NegTokenResp ::= SEQUENCE {
    #     negState       [0] ENUMERATED {
    #         accept-completed    (0),
    #         accept-incomplete   (1),
    #         reject              (2),
    #         request-mic         (3)
    #     }                                 OPTIONAL,
    #       -- REQUIRED in the first reply from the target
    #     supportedMech   [1] MechType      OPTIONAL,
    #       -- present only in the first reply from the target
    #     responseToken   [2] OCTET STRING  OPTIONAL,
    #     mechListMIC     [3] OCTET STRING  OPTIONAL,
    #     ...
    # }
    # This structure is not prepended by a GSS generic header!
    SPNEGO_NEG_TOKEN_RESP = 0xa1
    SPNEGO_NEG_TOKEN_TARG = 0xa0

    def __init__(self, data = None):
        self.fields = {}
        if data:
             self.fromString(data)
        pass

    def __setitem__(self,key,value):
        self.fields[key] = value

    def __getitem__(self, key):
        return self.fields[key]

    def __delitem__(self, key):
        del self.fields[key]

    def __len__(self):
        return len(self.getData())

    def __str__(self):
        return len(self.getData())

    def fromString(self, data = 0):
        payload = data
        next_byte = unpack('B', payload[:1])[0]
        if next_byte != SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            raise Exception('NegTokenResp not found %x' % next_byte)
        payload = payload[1:]
        decode_data, total_bytes = asn1decode(payload)
	next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != ASN1_SEQUENCE:
            raise Exception('SEQUENCE tag not found %x' % next_byte)
        decode_data = decode_data[1:]
        decode_data, total_bytes = asn1decode(decode_data)
        next_byte = unpack('B',decode_data[:1])[0]

        if next_byte != ASN1_MECH_TYPE:
            # MechType not found, could be an AUTH answer
            if next_byte != ASN1_RESPONSE_TOKEN:
               raise Exception('MechType/ResponseToken tag not found %x' % next_byte)
        else:
            decode_data2 = decode_data[1:]
            decode_data2, total_bytes = asn1decode(decode_data2)
            next_byte = unpack('B', decode_data2[:1])[0]
            if next_byte != ASN1_ENUMERATED:
                raise Exception('Enumerated tag not found %x' % next_byte)
            decode_data2 = decode_data2[1:]
            item, total_bytes2 = asn1decode(decode_data)
            self['NegResult'] = item
            decode_data = decode_data[1:]
            decode_data = decode_data[total_bytes:]

            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != ASN1_SUPPORTED_MECH:
                if next_byte != ASN1_RESPONSE_TOKEN:
                    raise Exception('Supported Mech/ResponseToken tag not found %x' % next_byte)
            else:
                decode_data2 = decode_data[1:]
                decode_data2, total_bytes = asn1decode(decode_data2)
                next_byte = unpack('B', decode_data2[:1])[0]
                if next_byte != ASN1_OID:
                    raise Exception('OID tag not found %x' % next_byte)
                decode_data2 = decode_data2[1:]
                item, total_bytes2 = asn1decode(decode_data2)
                self['SuportedMech'] = item

                decode_data = decode_data[1:]
                decode_data = decode_data[total_bytes:]
                next_byte = unpack('B', decode_data[:1])[0]
                if next_byte != ASN1_RESPONSE_TOKEN:
                    raise Exception('Response token tag not found %x' % next_byte)

        decode_data = decode_data[1:]
        decode_data, total_bytes = asn1decode(decode_data)
        next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != ASN1_OCTET_STRING:
            raise Exception('Octet string token tag not found %x' % next_byte)
        decode_data = decode_data[1:]
        decode_data, total_bytes = asn1decode(decode_data)
        self['ResponseToken'] = decode_data

    def dump(self):
        for i in self.fields.keys():
            print "%s: {%r}" % (i,self[i])
        
    def getData(self):
        ans = pack('B',SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP)
        if self.fields.has_key('NegResult') and self.fields.has_key('SupportedMech'):
            # Server resp
            ans += asn1encode(
               pack('B', ASN1_SEQUENCE) +
               asn1encode(
               pack('B',SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_TARG) +
               asn1encode(
               pack('B',ASN1_ENUMERATED) + 
               asn1encode( self['NegResult'] )) +
               pack('B',ASN1_SUPPORTED_MECH) +
               asn1encode( 
               pack('B',ASN1_OID) +
               asn1encode(self['SupportedMech'])) +
               pack('B',ASN1_RESPONSE_TOKEN ) +
               asn1encode(
               pack('B', ASN1_OCTET_STRING) + asn1encode(self['ResponseToken']))))
        elif self.fields.has_key('NegResult'):
            # Server resp
            ans += asn1encode(
               pack('B', ASN1_SEQUENCE) + 
               asn1encode(
               pack('B', SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_TARG) +
               asn1encode(
               pack('B',ASN1_ENUMERATED) +
               asn1encode( self['NegResult'] ))))
        else:
            # Client resp
            ans += asn1encode(
               pack('B', ASN1_SEQUENCE) +
               asn1encode(
               pack('B', ASN1_RESPONSE_TOKEN) +
               asn1encode(
               pack('B', ASN1_OCTET_STRING) + asn1encode(self['ResponseToken']))))
        return ans

class SPNEGO_NegTokenInit(GSSAPI):
    # http://tools.ietf.org/html/rfc4178#page-8 
    # NegTokeInit :: = SEQUENCE {
    #   mechTypes	[0] MechTypeList,
    #   reqFlags        [1] ContextFlags OPTIONAL,
    #   mechToken       [2] OCTET STRING OPTIONAL,	
    #   mechListMIC     [3] OCTET STRING OPTIONAL,
    # }
    SPNEGO_NEG_TOKEN_INIT = 0xa0
    def fromString(self, data = 0):
        GSSAPI.fromString(self, data)
        payload = self['Payload']
        next_byte = unpack('B', payload[:1])[0] 
        if next_byte != SPNEGO_NegTokenInit.SPNEGO_NEG_TOKEN_INIT:
            raise Exception('NegTokenInit not found %x' % next_byte)
        payload = payload[1:]
        decode_data, total_bytes = asn1decode(payload)
        # Now we should have a SEQUENCE Tag
	next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != ASN1_SEQUENCE:
            raise Exception('SEQUENCE tag not found %x' % next_byte)
        decode_data = decode_data[1:]
        decode_data, total_bytes2 = asn1decode(decode_data)
        next_byte = unpack('B',decode_data[:1])[0]
        if next_byte != ASN1_MECH_TYPE:
            raise Exception('MechType tag not found %x' % next_byte)
        decode_data = decode_data[1:]
        remaining_data = decode_data
        decode_data, total_bytes3 = asn1decode(decode_data)
        next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != ASN1_SEQUENCE:
            raise Exception('SEQUENCE tag not found %x' % next_byte)
        decode_data = decode_data[1:]
	decode_data, total_bytes4 = asn1decode(decode_data)
        # And finally we should have the MechTypes
        self['MechTypes'] = []
        i = 1
        while decode_data:
           next_byte = unpack('B', decode_data[:1])[0]
           if next_byte != ASN1_OID:    
             # Not a valid OID, there must be something else we won't unpack
             break
           decode_data = decode_data[1:]
           item, total_bytes = asn1decode(decode_data)
           self['MechTypes'].append(item)
           decode_data = decode_data[total_bytes:]

        # Do we have MechTokens as well?
        decode_data = remaining_data[total_bytes3:]
        if len(decode_data) > 0:
            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte == ASN1_MECH_TOKEN:
                # We have tokens in here!
                decode_data = decode_data[1:]
                decode_data, total_bytes = asn1decode(decode_data)
                next_byte = unpack('B', decode_data[:1])[0]
                if next_byte ==  ASN1_OCTET_STRING:
                    decode_data = decode_data[1:]
                    decode_data, total_bytes = asn1decode(decode_data)
                    self['MechToken'] =  decode_data

    def getData(self):
        mechTypes = ''
        for i in self['MechTypes']:
            mechTypes += pack('B', ASN1_OID)
            mechTypes += asn1encode(i)

	mechToken = ''
        # Do we have tokens to send?
        if self.fields.has_key('MechToken'):
           mechToken = pack('B', ASN1_MECH_TOKEN) + asn1encode(
                       pack('B', ASN1_OCTET_STRING) + asn1encode(
                       self['MechToken']))

        ans = pack('B',SPNEGO_NegTokenInit.SPNEGO_NEG_TOKEN_INIT)
        ans += asn1encode(
               pack('B', ASN1_SEQUENCE) +
               asn1encode(
               pack('B', ASN1_MECH_TYPE) +
               asn1encode(
               pack('B', ASN1_SEQUENCE) + 
               asn1encode(mechTypes)) + mechToken ))


        self['Payload'] = ans
        return GSSAPI.getData(self)
     
def strerror(errclass, errcode):
    if errclass == 0x01:
        return 'OS error', ERRDOS.get(errcode, 'Unknown error')
    elif errclass == 0x02:
        return 'Server error', ERRSRV.get(errcode, 'Unknown error')
    elif errclass == 0x03:
        return 'Hardware error', ERRHRD.get(errcode, 'Unknown error')
    # This is not a standard error class for SMB
    #elif errclass == 0x80:
    #    return 'Browse error', ERRBROWSE.get(errcode, 'Unknown error')
    elif errclass == 0xff:
        return 'Bad command', 'Bad command. Please file bug report'
    else:
        return 'Unknown error', 'Unknown error'

    

# Raised when an error has occured during a session
class SessionError(Exception):
    # SMB X/Open error codes for the ERRDOS error class
    ERRsuccess                           = 0
    ERRbadfunc                           = 1
    ERRbadfile                           = 2
    ERRbadpath                           = 3
    ERRnofids                            = 4
    ERRnoaccess                          = 5
    ERRbadfid                            = 6
    ERRbadmcb                            = 7
    ERRnomem                             = 8
    ERRbadmem                            = 9
    ERRbadenv                            = 10
    ERRbadaccess                         = 12
    ERRbaddata                           = 13
    ERRres                               = 14
    ERRbaddrive                          = 15
    ERRremcd                             = 16
    ERRdiffdevice                        = 17
    ERRnofiles                           = 18
    ERRgeneral                           = 31
    ERRbadshare                          = 32
    ERRlock                              = 33
    ERRunsup                             = 50
    ERRnetnamedel                        = 64
    ERRnosuchshare                       = 67
    ERRfilexists                         = 80
    ERRinvalidparam                      = 87
    ERRcannotopen                        = 110
    ERRinsufficientbuffer                = 122
    ERRinvalidname                       = 123
    ERRunknownlevel                      = 124
    ERRnotlocked                         = 158
    ERRrename                            = 183
    ERRbadpipe                           = 230
    ERRpipebusy                          = 231
    ERRpipeclosing                       = 232
    ERRnotconnected                      = 233
    ERRmoredata                          = 234
    ERRnomoreitems                       = 259
    ERRbaddirectory                      = 267
    ERReasnotsupported                   = 282
    ERRlogonfailure                      = 1326
    ERRbuftoosmall                       = 2123
    ERRunknownipc                        = 2142
    ERRnosuchprintjob                    = 2151
    ERRinvgroup                          = 2455

    # here's a special one from observing NT
    ERRnoipc                             = 66

    # These errors seem to be only returned by the NT printer driver system
    ERRdriveralreadyinstalled            = 1795
    ERRunknownprinterport                = 1796
    ERRunknownprinterdriver              = 1797
    ERRunknownprintprocessor             = 1798
    ERRinvalidseparatorfile              = 1799
    ERRinvalidjobpriority                = 1800
    ERRinvalidprintername                = 1801
    ERRprinteralreadyexists              = 1802
    ERRinvalidprintercommand             = 1803
    ERRinvaliddatatype                   = 1804
    ERRinvalidenvironment                = 1805

    ERRunknownprintmonitor               = 3000
    ERRprinterdriverinuse                = 3001
    ERRspoolfilenotfound                 = 3002
    ERRnostartdoc                        = 3003
    ERRnoaddjob                          = 3004
    ERRprintprocessoralreadyinstalled    = 3005
    ERRprintmonitoralreadyinstalled      = 3006
    ERRinvalidprintmonitor               = 3007
    ERRprintmonitorinuse                 = 3008
    ERRprinterhasjobsqueued              = 3009

    # Error codes for the ERRSRV class

    ERRerror                             = 1
    ERRbadpw                             = 2
    ERRbadtype                           = 3
    ERRaccess                            = 4
    ERRinvnid                            = 5
    ERRinvnetname                        = 6
    ERRinvdevice                         = 7
    ERRqfull                             = 49
    ERRqtoobig                           = 50
    ERRinvpfid                           = 52
    ERRsmbcmd                            = 64
    ERRsrverror                          = 65
    ERRfilespecs                         = 67
    ERRbadlink                           = 68
    ERRbadpermits                        = 69
    ERRbadpid                            = 70
    ERRsetattrmode                       = 71
    ERRpaused                            = 81
    ERRmsgoff                            = 82
    ERRnoroom                            = 83
    ERRrmuns                             = 87
    ERRtimeout                           = 88
    ERRnoresource                        = 89
    ERRtoomanyuids                       = 90
    ERRbaduid                            = 91
    ERRuseMPX                            = 250
    ERRuseSTD                            = 251
    ERRcontMPX                           = 252
    ERRbadPW                             = None
    ERRnosupport                         = 0
    ERRunknownsmb                        = 22

    # Error codes for the ERRHRD class

    ERRnowrite                           = 19
    ERRbadunit                           = 20
    ERRnotready                          = 21
    ERRbadcmd                            = 22
    ERRdata                              = 23
    ERRbadreq                            = 24
    ERRseek                              = 25
    ERRbadmedia                          = 26
    ERRbadsector                         = 27
    ERRnopaper                           = 28
    ERRwrite                             = 29
    ERRread                              = 30
    ERRgeneral                           = 31
    ERRwrongdisk                         = 34
    ERRFCBunavail                        = 35
    ERRsharebufexc                       = 36
    ERRdiskfull                          = 39


    hard_msgs = {
      19: ("ERRnowrite", "Attempt to write on write-protected diskette."),
      20: ("ERRbadunit", "Unknown unit."),
      21: ("ERRnotready", "Drive not ready."),
      22: ("ERRbadcmd", "Unknown command."),
      23: ("ERRdata", "Data error (CRC)."),
      24: ("ERRbadreq", "Bad request structure length."),
      25 : ("ERRseek", "Seek error."),
      26: ("ERRbadmedia", "Unknown media type."),
      27: ("ERRbadsector", "Sector not found."),
      28: ("ERRnopaper", "Printer out of paper."),
      29: ("ERRwrite", "Write fault."),
      30: ("ERRread", "Read fault."),
      31: ("ERRgeneral", "General failure."),
      32: ("ERRbadshare", "An open conflicts with an existing open."),
      33: ("ERRlock", "A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process."),
      34: ("ERRwrongdisk", "The wrong disk was found in a drive."),
      35: ("ERRFCBUnavail", "No FCBs are available to process request."),
      36: ("ERRsharebufexc", "A sharing buffer has been exceeded.")
      }

    nt_msgs = {
      0x02: ("ERRbadfunc", "Invalid function."),
      0x10: ("ERRbadfunc", "Invalid function."),
      0xAF: ("ERRbadfunc", "Invalid function."),
      0x0f: ("ERRbadfile", "File not found."),
      0x0e: ("ERRbadfile", "File not found."),
      0x34: ("ERRbadfile", "File not found."),
      0x3a: ("ERRbadpath", "Directory invalid."),
      0x6d: ("ERRnoaccess", "Access denied."),
      0x22: ("ERRnoaccess", "Access denied."),
      0x1E: ("ERRnoaccess", "Access denied."),
      0x1F: ("ERRnoaccess", "Access denied."),
      0x21: ("ERRnoaccess", "Access denied."),
      0x41: ("ERRnoaccess", "Access denied."),
      0x4B: ("ERRnoaccess", "Access denied."),
      0x56: ("ERRnoaccess", "Access denied."),
      0x61: ("ERRnoaccess", "Access denied."),
      0xBA: ("ERRnoaccess", "Access denied."),
      0xD5: ("ERRbadpath", "Directory invalid."),
      0x3A: ("ERRbadpath", "Directory invalid."),
      0x3B: ("ERRbadpath", "Directory invalid."),
      0x9B: ("ERRbadpath", "Directory invalid."),
      0xFB: ("ERRbadpath", "Directory invalid."),
      0xBD: ("ERRbadpath", "Duplicate name."),
      0x35: ("ERRfilexists", "The file named in a Create Directory, Make  New  File  or  Link  request already exists.") 
    }

    dos_msgs = {
      ERRbadfunc: ("ERRbadfunc", "Invalid function."),
      ERRbadfile: ("ERRbadfile", "File not found."),
      ERRbadpath: ("ERRbadpath", "Directory invalid."),
      ERRnofids: ("ERRnofids", "No file descriptors available"),
      ERRnoaccess: ("ERRnoaccess", "Access denied."),
      ERRbadfid: ("ERRbadfid", "Invalid file handle."),
      ERRbadmcb: ("ERRbadmcb", "Memory control blocks destroyed."),
      ERRnomem: ("ERRnomem", "Insufficient server memory to perform the requested function."),
      ERRbadmem: ("ERRbadmem", "Invalid memory block address."),
      ERRbadenv: ("ERRbadenv", "Invalid environment."),
      11: ("ERRbadformat", "Invalid format."),
      ERRbadaccess: ("ERRbadaccess", "Invalid open mode."),
      ERRbaddata: ("ERRbaddata", "Invalid data."),
      ERRres: ("ERRres", "reserved."),
      ERRbaddrive: ("ERRbaddrive", "Invalid drive specified."),
      ERRremcd: ("ERRremcd", "A Delete Directory request attempted  to  remove  the  server's  current directory."),
      ERRdiffdevice: ("ERRdiffdevice", "Not same device."),
      ERRnofiles: ("ERRnofiles", "A File Search command can find no more files matching the specified criteria."),
      ERRbadshare: ("ERRbadshare", "The sharing mode specified for an Open conflicts with existing  FIDs  on the file."),
      ERRlock: ("ERRlock", "A Lock request conflicted with an existing lock or specified an  invalid mode,  or an Unlock requested attempted to remove a lock held by another process."),
      ERRunsup: ("ERRunsup",  "The operation is unsupported"),
      ERRnosuchshare: ("ERRnosuchshare",  "You specified an invalid share name"),
      ERRfilexists: ("ERRfilexists", "The file named in a Create Directory, Make  New  File  or  Link  request already exists."),
      ERRinvalidname: ("ERRinvalidname",  "Invalid name"),
      ERRbadpipe: ("ERRbadpipe", "Pipe invalid."),
      ERRpipebusy: ("ERRpipebusy", "All instances of the requested pipe are busy."),
      ERRpipeclosing: ("ERRpipeclosing", "Pipe close in progress."),
      ERRnotconnected: ("ERRnotconnected", "No process on other end of pipe."),
      ERRmoredata: ("ERRmoredata", "There is more data to be returned."),
      ERRinvgroup: ("ERRinvgroup", "Invalid workgroup (try the -W option)"),
      ERRlogonfailure: ("ERRlogonfailure", "Logon failure"),
      ERRdiskfull: ("ERRdiskfull", "Disk full"),
      ERRgeneral: ("ERRgeneral",  "General failure"),
      ERRunknownlevel: ("ERRunknownlevel",  "Unknown info level")
      }

    server_msgs = { 
      1: ("ERRerror", "Non-specific error code."),
      2: ("ERRbadpw", "Bad password - name/password pair in a Tree Connect or Session Setup are invalid."),
      3: ("ERRbadtype", "reserved."),
      4: ("ERRaccess", "The requester does not have  the  necessary  access  rights  within  the specified  context for the requested function. The context is defined by the TID or the UID."),
      5: ("ERRinvnid", "The tree ID (TID) specified in a command was invalid."),
      6: ("ERRinvnetname", "Invalid network name in tree connect."),
      7: ("ERRinvdevice", "Invalid device - printer request made to non-printer connection or  non-printer request made to printer connection."),
      49: ("ERRqfull", "Print queue full (files) -- returned by open print file."),
      50: ("ERRqtoobig", "Print queue full -- no space."),
      51: ("ERRqeof", "EOF on print queue dump."),
      52: ("ERRinvpfid", "Invalid print file FID."),
      64: ("ERRsmbcmd", "The server did not recognize the command received."),
      65: ("ERRsrverror","The server encountered an internal error, e.g., system file unavailable."),
      67: ("ERRfilespecs", "The file handle (FID) and pathname parameters contained an invalid  combination of values."),
      68: ("ERRreserved", "reserved."),
      69: ("ERRbadpermits", "The access permissions specified for a file or directory are not a valid combination.  The server cannot set the requested attribute."),
      70: ("ERRreserved", "reserved."),
      71: ("ERRsetattrmode", "The attribute mode in the Set File Attribute request is invalid."),
      81: ("ERRpaused", "Server is paused."),
      82: ("ERRmsgoff", "Not receiving messages."),
      83: ("ERRnoroom", "No room to buffer message."),
      87: ("ERRrmuns", "Too many remote user names."),
      88: ("ERRtimeout", "Operation timed out."),
      89: ("ERRnoresource", "No resources currently available for request."),
      90: ("ERRtoomanyuids", "Too many UIDs active on this session."),
      91: ("ERRbaduid", "The UID is not known as a valid ID on this session."),
      250: ("ERRusempx","Temp unable to support Raw, use MPX mode."),
      251: ("ERRusestd","Temp unable to support Raw, use standard read/write."),
      252: ("ERRcontmpx", "Continue in MPX mode."),
      253: ("ERRreserved", "reserved."),
      254: ("ERRreserved", "reserved."),
  0xFFFF: ("ERRnosupport", "Function not supported.")
  }    
    # Error clases

    ERRDOS = 0x1
    error_classes = { 0: ("SUCCESS", {}),
                      ERRDOS: ("ERRDOS", dos_msgs),
                      0x02: ("ERRSRV",server_msgs),
                      0x03: ("ERRHRD",hard_msgs),
                      0x04: ("ERRXOS", {} ),
                      0xE1: ("ERRRMX1", {} ),
                      0xE2: ("ERRRMX2", {} ),
                      0xE3: ("ERRRMX3", {} ),
                      0xC000: ("ERRNT", nt_msgs),
                      0xFF: ("ERRCMD", {} ) }

    

    def __init__( self, str, error_class, error_code, nt_status = 0):
        Exception.__init__(self, str)
        self._args = str
        if nt_status:
           self.error_class = error_code
           self.error_code  = error_class
        else:
           self.error_class = error_class
           self.error_code = error_code
       
    def get_error_class( self ):
        return self.error_class

    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        error_class = SessionError.error_classes.get( self.error_class, None )
        if not error_class:
            error_code_str = self.error_code
            error_class_str = self.error_class
        else:
            error_class_str = error_class[0]
            error_code = error_class[1].get( self.error_code, None )
            if not error_code:
                error_code_str = self.error_code
            else:
                error_code_str = '%s(%s)' % (error_code)

        return 'SessionError: %s, class: %s, code: %s' % (self._args, error_class_str, error_code_str)


# Raised when an supported feature is present/required in the protocol but is not
# currently supported by pysmb
class UnsupportedFeature(Exception): pass

# Contains information about a SMB shared device/service
class SharedDevice:

    def __init__(self, name, type, comment):
        self.__name = name
        self.__type = type
        self.__comment = comment

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def get_comment(self):
        return self.__comment

    def __repr__(self):
        return '<SharedDevice instance: name=' + self.__name + ', type=' + str(self.__type) + ', comment="' + self.__comment + '">'


# Contains information about the shared file/directory
class SharedFile:
    def __init__(self, ctime, atime, mtime, filesize, allocsize, attribs, shortname, longname):
        self.__ctime = ctime
        self.__atime = atime
        self.__mtime = mtime
        self.__filesize = filesize
        self.__allocsize = allocsize
        self.__attribs = attribs
        try:
            self.__shortname = shortname[:string.index(shortname, '\0')]
        except ValueError:
            self.__shortname = shortname
        try:
            self.__longname = longname[:string.index(longname, '\0')]
        except ValueError:
            self.__longname = longname

    def get_ctime(self):
        return self.__ctime

    def get_ctime_epoch(self):
        return self.__convert_smbtime(self.__ctime)

    def get_mtime(self):
        return self.__mtime

    def get_mtime_epoch(self):
        return self.__convert_smbtime(self.__mtime)

    def get_atime(self):
        return self.__atime

    def get_atime_epoch(self):
        return self.__convert_smbtime(self.__atime)

    def get_filesize(self):
        return self.__filesize

    def get_allocsize(self):
        return self.__allocsize

    def get_attributes(self):
        return self.__attribs

    def is_archive(self):
        return self.__attribs & ATTR_ARCHIVE

    def is_compressed(self):
        return self.__attribs & ATTR_COMPRESSED

    def is_normal(self):
        return self.__attribs & ATTR_NORMAL

    def is_hidden(self):
        return self.__attribs & ATTR_HIDDEN

    def is_readonly(self):
        return self.__attribs & ATTR_READONLY

    def is_temporary(self):
        return self.__attribs & ATTR_TEMPORARY

    def is_directory(self):
        return self.__attribs & ATTR_DIRECTORY

    def is_system(self):
        return self.__attribs & ATTR_SYSTEM

    def get_shortname(self):
        return self.__shortname

    def get_longname(self):
        return self.__longname

    def __repr__(self):
        return '<SharedFile instance: shortname="' + self.__shortname + '", longname="' + self.__longname + '", filesize=' + str(self.__filesize) + '>'

    def __convert_smbtime(self, t):
        x = t >> 32
        y = t & 0xffffffffL
        geo_cal_offset = 11644473600.0  # = 369.0 * 365.25 * 24 * 60 * 60 - (3.0 * 24 * 60 * 60 + 6.0 * 60 * 60)
        return ((x * 4.0 * (1 << 30) + (y & 0xfff00000L)) * 1.0e-7 - geo_cal_offset)


# Contain information about a SMB machine
class SMBMachine:

    def __init__(self, nbname, type, comment):
        self.__nbname = nbname
        self.__type = type
        self.__comment = comment

    def __repr__(self):
        return '<SMBMachine instance: nbname="' + self.__nbname + '", type=' + hex(self.__type) + ', comment="' + self.__comment + '">'



class SMBDomain:
    def __init__(self, nbgroup, type, master_browser):
        self.__nbgroup = nbgroup
        self.__type = type
        self.__master_browser = master_browser

    def __repr__(self):
        return '<SMBDomain instance: nbgroup="' + self.__nbgroup + '", type=' + hex(self.__type) + ', master browser="' + self.__master_browser + '">'
    
# Represents a SMB Packet
class NewSMBPacket(Structure):
    structure = (
        ('Signature', '"\xffSMB'),
        ('Command','B=0'),
        ('ErrorClass','B=0'),
        ('_reserved','B=0'),
        ('ErrorCode','<H=0'),
        ('Flags1','B=0'),
        ('Flags2','<H=0'),
        ('PIDHigh','<H=0'),
        ('SecurityFeatures','8s=""'),
        ('Reserved','<H=0'),
        ('Tid','<H=0xffff'),
        ('Pid','<H=0'),
        ('Uid','<H=0'),
        ('Mid','<H=0'),
        ('Data','*:'),
    )

    def __init__(self, **kargs):
        Structure.__init__(self, **kargs)

        if self.fields.has_key('Flags2') is False:
             self['Flags2'] = 0

        if not kargs.has_key('data'):
            self['Data'] = []
    
    def addCommand(self, command):
        if len(self['Data']) == 0:
            self['Command'] = command.command
        else:
            self['Data'][-1]['Parameters']['AndXCommand'] = command.command
            self['Data'][-1]['Parameters']['AndXOffset'] = len(self)
        self['Data'].append(command)
        
    def isMoreData(self):
        return (self['Command'] in [SMB.SMB_COM_TRANSACTION, SMB.SMB_COM_READ_ANDX, SMB.SMB_COM_READ_RAW] and
                self['ErrorClass'] == 1 and self['ErrorCode'] == SessionError.ERRmoredata)

    def isMoreProcessingRequired(self):
        return self['ErrorClass'] == 0x16 and self['ErrorCode'] == 0xc000

    def isValidAnswer(self, cmd):
        # this was inside a loop reading more from the net (with recv_packet(None))
        if self['Command'] == cmd:
            if (self['ErrorClass'] == 0x00 and
                self['ErrorCode']  == 0x00):
                    return 1
            elif self.isMoreData():
                return 1
            elif self.isMoreProcessingRequired():
                return 1
            raise SessionError, ("SMB Library Error", self['ErrorClass'], self['ErrorCode'], self['Flags2'] & SMB.FLAGS2_NT_STATUS)
        else:
            raise UnsupportedFeature, ("Unexpected answer from server: Got %d, Expected %d" % (self['Command'], cmd))

class SMBPacket:
    def __init__(self,data = ''):
        # The uid attribute will be set when the client calls the login() method
        self._command = 0x0
        self._error_class = 0x0
        self._error_code = 0x0
        self._flags = 0x0
        self._flags2 = 0x0
        self._pad = '\0' * 12
        self._tid = 0x0
        self._pid = 0x0
        self._uid = 0x0
        self._mid = 0x0
        self._wordcount = 0x0
        self._parameter_words = ''
        self._bytecount = 0x0
        self._buffer = ''
        if data != '':
            self._command = ord(data[4])
            self._error_class = ord(data[5])
            self._error_code = unpack('<H',data[7:9])[0]
            self._flags = ord(data[9])
            self._flags2 = unpack('<H',data[10:12])[0]
            self._tid = unpack('<H',data[24:26])[0]
            self._pid = unpack('<H',data[26:28])[0]
            self._uid = unpack('<H',data[28:30])[0]
            self._mid = unpack('<H',data[30:32])[0]
            self._wordcount = ord(data[32])
            self._parameter_words = data[33:33+self._wordcount*2]
            self._bytecount = ord(data[33+self._wordcount*2])
            self._buffer = data[35+self._wordcount*2:]
    def set_command(self,command):
        self._command = command
    def set_error_class(self, error_class):
        self._error_class = error_class
    def set_error_code(self,error_code):
        self._error_code = error_code
    def set_flags(self,flags):
        self._flags = flags
    def set_flags2(self, flags2):
        self._flags2 = flags2
    def set_pad(self, pad):
        self._pad = pad
    def set_tid(self,tid):
        self._tid = tid
    def set_pid(self,pid):
        self._pid = pid
    def set_uid(self,uid):
        self._uid = uid
    def set_mid(self,mid):
        self._mid = mid
    def set_parameter_words(self,param):
        self._parameter_words = param
        self._wordcount = len(param)/2
    def set_buffer(self,buffer):
        if type(buffer) is types.UnicodeType:
            raise Exception('SMBPacket: Invalid buffer. Received unicode')
        self._buffer = buffer
        self._bytecount = len(buffer)

    def get_command(self):
        return self._command
    def get_error_class(self):
        return self._error_class
    def get_error_code(self):
        return self._error_code
    def get_flags(self):
        return self._flags
    def get_flags2(self):
        return self._flags2
    def get_pad(self):
        return self._pad
    def get_tid(self):
        return self._tid
    def get_pid(self):
        return self._pid
    def get_uid(self):
        return self._uid
    def get_mid(self):
        return self._mid
    def get_parameter_words(self):
        return self._parameter_words
    def get_wordcount(self):
        return self._wordcount
    def get_bytecount(self):
        return self._bytecount
    def get_buffer(self):
        return self._buffer
    def rawData(self):
        data = pack('<4sBBBHBH12sHHHHB','\xffSMB',self._command,self._error_class,0,self._error_code,self._flags,
                    self._flags2,self._pad,self._tid, self._pid, self._uid, self._mid, self._wordcount) + self._parameter_words + pack('<H',self._bytecount) + self._buffer
        return data        

class SMBCommand(Structure):
    structure = (
        ('WordCount', 'B=len(Parameters)/2'),
        ('_ParametersLength','_-Parameters','WordCount*2'),
        ('Parameters',':'),             # default set by constructor
        ('ByteCount','<H-Data'),
        ('Data',':'),                   # default set by constructor
    )

    def __init__(self, commandOrData = None, data = None, **kargs):
        if type(commandOrData) == type(0):
            self.command = commandOrData
        else:
            data = data or commandOrData

        Structure.__init__(self, data = data, **kargs)

        if data is None:
            self['Parameters'] = ''
            self['Data']       = ''

class AsciiOrUnicodeStructure(Structure):
    def __init__(self, flags = 0, **kargs):
        if flags & SMB.FLAGS2_UNICODE:
            self.structure = self.UnicodeStructure
        else:
            self.structure = self.AsciiStructure
        return Structure.__init__(self, **kargs)

class SMBCommand_Parameters(Structure):
    pass

class SMBAndXCommand_Parameters(Structure):
    commonHdr = (
        ('AndXCommand','B=0xff'),
        ('_reserved','B=0'),
        ('AndXOffset','<H=0'),
    )
    structure = (       # default structure, overriden by subclasses
        ('Data',':=""'),
    )

############# TRANSACTIONS RELATED 
# TRANS2_QUERY_FS_INFORMATION
# QUERY_FS Information Levels
# SMB_QUERY_FS_ATTRIBUTE_INFO
class SMBQueryFsAttributeInfo(Structure):
    structure = (
        ('FileSystemAttributes','<L'),
        ('MaxFilenNameLengthInBytes','<L'),
        ('LengthOfFileSystemName','<L-FileSystemName'),
        ('FileSystemName',':'),
    )

class SMBQueryFsInfoVolume(Structure):
    structure = (
        ('ulVolSerialNbr','<L=0xABCDEFAA'),
        ('cCharCount','<B-VolumeLabel'),
        ('VolumeLabel','z'),
    )

# SMB_QUERY_FS_SIZE_INFO
class SMBQueryFsSizeInfo(Structure):
    structure = (
        ('TotalAllocationUnits','<q=148529400'),
        ('TotalFreeAllocationUnits','<q=14851044'),
        ('SectorsPerAllocationUnit','<L=2'),
        ('BytesPerSector','<L=512'),
    )
# SMB_QUERY_FS_VOLUME_INFO
class SMBQueryFsVolumeInfo(Structure):
    structure = (
        ('VolumeCreationTime','<q'),
        ('SerialNumber','<L=0xABCDEFAA'),
        ('VolumeLabelSize','<L=len(VolumeLabel)/2'),
        ('Reserved','<H=0'),
        ('VolumeLabel',':')
    )
# SMB_FIND_FILE_BOTH_DIRECTORY_INFO level
class SMBFindFileBothDirectoryInfo(Structure):
    structure = (
        ('NextEntryOffset','<L=0'),
        ('FileIndex','<L=0'),
        ('CreationTime','<q'),
        ('LastAccessTime','<q'),
        ('LastWriteTime','<q'),
        ('LastChangeTime','<q'),
        ('EndOfFile','<q=0'),
        ('AllocationSize','<q=0'),
        ('ExtFileAttributes','<L=0'),
        ('FileNameLength','<L-FileName','len(FileName)'),
        ('EaSize','<L=0'),
        #('ShortNameLength','<B-ShortName','len(ShortName)'),
        ('ShortNameLength','<B=0'),
        ('Reserved','<B=0'),
        ('ShortName','24s'),
        ('FileName',':'),
    )

# SMB_FIND_FILE_DIRECTORY_INFO level
class SMBFindFileDirectoryInfo(Structure):
    structure = (
        ('NextEntryOffset','<L=0'),
        ('FileIndex','<L=0'),
        ('CreationTime','<q'),
        ('LastAccessTime','<q'),
        ('LastWriteTime','<q'),
        ('LastChangeTime','<q'),
        ('EndOfFile','<q=0'),
        ('AllocationSize','<q=1'),
        ('ExtFileAttributes','<L=0'),
        ('FileNameLength','<L-FileName','len(FileName)'),
        ('FileName','z'),
    )

# SMB_FIND_FILE_FULL_DIRECTORY_INFO level
class SMBFindFileFullDirectoryInfo(Structure):
    structure = (
        ('NextEntryOffset','<L=0'),
        ('FileIndex','<L=0'),
        ('CreationTime','<q'),
        ('LastAccessTime','<q'),
        ('LastWriteTime','<q'),
        ('LastChangeTime','<q'),
        ('EndOfFile','<q=0'),
        ('AllocationSize','<q=1'),
        ('ExtFileAttributes','<L=0'),
        ('FileNameLength','<L-FileName','len(FileName)'),
        ('EaSize','<L'),
        ('FileName','z'),
    )

# SMB_FIND_INFO_STANDARD level
class SMBFindInfoStandard(Structure):
    structure = (
        ('ResumeKey','<L=0xff'),
        ('CreationDate','<H=0'),
        ('CreationTime','<H=0'),
        ('LastAccessDate','<H=0'),
        ('LastAccessTime','<H=0'),
        ('LastWriteDate','<H=0'),
        ('LastWriteTime','<H=0'),
        ('EaSize','<L'),
        ('AllocationSize','<L=1'),
        ('ExtFileAttributes','<H=0'),
        ('FileNameLength','<B-FileName','len(FileName)'),
        ('FileName','z'),
    )

# SET_FILE_INFORMATION structures
# SMB_SET_FILE_DISPOSITION_INFO
class SMBSetFileDispositionInfo(Structure):
    structure = (
        ('DeletePending','<B'),
    )

# SMB_SET_FILE_BASIC_INFO
class SMBSetFileBasicInfo(Structure):
    structure = (
        ('CreationTime','<q'),
        ('LastAccessTime','<q'),
        ('LastWriteTime','<q'),
        ('ChangeTime','<q'),
        ('ExtFileAttributes','<H'),
        ('Reserved','<L'),
    )

# SMB_SET_FILE_END_OF_FILE_INFO
class SMBSetFileEndOfFileInfo(Structure):
    structure = (
        ('EndOfFile','<q'),
    )

# TRANS2_FIND_NEXT2
class SMBFindNext2_Parameters(Structure):
     structure = (
         ('SID','<H'),
         ('SearchCount','<H'),
         ('InformationLevel','<H'),
         ('ResumeKey','<L'),
         ('Flags','<H'),
         ('FileName','z'),
     )

class SMBFindNext2Response_Parameters(Structure):
     structure = (
         ('SearchCount','<H'),
         ('EndOfSearch','<H=1'),
         ('EaErrorOffset','<H=0'),
         ('LastNameOffset','<H=0'),
     )

class SMBFindNext2_Data(Structure):
     structure = (
         ('GetExtendedAttributesListLength','_-GetExtendedAttributesList', 'self["GetExtendedAttributesListLength"]'),
         ('GetExtendedAttributesList',':'),
     )


# TRANS2_FIND_FIRST2 
class SMBFindFirst2Response_Parameters(Structure):
     structure = (
         ('SID','<H'),
         ('SearchCount','<H'),
         ('EndOfSearch','<H=1'),
         ('EaErrorOffset','<H=0'),
         ('LastNameOffset','<H=0'),
     )

class SMBFindFirst2_Parameters(Structure):
     structure = (
         ('SearchAttributes','<H'),
         ('SearchCount','<H'),
         ('Flags','<H'),
         ('InformationLevel','<H'),
         ('SearchStorageType','<L'),
         ('FileName','z'),
     )

class SMBFindFirst2_Data(Structure):
     structure = (
         ('GetExtendedAttributesListLength','_-GetExtendedAttributesList', 'self["GetExtendedAttributesListLength"]'),
         ('GetExtendedAttributesList',':'),
     )

# TRANS2_SET_PATH_INFORMATION
class SMBSetPathInformation_Parameters(Structure):
    structure = (
        ('InformationLevel','<H'),
        ('Reserved','<L'),
        ('FileName','z'),
    )

class SMBSetPathInformationResponse_Parameters(Structure):
    structure = (
        ('EaErrorOffset','<H=0'),
    )

# TRANS2_SET_FILE_INFORMATION
class SMBSetFileInformation_Parameters(Structure):
    structure = (
        ('FID','<H'),
        ('InformationLevel','<H'),
        ('Reserved','<H'),
    )

class SMBSetFileInformationResponse_Parameters(Structure):
    structure = (
        ('EaErrorOffset','<H=0'),
    )

# TRANS2_QUERY_FILE_INFORMATION
class SMBQueryFileInformation_Parameters(Structure):
    structure = (
        ('FID','<H'),
        ('InformationLevel','<H'),
    )

class SMBQueryFileInformationResponse_Parameters(Structure):
    structure = (
        ('EaErrorOffset','<H=0')
    )

class SMBQueryFileInformation_Data(Structure):
    structure = (
        ('GetExtendedAttributeList',':'),
    )

class SMBQueryFileInformationResponse_Parameters(Structure):
    structure = (
        ('EaErrorOffset','<H=0'),
    )


# TRANS2_QUERY_PATH_INFORMATION
class SMBQueryPathInformationResponse_Parameters(Structure):
    structure = (
        ('EaErrorOffset','<H=0'),
    )

class SMBQueryPathInformation_Parameters(Structure):
    structure = (
        ('InformationLevel','<H'),
        ('Reserved','<L=0'),
        ('FileName','z'),
    )

class SMBQueryPathInformation_Data(Structure):
    structure = (
        ('GetExtendedAttributeList',':'),
    )


# SMB_QUERY_FILE_EA_INFO
class SMBQueryFileEaInfo(Structure):
    structure = (
        ('EaSize','<L=0'),
    )

# SMB_QUERY_FILE_BASIC_INFO 
class SMBQueryFileBasicInfo(Structure):
    structure = (
        ('CreationTime','<q'),
        ('LastAccessTime','<q'),
        ('LastWriteTime','<q'),
        ('LastChangeTime','<q'),
        ('ExtFileAttributes','<L'),
        #('Reserved','<L=0'),
    )

# SMB_QUERY_FILE_STANDARD_INFO
class SMBQueryFileStandardInfo(Structure):
    structure = (
        ('AllocationSize','<q'),
        ('EndOfFile','<q'),
        ('NumberOfLinks','<L=0'),
        ('DeletePending','<B=0'),
        ('Directory','<B'),
    )

# SMB_QUERY_FILE_ALL_INFO
class SMBQueryFileAllInfo(Structure):
    structure = (
        ('CreationTime','<q'),
        ('LastAccessTime','<q'),
        ('LastWriteTime','<q'),
        ('LastChangeTime','<q'),
        ('ExtFileAttributes','<L'),
        ('Reserved','<L=0'),
        ('AllocationSize','<q'),
        ('EndOfFile','<q'),
        ('NumberOfLinks','<L=0'),
        ('DeletePending','<B=0'),
        ('Directory','<B'),
        ('Reserved','<H=0'),
        ('EaSize','<L=0'),
        ('FileNameLength','<L-FileName','len(FileName)'),
        ('FileName','z'),
    )

# \PIPE\LANMAN NetShareEnum
class SMBNetShareEnum(Structure):
    structure = (
        ('RAPOpcode','<H=0'),
        ('ParamDesc','z'),
        ('DataDesc','z'),
        ('InfoLevel','<H'),
        ('ReceiveBufferSize','<H'),
    )

class SMBNetShareEnumResponse(Structure):
    structure = (
        ('Status','<H=0'),
        ('Convert','<H=0'),
        ('EntriesReturned','<H'),
        ('EntriesAvailable','<H'),
    )

class NetShareInfo1(Structure):
    structure = (
        ('NetworkName','13s'),
        ('Pad','<B=0'),
        ('Type','<H=0'),
        ('RemarkOffsetLow','<H=0'),
        ('RemarkOffsetHigh','<H=0'),
    )

############# Security Features
class SecurityFeatures(Structure):
    structure = (
        ('Key','<L=0'),
        ('CID','<H=0'),
        ('SequenceNumber','<H=0'),
    )

############# SMB_COM_QUERY_INFORMATION2 (0x23)
class SMBQueryInformation2_Parameters(Structure):
    structure = (
        ('Fid','<H'),
    )

class SMBQueryInformation2Response_Parameters(Structure):
    structure = (
        ('CreateDate','<H'),
        ('CreationTime','<H'),
        ('LastAccessDate','<H'),
        ('LastAccessTime','<H'),
        ('LastWriteDate','<H'),
        ('LastWriteTime','<H'),
        ('FileDataSize','<L'),
        ('FileAllocationSize','<L'),
        ('FileAttributes','<L'),
    )



############# SMB_COM_SESSION_SETUP_ANDX (0x73)
class SMBSessionSetupAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('MaxBuffer','<H'),
        ('MaxMpxCount','<H'),
        ('VCNumber','<H'),
        ('SessionKey','<L'),
        ('AnsiPwdLength','<H'),
        ('UnicodePwdLength','<H'),
        ('_reserved','<L=0'),
        ('Capabilities','<L'),
    )

class SMBSessionSetupAndX_Extended_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('MaxBufferSize','<H'),
        ('MaxMpxCount','<H'),
        ('VcNumber','<H'),
        ('SessionKey','<L'),
        ('SecurityBlobLength','<H'),
        ('Reserved','<L=0'),
        ('Capabilities','<L'),
    )

class SMBSessionSetupAndX_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('AnsiPwdLength','_-AnsiPwd','self["AnsiPwdLength"]'),
        ('UnicodePwdLength','_-UnicodePwd','self["UnicodePwdLength"]'),
        ('AnsiPwd',':=""'),
        ('UnicodePwd',':=""'),
        ('Account','z=""'),
        ('PrimaryDomain','z=""'),
        ('NativeOS','z=""'),
        ('NativeLanMan','z=""'),
    )
    
    UnicodeStructure = (
        ('AnsiPwdLength','_-AnsiPwd','self["AnsiPwdLength"]'),
        ('UnicodePwdLength','_-UnicodePwd','self["UnicodePwdLength"]'),
        ('AnsiPwd',':=""'),
        ('UnicodePwd',':=""'),
        ('Account','w=""'),
        ('PrimaryDomain','w=""'),
        ('NativeOS','w=""'),
        ('NativeLanMan','w=""'),
    )

class SMBSessionSetupAndX_Extended_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('SecurityBlobLength','_-SecurityBlob','self["SecurityBlobLength"]'),
        ('SecurityBlob',':'),
        ('NativeOS','z=""'),
        ('NativeLanMan','z=""'),
    )

    UnicodeStructure = (
        ('SecurityBlobLength','_-SecurityBlob','self["SecurityBlobLength"]'),
        ('SecurityBlob',':'),
        ('NativeOS','w=""'),
        ('NativeLanMan','w=""'),
    )

class SMBSessionSetupAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Action','<H'),
    )

class SMBSessionSetupAndX_Extended_Response_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Action','<H=0'),
        ('SecurityBlobLength','<H'),
    )

class SMBSessionSetupAndXResponse_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('NativeOS','z=""'),
        ('NativeLanMan','z=""'),
        ('PrimaryDomain','z=""'),
    )

    UnicodeStructure = (
        ('NativeOS','w=""'),
        ('NativeLanMan','w=""'),
        ('PrimaryDomain','w=""'),
    )

class SMBSessionSetupAndX_Extended_Response_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('SecurityBlobLength','_-SecurityBlob','self["SecurityBlobLength"]'),
        ('SecurityBlob',':'),
        ('NativeOS','z=""'),
        ('NativeLanMan','z=""'),
    )

    UnicodeStructure = (
        ('SecurityBlobLength','_-SecurityBlob','self["SecurityBlobLength"]'),
        ('SecurityBlob',':'),
        ('NativeOS','w=""'),
        ('NativeLanMan','w=""'),
    )

############# SMB_COM_TREE_CONNECT (0x70)
class SMBTreeConnect_Parameters(SMBCommand_Parameters):
    structure = (
    )

class SMBTreeConnect_Data(SMBCommand_Parameters):
    structure = (
        ('PathFormat','"\x04'),
        ('Path','z'),
        ('PasswordFormat','"\x04'),
        ('Password','z'),
        ('ServiceFormat','"\x04'),
        ('Service','z'),
    )

############# SMB_COM_TREE_CONNECT (0x75)
class SMBTreeConnectAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Flags','<H=0'),
        ('PasswordLength','<H'),
    )

class SMBTreeConnectAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('OptionalSupport','<H=0'),
    )

class SMBTreeConnectAndX_Data(Structure):
    structure = (
        ('_PasswordLength','_-Password','self["_PasswordLength"]'),
        ('Password',':'),
        ('Path','z'),
        ('Service','z'),
    )

class SMBTreeConnectAndXResponse_Data(Structure):
    structure = (
        ('Service','z'),
        ('PadLen','_-Pad','self["PadLen"]'),
        ('Pad',':=""'),
        ('NativeFileSystem','z'),
    )

############# SMB_COM_NT_CREATE_ANDX (0xA2)
class SMBNtCreateAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('_reserved', 'B=0'),
        ('FileNameLength','<H'),     # NameLength
        ('CreateFlags','<L'),        # Flags
        ('RootFid','<L=0'),          # RootDirectoryFID
        ('AccessMask','<L'),         # DesiredAccess
        ('AllocationSizeLo','<L=0'), # AllocationSize
        ('AllocationSizeHi','<L=0'),
        ('FileAttributes','<L=0'),   # ExtFileAttributes
        ('ShareAccess','<L=3'),      # 
        ('Disposition','<L=1'),      # CreateDisposition
        ('CreateOptions','<L'),      # CreateOptions
        ('Impersonation','<L=2'),
        ('SecurityFlags','B=3'),
    )

class SMBNtCreateAndXResponse_Parameters(SMBAndXCommand_Parameters):
    # XXX Is there a memory leak in the response for NTCreate (where the Data section would be) in Win 2000, Win XP, and Win 2003?
    structure = (
        ('OplockLevel', 'B=0'),
        ('Fid','<H'),
        ('CreateAction','<L'),
        ('CreateTime','<q=0'),
        ('LastAccessTime','<q=0'),
        ('LastWriteTime','<q=0'),
        ('LastChangeTime','<q=0'),
        ('FileAttributes','<L=0x80'),
        ('AllocationSize','<q=0'),
        ('EndOfFile','<q=0'),
        ('FileType','<H=0'),
        ('IPCState','<H=0'),
        ('IsDirectory','B'),
    )

class SMBNtCreateAndX_Data(Structure):
    structure = (
        ('FileName','z'),
    )

############# SMB_COM_OPEN_ANDX (0xD2)
class SMBOpenAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Flags','<H=0'),
        ('DesiredAccess','<H=0'),
        ('SearchAttributes','<H=0'),
        ('FileAttributes','<H=0'),
        ('CreationTime','<L=0'),
        ('OpenMode','<H=1'),        # SMB_O_OPEN = 1
        ('AllocationSize','<L=0'),
        ('Reserved','8s=""'),
    )

class SMBOpenAndX_Data(SMBNtCreateAndX_Data):
    pass

class SMBOpenAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H=0'),
        ('FileAttributes','<H=0'),
        ('LastWriten','<L=0'),
        ('FileSize','<L=0'),
        ('GrantedAccess','<H=0'),
        ('FileType','<H=0'),
        ('IPCState','<H=0'),
        ('Action','<H=0'),
        ('ServerFid','<L=0'),
        ('_reserved','<H=0'),
    )

############# SMB_COM_WRITE (0x0B)
class SMBWrite_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Count','<H'),
        ('Offset','<L'),
        ('Remaining','<H'),
    )

class SMBWriteResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('Count','<H'),
    )

class SMBWrite_Data(Structure):
    structure = (
        ('BufferFormat','<B=1'),
        ('DataLength','<H-Data'),
        ('Data',':'),
    )

    
############# SMB_COM_WRITE_ANDX (0x2F)
class SMBWriteAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('_reserved','<L=0xff'),
        ('WriteMode','<H=8'),
        ('Remaining','<H'),
        ('DataLength_Hi','<H=0'),
        ('DataLength','<H'),
        ('DataOffset','<H=0'),
        ('HighOffset','<L=0'),
    )

class SMBWriteAndX_Data(Structure):
     structure = (
         ('Pad','<B=0'),
         ('DataLength','_-Data','self["DataLength"]'),
         ('Data',':'),
     )
    
class SMBWriteAndX_Parameters2(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('_reserved','<L=0xff'),
        ('WriteMode','<H=8'),
        ('Remaining','<H'),
        ('DataLength_Hi','<H=0'),
        ('DataLength','<H'),
        ('DataOffset','<H=0'),
    )
    
class SMBWriteAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Count','<H'),
        ('Available','<H'),
        ('Reserved','<L=0'),
    )

############# SMB_COM_WRITE_RAW (0x1D)
class SMBWriteRaw_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Count','<H'),
        ('_reserved','<H=0'),
        ('Offset','<L'),
        ('Timeout','<L=0'),
        ('WriteMode','<H=0'),
        ('_reserved2','<L=0'),
        ('DataLength','<H'),
        ('DataOffset','<H=0'),
    )
    
############# SMB_COM_READ (0x0A)
class SMBRead_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Count','<H'),
        ('Offset','<L'),
        ('Remaining','<H=Count'),
    )

class SMBReadResponse_Parameters(Structure):
    structure = (
        ('Count','<H=0'),
        ('_reserved','"\0\0\0\0\0\0\0\0'),
    )

class SMBReadResponse_Data(Structure):
    structure = (
        ('BufferFormat','<B=0x1'),
        ('DataLength','<H-Data'),
        ('Data',':'),
    )

############# SMB_COM_READ_RAW (0x1A)
class SMBReadRaw_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('MaxCount','<H'),
        ('MinCount','<H=MaxCount'),
        ('Timeout','<L=0'),
        ('_reserved','<H=0'),
    )

############# SMB_COM_NT_TRANSACT  (0xA0)
class SMBNTTransaction_Parameters(SMBCommand_Parameters):
    structure = (
        ('MaxSetupCount','<B=0'),
        ('Reserved1','<H=0'),
        ('TotalParameterCount','<L'),
        ('TotalDataCount','<L'),
        ('MaxParameterCount','<L=1024'),
        ('MaxDataCount','<L=65504'),
        ('ParameterCount','<L'),
        ('ParameterOffset','<L'),
        ('DataCount','<L'),
        ('DataOffset','<L'),
        ('SetupCount','<B=len(Setup)/2'),
        ('Function','<H=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
    )

class SMBNTTransactionResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('Reserved1','"\0\0\0'),
        ('TotalParameterCount','<L'),
        ('TotalDataCount','<L'),
        ('ParameterCount','<L'),
        ('ParameterOffset','<L'),
        ('ParameterDisplacement','<L=0'),
        ('DataCount','<L'),
        ('DataOffset','<L'),
        ('DataDisplacement','<L=0'),
        ('SetupCount','<B=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
    )

class SMBNTTransaction_Data(Structure):
    structure = (
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('NT_Trans_ParametersLength','_-NT_Trans_Parameters','self["NT_Trans_ParametersLength"]'),
        ('NT_Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('NT_Trans_DataLength','_-NT_Trans_Data','self["NT_Trans_DataLength"]'),
        ('NT_Trans_Data',':'),
    )

class SMBNTTransactionResponse_Data(Structure):
    structure = (
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('Trans_ParametersLength','_-Trans_Parameters','self["Trans_ParametersLength"]'),
        ('Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('Trans_DataLength','_-Trans_Data','self["Trans_DataLength"]'),
        ('Trans_Data',':'),
    )


############# SMB_COM_TRANSACTION2_SECONDARY (0x33)
class SMBTransaction2Secondary_Parameters(SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H'),
        ('ParameterOffset','<H'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('FID','<H'),
    )

class SMBTransaction2Secondary_Data(Structure):
    structure = (
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('Trans_ParametersLength','_-Trans_Parameters','self["Trans_ParametersLength"]'),
        ('Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('Trans_DataLength','_-Trans_Data','self["Trans_DataLength"]'),
        ('Trans_Data',':'),
    )


############# SMB_COM_TRANSACTION2 (0x32)

class SMBTransaction2_Parameters(SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H'),
        ('TotalDataCount','<H'),
        ('MaxParameterCount','<H=1024'),
        ('MaxDataCount','<H=65504'),
        ('MaxSetupCount','<B=0'),
        ('Reserved1','<B=0'),
        ('Flags','<H=0'),
        ('Timeout','<L=0'),
        ('Reserved2','<H=0'),
        ('ParameterCount','<H'),
        ('ParameterOffset','<H'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('SetupCount','<B=len(Setup)/2'),
        ('Reserved3','<B=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
    )

class SMBTransaction2Response_Parameters(SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H'),
        ('TotalDataCount','<H'),
        ('Reserved1','<H=0'),
        ('ParameterCount','<H'),
        ('ParameterOffset','<H'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('SetupCount','<B=0'),
        ('Reserved2','<B=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
    )

class SMBTransaction2_Data(Structure):
    structure = (
#        ('NameLength','_-Name','1'),
#        ('Name',':'),
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('Trans_ParametersLength','_-Trans_Parameters','self["Trans_ParametersLength"]'),
        ('Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('Trans_DataLength','_-Trans_Data','self["Trans_DataLength"]'),
        ('Trans_Data',':'),
    )

class SMBTransaction2Response_Data(Structure):
    structure = (
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('Trans_ParametersLength','_-Trans_Parameters','self["Trans_ParametersLength"]'),
        ('Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('Trans_DataLength','_-Trans_Data','self["Trans_DataLength"]'),
        ('Trans_Data',':'),
    )

############# SMB_COM_QUERY_INFORMATION (0x08)

class SMBQueryInformation_Data(Structure):
    structure = (
        ('BufferFormat','B=4'),
        ('FileName','z'),
    )


class SMBQueryInformationResponse_Parameters(Structure):
    structure = (
        ('FileAttributes','<H'),
        ('LastWriteTime','<L'),
        ('FileSize','<L'),
        ('Reserved','"0123456789'),
    )

############# SMB_COM_TRANSACTION (0x25)
class SMBTransaction_Parameters(SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H'),
        ('TotalDataCount','<H'),
        ('MaxParameterCount','<H=1024'),
        ('MaxDataCount','<H=65504'),
        ('MaxSetupCount','<B=0'),
        ('Reserved1','<B=0'),
        ('Flags','<H=0'),
        ('Timeout','<L=0'),
        ('Reserved2','<H=0'),
        ('ParameterCount','<H'),
        ('ParameterOffset','<H'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('SetupCount','<B=len(Setup)/2'),
        ('Reserved3','<B=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
    )

class SMBTransactionResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H'),
        ('TotalDataCount','<H'),
        ('Reserved1','<H=0'),
        ('ParameterCount','<H'),
        ('ParameterOffset','<H'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('SetupCount','<B'),
        ('Reserved2','<B=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
    )

# TODO: We should merge these both. But this will require fixing 
# the instances where this structure is used on the client side
class SMBTransaction_SData(Structure):
    structure = (
        ('Name','z'),
        ('Trans_ParametersLength','_-Trans_Parameters'),
        ('Trans_Parameters',':'),
        ('Trans_DataLength','_-Trans_Data'),
        ('Trans_Data',':'),
    )

class SMBTransaction_Data(Structure):
    structure = (
        ('NameLength','_-Name'),
        ('Name',':'),
        ('Trans_ParametersLength','_-Trans_Parameters'),
        ('Trans_Parameters',':'),
        ('Trans_DataLength','_-Trans_Data'),
        ('Trans_Data',':'),
    )

class SMBTransactionResponse_Data(Structure):
    structure = (
        ('Trans_ParametersLength','_-Trans_Parameters'),
        ('Trans_Parameters',':'),
        ('Trans_DataLength','_-Trans_Data'),
        ('Trans_Data',':'),
    )

############# SMB_COM_READ_ANDX (0x2E)
class SMBReadAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('MaxCount','<H'),
        ('MinCount','<H=MaxCount'),
        ('_reserved','<L=0xffffffff'),
        ('Remaining','<H=MaxCount'),
        ('HighOffset','<L=0'),
    )

class SMBReadAndX_Parameters2(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('MaxCount','<H'),
        ('MinCount','<H=MaxCount'),
        ('_reserved','<L=0xffffffff'),
        ('Remaining','<H=MaxCount'),
    )

class SMBReadAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Remaining','<H=0'),
        ('DataMode','<H=0'),
        ('_reserved','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataCount_Hi','<L'),
        ('_reserved2','"\0\0\0\0\0\0'),
    )

############# SMB_COM_ECHO (0x2B)
class SMBEcho_Data(Structure):
    structure = (
        ('Data',':'),
    )

class SMBEcho_Parameters(Structure):
    structure = (
        ('EchoCount','<H'),
    )

class SMBEchoResponse_Data(Structure):
    structure = (
        ('Data',':'),
    )

class SMBEchoResponse_Parameters(Structure):
    structure = (
        ('SequenceNumber','<H=1'),
    )

############# SMB_COM_QUERY_INFORMATION_DISK (0x80)
class SMBQueryInformationDiskResponse_Parameters(Structure):
    structure = (
        ('TotalUnits','<H'),
        ('BlocksPerUnit','<H'),
        ('BlockSize','<H'),
        ('FreeUnits','<H'),
        ('Reserved','<H=0'),
    )


############# SMB_COM_LOGOFF_ANDX (0x74)
class SMBLogOffAndX(SMBAndXCommand_Parameters):
    strucure = ()

############# SMB_COM_CLOSE (0x04)
class SMBClose_Parameters(SMBCommand_Parameters):
   structure = (
        ('FID','<H'),
        ('Time','<L=0'),
   )

############# SMB_COM_CREATE_DIRECTORY (0x00)
class SMBCreateDirectory_Data(Structure):
    structure = (
        ('BufferFormat','<B=4'),
        ('DirectoryName','z'),
    )

############# SMB_COM_DELETE (0x06)
class SMBDelete_Data(Structure):
    structure = (
        ('BufferFormat','<B=4'),
        ('FileName','z'),
    )

class SMBDelete_Parameters(Structure):
    structure = (
        ('SearchAttributes','<H'),
    )

############# SMB_COM_DELETE_DIRECTORY (0x01)
class SMBDeleteDirectory_Data(Structure):
    structure = (
        ('BufferFormat','<B=4'),
        ('DirectoryName','z'),
    )

############# SMB_COM_RENAME (0x07)
class SMBRename_Parameters(SMBCommand_Parameters):
    structure = (
        ('SearchAttributes','<H'),
    )

class SMBRename_Data(Structure):
    structure = (
        ('BufferFormat1','<B=4'),
        ('OldFileName','z'),
        ('BufferFormat2','<B=4'),
        ('NewFileName','z'),
    )


############# SMB_COM_OPEN (0x02)
class SMBOpen_Parameters(SMBCommand_Parameters):
    structure = (
        ('DesiredAccess','<H=0'),
        ('SearchAttributes','<H=0'),
    )

class SMBOpen_Data(Structure):
    structure = (
        ('FileNameFormat','"\x04'),
        ('FileName','z'),
    )

class SMBOpenResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H=0'),
        ('FileAttributes','<H=0'),
        ('LastWriten','<L=0'),
        ('FileSize','<L=0'),
        ('GrantedAccess','<H=0'),
    )

############# EXTENDED SECURITY CLASSES
class SMBExtended_Security_Parameters(Structure):
    structure = (
        ('DialectIndex','<H'),
        ('SecurityMode','<B'),
        ('MaxMpxCount','<H'),
        ('MaxNumberVcs','<H'),
        ('MaxBufferSize','<L'),
        ('MaxRawSize','<L'),
        ('SessionKey','<L'),
        ('Capabilities','<L'),
        ('LowDateTime','<L'),
        ('HighDateTime','<L'),
        ('ServerTimeZone','<H'),
        ('ChallengeLength','<B'),
    )

class SMBExtended_Security_Data(Structure):
    structure = (
        ('ServerGUID','16s'),
        ('SecurityBlob',':'),
    )

class SMBNTLMDialect_Parameters(Structure):
    structure = (
        ('DialectIndex','<H'),
        ('SecurityMode','<B'),
        ('MaxMpxCount','<H'),
        ('MaxNumberVcs','<H'),
        ('MaxBufferSize','<L'),
        ('MaxRawSize','<L'),
        ('SessionKey','<L'),
        ('Capabilities','<L'),
        ('LowDateTime','<L'),
        ('HighDateTime','<L'),
        ('ServerTimeZone','<H'),
        ('ChallengeLength','<B'),
    )

class SMBNTLMDialect_Data(Structure):
    structure = (
        ('ChallengeLength','_-Challenge','self["ChallengeLength"]'),
        ('Challenge',':'),
        ('Payload',':'),
# For some reason on an old Linux this field is not present, we have to check this out. There must be a flag stating this.
        ('DomainName','_'),
        ('ServerName','_'),
    )
    def __init__(self,data = None, alignment = 0):
         Structure.__init__(self,data,alignment)
         #self['ChallengeLength']=8
         
    def fromString(self,data):
        Structure.fromString(self,data)
        if len(self['Payload']) > 0:
           if self['Payload'][1] == '\x00':
           # TODO: Ugly hack, should be taken of once mechListMIC is parsed in SPNEGO
               # We might have server's info
               data = self['Payload']
               length = data.index('\x00\x00')+1
               self['DomainName'] = data[:length].decode('utf-16le')
               data = data[length:]
               if len(data) > 3:
                  #We might have Server's Name
                  data = data[2:]
                  length = data.index('\x00\x00')+1
                  self['ServerName'] = data[:length].decode('utf-16le')
        else:
           self['DomainName'] = '' 
           self['ServerName'] = ''
           
class SMB:
    # SMB Command Codes
    SMB_COM_CREATE_DIRECTORY                = 0x00
    SMB_COM_DELETE_DIRECTORY                = 0x01
    SMB_COM_OPEN                            = 0x02
    SMB_COM_CREATE                          = 0x03
    SMB_COM_CLOSE                           = 0x04
    SMB_COM_FLUSH                           = 0x05
    SMB_COM_DELETE                          = 0x06
    SMB_COM_RENAME                          = 0x07
    SMB_COM_QUERY_INFORMATION               = 0x08
    SMB_COM_SET_INFORMATION                 = 0x09
    SMB_COM_READ                            = 0x0A
    SMB_COM_WRITE                           = 0x0B
    SMB_COM_LOCK_BYTE_RANGE                 = 0x0C
    SMB_COM_UNLOCK_BYTE_RANGE               = 0x0D
    SMB_COM_CREATE_TEMPORARY                = 0x0E
    SMB_COM_CREATE_NEW                      = 0x0F
    SMB_COM_CHECK_DIRECTORY                 = 0x10
    SMB_COM_PROCESS_EXIT                    = 0x11
    SMB_COM_SEEK                            = 0x12
    SMB_COM_LOCK_AND_READ                   = 0x13
    SMB_COM_WRITE_AND_UNLOCK                = 0x14
    SMB_COM_READ_RAW                        = 0x1A
    SMB_COM_READ_MPX                        = 0x1B
    SMB_COM_READ_MPX_SECONDARY              = 0x1C
    SMB_COM_WRITE_RAW                       = 0x1D
    SMB_COM_WRITE_MPX                       = 0x1E
    SMB_COM_WRITE_MPX_SECONDARY             = 0x1F
    SMB_COM_WRITE_COMPLETE                  = 0x20
    SMB_COM_QUERY_SERVER                    = 0x21
    SMB_COM_SET_INFORMATION2                = 0x22
    SMB_COM_QUERY_INFORMATION2              = 0x23
    SMB_COM_LOCKING_ANDX                    = 0x24
    SMB_COM_TRANSACTION                     = 0x25
    SMB_COM_TRANSACTION_SECONDARY           = 0x26
    SMB_COM_IOCTL                           = 0x27
    SMB_COM_IOCTL_SECONDARY                 = 0x28
    SMB_COM_COPY                            = 0x29
    SMB_COM_MOVE                            = 0x2A
    SMB_COM_ECHO                            = 0x2B
    SMB_COM_WRITE_AND_CLOSE                 = 0x2C
    SMB_COM_OPEN_ANDX                       = 0x2D
    SMB_COM_READ_ANDX                       = 0x2E
    SMB_COM_WRITE_ANDX                      = 0x2F
    SMB_COM_NEW_FILE_SIZE                   = 0x30
    SMB_COM_CLOSE_AND_TREE_DISC             = 0x31
    SMB_COM_TRANSACTION2                    = 0x32
    SMB_COM_TRANSACTION2_SECONDARY          = 0x33
    SMB_COM_FIND_CLOSE2                     = 0x34
    SMB_COM_FIND_NOTIFY_CLOSE               = 0x35
    # Used by Xenix/Unix 0x60 - 0x6E 
    SMB_COM_TREE_CONNECT                    = 0x70
    SMB_COM_TREE_DISCONNECT                 = 0x71
    SMB_COM_NEGOTIATE                       = 0x72
    SMB_COM_SESSION_SETUP_ANDX              = 0x73
    SMB_COM_LOGOFF_ANDX                     = 0x74
    SMB_COM_TREE_CONNECT_ANDX               = 0x75
    SMB_COM_QUERY_INFORMATION_DISK          = 0x80
    SMB_COM_SEARCH                          = 0x81
    SMB_COM_FIND                            = 0x82
    SMB_COM_FIND_UNIQUE                     = 0x83
    SMB_COM_FIND_CLOSE                      = 0x84
    SMB_COM_NT_TRANSACT                     = 0xA0
    SMB_COM_NT_TRANSACT_SECONDARY           = 0xA1
    SMB_COM_NT_CREATE_ANDX                  = 0xA2
    SMB_COM_NT_CANCEL                       = 0xA4
    SMB_COM_NT_RENAME                       = 0xA5
    SMB_COM_OPEN_PRINT_FILE                 = 0xC0
    SMB_COM_WRITE_PRINT_FILE                = 0xC1
    SMB_COM_CLOSE_PRINT_FILE                = 0xC2
    SMB_COM_GET_PRINT_QUEUE                 = 0xC3
    SMB_COM_READ_BULK                       = 0xD8
    SMB_COM_WRITE_BULK                      = 0xD9
    SMB_COM_WRITE_BULK_DATA                 = 0xDA

    # TRANSACT2 codes
    TRANS2_FIND_FIRST2                      = 0x0001
    TRANS2_FIND_NEXT2                       = 0x0002
    TRANS2_QUERY_FS_INFORMATION             = 0x0003
    TRANS2_QUERY_PATH_INFORMATION           = 0x0005
    TRANS2_QUERY_FILE_INFORMATION           = 0x0007
    TRANS2_SET_FILE_INFORMATION             = 0x0008
    TRANS2_SET_PATH_INFORMATION             = 0x0006

    # Security Share Mode (Used internally by SMB class)
    SECURITY_SHARE_MASK                     = 0x01
    SECURITY_SHARE_SHARE                    = 0x00
    SECURITY_SHARE_USER                     = 0x01
    SECURITY_SIGNATURES_ENABLED             = 0X04
    SECURITY_SIGNATURES_REQUIRED            = 0X08
    
    # Security Auth Mode (Used internally by SMB class)
    SECURITY_AUTH_MASK                      = 0x02
    SECURITY_AUTH_ENCRYPTED                 = 0x02
    SECURITY_AUTH_PLAINTEXT                 = 0x00

    # Raw Mode Mask (Used internally by SMB class. Good for dialect up to and including LANMAN2.1)
    RAW_READ_MASK                           = 0x01
    RAW_WRITE_MASK                          = 0x02

    # Capabilities Mask (Used internally by SMB class. Good for dialect NT LM 0.12)
    CAP_RAW_MODE                            = 0x00000001
    CAP_MPX_MODE                            = 0x0002
    CAP_UNICODE                             = 0x0004
    CAP_LARGE_FILES                         = 0x0008
    CAP_EXTENDED_SECURITY                   = 0x80000000
    CAP_USE_NT_ERRORS                       = 0x40
    CAP_NT_SMBS                             = 0x10

    # Flags1 Mask
    FLAGS1_LOCK_AND_READ_OK                 = 0x01
    FLAGS1_PATHCASELESS                     = 0x08
    FLAGS1_REPLY                            = 0x80

    # Flags2 Mask
    FLAGS2_LONG_NAMES                       = 0x0001
    FLAGS2_EAS                              = 0x0002
    FLAGS2_SMB_SECURITY_SIGNATURE           = 0x0004
    FLAGS2_IS_LONG_NAME                     = 0x0040
    FLAGS2_DFS                              = 0x1000
    FLAGS2_PAGING_IO                        = 0x2000
    FLAGS2_NT_STATUS                        = 0x4000
    FLAGS2_UNICODE                          = 0x8000
    FLAGS2_COMPRESSED                       = 0x0008
    FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED  = 0x0010
    FLAGS2_EXTENDED_SECURITY                = 0x0800
    
    # Dialect's Security Mode flags
    NEGOTIATE_USER_SECURITY                 = 0x01
    NEGOTIATE_ENCRYPT_PASSWORDS             = 0x02
    NEGOTIATE_SECURITY_SIGNATURE_ENABLE     = 0x04
    NEGOTIATE_SECURITY_SIGNATURE_REQUIRED   = 0x08

    # Tree Connect AndX Response optionalSuppor flags
    SMB_SUPPORT_SEARCH_BITS                 = 0x01
    SMB_SHARE_IS_IN_DFS                     = 0x02 



    def __init__(self, remote_name, remote_host, my_name = None, host_type = nmb.TYPE_SERVER, sess_port = nmb.NETBIOS_SESSION_PORT, timeout=None, UDP = 0):
        # The uid attribute will be set when the client calls the login() method
        self._uid = 0
        self.__server_name = ''
        self.__server_os = ''
        self.__server_lanman = ''
        self.__server_domain = ''
        self.__remote_name = string.upper(remote_name)
        self.__remote_host = remote_host
        self.__is_pathcaseless = 0
        # Negotiate Protocol Result, used everywhere
        # Could be extended or not, flags should be checked before 
        self._dialect_data = 0
        self._dialect_parameters = 0
        self._action = 0
        self._sess = None
        self.encrypt_passwords = True
        self.tid = 0
        self.fid = 0
        
        # Signing stuff
        self._SignSequenceNumber = 0
        self._SigningSessionKey = ''
        self._SigningChallengeResponse = ''
        self._SignatureEnabled = False
        self._SignatureVerificationEnabled = False
        self._SignatureRequired = False

        if timeout==None:
            self.__timeout = 5
        else:
            self.__timeout = timeout
        
        if not my_name:
            my_name = socket.gethostname()
            i = string.find(my_name, '.')
            if i > -1:
                my_name = my_name[:i]

        # If port 445 and the name sent is *SMBSERVER we're setting the name to the IP. This is to help some old applications still believing 
        # *SMSBSERVER will work against modern OSes. If port is NETBIOS_SESSION_PORT the user better know about *SMBSERVER's limitations
        if sess_port == 445 and remote_name == '*SMBSERVER':
           self.__remote_name = remote_host

        if UDP:
            self._sess = nmb.NetBIOSUDPSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)
        else:
            self._sess = nmb.NetBIOSTCPSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)

            # Initialize session values (_dialect_data and _dialect_parameters)
            self.neg_session()

            # Call login() without any authentication information to 
            # setup a session if the remote server
            # is in share mode.
            if (self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SHARE_MASK) == SMB.SECURITY_SHARE_SHARE:
                self.login('', '')

    def ntlm_supported(self):
        return False

    def get_remote_name(self):
        return self.__remote_name
    
    def get_remote_host(self):
        return self.__remote_host

    def set_timeout(self, timeout):
        self.__timeout = timeout

    def get_session(self):        
        return self._sess
    
    def get_tid(self):
        return self.tid

    def get_fid(self):
        return self.fid
   
    def isGuestSession(self):
        return self._action & SMB_SETUP_GUEST 

    def __del__(self):
        if self._sess:
            self._sess.close()

    def recvSMB(self):
        r = self._sess.recv_packet(self.__timeout)
        return NewSMBPacket(data = r.get_trailer())
    
    def recv_packet(self):
        r = self._sess.recv_packet(self.__timeout)
        return SMBPacket(r.get_trailer())
    
    def __decode_trans(self, params, data):
        totparamcnt, totdatacnt, _, paramcnt, paramoffset, paramds, datacnt, dataoffset, datads, setupcnt = unpack('<HHHHHHHHHB', params[:19])
        if paramcnt + paramds < totparamcnt or datacnt + datads < totdatacnt:
            has_more = 1
        else:
            has_more = 0
        paramoffset = paramoffset - 55 - setupcnt * 2
        dataoffset = dataoffset - 55 - setupcnt * 2
        return has_more, params[20:20 + setupcnt * 2], data[paramoffset:paramoffset + paramcnt], data[dataoffset:dataoffset + datacnt]

    # TODO: Move this to NewSMBPacket, it belongs there
    def signSMB(self, packet, signingSessionKey, signingChallengeResponse):
        # This logic MUST be applied for messages sent in response to any of the higher-layer actions and in
        # compliance with the message sequencing rules.
        #  * The client or server that sends the message MUST provide the 32-bit sequence number for this
        #    message, as specified in sections 3.2.4.1 and 3.3.4.1.
        #  * The SMB_FLAGS2_SMB_SECURITY_SIGNATURE flag in the header MUST be set.
        #  * To generate the signature, a 32-bit sequence number is copied into the 
        #    least significant 32 bits of the SecuritySignature field and the remaining 
        #    4 bytes are set to 0x00.
        #  * The MD5 algorithm, as specified in [RFC1321], MUST be used to generate a hash of the SMB
        #    message from the start of the SMB Header, which is defined as follows.
        #    CALL MD5Init( md5context )
        #    CALL MD5Update( md5context, Connection.SigningSessionKey )
        #    CALL MD5Update( md5context, Connection.SigningChallengeResponse )
        #    CALL MD5Update( md5context, SMB message )
        #    CALL MD5Final( digest, md5context )
        #    SET signature TO the first 8 bytes of the digest
        # The resulting 8-byte signature MUST be copied into the SecuritySignature field of the SMB Header,
        # after which the message can be transmitted.

        #print "seq(%d) signingSessionKey %r, signingChallengeResponse %r" % (self._SignSequenceNumber, signingSessionKey, signingChallengeResponse)
        packet['SecurityFeatures'] = struct.pack('<q',self._SignSequenceNumber)
        # Sign with the sequence
        m = hashlib.md5()
        m.update( signingSessionKey )
        m.update( signingChallengeResponse )
        m.update( str(packet) )
        # Replace sequence with acual hash
        dd = m.digest()[:8]
        #packet['SecurityFeatures'] = m.digest()[:8]
        packet['SecurityFeatures'] = dd
        if self._SignatureVerificationEnabled:
           self._SignSequenceNumber +=1
        else:
           self._SignSequenceNumber +=2


    def checkSignSMB(self, packet, signingSessionKey, signingChallengeResponse):
        # Let's check
        signature = packet['SecurityFeatures']
        #print "Signature received: %r " % signature
        self.signSMB(packet, signingSessionKey, signingChallengeResponse) 
        #print "Signature calculated: %r" % packet['SecurityFeatures']
        if self._SignatureVerificationEnabled is not True:
           self._SignSequenceNumber -= 1
        return packet['SecurityFeatures'] == signature
         
    def sendSMB(self,smb):
        smb['Uid'] = self._uid
        smb['Pid'] = os.getpid()
        if self._SignatureEnabled:
            smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
            self.signSMB(smb, self._SigningSessionKey, self._SigningChallengeResponse)
        self._sess.send_packet(str(smb))

    # Should be gone soon. Not used anymore within the library. DON'T use it!
    # Use sendSMB instead (and build the packet with NewSMBPacket)
    def send_smb(self,s):
        s.set_uid(self._uid)
        s.set_pid(os.getpid())
        self._sess.send_packet(s.rawData())

    def __send_smb_packet(self, cmd, flags, flags2, tid, mid, params = '', data = ''):
        smb = NewSMBPacket()
        smb['Flags1'] = flags
        smb['Flags2'] = flags2
        smb['Tid'] = tid
        smb['Mid'] = mid
        cmd = SMBCommand(cmd)
        smb.addCommand(cmd)

        cmd['Parameters'] = params
        cmd['Data'] = data
        self.sendSMB(smb)

    def isValidAnswer(self, s, cmd):
        while 1:
            if s.rawData():
                if s.get_command() == cmd:
                    if s.get_error_class() == 0x00 and s.get_error_code() == 0x00:
                        return 1
                    else:
                        raise SessionError, ( "SMB Library Error", s.get_error_class(), s.get_error_code())
                else:
                    break
        return 0

    def neg_session(self, extended_security = True):
        smb = NewSMBPacket()
        negSession = SMBCommand(SMB.SMB_COM_NEGOTIATE)
        if extended_security == True:
            smb['Flags2']=SMB.FLAGS2_EXTENDED_SECURITY
        negSession['Data'] = '\x02NT LM 0.12\x00'
        smb.addCommand(negSession)
        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_NEGOTIATE):
                sessionResponse = SMBCommand(smb['Data'][0])
                self._dialects_parameters = SMBNTLMDialect_Parameters(sessionResponse['Parameters'])
                self._dialects_data = SMBNTLMDialect_Data()
                self._dialects_data['ChallengeLength'] = self._dialects_parameters['ChallengeLength']
                self._dialects_data.fromString(sessionResponse['Data'])
                if self._dialects_parameters['Capabilities'] & SMB.CAP_EXTENDED_SECURITY:
                    # Whether we choose it or it is enforced by the server, we go for extended security
                    self._dialects_parameters = SMBExtended_Security_Parameters(sessionResponse['Parameters'])
                    self._dialects_data = SMBExtended_Security_Data(sessionResponse['Data'])
                    # Let's setup some variable for later use
                    if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
                         self._SignatureRequired = True

                    # Interestingly, the security Blob might be missing sometimes.
                    #spnego = SPNEGO_NegTokenInit(self._dialects_data['SecurityBlob'])
                    #for i in spnego['MechTypes']:
                    #      print "Mech Found: %s" % MechTypes[i]
                    return 1

                # If not, let's try the old way
                else:
                    self.__server_name = self._dialects_data['ServerName']
                    if self._dialects_parameters['DialectIndex'] == 0xffff:
                        raise UnsupportedFeature,"Remote server does not know NT LM 0.12"
                    self.__is_pathcaseless = smb['Flags1'] & SMB.FLAGS1_PATHCASELESS
                    return 1
            else:
                return 0

    def tree_connect(self, path, password = '', service = SERVICE_ANY):
        # return 0x800
        if password:
            # Password is only encrypted if the server passed us an "encryption" during protocol dialect
            if self._dialects_parameters['ChallengeLength'] > 0:
                # this code is untested
                password = self.get_ntlmv1_response(ntlm.compute_lmhash(password))

        if not unicode_support:
            if unicode_convert:
                path = str(path)
            else:
                raise Exception('SMB: Can\t conver path from unicode!')

        smb = NewSMBPacket()
        smb['Flags1']  = 8
        
        treeConnect = SMBCommand(SMB.SMB_COM_TREE_CONNECT)
        treeConnect['Parameters'] = SMBTreeConnect_Parameters()
        treeConnect['Data']       = SMBTreeConnect_Data()
        treeConnect['Data']['Path'] = path.upper()
        treeConnect['Data']['Password'] = password
        treeConnect['Data']['Service'] = service

        smb.addCommand(treeConnect)

        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_TREE_CONNECT):
                # XXX Here we are ignoring the rest of the response
                return smb['Tid']
            return smb['Tid']

    def get_uid(self):
        return self._uid

    def set_uid(self, uid):
        self._uid = uid

    def tree_connect_andx(self, path, password = None, service = SERVICE_ANY, smb_packet=None):
        if password:
            # Password is only encrypted if the server passed us an "encryption" during protocol dialect
            if self._dialects_parameters['ChallengeLength'] > 0:
                # this code is untested
                password = self.get_ntlmv1_response(ntlm.compute_lmhash(password))
        else:
            password = '\x00'

        if not unicode_support:
            if unicode_convert:
                path = str(path)
            else:
                raise Exception('SMB: Can\t convert path from unicode!')

        if smb_packet == None:
            smb = NewSMBPacket()
            smb['Flags1']  = 8
        else:
            smb = smb_packet
        
        treeConnect = SMBCommand(SMB.SMB_COM_TREE_CONNECT_ANDX)
        treeConnect['Parameters'] = SMBTreeConnectAndX_Parameters()
        treeConnect['Data']       = SMBTreeConnectAndX_Data()
        treeConnect['Parameters']['PasswordLength'] = len(password)
        treeConnect['Data']['Password'] = password
        treeConnect['Data']['Path'] = path.upper()
        treeConnect['Data']['Service'] = service

        smb.addCommand(treeConnect)

        # filename = "\PIPE\epmapper"

        # ntCreate = SMBCommand(SMB.SMB_COM_NT_CREATE_ANDX)
        # ntCreate['Parameters'] = SMBNtCreateAndX_Parameters()
        # ntCreate['Data']       = SMBNtCreateAndX_Data()
        # ntCreate['Parameters']['FileNameLength'] = len(filename)
        # ntCreate['Parameters']['CreateFlags'] = 0
        # ntCreate['Parameters']['AccessMask'] = 0x3
        # ntCreate['Parameters']['CreateOptions'] = 0x0
        # ntCreate['Data']['FileName'] = filename

        # smb.addCommand(ntCreate)
        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_TREE_CONNECT_ANDX):
                # XXX Here we are ignoring the rest of the response
                self.tid = smb['Tid']
                return self.tid
            self.tid = smb['Tid']
            return self.tid

    # backwars compatibility
    connect_tree = tree_connect_andx

    def get_server_name(self):
        #return self._dialects_data['ServerName']
        return self.__server_name

    def get_session_key(self):
        return self._dialects_parameters['SessionKey']

    def get_encryption_key(self):
        if self._dialects_data.fields.has_key('Challenge'):
            return self._dialects_data['Challenge']
        else:
            return None

    def get_server_time(self):
        timestamp = self._dialects_parameters['HighDateTime']
        timestamp <<= 32
        timestamp |= self._dialects_parameters['LowDateTime']
        timestamp -= 116444736000000000
        timestamp /= 10000000
        d = datetime.datetime.utcfromtimestamp(timestamp)
        return d.strftime("%a, %d %b %Y %H:%M:%S GMT")

    def disconnect_tree(self, tid):
        smb = NewSMBPacket()
        smb['Tid']  = tid
        smb.addCommand(SMBCommand(SMB.SMB_COM_TREE_DISCONNECT))
        self.sendSMB(smb)

        smb = self.recvSMB()

    def open(self, tid, filename, open_mode, desired_access):
        smb = NewSMBPacket()
        smb['Flags1']  = 8
        smb['Flags2'] = SMB.FLAGS2_LONG_NAMES
        smb['Tid']    = tid

        openFile = SMBCommand(SMB.SMB_COM_OPEN)
        openFile['Parameters'] = SMBOpen_Parameters()
        openFile['Parameters']['DesiredAccess']    = desired_access
        openFile['Parameters']['OpenMode']         = open_mode
        openFile['Parameters']['SearchAttributes'] = ATTR_READONLY | ATTR_HIDDEN | ATTR_ARCHIVE
        openFile['Data']       = SMBOpen_Data()
        openFile['Data']['FileName'] = filename
        
        smb.addCommand(openFile)

        self.sendSMB(smb)
        
        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_OPEN):
            # XXX Here we are ignoring the rest of the response
            openFileResponse   = SMBCommand(smb['Data'][0])
            openFileParameters = SMBOpenResponse_Parameters(openFileResponse['Parameters'])

            return (
                openFileParameters['Fid'],
                openFileParameters['FileAttributes'],
                openFileParameters['LastWriten'],
                openFileParameters['FileSize'],
                openFileParameters['GrantedAccess'],
            )
        
    def open_andx(self, tid, filename, open_mode, desired_access):
        smb = NewSMBPacket()
        smb['Flags1']  = 8
        smb['Flags2'] = SMB.FLAGS2_LONG_NAMES
        smb['Tid']    = tid

        openFile = SMBCommand(SMB.SMB_COM_OPEN_ANDX)
        openFile['Parameters'] = SMBOpenAndX_Parameters()
        openFile['Parameters']['DesiredAccess']    = desired_access
        openFile['Parameters']['OpenMode']         = open_mode
        openFile['Parameters']['SearchAttributes'] = ATTR_READONLY | ATTR_HIDDEN | ATTR_ARCHIVE
        openFile['Data']       = SMBOpenAndX_Data()
        openFile['Data']['FileName'] = filename
        
        smb.addCommand(openFile)

        self.sendSMB(smb)
        
        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_OPEN_ANDX):
            # XXX Here we are ignoring the rest of the response
            openFileResponse   = SMBCommand(smb['Data'][0])
            openFileParameters = SMBOpenAndXResponse_Parameters(openFileResponse['Parameters'])

            return (
                openFileParameters['Fid'],
                openFileParameters['FileAttributes'],
                openFileParameters['LastWriten'],
                openFileParameters['FileSize'],
                openFileParameters['GrantedAccess'],
                openFileParameters['FileType'],
                openFileParameters['IPCState'],
                openFileParameters['Action'],
                openFileParameters['ServerFid'],
            )
        
    def close(self, tid, fid):
        smb = NewSMBPacket()
        smb['Flags1']  = 8
        smb['Flags2'] = SMB.FLAGS2_LONG_NAMES
        smb['Tid']    = tid

        closeFile = SMBCommand(SMB.SMB_COM_CLOSE)
        closeFile['Parameters'] = SMBClose_Parameters()
        closeFile['Parameters']['FID']    = fid
        smb.addCommand(closeFile)

        self.sendSMB(smb)
        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_CLOSE):
           return 1
        return 0

    def send_trans(self, tid, setup, name, param, data, noAnswer = 0):
        smb = NewSMBPacket()
        smb['Flags1']  = 8
        smb['Flags2'] = SMB.FLAGS2_LONG_NAMES
        smb['Tid']    = tid

        transCommand = SMBCommand(SMB.SMB_COM_TRANSACTION)
        transCommand['Parameters'] = SMBTransaction_Parameters()
        transCommand['Data'] = SMBTransaction_Data()

        transCommand['Parameters']['Setup'] = setup
        transCommand['Parameters']['TotalParameterCount'] = len(param) 
        transCommand['Parameters']['TotalDataCount'] = len(data)

        transCommand['Parameters']['ParameterCount'] = len(param)
        transCommand['Parameters']['ParameterOffset'] = 32+3+28+len(setup)+len(name)

        transCommand['Parameters']['DataCount'] = len(data)
        transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param)

        transCommand['Data']['Name'] = name
        transCommand['Data']['Trans_Parameters'] = param
        transCommand['Data']['Trans_Data'] = data

        if noAnswer:
           transCommand['Parameters']['Flags'] = TRANS_NO_RESPONSE
      
        smb.addCommand(transCommand)
        self.sendSMB(smb)

    def trans2(self, tid, setup, name, param, data):
        data_len = len(data)
        name_len = len(name)
        param_len = len(param)
        setup_len = len(setup)

        assert setup_len & 0x01 == 0

        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
            
        self.__send_smb_packet(SMB.SMB_COM_TRANSACTION2, self.__is_pathcaseless, SMB.FLAGS2_LONG_NAMES, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, self._dialects_parameters['MaxBufferSize'], 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name  + param + data)

    def query_file_info(self, tid, fid):
        self.trans2(tid, '\x07\x00', '\x00', pack('<HH', fid, 0x107), '')

        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION2):
                f1, f2 = unpack('<LL', s.get_buffer()[53:53+8])
                return (f2 & 0xffffffffL) << 32 | f1

    def __nonraw_retr_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self._dialects_parameters['MaxBufferSize'] & ~0x3ff  # Read in multiple KB blocks
        read_offset = offset
        while read_offset < datasize:
            data = self.read_andx(tid, fid, read_offset, max_buf_size)

            callback(data)
            read_offset += len(data)

    def __raw_retr_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self._dialects_parameters['MaxBufferSize'] & ~0x3ff  # Write in multiple KB blocks
        read_offset = offset
        while read_offset < datasize:
            data = self.read_raw(tid, fid, read_offset, 0xffff)
            if not data:
                # No data returned. Need to send SMB_COM_READ_ANDX to find out what is the error.
                data = self.read_andx(tid, fid, read_offset, max_buf_size)

            callback(data)
            read_offset += len(data)

    def __nonraw_stor_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self._dialects_parameters['MaxBufferSize'] & ~0x3ff  # Write in multiple KB blocks
        write_offset = offset
        while 1:
            data = callback(max_buf_size)
            if not data:
                break

            smb = self.write_andx(tid,fid,data, write_offset)
            writeResponse   = SMBCommand(smb['Data'][0])
            writeResponseParameters = SMBWriteAndXResponse_Parameters(writeResponse['Parameters'])
            write_offset += writeResponseParameters['Count']

    def __raw_stor_file(self, tid, fid, offset, datasize, callback):
        write_offset = offset
        while 1:
            read_data = callback(self._dialects_parameters['MaxRawSize'])
            if not read_data:
                break
            read_len = len(read_data)
            self.__send_smb_packet(SMB.SMB_COM_WRITE_RAW, 0, 0, tid, 0, pack('<HHHLLHLHH', fid, read_len, 0, write_offset, 0, 0, 0, 0, 59), '')
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_WRITE_RAW):
                    self._sess.send_packet(read_data)
                    write_offset = write_offset + read_len
                    break

    def get_server_domain(self):
        return self.__server_domain

    def get_server_os(self):
        return self.__server_os

    def set_server_os(self, os):
        self.__server_os = os

    def get_server_lanman(self):
        return self.__server_lanman

    def is_login_required(self):
        # Login is required if share mode is user. 
        # Otherwise only public services or services in share mode
        # are allowed.
        return (self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SHARE_MASK) == SMB.SECURITY_SHARE_USER

    def get_ntlmv1_response(self, key):
        challenge = self._dialects_data['Challenge']
        return ntlm.get_ntlmv1_response(key, challenge)

    def login_extended(self, user, password, domain = '', lmhash = '', nthash = '' ):
        # Once everything's working we should join login methods into a single one
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY 
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired: 
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
          

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit() 

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1('',domain,self._SignatureRequired)
        blob['MechToken'] = str(auth)
        
        sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob']       = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash)

            #ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])

            if exportedSessionKey is not None: 
                self._SigningSessionKey = exportedSessionKey

            smb = NewSMBPacket()
            smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
            smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY #| SMB.FLAGS2_NT_STATUS

            # Are we required to sign SMB? If so we do it, if not we skip it
            if self._SignatureRequired: 
               smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = str(type3)

            # Reusing the previous structure
            sessionSetup['Parameters']['SecurityBlobLength'] = len(respToken2)
            sessionSetup['Data']['SecurityBlob'] = respToken2.getData()

            smb.addCommand(sessionSetup)
            self.sendSMB(smb)
            
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
                sessionResponse   = SMBCommand(smb['Data'][0])
                sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
                sessionData       = SMBSessionSetupAndXResponse_Data(flags = smb['Flags2'], data = sessionResponse['Data'])

                self._action = sessionParameters['Action']
                # If smb sign required, let's enable it for the rest of the connection
                if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
                   self._SignSequenceNumber = 2
                   self._SignatureEnabled = True

                # Let's parse some data and keep it to ourselves in case it is asked

                ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
                if ntlmChallenge['TargetInfoFields_len'] > 0:
                    infoFields = ntlmChallenge['TargetInfoFields']
                    av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']]) 
                    if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                       self.__server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1]

                

                self.__server_os     = sessionData['NativeOS']
                self.__server_lanman = sessionData['NativeLanMan']
                self.__server_domain = sessionData['PrimaryDomain']

                return 1
        else:
            raise Exception('Error: Could not login successfully')

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):

        # If we have hashes, normalize them
        if ( lmhash != '' or nthash != ''):
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            lmhash = a2b_hex(lmhash)
            nthash = a2b_hex(nthash)

        if self._dialects_parameters['Capabilities'] & SMB.CAP_EXTENDED_SECURITY:
            self.login_extended(user, password, domain, lmhash, nthash)
        else:
            self.login_standard(user, password, domain, lmhash, nthash)

    def login_standard(self, user, password, domain = '', lmhash = '', nthash = ''):
        # Only supports NTLMv1
        # Password is only encrypted if the server passed us an "encryption key" during protocol dialect negotiation
        if self._dialects_parameters['ChallengeLength'] > 0:
            if lmhash != '' or nthash != '':
               pwd_ansi = self.get_ntlmv1_response(lmhash)
               pwd_unicode = self.get_ntlmv1_response(nthash)
            elif password: 
               lmhash = ntlm.compute_lmhash(password)
               nthash = ntlm.compute_nthash(password)
               pwd_ansi = self.get_ntlmv1_response(lmhash)
               pwd_unicode = self.get_ntlmv1_response(nthash)
            else: # NULL SESSION
               pwd_ansi = ''
               pwd_unicode = ''
        else:
            pwd_ansi = password
            pwd_unicode = ''

        smb = NewSMBPacket()
        smb['Flags1']  = 8
        
        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Data()

        sessionSetup['Parameters']['MaxBuffer']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']      = 2
        sessionSetup['Parameters']['VCNumber']         = os.getpid()
        sessionSetup['Parameters']['SessionKey']       = self._dialects_parameters['SessionKey']
        sessionSetup['Parameters']['AnsiPwdLength']    = len(pwd_ansi)
        sessionSetup['Parameters']['UnicodePwdLength'] = len(pwd_unicode)
        sessionSetup['Parameters']['Capabilities']     = SMB.CAP_RAW_MODE

        sessionSetup['Data']['AnsiPwd']       = pwd_ansi
        sessionSetup['Data']['UnicodePwd']    = pwd_unicode
        sessionSetup['Data']['Account']       = str(user)
        sessionSetup['Data']['PrimaryDomain'] = str(domain)
        sessionSetup['Data']['NativeOS']      = str(os.name)
        sessionSetup['Data']['NativeLanMan']  = 'pysmb'

        smb.addCommand(sessionSetup)

        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndXResponse_Data(flags = smb['Flags2'], data = sessionResponse['Data'])

            self._action = sessionParameters['Action']

            # Still gotta figure out how to do this with no EXTENDED_SECURITY
            if sessionParameters['Action'] & SMB_SETUP_USE_LANMAN_KEY == 0:
                 self._SigningChallengeResponse = sessionSetup['Data']['UnicodePwd'] 
                 self._SigningSessionKey = nthash
            else:
                 self._SigningChallengeResponse = sessionSetup['Data']['AnsiPwd'] 
                 self._SigningSessionKey = lmhash

            #self._SignSequenceNumber = 1
            #self.checkSignSMB(smb, self._SigningSessionKey ,self._SigningChallengeResponse)
            #self._SignatureEnabled = True
            self.__server_os     = sessionData['NativeOS']
            self.__server_lanman = sessionData['NativeLanMan']
            self.__server_domain = sessionData['PrimaryDomain']

            return 1
        else: raise Exception('Error: Could not login successfully')

    def read(self, tid, fid, offset=0, max_size = None, wait_answer=1):
        if not max_size:
            max_size = self._dialects_parameters['MaxBufferSize'] # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        read = SMBCommand(SMB.SMB_COM_READ)
        
        read['Parameters'] = SMBRead_Parameters()
        read['Parameters']['Fid'] = fid
        read['Parameters']['Offset'] = offset
        read['Parameters']['Count'] = max_size

        smb.addCommand(read)

        if wait_answer:
            answer = ''
            while 1:
                self.sendSMB(smb)
                ans = self.recvSMB()

                if ans.isValidAnswer(SMB.SMB_COM_READ):
                    readResponse   = SMBCommand(ans['Data'][0])
                    readParameters = SMBReadResponse_Parameters(readResponse['Parameters'])
                    readData       = SMBReadResponse_Data(readResponse['Data'])

                    return readData['Data']

        return None

    def read_andx(self, tid, fid, offset=0, max_size = None, wait_answer=1, smb_packet=None):
        if not max_size:
            max_size = self._dialects_parameters['MaxBufferSize'] # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        if smb_packet == None:
            smb = NewSMBPacket()
            smb['Flags1'] = 0x18
            smb['Flags2'] = 0
            smb['Tid']    = tid

            readAndX = SMBCommand(SMB.SMB_COM_READ_ANDX)
            readAndX['Parameters'] = SMBReadAndX_Parameters()
            readAndX['Parameters']['Fid'] = fid
            readAndX['Parameters']['Offset'] = offset
            readAndX['Parameters']['MaxCount'] = max_size

            smb.addCommand(readAndX)
        else:
            smb = smb_packet


        if wait_answer:
            answer = ''
            while 1:
                self.sendSMB(smb)
                ans = self.recvSMB()

                if ans.isValidAnswer(SMB.SMB_COM_READ_ANDX):
                    # XXX Here we are only using a few fields from the response
                    readAndXResponse   = SMBCommand(ans['Data'][0])
                    readAndXParameters = SMBReadAndXResponse_Parameters(readAndXResponse['Parameters'])

                    offset = readAndXParameters['DataOffset']
                    count = readAndXParameters['DataCount']+0x10000*readAndXParameters['DataCount_Hi']
                    answer += str(ans)[offset:offset+count]
                    if not ans.isMoreData():
                        return answer
                    max_size = min(max_size, readAndXParameters['Remaining'])
                    readAndX['Parameters']['Offset'] += count                      # XXX Offset is not important (apparently)
        else:
            self.sendSMB(smb)
            ans = self.recvSMB()

            try:
                if ans.isValidAnswer(SMB.SMB_COM_READ_ANDX):
                    return ans
                else:
                    return None
            except:
                return ans

        return None

    def read_raw(self, tid, fid, offset=0, max_size = None, wait_answer=1):
        if not max_size:
            max_size = self._dialects_parameters['MaxBufferSize'] # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        readRaw = SMBCommand(SMB.SMB_COM_READ_RAW)
        
        readRaw['Parameters'] = SMBReadRaw_Parameters()
        readRaw['Parameters']['Fid'] = fid
        readRaw['Parameters']['Offset'] = offset
        readRaw['Parameters']['MaxCount'] = max_size

        smb.addCommand(readRaw)

        self.sendSMB(smb)
        if wait_answer:
            data = self._sess.recv_packet(self.__timeout).get_trailer()
            if not data:
                # If there is no data it means there was an error
                data = self.read_andx(tid, fid, offset, max_size)
            return data

        return None

    def write(self,tid,fid,data, offset = 0, wait_answer=1):
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        write = SMBCommand(SMB.SMB_COM_WRITE)
        smb.addCommand(write)
        
        write['Parameters'] = SMBWrite_Parameters()
        write['Data'] = SMBWrite_Data()
        write['Parameters']['Fid'] = fid
        write['Parameters']['Count'] = len(data)
        write['Parameters']['Offset'] = offset
        write['Parameters']['Remaining'] = len(data)
        write['Data']['Data'] = data

        self.sendSMB(smb)
                
        if wait_answer:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_WRITE):
                return smb
        return None

    def write_andx(self,tid,fid,data, offset = 0, wait_answer=1, smb_packet=None):
        if smb_packet == None:
            smb = NewSMBPacket()
            smb['Flags1'] = 0x18
            smb['Flags2'] = 0
            smb['Tid']    = tid

            writeAndX = SMBCommand(SMB.SMB_COM_WRITE_ANDX)
            smb.addCommand(writeAndX)
        
            writeAndX['Parameters'] = SMBWriteAndX_Parameters()
            writeAndX['Parameters']['Fid'] = fid
            writeAndX['Parameters']['Offset'] = offset
            writeAndX['Parameters']['WriteMode'] = 8
            writeAndX['Parameters']['Remaining'] = len(data)
            writeAndX['Parameters']['DataLength'] = len(data)
            writeAndX['Parameters']['DataOffset'] = len(smb)    # this length already includes the parameter
            writeAndX['Data'] = data
        else:
            smb = smb_packet

        self.sendSMB(smb)
                
        if wait_answer:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_WRITE_ANDX):
                return smb
        return None

    def write_raw(self,tid,fid,data, offset = 0, wait_answer=1):
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        writeRaw = SMBCommand(SMB.SMB_COM_WRITE_RAW)
        smb.addCommand(writeRaw)
        
        writeRaw['Parameters'] = SMBWriteRaw_Parameters()
        writeRaw['Parameters']['Fid'] = fid
        writeRaw['Parameters']['Offset'] = offset
        writeRaw['Parameters']['Count'] = len(data)
        writeRaw['Parameters']['DataLength'] = 0
        writeRaw['Parameters']['DataOffset'] = 0

        self.sendSMB(smb)
        self._sess.send_packet(data)
                
        if wait_answer:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_WRITE_RAW):
                return smb
        return None

    def TransactNamedPipe(self, tid, fid, data = '', noAnswer = 0, waitAnswer = 1, offset = 0):
        self.send_trans(tid,pack('<HH', 0x26, fid),'\\PIPE\\\x00','',data, noAnswer = noAnswer)

        if noAnswer or not waitAnswer:
            return
        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_TRANSACTION):
           transResponse = SMBCommand(smb['Data'][0])
           transParameters = SMBTransaction_Parameters(transResponse['Parameters'])
           return transResponse['Data'][-transParameters['TotalDataCount']:] # Remove Potential Prefix Padding

        return None

    def nt_create_andx(self,tid,filename, smb_packet=None, cmd = None):
        if smb_packet == None:
            smb = NewSMBPacket()
            smb['Flags1'] = 0x18
            smb['Flags2'] = SMB.FLAGS2_LONG_NAMES
            smb['Tid']    = tid
        else:
            smb = smb_packet
        
        if cmd == None:
            ntCreate = SMBCommand(SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = SMBNtCreateAndX_Parameters()
            ntCreate['Data']       = SMBNtCreateAndX_Data()
            ntCreate['Parameters']['FileNameLength'] = len(filename)
            ntCreate['Parameters']['CreateFlags'] = 0x16
            ntCreate['Parameters']['AccessMask'] = 0x2019f
            ntCreate['Parameters']['CreateOptions'] = 0x40
            ntCreate['Data']['FileName'] = filename
        else:
            ntCreate = cmd

        smb.addCommand(ntCreate)

        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_NT_CREATE_ANDX):
                # XXX Here we are ignoring the rest of the response
                ntCreateResponse   = SMBCommand(smb['Data'][0])
                ntCreateParameters = SMBNtCreateAndXResponse_Parameters(ntCreateResponse['Parameters'])

                self.fid = ntCreateParameters['Fid']
                return ntCreateParameters['Fid']

    def logoff(self):
        smb = NewSMBPacket()
        logOff = SMBCommand(SMB.SMB_COM_LOGOFF_ANDX)
        logOff['Parameters'] = SMBLogOffAndX()
        smb.addCommand(logOff)
        self.sendSMB(smb)

    def list_shared(self):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\IPC$')

        buf = StringIO()
        try:
            self.send_trans(tid, '', '\\PIPE\\LANMAN\0', '\x00\x00WrLeh\0B13BWz\0\x01\x00\xe0\xff', '')
            numentries = 0
            share_list = [ ]
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION):
                    has_more, _, transparam, transdata = self.__decode_trans(s.get_parameter_words(), s.get_buffer())
                    if not numentries:
                        status, data_offset, numentries = unpack('<HHH', transparam[:6])
                    buf.write(transdata)

                    if not has_more:
                        share_data = buf.getvalue()
                        offset = 0
                        for i in range(0, numentries):
                            name = share_data[offset:string.find(share_data, '\0', offset)]
                            type, commentoffset = unpack('<HH', share_data[offset + 14:offset + 18])
                            comment = share_data[commentoffset-data_offset:share_data.find('\0', commentoffset-data_offset)]
                            offset = offset + 20
                            share_list.append(SharedDevice(name, type, comment))
                        return share_list
        finally:
            buf.close()
            self.disconnect_tree(tid)

    def list_path(self, service, path = '*', password = None):
        path = string.replace(path, '/', '\\')

        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.trans2(tid, '\x01\x00', '\x00', '\x16\x00\x00\x02\x06\x00\x04\x01\x00\x00\x00\x00' + path + '\x00', '')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION2):
                    has_more, _, transparam, transdata = self.__decode_trans(s.get_parameter_words(), s.get_buffer())
                    sid, searchcnt, eos, erroffset, lastnameoffset = unpack('<HHHHH', transparam)
                    files = [ ]
                    offset = 0
                    data_len = len(transdata)
                    while offset < data_len:
                        nextentry, fileindex, lowct, highct, lowat, highat, lowmt, highmt, lowcht, hightcht, loweof, higheof, lowsz, highsz, attrib, longnamelen, easz, shortnamelen = unpack('<lL12LLlLB', transdata[offset:offset + 69])
                        files.append(SharedFile(highct << 32 | lowct, highat << 32 | lowat, highmt << 32 | lowmt, higheof << 32 | loweof, highsz << 32 | lowsz, attrib, transdata[offset + 70:offset + 70 + shortnamelen], transdata[offset + 94:offset + 94 + longnamelen]))
                        offset = offset + nextentry
                        if not nextentry:
                            break
                    return files
        finally:
            self.disconnect_tree(tid)

    def retr_file(self, service, filename, callback, mode = SMB_O_OPEN, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_andx(tid, filename, mode, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if not datasize:
                datasize = self.query_file_info(tid, fid)

            if self._dialects_parameters['Capabilities'] & SMB.CAP_RAW_MODE:
                self.__raw_retr_file(tid, fid, offset, datasize, callback)
            else:
                self.__nonraw_retr_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.close(tid, fid)
            self.disconnect_tree(tid)

    def stor_file(self, service, filename, callback, mode = SMB_O_CREAT | SMB_O_TRUNC, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_andx(tid, filename, mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)
            
            # If the max_transmit buffer size is more than 16KB, upload process using non-raw mode is actually
            # faster than using raw-mode.
            if self._dialects_parameters['MaxBufferSize'] < 16384 and self._dialects_parameters['Capabilities'] & SMB.CAP_RAW_MODE:
                # Once the __raw_stor_file returns, fid is already closed
                self.__raw_stor_file(tid, fid, offset, datasize, callback)
                fid = -1
            else:
                self.__nonraw_stor_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.close(tid, fid)
            self.disconnect_tree(tid)

    def stor_file_nonraw(self, service, filename, callback, mode = SMB_O_CREAT | SMB_O_TRUNC, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_andx(tid, filename, mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)
            self.__nonraw_stor_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.close(tid, fid)
            self.disconnect_tree(tid)

    def copy(self, src_service, src_path, dest_service, dest_path, callback = None, write_mode = SMB_O_CREAT | SMB_O_TRUNC, src_password = None, dest_password = None):
        dest_path = string.replace(dest_path, '/', '\\')
        src_path = string.replace(src_path, '/', '\\')
        src_tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + src_service, src_password)

        dest_tid = -1
        try:
            if src_service == dest_service:
                dest_tid = src_tid
            else:
                dest_tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + dest_service, dest_password)
            
            dest_fid = self.open_andx(dest_tid, dest_path, write_mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)[0]
            src_fid, _, _, src_datasize, _, _, _, _, _ = self.open_andx(src_tid, src_path, SMB_O_OPEN, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)
            if not src_datasize:
                src_datasize = self.query_file_info(src_tid, src_fid)

            if callback:
                callback(0, src_datasize)

            max_buf_size = (self._dialects_parameters['MaxBufferSize'] >> 10) << 10
            read_offset = 0
            write_offset = 0
            while read_offset < src_datasize:
                self.__send_smb_packet(SMB.SMB_COM_READ_ANDX, 0, 0, src_tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, src_fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
                while 1:
                    s = self.recv_packet()
                    if self.isValidAnswer(s,SMB.SMB_COM_READ_ANDX):
                        offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                        data_len, dataoffset = unpack('<HH', s.get_parameter_words()[10+offset:14+offset])
                        d = s.get_buffer()
                        if data_len == len(d):
                            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d)
                        else:
                            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d[dataoffset - 59:dataoffset - 59 + data_len])
                        while 1:
                            s = self.recv_packet()
                            if self.isValidAnswer(s,SMB.SMB_COM_WRITE_ANDX):
                                data_len, dataoffset = unpack('<HH', s.get_parameter_words()[4:8])
                                break
                        read_offset = read_offset + data_len
                        if callback:
                            callback(read_offset, src_datasize)
                        break
                
        finally:
            self.disconnect_tree(src_tid)
            if dest_tid > -1 and src_service != dest_service:
                self.disconnect_tree(dest_tid)

    def check_dir(self, service, path, password = None):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_CHECK_DIRECTORY, 0x08, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_CHECK_DIRECTORY):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def remove(self, service, path, password = None):
        # Perform a list to ensure the path exists
        self.list_path(service, path, password)

        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_DELETE, 0x08, 0, tid, 0, pack('<H', ATTR_HIDDEN | ATTR_SYSTEM | ATTR_ARCHIVE), '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_DELETE):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def rmdir(self, service, path, password = None):
        # Check that the directory exists
        self.check_dir(service, path, password)

        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_DELETE_DIRECTORY, 0x08, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_DELETE_DIRECTORY):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def mkdir(self, service, path, password = None):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            smb = NewSMBPacket()
            smb['Tid'] = tid
            createDir = SMBCommand(SMB.SMB_COM_CREATE_DIRECTORY)
            createDir['Data'] = SMBCreateDirectory_Data()
            createDir['Data']['DirectoryName'] = path
            smb.addCommand(createDir)
            self.sendSMB(smb)
        
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_CREATE_DIRECTORY):
                return 1
            return 0
        finally:
            self.disconnect_tree(smb['Tid'])

    def rename(self, service, old_path, new_path, password = None):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            smb = NewSMBPacket()
            smb['Tid'] = tid
            smb['Flags'] = SMB.FLAGS1_PATHCASELESS
            renameCmd = SMBCommand(SMB.SMB_COM_RENAME)
            renameCmd['Parameters'] = SMBRename_Parameters()
            renameCmd['Parameters']['SearchAttributes'] = ATTR_SYSTEM | ATTR_HIDDEN | ATTR_DIRECTORY 
            renameCmd['Data'] = SMBRename_Data()
            renameCmd['Data']['OldFileName'] = old_path
            renameCmd['Data']['NewFileName'] = new_path 

            smb.addCommand(renameCmd)
            self.sendSMB(smb)
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_RENAME):
               return 1
            return 0 
        finally:
            self.disconnect_tree(smb['Tid'])

    def get_socket(self):
        return self._sess.get_socket()

ERRDOS = { 1: 'Invalid function',
           2: 'File not found',
           3: 'Invalid directory',
           4: 'Too many open files',
           5: 'Access denied',
           6: 'Invalid file handle. Please file a bug report.',
           7: 'Memory control blocks destroyed',
           8: 'Out of memory',
           9: 'Invalid memory block address',
           10: 'Invalid environment',
           11: 'Invalid format',
           12: 'Invalid open mode',
           13: 'Invalid data',
           15: 'Invalid drive',
           16: 'Attempt to remove server\'s current directory',
           17: 'Not the same device',
           18: 'No files found',
           32: 'Sharing mode conflicts detected',
           33: 'Lock request conflicts detected',
           80: 'File already exists'
           }

ERRSRV = { 1: 'Non-specific error',
           2: 'Bad password',
           4: 'Access denied',
           5: 'Invalid tid. Please file a bug report.',
           6: 'Invalid network name',
           7: 'Invalid device',
           49: 'Print queue full',
           50: 'Print queue full',
           51: 'EOF on print queue dump',
           52: 'Invalid print file handle',
           64: 'Command not recognized. Please file a bug report.',
           65: 'Internal server error',
           67: 'Invalid path',
           69: 'Invalid access permissions',
           71: 'Invalid attribute mode',
           81: 'Server is paused',
           82: 'Not receiving messages',
           83: 'No room to buffer messages',
           87: 'Too many remote user names',
           88: 'Operation timeout',
           89: 'Out of resources',
           91: 'Invalid user handle. Please file a bug report.',
           250: 'Temporarily unable to support raw mode for transfer',
           251: 'Temporarily unable to support raw mode for transfer',
           252: 'Continue in MPX mode',
           65535: 'Unsupported function'
           }

ERRHRD = { 19: 'Media is write-protected',
           20: 'Unknown unit',
           21: 'Drive not ready',
           22: 'Unknown command',
           23: 'CRC error',
           24: 'Bad request',
           25: 'Seek error',
           26: 'Unknown media type',
           27: 'Sector not found',
           28: 'Printer out of paper',
           29: 'Write fault',
           30: 'Read fault',
           31: 'General failure',
           32: 'Open conflicts with an existing open',
           33: 'Invalid lock request',
           34: 'Wrong disk in drive',
           35: 'FCBs not available',
           36: 'Sharing buffer exceeded'
           }

