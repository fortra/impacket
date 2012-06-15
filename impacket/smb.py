# Copyright (c) 2003-2012 CORE Security Technologies)
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
# [ ] Implement TRANS/TRANS2 reassembly for list_path 

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
SHARED_DISK_HIDDEN               = 0x80000000
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
SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO = 0x105
SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO = 0x106


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

            # Do we have more data?
            if len(decode_data) == 0:
                return

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
      25: ("ERRseek", "Seek error."),
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
        0x0000: ("NT_STATUS_OK","The operation completed successfully."),
        0x0001: ("NT_STATUS_UNSUCCESSFUL","A device attached to the system is not functioning."),
        0x0002: ("NT_STATUS_NOT_IMPLEMENTED","Incorrect function."),
        0x0003: ("NT_STATUS_INVALID_INFO_CLASS","The parameter is incorrect."),
        0x0004: ("NT_STATUS_INFO_LENGTH_MISMATCH","The program issued a command but the command length is incorrect."),
        0x0005: ("NT_STATUS_ACCESS_VIOLATION","Invalid access to memory location."),
        0x0006: ("NT_STATUS_IN_PAGE_ERROR","Error performing inpage operation."),
        0x0007: ("NT_STATUS_PAGEFILE_QUOTA","Insufficient quota to complete the requested service."),
        0x0008: ("NT_STATUS_INVALID_HANDLE","The handle is invalid."),
        0x0009: ("NT_STATUS_BAD_INITIAL_STACK","Recursion too deep, stack overflowed."),
        0x000a: ("NT_STATUS_BAD_INITIAL_PC","Not a valid Windows NT application."),
        0x000b: ("NT_STATUS_INVALID_CID","The parameter is incorrect."),
        0x000c: ("NT_STATUS_TIMER_NOT_CANCELED","NT_STATUS_TIMER_NOT_CANCELED"),
        0x000d: ("NT_STATUS_INVALID_PARAMETER","The parameter is incorrect."),
        0x000e: ("NT_STATUS_NO_SUCH_DEVICE","The system cannot find the file specified."),
        0x000f: ("NT_STATUS_NO_SUCH_FILE","The system cannot find the file specified."),
        0x0010: ("NT_STATUS_INVALID_DEVICE_REQUEST","Incorrect function."),
        0x0011: ("NT_STATUS_END_OF_FILE","Reached end of file."),
        0x0012: ("NT_STATUS_WRONG_VOLUME","The wrong diskette is in the drive. Insert %2 (Volume Serial Number: %3) into drive %1."),
        0x0013: ("NT_STATUS_NO_MEDIA_IN_DEVICE","The device is not ready."),
        0x0014: ("NT_STATUS_UNRECOGNIZED_MEDIA","The disk media is not recognized. It may not be formatted."),
        0x0015: ("NT_STATUS_NONEXISTENT_SECTOR","The drive cannot find the sector requested."),
        0x0016: ("NT_STATUS_MORE_PROCESSING_REQUIRED","More data is available."),
        0x0017: ("NT_STATUS_NO_MEMORY","Not enough storage is available to process this command."),
        0x0018: ("NT_STATUS_CONFLICTING_ADDRESSES","Attempt to access invalid address."),
        0x0019: ("NT_STATUS_NOT_MAPPED_VIEW","Attempt to access invalid address."),
        0x001a: ("NT_STATUS_UNABLE_TO_FREE_VM","The parameter is incorrect."),
        0x001b: ("NT_STATUS_UNABLE_TO_DELETE_SECTION","The parameter is incorrect."),
        0x001c: ("NT_STATUS_INVALID_SYSTEM_SERVICE","Incorrect function."),
        0x001d: ("NT_STATUS_ILLEGAL_INSTRUCTION","NT_STATUS_ILLEGAL_INSTRUCTION"),
        0x001e: ("NT_STATUS_INVALID_LOCK_SEQUENCE","Access is denied."),
        0x001f: ("NT_STATUS_INVALID_VIEW_SIZE","Access is denied."),
        0x0020: ("NT_STATUS_INVALID_FILE_FOR_SECTION","Not a valid Windows NT application."),
        0x0021: ("NT_STATUS_ALREADY_COMMITTED","Access is denied."),
        0x0022: ("NT_STATUS_ACCESS_DENIED","Access is denied."),
        0x0023: ("NT_STATUS_BUFFER_TOO_SMALL","The data area passed to a system call is too small."),
        0x0024: ("NT_STATUS_OBJECT_TYPE_MISMATCH","The handle is invalid."),
        0x0025: ("NT_STATUS_NONCONTINUABLE_EXCEPTION","NT_STATUS_NONCONTINUABLE_EXCEPTION"),
        0x0026: ("NT_STATUS_INVALID_DISPOSITION","NT_STATUS_INVALID_DISPOSITION"),
        0x0027: ("NT_STATUS_UNWIND","NT_STATUS_UNWIND"),
        0x0028: ("NT_STATUS_BAD_STACK","NT_STATUS_BAD_STACK"),
        0x0029: ("NT_STATUS_INVALID_UNWIND_TARGET","NT_STATUS_INVALID_UNWIND_TARGET"),
        0x002a: ("NT_STATUS_NOT_LOCKED","The segment is already unlocked."),
        0x002b: ("NT_STATUS_PARITY_ERROR","NT_STATUS_PARITY_ERROR"),
        0x002c: ("NT_STATUS_UNABLE_TO_DECOMMIT_VM","Attempt to access invalid address."),
        0x002d: ("NT_STATUS_NOT_COMMITTED","Attempt to access invalid address."),
        0x002e: ("NT_STATUS_INVALID_PORT_ATTRIBUTES","NT_STATUS_INVALID_PORT_ATTRIBUTES"),
        0x002f: ("NT_STATUS_PORT_MESSAGE_TOO_LONG","NT_STATUS_PORT_MESSAGE_TOO_LONG"),
        0x0030: ("NT_STATUS_INVALID_PARAMETER_MIX","The parameter is incorrect."),
        0x0031: ("NT_STATUS_INVALID_QUOTA_LOWER","NT_STATUS_INVALID_QUOTA_LOWER"),
        0x0032: ("NT_STATUS_DISK_CORRUPT_ERROR","The disk structure is corrupt and non-readable."),
        0x0033: ("NT_STATUS_OBJECT_NAME_INVALID","The filename, directory name, or volume label syntax is incorrect."),
        0x0034: ("NT_STATUS_OBJECT_NAME_NOT_FOUND","The system cannot find the file specified."),
        0x0035: ("NT_STATUS_OBJECT_NAME_COLLISION","Cannot create a file when that file already exists."),
        0x0036: ("NT_STATUS_HANDLE_NOT_WAITABLE","NT_STATUS_HANDLE_NOT_WAITABLE"),
        0x0037: ("NT_STATUS_PORT_DISCONNECTED","The handle is invalid."),
        0x0038: ("NT_STATUS_DEVICE_ALREADY_ATTACHED","NT_STATUS_DEVICE_ALREADY_ATTACHED"),
        0x0039: ("NT_STATUS_OBJECT_PATH_INVALID","The specified path is invalid."),
        0x003a: ("NT_STATUS_OBJECT_PATH_NOT_FOUND","The system cannot find the path specified."),
        0x003b: ("NT_STATUS_OBJECT_PATH_SYNTAX_BAD","The specified path is invalid."),
        0x003c: ("NT_STATUS_DATA_OVERRUN","The request could not be performed because of an I/O device error."),
        0x003d: ("NT_STATUS_DATA_LATE_ERROR","The request could not be performed because of an I/O device error."),
        0x003e: ("NT_STATUS_DATA_ERROR","Data error (cyclic redundancy check)"),
        0x003f: ("NT_STATUS_CRC_ERROR","Data error (cyclic redundancy check)"),
        0x0040: ("NT_STATUS_SECTION_TOO_BIG","Not enough storage is available to process this command."),
        0x0041: ("NT_STATUS_PORT_CONNECTION_REFUSED","Access is denied."),
        0x0042: ("NT_STATUS_INVALID_PORT_HANDLE","The handle is invalid."),
        0x0043: ("NT_STATUS_SHARING_VIOLATION","The process cannot access the file because it is being used by another process."),
        0x0044: ("NT_STATUS_QUOTA_EXCEEDED","Not enough quota is available to process this command."),
        0x0045: ("NT_STATUS_INVALID_PAGE_PROTECTION","The parameter is incorrect."),
        0x0046: ("NT_STATUS_MUTANT_NOT_OWNED","Attempt to release mutex not owned by caller."),
        0x0047: ("NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED","Too many posts were made to a semaphore."),
        0x0048: ("NT_STATUS_PORT_ALREADY_SET","The parameter is incorrect."),
        0x0049: ("NT_STATUS_SECTION_NOT_IMAGE","The parameter is incorrect."),
        0x004a: ("NT_STATUS_SUSPEND_COUNT_EXCEEDED","The recipient process has refused the signal."),
        0x004b: ("NT_STATUS_THREAD_IS_TERMINATING","Access is denied."),
        0x004c: ("NT_STATUS_BAD_WORKING_SET_LIMIT","The parameter is incorrect."),
        0x004d: ("NT_STATUS_INCOMPATIBLE_FILE_MAP","The parameter is incorrect."),
        0x004e: ("NT_STATUS_SECTION_PROTECTION","The parameter is incorrect."),
        0x004f: ("NT_STATUS_EAS_NOT_SUPPORTED","NT_STATUS_EAS_NOT_SUPPORTED"),
        0x0050: ("NT_STATUS_EA_TOO_LARGE","The extended attributes are inconsistent."),
        0x0051: ("NT_STATUS_NONEXISTENT_EA_ENTRY","The file or directory is corrupt and non-readable."),
        0x0052: ("NT_STATUS_NO_EAS_ON_FILE","The file or directory is corrupt and non-readable."),
        0x0053: ("NT_STATUS_EA_CORRUPT_ERROR","The file or directory is corrupt and non-readable."),
        0x0054: ("NT_STATUS_FILE_LOCK_CONFLICT","The process cannot access the file because another process has locked a portion of the file."),
        0x0055: ("NT_STATUS_LOCK_NOT_GRANTED","The process cannot access the file because another process has locked a portion of the file."),
        0x0056: ("NT_STATUS_DELETE_PENDING","Access is denied."),
        0x0057: ("NT_STATUS_CTL_FILE_NOT_SUPPORTED","The network request is not supported."),
        0x0058: ("NT_STATUS_UNKNOWN_REVISION","The revision level is unknown."),
        0x0059: ("NT_STATUS_REVISION_MISMATCH","Indicates two revision levels are incompatible."),
        0x005a: ("NT_STATUS_INVALID_OWNER","This security ID may not be assigned as the owner of this object."),
        0x005b: ("NT_STATUS_INVALID_PRIMARY_GROUP","This security ID may not be assigned as the primary group of an object."),
        0x005c: ("NT_STATUS_NO_IMPERSONATION_TOKEN","An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client."),
        0x005d: ("NT_STATUS_CANT_DISABLE_MANDATORY","The group may not be disabled."),
        0x005e: ("NT_STATUS_NO_LOGON_SERVERS","There are currently no logon servers available to service the logon request."),
        0x005f: ("NT_STATUS_NO_SUCH_LOGON_SESSION","A specified logon session does not exist. It may already have been terminated."),
        0x0060: ("NT_STATUS_NO_SUCH_PRIVILEGE","A specified privilege does not exist."),
        0x0061: ("NT_STATUS_PRIVILEGE_NOT_HELD","A required privilege is not held by the client."),
        0x0062: ("NT_STATUS_INVALID_ACCOUNT_NAME","The name provided is not a properly formed account name."),
        0x0063: ("NT_STATUS_USER_EXISTS","The specified user already exists."),
        0x0064: ("NT_STATUS_NO_SUCH_USER","The specified user does not exist."),
        0x0065: ("NT_STATUS_GROUP_EXISTS","The specified group already exists."),
        0x0066: ("NT_STATUS_NO_SUCH_GROUP","The specified group does not exist."),
        0x0067: ("NT_STATUS_MEMBER_IN_GROUP","Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member."),
        0x0068: ("NT_STATUS_MEMBER_NOT_IN_GROUP","The specified user account is not a member of the specified group account."),
        0x0069: ("NT_STATUS_LAST_ADMIN","The last remaining administration account cannot be disabled or deleted."),
        0x006a: ("NT_STATUS_WRONG_PASSWORD","The specified network password is not correct."),
        0x006b: ("NT_STATUS_ILL_FORMED_PASSWORD","Unable to update the password. The value provided for the new password contains values that are not allowed in passwords."),
        0x006c: ("NT_STATUS_PASSWORD_RESTRICTION","Unable to update the password because a password update rule has been violated."),
        0x006d: ("NT_STATUS_LOGON_FAILURE","Logon failure: unknown user name or bad password."),
        0x006e: ("NT_STATUS_ACCOUNT_RESTRICTION","Logon failure: user account restriction."),
        0x006f: ("NT_STATUS_INVALID_LOGON_HOURS","Logon failure: account logon time restriction violation."),
        0x0070: ("NT_STATUS_INVALID_WORKSTATION","Logon failure: user not allowed to log on to this computer."),
        0x0071: ("NT_STATUS_PASSWORD_EXPIRED","Logon failure: the specified account password has expired."),
        0x0072: ("NT_STATUS_ACCOUNT_DISABLED","Logon failure: account currently disabled."),
        0x0073: ("NT_STATUS_NONE_MAPPED","No mapping between account names and security IDs was done."),
        0x0074: ("NT_STATUS_TOO_MANY_LUIDS_REQUESTED","Too many local user identifiers (LUIDs) were requested at one time."),
        0x0075: ("NT_STATUS_LUIDS_EXHAUSTED","No more local user identifiers (LUIDs) are available."),
        0x0076: ("NT_STATUS_INVALID_SUB_AUTHORITY","The subauthority part of a security ID is invalid for this particular use."),
        0x0077: ("NT_STATUS_INVALID_ACL","The access control list (ACL) structure is invalid."),
        0x0078: ("NT_STATUS_INVALID_SID","The security ID structure is invalid."),
        0x0079: ("NT_STATUS_INVALID_SECURITY_DESCR","The security descriptor structure is invalid."),
        0x007a: ("NT_STATUS_PROCEDURE_NOT_FOUND","The specified procedure could not be found."),
        0x007b: ("NT_STATUS_INVALID_IMAGE_FORMAT","%1 is not a valid Windows NT application."),
        0x007c: ("NT_STATUS_NO_TOKEN","An attempt was made to reference a token that does not exist."),
        0x007d: ("NT_STATUS_BAD_INHERITANCE_ACL","The inherited access control list (ACL) or access control entry (ACE) could not be built."),
        0x007e: ("NT_STATUS_RANGE_NOT_LOCKED","The segment is already unlocked."),
        0x007f: ("NT_STATUS_DISK_FULL","There is not enough space on the disk."),
        0x0080: ("NT_STATUS_SERVER_DISABLED","The server is currently disabled."),
        0x0081: ("NT_STATUS_SERVER_NOT_DISABLED","The server is currently enabled."),
        0x0082: ("NT_STATUS_TOO_MANY_GUIDS_REQUESTED","The name limit for the local computer network adapter card was exceeded."),
        0x0083: ("NT_STATUS_GUIDS_EXHAUSTED","No more data is available."),
        0x0084: ("NT_STATUS_INVALID_ID_AUTHORITY","The value provided was an invalid value for an identifier authority."),
        0x0085: ("NT_STATUS_AGENTS_EXHAUSTED","No more data is available."),
        0x0086: ("NT_STATUS_INVALID_VOLUME_LABEL","The volume label you entered exceeds the label character limit of the target file system."),
        0x0087: ("NT_STATUS_SECTION_NOT_EXTENDED","Not enough storage is available to complete this operation."),
        0x0088: ("NT_STATUS_NOT_MAPPED_DATA","Attempt to access invalid address."),
        0x0089: ("NT_STATUS_RESOURCE_DATA_NOT_FOUND","The specified image file did not contain a resource section."),
        0x008a: ("NT_STATUS_RESOURCE_TYPE_NOT_FOUND","The specified resource type can not be found in the image file."),
        0x008b: ("NT_STATUS_RESOURCE_NAME_NOT_FOUND","The specified resource name can not be found in the image file."),
        0x008c: ("NT_STATUS_ARRAY_BOUNDS_EXCEEDED","NT_STATUS_ARRAY_BOUNDS_EXCEEDED"),
        0x008d: ("NT_STATUS_FLOAT_DENORMAL_OPERAND","NT_STATUS_FLOAT_DENORMAL_OPERAND"),
        0x008e: ("NT_STATUS_FLOAT_DIVIDE_BY_ZERO","NT_STATUS_FLOAT_DIVIDE_BY_ZERO"),
        0x008f: ("NT_STATUS_FLOAT_INEXACT_RESULT","NT_STATUS_FLOAT_INEXACT_RESULT"),
        0x0090: ("NT_STATUS_FLOAT_INVALID_OPERATION","NT_STATUS_FLOAT_INVALID_OPERATION"),
        0x0091: ("NT_STATUS_FLOAT_OVERFLOW","NT_STATUS_FLOAT_OVERFLOW"),
        0x0092: ("NT_STATUS_FLOAT_STACK_CHECK","NT_STATUS_FLOAT_STACK_CHECK"),
        0x0093: ("NT_STATUS_FLOAT_UNDERFLOW","NT_STATUS_FLOAT_UNDERFLOW"),
        0x0094: ("NT_STATUS_INTEGER_DIVIDE_BY_ZERO","NT_STATUS_INTEGER_DIVIDE_BY_ZERO"),
        0x0095: ("NT_STATUS_INTEGER_OVERFLOW","Arithmetic result exceeded 32 bits."),
        0x0096: ("NT_STATUS_PRIVILEGED_INSTRUCTION","NT_STATUS_PRIVILEGED_INSTRUCTION"),
        0x0097: ("NT_STATUS_TOO_MANY_PAGING_FILES","Not enough storage is available to process this command."),
        0x0098: ("NT_STATUS_FILE_INVALID","The volume for a file has been externally altered such that the opened file is no longer valid."),
        0x0099: ("NT_STATUS_ALLOTTED_SPACE_EXCEEDED","No more memory is available for security information updates."),
        0x009a: ("NT_STATUS_INSUFFICIENT_RESOURCES","Insufficient system resources exist to complete the requested service."),
        0x009b: ("NT_STATUS_DFS_EXIT_PATH_FOUND","The system cannot find the path specified."),
        0x009c: ("NT_STATUS_DEVICE_DATA_ERROR","Data error (cyclic redundancy check)"),
        0x009d: ("NT_STATUS_DEVICE_NOT_CONNECTED","The device is not ready."),
        0x009e: ("NT_STATUS_DEVICE_POWER_FAILURE","The device is not ready."),
        0x009f: ("NT_STATUS_FREE_VM_NOT_AT_BASE","Attempt to access invalid address."),
        0x00a0: ("NT_STATUS_MEMORY_NOT_ALLOCATED","Attempt to access invalid address."),
        0x00a1: ("NT_STATUS_WORKING_SET_QUOTA","Insufficient quota to complete the requested service."),
        0x00a2: ("NT_STATUS_MEDIA_WRITE_PROTECTED","The media is write protected."),
        0x00a3: ("NT_STATUS_DEVICE_NOT_READY","The device is not ready."),
        0x00a4: ("NT_STATUS_INVALID_GROUP_ATTRIBUTES","The specified attributes are invalid, or incompatible with the attributes for the group as a whole."),
        0x00a5: ("NT_STATUS_BAD_IMPERSONATION_LEVEL","Either a required impersonation level was not provided, or the provided impersonation level is invalid."),
        0x00a6: ("NT_STATUS_CANT_OPEN_ANONYMOUS","Cannot open an anonymous level security token."),
        0x00a7: ("NT_STATUS_BAD_VALIDATION_CLASS","The validation information class requested was invalid."),
        0x00a8: ("NT_STATUS_BAD_TOKEN_TYPE","The type of the token is inappropriate for its attempted use."),
        0x00a9: ("NT_STATUS_BAD_MASTER_BOOT_RECORD","NT_STATUS_BAD_MASTER_BOOT_RECORD"),
        0x00aa: ("NT_STATUS_INSTRUCTION_MISALIGNMENT","NT_STATUS_INSTRUCTION_MISALIGNMENT"),
        0x00ab: ("NT_STATUS_INSTANCE_NOT_AVAILABLE","All pipe instances are busy."),
        0x00ac: ("NT_STATUS_PIPE_NOT_AVAILABLE","All pipe instances are busy."),
        0x00ad: ("NT_STATUS_INVALID_PIPE_STATE","The pipe state is invalid."),
        0x00ae: ("NT_STATUS_PIPE_BUSY","All pipe instances are busy."),
        0x00af: ("NT_STATUS_ILLEGAL_FUNCTION","Incorrect function."),
        0x00b0: ("NT_STATUS_PIPE_DISCONNECTED","No process is on the other end of the pipe."),
        0x00b1: ("NT_STATUS_PIPE_CLOSING","The pipe is being closed."),
        0x00b2: ("NT_STATUS_PIPE_CONNECTED","There is a process on other end of the pipe."),
        0x00b3: ("NT_STATUS_PIPE_LISTENING","Waiting for a process to open the other end of the pipe."),
        0x00b4: ("NT_STATUS_INVALID_READ_MODE","The pipe state is invalid."),
        0x00b5: ("NT_STATUS_IO_TIMEOUT","The semaphore timeout period has expired."),
        0x00b6: ("NT_STATUS_FILE_FORCED_CLOSED","Reached end of file."),
        0x00b7: ("NT_STATUS_PROFILING_NOT_STARTED","NT_STATUS_PROFILING_NOT_STARTED"),
        0x00b8: ("NT_STATUS_PROFILING_NOT_STOPPED","NT_STATUS_PROFILING_NOT_STOPPED"),
        0x00b9: ("NT_STATUS_COULD_NOT_INTERPRET","NT_STATUS_COULD_NOT_INTERPRET"),
        0x00ba: ("NT_STATUS_FILE_IS_A_DIRECTORY","Access is denied."),
        0x00bb: ("NT_STATUS_NOT_SUPPORTED","The network request is not supported."),
        0x00bc: ("NT_STATUS_REMOTE_NOT_LISTENING","The remote computer is not available."),
        0x00bd: ("NT_STATUS_DUPLICATE_NAME","A duplicate name exists on the network."),
        0x00be: ("NT_STATUS_BAD_NETWORK_PATH","The network path was not found."),
        0x00bf: ("NT_STATUS_NETWORK_BUSY","The network is busy."),
        0x00c0: ("NT_STATUS_DEVICE_DOES_NOT_EXIST","The specified network resource or device is no longer available."),
        0x00c1: ("NT_STATUS_TOO_MANY_COMMANDS","The network BIOS command limit has been reached."),
        0x00c2: ("NT_STATUS_ADAPTER_HARDWARE_ERROR","A network adapter hardware error occurred."),
        0x00c3: ("NT_STATUS_INVALID_NETWORK_RESPONSE","The specified server cannot perform the requested operation."),
        0x00c4: ("NT_STATUS_UNEXPECTED_NETWORK_ERROR","An unexpected network error occurred."),
        0x00c5: ("NT_STATUS_BAD_REMOTE_ADAPTER","The remote adapter is not compatible."),
        0x00c6: ("NT_STATUS_PRINT_QUEUE_FULL","The printer queue is full."),
        0x00c7: ("NT_STATUS_NO_SPOOL_SPACE","Space to store the file waiting to be printed is not available on the server."),
        0x00c8: ("NT_STATUS_PRINT_CANCELLED","Your file waiting to be printed was deleted."),
        0x00c9: ("NT_STATUS_NETWORK_NAME_DELETED","The specified network name is no longer available."),
        0x00ca: ("NT_STATUS_NETWORK_ACCESS_DENIED","Network access is denied."),
        0x00cb: ("NT_STATUS_BAD_DEVICE_TYPE","The network resource type is not correct."),
        0x00cc: ("NT_STATUS_BAD_NETWORK_NAME","The network name cannot be found."),
        0x00cd: ("NT_STATUS_TOO_MANY_NAMES","The name limit for the local computer network adapter card was exceeded."),
        0x00ce: ("NT_STATUS_TOO_MANY_SESSIONS","The network BIOS session limit was exceeded."),
        0x00cf: ("NT_STATUS_SHARING_PAUSED","The remote server has been paused or is in the process of being started."),
        0x00d0: ("NT_STATUS_REQUEST_NOT_ACCEPTED","No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept."),
        0x00d1: ("NT_STATUS_REDIRECTOR_PAUSED","The specified printer or disk device has been paused."),
        0x00d2: ("NT_STATUS_NET_WRITE_FAULT","A write fault occurred on the network."),
        0x00d3: ("NT_STATUS_PROFILING_AT_LIMIT","NT_STATUS_PROFILING_AT_LIMIT"),
        0x00d4: ("NT_STATUS_NOT_SAME_DEVICE","The system cannot move the file to a different disk drive."),
        0x00d5: ("NT_STATUS_FILE_RENAMED","NT_STATUS_FILE_RENAMED"),
        0x00d6: ("NT_STATUS_VIRTUAL_CIRCUIT_CLOSED","The session was cancelled."),
        0x00d7: ("NT_STATUS_NO_SECURITY_ON_OBJECT","Unable to perform a security operation on an object which has no associated security."),
        0x00d8: ("NT_STATUS_CANT_WAIT","NT_STATUS_CANT_WAIT"),
        0x00d9: ("NT_STATUS_PIPE_EMPTY","The pipe is being closed."),
        0x00da: ("NT_STATUS_CANT_ACCESS_DOMAIN_INFO","Indicates a Windows NT Server could not be contacted or that objects within the domain are protected such that necessary information could not be retrieved."),
        0x00db: ("NT_STATUS_CANT_TERMINATE_SELF","NT_STATUS_CANT_TERMINATE_SELF"),
        0x00dc: ("NT_STATUS_INVALID_SERVER_STATE","The security account manager (SAM) or local security authority (LSA) server was in the wrong state to perform the security operation."),
        0x00dd: ("NT_STATUS_INVALID_DOMAIN_STATE","The domain was in the wrong state to perform the security operation."),
        0x00de: ("NT_STATUS_INVALID_DOMAIN_ROLE","This operation is only allowed for the Primary Domain Controller of the domain."),
        0x00df: ("NT_STATUS_NO_SUCH_DOMAIN","The specified domain did not exist."),
        0x00e0: ("NT_STATUS_DOMAIN_EXISTS","The specified domain already exists."),
        0x00e1: ("NT_STATUS_DOMAIN_LIMIT_EXCEEDED","An attempt was made to exceed the limit on the number of domains per server."),
        0x00e2: ("NT_STATUS_OPLOCK_NOT_GRANTED","NT_STATUS_OPLOCK_NOT_GRANTED"),
        0x00e3: ("NT_STATUS_INVALID_OPLOCK_PROTOCOL","NT_STATUS_INVALID_OPLOCK_PROTOCOL"),
        0x00e4: ("NT_STATUS_INTERNAL_DB_CORRUPTION","Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk."),
        0x00e5: ("NT_STATUS_INTERNAL_ERROR","The security account database contains an internal inconsistency."),
        0x00e6: ("NT_STATUS_GENERIC_NOT_MAPPED","Generic access types were contained in an access mask which should already be mapped to non-generic types."),
        0x00e7: ("NT_STATUS_BAD_DESCRIPTOR_FORMAT","A security descriptor is not in the right format (absolute or self-relative)."),
        0x00e8: ("NT_STATUS_INVALID_USER_BUFFER","The supplied user buffer is not valid for the requested operation."),
        0x00e9: ("NT_STATUS_UNEXPECTED_IO_ERROR","NT_STATUS_UNEXPECTED_IO_ERROR"),
        0x00ea: ("NT_STATUS_UNEXPECTED_MM_CREATE_ERR","NT_STATUS_UNEXPECTED_MM_CREATE_ERR"),
        0x00eb: ("NT_STATUS_UNEXPECTED_MM_MAP_ERROR","NT_STATUS_UNEXPECTED_MM_MAP_ERROR"),
        0x00ec: ("NT_STATUS_UNEXPECTED_MM_EXTEND_ERR","NT_STATUS_UNEXPECTED_MM_EXTEND_ERR"),
        0x00ed: ("NT_STATUS_NOT_LOGON_PROCESS","The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process."),
        0x00ee: ("NT_STATUS_LOGON_SESSION_EXISTS","Cannot start a new logon session with an ID that is already in use."),
        0x00ef: ("NT_STATUS_INVALID_PARAMETER_1","The parameter is incorrect."),
        0x00f0: ("NT_STATUS_INVALID_PARAMETER_2","The parameter is incorrect."),
        0x00f1: ("NT_STATUS_INVALID_PARAMETER_3","The parameter is incorrect."),
        0x00f2: ("NT_STATUS_INVALID_PARAMETER_4","The parameter is incorrect."),
        0x00f3: ("NT_STATUS_INVALID_PARAMETER_5","The parameter is incorrect."),
        0x00f4: ("NT_STATUS_INVALID_PARAMETER_6","The parameter is incorrect."),
        0x00f5: ("NT_STATUS_INVALID_PARAMETER_7","The parameter is incorrect."),
        0x00f6: ("NT_STATUS_INVALID_PARAMETER_8","The parameter is incorrect."),
        0x00f7: ("NT_STATUS_INVALID_PARAMETER_9","The parameter is incorrect."),
        0x00f8: ("NT_STATUS_INVALID_PARAMETER_10","The parameter is incorrect."),
        0x00f9: ("NT_STATUS_INVALID_PARAMETER_11","The parameter is incorrect."),
        0x00fa: ("NT_STATUS_INVALID_PARAMETER_12","The parameter is incorrect."),
        0x00fb: ("NT_STATUS_REDIRECTOR_NOT_STARTED","The system cannot find the path specified."),
        0x00fc: ("NT_STATUS_REDIRECTOR_STARTED","NT_STATUS_REDIRECTOR_STARTED"),
        0x00fd: ("NT_STATUS_STACK_OVERFLOW","Recursion too deep, stack overflowed."),
        0x00fe: ("NT_STATUS_NO_SUCH_PACKAGE","A specified authentication package is unknown."),
        0x00ff: ("NT_STATUS_BAD_FUNCTION_TABLE","NT_STATUS_BAD_FUNCTION_TABLE"),
        0x0101: ("NT_STATUS_DIRECTORY_NOT_EMPTY","The directory is not empty."),
        0x0102: ("NT_STATUS_FILE_CORRUPT_ERROR","The file or directory is corrupt and non-readable."),
        0x0103: ("NT_STATUS_NOT_A_DIRECTORY","The directory name is invalid."),
        0x0104: ("NT_STATUS_BAD_LOGON_SESSION_STATE","The logon session is not in a state that is consistent with the requested operation."),
        0x0105: ("NT_STATUS_LOGON_SESSION_COLLISION","The logon session ID is already in use."),
        0x0106: ("NT_STATUS_NAME_TOO_LONG","The filename or extension is too long."),
        0x0107: ("NT_STATUS_FILES_OPEN","NT_STATUS_FILES_OPEN"),
        0x0108: ("NT_STATUS_CONNECTION_IN_USE","The device is being accessed by an active process."),
        0x0109: ("NT_STATUS_MESSAGE_NOT_FOUND","NT_STATUS_MESSAGE_NOT_FOUND"),
        0x010a: ("NT_STATUS_PROCESS_IS_TERMINATING","Access is denied."),
        0x010b: ("NT_STATUS_INVALID_LOGON_TYPE","A logon request contained an invalid logon type value."),
        0x010c: ("NT_STATUS_NO_GUID_TRANSLATION","NT_STATUS_NO_GUID_TRANSLATION"),
        0x010d: ("NT_STATUS_CANNOT_IMPERSONATE","Unable to impersonate via a named pipe until data has been read from that pipe."),
        0x010e: ("NT_STATUS_IMAGE_ALREADY_LOADED","An instance of the service is already running."),
        0x010f: ("NT_STATUS_ABIOS_NOT_PRESENT","NT_STATUS_ABIOS_NOT_PRESENT"),
        0x0110: ("NT_STATUS_ABIOS_LID_NOT_EXIST","NT_STATUS_ABIOS_LID_NOT_EXIST"),
        0x0111: ("NT_STATUS_ABIOS_LID_ALREADY_OWNED","NT_STATUS_ABIOS_LID_ALREADY_OWNED"),
        0x0112: ("NT_STATUS_ABIOS_NOT_LID_OWNER","NT_STATUS_ABIOS_NOT_LID_OWNER"),
        0x0113: ("NT_STATUS_ABIOS_INVALID_COMMAND","NT_STATUS_ABIOS_INVALID_COMMAND"),
        0x0114: ("NT_STATUS_ABIOS_INVALID_LID","NT_STATUS_ABIOS_INVALID_LID"),
        0x0115: ("NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE","NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE"),
        0x0116: ("NT_STATUS_ABIOS_INVALID_SELECTOR","NT_STATUS_ABIOS_INVALID_SELECTOR"),
        0x0117: ("NT_STATUS_NO_LDT","NT_STATUS_NO_LDT"),
        0x0118: ("NT_STATUS_INVALID_LDT_SIZE","NT_STATUS_INVALID_LDT_SIZE"),
        0x0119: ("NT_STATUS_INVALID_LDT_OFFSET","NT_STATUS_INVALID_LDT_OFFSET"),
        0x011a: ("NT_STATUS_INVALID_LDT_DESCRIPTOR","NT_STATUS_INVALID_LDT_DESCRIPTOR"),
        0x011b: ("NT_STATUS_INVALID_IMAGE_NE_FORMAT","%1 is not a valid Windows NT application."),
        0x011c: ("NT_STATUS_RXACT_INVALID_STATE","The transaction state of a Registry subtree is incompatible with the requested operation."),
        0x011d: ("NT_STATUS_RXACT_COMMIT_FAILURE","An internal security database corruption has been encountered."),
        0x011e: ("NT_STATUS_MAPPED_FILE_SIZE_ZERO","The volume for a file has been externally altered such that the opened file is no longer valid."),
        0x011f: ("NT_STATUS_TOO_MANY_OPENED_FILES","The system cannot open the file."),
        0x0120: ("NT_STATUS_CANCELLED","The I/O operation has been aborted because of either a thread exit or an application request."),
        0x0121: ("NT_STATUS_CANNOT_DELETE","Access is denied."),
        0x0122: ("NT_STATUS_INVALID_COMPUTER_NAME","The format of the specified computer name is invalid."),
        0x0123: ("NT_STATUS_FILE_DELETED","Access is denied."),
        0x0124: ("NT_STATUS_SPECIAL_ACCOUNT","Cannot perform this operation on built-in accounts."),
        0x0125: ("NT_STATUS_SPECIAL_GROUP","Cannot perform this operation on this built-in special group."),
        0x0126: ("NT_STATUS_SPECIAL_USER","Cannot perform this operation on this built-in special user."),
        0x0127: ("NT_STATUS_MEMBERS_PRIMARY_GROUP","The user cannot be removed from a group because the group is currently the user's primary group."),
        0x0128: ("NT_STATUS_FILE_CLOSED","The handle is invalid."),
        0x0129: ("NT_STATUS_TOO_MANY_THREADS","NT_STATUS_TOO_MANY_THREADS"),
        0x012a: ("NT_STATUS_THREAD_NOT_IN_PROCESS","NT_STATUS_THREAD_NOT_IN_PROCESS"),
        0x012b: ("NT_STATUS_TOKEN_ALREADY_IN_USE","The token is already in use as a primary token."),
        0x012c: ("NT_STATUS_PAGEFILE_QUOTA_EXCEEDED","NT_STATUS_PAGEFILE_QUOTA_EXCEEDED"),
        0x012d: ("NT_STATUS_COMMITMENT_LIMIT","The paging file is too small for this operation to complete."),
        0x012e: ("NT_STATUS_INVALID_IMAGE_LE_FORMAT","%1 is not a valid Windows NT application."),
        0x012f: ("NT_STATUS_INVALID_IMAGE_NOT_MZ","%1 is not a valid Windows NT application."),
        0x0130: ("NT_STATUS_INVALID_IMAGE_PROTECT","%1 is not a valid Windows NT application."),
        0x0131: ("NT_STATUS_INVALID_IMAGE_WIN_16","%1 is not a valid Windows NT application."),
        0x0132: ("NT_STATUS_LOGON_SERVER_CONFLICT","NT_STATUS_LOGON_SERVER_CONFLICT"),
        0x0133: ("NT_STATUS_TIME_DIFFERENCE_AT_DC","NT_STATUS_TIME_DIFFERENCE_AT_DC"),
        0x0134: ("NT_STATUS_SYNCHRONIZATION_REQUIRED","NT_STATUS_SYNCHRONIZATION_REQUIRED"),
        0x0135: ("NT_STATUS_DLL_NOT_FOUND","The specified module could not be found."),
        0x0136: ("NT_STATUS_OPEN_FAILED","NT_STATUS_OPEN_FAILED"),
        0x0137: ("NT_STATUS_IO_PRIVILEGE_FAILED","NT_STATUS_IO_PRIVILEGE_FAILED"),
        0x0138: ("NT_STATUS_ORDINAL_NOT_FOUND","The operating system cannot run %1."),
        0x0139: ("NT_STATUS_ENTRYPOINT_NOT_FOUND","The specified procedure could not be found."),
        0x013a: ("NT_STATUS_CONTROL_C_EXIT","NT_STATUS_CONTROL_C_EXIT"),
        0x013b: ("NT_STATUS_LOCAL_DISCONNECT","The specified network name is no longer available."),
        0x013c: ("NT_STATUS_REMOTE_DISCONNECT","The specified network name is no longer available."),
        0x013d: ("NT_STATUS_REMOTE_RESOURCES","The remote computer is not available."),
        0x013e: ("NT_STATUS_LINK_FAILED","An unexpected network error occurred."),
        0x013f: ("NT_STATUS_LINK_TIMEOUT","An unexpected network error occurred."),
        0x0140: ("NT_STATUS_INVALID_CONNECTION","An unexpected network error occurred."),
        0x0141: ("NT_STATUS_INVALID_ADDRESS","An unexpected network error occurred."),
        0x0142: ("NT_STATUS_DLL_INIT_FAILED","A dynamic link library (DLL) initialization routine failed."),
        0x0143: ("NT_STATUS_MISSING_SYSTEMFILE","NT_STATUS_MISSING_SYSTEMFILE"),
        0x0144: ("NT_STATUS_UNHANDLED_EXCEPTION","NT_STATUS_UNHANDLED_EXCEPTION"),
        0x0145: ("NT_STATUS_APP_INIT_FAILURE","NT_STATUS_APP_INIT_FAILURE"),
        0x0146: ("NT_STATUS_PAGEFILE_CREATE_FAILED","NT_STATUS_PAGEFILE_CREATE_FAILED"),
        0x0147: ("NT_STATUS_NO_PAGEFILE","NT_STATUS_NO_PAGEFILE"),
        0x0148: ("NT_STATUS_INVALID_LEVEL","The system call level is not correct."),
        0x0149: ("NT_STATUS_WRONG_PASSWORD_CORE","The specified network password is not correct."),
        0x014a: ("NT_STATUS_ILLEGAL_FLOAT_CONTEXT","NT_STATUS_ILLEGAL_FLOAT_CONTEXT"),
        0x014b: ("NT_STATUS_PIPE_BROKEN","The pipe has been ended."),
        0x014c: ("NT_STATUS_REGISTRY_CORRUPT","The configuration registry database is corrupt."),
        0x014d: ("NT_STATUS_REGISTRY_IO_FAILED","An I/O operation initiated by the Registry failed unrecoverably. The Registry could not read in, or write out, or flush, one of the files that contain the system's image of the Registry."),
        0x014e: ("NT_STATUS_NO_EVENT_PAIR","NT_STATUS_NO_EVENT_PAIR"),
        0x014f: ("NT_STATUS_UNRECOGNIZED_VOLUME","The volume does not contain a recognized file system. Please make sure that all required file system drivers are loaded and that the volume is not corrupt."),
        0x0150: ("NT_STATUS_SERIAL_NO_DEVICE_INITED","No serial device was successfully initialized. The serial driver will unload."),
        0x0151: ("NT_STATUS_NO_SUCH_ALIAS","The specified local group does not exist."),
        0x0152: ("NT_STATUS_MEMBER_NOT_IN_ALIAS","The specified account name is not a member of the local group."),
        0x0153: ("NT_STATUS_MEMBER_IN_ALIAS","The specified account name is already a member of the local group."),
        0x0154: ("NT_STATUS_ALIAS_EXISTS","The specified local group already exists."),
        0x0155: ("NT_STATUS_LOGON_NOT_GRANTED","Logon failure: the user has not been granted the requested logon type at this computer."),
        0x0156: ("NT_STATUS_TOO_MANY_SECRETS","The maximum number of secrets that may be stored in a single system has been exceeded."),
        0x0157: ("NT_STATUS_SECRET_TOO_LONG","The length of a secret exceeds the maximum length allowed."),
        0x0158: ("NT_STATUS_INTERNAL_DB_ERROR","The local security authority database contains an internal inconsistency."),
        0x0159: ("NT_STATUS_FULLSCREEN_MODE","The requested operation cannot be performed in full-screen mode."),
        0x015a: ("NT_STATUS_TOO_MANY_CONTEXT_IDS","During a logon attempt, the user's security context accumulated too many security IDs."),
        0x015b: ("NT_STATUS_LOGON_TYPE_NOT_GRANTED","Logon failure: the user has not been granted the requested logon type at this computer."),
        0x015c: ("NT_STATUS_NOT_REGISTRY_FILE","The system has attempted to load or restore a file into the Registry, but the specified file is not in a Registry file format."),
        0x015d: ("NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED","A cross-encrypted password is necessary to change a user password."),
        0x015e: ("NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR","NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR"),
        0x015f: ("NT_STATUS_FT_MISSING_MEMBER","The request could not be performed because of an I/O device error."),
        0x0160: ("NT_STATUS_ILL_FORMED_SERVICE_ENTRY","NT_STATUS_ILL_FORMED_SERVICE_ENTRY"),
        0x0161: ("NT_STATUS_ILLEGAL_CHARACTER","NT_STATUS_ILLEGAL_CHARACTER"),
        0x0162: ("NT_STATUS_UNMAPPABLE_CHARACTER","No mapping for the Unicode character exists in the target multi-byte code page."),
        0x0163: ("NT_STATUS_UNDEFINED_CHARACTER","NT_STATUS_UNDEFINED_CHARACTER"),
        0x0164: ("NT_STATUS_FLOPPY_VOLUME","NT_STATUS_FLOPPY_VOLUME"),
        0x0165: ("NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND","No ID address mark was found on the floppy disk."),
        0x0166: ("NT_STATUS_FLOPPY_WRONG_CYLINDER","Mismatch between the floppy disk sector ID field and the floppy disk controller track address."),
        0x0167: ("NT_STATUS_FLOPPY_UNKNOWN_ERROR","The floppy disk controller reported an error that is not recognized by the floppy disk driver."),
        0x0168: ("NT_STATUS_FLOPPY_BAD_REGISTERS","The floppy disk controller returned inconsistent results in its registers."),
        0x0169: ("NT_STATUS_DISK_RECALIBRATE_FAILED","While accessing the hard disk, a recalibrate operation failed, even after retries."),
        0x016a: ("NT_STATUS_DISK_OPERATION_FAILED","While accessing the hard disk, a disk operation failed even after retries."),
        0x016b: ("NT_STATUS_DISK_RESET_FAILED","While accessing the hard disk, a disk controller reset was needed, but even that failed."),
        0x016c: ("NT_STATUS_SHARED_IRQ_BUSY","Unable to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened."),
        0x016d: ("NT_STATUS_FT_ORPHANING","The request could not be performed because of an I/O device error."),
        0x0172: ("NT_STATUS_PARTITION_FAILURE","Tape could not be partitioned."),
        0x0173: ("NT_STATUS_INVALID_BLOCK_LENGTH","When accessing a new tape of a multivolume partition, the current blocksize is incorrect."),
        0x0174: ("NT_STATUS_DEVICE_NOT_PARTITIONED","Tape partition information could not be found when loading a tape."),
        0x0175: ("NT_STATUS_UNABLE_TO_LOCK_MEDIA","Unable to lock the media eject mechanism."),
        0x0176: ("NT_STATUS_UNABLE_TO_UNLOAD_MEDIA","Unable to unload the media."),
        0x0177: ("NT_STATUS_EOM_OVERFLOW","Physical end of tape encountered."),
        0x0178: ("NT_STATUS_NO_MEDIA","No media in drive."),
        0x017a: ("NT_STATUS_NO_SUCH_MEMBER","A new member could not be added to a local group because the member does not exist."),
        0x017b: ("NT_STATUS_INVALID_MEMBER","A new member could not be added to a local group because the member has the wrong account type."),
        0x017c: ("NT_STATUS_KEY_DELETED","Illegal operation attempted on a Registry key which has been marked for deletion."),
        0x017d: ("NT_STATUS_NO_LOG_SPACE","System could not allocate the required space in a Registry log."),
        0x017e: ("NT_STATUS_TOO_MANY_SIDS","Too many security IDs have been specified."),
        0x017f: ("NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED","A cross-encrypted password is necessary to change this user password."),
        0x0180: ("NT_STATUS_KEY_HAS_CHILDREN","Cannot create a symbolic link in a Registry key that already has subkeys or values."),
        0x0181: ("NT_STATUS_CHILD_MUST_BE_VOLATILE","Cannot create a stable subkey under a volatile parent key."),
        0x0182: ("NT_STATUS_DEVICE_CONFIGURATION_ERROR","The parameter is incorrect."),
        0x0183: ("NT_STATUS_DRIVER_INTERNAL_ERROR","The request could not be performed because of an I/O device error."),
        0x0184: ("NT_STATUS_INVALID_DEVICE_STATE","The device does not recognize the command."),
        0x0185: ("NT_STATUS_IO_DEVICE_ERROR","The request could not be performed because of an I/O device error."),
        0x0186: ("NT_STATUS_DEVICE_PROTOCOL_ERROR","The request could not be performed because of an I/O device error."),
        0x0187: ("NT_STATUS_BACKUP_CONTROLLER","NT_STATUS_BACKUP_CONTROLLER"),
        0x0188: ("NT_STATUS_LOG_FILE_FULL","The event log file is full."),
        0x0189: ("NT_STATUS_TOO_LATE","The media is write protected."),
        0x018a: ("NT_STATUS_NO_TRUST_LSA_SECRET","The workstation does not have a trust secret."),
        0x018b: ("NT_STATUS_NO_TRUST_SAM_ACCOUNT","The SAM database on the Windows NT Server does not have a computer account for this workstation trust relationship."),
        0x018c: ("NT_STATUS_TRUSTED_DOMAIN_FAILURE","The trust relationship between the primary domain and the trusted domain failed."),
        0x018d: ("NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE","The trust relationship between this workstation and the primary domain failed."),
        0x018e: ("NT_STATUS_EVENTLOG_FILE_CORRUPT","The event log file is corrupt."),
        0x018f: ("NT_STATUS_EVENTLOG_CANT_START","No event log file could be opened, so the event logging service did not start."),
        0x0190: ("NT_STATUS_TRUST_FAILURE","The network logon failed."),
        0x0191: ("NT_STATUS_MUTANT_LIMIT_EXCEEDED","NT_STATUS_MUTANT_LIMIT_EXCEEDED"),
        0x0192: ("NT_STATUS_NETLOGON_NOT_STARTED","An attempt was made to logon, but the network logon service was not started."),
        0x0193: ("NT_STATUS_ACCOUNT_EXPIRED","The user's account has expired."),
        0x0194: ("NT_STATUS_POSSIBLE_DEADLOCK","A potential deadlock condition has been detected."),
        0x0195: ("NT_STATUS_NETWORK_CREDENTIAL_CONFLICT","The credentials supplied conflict with an existing set of credentials."),
        0x0196: ("NT_STATUS_REMOTE_SESSION_LIMIT","An attempt was made to establish a session to a network server, but there are already too many sessions established to that server."),
        0x0197: ("NT_STATUS_EVENTLOG_FILE_CHANGED","The event log file has changed between reads."),
        0x0198: ("NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT","The account used is an interdomain trust account. Use your global user account or local user account to access this server."),
        0x0199: ("NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT","The account used is a Computer Account. Use your global user account or local user account to access this server."),
        0x019a: ("NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT","The account used is an server trust account. Use your global user account or local user account to access this server."),
        0x019b: ("NT_STATUS_DOMAIN_TRUST_INCONSISTENT","The name or security ID (SID) of the domain specified is inconsistent with the trust information for that domain."),
        0x019c: ("NT_STATUS_FS_DRIVER_REQUIRED","NT_STATUS_FS_DRIVER_REQUIRED"),
        0x0202: ("NT_STATUS_NO_USER_SESSION_KEY","There is no user session key for the specified logon session."),
        0x0203: ("NT_STATUS_USER_SESSION_DELETED","An unexpected network error occurred."),
        0x0204: ("NT_STATUS_RESOURCE_LANG_NOT_FOUND","The specified resource language ID cannot be found in the image file."),
        0x0205: ("NT_STATUS_INSUFF_SERVER_RESOURCES","Not enough server storage is available to process this command."),
        0x0206: ("NT_STATUS_INVALID_BUFFER_SIZE","The supplied user buffer is not valid for the requested operation."),
        0x0207: ("NT_STATUS_INVALID_ADDRESS_COMPONENT","The format of the specified network name is invalid."),
        0x0208: ("NT_STATUS_INVALID_ADDRESS_WILDCARD","The format of the specified network name is invalid."),
        0x0209: ("NT_STATUS_TOO_MANY_ADDRESSES","The name limit for the local computer network adapter card was exceeded."),
        0x020a: ("NT_STATUS_ADDRESS_ALREADY_EXISTS","A duplicate name exists on the network."),
        0x020b: ("NT_STATUS_ADDRESS_CLOSED","The specified network name is no longer available."),
        0x020c: ("NT_STATUS_CONNECTION_DISCONNECTED","The specified network name is no longer available."),
        0x020d: ("NT_STATUS_CONNECTION_RESET","The specified network name is no longer available."),
        0x020e: ("NT_STATUS_TOO_MANY_NODES","The name limit for the local computer network adapter card was exceeded."),
        0x020f: ("NT_STATUS_TRANSACTION_ABORTED","An unexpected network error occurred."),
        0x0210: ("NT_STATUS_TRANSACTION_TIMED_OUT","An unexpected network error occurred."),
        0x0211: ("NT_STATUS_TRANSACTION_NO_RELEASE","An unexpected network error occurred."),
        0x0212: ("NT_STATUS_TRANSACTION_NO_MATCH","An unexpected network error occurred."),
        0x0213: ("NT_STATUS_TRANSACTION_RESPONDED","An unexpected network error occurred."),
        0x0214: ("NT_STATUS_TRANSACTION_INVALID_ID","An unexpected network error occurred."),
        0x0215: ("NT_STATUS_TRANSACTION_INVALID_TYPE","An unexpected network error occurred."),
        0x0216: ("NT_STATUS_NOT_SERVER_SESSION","The network request is not supported."),
        0x0217: ("NT_STATUS_NOT_CLIENT_SESSION","The network request is not supported."),
        0x0218: ("NT_STATUS_CANNOT_LOAD_REGISTRY_FILE","NT_STATUS_CANNOT_LOAD_REGISTRY_FILE"),
        0x0219: ("NT_STATUS_DEBUG_ATTACH_FAILED","NT_STATUS_DEBUG_ATTACH_FAILED"),
        0x021a: ("NT_STATUS_SYSTEM_PROCESS_TERMINATED","NT_STATUS_SYSTEM_PROCESS_TERMINATED"),
        0x021b: ("NT_STATUS_DATA_NOT_ACCEPTED","NT_STATUS_DATA_NOT_ACCEPTED"),
        0x021c: ("NT_STATUS_NO_BROWSER_SERVERS_FOUND","The list of servers for this workgroup is not currently available"),
        0x021d: ("NT_STATUS_VDM_HARD_ERROR","NT_STATUS_VDM_HARD_ERROR"),
        0x021e: ("NT_STATUS_DRIVER_CANCEL_TIMEOUT","NT_STATUS_DRIVER_CANCEL_TIMEOUT"),
        0x021f: ("NT_STATUS_REPLY_MESSAGE_MISMATCH","NT_STATUS_REPLY_MESSAGE_MISMATCH"),
        0x0220: ("NT_STATUS_MAPPED_ALIGNMENT","The base address or the file offset specified does not have the proper alignment."),
        0x0221: ("NT_STATUS_IMAGE_CHECKSUM_MISMATCH","%1 is not a valid Windows NT application."),
        0x0222: ("NT_STATUS_LOST_WRITEBEHIND_DATA","NT_STATUS_LOST_WRITEBEHIND_DATA"),
        0x0223: ("NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID","NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID"),
        0x0224: ("NT_STATUS_PASSWORD_MUST_CHANGE","The user must change his password before he logs on the first time."),
        0x0225: ("NT_STATUS_NOT_FOUND","NT_STATUS_NOT_FOUND"),
        0x0226: ("NT_STATUS_NOT_TINY_STREAM","NT_STATUS_NOT_TINY_STREAM"),
        0x0227: ("NT_STATUS_RECOVERY_FAILURE","NT_STATUS_RECOVERY_FAILURE"),
        0x0228: ("NT_STATUS_STACK_OVERFLOW_READ","NT_STATUS_STACK_OVERFLOW_READ"),
        0x0229: ("NT_STATUS_FAIL_CHECK","NT_STATUS_FAIL_CHECK"),
        0x022a: ("NT_STATUS_DUPLICATE_OBJECTID","NT_STATUS_DUPLICATE_OBJECTID"),
        0x022b: ("NT_STATUS_OBJECTID_EXISTS","NT_STATUS_OBJECTID_EXISTS"),
        0x022c: ("NT_STATUS_CONVERT_TO_LARGE","NT_STATUS_CONVERT_TO_LARGE"),
        0x022d: ("NT_STATUS_RETRY","NT_STATUS_RETRY"),
        0x022e: ("NT_STATUS_FOUND_OUT_OF_SCOPE","NT_STATUS_FOUND_OUT_OF_SCOPE"),
        0x022f: ("NT_STATUS_ALLOCATE_BUCKET","NT_STATUS_ALLOCATE_BUCKET"),
        0x0230: ("NT_STATUS_PROPSET_NOT_FOUND","NT_STATUS_PROPSET_NOT_FOUND"),
        0x0231: ("NT_STATUS_MARSHALL_OVERFLOW","NT_STATUS_MARSHALL_OVERFLOW"),
        0x0232: ("NT_STATUS_INVALID_VARIANT","NT_STATUS_INVALID_VARIANT"),
        0x0233: ("NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND","Could not find the domain controller for this domain."),
        0x0234: ("NT_STATUS_ACCOUNT_LOCKED_OUT","The referenced account is currently locked out and may not be logged on to."),
        0x0235: ("NT_STATUS_HANDLE_NOT_CLOSABLE","The handle is invalid."),
        0x0236: ("NT_STATUS_CONNECTION_REFUSED","The remote system refused the network connection."),
        0x0237: ("NT_STATUS_GRACEFUL_DISCONNECT","The network connection was gracefully closed."),
        0x0238: ("NT_STATUS_ADDRESS_ALREADY_ASSOCIATED","The network transport endpoint already has an address associated with it."),
        0x0239: ("NT_STATUS_ADDRESS_NOT_ASSOCIATED","An address has not yet been associated with the network endpoint."),
        0x023a: ("NT_STATUS_CONNECTION_INVALID","An operation was attempted on a non-existent network connection."),
        0x023b: ("NT_STATUS_CONNECTION_ACTIVE","An invalid operation was attempted on an active network connection."),
        0x023c: ("NT_STATUS_NETWORK_UNREACHABLE","The remote network is not reachable by the transport."),
        0x023d: ("NT_STATUS_HOST_UNREACHABLE","The remote system is not reachable by the transport."),
        0x023e: ("NT_STATUS_PROTOCOL_UNREACHABLE","The remote system does not support the transport protocol."),
        0x023f: ("NT_STATUS_PORT_UNREACHABLE","No service is operating at the destination network endpoint on the remote system."),
        0x0240: ("NT_STATUS_REQUEST_ABORTED","The request was aborted."),
        0x0241: ("NT_STATUS_CONNECTION_ABORTED","The network connection was aborted by the local system."),
        0x0242: ("NT_STATUS_BAD_COMPRESSION_BUFFER","NT_STATUS_BAD_COMPRESSION_BUFFER"),
        0x0243: ("NT_STATUS_USER_MAPPED_FILE","The requested operation cannot be performed on a file with a user mapped section open."),
        0x0244: ("NT_STATUS_AUDIT_FAILED","NT_STATUS_AUDIT_FAILED"),
        0x0245: ("NT_STATUS_TIMER_RESOLUTION_NOT_SET","NT_STATUS_TIMER_RESOLUTION_NOT_SET"),
        0x0246: ("NT_STATUS_CONNECTION_COUNT_LIMIT","A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached."),
        0x0247: ("NT_STATUS_LOGIN_TIME_RESTRICTION","Attempting to login during an unauthorized time of day for this account."),
        0x0248: ("NT_STATUS_LOGIN_WKSTA_RESTRICTION","The account is not authorized to login from this station."),
        0x0249: ("NT_STATUS_IMAGE_MP_UP_MISMATCH","%1 is not a valid Windows NT application."),
        0x0250: ("NT_STATUS_INSUFFICIENT_LOGON_INFO","NT_STATUS_INSUFFICIENT_LOGON_INFO"),
        0x0251: ("NT_STATUS_BAD_DLL_ENTRYPOINT","NT_STATUS_BAD_DLL_ENTRYPOINT"),
        0x0252: ("NT_STATUS_BAD_SERVICE_ENTRYPOINT","NT_STATUS_BAD_SERVICE_ENTRYPOINT"),
        0x0253: ("NT_STATUS_LPC_REPLY_LOST","The security account database contains an internal inconsistency."),
        0x0254: ("NT_STATUS_IP_ADDRESS_CONFLICT1","NT_STATUS_IP_ADDRESS_CONFLICT1"),
        0x0255: ("NT_STATUS_IP_ADDRESS_CONFLICT2","NT_STATUS_IP_ADDRESS_CONFLICT2"),
        0x0256: ("NT_STATUS_REGISTRY_QUOTA_LIMIT","NT_STATUS_REGISTRY_QUOTA_LIMIT"),
        0x0257: ("NT_STATUS_PATH_NOT_COVERED","The remote system is not reachable by the transport."),
        0x0258: ("NT_STATUS_NO_CALLBACK_ACTIVE","NT_STATUS_NO_CALLBACK_ACTIVE"),
        0x0259: ("NT_STATUS_LICENSE_QUOTA_EXCEEDED","The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because there are already as many connections as the service can accept."),
        0x025a: ("NT_STATUS_PWD_TOO_SHORT","NT_STATUS_PWD_TOO_SHORT"),
        0x025b: ("NT_STATUS_PWD_TOO_RECENT","NT_STATUS_PWD_TOO_RECENT"),
        0x025c: ("NT_STATUS_PWD_HISTORY_CONFLICT","NT_STATUS_PWD_HISTORY_CONFLICT"),
        0x025e: ("NT_STATUS_PLUGPLAY_NO_DEVICE","The specified service is disabled and cannot be started."),
        0x025f: ("NT_STATUS_UNSUPPORTED_COMPRESSION","NT_STATUS_UNSUPPORTED_COMPRESSION"),
        0x0260: ("NT_STATUS_INVALID_HW_PROFILE","NT_STATUS_INVALID_HW_PROFILE"),
        0x0261: ("NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH","NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH"),
        0x0262: ("NT_STATUS_DRIVER_ORDINAL_NOT_FOUND","The operating system cannot run %1."),
        0x0263: ("NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND","The specified procedure could not be found."),
        0x0264: ("NT_STATUS_RESOURCE_NOT_OWNED","Attempt to release mutex not owned by caller."),
        0x0265: ("NT_STATUS_TOO_MANY_LINKS","An attempt was made to create more links on a file than the file system supports."),
        0x0266: ("NT_STATUS_QUOTA_LIST_INCONSISTENT","NT_STATUS_QUOTA_LIST_INCONSISTENT"),
        0x0267: ("NT_STATUS_FILE_IS_OFFLINE","NT_STATUS_FILE_IS_OFFLINE"),
        0x0275: ("NT_STATUS_NOT_A_REPARSE_POINT","NT_STATUS_NOT_A_REPARSE_POINT"),
        0x0EDE: ("NT_STATUS_NO_SUCH_JOB","NT_STATUS_NO_SUCH_JOB"),
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

        return 'SMB SessionError: class: %s, code: %s' % (error_class_str, error_code_str)


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
        if self.fields.has_key('Flags1') is False:
             self['Flags1'] = 0

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
            raise SessionError, ("SMB Library Error", self['ErrorClass'] + (self['_reserved'] << 8), self['ErrorCode'], self['Flags2'] & SMB.FLAGS2_NT_STATUS)
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
            self._reserved = ord(data[6])
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
    def get_reserved(self):
        return self._reserved
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
# SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO level
class SMBFindFileIdFullDirectoryInfo(Structure):
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
        ('FileID','<q=0'),
        ('FileName',':'),
    )

# SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO level
class SMBFindFileIdBothDirectoryInfo(Structure):
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
        ('Reserved','<H=0'),
        ('FileID','<q=0'),
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

# \PIPE\LANMAN NetServerGetInfo
class SMBNetServerGetInfoResponse(Structure):
    structure = (
        ('Status','<H=0'),
        ('Convert','<H=0'),
        ('TotalBytesAvailable','<H'),
    )

class SMBNetServerInfo1(Structure):
    # Level 1 Response
    structure = (
        ('ServerName','16s'),
        ('MajorVersion','B=5'),
        ('MinorVersion','B=0'),
        ('ServerType','<L=3'),
        ('ServerCommentLow','<H=0'),
        ('ServerCommentHigh','<H=0'),
    )

# \PIPE\LANMAN NetShareGetInfo
class SMBNetShareGetInfo(Structure):
    structure = (
        ('RAPOpcode','<H=0'),
        ('ParamDesc','z'),
        ('DataDesc','z'),
        ('ShareName','z'),
        ('InfoLevel','<H'),
        ('ReceiveBufferSize','<H'),
    )

class SMBNetShareGetInfoResponse(Structure):
    structure = (
        ('Status','<H=0'),
        ('Convert','<H=0'),
        ('TotalBytesAvailable','<H'),
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
        ('Account','u=""'),
        ('PrimaryDomain','u=""'),
        ('NativeOS','u=""'),
        ('NativeLanMan','u=""'),
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
        ('NativeOS','u=""'),
        ('NativeLanMan','u=""'),
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
        ('NativeOS','u=""'),
        ('NativeLanMan','u=""'),
        ('PrimaryDomain','u=""'),
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
        ('NativeOS','u=""'),
        ('NativeLanMan','u=""'),
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

class SMBTreeConnectAndXExtendedResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('OptionalSupport','<H=1'),
        ('MaximalShareAccessRights','<L=0x1fffff'),
        ('GuestMaximalShareAccessRights','<L=0x1fffff'),
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

class SMBNtCreateAndXExtendedResponse_Parameters(SMBAndXCommand_Parameters):
    # [MS-SMB] Extended response description
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
        ('VolumeGUID','16s'),
        ('FileIdLow','<L=0'),
        ('FileIdHigh','<L=0'),
        ('MaximalAccessRights','<L=0x12019b'),
        ('GuestMaximalAccessRights','<L=0x120089'),
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

    # TRANSACT codes
    TRANS_TRANSACT_NMPIPE                   = 0x26

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
    CAP_LARGE_READX                         = 0x00004000
    CAP_LARGE_WRITEX                        = 0x00008000

    # Flags1 Mask
    FLAGS1_LOCK_AND_READ_OK                 = 0x01
    FLAGS1_PATHCASELESS                     = 0x08
    FLAGS1_CANONICALIZED_PATHS              = 0x10
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



    def __init__(self, remote_name, remote_host, my_name = None, host_type = nmb.TYPE_SERVER, sess_port = 445, timeout=None, UDP = 0):
        # The uid attribute will be set when the client calls the login() method
        self._uid = 0
        self.__server_name = ''
        self.__server_os = ''
        self.__server_lanman = ''
        self.__server_domain = ''
        self.__remote_name = string.upper(remote_name)
        self.__remote_host = remote_host
        self.__is_pathcaseless = 0
        self.__isNTLMv2 = True
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

        # Base flags
        self.__flags1 = 0
        self.__flags2 = 0

        if timeout==None:
            self.__timeout = 10
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
            self._sess = nmb.NetBIOSUDPSession(my_name, remote_name, remote_host, host_type, sess_port, self.__timeout)
        else:
            self._sess = nmb.NetBIOSTCPSession(my_name, remote_name, remote_host, host_type, sess_port, self.__timeout)

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

    def get_flags(self):
        return self.__flags1, self.__flags2

    def set_flags(self, flags1=None, flags2=None):
        if flags1 is not None:
           self.__flags1 = flags1
        if flags2 is not None:
           self.__flags2 = flags2

    def set_timeout(self, timeout):
        self.__timeout = timeout

    def get_timeout(self):
        return self.__timeout

    def get_session(self):        
        return self._sess
    
    def get_tid(self):
        return self.tid

    def get_fid(self):
        return self.fid
   
    def isGuestSession(self):
        return self._action & SMB_SETUP_GUEST 
 
    def doesSupportNTLMv2(self):
        return self.__isNTLMv2

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
        packet['SecurityFeatures'] = m.digest()[:8]
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
        smb['Flags1'] |= self.__flags1
        smb['Flags2'] |= self.__flags2
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
                        raise SessionError, ( "SMB Library Error", s.get_error_class()+ (s.get_reserved() << 8), s.get_error_code() , s.get_flags2() & SMB.FLAGS2_NT_STATUS )
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
                    if self._dialects_data['ServerName'] is not None:
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
        smb['Flags1']  = SMB.FLAGS1_PATHCASELESS
        
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
            smb['Flags1']  = SMB.FLAGS1_PATHCASELESS
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
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
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
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
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
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
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
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
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
        if (self._dialects_parameters['Capabilities'] & SMB.CAP_LARGE_READX) and self._SignatureEnabled is False:
            max_buf_size = 65000
        else:
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
        if (self._dialects_parameters['Capabilities'] & SMB.CAP_LARGE_WRITEX) and self._SignatureEnabled is False:
            max_buf_size = 65000
        else:
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
            max_raw_size = self._dialects_parameters['MaxRawSize']
            # Due to different dialects interpretation of MaxRawSize, we're limiting it to 0xffff
            if max_raw_size > 65535:
               max_raw_size = 65535
            read_data = callback(max_raw_size)

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

    def login_extended(self, user, password, domain = '', lmhash = '', nthash = '', use_ntlmv2 = True ):
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
        auth = ntlm.getNTLMSSPType1('',domain,self._SignatureRequired, use_ntlmv2 = use_ntlmv2)
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

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                infoFields = ntlmChallenge['TargetInfoFields']
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']]) 
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                   try:
                       self.__server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass 
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                   try:
                       if self.__server_name != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'): 
                           self.__server_domain = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass 

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash, use_ntlmv2 = use_ntlmv2)

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

            # Storing some info for later use
            self.__server_os     = sessionData['NativeOS']
            self.__server_lanman = sessionData['NativeLanMan']

            smb.addCommand(sessionSetup)
            self.sendSMB(smb)
            
            smb = self.recvSMB()
            self._uid = 0
            if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
                self._uid = smb['Uid']
                sessionResponse   = SMBCommand(smb['Data'][0])
                sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
                sessionData       = SMBSessionSetupAndXResponse_Data(flags = smb['Flags2'], data = sessionResponse['Data'])

                self._action = sessionParameters['Action']
                # If smb sign required, let's enable it for the rest of the connection
                if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
                   self._SignSequenceNumber = 2
                   self._SignatureEnabled = True
                # Set up the flags to be used from now on
                self.__flags1 = SMB.FLAGS1_PATHCASELESS
                self.__flags2 = SMB.FLAGS2_EXTENDED_SECURITY
                return 1
        else:
            raise Exception('Error: Could not login successfully')

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):

        # If we have hashes, normalize them
        if ( lmhash != '' or nthash != ''):
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try: # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        if self._dialects_parameters['Capabilities'] & SMB.CAP_EXTENDED_SECURITY:
            try:
                self.login_extended(user, password, domain, lmhash, nthash, use_ntlmv2 = True)
            except:
                # If the target OS is Windows 5.0 or Samba, let's try using NTLMv1
                if (self.get_server_lanman().find('Windows 2000') != -1) or (self.get_server_lanman().find('Samba') != -1):
                    self.login_extended(user, password, domain, lmhash, nthash, use_ntlmv2 = False)
                    self.__isNTLMv2 = False
                else:
                    raise
        else:
            self.login_standard(user, password, domain, lmhash, nthash)
            self.__isNTLMv2 = False

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
        smb['Flags1']  = SMB.FLAGS1_PATHCASELESS
        
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

            # Set up the flags to be used from now on
            self.__flags1 = SMB.FLAGS1_PATHCASELESS
            self.__flags2 = 0
            return 1
        else: raise Exception('Error: Could not login successfully')

    def read(self, tid, fid, offset=0, max_size = None, wait_answer=1):
        if not max_size:
            max_size = self._dialects_parameters['MaxBufferSize'] # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
            if (self._dialects_parameters['Capabilities'] & SMB.CAP_LARGE_READX) and self._SignatureEnabled is False:
                max_size = 65000
            else:
                max_size = self._dialects_parameters['MaxBufferSize'] # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        if smb_packet == None:
            smb = NewSMBPacket()
            smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
        smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
        smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
            smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
        smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
           transParameters = SMBTransactionResponse_Parameters(transResponse['Parameters'])
           return transResponse['Data'][-transParameters['TotalDataCount']:] # Remove Potential Prefix Padding

        return None

    def nt_create_andx(self,tid,filename, smb_packet=None, cmd = None):
        if smb_packet == None:
            smb = NewSMBPacket()
            smb['Flags1'] = SMB.FLAGS1_CANONICALIZED_PATHS | SMB.FLAGS1_PATHCASELESS 
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
            resume = False
            files = [ ]

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION2):
                    has_more, _, transparam, transdata = self.__decode_trans(s.get_parameter_words(), s.get_buffer())
                    # A fairly quick trans reassembly. 
                    while has_more:
                       s2 = self.recv_packet()
                       if self.isValidAnswer(s2,SMB.SMB_COM_TRANSACTION2):
                          has_more, _, transparam2, transdata2 = self.__decode_trans(s2.get_parameter_words(), s2.get_buffer())
                          transdata += transdata2
                          transparam += transparam2

                    if not resume:
                        sid, searchcnt, eos, erroffset, lastnameoffset = unpack('<HHHHH', transparam)
                    else:
                        searchcnt, eos, erroffset, lastnameoffset = unpack('<HHHH', transparam)

                    offset = 0
                    data_len = len(transdata)
                    while offset < data_len:
                        nextentry, fileindex, lowct, highct, lowat, highat, lowmt, highmt, lowcht, hightcht, loweof, higheof, lowsz, highsz, attrib, longnamelen, easz, shortnamelen = unpack('<lL12LLlLB', transdata[offset:offset + 69])
                        files.append(SharedFile(highct << 32 | lowct, highat << 32 | lowat, highmt << 32 | lowmt, higheof << 32 | loweof, highsz << 32 | lowsz, attrib, transdata[offset + 70:offset + 70 + shortnamelen], transdata[offset + 94:offset + 94 + longnamelen]))
                        resume_filename = transdata[offset + 94:offset + 94 + longnamelen]
                        offset = offset + nextentry
                        if not nextentry:
                            break
                    if eos:
                       return files
                    else:
                       self.trans2(tid, '\x02\x00', '\x00', pack('<H', sid) + '\x56\x05\x04\x01\x00\x00\x00\x00\x06\x00' + resume_filename + '\x00', '')
                       resume = True
                       resume_filename = ''
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

