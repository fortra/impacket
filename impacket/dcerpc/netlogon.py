# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
#
# Description:
#   [MS-NRPC] Netlogon interface implementation.
#

import array
import random
from struct import *
from impacket.structure import Structure
from impacket.dcerpc import ndrutils, dcerpc
from impacket.uuid import uuidtup_to_bin
from impacket import nt_errors, crypto
import hmac, hashlib
try:
 from Crypto.Cipher import DES, AES, ARC4
except Exception:
    print "Warning: You don't have any crypto installed. You need PyCrypto"
    print "See http://www.pycrypto.org/"


MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB', '1.0'))

# SSP Stuff
# Constants
NL_AUTH_MESSAGE_NETBIOS_DOMAIN        = 0x1
NL_AUTH_MESSAGE_NETBIOS_HOST          = 0x2
NL_AUTH_MESSAGE_DNS_DOMAIN            = 0x4
NL_AUTH_MESSAGE_DNS_HOST              = 0x8
NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8     = 0x10

NL_AUTH_MESSAGE_REQUEST               = 0x0
NL_AUTH_MESSAGE_RESPONSE              = 0x1

NL_SIGNATURE_HMAC_MD5    = 0x77
NL_SIGNATURE_HMAC_SHA256 = 0x13
NL_SEAL_NOT_ENCRYPTED    = 0xffff
NL_SEAL_RC4              = 0x7A
NL_SEAL_AES128           = 0x1A

# Structures
class NL_AUTH_MESSAGE(Structure):
    structure = (
        ('MessageType','<L=0'),
        ('Flags','<L=0'),
        ('Buffer',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Buffer'] = '\x00'*4

class NL_AUTH_SIGNATURE(Structure):
    structure = (
        ('SignatureAlgorithm','<H=0'),
        ('SealAlgorithm','<H=0'),
        ('Pad','<H=0xffff'),
        ('Flags','<H=0'),
        ('SequenceNumber','8s=""'),
        ('Checksum','8s=""'),
        ('_Confounder','_-Confounder','8'),
        ('Confounder',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Confounder'] = ''

class NL_AUTH_SHA2_SIGNATURE(Structure):
    structure = (
        ('SignatureAlgorithm','<H=0'),
        ('SealAlgorithm','<H=0'),
        ('Pad','<H=0xffff'),
        ('Flags','<H=0'),
        ('SequenceNumber','8s=""'),
        ('Checksum','32s=""'),
        ('_Confounder','_-Confounder','8'),
        ('Confounder',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Confounder'] = ''

def ComputeNetlogonCredential(inputData, Sk):
    # [MS-NRPC] Section 3.1.4.4.2
    k1 = Sk[:7]
    k3 = crypto.transformKey(k1)
    k2 = Sk[7:14]
    k4 = crypto.transformKey(k2)
    Crypt1 = DES.new(k3, DES.MODE_ECB)
    Crypt2 = DES.new(k4, DES.MODE_ECB)
    cipherText = Crypt1.encrypt(inputData)
    return Crypt2.encrypt(cipherText)

def ComputeNetlogonCredentialAES(inputData, Sk):
    # [MS-NRPC] Section 3.1.4.4.1
    IV='\x00'*16
    Crypt1 = AES.new(Sk, AES.MODE_CFB, IV)
    return Crypt1.encrypt(inputData)

def ComputeSessionKeyAES(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = None):
    # [MS-NRPC] Section 3.1.4.3.1, added the ability to receive hashes already
    if sharedSecretHash is None:
        M4SS = ntlm.NTOWFv1(sharedSecret)
    else:
        M4SS = sharedSecretHash

    hm = hmac.new(key=M4SS, digestmod=hashlib.sha256)
    hm.update(clientChallenge)
    hm.update(serverChallenge)
    sessionKey = hm.digest()

    return sessionKey[:16]


def ComputeSessionKeyStrongKey(sharedSecret, clientChallenge, serverChallenge, sharedSecretHash = None):
    # [MS-NRPC] Section 3.1.4.3.2, added the ability to receive hashes already

    if sharedSecretHash is None:
        M4SS = ntlm.NTOWFv1(sharedSecret)
    else:
        M4SS = sharedSecretHash

    md5 = hashlib.new('md5')
    md5.update('\x00'*4)
    md5.update(clientChallenge)
    md5.update(serverChallenge)
    finalMD5 = md5.digest()
    hm = hmac.new(M4SS) 
    hm.update(finalMD5)
    return hm.digest()
    
def deriveSequenceNumber(sequenceNum):
    res = ''

    sequenceLow = sequenceNum & 0xffffffff
    sequenceHigh = (sequenceNum >> 32) & 0xffffffff
    sequenceHigh |= 0x80000000

    res = pack('>L', sequenceLow)
    res += pack('>L', sequenceHigh)
    return res

def ComputeNetlogonSignatureAES(authSignature, message, confounder, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 7
    hm = hmac.new(key=sessionKey, digestmod=hashlib.sha256)
    hm.update(str(authSignature)[:8])
    # If no confidentiality requested, it should be ''
    hm.update(confounder)
    hm.update(str(message))
    return hm.digest()[:8]+'\x00'*24

def ComputeNetlogonSignatureMD5(authSignature, message, confounder, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 7
    md5 = hashlib.new('md5')
    md5.update('\x00'*4)
    md5.update(str(authSignature)[:8])
    # If no confidentiality requested, it should be ''
    md5.update(confounder)
    md5.update(str(message))
    finalMD5 = md5.digest()
    hm = hmac.new(sessionKey)
    hm.update(finalMD5)
    return hm.digest()[:8]

def encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9

    hm = hmac.new(sessionKey)
    hm.update('\x00'*4)
    hm2 = hmac.new(hm.digest())
    hm2.update(checkSum)
    encryptionKey = hm2.digest()

    cipher = ARC4.new(encryptionKey)
    return cipher.encrypt(sequenceNum)

def decryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.2, point 5

    return encryptSequenceNumberRC4(sequenceNum, checkSum, sessionKey)

def encryptSequenceNumberAES(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.encrypt(sequenceNum)

def decryptSequenceNumberAES(sequenceNum, checkSum, sessionKey):
    # [MS-NRPC] Section 3.3.4.2.1, point 9
    IV = checkSum[:8] + checkSum[:8]
    Cipher = AES.new(sessionKey, AES.MODE_CFB, IV)
    return Cipher.decrypt(sequenceNum)

def SIGN(data, conFounder, sequenceNum, key, aes = False):
    if aes is False:
        signature = NL_AUTH_SIGNATURE()
        signature['SignatureAlgorithm'] = NL_SIGNATURE_HMAC_MD5
        if conFounder == '':
            signature['SealAlgorithm'] = NL_SEAL_NOT_ENCRYPTED
        else:
            signature['SealAlgorithm'] = NL_SEAL_RC4
        signature['Checksum'] = ComputeNetlogonSignatureMD5(signature, data, conFounder, key)
        signature['SequenceNumber'] = encryptSequenceNumberRC4(deriveSequenceNumber(sequenceNum), signature['Checksum'], key)
        return signature
    else:
        signature = NL_AUTH_SIGNATURE()
        signature['SignatureAlgorithm'] = NL_SIGNATURE_HMAC_SHA256
        if conFounder == '':
            signature['SealAlgorithm'] = NL_SEAL_NOT_ENCRYPTED
        else:
            signature['SealAlgorithm'] = NL_SEAL_AES128
        signature['Checksum'] = ComputeNetlogonSignatureAES(signature, data, conFounder, key)
        signature['SequenceNumber'] = encryptSequenceNumberAES(deriveSequenceNumber(sequenceNum), signature['Checksum'], key)
        return signature

def SEAL(data, confounder, sequenceNum, key, aes = False):
    XorKey = []
    for i in key:
       XorKey.append(chr(ord(i) ^ 0xf0))

    XorKey = ''.join(XorKey)
    if aes is False:
        hm = hmac.new(XorKey)
        hm.update('\x00'*4)
        hm2 = hmac.new(hm.digest())
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(confounder)
        cipher = ARC4.new(encryptionKey)
        plain = cipher.encrypt(data)

        return plain, cfounder
    else:
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.encrypt(confounder)
        plain = cipher.encrypt(data)
        return plain, cfounder
        
def UNSEAL(data, confounder, sequenceNum, key, aes = False):
    XorKey = []
    for i in key:
       XorKey.append(chr(ord(i) ^ 0xf0))

    XorKey = ''.join(XorKey)
    if aes is False:
        hm = hmac.new(XorKey)
        hm.update('\x00'*4)
        hm2 = hmac.new(hm.digest())
        hm2.update(sequenceNum)
        encryptionKey = hm2.digest()

        cipher = ARC4.new(encryptionKey)
        cfounder = cipher.encrypt(confounder)
        cipher = ARC4.new(encryptionKey)
        plain = cipher.encrypt(data)

        return plain, cfounder
    else:
        IV = sequenceNum + sequenceNum
        cipher = AES.new(XorKey, AES.MODE_CFB, IV)
        cfounder = cipher.decrypt(confounder)
        plain = cipher.decrypt(data)
        return plain, cfounder
        
    
def getSSPType1(workstation='', domain='', signingRequired=False):
    auth = NL_AUTH_MESSAGE()
    auth['Flags'] = 0
    auth['Buffer'] = ''
    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_DOMAIN 
    if domain != '':
        auth['Buffer'] = auth['Buffer'] + domain + '\x00'
    else:
        auth['Buffer'] = auth['Buffer'] + 'WORKGROUP\x00'

    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_HOST 
    if workstation != '':
        auth['Buffer'] = auth['Buffer'] + workstation + '\x00'
    else:
        auth['Buffer'] = auth['Buffer'] + 'MYHOST\x00'

    auth['Flags'] |= NL_AUTH_MESSAGE_NETBIOS_HOST_UTF8 
    if workstation != '':
        auth['Buffer'] += pack('<B',len(workstation)) + workstation + '\x00'
    else:
        auth['Buffer'] += '\x06MYHOST\x00'

    return auth

# NETLOGON RPC Stuff
# Constants

# NETLOGON_SECURE_CHANNEL_TYPE 
NullSecureChannel = 0
MsvApSecureChannel = 1
WorkstationSecureChannel = 2
TrustedDnsDomainSecureChannel = 3
TrustedDomainSecureChannel = 4
UasServerSecureChannel = 5
ServerSecureChannel = 6
CdcServerSecureChannel = 7

# Structures
class NETLOGON_CREDENTIAL(Structure):
    structure = (
        ('data','8s=""'),
    )

class NETLOGON_AUTHENTICATOR(Structure):
    structure = (
        ('Credential',':', NETLOGON_CREDENTIAL),
        ('Timestamp','<L=0'),
    )
    def __init__(self, data=None, alignment=0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['Credential'] = NETLOGON_CREDENTIAL()

class PNETLOGON_AUTHENTICATOR(ndrutils.NDRPointerNew):
    structure = NETLOGON_AUTHENTICATOR.structure
    
class ENCRYPTED_NT_OWF_PASSWORD(Structure):
    structure = (
        ('data','16s=""'),
    )

class PENCRYPTED_NT_OWF_PASSWORD(ndrutils.NDRPointerNew):
    structure = ENCRYPTED_NT_OWF_PASSWORD.structure

class NL_GENERIC_RPC_DATA(Structure):
    structure = (
        ('UlongEntryCount','<L=0'),
        ('pUlongData', ':', ndrutils.NDRPointerNew),
        ('UnicodeStringEntryCount','<L=0'),
        ('pUnicodeStringData',':', ndrutils.NDRPointerNew),
        ('SizeIs2','<L=0'),
        ('_UlongData', '_-UlongData', 'self["UlongEntryCount"]*4'),
        ('UlongData', ':'),
        ('UnicodeStringData', ':'),
    )

class PNL_GENERIC_RPC_DATA(ndrutils.NDRPointerNew):
    structure = NL_GENERIC_RPC_DATA.structure

class NETLOGONGetDCName(Structure):
    opnum = 11
    structure = (
        ('ServerName',':', ndrutils.NDRStringW),
        ('DomainName',':', ndrutils.NDRUniqueStringW),
    )

class NETLOGONGetDCNameResponse(Structure):
    structure = (
        ('Buffer',':', ndrutils.NDRUniqueStringW),
    )

class NETLOGONGetAnyDCName(Structure):
    opnum = 13
    structure = (
        ('ServerName',':', ndrutils.NDRUniqueStringW),
        ('DomainName',':', ndrutils.NDRUniqueStringW),
    )

class NETLOGONGetAnyDCNameResponse(Structure):
    structure = (
        ('Buffer',':', ndrutils.NDRUniqueStringW),
    )

class NETLOGONGetSiteName(Structure):
    opnum = 28
    structure = (
        ('ComputerName',':', ndrutils.NDRUniqueStringW),
    )

class NETLOGONGetSiteNameResponse(Structure):
    structure = (
        ('SiteName',':', ndrutils.NDRUniqueStringW),
    )


class NETLOGONGetDcSiteCoverageW(Structure):
    opnum = 38
    structure = (
        ('ServerName',':', ndrutils.NDRUniqueStringW),
    )

class NETLOGONGetDcSiteCoverageWResponse(Structure):
    structure = (
        ('SiteNames',':'),
    )

class NETLOGONServerAuthenticate3(Structure):
    opnum = 26
    structure = (
        ('PrimaryName',':', ndrutils.NDRUniqueStringW),
        ('AccountName',':', ndrutils.NDRStringW ),
        ('SecureChannelType','<H=0'),
        ('Pad0', ':'),
        ('ComputerName',':', ndrutils.NDRStringW ),
        ('ClientCredential',':'),
        ('Pad', ':'),
        ('NegotiateFlags','<L=0'),
    )

class NETLOGONServerAuthenticate3Response(Structure):
    structure = (
        ('ServerCredential','8s'),
        ('NegotiateFlags','<L=0'),
        ('AccountRid','<L=0'),
    )

class NETLOGONServerReqChallenge(Structure):
    opnum = 4
    alingment = 4
    structure = (
        ('PrimaryName',':', ndrutils.NDRUniqueStringW),
        ('ComputerName',':', ndrutils.NDRStringW ),
        ('ClientChallenge','8s'),
    )

class NETLOGONServerReqChallengeResponse(Structure):
    structure = (
        ('ServerChallenge','8s'),
    )

class NETLOGONServerGetTrustInfo(Structure):
    opnum = 46
    structure = (
        ('TrustedDcName',':',ndrutils.NDRUniqueStringW),
        ('AccountName',':', ndrutils.NDRStringW),
        ('SecureChannelType','<H=0'),
        ('Pad0', ':'),
        ('ComputerName',':', ndrutils.NDRStringW ),
        ('Authenticator',':', NETLOGON_AUTHENTICATOR),
    )

class NETLOGONServerGetTrustInfoResponse(Structure):
    structure = (
        ('ReturnAuthenticator',':', NETLOGON_AUTHENTICATOR),
        ('EncryptedNewOwfPassword',':', ENCRYPTED_NT_OWF_PASSWORD),
        ('EncryptedOldOwfPassword',':', ENCRYPTED_NT_OWF_PASSWORD),
        ('TrustInfo',':', PNL_GENERIC_RPC_DATA),
    )

class NETLOGONServerPasswordGet(Structure):
    opnum = 31
    structure = (
        ('PrimaryName',':', ndrutils.NDRUniqueStringW),
        ('AccountName',':', ndrutils.NDRStringW),
        ('AccountType','<H=0'),
        ('Pad0', ':'),
        ('ComputerName',':', ndrutils.NDRStringW),
        ('Authenticator',':', NETLOGON_AUTHENTICATOR),
    )

class NETLOGONServerPasswordGetResponse(Structure):
    structure = (
        ('ReturnAuthenticator',':', NETLOGON_AUTHENTICATOR),
        ('EncryptedNtOwfPassword',':', ENCRYPTED_NT_OWF_PASSWORD),
    )

class NETLOGONLogonGetDomainInfo(Structure):
    opnum = 29
    structure = (
        ('ServerName',':', ndrutils.NDRStringW),
        ('ComputerName',':', ndrutils.NDRUniqueStringW),
        ('Authenticator',':', NETLOGON_AUTHENTICATOR),
        ('ReturnAuthenticator',':', NETLOGON_AUTHENTICATOR),
        ('Level','<L=1'),
    )

class NETLOGONLogonGetDomainInfoResponse(Structure):
    structure = (
        ('ReturnAuthenticator',':', NETLOGON_AUTHENTICATOR),
    )

class NETLOGONLogonGetCapabilities(Structure):
    opnum = 21
    structure = (
        ('ServerName',':', ndrutils.NDRStringW),
        ('ComputerName',':', ndrutils.NDRUniqueStringW),
        ('Authenticator',':', NETLOGON_AUTHENTICATOR),
        ('ReturnAuthenticator',':', NETLOGON_AUTHENTICATOR),
        ('Level','<L=1'),
    )

class NETLOGONLogonGetCapabilitiesResponse(Structure):
    structure = (
        ('ReturnAuthenticator',':', NETLOGON_AUTHENTICATOR),
        ('SwitchIs','<L=0'),
        ('ServerCapabilities','<L=0'),
    )
 
class NETLOGONSessionError(Exception):
    
    error_messages = {
    }    

    def __init__( self, error_code):
        Exception.__init__(self)
        self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        if (NETLOGONSessionError.error_messages.has_key(self.error_code)):
            error_msg_short = NETLOGONSessionError.error_messages[self.error_code][0]
            error_msg_verbose = NETLOGONSessionError.error_messages[self.error_code][1] 
            return 'NETLOGON SessionError: code: %s - %s - %s' % (str(self.error_code), error_msg_short, error_msg_verbose)
        elif nt_errors.ERROR_MESSAGES.has_key(self.error_code):
            return 'NETLOGON SessionError: %s(%s)' % (nt_errors.ERROR_MESSAGES[self.error_code])
        else:
            return 'NETLOGON SessionError: unknown error code: %x' % (self.error_code)

class DCERPCNetLogon:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                error_code = unpack("<L", answer[-4:])[0]
                raise NETLOGONSessionError(error_code)  
        return answer

    def NetrServerReqChallenge(self, primaryName='', computerName='X'.encode('utf-16le'), clientChallenge='12345678'):
        """
        receives a client challenge and returns a server challenge

        :param UNICODE primaryName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE computerName: Unicode string that contains the NetBIOS name of the client computer calling this method. The default value would do the work.
        :param string clientChallenge: an 8-byte string representing the client challenge

        :return: returns an NETLOGONServerReqChallengeResponse structure with the server chalenge. Call dump() method to see its contents. On error it raises an exception
        """
        reqChallenge = NETLOGONServerReqChallenge()
        reqChallenge['PrimaryName'] = ndrutils.NDRUniqueStringW()
        reqChallenge['PrimaryName']['Data'] = primaryName+'\x00'.encode('utf-16le')
        reqChallenge['ComputerName'] = ndrutils.NDRStringW()
        reqChallenge['ComputerName'].alignment = 0
        reqChallenge['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        reqChallenge['ClientChallenge'] =  clientChallenge
        packet = self.doRequest(reqChallenge, checkReturn = 1)
        ans = NETLOGONServerReqChallengeResponse(packet)
        return ans

    def NetrServerAuthenticate3(self, primaryName, accountName, secureChannelType, computerName='X'.encode('utf-16le'), clientCredential='', negotiateFlags=''):
        """
        receives a client challenge and returns a server challenge

        :param UNICODE primaryName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE accountName: Unicode string that identifies the name of the account that contains the secret key (password) that is shared between the client and the server
        :param WORD secureChannelType: the channel type requested. See [MS-NRPC] Section 2.2.1.3.13 for valid values
        :param UNICODE computerName: Unicode string that contains the NetBIOS name of the client computer calling this method. The default value would do the work.
        :param STRING clientCredential: the credentials for the accountName. See [MS-NRPC] Section 3.1.4.4 for details on how to craft this field.
        :param INT negotiateFlags: indicates the features supported. See [MS-NRPC] Section 3.1.4.2 for a list of valid flags.

        :return: returns an NETLOGONServerAuthenticate3Response structure including server credentials, account rid and updated negotiate flags. Call dump() method to see its contents. On error it raises an exception
        """
        serverAuthenticate3 = NETLOGONServerAuthenticate3()
        serverAuthenticate3['PrimaryName'] = ndrutils.NDRUniqueStringW()
        serverAuthenticate3['PrimaryName']['Data'] = primaryName+'\x00'.encode('utf-16le')
        serverAuthenticate3['AccountName'] = ndrutils.NDRStringW()
        serverAuthenticate3['AccountName'].alignment = 0
        serverAuthenticate3['AccountName']['Data'] = accountName+'\x00'.encode('utf-16le')
        serverAuthenticate3['SecureChannelType'] = secureChannelType
        # So.. We have to have the buffer aligned before Computer Name, there we go. The "2" there belongs to the size
        # of SecureChannelType
        serverAuthenticate3['Pad0'] = '\x00'*((len(serverAuthenticate3['AccountName']['Data'])+2) % 4)
        serverAuthenticate3['ComputerName'] = ndrutils.NDRStringW()
        serverAuthenticate3['ComputerName'].alignment = 0
        serverAuthenticate3['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        serverAuthenticate3['ClientCredential'] = clientCredential
        serverAuthenticate3['Pad'] = '\x00'*(len(serverAuthenticate3['ComputerName']['Data']) % 4)
        serverAuthenticate3['NegotiateFlags'] = negotiateFlags

        packet = self.doRequest(serverAuthenticate3, checkReturn = 1)
        ans = NETLOGONServerAuthenticate3Response(packet)
        return ans

    def DsrGetDcSiteCoverageW(self, serverName=''):
        """
        returns a list of sites covered by a domain controller

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well

        :return: 
        """
        getDCSite = NETLOGONGetDcSiteCoverageW()
        getDCSite['ServerName'] = ndrutils.NDRUniqueStringW()
        getDCSite['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        getDCSite['ServerName'].alignment = 0

        packet = self.doRequest(getDCSite, checkReturn = 1)
        ans = NETLOGONGetDcSiteCoverageWResponse(packet)
        return ans

    def DsrGetSiteName(self, computerName=''):
        """
        returns the site name for the specified computer that receives this call

        :param UNICODE computerName: the NetBIOS name of the remote machine. '' would do the work as well

        :return: returns an NETLOGONGetSiteNameResponse structure including the server's site name. Call dump() method to see its contents. On error it raises an exception

        """
        getSiteName = NETLOGONGetSiteName()
        getSiteName['ComputerName'] = ndrutils.NDRUniqueStringW()
        getSiteName['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        getSiteName['ComputerName'].alignment = 0

        packet = self.doRequest(getSiteName, checkReturn = 1)
        ans = NETLOGONGetSiteNameResponse(packet)
        return ans

    def DsrNetrGetAnyDCName(self, serverName='', domainName=''):
        """
        retrieves the name of a domain controller in the specified primary or directly trusted domain

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE domainName: the name of the primary or directly trusted domain. If the string is NULL or empty (that is, the first character in the string is the null-terminator character), the primary domain name (3) is assumed

        :return: returns an NETLOGONGetAnyDCNameResponse structure including the server's NetBIOS name. Call dump() method to see its contents. On error it raises an exception

        """
        getAnyDCName = NETLOGONGetAnyDCName()
        getAnyDCName['ServerName'] = ndrutils.NDRUniqueStringW()
        getAnyDCName['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        getAnyDCName['ServerName'].alignment = 4
        getAnyDCName['DomainName'] = ndrutils.NDRUniqueStringW()
        getAnyDCName['DomainName']['Data'] = domainName+'\x00'.encode('utf-16le')
        getAnyDCName['DomainName'].alignment = 0

        packet = self.doRequest(getAnyDCName, checkReturn = 1)
        ans = NETLOGONGetAnyDCNameResponse(packet)
        return ans

    def NetrGetDCName(self, serverName='', domainName=''):
        """
        retrieves the NetBIOS name of the PDC for the specified domain
 
        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE domainName: Unicode string that specifies the domain name 

        :return: returns an NETLOGONGetDCNameResponse structure including the server's NetBIOS name. Call dump() method to see its contents. On error it raises an exception

        """
        getDCName = NETLOGONGetDCName()
        getDCName['ServerName'] = ndrutils.NDRStringW()
        getDCName['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        getDCName['ServerName'].alignment = 4
        getDCName['DomainName'] = ndrutils.NDRUniqueStringW()
        getDCName['DomainName']['Data'] = domainName+'\x00'.encode('utf-16le')
        getDCName['DomainName'].alignment = 0

        packet = self.doRequest(getDCName, checkReturn = 1)
        ans = NETLOGONGetDCNameResponse(packet)
        return ans

    def NetrServerGetTrustInfo(self, trustedDcName, accountName, secureChannelType, computerName='X'.encode('utf-16le'), authenticator=None):
        """
        returns an information block from a specified server. The information includes encrypted current and previous passwords for a particular account and additional trust data. The account name requested MUST be the name used when the secure channel was created, unless the method is called on a PDC by a domain controller, in which case it can be any valid account name

        :param UNICODE trustedDcName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE accountName: Unicode string that identifies the name of the account
        :param WORD secureChannelType: the channel type requested. See [MS-NRPC] Section 2.2.1.3.13 for valid values
        :param UNICODE computerName: Unicode string that contains the NetBIOS name of the client computer calling this method. The default value would do the work.
        :param NETLOGON_AUTHENTICATOR authenticator: the NETLOGON_AUTHENTICATOR for this call. For more information about how to compute such value, check [MS-NRPC] Section 3.1.4.5

        :return: returns a NETLOGONServerGetTrustInfoResponse structure. Call dump() method to see its contents. For understanding the meaning of each field, check [MS-NRPC] Section 3.5.4.7.6
        """

        getTrustInfo = NETLOGONServerGetTrustInfo()
        getTrustInfo['TrustedDcName'] = ndrutils.NDRUniqueStringW()
        getTrustInfo['TrustedDcName']['Data'] = trustedDcName+'\x00'.encode('utf-16le')
        getTrustInfo['TrustedDcName'].alignment = 4

        getTrustInfo['AccountName'] = ndrutils.NDRStringW()
        getTrustInfo['AccountName'].alignment = 0
        getTrustInfo['AccountName']['Data'] = accountName+'\x00'.encode('utf-16le')
        getTrustInfo['SecureChannelType'] = secureChannelType
        # So.. We have to have the buffer aligned before Computer Name, there we go. The "2" there belongs to the size
        # of SecureChannelType
        getTrustInfo['Pad0'] = '\x00'*((len(getTrustInfo['AccountName']['Data'])+2) % 4)
        getTrustInfo['ComputerName'] = ndrutils.NDRStringW()
        getTrustInfo['ComputerName'].alignment = 4
        getTrustInfo['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        getTrustInfo['Authenticator'] = authenticator

        packet = self.doRequest(getTrustInfo, checkReturn = 1)
        ans = NETLOGONServerGetTrustInfoResponse(packet)
        return ans

    def NetrServerPasswordGet(self, primaryName, accountName, accountType, computerName='X'.encode('utf-16le'), authenticator=None):
        """
        allows a BDC to get a machine account password from the DC with the PDC role in the domain

        :param UNICODE primaryName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE accountName: Unicode string that identifies the name of the account
        :param WORD accountType: the channel type requested. See [MS-NRPC] Section 2.2.1.3.13 for valid values
        :param UNICODE computerName: Unicode string that contains the NetBIOS name of the client computer calling this method. 
        :param NETLOGON_AUTHENTICATOR authenticator: the NETLOGON_AUTHENTICATOR for this call. For more information about how to compute such value, check [MS-NRPC] Section 3.1.4.5

        :return: returns a NETLOGONServerPasswordResponse structure. Call dump() method to see its contents. For understanding the meaning of each field, check [MS-NRPC] Section 3.5.4.7.6
        """
        passwordGet = NETLOGONServerPasswordGet()
        passwordGet['PrimaryName'] = ndrutils.NDRUniqueStringW()
        passwordGet['PrimaryName']['Data'] = primaryName+'\x00'.encode('utf-16le')
        passwordGet['PrimaryName'].alignment = 4

        passwordGet['AccountName'] = ndrutils.NDRStringW()
        passwordGet['AccountName'].alignment = 0
        passwordGet['AccountName']['Data'] = accountName+'\x00'.encode('utf-16le')

        passwordGet['AccountType'] = accountType
        # So.. We have to have the buffer aligned before Computer Name, there we go. The "2" there belongs to the size
        # of SecureChannelType

        passwordGet['Pad0'] = '\x00'*((len(passwordGet['AccountName']['Data'])+2) % 4)
        passwordGet['ComputerName'] = ndrutils.NDRStringW()
        passwordGet['ComputerName'].alignment = 4
        passwordGet['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        passwordGet['Authenticator'] = authenticator

        packet = self.doRequest(passwordGet, checkReturn = 1)
        ans = NETLOGONServerPasswordGetResponse(packet)
        return ans

    def NetrLogonGetDomainInfo(self, serverName, computerName='X'.encode('utf-16le'), authenticator=None):
        """
        returns information that describes the current domain to which the specified client belongs

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE computerName: Unicode string that contains the NetBIOS name of the client computer calling this method. The default value would do the work.
        :param NETLOGON_AUTHENTICATOR authenticator: the NETLOGON_AUTHENTICATOR for this call. For more information about how to compute such value, check [MS-NRPC] Section 3.1.4.5

        :return: returns a structure. Call dump() method to see its contents. For understanding the meaning of each field, check [MS-NRPC] Section 
        """
        ### NOT FINISHED YET
        getDomainInfo = NETLOGONLogonGetDomainInfo()
        getDomainInfo['ServerName'] = ndrutils.NDRStringW()
        getDomainInfo['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        getDomainInfo['ServerName'].alignment = 4

        getDomainInfo['ComputerName'] = ndrutils.NDRUniqueStringW()
        getDomainInfo['ComputerName'].alignment = 4
        getDomainInfo['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        getDomainInfo['Authenticator'] = authenticator
        getDomainInfo['ReturnAuthenticator'] = NETLOGON_AUTHENTICATOR()

        packet = self.doRequest(getDomainInfo, checkReturn = 1)
        ans = NETLOGONLogonGetDomainInfoResponse(packet)
        return ans

    def NetrLogonGetCapabilities(self, serverName, computerName='X'.encode('utf-16le'), authenticator = None):
        """
        used by clients to confirm the server capabilities after a secure channel has been established ( only NETLOGON_INFO_1 level supported)

        :param UNICODE serverName: the NetBIOS name of the remote machine. '' would do the work as well
        :param UNICODE computerName: Unicode string that contains the NetBIOS name of the client computer calling this method. The default value would do the work.
        :param NETLOGON_AUTHENTICATOR authenticator: the NETLOGON_AUTHENTICATOR for this call. For more information about how to compute such value, check [MS-NRPC] Section 3.1.4.5

        :return: returns a NETLOGONLogonGetCapabilitiesResponse structure. Call dump() method to see its contents. 
        """
        getCapabilities = NETLOGONLogonGetCapabilities()
        getCapabilities['ServerName'] = ndrutils.NDRStringW()
        getCapabilities['ServerName']['Data'] = serverName+'\x00'.encode('utf-16le')
        getCapabilities['ServerName'].alignment = 4

        getCapabilities['ComputerName'] = ndrutils.NDRUniqueStringW()
        getCapabilities['ComputerName'].alignment = 4
        getCapabilities['ComputerName']['Data'] = computerName+'\x00'.encode('utf-16le')
        getCapabilities['Authenticator'] = authenticator
        getCapabilities['ReturnAuthenticator'] = NETLOGON_AUTHENTICATOR()

        packet = self.doRequest(getCapabilities, checkReturn = 1)
        ans = NETLOGONLogonGetCapabilitiesResponse(packet)
        return ans


