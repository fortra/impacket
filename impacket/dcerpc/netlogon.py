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
from impacket import nt_errors

MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB', '1.0'))

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




