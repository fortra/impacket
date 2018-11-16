###############################################################################
#  Tested so far: 
#
# DsrGetDcNameEx2
# DsrGetDcNameEx
# DsrGetDcName
# NetrGetDCName
# NetrGetAnyDCName
# DsrGetSiteName
# DsrGetDcSiteCoverageW
# DsrAddressToSiteNamesW
# DsrAddressToSiteNamesExW
# DsrDeregisterDnsHostRecords
# NetrServerReqChallenge
# NetrServerAuthenticate3
# NetrServerAuthenticate2
# NetrServerAuthenticate
# NetrServerTrustPasswordsGet
# NetrLogonGetCapabilities
# NetrDatabaseDeltas
# NetrDatabaseSync2
# NetrDatabaseSync
# DsrEnumerateDomainTrusts
# NetrEnumerateTrustedDomainsEx
# NetrEnumerateTrustedDomains
# NetrGetForestTrustInformation
# DsrGetForestTrustInformation
# NetrServerGetTrustInfo
# NetrLogonGetTrustRid
# NetrLogonComputeServerDigest
# NetrLogonComputeClientDigest
# NetrLogonSendToSam
# NetrLogonSetServiceBits
# NetrLogonGetTimeServiceParentDomain
# NetrLogonControl2Ex
# NetrLogonControl2
# NetrLogonControl
# NetrLogonUasLogon
# NetrLogonGetDomainInfo
#
#  Not yet:
# 
# DSRUpdateReadOnlyServerDnsRecords
# NetrServerPasswordGet
# NetrLogonSamLogonEx
# NetrLogonSamLogonWithFlags
# NetrLogonSamLogon
# NetrLogonSamLogoff
# NetrDatabaseRedo
# 
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser
from struct import pack, unpack
from binascii import unhexlify

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, nrpc
from impacket.dcerpc.v5.dtypes import NULL
from impacket import ntlm


class NRPCTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.serverName + '\x00', '12345678')
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        self.sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, NULL, self.username + '\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,self.serverName + '\x00',ppp, 0x600FFFFF )
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise

        self.clientStoredCredential = pack('<Q', unpack('<Q',ppp)[0] + 10)

        #dce.set_auth_type(RPC_C_AUTHN_NETLOGON)
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        #dce2 = dce.alter_ctx(nrpc.MSRPC_UUID_NRPC)
        #dce2.set_session_key(self.sessionKey)

        return dce, rpctransport


    def update_authenticator(self):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(self.clientStoredCredential, self.sessionKey)
        authenticator['Timestamp'] = 10
        return authenticator

    def test_DsrGetDcNameEx2(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrGetDcNameEx2()
        request['ComputerName'] = NULL
        request['AccountName'] = 'Administrator\x00'
        request['AllowableAccountControlBits'] = 1 << 9
        request['DomainName'] = NULL
        request['DomainGuid'] = NULL
        request['SiteName'] = NULL
        request['Flags'] = 0
  
        resp = dce.request(request)
        resp.dump()

    def test_hDsrGetDcNameEx2(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hDsrGetDcNameEx2(dce, NULL, 'Administrator\x00', 1 << 9, NULL, NULL, NULL, 0)
        resp.dump()

    def test_DsrGetDcNameEx(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrGetDcNameEx()
        request['ComputerName'] = NULL
        request['DomainName'] = NULL
        request['DomainGuid'] = NULL
        request['SiteName'] = NULL
        request['Flags'] = 0
  
        resp = dce.request(request)
        resp.dump()

    def test_hDsrGetDcNameEx(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hDsrGetDcNameEx(dce, NULL, NULL, NULL, NULL, 0)
        resp.dump()

    def test_DsrGetDcName(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrGetDcName()
        request['ComputerName'] = NULL
        request['DomainName'] = NULL
        request['DomainGuid'] = NULL
        request['SiteGuid'] = NULL
        request['Flags'] = 0
  
        resp = dce.request(request)
        resp.dump()

    def test_hDsrGetDcName(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hDsrGetDcName(dce, NULL, NULL, NULL, NULL, 0)
        resp.dump()

    def test_NetrGetDCName(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrGetDCName()
        request['ServerName'] = '\x00'*20
        request['DomainName'] = self.domain + '\x00'
  
        resp = dce.request(request)
        resp.dump()

    def test_hNetrGetDCName(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrGetDCName(dce, '\x00'*20, self.domain + '\x00')
        resp.dump()

    def test_NetrGetAnyDCName(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrGetAnyDCName()
        request['ServerName'] = NULL
        request['DomainName'] = self.domain + '\x00'
  
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NO_SUCH_DOMAIN') < 0:
                raise

    def test_hNetrGetAnyDCName(self):
        dce, rpctransport = self.connect()
        try:
            resp = nrpc.hNetrGetAnyDCName(dce, '\x00'*20, self.domain + '\x00')
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NO_SUCH_DOMAIN') < 0:
                raise

    def test_DsrGetSiteName(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrGetSiteName()
        request['ComputerName'] = NULL
  
        resp = dce.request(request)
        resp.dump()

    def test_hDsrGetSiteName(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hDsrGetSiteName(dce, NULL)
        resp.dump()

    def test_DsrGetDcSiteCoverageW(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrGetDcSiteCoverageW()
        request['ServerName'] = NULL
  
        resp = dce.request(request)
        resp.dump()

    def test_hDsrGetDcSiteCoverageW(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hDsrGetDcSiteCoverageW(dce, NULL)
        resp.dump()

    def test_DsrAddressToSiteNamesW(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrAddressToSiteNamesW()
        request['ComputerName'] = NULL
        request['EntryCount'] = 1
        addr = nrpc.IPv4Address()
        import socket
        addr['AddressFamily'] = socket.AF_INET
        addr['Port'] = 0
        addr['Address'] = unpack('>L', socket.inet_aton(self.machine))[0]
        socketAddress = nrpc.NL_SOCKET_ADDRESS()
        socketAddress['lpSockaddr'] = list(str(addr))
        socketAddress['iSockaddrLength'] = len(str(addr))
        request['SocketAddresses'].append(socketAddress)
  
        resp = dce.request(request)
        resp.dump()

    def test_hDsrAddressToSiteNamesW(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrAddressToSiteNamesW()
        request['ComputerName'] = NULL
        request['EntryCount'] = 1
        addr = nrpc.IPv4Address()
        import socket
        addr['AddressFamily'] = socket.AF_INET
        addr['Port'] = 0
        addr['Address'] = unpack('>L', socket.inet_aton(self.machine))[0]
        socketAddress = nrpc.NL_SOCKET_ADDRESS()
        socketAddress['lpSockaddr'] = list(str(addr))
        socketAddress['iSockaddrLength'] = len(str(addr))
        request['SocketAddresses'].append(socketAddress)
  
        resp = dce.request(request)
        resp.dump()

    def test_DsrAddressToSiteNamesExW(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrAddressToSiteNamesExW()
        request['ComputerName'] = NULL
        request['EntryCount'] = 1
        addr = nrpc.IPv4Address()
        import socket
        addr['AddressFamily'] = socket.AF_INET
        addr['Port'] = 0
        addr['Address'] = unpack('>L', socket.inet_aton(self.machine))[0]
        socketAddress = nrpc.NL_SOCKET_ADDRESS()
        socketAddress['lpSockaddr'] = list(str(addr))
        socketAddress['iSockaddrLength'] = len(str(addr))
        request['SocketAddresses'].append(socketAddress)
  
        resp = dce.request(request)
        resp.dump()

    def test_DsrDeregisterDnsHostRecords(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrDeregisterDnsHostRecords()
        request['ServerName'] = NULL
        request['DnsDomainName'] = 'BETUS\x00'
        request['DomainGuid'] = NULL
        request['DsaGuid'] = NULL
        request['DnsHostName'] = 'BETUS\x00'
  
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrServerReqChallenge_NetrServerAuthenticate3(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientChallenge'] = '12345678'
  
        resp = dce.request(request)
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        request = nrpc.NetrServerAuthenticate3()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.username + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientCredential'] = ppp
        request['NegotiateFlags'] = 0x600FFFFF
  
        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerReqChallenge_hNetrServerAuthenticate3(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerReqChallenge(dce, NULL,  self.serverName + '\x00','12345678' )
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        resp = nrpc.hNetrServerAuthenticate3(dce, NULL,self.username + '\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
,self.serverName + '\x00', ppp,0x600FFFFF )
        resp.dump()

    def test_NetrServerReqChallenge_hNetrServerAuthenticate2(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientChallenge'] = '12345678'
  
        resp = dce.request(request)
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        resp = nrpc.hNetrServerAuthenticate2(dce, NULL,self.username + '\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
,self.serverName + '\x00', ppp,0x600FFFFF )
        resp.dump()

    def test_hNetrServerReqChallenge_NetrServerAuthenticate2(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerReqChallenge(dce, NULL,  self.serverName + '\x00','12345678' )
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        request = nrpc.NetrServerAuthenticate2()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.username + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientCredential'] = ppp
        request['NegotiateFlags'] = 0x600FFFFF
  
        resp = dce.request(request)
        resp.dump()

    def test_NetrServerReqChallenge_NetrServerAuthenticate(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientChallenge'] = '12345678'
  
        resp = dce.request(request)
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        request = nrpc.NetrServerAuthenticate()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.username + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientCredential'] = ppp
  
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise

    def test_hNetrServerReqChallenge_hNetrServerAuthenticate(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerReqChallenge(dce, NULL,  self.serverName + '\x00','12345678' )
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        if self.hashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.hashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        resp.dump()
        try:
            resp = nrpc.hNetrServerAuthenticate(dce, NULL,self.username + '\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel ,self.serverName + '\x00', ppp)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise

    def test_NetrServerPasswordGet(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerPasswordGet()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.username + '\x00'
        request['AccountType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()

        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise

    def test_hNetrServerPasswordGet(self):
        dce, rpctransport = self.connect()
        try:
            resp = nrpc.hNetrServerPasswordGet(dce, NULL, self.username + '\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel ,self.serverName + '\x00', self.update_authenticator())
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise

    def test_NetrServerTrustPasswordsGet(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerTrustPasswordsGet()
        request['TrustedDcName'] = NULL
        request['AccountName'] = self.username + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()

        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerTrustPasswordsGet(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerTrustPasswordsGet(dce, NULL, self.username,nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel ,self.serverName, self.update_authenticator())
        resp.dump()

    def test_NetrLogonGetDomainInfo(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonGetDomainInfo()
        request['ServerName'] = '\x00'*20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['Level'] = 1
        request['WkstaBuffer']['tag'] = 1
        request['WkstaBuffer']['WorkstationInfo']['DnsHostName'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['SiteName'] = NULL
        request['WkstaBuffer']['WorkstationInfo']['OsName'] = ''
        request['WkstaBuffer']['WorkstationInfo']['Dummy1'] = NULL 
        request['WkstaBuffer']['WorkstationInfo']['Dummy2'] = NULL  
        request['WkstaBuffer']['WorkstationInfo']['Dummy3'] = NULL 
        request['WkstaBuffer']['WorkstationInfo']['Dummy4'] = NULL  
        resp = dce.request(request)
        resp.dump()

    def test_hNetrLogonGetDomainInfo(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrLogonGetDomainInfo(dce,'\x00'*20, self.serverName,self.update_authenticator(), 0, 1)
        resp.dump()

    def test_NetrLogonGetCapabilities(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonGetCapabilities()
        request['ServerName'] = '\x00'*20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['QueryLevel'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hNetrLogonGetCapabilities(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrLogonGetCapabilities(dce,'\x00'*20, self.serverName + '\x00',self.update_authenticator(), 0)
        resp.dump()

    def test_NetrLogonSamLogonEx(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonSamLogonEx()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = self.serverName + '\x00'
        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain 
        request['LogonInformation']['LogonInteractive']['Identity']['ParameterControl'] = 2 + 2**14 + 2**7 + 2**9 + 2**5 + 2**11
        request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username 
        request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        else:
            lmhash = ntlm.LMOWFv1(self.password)
            nthash = ntlm.NTOWFv1(self.password)
        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        rc4 = ARC4.new(self.sessionKey)
        lmhash = rc4.encrypt(lmhash)
        rc4 = ARC4.new(self.sessionKey)
        nthash = rc4.encrypt(nthash)

        request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = lmhash
        request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = nthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        request['ExtraFlags'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_NetrLogonSamLogonWithFlags(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = self.serverName + '\x00'
        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain
        request['LogonInformation']['LogonInteractive']['Identity']['ParameterControl'] = 2 + 2**14 + 2**7 + 2**9 + 2**5 + 2**11
        request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username
        request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        else:
            lmhash = ntlm.LMOWFv1(self.password)
            nthash = ntlm.NTOWFv1(self.password)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        rc4 = ARC4.new(self.sessionKey)
        lmhash = rc4.encrypt(lmhash)
        rc4 = ARC4.new(self.sessionKey)
        nthash = rc4.encrypt(nthash)

        request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = lmhash
        request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = nthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_USER') < 0:
                raise

    def test_NetrLogonSamLogon(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonSamLogon()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = self.serverName + '\x00'
        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain
        request['LogonInformation']['LogonInteractive']['Identity']['ParameterControl'] = 2 
        request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username
        request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        else:
            lmhash = ntlm.LMOWFv1(self.password)
            nthash = ntlm.NTOWFv1(self.password)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print "Warning: You don't have any crypto installed. You need PyCrypto"
            print "See https://www.pycrypto.org/"

        rc4 = ARC4.new(self.sessionKey)
        lmhash = rc4.encrypt(lmhash)
        rc4 = ARC4.new(self.sessionKey)
        nthash = rc4.encrypt(nthash)

        request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = lmhash
        request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = nthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo2
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_SUCH_USER') < 0:
                raise

    def test_NetrDatabaseDeltas(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrDatabaseDeltas()
        request['PrimaryName'] = '\x00'*20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['DatabaseID'] = 0
        #request['DomainModifiedCount'] = 1
        request['PreferredMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDatabaseSync2(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrDatabaseSync2()
        request['PrimaryName'] = '\x00'*20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['DatabaseID'] = 0
        request['RestartState'] = nrpc.SYNC_STATE.NormalState
        request['SyncContext'] = 0
        request['PreferredMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_NetrDatabaseSync(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrDatabaseSync()
        request['PrimaryName'] = '\x00'*20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['DatabaseID'] = 0
        request['SyncContext'] = 0
        request['PreferredMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def te_NetrDatabaseRedo(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrDatabaseRedo()
        request['PrimaryName'] = '\x00'*20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ChangeLogEntry'] = 0
        request['ChangeLogEntrySize'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_DsrEnumerateDomainTrusts(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrEnumerateDomainTrusts()
        request['ServerName'] = NULL
        request['Flags'] = 1
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_NetrEnumerateTrustedDomainsEx(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrEnumerateTrustedDomainsEx()
        request['ServerName'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_NetrEnumerateTrustedDomains(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrEnumerateTrustedDomains()
        request['ServerName'] = NULL
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_SUPPORTED') < 0:
                raise

    def test_NetrGetForestTrustInformation(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrGetForestTrustInformation()
        request['ServerName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['Flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NOT_IMPLEMENTED') < 0:
                raise

    def test_DsrGetForestTrustInformation(self):
        dce, rpctransport = self.connect()
        request = nrpc.DsrGetForestTrustInformation()
        request['ServerName'] = NULL
        request['TrustedDomainName'] = self.domain + '\x00'
        request['Flags'] = 0
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NO_SUCH_DOMAIN') < 0:
                raise

    def test_NetrServerGetTrustInfo(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerGetTrustInfo()
        request['TrustedDcName'] = NULL
        request['AccountName'] = self.username+ '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NO_SUCH_DOMAIN') < 0:
                raise

    def test_hNetrServerGetTrustInfo(self):
        dce, rpctransport = self.connect()
        try:
            resp = nrpc.hNetrServerGetTrustInfo(dce, NULL, self.username, nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,self.serverName,self.update_authenticator())
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NO_SUCH_DOMAIN') < 0:
                raise

    def test_NetrLogonGetTrustRid(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonGetTrustRid()
        request['ServerName'] = NULL
        request['DomainName'] = self.domain+ '\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonComputeServerDigest(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonComputeServerDigest()
        request['ServerName'] = NULL
        request['Rid'] = 1001
        request['Message'] = 'HOLABETOCOMOANDAS\x00'
        request['MessageSize'] = len('HOLABETOCOMOANDAS\x00')
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonComputeClientDigest(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonComputeClientDigest()
        request['ServerName'] = NULL
        request['DomainName'] = self.domain + '\x00'
        request['Message'] = 'HOLABETOCOMOANDAS\x00'
        request['MessageSize'] = len('HOLABETOCOMOANDAS\x00')
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonSendToSam(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonSendToSam()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName+ '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['OpaqueBuffer'] = 'HOLABETOCOMOANDAS\x00'
        request['OpaqueBufferSize'] = len('HOLABETOCOMOANDAS\x00')
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise

    def test_NetrLogonSetServiceBits(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonSetServiceBits()
        request['ServerName'] = NULL
        request['ServiceBitsOfInterest'] = 1 << 7
        request['ServiceBits'] = 1 << 7
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def te_NetrLogonGetTimeServiceParentDomain(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonGetTimeServiceParentDomain()
        request['ServerName'] = self.domain + '\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonControl2Ex(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonControl2Ex()
        request['ServerName'] = NULL
        request['FunctionCode'] = nrpc.NETLOGON_CONTROL_FIND_USER
        request['QueryLevel'] = 4
        request['Data']['tag'] = 8
        request['Data']['UserName'] = 'normaluser7\x00'
        
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonControl2(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonControl2()
        request['ServerName'] = NULL
        request['FunctionCode'] = nrpc.NETLOGON_CONTROL_FIND_USER
        request['QueryLevel'] = 4
        request['Data']['tag'] = 8
        request['Data']['UserName'] = 'normaluser7\x00'
        
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonControl(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonControl()
        request['ServerName'] = NULL
        request['FunctionCode'] = nrpc.NETLOGON_CONTROL_QUERY
        request['QueryLevel'] = 4
        request['Data']['tag'] = 65534
        request['Data']['DebugFlag'] = 1
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_LEVEL') < 0:
                raise

    def test_NetrLogonUasLogon(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonUasLogon()
        request['ServerName'] = NULL
        request['UserName'] = 'normaluser7\x00'
        request['Workstation'] = self.serverName + '\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

    def test_NetrLogonUasLogoff(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonUasLogoff()
        request['ServerName'] = NULL
        request['UserName'] = 'normaluser7\x00'
        request['Workstation'] = self.serverName + '\x00'
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') < 0:
                raise

class TCPTransport(NRPCTests):
    def setUp(self):
        NRPCTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        #print epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        self.stringBinding = epm.hept_map(self.machine, nrpc.MSRPC_UUID_NRPC, protocol = 'ncacn_ip_tcp')

class SMBTransport(NRPCTests):
    def setUp(self):
        NRPCTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\netlogon]' % self.machine

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport))
    unittest.TextTestRunner(verbosity=1).run(suite)
