# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)DsrGetDcNameEx2
#   (h)DsrGetDcNameEx
#   (h)DsrGetDcName
#   (h)NetrGetDCName
#   (h)NetrGetAnyDCName
#   (h)DsrGetSiteName
#   (h)DsrGetDcSiteCoverageW
#   (h)DsrAddressToSiteNamesW
#   DsrAddressToSiteNamesExW
#   DsrDeregisterDnsHostRecords
#   (h)NetrServerReqChallenge
#   (h)NetrServerAuthenticate3
#   (h)NetrServerAuthenticate2
#   (h)NetrServerAuthenticate
#   (h)NetrServerPasswordGet
#   (h)NetrServerTrustPasswordsGet
#   (h)NetrServerPasswordSet2
#   (h)NetrLogonGetDomainInfo
#   (h)NetrLogonGetCapabilities
#   NetrLogonSamLogonEx
#   NetrLogonSamLogonWithFlags
#   NetrLogonSamLogon
#   NetrDatabaseDeltas
#   NetrDatabaseSync2
#   NetrDatabaseSync
#   NetrDatabaseRedo
#   DsrEnumerateDomainTrusts
#   NetrEnumerateTrustedDomainsEx
#   NetrEnumerateTrustedDomains
#   NetrGetForestTrustInformation
#   DsrGetForestTrustInformation
#   (h)NetrServerGetTrustInfo
#   NetrLogonGetTrustRid
#   NetrLogonComputeServerDigest
#   NetrLogonComputeClientDigest
#   NetrLogonSendToSam
#   NetrLogonSetServiceBits
#   NetrLogonGetTimeServiceParentDomain
#   NetrLogonControl2Ex
#   NetrLogonControl2
#   NetrLogonControl
#   NetrLogonUasLogon
#   NetrLogonUasLogoff
#
# Not yet:
#   DSRUpdateReadOnlyServerDnsRecords
#   NetrLogonSamLogoff
#
import pytest
import unittest
from struct import pack, unpack
from tests.dcerpc import DCERPCTests
from six import assertRaisesRegex

from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL
from impacket import ntlm


class NRPCTests(DCERPCTests):
    iface_uuid = nrpc.MSRPC_UUID_NRPC
    authn = True
    machine_account = True

    def authenticate(self, dce):
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.serverName + '\x00', b'12345678')
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        self.sessionKey = nrpc.ComputeSessionKeyStrongKey('', b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, NULL, self.machine_user + '\x00',
                                                 nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                                 self.serverName + '\x00', ppp, 0x600FFFFF)
            resp.dump()
        except nrpc.DCERPCSessionError as e:
            if str(e).find("STATUS_DOWNGRADE_DETECTED") < 0:
                raise

        self.clientStoredCredential = pack('<Q', unpack('<Q', ppp)[0] + 10)

        # dce.set_auth_type(RPC_C_AUTHN_NETLOGON)
        # dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        # dce2 = dce.alter_ctx(nrpc.MSRPC_UUID_NRPC)
        # dce2.set_session_key(self.sessionKey)

    def update_authenticator(self):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(self.clientStoredCredential, self.sessionKey)
        authenticator['Timestamp'] = 10
        return authenticator

    def test_DsrGetDcNameEx2(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
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
        request['ServerName'] = '\x00' * 20
        request['DomainName'] = self.domain.split('.')[0] + '\x00'

        resp = dce.request(request)
        resp.dump()

    def test_hNetrGetDCName(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrGetDCName(dce, '\x00' * 20, self.domain.split('.')[0] + '\x00')
        resp.dump()

    def test_NetrGetAnyDCName(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrGetAnyDCName()
        request['ServerName'] = NULL
        request['DomainName'] = self.domain + '\x00'

        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_SUCH_DOMAIN"):
            dce.request(request)

    def test_hNetrGetAnyDCName(self):
        dce, rpctransport = self.connect()
        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_SUCH_DOMAIN"):
            nrpc.hNetrGetAnyDCName(dce, '\x00' * 20, self.domain + '\x00')

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
        socketAddress['lpSockaddr'] = list(addr.getData())
        socketAddress['iSockaddrLength'] = len(addr.getData())
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
        socketAddress['lpSockaddr'] = list(addr.getData())
        socketAddress['iSockaddrLength'] = len(addr.getData())
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
        socketAddress['lpSockaddr'] = list(addr.getData())
        socketAddress['iSockaddrLength'] = len(addr.getData())
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

        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrServerReqChallenge_NetrServerAuthenticate3(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientChallenge'] = b'12345678'

        resp = dce.request(request)
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        request = nrpc.NetrServerAuthenticate3()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientCredential'] = ppp
        request['NegotiateFlags'] = 0x600FFFFF

        resp = dce.request(request)
        resp.dump()

    def test_hNetrServerReqChallenge_hNetrServerAuthenticate3(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.serverName + '\x00', b'12345678')
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        resp = nrpc.hNetrServerAuthenticate3(dce, NULL, self.machine_user + '\x00',
                                             nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                             self.serverName + '\x00', ppp, 0x600FFFFF)
        resp.dump()

    def test_NetrServerReqChallenge_hNetrServerAuthenticate2(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrServerReqChallenge()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientChallenge'] = b'12345678'

        resp = dce.request(request)
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        resp = nrpc.hNetrServerAuthenticate2(dce, NULL, self.machine_user + '\x00',
                                             nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                             self.serverName + '\x00', ppp, 0x600FFFFF)
        resp.dump()

    def test_hNetrServerReqChallenge_NetrServerAuthenticate2(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.serverName + '\x00', b'12345678')
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        request = nrpc.NetrServerAuthenticate2()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
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
        request['ClientChallenge'] = b'12345678'

        resp = dce.request(request)
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        request = nrpc.NetrServerAuthenticate()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['ClientCredential'] = ppp

        with assertRaisesRegex(self, DCERPCException, "STATUS_DOWNGRADE_DETECTED"):
            dce.request(request)

    def test_hNetrServerReqChallenge_hNetrServerAuthenticate(self):
        dce, rpctransport = self.connect()
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.serverName + '\x00', b'12345678')
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        sessionKey = nrpc.ComputeSessionKeyStrongKey(self.password, b'12345678', serverChallenge, bnthash)

        ppp = nrpc.ComputeNetlogonCredential(b'12345678', sessionKey)

        resp.dump()
        with assertRaisesRegex(self, DCERPCException, "STATUS_DOWNGRADE_DETECTED"):
            nrpc.hNetrServerAuthenticate(dce, NULL, self.machine_user + '\x00',
                                         nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                         self.serverName + '\x00', ppp)

    def test_NetrServerPasswordGet(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrServerPasswordGet()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
        request['AccountType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()

        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            dce.request(request)

    def test_hNetrServerPasswordGet(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            nrpc.hNetrServerPasswordGet(dce, NULL, self.machine_user + '\x00',
                                        nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                        self.serverName + '\x00', self.update_authenticator())

    def test_NetrServerTrustPasswordsGet(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrServerTrustPasswordsGet()
        request['TrustedDcName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()

        resp = dce.request(request)
        resp.dump()

    @pytest.mark.xfail
    def test_hNetrServerTrustPasswordsGet(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        resp = nrpc.hNetrServerTrustPasswordsGet(dce, NULL, self.machine_user,
                                                 nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                                 self.serverName, self.update_authenticator())
        resp.dump()

    def test_NetrServerPasswordSet2(self):
        # It doesn't do much, should throw STATUS_ACCESS_DENIED
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrServerPasswordSet2()
        request['PrimaryName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        cnp = nrpc.NL_TRUST_PASSWORD()
        cnp['Buffer'] = b'\x00'*512
        cnp['Length'] = 0x8

        request['ClearNewPassword'] = cnp.getData()
        #request['ClearNewPassword'] = nrpc.NL_TRUST_PASSWORD()
        #request['ClearNewPassword']['Buffer'] = b'\x00' *512
        #request['ClearNewPassword']['Length'] = 0x8
        request.dump()

        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            dce.request(request)
            
    def test_hNetrServerPasswordSet2(self):
        # It doesn't do much, should throw STATUS_ACCESS_DENIED
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        cnp = nrpc.NL_TRUST_PASSWORD()
        cnp['Buffer'] = b'\x00'*512
        cnp['Length'] = 0x8

        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            nrpc.hNetrServerPasswordSet2(dce, NULL, self.machine_user,
                                         nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                         self.serverName, self.update_authenticator(), cnp.getData())

    def test_NetrLogonGetDomainInfo(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonGetDomainInfo()
        request['ServerName'] = '\x00' * 20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
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
        self.authenticate(dce)
        resp = nrpc.hNetrLogonGetDomainInfo(dce, '\x00' * 20, self.serverName, self.update_authenticator(), 0, 1)
        resp.dump()

    def test_NetrLogonGetCapabilities(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonGetCapabilities()
        request['ServerName'] = '\x00' * 20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['QueryLevel'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hNetrLogonGetCapabilities(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        resp = nrpc.hNetrLogonGetCapabilities(dce, '\x00' * 20, self.serverName + '\x00', self.update_authenticator(),
                                              0)
        resp.dump()

    def test_NetrLogonSamLogonEx(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonSamLogonEx()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = self.serverName + '\x00'

        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain.split('.')[0]
        request['LogonInformation']['LogonInteractive']['Identity'][
            'ParameterControl'] = 2 + 2 ** 14 + 2 ** 7 + 2 ** 9 + 2 ** 5 + 2 ** 11
        request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username
        request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''

        if len(self.hashes):
            blmhash = self.blmhash
            bnthash = self.bnthash
        else:
            blmhash = ntlm.LMOWFv1(self.password)
            bnthash = ntlm.NTOWFv1(self.password)
        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        rc4 = ARC4.new(self.sessionKey)
        blmhash = rc4.encrypt(blmhash)
        rc4 = ARC4.new(self.sessionKey)
        bnthash = rc4.encrypt(bnthash)

        request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = blmhash
        request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = bnthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        request['ExtraFlags'] = 1
        with assertRaisesRegex(self, DCERPCException, "STATUS_INTERNAL_ERROR"):
            dce.request(request)

    def test_NetrLogonSamLogonWithFlags(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = self.serverName + '\x00'
        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain
        request['LogonInformation']['LogonInteractive']['Identity']['ParameterControl'] = 2 + 2 ** 14 + 2 ** 7 + 2 ** 9 + 2 ** 5 + 2 ** 11
        request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username
        request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''
        if len(self.hashes):
            blmhash = self.blmhash
            bnthash = self.bnthash
        else:
            blmhash = ntlm.LMOWFv1(self.password)
            bnthash = ntlm.NTOWFv1(self.password)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        rc4 = ARC4.new(self.sessionKey)
        blmhash = rc4.encrypt(blmhash)
        rc4 = ARC4.new(self.sessionKey)
        bnthash = rc4.encrypt(bnthash)

        request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = blmhash
        request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = bnthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        with assertRaisesRegex(self, DCERPCException, "STATUS_NO_SUCH_USER"):
            dce.request(request)

    def test_NetrLogonSamLogon(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonSamLogon()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = self.serverName + '\x00'
        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain
        request['LogonInformation']['LogonInteractive']['Identity']['ParameterControl'] = 2
        request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username
        request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''
        if len(self.hashes):
            blmhash = self.blmhash
            bnthash = self.bnthash
        else:
            blmhash = ntlm.LMOWFv1(self.password)
            bnthash = ntlm.NTOWFv1(self.password)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need PyCrypto")
            print("See http://www.pycrypto.org/")

        rc4 = ARC4.new(self.sessionKey)
        blmhash = rc4.encrypt(blmhash)
        rc4 = ARC4.new(self.sessionKey)
        bnthash = rc4.encrypt(bnthash)

        request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = blmhash
        request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = bnthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo2
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        with assertRaisesRegex(self, DCERPCException, "STATUS_NO_SUCH_USER"):
            dce.request(request)

    def test_NetrDatabaseDeltas(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrDatabaseDeltas()
        request['PrimaryName'] = '\x00' * 20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['DatabaseID'] = 0
        # request['DomainModifiedCount'] = 1
        request['PreferredMaximumLength'] = 0xffffffff
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_NetrDatabaseSync2(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrDatabaseSync2()
        request['PrimaryName'] = '\x00' * 20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['DatabaseID'] = 0
        request['RestartState'] = nrpc.SYNC_STATE.NormalState
        request['SyncContext'] = 0
        request['PreferredMaximumLength'] = 0xffffffff
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_NetrDatabaseSync(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrDatabaseSync()
        request['PrimaryName'] = '\x00' * 20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['DatabaseID'] = 0
        request['SyncContext'] = 0
        request['PreferredMaximumLength'] = 0xffffffff
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_NetrDatabaseRedo(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrDatabaseRedo()
        request['PrimaryName'] = '\x00' * 20
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = '\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ChangeLogEntry'] = 0
        request['ChangeLogEntrySize'] = 0
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_DsrEnumerateDomainTrusts(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.DsrEnumerateDomainTrusts()
        request['ServerName'] = NULL
        request['Flags'] = 1
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_NetrEnumerateTrustedDomainsEx(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrEnumerateTrustedDomainsEx()
        request['ServerName'] = NULL
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_NetrEnumerateTrustedDomains(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrEnumerateTrustedDomains()
        request['ServerName'] = NULL
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_SUPPORTED"):
            dce.request(request)

    def test_NetrGetForestTrustInformation(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrGetForestTrustInformation()
        request['ServerName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['Flags'] = 0
        with assertRaisesRegex(self, DCERPCException, "STATUS_NOT_IMPLEMENTED"):
            dce.request(request)

    def test_DsrGetForestTrustInformation(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.DsrGetForestTrustInformation()
        request['ServerName'] = NULL
        request['TrustedDomainName'] = self.domain + '\x00'
        request['Flags'] = 0
        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_SUCH_DOMAIN|rpc_s_access_denied"):
            dce.request(request)

    def test_NetrServerGetTrustInfo(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrServerGetTrustInfo()
        request['TrustedDcName'] = NULL
        request['AccountName'] = self.machine_user + '\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_SUCH_DOMAIN"):
            dce.request(request)

    def test_hNetrServerGetTrustInfo(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        with assertRaisesRegex(self, DCERPCException, "ERROR_NO_SUCH_DOMAIN"):
            nrpc.hNetrServerGetTrustInfo(dce, NULL, self.machine_user,
                                         nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                         self.serverName, self.update_authenticator())

    def test_NetrLogonGetTrustRid(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonGetTrustRid()
        request['ServerName'] = NULL
        request['DomainName'] = self.domain + '\x00'
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonComputeServerDigest(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonComputeServerDigest()
        request['ServerName'] = NULL
        request['Rid'] = 1001
        request['Message'] = b'HOLABETOCOMOANDAS\x00'
        request['MessageSize'] = len(b'HOLABETOCOMOANDAS\x00')
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonComputeClientDigest(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonComputeClientDigest()
        request['ServerName'] = NULL
        request['DomainName'] = self.domain + '\x00'
        request['Message'] = b'HOLABETOCOMOANDAS\x00'
        request['MessageSize'] = len(request['Message'])
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonSendToSam(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonSendToSam()
        request['PrimaryName'] = NULL
        request['ComputerName'] = self.serverName + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['OpaqueBuffer'] = b'HOLABETOCOMOANDAS\x00'
        request['OpaqueBufferSize'] = len(b'HOLABETOCOMOANDAS\x00')
        with assertRaisesRegex(self, DCERPCException, "STATUS_ACCESS_DENIED"):
            dce.request(request)

    def test_NetrLogonSetServiceBits(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonSetServiceBits()
        request['ServerName'] = NULL
        request['ServiceBitsOfInterest'] = 1 << 7
        request['ServiceBits'] = 1 << 7
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    #@pytest.mark.xfail
    def test_NetrLogonGetTimeServiceParentDomain(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonGetTimeServiceParentDomain()
        request['ServerName'] = self.domain + '\x00'
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonControl2Ex(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonControl2Ex()
        request['ServerName'] = NULL
        request['FunctionCode'] = nrpc.NETLOGON_CONTROL_FIND_USER
        request['QueryLevel'] = 4
        request['Data']['tag'] = 8
        request['Data']['UserName'] = 'normaluser7\x00'
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonControl2(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonControl2()
        request['ServerName'] = NULL
        request['FunctionCode'] = nrpc.NETLOGON_CONTROL_FIND_USER
        request['QueryLevel'] = 4
        request['Data']['tag'] = 8
        request['Data']['UserName'] = 'normaluser7\x00'

        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonControl(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonControl()
        request['ServerName'] = NULL
        request['FunctionCode'] = nrpc.NETLOGON_CONTROL_QUERY
        request['QueryLevel'] = 4
        request['Data']['tag'] = 65534
        request['Data']['DebugFlag'] = 1
        with assertRaisesRegex(self, DCERPCException, "ERROR_INVALID_LEVEL"):
            dce.request(request)

    def test_NetrLogonUasLogon(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonUasLogon()
        request['ServerName'] = NULL
        request['UserName'] = 'normaluser7\x00'
        request['Workstation'] = self.serverName + '\x00'
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)

    def test_NetrLogonUasLogoff(self):
        dce, rpctransport = self.connect()
        request = nrpc.NetrLogonUasLogoff()
        request['ServerName'] = NULL
        request['UserName'] = 'normaluser7\x00'
        request['Workstation'] = self.serverName + '\x00'
        with assertRaisesRegex(self, DCERPCException, "rpc_s_access_denied"):
            dce.request(request)


@pytest.mark.remote
class NRPCTestsSMBTransport(NRPCTests, unittest.TestCase):
    string_binding = r"ncacn_np:{0.machine}[\PIPE\netlogon]"
    string_binding_formatting = DCERPCTests.STRING_BINDING_FORMATTING


@pytest.mark.remote
class NRPCTestsTCPTransport(NRPCTests, unittest.TestCase):
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER


# Process command-line arguments.
if __name__ == '__main__':
    unittest.main(verbosity=1)
