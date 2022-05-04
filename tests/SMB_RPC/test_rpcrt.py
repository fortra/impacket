# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
from __future__ import division
from __future__ import print_function

import pytest
import unittest
from tests import RemoteTestCase

from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5 import transport, epm, samr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, \
    RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_WINNT
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING


# aimed at testing just the DCERPC engine, not the particular
# endpoints (we should do specific tests for endpoints)
# here we're using EPM just because we need one, and it's the 
# easiest one
class RPCRTTests(RemoteTestCase):

    def connectDCE(self, username, password, domain, lm='', nt='', aes_key='', TGT=None, TGS=None, tfragment=0,
                   dceFragment=0, auth_type=RPC_C_AUTHN_WINNT, auth_level=RPC_C_AUTHN_LEVEL_NONE, dceAuth=True,
                   doKerberos=False, bind=epm.MSRPC_UUID_PORTMAP):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(username, password, domain, lm, nt, aes_key, TGT, TGS)
            rpctransport.set_kerberos(doKerberos, kdcHost=self.machine)

        rpctransport.set_max_fragment_size(tfragment)
        rpctransport.setRemoteName(self.serverName)
        rpctransport.setRemoteHost(self.machine)
        dce = rpctransport.get_dce_rpc()
        dce.set_max_fragment_size(dceFragment)
        if dceAuth is True:
            dce.set_credentials(*(rpctransport.get_credentials()))
        dce.connect()
        dce.set_auth_type(auth_type)
        dce.set_auth_level(auth_level)
        dce.bind(bind)

        return dce

    def test_connection(self):
        dce = self.connectDCE(self.username, self.password, self.domain, dceAuth=False)
        dce.disconnect()

    def test_connectionHashes(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceAuth=False)
        dce.disconnect()

    def test_dceAuth(self):
        dce = self.connectDCE(self.username, self.password, self.domain, dceAuth=True)
        epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthKerberos(self):
        dce = self.connectDCE(self.username, self.password, self.domain, dceAuth=True, doKerberos=True)
        epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasHashes(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceAuth=True)
        epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasHashesKerberos(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceAuth=True, doKerberos=True)
        epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasAes128Kerberos(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aes_key_128, dceAuth=True, doKerberos=True)
        epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceAuthHasAes256Kerberos(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aes_key_256, dceAuth=True, doKerberos=True)
        epm.hept_lookup(self.machine)
        dce.disconnect()

    def test_dceTransportFragmentation(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, tfragment=1, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_dceFragmentation(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceFragment=1, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_bigRequestMustFragment(self):
        class dummyCall(NDRCALL):
            opnum = 2
            structure = (
                ('Name', RPC_UNICODE_STRING),
            )
        oldBinding = self.stringBinding
        self.stringBinding = epm.hept_map(self.machine, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        print(self.stringBinding)
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceFragment=0,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              dceAuth=True,
                              doKerberos=True, bind=samr.MSRPC_UUID_SAMR)
        self.stringBinding = oldBinding

        request = samr.SamrConnect()
        request['ServerName'] = b'BETO\x00'
        request['DesiredAccess'] = samr.DELETE | samr.READ_CONTROL | samr.WRITE_DAC | samr.WRITE_OWNER | samr.ACCESS_SYSTEM_SECURITY | samr.GENERIC_READ | samr.GENERIC_WRITE | samr.GENERIC_EXECUTE | samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_SHUTDOWN | samr.SAM_SERVER_INITIALIZE | samr.SAM_SERVER_CREATE_DOMAIN | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN | samr.SAM_SERVER_READ | samr.SAM_SERVER_WRITE | samr.SAM_SERVER_EXECUTE
        resp = dce.request(request)
        request = samr.SamrEnumerateDomainsInSamServer()
        request['ServerHandle'] = resp['ServerHandle']
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 500
        dce.request(request)
        try:
            request = samr.SamrLookupDomainInSamServer()
            request['ServerHandle'] = resp['ServerHandle']
            request['Name'] = 'A'*4500
            dce.request(request)
        except Exception as e:
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise
        dce.disconnect()

    def test_dceFragmentationWINNTPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceFragment=1,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_dceFragmentationWINNTPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceFragment=1,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_dceFragmentationKerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceFragment=1,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_dceFragmentationKerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, dceFragment=1,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_WINNTPacketIntegrity(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                              dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_KerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_HashesWINNTPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_HashesKerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes128KerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aes_key_128,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes256KerberosPacketIntegrity(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aes_key_256,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_packetAnonWINNTPacketIntegrity(self):
        # With SMB Transport this will fail with STATUS_ACCESS_DENIED
        try:
            dce = self.connectDCE('', '', '', auth_level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,dceAuth=False, doKerberos=False)
            request = epm.ept_lookup()
            request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
            request['object'] = NULL
            request['Ifid'] = NULL
            request['vers_option'] = epm.RPC_C_VERS_ALL
            request['max_ents'] = 499
            dce.request(request)
            dce.disconnect()
        except Exception as e:
            if not (str(e).find('STATUS_ACCESS_DENIED') >=0 and self.stringBinding.find('ncacn_np') >=0):
                raise

    def test_WINNTPacketPrivacy(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.request(request)
        dce.disconnect()

    def test_KerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, self.password, self.domain, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_HashesWINNTPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=False)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        dce.disconnect()

    def test_HashesKerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, self.lmhash, self.nthash, auth_type=RPC_C_AUTHN_GSS_NEGOTIATE,
                              auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes128KerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aes_key_128,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_Aes256KerberosPacketPrivacy(self):
        dce = self.connectDCE(self.username, '', self.domain, '', '', self.aes_key_256,
                              auth_type=RPC_C_AUTHN_GSS_NEGOTIATE, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              dceAuth=True, doKerberos=True)
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
        dce.request(request)
        resp = dce.request(request)
        resp.dump()
        dce.disconnect()

    def test_AnonWINNTPacketPrivacy(self):
        # With SMB Transport this will fail with STATUS_ACCESS_DENIED
        try:
            dce = self.connectDCE('', '', '', auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, dceAuth=False, doKerberos=False)
            request = epm.ept_lookup()
            request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
            request['object'] = NULL
            request['Ifid'] = NULL
            request['vers_option'] = epm.RPC_C_VERS_ALL
            request['max_ents'] = 499
            dce.request(request)
            dce.disconnect()
        except Exception as e:
            if not (str(e).find('STATUS_ACCESS_DENIED') >= 0 and self.stringBinding.find('ncacn_np') >= 0):
                raise


@pytest.mark.remote
class RPCRTTestsTCPTransport(RPCRTTests, unittest.TestCase):

    def setUp(self):
        super(RPCRTTestsTCPTransport, self).setUp()
        self.set_transport_config(aes_keys=True)
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine


@pytest.mark.remote
class RPCRTTestsSMBTransport(RPCRTTests, unittest.TestCase):
    def setUp(self):
        # Put specific configuration for target machine with SMB_002
        super(RPCRTTestsSMBTransport, self).setUp()
        self.set_transport_config(aes_keys=True)
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine


if __name__ == "__main__":
    unittest.main(verbosity=1)
