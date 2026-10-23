#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from impacket.examples.ntlmrelayx.clients.smbrelayclient import MYSMB3, SMBRelayClient
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.smb3 import SMB2Negotiate_Response, SMB2Packet, SMB3Packet, SMB2_DIALECT_30, \
    SMB2_GLOBAL_CAP_ENCRYPTION, SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_NEGOTIATE_SIGNING_REQUIRED


class ReauthBypassConfigTests(unittest.TestCase):
    def test_bypass_is_off_by_default(self):
        config = NTLMRelayxConfig()

        self.assertFalse(config.reauth_bypass)
        self.assertEqual(config.reauth_user, '')

    def test_no_credential_leaves_the_bypass_off(self):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions(None, None)

        self.assertFalse(config.reauth_bypass)

    def test_credential_with_domain_and_password(self):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions('AD.LOCAL/user1:Passw0rd1', None)

        self.assertTrue(config.reauth_bypass)
        self.assertEqual(config.reauth_domain, 'AD.LOCAL')
        self.assertEqual(config.reauth_user, 'user1')
        self.assertEqual(config.reauth_password, 'Passw0rd1')
        self.assertEqual(config.reauth_lmhash, '')
        self.assertEqual(config.reauth_nthash, '')

    def test_credential_with_hashes_and_no_password(self):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions('AD.LOCAL/user1', 'aad3b435b51404eeaad3b435b51404ee:'
                                                        'cf3a5525ee9414229e66279623ed5c58')

        self.assertTrue(config.reauth_bypass)
        self.assertEqual(config.reauth_password, '')
        self.assertEqual(config.reauth_lmhash, 'aad3b435b51404eeaad3b435b51404ee')
        self.assertEqual(config.reauth_nthash, 'cf3a5525ee9414229e66279623ed5c58')

    def test_credential_without_domain(self):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions('user1:Passw0rd1', None)

        self.assertEqual(config.reauth_domain, '')
        self.assertEqual(config.reauth_user, 'user1')

    def test_credential_without_username_is_rejected(self):
        config = NTLMRelayxConfig()

        with self.assertRaises(Exception):
            config.setReauthBypassOptions('AD.LOCAL/:Passw0rd1', None)
        self.assertFalse(config.reauth_bypass)

    def test_credential_without_secret_is_rejected(self):
        config = NTLMRelayxConfig()

        with self.assertRaises(Exception):
            config.setReauthBypassOptions('AD.LOCAL/user1', None)
        self.assertFalse(config.reauth_bypass)

    def test_malformed_hashes_are_rejected(self):
        config = NTLMRelayxConfig()

        with self.assertRaises(Exception):
            config.setReauthBypassOptions('AD.LOCAL/user1', 'cf3a5525ee9414229e66279623ed5c58')
        self.assertFalse(config.reauth_bypass)


class ReauthBypassClientTests(unittest.TestCase):
    @staticmethod
    def signingRequiredNegotiateResponse():
        response = SMB2Negotiate_Response()
        response['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED
        response['DialectRevision'] = SMB2_DIALECT_30
        response['ServerGuid'] = b'A' * 16
        response['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
        response['MaxTransactSize'] = 0x800000
        response['MaxReadSize'] = 0x800000
        response['MaxWriteSize'] = 0x800000
        response['Buffer'] = b''

        packet = SMB2Packet()
        packet['Data'] = response.getData()
        return packet

    @staticmethod
    def negotiatedClient(allowSigning):
        # The negotiation only touches these two, so we can replay it without a socket
        client = MYSMB3.__new__(MYSMB3)
        client.allowSigning = allowSigning
        client.RequireMessageSigning = False
        client._Connection = {}
        client.SMB_PACKET = SMB2Packet
        return client

    @staticmethod
    def relayClient(bypass):
        config = NTLMRelayxConfig()
        if bypass:
            config.setReauthBypassOptions('AD.LOCAL/user1:Passw0rd1', None)
        return SMBRelayClient(config, urlparse('smb://10.0.0.10'))

    def test_signing_required_target_is_refused_without_the_bypass(self):
        client = self.negotiatedClient(allowSigning=False)

        client.negotiateSession(negSessionResponse=self.signingRequiredNegotiateResponse())

        self.assertEqual(client._Connection['ClientSecurityMode'], 0)
        self.assertNotIn('ServerSecurityMode', client._Connection)
        self.assertIs(client.SMB_PACKET, SMB2Packet)

    def test_signing_required_target_is_negotiated_with_the_bypass(self):
        client = self.negotiatedClient(allowSigning=True)

        client.negotiateSession(negSessionResponse=self.signingRequiredNegotiateResponse())

        self.assertEqual(client._Connection['ClientSecurityMode'], SMB2_NEGOTIATE_SIGNING_ENABLED)
        self.assertEqual(client._Connection['ServerSecurityMode'],
                         SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED)
        self.assertEqual(client._Connection['Dialect'], SMB2_DIALECT_30)
        self.assertIs(client.SMB_PACKET, SMB3Packet)

    def test_session_setup_security_mode_follows_the_bypass(self):
        self.assertEqual(self.relayClient(bypass=False).sessionSetupSecurityMode(), 0)
        self.assertEqual(self.relayClient(bypass=True).sessionSetupSecurityMode(),
                         SMB2_NEGOTIATE_SIGNING_ENABLED)


if __name__ == '__main__':
    unittest.main(verbosity=1)
