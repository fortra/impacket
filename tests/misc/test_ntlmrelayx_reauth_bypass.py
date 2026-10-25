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
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from impacket.examples.ntlmrelayx.clients.smbrelayclient import MYSMB3, SMBRelayClient
from impacket.examples.ntlmrelayx.clients import ldaprelayclient
from impacket.examples.ntlmrelayx.clients.ldaprelayclient import LDAPRelayClient
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import BindResponse, LDAPMessage, ModifyResponse, PartialAttribute, \
    ResultCode, SearchResultEntry
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMSSP_NEGOTIATE_UNICODE
from impacket.smb3 import SMB2Negotiate_Response, SMB2Packet, SMB3Packet, SMB2_DIALECT_30, \
    SMB2_GLOBAL_CAP_ENCRYPTION, SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_NEGOTIATE_SIGNING_REQUIRED
from pyasn1.codec.ber import decoder


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

    def test_anonymous_credential_is_allowed(self):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions(':', None)

        self.assertTrue(config.reauth_bypass)
        self.assertTrue(config.reauth_anonymous)
        self.assertEqual(config.reauth_user, '')
        self.assertEqual(config.reauth_password, '')

    def test_named_account_is_not_anonymous(self):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions('AD.LOCAL/user1:Passw0rd1', None)

        self.assertFalse(config.reauth_anonymous)

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


class ReauthBypassLDAPClientTests(unittest.TestCase):
    def setUp(self):
        # The read-back waits for the DC, which has nothing to apply here
        patcher = mock.patch.object(ldaprelayclient.time, 'sleep')
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def ldapClient(delegate_access=False, shadow_creds=False, escalate_user=None, sid=False,
                   shadow_outfile=None, shadow_replace=False, backup_path=None):
        config = NTLMRelayxConfig()
        config.setReauthBypassOptions('AD.LOCAL/low:Passw0rd1', None)
        # The LDAP bypass reads the standard LDAP attack options, same as a normal relay
        config.setLDAPOptions(True, True, True, True, escalate_user, None, delegate_access,
                              False, False, False, sid, None, False)
        config.setIsShadowCredentialsAttack(shadow_creds)
        config.setShadowCredentialsOptions(None, None, None, shadow_outfile, shadow_replace, backup_path)
        client = LDAPRelayClient(config, urlparse('ldap://10.0.0.10'))
        client.targetDN = 'CN=victim,DC=ad,DC=local'
        client.targetSam = 'victim$'
        client.baseDN = 'DC=ad,DC=local'
        return client

    @staticmethod
    def authenticateMessage(domain, user, unicode=True):
        message = NTLMAuthChallengeResponse()
        encoding = 'utf-16le' if unicode else 'ascii'
        message['flags'] = NTLMSSP_NEGOTIATE_UNICODE if unicode else 0
        message['domain_name'] = domain.encode(encoding)
        message['user_name'] = user.encode(encoding)
        return message

    def test_victim_name_unicode(self):
        message = self.authenticateMessage('RD', 'victim$', unicode=True)

        self.assertEqual(LDAPRelayClient.victimName(message), 'RD\\victim$')
        self.assertEqual(LDAPRelayClient.victimSam(message), 'victim$')

    def test_victim_name_oem(self):
        message = self.authenticateMessage('RD', 'victim$', unicode=False)

        self.assertEqual(LDAPRelayClient.victimName(message), 'RD\\victim$')

    def test_selected_attack_picks_the_single_write(self):
        self.assertEqual(self.ldapClient(delegate_access=True).bypassSelectedAttack(), 'rbcd')
        self.assertEqual(self.ldapClient(shadow_creds=True).bypassSelectedAttack(), 'shadow')
        self.assertIsNone(self.ldapClient().bypassSelectedAttack())
        self.assertIsNone(self.ldapClient(delegate_access=True, shadow_creds=True).bypassSelectedAttack())

    def test_rbcd_write_with_explicit_sid(self):
        client = self.ldapClient(delegate_access=True, escalate_user='S-1-5-21-1-2-3-1104', sid=True)
        client.bypassReadAttribute = lambda dn, attribute: []  # no existing descriptor to read as our account
        attribute, values, operation = client.bypassBuildWrite()

        self.assertEqual(attribute, 'msDS-AllowedToActOnBehalfOfOtherIdentity')
        self.assertEqual(operation, 2)  # replace the descriptor we built from the (empty) existing one
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0][:1], b'\x01')  # self-relative SD revision
        self.assertGreater(len(values[0]), 20)

    def test_shadow_write_appends_to_existing(self):
        client = self.ldapClient(shadow_creds=True)
        client.bypassReadAttribute = lambda dn, attribute: [b'B:4:cafe:CN=victim,DC=ad,DC=local']
        attribute, values, operation = client.bypassBuildWrite()

        self.assertEqual(attribute, 'msDS-KeyCredentialLink')
        self.assertEqual(operation, 2)  # REPLACE with the full set, like the classic attack
        self.assertEqual(len(values), 2)  # existing one kept + ours appended
        self.assertEqual(values[0], b'B:4:cafe:CN=victim,DC=ad,DC=local')
        self.assertTrue(values[1].startswith(b'B:'))

    def test_shadow_replace_drops_existing_and_backs_up(self):
        outdir = tempfile.mkdtemp()
        backup = os.path.join(outdir, 'backup.json')
        try:
            client = self.ldapClient(shadow_creds=True, shadow_replace=True, backup_path=backup)
            client.bypassReadAttribute = lambda dn, attribute: [b'B:4:cafe:CN=victim,DC=ad,DC=local']
            attribute, values, operation = client.bypassBuildWrite()

            self.assertEqual(operation, 2)
            self.assertEqual(len(values), 1)  # only ours remains
            self.assertTrue(values[0].startswith(b'B:'))
            self.assertTrue(os.path.isfile(backup))  # existing key credential backed up first
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def test_shadow_pfx_saved_only_on_demand(self):
        outdir = tempfile.mkdtemp()
        outfile = os.path.join(outdir, 'reauth_shadow')
        try:
            client = self.ldapClient(shadow_creds=True, shadow_outfile=outfile)
            client.bypassReadAttribute = lambda dn, attribute: []
            client.bypassBuildWrite()

            # The PFX is written only once the DC accepts the Modify, not during build
            self.assertFalse(os.path.isfile(outfile + '.pfx'))
            client.bypassSaveShadowCredential()
            self.assertTrue(os.path.isfile(outfile + '.pfx'))
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def test_write_confirmed_exact_and_dn_binary(self):
        # Exact match (e.g. a raw security descriptor)
        self.assertTrue(LDAPRelayClient.writeConfirmed(b'\x01\x00rbcd', [b'\x01\x00rbcd']))
        self.assertFalse(LDAPRelayClient.writeConfirmed(b'\x01\x00rbcd', [b'other']))
        # DN-Binary: same B:<len>:<hex> but the DC canonicalized the trailing DN
        ours = b'B:8:deadbeef:CN=DC01,OU=Domain Controllers,DC=ad,DC=local'
        # The DC canonicalizes the trailing DN and upper-cases the hex
        stored = b'B:8:DEADBEEF:CN=DC01,OU=Domain Controllers,DC=AD,DC=LOCAL'
        self.assertTrue(LDAPRelayClient.writeConfirmed(ours, [stored]))
        self.assertFalse(LDAPRelayClient.writeConfirmed(ours, [b'B:8:cafe:CN=DC01,DC=ad,DC=local']))

    def test_sasl_bind_request_round_trips(self):
        wire = LDAPRelayClient.ldapMessage(LDAPRelayClient.saslBindRequest(b'spnego-token'), 1)
        message, _ = decoder.decode(wire, asn1Spec=LDAPMessage())
        auth = message['protocolOp']['bindRequest']['authentication']['sasl']

        self.assertEqual(str(auth['mechanism']), 'GSS-SPNEGO')
        self.assertEqual(bytes(auth['credentials']), b'spnego-token')

    @staticmethod
    def resultMessage(response, resultCode, messageID):
        response['resultCode'] = ResultCode(resultCode)
        response['matchedDN'] = ''
        response['diagnosticMessage'] = ''
        return LDAPRelayClient.ldapMessage(response, messageID)

    @staticmethod
    def recordStream(client, *plaintexts):
        # A fake connection replaying sealed records, 'decryption' being the stripping of the length prefix
        class FakeSocket(object):
            def __init__(self, data):
                self.data = data

            def recv(self, length):
                chunk, self.data = self.data[:length], self.data[length:]
                return chunk

        class FakeConnection(object):
            def __init__(self, data):
                self._socket = FakeSocket(data)

            @staticmethod
            def decrypt(data):
                return data[4:]

        wire = b''.join(struct.pack('>I', len(plaintext)) + plaintext for plaintext in plaintexts)
        client.bypassConnection = FakeConnection(wire)

    def test_in_record_responses_report_an_accepted_modify(self):
        client = self.ldapClient(delegate_access=True)
        self.recordStream(client,
                          self.resultMessage(BindResponse(), 'success', 1),
                          self.resultMessage(ModifyResponse(), 'success', 2))

        self.assertTrue(client.readInRecordResponses())

    def test_in_record_responses_stop_on_an_unreadable_record(self):
        client = self.ldapClient(delegate_access=True)
        # The DC answers the Modify under the victim's seal key, so the second record is noise for us
        self.recordStream(client,
                          self.resultMessage(BindResponse(), 'success', 1),
                          b'\xde\xad\xbe\xef')

        self.assertFalse(client.readInRecordResponses())

    def test_in_record_responses_report_a_refused_modify(self):
        client = self.ldapClient(delegate_access=True)
        self.recordStream(client,
                          self.resultMessage(BindResponse(), 'success', 1),
                          self.resultMessage(ModifyResponse(), 'insufficientAccessRights', 2))

        self.assertFalse(client.readInRecordResponses())

    @staticmethod
    def searchResultEntry(dn, attribute, values):
        entry = SearchResultEntry()
        entry['objectName'] = dn
        attributes = entry.setComponentByName('attributes').getComponentByName('attributes')
        partial = PartialAttribute()
        partial['type'] = attribute
        partial['vals'].setComponents(*values)
        attributes.setComponentByPosition(0, partial)
        return entry

    def readBackClient(self, entries):
        client = self.ldapClient(delegate_access=True)
        closed = []

        class FakeSession(object):
            @staticmethod
            def search(**kwargs):
                return entries

            @staticmethod
            def close():
                closed.append(True)

        client.bypassOpenSession = FakeSession
        return client, closed

    def test_read_back_confirms_the_write(self):
        entries = [self.searchResultEntry('CN=victim,DC=ad,DC=local', 'description', [b'pwned'])]
        client, closed = self.readBackClient(entries)

        self.assertTrue(client.verifyWrite('description', b'pwned'))
        self.assertFalse(client.verifyWrite('description', b'something else'))
        self.assertEqual(len(closed), 2)  # the read-back session is closed every time

    def test_read_back_unavailable_is_not_a_confirmation(self):
        client = self.ldapClient(delegate_access=True)

        def unreachable():
            raise LDAPSessionError(errorString='connection refused')

        client.bypassOpenSession = unreachable

        self.assertFalse(client.verifyWrite('description', b'pwned'))

    def test_modify_request_targets_resolved_dn(self):
        client = self.ldapClient(delegate_access=True)
        wire = LDAPRelayClient.ldapMessage(client.modifyRequest('description', [b'pwned'], 2), 2)
        message, _ = decoder.decode(wire, asn1Spec=LDAPMessage())
        modify = message['protocolOp']['modifyRequest']

        self.assertEqual(str(modify['object']), 'CN=victim,DC=ad,DC=local')
        self.assertEqual(int(modify['changes'][0]['operation']), 2)
        self.assertEqual(str(modify['changes'][0]['modification']['type']), 'description')


if __name__ == '__main__':
    unittest.main(verbosity=1)
