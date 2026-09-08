  # tests/SMB_RPC/test_spnego_negoex.py

import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import Mock

from impacket import smb
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED
from impacket.ntlm import getNTLMSSPType1
from impacket.smbconnection import SMB_DIALECT
from impacket.smbserver import SMBCommands
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.negoex import (
      AUTH_SCHEME_PKU2U,
      MESSAGE_TYPE,
      createNegoMessage,
      createExchangeMessage,
  )


class SPNEGONegoExTests(unittest.TestCase):

      def setUp(self):
          self.conversation_id = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')
          self.negoex_oid = TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism']
          self.ntlm_oid = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

          self.nego_message = createNegoMessage(
              MESSAGE_TYPE.INITIATOR_NEGO,
              0,
              self.conversation_id,
              [AUTH_SCHEME_PKU2U],
          )
          self.ap_request = createExchangeMessage(
              MESSAGE_TYPE.AP_REQUEST,
              1,
              self.conversation_id,
              AUTH_SCHEME_PKU2U,
              b'opaque-pku2u-ap-request',
          )

      def test_neg_token_init_detects_negoex_offered(self):
          token = SPNEGO_NegTokenInit()
          token['MechTypes'] = [self.negoex_oid, self.ntlm_oid]
          token['MechToken'] = self.nego_message

          parsed = SPNEGO_NegTokenInit(token.getData())

          self.assertTrue(parsed.hasMechType(self.negoex_oid))
          self.assertTrue(parsed.isNegoExOffered())
          self.assertEqual(self.nego_message, parsed.getNegoExToken())

      def test_neg_token_init_parses_negoex_mech_token_messages(self):
          token = SPNEGO_NegTokenInit()
          token['MechTypes'] = [self.negoex_oid]
          token['MechToken'] = self.nego_message + self.ap_request

          parsed = SPNEGO_NegTokenInit(token.getData())
          messages = parsed.getNegoExMessages()

          self.assertEqual(2, len(messages))
          self.assertEqual(MESSAGE_TYPE.INITIATOR_NEGO, messages[0].message_type)
          self.assertEqual(MESSAGE_TYPE.AP_REQUEST, messages[1].message_type)
          self.assertEqual(self.nego_message, messages[0].raw_data)
          self.assertEqual(self.ap_request, messages[1].raw_data)

      def test_neg_token_init_does_not_parse_ntlm_as_negoex(self):
          token = SPNEGO_NegTokenInit()
          token['MechTypes'] = [self.ntlm_oid]
          token['MechToken'] = b'NTLMSSP\x00\x01\x00\x00\x00'

          parsed = SPNEGO_NegTokenInit(token.getData())

          self.assertFalse(parsed.isNegoExOffered())
          self.assertIsNone(parsed.getNegoExToken())
          self.assertEqual([], parsed.getNegoExMessages())

      def test_neg_token_init_malformed_negoex_payload_is_non_fatal_without_strict(self):
          token = SPNEGO_NegTokenInit()
          token['MechTypes'] = [self.negoex_oid, self.ntlm_oid]
          token['MechToken'] = b'not-a-negoex-token'

          parsed = SPNEGO_NegTokenInit(token.getData())

          self.assertTrue(parsed.isNegoExOffered())
          self.assertEqual(b'not-a-negoex-token', parsed.getNegoExToken())
          self.assertEqual([], parsed.getNegoExMessages())

          with self.assertRaises(Exception):
              parsed.getNegoExMessages(strict=True)

      def test_neg_token_init_requires_preferred_mech_or_signature_for_mechtoken(self):
          token = SPNEGO_NegTokenInit()
          token['MechTypes'] = [self.ntlm_oid, self.negoex_oid]
          token['MechToken'] = b'NTLMSSP\x00\x01\x00\x00\x00'

          parsed = SPNEGO_NegTokenInit(token.getData())

          self.assertTrue(parsed.isNegoExOffered())
          self.assertIsNone(parsed.getNegoExToken())
          self.assertEqual([], parsed.getNegoExMessages())

      def _run_smb1_session_setup(self, mech_types, mech_token):
          token = SPNEGO_NegTokenInit()
          token['MechTypes'] = mech_types
          token['MechToken'] = mech_token
          security_blob = token.getData()

          parameters = smb.SMBSessionSetupAndX_Extended_Parameters()
          parameters['MaxBufferSize'] = 65535
          parameters['MaxMpxCount'] = 2
          parameters['VcNumber'] = 1
          parameters['SessionKey'] = 0
          parameters['SecurityBlobLength'] = len(security_blob)
          parameters['Capabilities'] = smb.SMB.CAP_EXTENDED_SECURITY

          data = smb.SMBSessionSetupAndX_Extended_Data()
          data['SecurityBlob'] = security_blob
          data['NativeOS'] = ''
          data['NativeLanMan'] = ''

          command = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
          command['Parameters'] = parameters.getData()
          command['Data'] = data.getData()
          command = smb.SMBCommand(command.getData())

          server = Mock()
          server.getConnectionData.return_value = {}
          server.getServerOS.return_value = 'Unix'
          return SMBCommands.smbComSessionSetupAndX('connection', server, command, {'Flags2': 0})

      def test_smb1_handler_requests_ntlm_for_non_ntlm_first_offer(self):
          kerberos_oid = TypesMech['MS KRB5 - Microsoft Kerberos 5']
          cases = (
              ([self.negoex_oid, self.ntlm_oid], b'NEGOEXTS' + b'\x00' * 40),
              ([kerberos_oid, self.ntlm_oid], b'kerberos-optimistic-token'),
          )

          for mech_types, mech_token in cases:
              with self.subTest(first_mech=mech_types[0]):
                  responses, packets, status = self._run_smb1_session_setup(mech_types, mech_token)

                  self.assertEqual(STATUS_MORE_PROCESSING_REQUIRED, status)
                  self.assertIsNone(packets)
                  response = responses[0]
                  parsed = SPNEGO_NegTokenResp(response['Data']['SecurityBlob'])
                  self.assertEqual(b'\x03', parsed['NegState'])
                  self.assertEqual(self.ntlm_oid, parsed['SupportedMech'])
                  self.assertNotIn('ResponseToken', parsed.fields)

      def test_smb_relay_client_rejects_target_negoex_selection_during_negotiate(self):
          selection = SPNEGO_NegTokenResp()
          selection['NegState'] = b'\x01'
          selection['SupportedMech'] = self.negoex_oid
          target_response = selection.getData()
          negotiate_message = getNTLMSSPType1('', '').getData()

          for dialect, method_name in ((SMB_DIALECT, 'sendNegotiatev1'), ('SMB2', 'sendNegotiatev2')):
              with self.subTest(dialect=dialect):
                  client = SMBRelayClient.__new__(SMBRelayClient)
                  client.serverConfig = SimpleNamespace(remove_mic=False)
                  client.session = Mock()
                  client.session.getDialect.return_value = dialect
                  send_negotiate = Mock(return_value=target_response)
                  setattr(client, method_name, send_negotiate)

                  with self.assertRaisesRegex(Exception, 'NEGOEX/PKU2U relay is not supported'):
                      client.sendNegotiate(negotiate_message)

                  send_negotiate.assert_called_once()

      def test_neg_token_resp_detects_negoex_selected(self):
          token = SPNEGO_NegTokenResp()
          token['NegState'] = b'\x01'
          token['SupportedMech'] = self.negoex_oid
          token['ResponseToken'] = self.nego_message

          parsed = SPNEGO_NegTokenResp(token.getData())

          self.assertTrue(parsed.isNegoExSelected())
          self.assertEqual(self.negoex_oid, parsed.getSupportedMech())
          self.assertEqual(self.nego_message, parsed.getNegoExToken())

      def test_neg_token_resp_parses_selection_without_response_token(self):
          token = SPNEGO_NegTokenResp()
          token['NegState'] = b'\x01'
          token['SupportedMech'] = self.negoex_oid

          parsed = SPNEGO_NegTokenResp(token.getData())

          self.assertTrue(parsed.isNegoExSelected())
          self.assertEqual(self.negoex_oid, parsed.getSupportedMech())
          self.assertNotIn('ResponseToken', parsed.fields)

      def test_neg_token_resp_parses_negoex_response_token_messages(self):
          token = SPNEGO_NegTokenResp()
          token['NegState'] = b'\x01'
          token['SupportedMech'] = self.negoex_oid
          token['ResponseToken'] = self.nego_message + self.ap_request

          parsed = SPNEGO_NegTokenResp(token.getData())
          messages = parsed.getNegoExMessages()

          self.assertEqual(2, len(messages))
          self.assertEqual(MESSAGE_TYPE.INITIATOR_NEGO, messages[0].message_type)
          self.assertEqual(MESSAGE_TYPE.AP_REQUEST, messages[1].message_type)

      def test_neg_token_resp_does_not_parse_ntlm_response_as_negoex(self):
          token = SPNEGO_NegTokenResp()
          token['NegState'] = b'\x01'
          token['SupportedMech'] = self.ntlm_oid
          token['ResponseToken'] = b'NTLMSSP\x00\x02\x00\x00\x00'

          parsed = SPNEGO_NegTokenResp(token.getData())

          self.assertFalse(parsed.isNegoExSelected())
          self.assertIsNone(parsed.getNegoExToken())
          self.assertEqual([], parsed.getNegoExMessages())

      def test_malformed_negoex_payload_raises_clear_error_when_selected(self):
          token = SPNEGO_NegTokenResp()
          token['NegState'] = b'\x01'
          token['SupportedMech'] = self.negoex_oid
          token['ResponseToken'] = b'not-a-negoex-token'

          parsed = SPNEGO_NegTokenResp(token.getData())

          with self.assertRaises(Exception):
              parsed.getNegoExMessages(strict=True)


if __name__ == '__main__':
    unittest.main(verbosity=1)
