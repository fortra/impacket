  # tests/SMB_RPC/test_spnego_negoex.py

import unittest
import uuid

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

      def test_neg_token_resp_detects_negoex_selected(self):
          token = SPNEGO_NegTokenResp()
          token['NegState'] = b'\x01'
          token['SupportedMech'] = self.negoex_oid
          token['ResponseToken'] = self.nego_message

          parsed = SPNEGO_NegTokenResp(token.getData())

          self.assertTrue(parsed.isNegoExSelected())
          self.assertEqual(self.negoex_oid, parsed.getSupportedMech())
          self.assertEqual(self.nego_message, parsed.getNegoExToken())

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