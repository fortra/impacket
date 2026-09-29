import base64
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from impacket import smb
from impacket.dcerpc.v5.rpcrt import MSRPC_BIND
from impacket.examples.ntlmrelayx.servers.mssqlrelayserver import MSSQLRelayServer
from impacket.examples.ntlmrelayx.servers.rdprelayserver import RDPRelayServer
from impacket.examples.ntlmrelayx.servers.rpcrelayserver import RPCRelayServer
from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
from impacket.examples.ntlmrelayx.servers.wcfrelayserver import WCFRelayServer
from impacket.examples.ntlmrelayx.servers.winrmrelayserver import WinRMRelayServer
from impacket.examples.ntlmrelayx.servers.winrmsrelayserver import WinRMSRelayServer
from impacket.examples.ntlmrelayx.utils.spnegoutils import (
    NEGOEX_MECH,
    NTLM_MECH,
    build_ntlm_challenge_token,
    build_ntlm_fallback_token,
    find_embedded_spnego_token,
    get_ntlm_message_type,
    inspect_spnego_token,
)
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_MORE_PROCESSING_REQUIRED
from impacket.ntlm import getNTLMSSPType1
from impacket.smb3structs import SMB2SessionSetup
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp


class _EOFSocket(object):
    def __init__(self, data):
        self.data = data
        self.sent = []

    def recv(self, size):
        if not self.data:
            raise EOFError('end of test input')
        chunk = self.data[:size]
        self.data = self.data[size:]
        return chunk

    def sendall(self, data):
        self.sent.append(data)


class NegoExRelayServerTests(unittest.TestCase):
    def setUp(self):
        self.ntlm_type1 = getNTLMSSPType1('', '').getData()

    def _offer(self, mech_types, inner_token):
        offer = SPNEGO_NegTokenInit()
        offer['MechTypes'] = mech_types
        offer['MechToken'] = inner_token
        return offer.getData()

    def test_spnego_helpers_preserve_mechanism_order_and_ntlm_tokens(self):
        offer = self._offer([NTLM_MECH, NEGOEX_MECH], self.ntlm_type1)
        info = inspect_spnego_token(offer)

        self.assertTrue(info.is_init)
        self.assertTrue(info.negoex_offered)
        self.assertEqual(NTLM_MECH, info.mech_types[0])
        self.assertEqual(1, get_ntlm_message_type(info.inner_token))

        embedded = find_embedded_spnego_token(b'outer-framing' + offer)
        self.assertIsNotNone(embedded)
        self.assertTrue(embedded.negoex_offered)

    def test_spnego_helpers_build_ntlm_fallback_and_challenge(self):
        fallback = SPNEGO_NegTokenResp(build_ntlm_fallback_token())
        self.assertEqual(b'\x03', fallback['NegState'])
        self.assertEqual(NTLM_MECH, fallback['SupportedMech'])
        self.assertNotIn('ResponseToken', fallback.fields)

        challenge = b'NTLMSSP\x00\x02\x00\x00\x00test-challenge'
        wrapped = SPNEGO_NegTokenResp(build_ntlm_challenge_token(challenge))
        self.assertEqual(b'\x01', wrapped['NegState'])
        self.assertEqual(NTLM_MECH, wrapped['SupportedMech'])
        self.assertEqual(challenge, wrapped['ResponseToken'])

    def _run_smb2_offer(self):
        offer = self._offer([NEGOEX_MECH, NTLM_MECH], b'NEGOEXTS' + b'\x00' * 40)
        setup = SMB2SessionSetup()
        setup['SecurityBufferLength'] = len(offer)
        setup['Buffer'] = offer

        relay = SMBRelayServer.__new__(SMBRelayServer)
        relay.config = SimpleNamespace(disableMulti=True)
        server = Mock()
        server.getConnectionData.return_value = {'ClientIP': '192.0.2.10'}
        return relay.SmbSessionSetup('connection', server, {'Data': setup.getData()})

    def test_smb2_relay_logs_visibly_and_requests_ntlm(self):
        with patch('impacket.examples.ntlmrelayx.servers.smbrelayserver.LOG.info') as log_info:
            responses, packets, status = self._run_smb2_offer()

        self.assertEqual(STATUS_MORE_PROCESSING_REQUIRED, status)
        self.assertIsNone(packets)
        fallback = SPNEGO_NegTokenResp(responses[0]['Buffer'])
        self.assertEqual(NTLM_MECH, fallback['SupportedMech'])
        self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in log_info.call_args_list))

    def test_smb2_negoex_selection_returns_serializable_access_denied(self):
        selection = SPNEGO_NegTokenResp()
        selection['NegState'] = b'\x01'
        selection['SupportedMech'] = NEGOEX_MECH
        selection['ResponseToken'] = b'NEGOEXTS' + b'\x00' * 40

        setup = SMB2SessionSetup()
        setup['SecurityBufferLength'] = len(selection.getData())
        setup['Buffer'] = selection.getData()

        relay = SMBRelayServer.__new__(SMBRelayServer)
        relay.config = SimpleNamespace(disableMulti=True)
        server = Mock()
        server.getConnectionData.return_value = {'ClientIP': '192.0.2.10'}

        with patch('impacket.examples.ntlmrelayx.servers.smbrelayserver.LOG.info') as log_info:
            responses, packets, status = relay.SmbSessionSetup(
                'connection', server, {'Data': setup.getData()}
            )

        self.assertEqual(STATUS_ACCESS_DENIED, status)
        self.assertIsNone(packets)
        self.assertEqual(0, responses[0]['SecurityBufferLength'])
        self.assertEqual(b'', responses[0]['Buffer'])
        self.assertIsInstance(responses[0].getData(), bytes)
        self.assertTrue(any('NEGOEX selected' in call.args[0] for call in log_info.call_args_list))

    def _run_smb1_offer(self):
        offer = self._offer([NEGOEX_MECH, NTLM_MECH], b'NEGOEXTS' + b'\x00' * 40)
        parameters = smb.SMBSessionSetupAndX_Extended_Parameters()
        parameters['MaxBufferSize'] = 65535
        parameters['MaxMpxCount'] = 2
        parameters['VcNumber'] = 1
        parameters['SessionKey'] = 0
        parameters['SecurityBlobLength'] = len(offer)
        parameters['Capabilities'] = smb.SMB.CAP_EXTENDED_SECURITY

        data = smb.SMBSessionSetupAndX_Extended_Data()
        data['SecurityBlob'] = offer
        data['NativeOS'] = ''
        data['NativeLanMan'] = ''

        command = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
        command['Parameters'] = parameters.getData()
        command['Data'] = data.getData()
        command = smb.SMBCommand(command.getData())

        relay = SMBRelayServer.__new__(SMBRelayServer)
        relay.config = SimpleNamespace(disableMulti=True)
        server = Mock()
        server.getConnectionData.return_value = {
            'ClientIP': '192.0.2.10',
            '_dialects_parameters': {'Capabilities': smb.SMB.CAP_EXTENDED_SECURITY},
        }
        return relay.SmbSessionSetupAndX('connection', server, command, {'Flags2': 0})

    def test_smb1_relay_logs_and_requests_ntlm(self):
        with patch('impacket.examples.ntlmrelayx.servers.smbrelayserver.LOG.info') as log_info:
            responses, packets, status = self._run_smb1_offer()

        self.assertEqual(STATUS_MORE_PROCESSING_REQUIRED, status)
        self.assertIsNone(packets)
        fallback = SPNEGO_NegTokenResp(responses[0]['Data']['SecurityBlob'])
        self.assertEqual(NTLM_MECH, fallback['SupportedMech'])
        self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in log_info.call_args_list))

    def _http_handler(self, handler_class, offer):
        handler = handler_class.__new__(handler_class)
        handler.headers = {'Authorization': 'Negotiate ' + base64.b64encode(offer).decode('ascii')}
        handler.client_address = ('192.0.2.10', 50000)
        handler.auth_scheme = 'Negotiate'
        handler.client_uses_spnego = False
        handler.do_AUTHHEAD = Mock()
        return handler

    def test_winrm_listeners_log_and_request_ntlm(self):
        offer = self._offer([NEGOEX_MECH, NTLM_MECH], b'NEGOEXTS' + b'\x00' * 40)
        cases = (
            ('WinRM', WinRMRelayServer.HTTPHandler, 'impacket.examples.ntlmrelayx.servers.winrmrelayserver.LOG.info'),
            ('WinRMS', WinRMSRelayServer.HTTPHandler, 'impacket.examples.ntlmrelayx.servers.winrmsrelayserver.LOG.info'),
        )

        for name, handler_class, logger_path in cases:
            with self.subTest(listener=name):
                handler = self._http_handler(handler_class, offer)
                with patch(logger_path) as log_info:
                    token, message_type = handler.strip_blob(False)

                self.assertIsNone(token)
                self.assertEqual(0, message_type)
                response = handler.do_AUTHHEAD.call_args.kwargs['message']
                scheme, encoded = response.split(b' ', 1)
                self.assertEqual(b'Negotiate', scheme)
                fallback = SPNEGO_NegTokenResp(base64.b64decode(encoded))
                self.assertEqual(NTLM_MECH, fallback['SupportedMech'])
                self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in log_info.call_args_list))

    def test_winrm_listeners_log_negoex_second_without_disrupting_ntlm(self):
        offer = self._offer([NTLM_MECH, NEGOEX_MECH], self.ntlm_type1)
        cases = (
            (WinRMRelayServer.HTTPHandler, 'impacket.examples.ntlmrelayx.servers.winrmrelayserver.LOG.info'),
            (WinRMSRelayServer.HTTPHandler, 'impacket.examples.ntlmrelayx.servers.winrmsrelayserver.LOG.info'),
        )

        for handler_class, logger_path in cases:
            handler = self._http_handler(handler_class, offer)
            with patch(logger_path) as log_info:
                token, message_type = handler.strip_blob(False)

            self.assertEqual(self.ntlm_type1, token)
            self.assertEqual(1, message_type)
            handler.do_AUTHHEAD.assert_not_called()
            self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in log_info.call_args_list))

    def test_wcf_logs_negoex_when_ntlm_is_preferred(self):
        offer = self._offer([NTLM_MECH, NEGOEX_MECH], self.ntlm_type1)
        via = b'net.tcp://test/'
        upgrade = b'application/negotiate'
        framing = (
            b'\x00\x01\x00'
            + b'\x01\x00'
            + b'\x02' + struct.pack('B', len(via)) + via
            + b'\x03\x00'
            + b'\x09' + struct.pack('B', len(upgrade)) + upgrade
            + b'\x16\x01\x00' + struct.pack('>H', len(offer)) + offer
        )
        handler = WCFRelayServer.WCFHandler.__new__(WCFRelayServer.WCFHandler)
        handler.request = _EOFSocket(framing)

        with patch('impacket.examples.ntlmrelayx.servers.wcfrelayserver.LOG.info') as log_info:
            with self.assertRaises(EOFError):
                handler.handle()

        self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in log_info.call_args_list))

    def test_mssql_and_rdp_detection_use_visible_logger(self):
        offer = self._offer([NEGOEX_MECH, NTLM_MECH], b'NEGOEXTS' + b'\x00' * 40)

        mssql_handler = MSSQLRelayServer.MSSQLHandler.__new__(MSSQLRelayServer.MSSQLHandler)
        mssql_handler.client_address = ('192.0.2.10', 1433)
        with patch('impacket.examples.ntlmrelayx.servers.mssqlrelayserver.LOG.info') as mssql_log:
            info = mssql_handler.inspectClientToken(offer)

            selection = SPNEGO_NegTokenResp()
            selection['NegState'] = b'\x01'
            selection['SupportedMech'] = NEGOEX_MECH
            mssql_handler.inspectClientToken(selection.getData())

        self.assertTrue(info.negoex_offered)
        logged_messages = [call.args[0] for call in mssql_log.call_args_list]
        self.assertTrue(any(
            'NEGOEX authentication offered by client 192.0.2.10' in message
            for message in logged_messages
        ))
        self.assertTrue(any(
            'NEGOEX selected by client 192.0.2.10' in message
            for message in logged_messages
        ))

        rdp_handler = RDPRelayServer.RDPHandler.__new__(RDPRelayServer.RDPHandler)
        credssp = rdp_handler.build_tsrequest_challenge(offer)
        with patch('impacket.examples.ntlmrelayx.servers.rdprelayserver.LOG.info') as rdp_log:
            info = rdp_handler.inspect_client_token(credssp, '192.0.2.10')
        self.assertTrue(info.negoex_offered)
        self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in rdp_log.call_args_list))

    def test_mssql_wraps_challenge_after_spnego_fallback(self):
        challenge = b'NTLMSSP\x00\x02\x00\x00\x00test-challenge'

        class _Challenge(object):
            def __str__(self):
                return challenge.hex()

        handler = MSSQLRelayServer.MSSQLHandler.__new__(MSSQLRelayServer.MSSQLHandler)
        handler.target = SimpleNamespace(scheme='SMB')
        handler.client = Mock()
        handler.client.sendNegotiate.return_value = _Challenge()
        handler.client_uses_spnego = True
        handler.sendSSPIToken = Mock()

        handler.relayNegotiateToken(self.ntlm_type1)

        handler.client.sendNegotiate.assert_called_once_with(self.ntlm_type1)
        wrapped = SPNEGO_NegTokenResp(handler.sendSSPIToken.call_args.args[0])
        self.assertEqual(NTLM_MECH, wrapped['SupportedMech'])
        self.assertEqual(challenge, wrapped['ResponseToken'])

    def test_rpc_logs_and_returns_ntlm_fallback(self):
        offer = self._offer([NEGOEX_MECH, NTLM_MECH], b'NEGOEXTS' + b'\x00' * 40)
        handler = RPCRelayServer.RPCHandler.__new__(RPCRelayServer.RPCHandler)
        handler.request_header = {'auth_data': offer}
        handler.client_address = ('192.0.2.10', 50000)
        handler.bind = Mock(return_value='bind-response')

        with patch('impacket.examples.ntlmrelayx.servers.rpcrelayserver.LOG.info') as log_info:
            response = handler.handle_gss_negotiate(MSRPC_BIND)

        self.assertEqual('bind-response', response)
        fallback = SPNEGO_NegTokenResp(handler.bind.call_args.args[0])
        self.assertEqual(NTLM_MECH, fallback['SupportedMech'])
        self.assertTrue(any('NEGOEX authentication offered' in call.args[0] for call in log_info.call_args_list))


if __name__ == '__main__':
    unittest.main()
