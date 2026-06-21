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

import base64
import hashlib
import importlib.util
import os
import py_compile
import types
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from impacket.tls import (
    tls_server_end_point_channel_binding_from_certificate,
    tls_server_end_point_channel_binding_from_digest,
)
from impacket.winrm import (
    SOAP_NAMESPACES,
    WINRS_RESOURCE_URI,
    WinRMAuthError,
    WinRMFaultError,
    build_winrs_command_request,
    build_winrs_create_request,
    build_winrs_receive_request,
    envelope_to_bytes,
    iter_streams,
    parse_command_id,
    parse_command_state,
    parse_shell_id,
    parse_wsman_response,
)


class WinRMTests(unittest.TestCase):
    @staticmethod
    def _load_winrmexec_module():
        example_path = os.path.join(os.path.dirname(__file__), '..', '..', 'examples', 'winrmexec.py')
        spec = importlib.util.spec_from_file_location('test_winrmexec', example_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_tls_server_end_point_channel_binding_helper(self):
        certificate = b'fake-certificate'
        digest = b"\xb3\xad\xf0\r" * 8

        self.assertEqual(
            tls_server_end_point_channel_binding_from_digest(digest),
            tls_server_end_point_channel_binding_from_digest(digest),
        )
        self.assertEqual(
            tls_server_end_point_channel_binding_from_certificate(certificate),
            tls_server_end_point_channel_binding_from_digest(hashlib.sha256(certificate).digest()),
        )

    def test_build_create_request(self):
        envelope = build_winrs_create_request(timeout=20, session_id='uuid:SESSION', codepage=65001, no_profile=True)
        root = ET.fromstring(envelope_to_bytes(envelope))

        self.assertEqual(
            root.find('./s:Header/wsa:Action', SOAP_NAMESPACES).text,
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
        )
        self.assertEqual(root.find('./s:Header/wsman:ResourceURI', SOAP_NAMESPACES).text, WINRS_RESOURCE_URI)
        self.assertEqual(root.find('./s:Header/wsmv:SessionId', SOAP_NAMESPACES).text, 'uuid:SESSION')
        self.assertEqual(
            root.find('./s:Header/wsman:OptionSet/wsman:Option[@Name="WINRS_NOPROFILE"]', SOAP_NAMESPACES).text,
            'TRUE',
        )
        self.assertEqual(
            root.find('./s:Header/wsman:OptionSet/wsman:Option[@Name="WINRS_CODEPAGE"]', SOAP_NAMESPACES).text,
            '65001',
        )
        self.assertEqual(root.find('./s:Body/rsp:Shell/rsp:InputStreams', SOAP_NAMESPACES).text, 'stdin')
        self.assertEqual(root.find('./s:Body/rsp:Shell/rsp:OutputStreams', SOAP_NAMESPACES).text, 'stdout stderr')

    def test_build_command_and_receive_requests(self):
        command = build_winrs_command_request('shell-id', 'cmd.exe', ['/Q', '/c', 'whoami'], timeout=5, session_id='uuid:SESSION')
        receive = build_winrs_receive_request('shell-id', 'command-id', timeout=5, session_id='uuid:SESSION')

        command_root = ET.fromstring(envelope_to_bytes(command))
        receive_root = ET.fromstring(envelope_to_bytes(receive))

        self.assertEqual(
            command_root.find('./s:Body/rsp:CommandLine/rsp:Command', SOAP_NAMESPACES).text,
            'cmd.exe',
        )
        self.assertEqual(
            [node.text for node in command_root.findall('./s:Body/rsp:CommandLine/rsp:Arguments', SOAP_NAMESPACES)],
            ['/Q', '/c', 'whoami'],
        )
        self.assertEqual(
            command_root.find('./s:Header/wsman:SelectorSet/wsman:Selector[@Name="ShellId"]', SOAP_NAMESPACES).text,
            'shell-id',
        )
        self.assertEqual(
            receive_root.find('./s:Body/rsp:Receive/rsp:DesiredStream', SOAP_NAMESPACES).get('CommandId'),
            'command-id',
        )
        self.assertEqual(
            receive_root.find(
                './s:Header/wsman:OptionSet/wsman:Option[@Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE"]',
                SOAP_NAMESPACES,
            ).text,
            'true',
        )

    def test_parse_receive_response(self):
        stdout = base64.b64encode(b'hello\n').decode('ascii')
        stderr = base64.b64encode(b'warning\n').decode('ascii')
        response = '''
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
          <s:Header>
            <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse</wsa:Action>
          </s:Header>
          <s:Body>
            <rsp:ReceiveResponse>
              <rsp:Stream Name="stdout">{stdout}</rsp:Stream>
              <rsp:Stream Name="stderr">{stderr}</rsp:Stream>
              <rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
              </rsp:CommandState>
            </rsp:ReceiveResponse>
          </s:Body>
        </s:Envelope>
        '''.format(stdout=stdout, stderr=stderr)

        root = parse_wsman_response(response.encode('utf-8'))
        self.assertEqual(list(iter_streams(root)), [('stdout', b'hello\n'), ('stderr', b'warning\n')])
        self.assertEqual(parse_command_state(root), (
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done',
            0,
        ))

    def test_parse_shell_and_command_id(self):
        create_response = b'''
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                    xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
          <s:Header>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse</wsa:Action>
          </s:Header>
          <s:Body>
            <wsman:SelectorSet>
              <wsman:Selector Name="ShellId">shell-id</wsman:Selector>
            </wsman:SelectorSet>
          </s:Body>
        </s:Envelope>
        '''
        command_response = b'''
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
          <s:Header>
            <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse</wsa:Action>
          </s:Header>
          <s:Body>
            <rsp:CommandResponse>
              <rsp:CommandId>command-id</rsp:CommandId>
            </rsp:CommandResponse>
          </s:Body>
        </s:Envelope>
        '''

        self.assertEqual(parse_shell_id(parse_wsman_response(create_response)), 'shell-id')
        self.assertEqual(parse_command_id(parse_wsman_response(command_response)), 'command-id')

    def test_parse_fault_raises(self):
        fault = b'''
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body>
            <s:Fault>
              <s:Code>
                <s:Value>s:Sender</s:Value>
                <s:Subcode>
                  <s:Value>w:TimedOut</s:Value>
                </s:Subcode>
              </s:Code>
              <s:Reason>
                <s:Text xml:lang="en-US">The WS-Management service cannot process the request.</s:Text>
              </s:Reason>
              <s:Detail>
                <s:Message>Operation timed out</s:Message>
              </s:Detail>
            </s:Fault>
          </s:Body>
        </s:Envelope>
        '''

        with self.assertRaises(WinRMFaultError) as error:
            parse_wsman_response(fault)

        self.assertEqual(error.exception.code, 'w:TimedOut')
        self.assertEqual(error.exception.detail, 'Operation timed out')

    def test_keytab_rc4_hashes_are_reparsed_after_load(self):
        module = self._load_winrmexec_module()
        credentials = object()
        captured = {}

        def load_keytab(_path, _username, _domain, options):
            options.hashes = ':00112233445566778899AABBCCDDEEFF'

        def get_credentials(_spn, **kwargs):
            captured.update(kwargs)
            return credentials

        options = types.SimpleNamespace(
            target='TEST/user@server.test.local',
            hashes='',
            keytab='user.keytab',
            cert_pem='',
            cert_key='',
            ssl=False,
            aesKey='',
            k=True,
            basic=False,
            credssp=False,
            no_pass=True,
            timeout=1,
            target_ip='',
            url='',
            port=None,
            spn='HTTP/server.test.local',
            dc_ip='dc.test.local',
        )

        with mock.patch.object(module.Keytab, 'loadKeysFromKeytab', side_effect=load_keytab):
            with mock.patch.object(module, 'get_kerberos_credential', side_effect=get_credentials):
                transport = module.create_transport(options)

        self.assertIsInstance(transport, module.KerberosFallbackTransport)
        self.assertEqual(captured['lmhash'], '')
        self.assertEqual(captured['nthash'], '00112233445566778899AABBCCDDEEFF')

    def test_kerberos_transport_falls_back_on_first_auth_failure(self):
        module = self._load_winrmexec_module()
        credentials = object()
        kerberos_transport = mock.Mock()
        kerberos_transport.send.side_effect = WinRMAuthError('kerberos failed')
        negotiate_transport = mock.Mock()
        negotiate_transport.send.return_value = b'ok'

        with mock.patch.object(module, 'KerberosTransport', return_value=kerberos_transport):
            with mock.patch.object(module, 'NegotiateTransport', return_value=negotiate_transport):
                transport = module.KerberosFallbackTransport('http://server/wsman', credentials, timeout=5)
                result = transport.send(b'<request />')

        self.assertEqual(result, b'ok')
        kerberos_transport.close.assert_called_once_with()
        negotiate_transport.send.assert_called_once_with(b'<request />')

    def test_example_compiles(self):
        example_path = os.path.join(os.path.dirname(__file__), '..', '..', 'examples', 'winrmexec.py')
        py_compile.compile(example_path, doraise=True)


if __name__ == '__main__':
    unittest.main(verbosity=1)
