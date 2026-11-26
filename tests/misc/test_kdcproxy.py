import datetime
import importlib.util
import ssl
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pyasn1.codec.der import encoder

from impacket.krb5 import constants
from impacket.krb5.asn1 import KDC_PROXY_MESSAGE, KRB_ERROR, seq_set
from impacket.krb5.kdcproxy import KDCProxyClient, KDCProxyError
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import KerberosTime, Principal


def proxy_response(reply):
    message = KDC_PROXY_MESSAGE()
    message['kerb-message'] = len(reply).to_bytes(4, 'big') + reply
    return encoder.encode(message)


def kerberos_error(code):
    error = KRB_ERROR()
    error['pvno'] = 5
    error['msg-type'] = constants.ApplicationTagNumbers.KRB_ERROR.value
    error['stime'] = KerberosTime.to_asn1(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
    error['susec'] = 0
    error['error-code'] = code
    error['realm'] = 'EXAMPLE.TEST'
    seq_set(error, 'sname', Principal('krbtgt/EXAMPLE.TEST',
        type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    return encoder.encode(error)


def load_example(name):
    path = Path(__file__).resolve().parents[2] / 'examples' / (name + '.py')
    spec = importlib.util.spec_from_file_location('impacket_' + name + '_kdcproxy', path)
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    return example


class KDCProxyClientTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('impacket.krb5.kdcproxy.HTTPSConnection')
        self.connection = patcher.start().return_value
        self.addCleanup(patcher.stop)
        self.response = self.connection.getresponse.return_value
        self.response.status = 200

    def test_https_exchange_framing_and_realm(self):
        self.response.read.return_value = proxy_response(b'\x6b\x00')
        with mock.patch('ssl.create_default_context', side_effect=AssertionError('insecure default context used')):
            client = KDCProxyClient('https://proxy.example.test/KdcProxy?site=one')
        self.assertTrue(client.context.check_hostname)
        self.assertEqual(client.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(client.exchange(b'\x6a\x00', 'EXAMPLE.TEST', timeout=7), b'\x6b\x00')

        method, path, body = self.connection.request.call_args.args
        self.assertEqual((method, path), ('POST', '/KdcProxy?site=one'))
        self.assertEqual(body, bytes.fromhex(
            '30 1a a0 08 04 06 00 00 00 02 6a 00 a1 0e 1b 0c '
            '45 58 41 4d 50 4c 45 2e 54 45 53 54'))
        self.assertEqual(self.connection.request.call_args.kwargs['headers']['Content-Type'],
                         'application/kerberos')
        self.connection.close.assert_called_once()

    def test_kerberos_errors_follow_direct_exchange_contract(self):
        client = KDCProxyClient('https://proxy.example.test')
        preauth = kerberos_error(constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value)
        self.response.read.return_value = proxy_response(preauth)
        self.assertEqual(client.exchange(b'\x6a\x00', 'EXAMPLE.TEST'), preauth)

        failure = kerberos_error(constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value)
        self.response.read.return_value = proxy_response(failure)
        with self.assertRaises(KerberosError) as caught:
            client.exchange(b'\x6a\x00', 'EXAMPLE.TEST')
        self.assertEqual(caught.exception.getErrorCode(), constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value)

    def test_rejects_bad_transport_and_proxy_responses(self):
        for url in ('http://proxy.example.test', 'https://user@proxy.example.test',
                    'https://@proxy.example.test',
                    'https://proxy.example.test/path#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                KDCProxyClient(url)
        client = KDCProxyClient('https://proxy.example.test')
        with self.assertRaises(ValueError):
            client.exchange(b'\x6a\x00', 'EXAMPLE.TEST', kdcHost='dc.example.test')
        self.connection.request.assert_not_called()

        self.response.status = 503
        with self.assertRaisesRegex(KDCProxyError, 'HTTP status 503'):
            client.exchange(b'\x6a\x00', 'EXAMPLE.TEST')
        self.response.status = 200
        for body in (b'not DER', proxy_response(b'\x6b\x00') + b'junk'):
            self.response.read.return_value = body
            with self.subTest(body=body), self.assertRaises(KDCProxyError):
                client.exchange(b'\x6a\x00', 'EXAMPLE.TEST')
        message = KDC_PROXY_MESSAGE()
        message['kerb-message'] = b'\x00\x00\x00\x03\x6b\x00'
        self.response.read.return_value = encoder.encode(message)
        with self.assertRaisesRegex(KDCProxyError, 'message length'):
            client.exchange(b'\x6a\x00', 'EXAMPLE.TEST')
        self.response.read.return_value = b'0123456789'
        with mock.patch('impacket.krb5.kdcproxy.MAX_RESPONSE_SIZE', 8):
            with self.assertRaisesRegex(KDCProxyError, 'too large'):
                client.exchange(b'\x6a\x00', 'EXAMPLE.TEST')

    def test_gettgt_example_passes_selected_exchange(self):
        example = load_example('getTGT')
        options = SimpleNamespace(aesKey='', dc_ip=None, service=None, hashes=None,
                                  principalType=constants.PrincipalNameType.NT_PRINCIPAL,
                                  via_kdc_proxy='https://proxy.example.test/KdcProxy',
                                  kdc_proxy_ca=None)
        example.options = options  # The existing example reads its parsed options from module scope.
        client = mock.Mock()
        command = example.GETTGT('user', '', 'EXAMPLE.TEST', options, certificate=mock.sentinel.certificate)
        with mock.patch.object(example, 'KDCProxyClient', return_value=client), \
                mock.patch.object(example, 'getKerberosTGT', return_value=(b'tgt', None, b'key', None)) as tgt, \
                mock.patch.object(command, 'saveTicket'):
            command.run()
        self.assertIs(tgt.call_args.kwargs['exchange'], client.exchange)
        self.assertIs(tgt.call_args.kwargs['certificate'], mock.sentinel.certificate)

    def test_getst_example_passes_selected_exchange(self):
        example = load_example('getST')
        options = SimpleNamespace(aesKey='', dc_ip=None, force_forwardable=False,
                                  additional_ticket=None, dmsa=False, no_s4u2proxy=False,
                                  hashes=None, impersonate=None, renew=False,
                                  spn='cifs/server.example.test')
        exchange = mock.Mock()
        command = example.GETST('user', '', 'EXAMPLE.TEST', options, exchange=exchange)
        key = SimpleNamespace(contents=b'key')
        with mock.patch.object(example.CCache, 'parseFile', return_value=('EXAMPLE.TEST', None, None, None)), \
                mock.patch.object(example, 'getKerberosTGT', return_value=(b'tgt', None, key, key)) as tgt, \
                mock.patch.object(example, 'getKerberosTGS', return_value=(b'tgs', None, key, key)) as tgs, \
                mock.patch.object(command, 'saveTicket'):
            command.run()
        self.assertIs(tgt.call_args.kwargs['exchange'], exchange)
        self.assertIs(tgs.call_args.kwargs['exchange'], exchange)
