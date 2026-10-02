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
# Tests for the ntlmrelayx HTTP SOCKS plugin request rewriting
# (HTTPSocksRelay.prepareRequest).
#
import unittest

from impacket.examples.ntlmrelayx.servers.socksplugins.http import HTTPSocksRelay, EOL


class FakeSocket(object):
    """Minimal socket stand-in that yields a preloaded buffer in recv()-sized chunks."""

    def __init__(self, buffer=b''):
        self.buffer = buffer

    def recv(self, size):
        chunk = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return chunk


def build_relay(recv_buffer=b''):
    # Build an HTTPSocksRelay without running __init__ (it needs live sockets and
    # an activeRelays registry that are irrelevant to request rewriting).
    relay = HTTPSocksRelay.__new__(HTTPSocksRelay)
    relay.packetSize = 8192
    relay.socksSocket = FakeSocket(recv_buffer)
    return relay


def make_request(method, headers, body):
    head = method.encode() + b' / HTTP/1.1' + EOL
    head += EOL.join(h.encode() for h in headers) + EOL
    if body:
        head += (b'Content-Length: %d' % len(body)) + EOL
    head += EOL
    return head + body


def server_view(sent, body):
    """Model what the upstream server does: after the header terminator it reads
    Content-Length body bytes; anything past that is surplus left on the socket."""
    header_end = sent.find(EOL + EOL)
    body_start = header_end + 4
    read_body = sent[body_start:body_start + len(body)]
    leftover = len(sent) - (body_start + len(body))
    return read_body, leftover


class Test(unittest.TestCase):

    def _assert_clean(self, sent, original_body):
        read_body, leftover = server_view(sent, original_body)
        self.assertEqual(read_body, original_body,
                         "body the server reads must be byte-identical to the client's body")
        self.assertEqual(leftover, 0,
                         "no surplus bytes may remain on the keep-alive connection")

    def test_get_without_body(self):
        req = make_request('GET', ['Host: target', 'Authorization: Basic QUJD'], b'')
        sent = build_relay().prepareRequest(req)
        # Authorization header must be stripped
        self.assertNotIn(b'authorization', sent.lower())
        # A bodyless request has an empty body and no surplus
        self._assert_clean(sent, b'')

    def test_simple_post_body_preserved(self):
        body = b'field1=value1&field2=value2'
        req = make_request('POST', ['Host: target', 'Authorization: Basic QUJD',
                                    'Content-Type: application/x-www-form-urlencoded'], body)
        sent = build_relay().prepareRequest(req)
        self.assertNotIn(b'authorization', sent.lower())
        self._assert_clean(sent, body)

    def test_multipart_body_with_internal_crlfcrlf(self):
        # A multipart body always contains a CRLFCRLF between the part headers and
        # the file content. This is the case that split(EOL+EOL)[1] truncated.
        body = (b'--BOUNDARY\r\n'
                b'Content-Disposition: form-data; name="files"; filename="a.txt"\r\n'
                b'Content-Type: text/plain\r\n'
                b'\r\n'
                b'HELLO-PAYLOAD-DATA\r\n'
                b'--BOUNDARY--\r\n')
        req = make_request('POST', ['Host: target', 'Authorization: Basic QUJD',
                                    'Content-Type: multipart/form-data; boundary=BOUNDARY'], body)
        sent = build_relay().prepareRequest(req)
        self._assert_clean(sent, body)

    def test_connection_close_rewritten_to_keep_alive(self):
        body = b'x=1'
        req = make_request('POST', ['Host: target', 'Connection: close'], body)
        sent = build_relay().prepareRequest(req)
        self.assertNotIn(b'connection: close', sent.lower())
        self.assertIn(b'Connection: Keep-Alive', sent)
        self._assert_clean(sent, body)

    def test_large_multipacket_body(self):
        # Body larger than packetSize: the first recv() only carries the headers plus
        # the leading slice of the body, and prepareRequest must pull the remainder
        # off the socket across multiple recv() calls.
        payload = b'A' * 20000
        body = (b'--BOUNDARY\r\n'
                b'Content-Disposition: form-data; name="files"; filename="big.bin"\r\n'
                b'Content-Type: application/octet-stream\r\n'
                b'\r\n' + payload + b'\r\n'
                b'--BOUNDARY--\r\n')
        req = make_request('POST', ['Host: target', 'Authorization: Basic QUJD',
                                    'Content-Type: multipart/form-data; boundary=BOUNDARY'], body)
        self.assertGreater(len(req), 8192)
        first_chunk = req[:8192]
        remainder = req[8192:]
        relay = build_relay(recv_buffer=remainder)
        sent = relay.prepareRequest(first_chunk)
        self._assert_clean(sent, body)
        # The whole preloaded buffer must have been consumed
        self.assertEqual(relay.socksSocket.buffer, b'')


if __name__ == '__main__':
    unittest.main()
