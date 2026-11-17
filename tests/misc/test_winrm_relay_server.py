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
import socket
import threading
import time
import unittest
from types import SimpleNamespace

from impacket.examples.ntlmrelayx.servers.winrmrelayserver import WinRMRelayServer


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def relay_config(port):
    return SimpleNamespace(
        listeningPort=port,
        interfaceIp="127.0.0.1",
        ipv6=False,
        target=None,
        disableMulti=True,
        protocolClients={},
        outputFile=None,
        mode="RELAY",
        attacks={},
        dumpHashes=False,
        redirecthost=None,
        remove_target=False,
        runSocks=False,
        serve_image=False,
        socksServer=None,
        wpad_auth_num=0,
        wpad_host=None,
    )


class WinRMRelayServerTests(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.server = WinRMRelayServer(relay_config(self.port))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()

        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)

        self.fail("WinRM relay server did not start")

    def tearDown(self):
        try:
            self.server.server.shutdown()
        except Exception:
            pass
        self.server.server.server_close()

    def post(self, request_line):
        request = (
            request_line
            + "\r\n"
            + "Host: 127.0.0.1\r\n"
            + "Content-Type: application/soap+xml; charset=UTF-8\r\n"
            + "Content-Length: 0\r\n"
            + "\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.sendall(request)
            return client.recv(4096).decode("latin-1", "replace")

    def test_absolute_form_request_is_not_treated_as_a_proxy(self):
        # WinRM clients use an absolute-form request target even on a direct
        # connection. Replying 407 makes the client drop the connection.
        response = self.post("POST http://127.0.0.1:%d/wsman HTTP/1.1" % self.port)

        self.assertTrue(response.startswith("HTTP/1.1 401"), response.splitlines()[0])
        self.assertIn("WWW-Authenticate: Negotiate", response)

    def test_origin_form_request_still_gets_401(self):
        response = self.post("POST /wsman HTTP/1.1")

        self.assertTrue(response.startswith("HTTP/1.1 401"), response.splitlines()[0])
        self.assertIn("WWW-Authenticate: Negotiate", response)


if __name__ == "__main__":
    unittest.main()
