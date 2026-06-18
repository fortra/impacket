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
import struct
import unittest
from unittest import mock

from impacket.examples.ntlmrelayx.servers.socksserver import SocksRequestHandler


class _SuccessfulRelay:
    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        self.username = "USER"

    def initConnection(self):
        pass

    def skipAuthentication(self):
        return True

    def tunnelConnection(self):
        return True


class SocksRequestHandlerTests(unittest.TestCase):
    def test_successful_tunnel_does_not_send_final_error_reply(self):
        conn = mock.Mock(spec=socket.socket)
        conn.recv.side_effect = [
            b"\x05\x01\x00",
            b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 1433),
        ]
        conn.getsockname.return_value = ("127.0.0.1", 1080)

        server = mock.Mock()
        server.activeRelays = {
            "127.0.0.1": {
                1433: {
                    "scheme": "MSSQL",
                    "data": {},
                    "USER": {
                        "inUse": False,
                    },
                }
            }
        }
        server.socksPlugins = {"MSSQL": _SuccessfulRelay}

        handler = SocksRequestHandler.__new__(SocksRequestHandler)
        handler._SocksRequestHandler__socksServer = server
        handler._SocksRequestHandler__ip = "127.0.0.1"
        handler._SocksRequestHandler__port = 50000
        handler._SocksRequestHandler__connSocket = conn
        handler._SocksRequestHandler__socksVersion = 5
        handler.targetHost = None
        handler.targetPort = None
        handler._SocksRequestHandler__NBSession = None

        handler.handle()

        self.assertEqual(conn.sendall.call_count, 2)
        self.assertFalse(server.activeRelays["127.0.0.1"][1433]["USER"]["inUse"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
