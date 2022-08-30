# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
from __future__ import division
from __future__ import print_function
from struct import unpack

import pytest
import unittest
from tests import RemoteTestCase

from impacket.dcerpc.v5 import transport, epm, rpch
from impacket.dcerpc.v5.ndr import NULL

@pytest.mark.remote
class RPCHTest(RemoteTestCase, unittest.TestCase):

    def setUp(self):
        super(RPCHTest, self).setUp()
        self.set_transport_config()

    def test_1(self):
        # Direct connection to ncacn_http service, RPC over HTTP v1
        # No authentication
        stringbinding = 'ncacn_http:%s' % self.machine
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 10

        dce.request(request)
        dce.disconnect()

        # Reconnecting
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        dce.request(request)
        dce.disconnect()


class RPCHLocalTest(unittest.TestCase):

    def test_2(self):
        # CONN/A1
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x4c\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x00\x00\x04\x00\x06\x00\x00\x00\x01\x00\x00\x00' + \
               b'\x03\x00\x00\x00\xb0\xf6\xaf\x3d\x77\x62\x98\x07\x9b\x21' + \
               b'\x54\x6e\xec\xf4\x22\x53\x03\x00\x00\x00\x3a\x24\x7a\x37' + \
               b'\x6d\xc1\xed\x2c\x68\x5d\x34\x35\x13\x46\x43\x25\x00\x00' + \
               b'\x00\x00\x00\x00\x04\x00'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        self.assertEqual(numberOfCommands, 4)
        self.assertEqual(packet['Flags'], rpch.RTS_FLAG_NONE)
        self.assertEqual(packet['frag_len'], 76)
        self.assertEqual(len(pduData), 56)

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        self.assertEqual(server_cmds[0].getData(), rpch.Version().getData())
        receiveWindowSize = rpch.ReceiveWindowSize()
        receiveWindowSize['ReceiveWindowSize'] = 262144

        self.assertEqual(server_cmds[3].getData(), receiveWindowSize.getData())

        cookie = rpch.Cookie()
        cookie['Cookie'] = b'\xb0\xf6\xaf=wb\x98\x07\x9b!Tn\xec\xf4"S'

        self.assertEqual(server_cmds[1].getData(), cookie.getData())

    def test_3(self):
        # CONN/A3
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x1c\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\xc0\xd4\x01\x00'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        connectionTimeout = rpch.ConnectionTimeout()
        connectionTimeout['ConnectionTimeout'] = 120000

        self.assertEqual(server_cmds[0].getData(), connectionTimeout.getData())

    def test_4(self):
        # PING
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x14\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x01\x00\x00\x00'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        self.assertEqual(packet['Flags'], rpch.RTS_FLAG_PING)

    def test_5(self):
        # CONN/C2
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x2c\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x00\x00\x03\x00\x06\x00\x00\x00\x01\x00\x00\x00' + \
               b'\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\xc0\xd4' + \
               b'\x01\x00'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        connectionTimeout = rpch.ConnectionTimeout()
        connectionTimeout['ConnectionTimeout'] = 120000

        self.assertEqual(server_cmds[2].getData(), connectionTimeout.getData())

        receiveWindowSize = rpch.ReceiveWindowSize()
        receiveWindowSize['ReceiveWindowSize'] = 65536

        self.assertEqual(server_cmds[1].getData(), receiveWindowSize.getData())
        self.assertEqual(server_cmds[0].getData(), rpch.Version().getData())

    def test_6(self):
        # FlowControlAckWithDestination
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x38\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x02\x00\x02\x00\x0d\x00\x00\x00\x00\x00\x00\x00' + \
               b'\x01\x00\x00\x00\x92\x80\x00\x00\x00\x00\x01\x00\xe3\x79' + \
               b'\x6e\x7c\xbc\x68\xa9\x4d\xab\x8d\x82\x40\xa0\x05\x72\x32'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        self.assertEqual(packet['Flags'], rpch.RTS_FLAG_OTHER_CMD)

        ack = rpch.Ack()
        ack['BytesReceived'] = 32914
        ack['AvailableWindow'] = 65536
        ack['ChannelCookie'] = rpch.RTSCookie()
        ack['ChannelCookie']['Cookie'] = b'\xe3yn|\xbch\xa9M\xab\x8d\x82@\xa0\x05r2'

        self.assertEqual(server_cmds[1]['Ack'].getData(), ack.getData())

    def test_7(self):
        # CONN/B2, IPv4
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x80\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x08\x00\x07\x00\x06\x00\x00\x00\x01\x00\x00\x00' + \
               b'\x03\x00\x00\x00\x61\xec\x8b\xb3\x40\x28\xa8\x46\xba\xfd' + \
               b'\x90\xcf\x6d\x31\xdc\x29\x03\x00\x00\x00\x20\xce\x94\x22' + \
               b'\x30\x83\x1b\x45\x94\xea\x0d\x7e\x05\xd2\xa8\x5a\x00\x00' + \
               b'\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\xc0\xd4\x01\x00' + \
               b'\x0c\x00\x00\x00\xdf\x28\xb4\x20\x77\xa4\x70\x42\xb1\xd1' + \
               b'\x4a\x03\x49\x5f\x6b\x7b\x0b\x00\x00\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x00\x00\xc0\xa8\x02\xfe\x00\x00\x00\x00\x00\x00' + \
               b'\x00\x00'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        self.assertEqual(packet['Flags'], rpch.RTS_FLAG_IN_CHANNEL)

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        # TODO: Check ClientAddress. Why is it in the padding?!

    def test_8(self):
        # CONN/A2
        resp = b'\x05\x00\x14\x03\x10\x00\x00\x00\x54\x00\x00\x00\x00\x00' + \
               b'\x00\x00\x10\x00\x05\x00\x06\x00\x00\x00\x01\x00\x00\x00' + \
               b'\x03\x00\x00\x00\x61\xec\x8b\xb3\x40\x28\xa8\x46\xba\xfd' + \
               b'\x90\xcf\x6d\x31\xdc\x29\x03\x00\x00\x00\xbc\x38\x10\x35' + \
               b'\xa7\xf0\x3d\x43\x9c\x3f\x44\x85\x6e\xf1\xc3\xb0\x04\x00' + \
               b'\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x01\x00'

        packet = rpch.RTSHeader(resp)
        packet.dump()

        pduData = packet['pduData']
        numberOfCommands = packet['NumberOfCommands']

        self.assertEqual(packet['Flags'], rpch.RTS_FLAG_OUT_CHANNEL)

        server_cmds = []
        while numberOfCommands > 0:
            numberOfCommands -= 1

            cmd_type = unpack('<L', pduData[:4])[0]
            cmd = rpch.COMMANDS[cmd_type](pduData)
            server_cmds.append(cmd)
            pduData = pduData[len(cmd):]

        for cmd in server_cmds:
            cmd.dump()

        channelLifetime = rpch.ChannelLifetime()
        channelLifetime['ChannelLifetime'] = 1073741824

        self.assertEqual(server_cmds[-2].getData(), channelLifetime.getData())


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
