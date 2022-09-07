# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   (h)EvtRpcRegisterLogQuery
#   (h)EvtRpcQueryNext
# Not yet
#   EvtRpcQuerySeek
#   EvtRpcClose
#   EvtRpcOpenLogHandle
#   EvtRpcGetChannelList
#
from __future__ import division
from __future__ import print_function
import pytest
import unittest
from six.moves import xrange

from tests.dcerpc import DCERPCTests

from impacket.dcerpc.v5 import even6
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class EVEN6Tests(DCERPCTests):
    iface_uuid = even6.MSRPC_UUID_EVEN6
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    string_binding = r"ncacn_np:{0.machine}[\PIPE\eventlog]"
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_EvtRpcRegisterLogQuery_EvtRpcQueryNext(self):
        dce, rpctransport = self.connect()

        request = even6.EvtRpcRegisterLogQuery()
        request['Path'] = 'Security\x00'
        request['Query'] = '*\x00'
        request['Flags'] = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest
        request.dump()

        resp = dce.request(request)
        resp.dump()
        log_handle = resp['Handle']

        request = even6.EvtRpcQueryNext()
        request['LogQuery'] = log_handle
        request['NumRequestedRecords'] = 5
        request['TimeOutEnd'] = 1000
        request['Flags'] = 0
        request.dump()

        resp = dce.request(request)
        resp.dump()

        for i in xrange(resp['NumActualRecords']):
            event_offset = resp['EventDataIndices'][i]['Data']
            event_size = resp['EventDataSizes'][i]['Data']
            event = resp['ResultBuffer'][event_offset:event_offset + event_size]

    def test_hEvtRpcRegisterLogQuery_hEvtRpcQueryNext(self):
        dce, rpctransport = self.connect()

        resp = even6.hEvtRpcRegisterLogQuery(dce, 'Security\x00',
                                             even6.EvtQueryChannelName | even6.EvtReadNewestToOldest,
                                             '*\x00')
        resp.dump()
        log_handle = resp['Handle']

        resp = even6.hEvtRpcQueryNext(dce, log_handle, 5, 1000)
        resp.dump()

        for i in xrange(resp['NumActualRecords']):
            event_offset = resp['EventDataIndices'][i]['Data']
            event_size = resp['EventDataSizes'][i]['Data']
            event = resp['ResultBuffer'][event_offset:event_offset + event_size]


@pytest.mark.remote
class EVEN6TestsTCPTransport(EVEN6Tests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class EVEN6TestsTCPTransport64(EVEN6Tests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
