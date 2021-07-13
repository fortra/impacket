###############################################################################
#  Tested so far:
#  EvtRpcRegisterLogQuery
#  hEvtRpcRegisterLogQuery
#  EvtRpcQueryNext
#  hEvtRpcQueryNext
###############################################################################

from __future__ import division
from __future__ import print_function
import pytest
import unittest
from tests import RemoteTestCase

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, even6
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.structure import hexdump


class EVEN6Tests(RemoteTestCase):

    def connect(self, version):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        if version == 1:
            dce.bind(even6.MSRPC_UUID_EVEN6, transfer_syntax=self.ts)
        else:
            dce.bind(even6.MSRPC_UUID_EVEN6, transfer_syntax=self.ts)

        return dce, rpctransport

    def test_EvtRpcRegisterLogQuery_EvtRpcQueryNext(self):
        dce, rpctransport = self.connect(2)

        request = even6.EvtRpcRegisterLogQuery()
        request['Path'] = 'Security\x00'
        request['Query'] = '*\x00'
        request['Flags'] = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest

        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception:
            return

        log_handle = resp['Handle']

        request = even6.EvtRpcQueryNext()
        request['LogQuery'] = log_handle
        request['NumRequestedRecords'] = 5
        request['TimeOutEnd'] = 1000
        request['Flags'] = 0
        request.dump()
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception:
            return

        for i in range(resp['NumActualRecords']):
            event_offset = resp['EventDataIndices'][i]['Data']
            event_size = resp['EventDataSizes'][i]['Data']
            event = resp['ResultBuffer'][event_offset:event_offset + event_size]
            buff = b''.join(event)
            print(hexdump(buff))

    def test_hEvtRpcRegisterLogQuery_hEvtRpcQueryNext(self):
        dce, rpctransport = self.connect(2)

        try:
            resp = even6.hEvtRpcRegisterLogQuery(dce, 'Security\x00', '*\x00', even6.EvtQueryChannelName | even6.EvtReadNewestToOldest)
            resp.dump()
        except Exception:
            return

        log_handle = resp['Handle']

        try:
            resp = even6.EvtRpcQueryNext(dce, log_handle, 5, 1000, 0)
            resp.dump()
        except Exception:
            return

        for i in range(resp['NumActualRecords']):
            event_offset = resp['EventDataIndices'][i]['Data']
            event_size = resp['EventDataSizes'][i]['Data']
            event = resp['ResultBuffer'][event_offset:event_offset + event_size]
            buff = ''.join([x.encode('hex') for x in event]).decode('hex')
            print(hexdump(buff))


@pytest.mark.remote
class SMBTransport(EVEN6Tests, unittest.TestCase):

    def setUp(self):
        super(SMBTransport, self).setUp()
        self.set_smb_transport_config()
        self.stringBinding = r'ncacn_np:%s[\PIPE\eventlog]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


@pytest.mark.remote
class SMBTransport64(SMBTransport):

    def setUp(self):
        super(SMBTransport64, self).setUp()
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


@pytest.mark.remote
class TCPTransport(EVEN6Tests, unittest.TestCase):

    def setUp(self):
        super(TCPTransport, self).setUp()
        self.set_tcp_transport_config()
        self.stringBinding = epm.hept_map(self.machine, even6.MSRPC_UUID_EVEN6, protocol='ncacn_ip_tcp')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


@pytest.mark.remote
class TCPTransport64(TCPTransport):

    def setUp(self):
        super(TCPTransport64, self).setUp()
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    unittest.main(verbosity=1)
