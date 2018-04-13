###############################################################################
#  Tested so far: 
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#  
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm
from impacket.dcerpc.v5.ndr import NULL
from impacket.uuid import string_to_bin, uuidtup_to_bin


class EPMTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_hept_map(self):
        MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))
        resp = epm.hept_map(self.machine,MSRPC_UUID_SAMR)
        resp = epm.hept_map(self.machine, MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
        MSRPC_UUID_ATSVC = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0'))
        resp = epm.hept_map(self.machine,MSRPC_UUID_ATSVC)
        MSRPC_UUID_SCMR = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))
        resp = epm.hept_map(self.machine,MSRPC_UUID_SCMR, protocol = 'ncacn_ip_tcp')

    def test_lookup(self):
        dce, rpctransport = self.connect()
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = NULL
        request['Ifid'] = NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 499
      
        resp = dce.request(request)
        for entry in resp['entries']:
            tower = entry['tower']['tower_octet_string']
            tower = epm.EPMTower(''.join(tower))
            #print tower['Floors'][0]
            #print tower['Floors'][1]

    def test_hlookup(self):
        resp = epm.hept_lookup(self.machine)
        #for entry in resp:
        #    print epm.PrintStringBinding(entry['tower']['Floors'], self.machine)
        MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))
        resp = epm.hept_lookup(self.machine, inquiry_type = epm.RPC_C_EP_MATCH_BY_IF, ifId = MSRPC_UUID_SAMR)
        MSRPC_UUID_ATSVC = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0'))
        resp = epm.hept_lookup(self.machine, inquiry_type = epm.RPC_C_EP_MATCH_BY_IF, ifId = MSRPC_UUID_ATSVC)
        MSRPC_UUID_SCMR = uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0'))
        resp = epm.hept_lookup(self.machine, inquiry_type = epm.RPC_C_EP_MATCH_BY_IF, ifId = MSRPC_UUID_SCMR)

    def test_map(self):
        dce, rpctransport = self.connect()
        tower2 = '\x04\x00\x13\x00\r\xac\xbe\x00\xc1:\xd3KJ\xbf#\xbb\xefFc\xd0\x17\x01\x00\x02\x00\x00\x00\x13\x00\r\x04]\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00+\x10H`\x02\x00\x02\x00\x00\x00\x01\x00\x0c\x02\x00\x00\x00\x01\x00\x10\x18\x00LRPC-26b184043749be8892\x00'
        tower = epm.EPMTower()
        interface = epm.EPMRPCInterface()
        interface['InterfaceUUID'] = string_to_bin('12345778-1234-ABCD-EF00-0123456789AC')
        interface['MajorVersion'] = 1
        interface['MinorVersion'] = 0

        dataRep = epm.EPMRPCDataRepresentation()
        dataRep['DataRepUuid'] = string_to_bin('8a885d04-1ceb-11c9-9fe8-08002b104860')
        dataRep['MajorVersion'] = 2
        dataRep['MinorVersion'] = 0

        protId = epm.EPMProtocolIdentifier()
        protId['ProtIdentifier'] = 0xb

        pipeName = epm.EPMPipeName()
        pipeName['PipeName'] = '\x00'

        portAddr = epm.EPMPortAddr()
        portAddr['IpPort'] = 0

        hostAddr = epm.EPMHostAddr()
        import socket
        hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')

        hostName = epm.EPMHostName()
        hostName['HostName'] = '\x00'

        tower['NumberOfFloors'] = 5
        tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + portAddr.getData() + hostAddr.getData()
        #tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + pipeName.getData() + hostName.getData()
        request = epm.ept_map()
        request['max_towers'] = 4
        request['map_tower']['tower_length'] = len(tower)
        request['map_tower']['tower_octet_string'] = str(tower)
        #request.dumpRaw()
        resp = dce.request(request)
        resp.dump()

class SMBTransport(EPMTests):
    def setUp(self):
        EPMTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport(EPMTests):
    def setUp(self):
        EPMTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s[135]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(EPMTests):
    def setUp(self):
        EPMTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\pipe\epmapper]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

class TCPTransport64(EPMTests):
    def setUp(self):
        EPMTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s[135]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        #suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport64)
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
