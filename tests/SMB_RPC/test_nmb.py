import ConfigParser
import unittest

from impacket import nmb


class NMBTests(unittest.TestCase):
    def create_connection(self):
        pass

    def test_getnetbiosname(self):
        n = nmb.NetBIOS()
        res = n.getnetbiosname(self.machine)
        print repr(res)
        self.assertTrue( self.serverName, res)

    def test_getnodestatus(self):
        n = nmb.NetBIOS()
        resp = n.getnodestatus(self.serverName.upper(), self.machine)
        print resp

    def test_gethostbyname(self):
        n = nmb.NetBIOS()
        n.set_nameserver(self.serverName)
        resp = n.gethostbyname(self.serverName, nmb.TYPE_SERVER)
        print resp.entries

    def test_name_registration_request(self):
        n = nmb.NetBIOS()
        # ToDo: Look at this
        #resp = n.name_registration_request('*SMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None,nmb.NB_FLAGS_G, '1.1.1.1')
        resp = n.name_registration_request('*JSMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None,nmb.NB_FLAGS_ONT_P, '1.1.1.2')
        resp.dump()

    def test_name_query_request(self):
        n = nmb.NetBIOS()
        # ToDo: Look at this
        # resp = n.name_registration_request('*SMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None,nmb.NB_FLAGS_G, '1.1.1.1')
        resp = n.name_query_request(self.serverName, self.machine)
        print resp.entries

class NetBIOSTests(NMBTests):
    def setUp(self):
        NMBTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.machine  = configFile.get('SMBTransport', 'machine')

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(NetBIOSTests)
    unittest.TextTestRunner(verbosity=1).run(suite)
