# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import unittest

from impacket import nmb
from impacket.structure import hexdump


class NMBTests(unittest.TestCase):
    def create_connection(self):
        pass

    def test_encodedecodename(self):
        name = 'THISISAVERYLONGLONGNAME'
        encoded = nmb.encode_name(name,nmb.TYPE_SERVER,None)
        hexdump(encoded)
        decoded = nmb.decode_name(encoded)
        hexdump(bytearray(decoded[1],'utf-8'))

        #self.assertTrue(nmb.TYPE_SERVER==decoded[0])
        self.assertTrue(name[:15]==decoded[1].strip())

        # ToDo: Fix the scope functionality
        #namescope = 'MYNAME'
        #encoded = nmb.encode_name(namescope,nmb.TYPE_SERVER,'SCOPE')
        #hexdump(encoded)
        #decoded = nmb.decode_name(encoded)
        #hexdump(decoded)

        #self.assertTrue(nmb.TYPE_SERVER==decoded[0])
        #self.assertTrue(namescope[:15]==decoded[1].strip())

    def test_getnetbiosname(self):
        n = nmb.NetBIOS()
        res = n.getnetbiosname(self.machine)
        print(repr(res))
        self.assertTrue( self.serverName, res)

    def test_getnodestatus(self):
        n = nmb.NetBIOS()
        resp = n.getnodestatus(self.serverName.upper(), self.machine)
        for r in resp:
            r.dump()
        print(resp)

    def test_gethostbyname(self):
        n = nmb.NetBIOS()
        n.set_nameserver(self.serverName)
        resp = n.gethostbyname(self.serverName, nmb.TYPE_SERVER)
        print((resp.entries))

    def test_name_registration_request(self):
        n = nmb.NetBIOS()
        # ToDo: Look at this
        #resp = n.name_registration_request('*SMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None,nmb.NB_FLAGS_G, '1.1.1.1')
        try:
            resp = n.name_registration_request('*JSMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None,nmb.NB_FLAGS_ONT_P, '1.1.1.2')
            resp.dump()
        except Exception as e:
            print(str(e))
            if str(e).find('NETBIOS') <= 0:
                raise e

    def test_name_query_request(self):
        n = nmb.NetBIOS()
        # ToDo: Look at this
        # resp = n.name_registration_request('*SMBSERVER', self.serverName, nmb.TYPE_WORKSTATION, None,nmb.NB_FLAGS_G, '1.1.1.1')
        resp = n.name_query_request(self.serverName, self.machine)
        print((resp.entries))

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
    unittest.main(defaultTest='suite')
