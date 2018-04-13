###############################################################################
#  Tested so far: 
#
#
#  Not yet:
#
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import mimilib, epm
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, OWNER_SECURITY_INFORMATION
from impacket.winregistry import hexdump
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class RRPTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        rpctransport.set_connect_timeout(30000)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        #if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
        #    rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(mimilib.MSRPC_UUID_MIMIKATZ, transfer_syntax = self.ts)
        dh = mimilib.MimiDiffeH()
        blob = mimilib.PUBLICKEYBLOB()
        blob['y'] = dh.genPublicKey()[::-1]
        request = mimilib.MimiBind()
        request['clientPublicKey']['sessionType'] = mimilib.CALG_RC4
        request['clientPublicKey']['cbPublicKey'] = 144
        request['clientPublicKey']['pbPublicKey'] = str(blob)
        resp = dce.request(request)
        blob = mimilib.PUBLICKEYBLOB(''.join(resp['serverPublicKey']['pbPublicKey']))
        key = dh.getSharedSecret(''.join(blob['y'])[::-1])
        pHandle = resp['phMimi']

        return dce, rpctransport, pHandle, key[-16:]

    def test_MimiBind(self):
        dce, rpctransport, pHandle, key = self.connect()
        dh = mimilib.MimiDiffeH()
        print 'Our Public'
        print '='*80
        hexdump(dh.genPublicKey())

        blob = mimilib.PUBLICKEYBLOB()
        blob['y'] = dh.genPublicKey()[::-1]
        request = mimilib.MimiBind()
        request['clientPublicKey']['sessionType'] = mimilib.CALG_RC4
        request['clientPublicKey']['cbPublicKey'] = 144
        request['clientPublicKey']['pbPublicKey'] = str(blob)

        resp = dce.request(request)
        blob = mimilib.PUBLICKEYBLOB(''.join(resp['serverPublicKey']['pbPublicKey']))
        print '='*80
        print 'Server Public'
        hexdump(''.join(blob['y']))
        print '='*80
        print 'Shared'
        hexdump(dh.getSharedSecret(''.join(blob['y'])[::-1]))
        resp.dump()

    def test_MimiCommand(self):
        dce, rpctransport, pHandle, key = self.connect()
        from Crypto.Cipher import ARC4
        cipher = ARC4.new(key[::-1])
        command = cipher.encrypt('token::whoami\x00'.encode('utf-16le'))
        #command = cipher.encrypt('sekurlsa::logonPasswords\x00'.encode('utf-16le'))
        #command = cipher.encrypt('process::imports\x00'.encode('utf-16le'))
        request = mimilib.MimiCommand()
        request['phMimi'] = pHandle
        request['szEncCommand'] = len(command)
        request['encCommand'] = list(command)
        resp = dce.request(request)
        cipherText = ''.join(resp['encResult'])
        cipher = ARC4.new(key[::-1])
        plain = cipher.decrypt(cipherText)
        print '='*80
        print plain
        #resp.dump()

    def test_MimiUnBind(self):
        dce, rpctransport, pHandle, key = self.connect()
        command = 'token::whoami\x00'
        request = mimilib.MimiUnbind()
        request['phMimi'] = pHandle
        hexdump(str(request))
        resp = dce.request(request)
        resp.dump()

class TCPTransport(RRPTests):
    def setUp(self):
        RRPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, mimilib.MSRPC_UUID_MIMIKATZ, protocol = 'ncacn_ip_tcp')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
