###############################################################################
#  Tested so far: 
#
# BackuprKey
# 
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, bkrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED
from impacket.winregistry import hexdump

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print "In order to run these test cases you need the cryptography package"


class BKRPTests(unittest.TestCase):
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
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(bkrp.MSRPC_UUID_BKRP, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_BackuprKey_BACKUPKEY_BACKUP_GUID_BACKUPKEY_RESTORE_GUID(self):
        dce, rpctransport = self.connect()
        DataIn = "Huh? wait wait, let me, let me explain something to you. Uh, I am not Mr. Lebowski; " \
                 "you're Mr. Lebowski. I'm the Dude. So that's what you call me. You know, uh, That, or uh, " \
                 "his Dudeness, or uh Duder, or uh El Duderino, if, you know, you're not into the whole brevity thing--uh."
        request = bkrp.BackuprKey()
        request['pguidActionAgent'] = bkrp.BACKUPKEY_BACKUP_GUID
        request['pDataIn'] = DataIn
        request['cbDataIn'] = len(DataIn)
        request['dwParam'] = 0

        resp = dce.request(request)

        resp.dump()

        wrapped = bkrp.WRAPPED_SECRET()
        wrapped.fromString(''.join(resp['ppDataOut']))
        wrapped.dump()

        request = bkrp.BackuprKey()
        request['pguidActionAgent'] = bkrp.BACKUPKEY_RESTORE_GUID
        request['pDataIn'] = ''.join(resp['ppDataOut'])
        request['cbDataIn'] = resp['pcbDataOut']
        request['dwParam'] = 0

        resp = dce.request(request)

        resp.dump()

        assert(DataIn == ''.join(resp['ppDataOut']))

    def test_hBackuprKey_BACKUPKEY_BACKUP_GUID_BACKUPKEY_RESTORE_GUID(self):
        dce, rpctransport = self.connect()

        DataIn = "Huh? wait wait, let me, let me explain something to you. Uh, I am not Mr. Lebowski; " \
                 "you're Mr. Lebowski. I'm the Dude. So that's what you call me. You know, uh, That, or uh, " \
                 "his Dudeness, or uh Duder, or uh El Duderino, if, you know, you're not into the whole brevity thing--uh."
        resp = bkrp.hBackuprKey(dce, bkrp.BACKUPKEY_BACKUP_GUID, DataIn)

        resp.dump()

        wrapped = bkrp.WRAPPED_SECRET()
        wrapped.fromString(''.join(resp['ppDataOut']))
        wrapped.dump()

        resp = bkrp.hBackuprKey(dce, bkrp.BACKUPKEY_RESTORE_GUID, ''.join(resp['ppDataOut']))

        resp.dump()

        assert (DataIn == ''.join(resp['ppDataOut']))

    def test_BackuprKey_BACKUPKEY_BACKUP_GUID_BACKUPKEY_RESTORE_GUID_WIN2K(self):
        dce, rpctransport = self.connect()
        DataIn = "Huh? wait wait, let me, let me explain something to you. Uh, I am not Mr. Lebowski; " \
                 "you're Mr. Lebowski. I'm the Dude. So that's what you call me. You know, uh, That, or uh, " \
                 "his Dudeness, or uh Duder, or uh El Duderino, if, you know, you're not into the whole brevity thing--uh."
        request = bkrp.BackuprKey()
        request['pguidActionAgent'] = bkrp.BACKUPKEY_BACKUP_GUID
        request['pDataIn'] = DataIn
        request['cbDataIn'] = len(DataIn)
        request['dwParam'] = 0

        resp = dce.request(request)

        resp.dump()

        wrapped = bkrp.WRAPPED_SECRET()
        wrapped.fromString(''.join(resp['ppDataOut']))
        wrapped.dump()

        request = bkrp.BackuprKey()
        request['pguidActionAgent'] = bkrp.BACKUPKEY_RESTORE_GUID_WIN2K
        request['pDataIn'] = ''.join(resp['ppDataOut'])
        request['cbDataIn'] = resp['pcbDataOut']
        request['dwParam'] = 0

        resp = dce.request(request)

        resp.dump()

        assert(DataIn == ''.join(resp['ppDataOut']))

    def test_hBackuprKey_BACKUPKEY_BACKUP_GUID_BACKUPKEY_RESTORE_GUID_WIN2K(self):
        dce, rpctransport = self.connect()

        DataIn = "Huh? wait wait, let me, let me explain something to you. Uh, I am not Mr. Lebowski; " \
                 "you're Mr. Lebowski. I'm the Dude. So that's what you call me. You know, uh, That, or uh, " \
                 "his Dudeness, or uh Duder, or uh El Duderino, if, you know, you're not into the whole brevity thing--uh."
        resp = bkrp.hBackuprKey(dce, bkrp.BACKUPKEY_BACKUP_GUID, DataIn )

        resp.dump()

        wrapped = bkrp.WRAPPED_SECRET()
        wrapped.fromString(''.join(resp['ppDataOut']))
        wrapped.dump()

        resp = bkrp.hBackuprKey(dce, bkrp.BACKUPKEY_RESTORE_GUID_WIN2K, ''.join(resp['ppDataOut']) )

        resp.dump()

        assert(DataIn == ''.join(resp['ppDataOut']))


    def test_BackuprKey_BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID(self):
        dce, rpctransport = self.connect()
        request = bkrp.BackuprKey()
        request['pguidActionAgent'] = bkrp.BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID
        request['pDataIn'] = NULL
        request['cbDataIn'] = 0
        request['dwParam'] = 0

        resp = dce.request(request)

        resp.dump()

        #print "LEN: %d" % len(''.join(resp['ppDataOut']))
        #hexdump(''.join(resp['ppDataOut']))

        cert = x509.load_der_x509_certificate(''.join(resp['ppDataOut']), default_backend())

        print cert.subject
        print cert.issuer
        print cert.signature

    def test_hBackuprKey_BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID(self):
        dce, rpctransport = self.connect()
        request = bkrp.BackuprKey()
        request['pguidActionAgent'] = bkrp.BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID
        request['pDataIn'] = NULL
        request['cbDataIn'] = 0
        request['dwParam'] = 0

        resp = bkrp.hBackuprKey(dce, bkrp.BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, NULL)

        resp.dump()

        #print "LEN: %d" % len(''.join(resp['ppDataOut']))
        #hexdump(''.join(resp['ppDataOut']))

        cert = x509.load_der_x509_certificate(''.join(resp['ppDataOut']), default_backend())

        print cert.subject
        print cert.issuer
        print cert.signature


class SMBTransport(BKRPTests):
    def setUp(self):
        BKRPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\protected_storage]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(BKRPTests):
    def setUp(self):
        BKRPTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\protected_storage]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
