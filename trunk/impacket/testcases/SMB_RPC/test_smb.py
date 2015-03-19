import unittest
from impacket import smb
from impacket.smbconnection import *
from impacket.smb3structs import *
import time, ntpath

# IMPORTANT NOTE:
# For some reason, under Windows 8, you cannot switch between
# dialects 002, 2_1 and 3_0 (it will throw STATUS_USER_SESSION_DELETED),
# but you can with SMB1.
# So, you can't run all test cases against the same machine.
# Usually running all the tests against a Windows 7 except SMB3
# would do the trick.
# ToDo:
# [ ] Add the rest of SMBConnection public methods

class SMBTests(unittest.TestCase):

    def test_connectTree(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        tid = smb.connectTree(self.share)
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        tid = smb.connectTree(UNC)

    def test_connection(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        credentials = smb.getCredentials()
        self.assertTrue( credentials == (self.username, self.password, self.domain, '','','', None, None))
        smb.logoff()
        del(smb)

    def test_loginHashes(self):
        lmhash, nthash = self.hashes.split(':')
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)    
        smb.login(self.username, '', self.domain, lmhash, nthash)
        credentials = smb.getCredentials()
        self.assertTrue( credentials == (self.username, '', self.domain, lmhash.decode('hex'), nthash.decode('hex'), '', None, None) )
        smb.logoff()

    def test_loginKerberosHashes(self):
        lmhash, nthash = self.hashes.split(':')
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)    
        smb.kerberosLogin(self.username, '', self.domain, lmhash, nthash, '')
        credentials = smb.getCredentials()
        self.assertTrue( credentials == (self.username, '', self.domain, lmhash.decode('hex'), nthash.decode('hex'), '', None, None) )
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        tid = smb.connectTree(UNC)
        smb.logoff()

    def test_loginKerberos(self):
        lmhash, nthash = self.hashes.split(':')
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)    
        smb.kerberosLogin(self.username, self.password, self.domain, '', '', '')
        credentials = smb.getCredentials()
        self.assertTrue( credentials == (self.username, self.password, self.domain, '','','', None, None) )
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        tid = smb.connectTree(UNC)
        smb.logoff()

    def test_loginKerberosAES(self):
        lmhash, nthash = self.hashes.split(':')
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)    
        smb.kerberosLogin(self.username, '', self.domain, '', '', self.aesKey)
        credentials = smb.getCredentials()
        self.assertTrue( credentials == (self.username, '', self.domain, '','',self.aesKey, None, None) )
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        tid = smb.connectTree(UNC)
        smb.logoff()

    def test_listPath(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects )
        smb.login(self.username, self.password, self.domain)
        smb.listPath(self.share, '*')
        smb.logoff()

    def test_createFile(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        smb.closeFile(tid,fid)
        smb.rename(self.share, self.file, self.file + '.bak')
        smb.deleteFile(self.share, self.file + '.bak')
        smb.disconnectTree(tid)
        smb.logoff()
        
    def test_readwriteFile(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        smb.writeFile(tid, fid, "A"*65535)
        data = smb.readFile(tid,fid, 0, 65535)
        self.assertTrue(len(data) == 65535)
        self.assertTrue(data == "A"*65535)
        smb.closeFile(tid,fid)
        fid = smb.openFile(tid, self.file)
        smb.closeFile(tid, fid)
        smb.deleteFile(self.share, self.file)
        smb.disconnectTree(tid)
        
        smb.logoff()
         
    def test_createdeleteDirectory(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        smb.createDirectory(self.share, self.directory)
        smb.deleteDirectory(self.share, self.directory) 
        smb.logoff()
 
    def test_getData(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        smb.getDialect()
        smb.getServerName()
        smb.getRemoteHost()
        smb.getServerDomain()
        smb.getServerOS()
        smb.doesSupportNTLMv2()
        smb.isLoginRequired()
        smb.logoff()

    def test_getServerName(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        serverName = smb.getServerName()
        self.assertTrue( serverName == self.serverName )
        smb.logoff()

    def test_getServerDomain(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        serverDomain = smb.getServerDomain()
        self.assertTrue( serverDomain.upper() == self.domain.upper())
        smb.logoff()

    def test_getRemoteHost(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        remoteHost = smb.getRemoteHost()
        self.assertTrue( remoteHost == self.machine)
        smb.logoff()

    def test_getDialect(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        dialect = smb.getDialect()
        self.assertTrue( dialect == self.dialects)
        smb.logoff()

    def test_uploadDownload(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        f = open(self.upload)
        smb.putFile(self.share, self.file, f.read)
        f.close()
        f = open(self.upload + '2', 'w+')
        smb.getFile(self.share, self.file, f.write)
        f.close()
        smb.deleteFile(self.share, self.file)
        smb.logoff()

    def test_listShares(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        smb.listShares()
        smb.logoff()

    def test_getSessionKey(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password, self.domain)
        smb.getSessionKey()
        smb.logoff
        

class SMB1Tests(SMBTests):
    def setUp(self):
        SMBTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        self.username = 'Administrator'
        self.domain   = 'FREEFLY'
        self.serverName = 'ULTIMATE64'
        self.password = 'Admin123456'
        self.hashes   = 'aad3b435b51404eeaad3b435b51404ee:ae4c0d5fb959fda8f4cb1d14a8376af4'
        self.aesKey   = ''
        self.machine  = '192.168.88.105'
        self.share    = 'C$'
        self.file     = '/TEST'
        self.directory= '/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = smb.SMB_DIALECT

class SMB002Tests(SMBTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB_002
        SMBTests.setUp(self)
        self.username = 'Administrator'
        self.domain   = 'FREEFLY'
        self.serverName = 'ULTIMATE64'
        self.password = 'Admin123456'
        self.hashes   = 'aad3b435b51404eeaad3b435b51404ee:ae4c0d5fb959fda8f4cb1d14a8376af4'
        self.aesKey   = ''
        self.machine  = '192.168.88.105'
        self.share    = 'C$'
        self.file     = '/TEST'
        self.directory= '/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = SMB2_DIALECT_002

class SMB21Tests(SMBTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB 2.1
        SMBTests.setUp(self)
        self.username = 'Administrator'
        self.domain   = 'FREEFLY'
        self.serverName = 'ULTIMATE64'
        self.password = 'Admin123456'
        self.hashes   = 'aad3b435b51404eeaad3b435b51404ee:ae4c0d5fb959fda8f4cb1d14a8376af4'
        self.aesKey   = ''
        self.machine  = '192.168.88.105'
        self.share    = 'C$'
        self.file     = '/TEST'
        self.directory= '/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = SMB2_DIALECT_21

class SMB3Tests(SMBTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB3
        SMBTests.setUp(self)
        self.username = 'admin'
        self.domain   = ''
        self.serverName = 'WINDOWS81'
        self.password = 'admin'
        self.hashes   = 'aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634'
        self.machine  = '192.168.88.114'
        self.share    = 'C$'
        self.file     = '/TEST'
        self.directory= '/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = SMB2_DIALECT_30

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(SMB1Tests)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMB002Tests))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMB21Tests))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMB3Tests))
    unittest.TextTestRunner(verbosity=1).run(suite)
