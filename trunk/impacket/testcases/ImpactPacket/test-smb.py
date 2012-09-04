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

    def test_connection(self):
       smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
       smb.login(self.username, self.password)
       smb.logoff()
       del(smb)

    def test_loginHashes(self):
        pass

    def test_listPath(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects )
        smb.login(self.username, self.password)
        smb.listPath(self.share, '*')
        smb.logoff()

    def test_createFile(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        smb.closeFile(tid,fid)
        smb.deleteFile(self.share, self.file)
        smb.disconnectTree(tid)
        smb.logoff()
        
    def test_readwriteFile(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        smb.writeFile(tid, fid, "A"*65535)
        data = smb.readFile(tid,fid, 0, 65535)
        self.assertTrue(len(data) == 65535)
        self.assertTrue(data == "A"*65535)
        smb.closeFile(tid,fid)
        smb.deleteFile(self.share, self.file)
        smb.disconnectTree(tid)
        
        smb.logoff()
         
    def test_createdeleteDirectory(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password)
        smb.createDirectory(self.share, self.directory)
        smb.deleteDirectory(self.share, self.directory) 
        smb.logoff()
 
    def test_getData(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password)
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
        smb.login(self.username, self.password)
        smb.logoff()

    def test_uploadDownload(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect = self.dialects)
        smb.login(self.username, self.password)
        f = open(self.upload)
        smb.putFile(self.share, self.file, f.read)
        f.close()
        f = open(self.upload + '2', 'w+')
        smb.getFile(self.share, self.file, f.write)
        f.close()
        smb.deleteFile(self.share, self.file)
        smb.logoff()

class SMB1Tests(SMBTests):
    def setUp(self):
        SMBTests.setUp(self)
        # Put specific configuration for target machine with SMB1
        self.username = 'admin'
        self.password = 'admin'
        self.machine  = '192.168.53.218'
        self.share    = 'Users'
        self.file     = '/admin/TEST'
        self.directory= '/admin/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = smb.SMB_DIALECT

class SMB002Tests(SMBTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB_002
        SMBTests.setUp(self)
        self.username = 'admin'
        self.password = 'admin'
        self.machine  = '192.168.53.218'
        self.share    = 'Users'
        self.file     = '/admin/TEST'
        self.directory= '/admin/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = SMB2_DIALECT_002

class SMB21Tests(SMBTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB 2.1
        SMBTests.setUp(self)
        self.username = 'admin'
        self.password = 'admin'
        self.machine  = '192.168.53.218'
        self.share    = 'Users'
        self.file     = '/admin/TEST'
        self.directory= '/admin/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = SMB2_DIALECT_21

class SMB3Tests(SMBTests):
    def setUp(self):
        # Put specific configuration for target machine with SMB3
        SMBTests.setUp(self)
        self.username = 'admin'
        self.password = 'admin'
        self.machine  = '192.168.53.218'
        self.share    = 'Users'
        self.file     = '/admin/TEST'
        self.directory= '/admin/BETO'
        self.upload   = '../../nt_errors.py'
        self.dialects = SMB2_DIALECT_30

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(SMB1Tests)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMB002Tests))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMB21Tests))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMB3Tests))
    unittest.TextTestRunner(verbosity=1).run(suite)
