import unittest

from impacket import smb
from impacket.smbconnection import *
from impacket.smb3structs import *
import time, ntpath

class SMBTests(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.username = 'test'
        self.password = 'passwd'
        self.machine  = '192.168.53.236'
        self.share    = 'c$'
        self.file     = '/tmp/TEST'
        self.directory= '/tmp/BETO'
        self.upload   = '../../nt_errors.py'
        #self.dialects = [smb.SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
        #self.dialects = smb.SMB_DIALECT
        self.dialects = SMB2_DIALECT_21

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

if __name__ == "__main__":
    unittest.main()
