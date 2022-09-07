# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import os
import errno
import socket
import select

import pytest
import unittest
from tests import RemoteTestCase

from impacket.smbconnection import SMBConnection, smb
from impacket.smb3structs import SMB2_DIALECT_002,SMB2_DIALECT_21, SMB2_DIALECT_30
from impacket import nt_errors, nmb

# IMPORTANT NOTE:
# For some reason, under Windows 8, you cannot switch between
# dialects 002, 2_1 and 3_0 (it will throw STATUS_USER_SESSION_DELETED),
# but you can with SMB1.
# So, you can't run all test cases against the same machine.
# Usually running all the tests against a Windows 7 except SMB3
# would do the trick.
# ToDo:
#   [ ] Add the rest of SMBConnection public methods


class SMBTests(RemoteTestCase):

    dialects = None

    def create_connection(self):
        if self.dialects == smb.SMB_DIALECT:
            # Only for SMB1 let's do manualNego
            s = SMBConnection(self.serverName, self.machine, preferredDialect=self.dialects, sess_port=self.sessPort, manualNegotiate=True)
            s.negotiateSession(self.dialects, flags2=self.flags2)
        else:
            s = SMBConnection(self.serverName, self.machine, preferredDialect=self.dialects, sess_port=self.sessPort)
        return s

    def test_aliasconnection(self):
        smb = SMBConnection('*SMBSERVER', self.machine, preferredDialect=self.dialects, sess_port=self.sessPort)
        smb.login(self.username, self.password, self.domain)
        smb.listPath(self.share, '*')
        smb.logoff()

    def test_reconnect(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb.listPath(self.share, '*')
        smb.logoff()
        smb.reconnect()
        smb.listPath(self.share, '*')
        smb.logoff()

    def test_reconnectKerberosHashes(self):
        smb = self.create_connection()
        smb.kerberosLogin(self.username, '', self.domain, self.lmhash, self.nthash, '')
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, '', self.domain, self.blmhash, self.bnthash, '', None, None))
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        smb.connectTree(UNC)
        smb.logoff()
        smb.reconnect()
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, '', self.domain, self.blmhash, self.bnthash, '', None, None))
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        smb.connectTree(UNC)
        smb.logoff()

    def test_connectTree(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb.connectTree(self.share)
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        smb.connectTree(UNC)

    def test_connection(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, self.password, self.domain, '', '', '', None, None))
        smb.logoff()
        del(smb)
        
    def test_close_connection(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb_connection_socket = smb.getSMBServer().get_socket()
        self.assertTrue(self.__is_socket_opened(smb_connection_socket))
        smb.close()
        self.assertFalse(self.__is_socket_opened(smb_connection_socket))
        del(smb)

    def test_manualNego(self):
        smb = self.create_connection()
        smb.negotiateSession(self.dialects)
        smb.login(self.username, self.password, self.domain)
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, self.password, self.domain, '', '', '', None, None))
        smb.logoff()
        del(smb)

    def test_loginHashes(self):
        smb = self.create_connection()
        smb.login(self.username, '', self.domain, self.lmhash, self.nthash)
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, '', self.domain, self.blmhash, self.bnthash, '', None, None))
        smb.logoff()

    def test_loginKerberosHashes(self):
        smb = self.create_connection()
        smb.kerberosLogin(self.username, '', self.domain, self.lmhash, self.nthash, '')
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, '', self.domain, self.blmhash, self.bnthash, '', None, None))
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        smb.connectTree(UNC)
        smb.logoff()

    def test_loginKerberos(self):
        smb = self.create_connection()
        smb.kerberosLogin(self.username, self.password, self.domain, '', '', '')
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, self.password, self.domain, '', '', '', None, None))
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        smb.connectTree(UNC)
        smb.logoff()

    def test_loginKerberosAES(self):
        smb = self.create_connection()
        smb.kerberosLogin(self.username, '', self.domain, '', '', self.aes_key_128)
        credentials = smb.getCredentials()
        self.assertEqual(credentials, (self.username, '', self.domain, '', '', self.aes_key_128, None, None))
        UNC = '\\\\%s\\%s' % (self.machine, self.share)
        smb.connectTree(UNC)
        smb.logoff()

    def test_listPath(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb.listPath(self.share, '*')
        smb.logoff()

    def test_createFile(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        smb.closeFile(tid,fid)
        smb.rename(self.share, self.file, self.file + '.bak')
        smb.deleteFile(self.share, self.file + '.bak')
        smb.disconnectTree(tid)
        smb.logoff()
        
    def test_readwriteFile(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        smb.writeFile(tid, fid, "A"*65535)
        data = b''
        offset = 0
        remaining = 65535
        while remaining>0:
            data += smb.readFile(tid,fid, offset, remaining)
            remaining = 65535 - len(data)
        self.assertEqual(len(data), 65535)
        self.assertEqual(data, b"A" * 65535)
        smb.closeFile(tid, fid)
        fid = smb.openFile(tid, self.file)
        smb.closeFile(tid, fid)
        smb.deleteFile(self.share, self.file)
        smb.disconnectTree(tid)
        
        smb.logoff()
         
    def test_createdeleteDirectory(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb.createDirectory(self.share, self.directory)
        smb.deleteDirectory(self.share, self.directory)
        smb.createDirectory(self.share, self.directory)
        nested_dir = "%s\\%s" %(self.directory, self.directory)
        smb.createDirectory(self.share, nested_dir)
        try:
            smb.deleteDirectory(self.share, self.directory)
        except Exception as e:
            if e.error == nt_errors.STATUS_DIRECTORY_NOT_EMPTY:
                smb.deleteDirectory(self.share, nested_dir)
                smb.deleteDirectory(self.share, self.directory)
        smb.logoff()
 
    def test_getData(self):
        smb = self.create_connection()
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
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        serverName = smb.getServerName()
        self.assertEqual(serverName.upper(), self.serverName.upper())
        smb.logoff()

    def test_getServerDNSDomainName(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        serverDomain = smb.getServerDNSDomainName()
        self.assertEqual(serverDomain.upper(), self.domain.upper())
        smb.logoff()

    def test_getServerDomain(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        serverDomain = smb.getServerDomain()
        self.assertEqual(serverDomain.upper(), self.domain.upper().split('.')[0])
        smb.logoff()

    def test_getRemoteHost(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        remoteHost = smb.getRemoteHost()
        self.assertEqual(remoteHost, self.machine)
        smb.logoff()

    def test_getDialect(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        dialect = smb.getDialect()
        self.assertEqual(dialect, self.dialects)
        smb.logoff()

    def test_uploadDownload(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        f = open(self.upload)
        smb.putFile(self.share, self.file, f.read)
        f.close()
        f = open(self.upload + '2', 'wb+')
        smb.getFile(self.share, self.file, f.write)
        f.close()
        os.unlink(self.upload + '2')
        smb.deleteFile(self.share, self.file)
        smb.logoff()

    def test_listShares(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb.listShares()
        smb.logoff()

    def test_getSessionKey(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        smb.getSessionKey()
        smb.logoff()
        
    def __is_socket_opened(self, s):
        # We assume that if socket is selectable, it's open; and if it were not, it's closed.
        # Note: this method is accurate as long as the file descriptor used for the socket is not re-used
        is_socket_opened = True 
        try:
            select.select([s], [], [], 0)
        except socket.error as e:
            if e.errno == errno.EBADF:
                is_socket_opened = False
        except ValueError:
            is_socket_opened = False
        return is_socket_opened


@pytest.mark.remote
class SMB1Tests(SMBTests, unittest.TestCase):

    def setUp(self):
        super(SMB1Tests, self).setUp()
        self.set_transport_config(aes_keys=True)
        self.share = 'C$'
        self.file = '/TEST'
        self.directory = '/BETO'
        self.upload = 'impacket/nt_errors.py'
        self.flags2 = smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_LONG_NAMES
        self.dialects = smb.SMB_DIALECT
        self.sessPort = nmb.SMB_SESSION_PORT


@pytest.mark.remote
class SMB1TestsNetBIOS(SMB1Tests):

    def setUp(self):
        super(SMB1TestsNetBIOS, self).setUp()
        self.sessPort = nmb.NETBIOS_SESSION_PORT


@pytest.mark.remote
class SMB1TestsUnicode(SMB1Tests):

    def setUp(self):
        super(SMB1TestsUnicode, self).setUp()
        self.flags2 = smb.SMB.FLAGS2_UNICODE | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_LONG_NAMES


@pytest.mark.remote
class SMB002Tests(SMB1Tests):

    def setUp(self):
        super(SMB002Tests, self).setUp()
        self.dialects = SMB2_DIALECT_002


@pytest.mark.remote
class SMB21Tests(SMB1Tests):

    def setUp(self):
        super(SMB21Tests, self).setUp()
        self.dialects = SMB2_DIALECT_21


@pytest.mark.remote
class SMB3Tests(SMB1Tests):

    def setUp(self):
        super(SMB3Tests, self).setUp()
        self.dialects = SMB2_DIALECT_30


if __name__ == "__main__":
    unittest.main(verbosity=1)
