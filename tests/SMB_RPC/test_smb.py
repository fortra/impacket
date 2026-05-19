# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import os
import errno
import socket
import select
import struct

try:
    import pytest
    remote_mark = pytest.mark.remote
except ImportError:
    pytest = None
    def remote_mark(c):
        return c
import unittest
from unittest.mock import Mock, patch, MagicMock
from tests import RemoteTestCase

from impacket.smbconnection import SMBConnection, SessionError, smb
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
        smb.isSigningRequired()
        smb.getIOCapabilities()
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

    def test_queryInfo(self):
        smb = self.create_connection()
        smb.login(self.username, self.password, self.domain)
        tid = smb.connectTree(self.share)
        fid = smb.createFile(tid, self.file)
        file_info = smb.queryInfo(tid, fid)
        self.assertEqual(file_info["AllocationSize"], 0)
        self.assertEqual(file_info["EndOfFile"], 0)
        self.assertEqual(file_info["Directory"], 0)
        smb.closeFile(tid,fid)
        smb.deleteFile(self.share, self.file)
        smb.disconnectTree(tid)
        smb.logoff()
    
    # ToDo: add to tests when merged to master.
    # def test_setInfo(self):
    #     import datetime
    #     smb = self.create_connection()
    #     smb.login(self.username, self.password, self.domain)
    #     tid = smb.connectTree(self.share)
    #     fid = smb.createFile(tid, self.file)
    #     info_data = smb.SMBSetFileBasicInfo()
    #     info_data['CreationTime'] = smb.POSIXtoFT(datetime.datetime(2003, 7, 7, 12, 34, 56, 789).timestamp())
    #     info_data['LastAccessTime'] = smb.POSIXtoFT(datetime.datetime(2003, 7, 7, 12, 34, 56, 789).timestamp())
    #     info_data['LastWriteTime'] = smb.POSIXtoFT(datetime.datetime(2003, 7, 7, 12, 34, 56, 789).timestamp())
    #     info_data['ChangeTime'] = smb.POSIXtoFT(datetime.datetime(2003, 7, 7, 12, 34, 56, 789).timestamp())
    #     info_data['ExtFileAttributes'] = 0
    #     info_data['Reserved'] = 0
    #     smb.setInfo(tid, fid, smb.SMB_SET_FILE_BASIC_INFO, info_data)
    #     smb.closeFile(tid,fid)
    #     smb.deleteFile(self.share, self.file)
    #     smb.disconnectTree(tid)
    #     smb.logoff()

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


@remote_mark
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


@remote_mark
class SMB1TestsNetBIOS(SMB1Tests):

    def setUp(self):
        super(SMB1TestsNetBIOS, self).setUp()
        self.sessPort = nmb.NETBIOS_SESSION_PORT


@remote_mark
class SMB1TestsUnicode(SMB1Tests):

    def setUp(self):
        super(SMB1TestsUnicode, self).setUp()
        self.flags2 = smb.SMB.FLAGS2_UNICODE | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_LONG_NAMES


@remote_mark
class SMB002Tests(SMB1Tests):

    def setUp(self):
        super(SMB002Tests, self).setUp()
        self.dialects = SMB2_DIALECT_002


@remote_mark
class SMB21Tests(SMB1Tests):

    def setUp(self):
        super(SMB21Tests, self).setUp()
        self.dialects = SMB2_DIALECT_21


@remote_mark
class SMB3Tests(SMB1Tests):

    def setUp(self):
        super(SMB3Tests, self).setUp()
        self.dialects = SMB2_DIALECT_30


class Test_Issue2099_SessionError_On_Truncated_Response(unittest.TestCase):
    """Regression for #2099: when session setup response is truncated/malformed, login must raise SessionError, not ValueError.

    Local test (mocks transport; no remote target). Runs with pytest -m 'not remote'.
    """

    def test_login_raises_session_error_when_session_response_parsing_fails(self):
        # When sessionData.fromString(sessionResponse['Data']) raises parse errors (e.g. ValueError/struct.error),
        # login_extended should catch it and raise SessionError so users see auth failure, not raw parse errors.
        from impacket.smb import (
            NewSMBPacket,
            SMBCommand,
            SMBSessionSetupAndX_Extended_Response_Parameters,
            SMBNTLMDialect_Parameters,
            SMBSessionSetupAndX_Extended_Response_Data,
        )

        # Build minimal negotiate response so neg_session succeeds
        neg_params = SMBNTLMDialect_Parameters()
        neg_params['DialectIndex'] = 0
        neg_params['SecurityMode'] = 0
        neg_params['MaxMpxCount'] = 2
        neg_params['MaxNumberVcs'] = 1
        neg_params['MaxBufferSize'] = 61440
        neg_params['MaxRawSize'] = 65536
        neg_params['SessionKey'] = 0
        neg_params['Capabilities'] = smb.SMB.CAP_EXTENDED_SECURITY
        neg_params['LowDateTime'] = 0
        neg_params['HighDateTime'] = 0
        neg_params['ServerTimeZone'] = 0
        neg_params['ChallengeLength'] = 0
        neg_cmd = SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        neg_cmd['Parameters'] = neg_params.getData()
        neg_cmd['Data'] = b'\x00' * 16  # ServerGUID + empty SecurityBlob for extended
        neg_pkt = NewSMBPacket()
        neg_pkt['Command'] = smb.SMB.SMB_COM_NEGOTIATE
        neg_pkt['ErrorClass'] = 0
        neg_pkt['ErrorCode'] = 0
        neg_pkt['Data'] = [neg_cmd.getData()]
        neg_bytes = neg_pkt.getData()

        # Build minimal session setup response (Data will be passed to fromString; we patch fromString to raise)
        resp_params = SMBSessionSetupAndX_Extended_Response_Parameters()
        resp_params['Action'] = 0
        resp_params['SecurityBlobLength'] = 0
        resp_cmd = SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
        resp_cmd['Parameters'] = resp_params.getData()
        resp_cmd['Data'] = b'TruncatedNoNUL'  # truncated so fromString would raise; we'll patch anyway
        resp_pkt = NewSMBPacket()
        resp_pkt['Command'] = smb.SMB.SMB_COM_SESSION_SETUP_ANDX
        resp_pkt['ErrorClass'] = 0
        resp_pkt['ErrorCode'] = 0
        resp_pkt['Uid'] = 1
        resp_pkt['Data'] = [resp_cmd.getData()]
        session_setup_bytes = resp_pkt.getData()

        class RecvResponse(object):
            def __init__(self, data):
                self._data = data
            def get_trailer(self):
                return self._data

        mock_sess = Mock()
        mock_sess.recv_packet = Mock(side_effect=[
            RecvResponse(neg_bytes),
            RecvResponse(session_setup_bytes),
        ])
        mock_sess.send_packet = Mock()

        parse_exceptions = [
            ValueError("Can't find NUL terminator in field 'NativeOS'"),
            struct.error("unpack requires a buffer of 2 bytes"),
        ]
        for parse_exc in parse_exceptions:
            with self.subTest(parse_exception=type(parse_exc).__name__):
                mock_sess.recv_packet = Mock(side_effect=[
                    RecvResponse(neg_bytes),
                    RecvResponse(session_setup_bytes),
                ])

                with patch('impacket.nmb.NetBIOSTCPSession', return_value=mock_sess), \
                     patch.object(SMBSessionSetupAndX_Extended_Response_Data, 'fromString', side_effect=parse_exc):
                    # Session setup response parsing raises; SMB.__init__ may call login('','') which
                    # triggers recv then fromString. Raised type is smb.SessionError (from init) or
                    # smbconnection.SessionError (from conn.login after init).
                    with self.assertRaises((SessionError, smb.SessionError)) as ctx:
                        conn = SMBConnection('127.0.0.1', '127.0.0.1')
                        conn.login('user', 'pass')
                    self.assertIsNotNone(getattr(ctx.exception, 'error', None) or getattr(ctx.exception, 'error_code', None))


if __name__ == "__main__":
    unittest.main(verbosity=1)
