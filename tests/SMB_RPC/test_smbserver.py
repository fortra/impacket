#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Basic unit tests for the SMB Server.
#
# Author:
#   Martin Gallo (@martingalloar)
#
# TODO:
#     The following are all the commands implemented by SMBServer:
#     [ ] TRANSCommands
#         [ ] lanMan
#         [ ] transactNamedPipe
#     [ ] TRANS2Commands
#         [ ] setPathInformation
#         [ ] setFileInformation
#         [ ] queryPathInformation
#         [ ] queryFileInformation
#         [ ] queryFsInformation
#         [ ] findNext2
#         [ ] findFirst2
#     [ ] SMBCommands
#         [ ] smbTransaction
#         [ ] smbNTTransact
#         [ ] smbTransaction2
#         [ ] smbComLockingAndX
#         [ ] smbComClose
#         [ ] smbComWrite
#         [ ] smbComFlush
#         [ ] smbComCreateDirectory
#         [ ] smbComRename
#         [ ] smbComDelete
#         [ ] smbComDeleteDirectory
#         [ ] smbComWriteAndX
#         [ ] smbComRead
#         [ ] smbComReadAndX
#         [ ] smbQueryInformation
#         [ ] smbQueryInformationDisk
#         [ ] smbComEcho
#         [ ] smbComTreeDisconnect
#         [ ] smbComLogOffAndX
#         [ ] smbComQueryInformation2
#         [ ] smbComNtCreateAndX
#         [ ] smbComOpenAndX
#         [ ] smbComTreeConnectAndX
#         [ ] smbComSessionSetupAndX
#         [ ] smbComNegotiate
#     [ ] SMB2Commands
#         [ ] smb2Negotiate
#         [ ] smb2SessionSetup
#         [ ] smb2TreeConnect
#         [ ] smb2Create
#         [ ] smb2Close
#         [ ] smb2QueryInfo
#         [ ] smb2SetInfo
#         [ ] smb2Write
#         [ ] smb2Read
#         [ ] smb2Flush
#         [ ] smb2QueryDirectory
#         [ ] smb2ChangeNotify
#         [ ] smb2Echo
#         [ ] smb2TreeDisconnect
#         [ ] smb2Logoff
#         [ ] smb2Ioctl
#         [ ] smb2Lock
#         [ ] smb2Cancel
#
import unittest
from time import sleep
from os.path import exists, join
from os import mkdir, rmdir, remove
from multiprocessing import Process

from six import PY2, StringIO, BytesIO, b, assertRaisesRegex, assertCountEqual

from impacket.smb import SMB_DIALECT
from impacket.smbserver import normalize_path, isInFileJail, SimpleSMBServer
from impacket.smbconnection import SMBConnection, SessionError, compute_lmhash, compute_nthash


class SMBServerUnitTests(unittest.TestCase):
    """Unit tests for the SMBServer
    """

    def test_normalize_path(self):
        """Test file path normalization.
        """
        self.assertEqual(normalize_path("filepath"), "filepath")
        self.assertEqual(normalize_path("filepath\\"), "filepath")
        self.assertEqual(normalize_path("filepath\\\\"), "filepath")
        self.assertEqual(normalize_path("\\filepath\\"), "filepath")
        self.assertEqual(normalize_path("\\\\filepath\\"), "/filepath")
        self.assertEqual(normalize_path(".\\filepath"), "filepath")
        self.assertEqual(normalize_path(".\\.\\filepath"), "filepath")
        self.assertEqual(normalize_path("..\\.\\filepath"), "../filepath")
        self.assertEqual(normalize_path("..\\filepath\\..\\..\\filepath"), "../../filepath")
        self.assertEqual(normalize_path("/filepath"), "filepath")
        self.assertEqual(normalize_path("//filepath"), "/filepath")
        self.assertEqual(normalize_path("./filepath"), "filepath")
        self.assertEqual(normalize_path("././filepath"), "filepath")
        self.assertEqual(normalize_path(".././filepath"), "../filepath")
        self.assertEqual(normalize_path("../filepath/../../filepath"), "../../filepath")

        self.assertEqual(normalize_path("filepath", ''), "filepath")
        self.assertEqual(normalize_path("/filepath", ''), "/filepath")
        self.assertEqual(normalize_path("//filepath", ''), "//filepath")
        self.assertEqual(normalize_path("filepath", 'path'), "filepath")
        self.assertEqual(normalize_path("/filepath", 'path'), "filepath")
        self.assertEqual(normalize_path("//filepath", 'path'), "/filepath")

    def test_isInFileJail(self):
        """Test validation of common prefix path.
        """
        jail_path = "/tmp/jail_path"
        self.assertTrue(isInFileJail(jail_path, "filename"))
        self.assertTrue(isInFileJail(jail_path, "./filename"))
        self.assertTrue(isInFileJail(jail_path, "../jail_path/filename"))

        self.assertFalse(isInFileJail(jail_path, "/filename"))
        self.assertFalse(isInFileJail(jail_path, "/tmp/filename"))
        self.assertFalse(isInFileJail(jail_path, "../filename"))
        self.assertFalse(isInFileJail(jail_path, "../../filename"))

        jail_path = ""
        self.assertTrue(isInFileJail(jail_path, "filename"))
        self.assertTrue(isInFileJail(jail_path, "./filename"))

        self.assertFalse(isInFileJail(jail_path, "../jail_path/filename"))
        self.assertFalse(isInFileJail(jail_path, "/filename"))
        self.assertFalse(isInFileJail(jail_path, "/tmp/filename"))
        self.assertFalse(isInFileJail(jail_path, "../filename"))
        self.assertFalse(isInFileJail(jail_path, "../../filename"))


class SimpleSMBServerFuncTests(unittest.TestCase):
    """Pseudo functional tests for the SimpleSMBServer.

    These are pseudo functional as we're using our own SMBConnection classes. For a complete functional test
    we should (and can) use for example Samba's smbclient or similar.
    """
    server = None
    server_smb2_support = False
    client_preferred_dialect = None

    address = "127.0.0.1"
    port = 1445
    username = "UserName"
    password = "Password"
    domain = "DOMAIN"
    lmhash = compute_lmhash(password)
    nthash = compute_nthash(password)

    unicode_share_file = "test\u202Etest"
    unicode_username = "User\u202EName"

    share_name = "share"
    share_path = "jail_dir"
    share_file = "jail_file"
    share_new_file = "jail_new_file"
    share_unjailed_file = "unjailed_file"
    share_unjailed_new_file = "unjailed_new_file"
    share_new_content = "some content"

    share_directory = "directory"
    share_new_directory = "new_directory"
    share_unjailed_directory = "unjailed_directory"
    share_unjailed_new_directory = "unjailed_new_directory"

    # When listing files in a share, SMB1 response includes "." and ".."
    share_list = [".", "..", share_file, share_directory, unicode_share_file]

    def setUp(self):
        """Creates folders and files required for testing the list, put and get functionality.
        """
        self.server_process = None
        for d in [self.share_path,
                  self.share_unjailed_directory,
                  join(self.share_path, self.share_directory)]:
            if not exists(d):
                mkdir(d)
        for f in [self.share_unjailed_file,
                  join(self.share_path, self.share_file),
                  join(self.share_path, self.unicode_share_file)]:
            if not exists(f):
                with open(f, "a") as fd:
                    fd.write(self.share_new_content)

    def tearDown(self):
        """Removes folders and files used for testing.
        """
        for f in [self.share_unjailed_file,
                  self.share_unjailed_new_file,
                  join(self.share_path, self.share_file),
                  join(self.share_path, self.unicode_share_file),
                  join(self.share_path, self.share_new_file)]:
            if exists(f):
                remove(f)
        for d in [self.share_unjailed_directory,
                  self.share_unjailed_new_directory,
                  join(self.share_path, self.share_directory),
                  join(self.share_path, self.share_new_directory),
                  self.share_path]:
            if exists(d):
                rmdir(d)
        self.stop_smbserver()

    def get_smbserver(self, add_credential=True, add_share=True):
        smbserver = SimpleSMBServer(listenAddress=self.address, listenPort=int(self.port))
        if add_credential:
            smbserver.addCredential(self.username, 0, self.lmhash, self.nthash)
        if add_share:
            smbserver.addShare(self.share_name, self.share_path)
        if self.server_smb2_support is not None:
            smbserver.setSMB2Support(self.server_smb2_support)
        return smbserver

    def get_smbclient(self):
        smbclient = SMBConnection(self.address, self.address, sess_port=int(self.port),
                                  preferredDialect=self.client_preferred_dialect)
        return smbclient

    def start_smbserver(self, server):
        """Starts the SimpleSMBServer process.
        """
        self.server = server
        self.server_process = Process(target=server.start)
        self.server_process.start()

    def stop_smbserver(self):
        """Stops the SimpleSMBServer process and wait for insider threads to join.
        """
        if self.server:
            self.server.stop()
            self.server = None
        if self.server_process:
            self.server_process.terminate()
            sleep(0.1)
            self.server_process = None

    def test_smbserver_login_valid(self):
        """Test authentication using valid password and LM/NTHash.
        """
        server = self.get_smbserver(add_share=False)
        self.start_smbserver(server)

        # Valid password login
        client = self.get_smbclient()
        client.login(self.username, self.password)
        client.close()

        # Valid hash login
        client = self.get_smbclient()
        client.login(self.username, '', lmhash=self.lmhash, nthash=self.nthash)
        client.close()

    def test_smbserver_login_invalid(self):
        """Test authentication using invalid password and LM/NTHash.
        """
        server = self.get_smbserver(add_share=False)
        self.start_smbserver(server)

        # Invalid password login
        client = self.get_smbclient()
        with assertRaisesRegex(self, SessionError, "STATUS_LOGON_FAILURE"):
            client.login(self.username, 'SomeInvalidPassword')
        client.close()

        # Invalid username login
        client = self.get_smbclient()
        with assertRaisesRegex(self, SessionError, "STATUS_LOGON_FAILURE"):
            client.login("InvalidUser", "", lmhash=self.lmhash, nthash=self.nthash)
        client.close()

        # Invalid hash login
        client = self.get_smbclient()
        with assertRaisesRegex(self, SessionError, "STATUS_LOGON_FAILURE"):
            client.login(self.username, "", lmhash=self.nthash, nthash=self.lmhash)
        client.close()

    def test_smbserver_unicode_login(self):
        """Test authentication using a unicode username.
        """
        server = self.get_smbserver(add_credential=False, add_share=False)
        server.addCredential(self.unicode_username, 0, self.lmhash, self.nthash)
        self.start_smbserver(server)

        # Valid Unicode username login
        client = self.get_smbclient()
        client.login(self.unicode_username, self.password)
        client.close()

    def test_smbserver_list_shares(self):
        """Test listing shares.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated list shares
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.listShares()

        # Check authenticated list shares
        client.login(self.username, self.password)
        shares = client.listShares()
        shares_names = [share['shi1_netname'][:-1] for share in shares]
        assertCountEqual(self, [self.share_name.upper(), "IPC$"], shares_names)

        client.close()

    def test_smbserver_connect_disconnect_tree(self):
        """Test connecting/disconnecting to a share tree.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated connect tree
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.connectTree(self.share_name)

        # Check authenticated list shares
        client.login(self.username, self.password)
        tree_id = client.connectTree(self.share_name)

        # Check disconnect tree
        client.disconnectTree(tree_id)

        # Check unexistent share
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_NOT_FOUND"):
            client.connectTree("unexistent")

        client.close()

    @unittest.skipIf(PY2, "Unicode filename expected failing in Python 2.x")
    def test_smbserver_list_path(self):
        """Test listing files in a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated list path
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.listPath(self.share_name, "/")

        # Check authenticated list path
        client.login(self.username, self.password)

        files = client.listPath(self.share_name, self.share_file)
        assertCountEqual(self, [f.get_longname() for f in files],
                         [self.share_file])
        files = client.listPath(self.share_name, self.share_directory)
        assertCountEqual(self, [f.get_longname() for f in files],
                         [self.share_directory])
        files = client.listPath(self.share_name, self.unicode_share_file)
        assertCountEqual(self, [f.get_longname() for f in files],
                         [self.unicode_share_file])

        # Check list with pattern of files
        files = client.listPath(self.share_name, "*")
        assertCountEqual(self, [f.get_longname() for f in files], self.share_list)

        # Check path traversal in list as in #1066
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.listPath(self.share_name, join("..", self.share_unjailed_file))

        # Check unexistent file
        with assertRaisesRegex(self, SessionError, "STATUS_NO_SUCH_FILE"):
            client.listPath(self.share_name, "unexistent")

        client.close()

    def test_smbserver_put(self):
        """Test writing files to a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated put
        local_file = StringIO(self.share_new_content)
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.putFile(self.share_name, self.share_new_file, local_file.read)
        self.assertFalse(exists(join(self.share_path, self.share_new_file)))

        # Check authenticated put
        local_file = StringIO(self.share_new_content)
        client.login(self.username, self.password)
        client.putFile(self.share_name, self.share_new_file, local_file.read)
        self.assertTrue(exists(join(self.share_path, self.share_new_file)))
        with open(join(self.share_path, self.share_new_file), "r") as fd:
            self.assertEqual(fd.read(), self.share_new_content)

        # Check path traversal in put as in #1066
        local_file = StringIO(self.share_new_content)
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.putFile(self.share_name, join("..", self.share_unjailed_new_file), local_file.read)
        self.assertFalse(exists(self.share_unjailed_new_file))

        client.close()

    def test_smbserver_get_file(self):
        """Test reading files from a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated get
        local_file = BytesIO()
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.getFile(self.share_name, self.share_file, local_file.write)

        # Check authenticated get
        local_file = BytesIO()
        client.login(self.username, self.password)
        client.getFile(self.share_name, self.share_file, local_file.write)
        local_file.seek(0)
        self.assertEqual(local_file.read(), b(self.share_new_content))

        # Check path traversal in get as in #1066
        local_file = BytesIO()
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.getFile(self.share_name, join("..", self.share_unjailed_file), local_file.write)
        local_file.seek(0)
        self.assertEqual(local_file.read(), b(""))

        # Check unexistent get file
        with assertRaisesRegex(self, SessionError, "STATUS_NO_SUCH_FILE"):
            client.getFile(self.share_name, "unexistent", local_file.write)

        client.close()

    @unittest.skipIf(PY2, "Unicode filename expected failing in Python 2.x")
    def test_smbserver_get_unicode_file(self):
        """Test reading unicode files from a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()
        local_file = BytesIO()
        client.login(self.username, self.password)
        client.getFile(self.share_name, self.unicode_share_file, local_file.write)
        local_file.seek(0)
        self.assertEqual(local_file.read(), b(self.share_new_content))

        client.close()

    def test_smbserver_delete_file(self):
        """Test deleting files from a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated delete
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.deleteFile(self.share_name, self.share_file)
        self.assertTrue(exists(join(self.share_path, self.share_file)))

        # Check path traversal in delete as in #1066
        client.login(self.username, self.password)
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.deleteFile(self.share_name, join("..", self.share_unjailed_file))
        self.assertTrue(exists(self.share_unjailed_file))

        # Check authenticated delete
        client.deleteFile(self.share_name, self.share_file)
        self.assertFalse(exists(join(self.share_path, self.share_file)))

        # Check unexistent file
        with assertRaisesRegex(self, SessionError, "STATUS_NO_SUCH_FILE"):
            client.deleteFile(self.share_name, "unexistent")

        client.close()

    def test_smbserver_create_directory(self):
        """Test creating a directory on a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated create directory
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.createDirectory(self.share_name, self.share_new_directory)
        self.assertFalse(exists(join(self.share_path, self.share_new_directory)))

        # Check authenticated create directory
        client.login(self.username, self.password)
        client.createDirectory(self.share_name, self.share_new_directory)
        self.assertTrue(exists(join(self.share_path, self.share_new_directory)))

        # Check path traversal in create directory as in #1066
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.createDirectory(self.share_name, join("..", self.share_unjailed_new_directory))
        self.assertFalse(exists(self.share_unjailed_new_directory))

        client.close()

    def test_smbserver_rename_file(self):
        """Test renaming files in a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated rename file
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.rename(self.share_name, self.share_file, self.share_new_file)
        self.assertTrue(exists(join(self.share_path, self.share_file)))
        self.assertFalse(exists(join(self.share_path, self.share_new_file)))

        # Check path traversal in rename file as in #1066
        client.login(self.username, self.password)
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.rename(self.share_name, self.share_file, join("..", self.share_unjailed_new_file))
        self.assertTrue(exists(join(self.share_path, self.share_file)))
        self.assertFalse(exists(self.share_unjailed_new_file))

        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.rename(self.share_name, join("..", self.share_unjailed_file), self.share_new_file)
        self.assertTrue(exists(self.share_unjailed_file))
        self.assertFalse(exists(self.share_new_file))

        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.rename(self.share_name, join("..", self.share_unjailed_file), join("..", self.share_unjailed_new_file))
        self.assertTrue(exists(self.share_unjailed_file))
        self.assertFalse(exists(self.share_unjailed_new_file))

        # Check authenticated rename file
        client.rename(self.share_name, self.share_file, self.share_new_file)
        self.assertFalse(exists(join(self.share_path, self.share_file)))
        self.assertTrue(exists(join(self.share_path, self.share_new_file)))
        with open(join(self.share_path, self.share_new_file), "r") as fd:
            self.assertEqual(fd.read(), self.share_new_content)

        # Check unexistent rename file
        with assertRaisesRegex(self, SessionError, "STATUS_NO_SUCH_FILE"):
            client.rename(self.share_name, "unexistent", self.share_new_file)

        client.close()

    def test_smbserver_open_close_file(self):
        """Test opening and closing files in a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check authenticated open file
        client.login(self.username, self.password)
        tree_id = client.connectTree(self.share_name)
        file_id = client.openFile(tree_id, self.share_file)

        # Check path traversal in open file as in #1066
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.openFile(tree_id, join("..", self.share_unjailed_file))

        # Check authenticated open unexistent file
        with assertRaisesRegex(self, SessionError, "STATUS_NO_SUCH_FILE"):
            client.openFile(tree_id, "unexistent")

        # Check close invalid tree or file ids
        with self.assertRaises(SessionError):
            client.closeFile(tree_id, 123)
        with self.assertRaises(SessionError):
            client.closeFile(123, file_id)
        with self.assertRaises(SessionError):
            client.closeFile("123", file_id)

        # Check close valid file
        client.closeFile(tree_id, file_id)

        # Now close the tree and client
        client.disconnectTree(tree_id)
        client.close()

    def test_smbserver_query_info_file(self):
        """Test query info on a file in a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()
        client.login(self.username, self.password)

        # Check query info on file
        tree_id = client.connectTree(self.share_name)
        file_id = client.openFile(tree_id, self.share_file)
        file_info = client.queryInfo(tree_id, file_id)
        self.assertEqual(file_info["AllocationSize"], len(self.share_new_content))
        self.assertEqual(file_info["EndOfFile"], len(self.share_new_content))
        self.assertEqual(file_info["Directory"], 0)

        # Now close everything
        client.closeFile(tree_id, file_id)
        client.disconnectTree(tree_id)
        client.close()

    @unittest.skip("Query directory not implemented on client")
    def test_smbserver_query_info_directory(self):
        """Test query info on a directory in a shared folder.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()
        client.login(self.username, self.password)

        # Check query info on directory
        tree_id = client.connectTree(self.share_name)
        directory_id = client.openFile(tree_id, self.share_directory)
        directory_info = client.queryInfo(tree_id, directory_id)
        self.assertEqual(directory_info["AllocationSize"], len(self.share_new_content))
        self.assertEqual(directory_info["EndOfFile"], len(self.share_new_content))
        self.assertEqual(directory_info["Directory"], 1)

        # Now close everything
        client.closeFile(tree_id, directory_id)
        client.disconnectTree(tree_id)
        client.close()


class SimpleSMBServer2FuncTestsClientFallBack(SimpleSMBServerFuncTests):

    server_smb2_support = True
    client_preferred_dialect = SMB_DIALECT


class SimpleSMBServer2FuncTests(SimpleSMBServerFuncTests):

    server_smb2_support = True

    # When listing files in a share, SMB2 response doesn't include "." and ".."
    share_list = [SimpleSMBServerFuncTests.share_file,
                  SimpleSMBServerFuncTests.share_directory,
                  SimpleSMBServerFuncTests.unicode_share_file]

    def test_smbserver_delete_directory(self):
        """Test deleting directories from a shared folder.

        This is only tested in SMB2 as SMB_COM_CHECK_DIRECTORY is not
        implemented yet in SMB, the SMB2 client uses a query info instead.
        """
        server = self.get_smbserver()
        self.start_smbserver(server)

        client = self.get_smbclient()

        # Check unauthenticated delete directory
        with assertRaisesRegex(self, SessionError, "STATUS_ACCESS_DENIED"):
            client.deleteDirectory(self.share_name, self.share_directory)
        self.assertTrue(exists(join(self.share_path, self.share_directory)))

        # Check path traversal in delete directory as in #1066
        client.login(self.username, self.password)
        with assertRaisesRegex(self, SessionError, "STATUS_OBJECT_PATH_SYNTAX_BAD"):
            client.deleteDirectory(self.share_name, join("..", self.share_unjailed_directory))

        # Check authenticated delete directory
        client.deleteDirectory(self.share_name, self.share_directory)
        self.assertFalse(exists(join(self.share_path, self.share_directory)))

        # Check unexistent directory directory
        with assertRaisesRegex(self, SessionError, "STATUS_NO_SUCH_FILE"):
            client.deleteDirectory(self.share_name, "unexistent")

        client.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
