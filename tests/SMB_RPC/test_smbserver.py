#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Basic unit tests for the SMB Server.
#
# Author:
#  Martin Gallo (@martingalloar)
#

import unittest
from time import sleep
from os.path import exists, join
from os import mkdir, rmdir, remove
from multiprocessing import Process

from six import StringIO, BytesIO, b

from impacket.smbserver import isInFileJail, SimpleSMBServer
from impacket.smbconnection import SMBConnection, SessionError, compute_lmhash, compute_nthash


class SMBServerUnitTests(unittest.TestCase):
    """Unit tests for the SMBServer
    """

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


class SimpleSMBServerFuncTests(unittest.TestCase):
    """Pseudo functional tests for the SimpleSMBServer.

    These are pseudo functional as we're using our own SMBConnection classes. For a complete functional test
    we should (and can) use for example Samba's smbclient or similar.
    """

    address = "127.0.0.1"
    port = 1445
    username = "UserName"
    password = "Password"
    domain = "DOMAIN"
    lmhash = compute_lmhash(password)
    nthash = compute_nthash(password)

    share_name = "share"
    share_path = "jail_dir"
    share_file = "jail_file"
    share_new_file = "jail_new_file"
    share_unjailed_file = "unjailed_new_file"
    share_new_content = "some content"

    def setUp(self):
        """Creates folders and files required for testing the list, put and get functionality.
        """
        if not exists(self.share_path):
            mkdir(self.share_path)
        for f in [self.share_file, self.share_new_file]:
            if not exists(join(self.share_path, f)):
                with open(join(self.share_path, f), "a") as fd:
                    fd.write(self.share_new_content)

    def tearDown(self):
        """Removes folders and files used for testing.
        """
        for f in [self.share_file, self.share_new_file]:
            if exists(join(self.share_path, f)):
                remove(join(self.share_path, f))
        if exists(self.share_unjailed_file):
            remove(self.share_unjailed_file)
        if exists(self.share_path):
            rmdir(self.share_path)
        self.stop_smbserver()

    def get_smbserver(self):
        return SimpleSMBServer(listenAddress=self.address, listenPort=int(self.port))

    def start_smbserver(self, server):
        """Starts the SimpleSMBServer process.
        """
        self.server_process = Process(target=server.start)
        self.server_process.start()

    def stop_smbserver(self):
        """Stops the SimpleSMBServer process and wait for insider threads to join.
        """
        self.server_process.terminate()
        sleep(0.5)

    def test_smbserver_login(self):
        """Test authentication using password and LM/NTHash login.
        """
        server = self.get_smbserver()
        server.addCredential(self.username, 0, self.lmhash, self.nthash)
        self.start_smbserver(server)

        # Valid password login
        client = SMBConnection(self.address, self.address, sess_port=int(self.port))
        client.login(self.username, self.password)
        client.close()

        # Valid hash login
        client = SMBConnection(self.address, self.address, sess_port=int(self.port))
        client.login(self.username, '', lmhash=self.lmhash, nthash=self.nthash)
        client.close()

        # Invalid password login
        with self.assertRaises(SessionError):
            client = SMBConnection(self.address, self.address, sess_port=int(self.port))
            client.login(self.username, 'SomeInvalidPassword')
            client.close()

        # Invalid username login
        with self.assertRaises(SessionError):
            client = SMBConnection(self.address, self.address, sess_port=int(self.port))
            client.login("InvalidUser", "", lmhash=self.lmhash, nthash=self.nthash)
            client.close()

        # Invalid hash login
        with self.assertRaises(SessionError):
            client = SMBConnection(self.address, self.address, sess_port=int(self.port))
            client.login(self.username, "", lmhash=self.nthash, nthash=self.lmhash)
            client.close()

    def test_smbserver_share_list(self):
        """Test listing files in a shared folder.
        """
        server = SimpleSMBServer(listenAddress=self.address, listenPort=int(self.port))
        server.addCredential(self.username, 0, self.lmhash, self.nthash)
        server.addShare(self.share_name, self.share_path)
        self.start_smbserver(server)

        client = SMBConnection(self.address, self.address, sess_port=int(self.port))
        client.login(self.username, self.password)
        client.listPath(self.share_name, "/")

        # Check path traversal in list as in #1066
        with self.assertRaises(SessionError):
            client.listPath(self.share_name, "../impacket/")

        client.close()

    def test_smbserver_share_put(self):
        """Test writing files to a shared folder.
        """
        server = SimpleSMBServer(listenAddress=self.address, listenPort=int(self.port))
        server.addCredential(self.username, 0, self.lmhash, self.nthash)
        server.addShare(self.share_name, self.share_path)
        self.start_smbserver(server)

        client = SMBConnection(self.address, self.address, sess_port=int(self.port))
        client.login(self.username, self.password)

        local_file = StringIO(self.share_new_content)

        client.putFile(self.share_name, self.share_new_file, local_file.read)
        self.assertTrue(exists(join(self.share_path, self.share_new_file)))
        with open(join(self.share_path, self.share_new_file), "r") as fd:
            self.assertEqual(fd.read(), self.share_new_content)

        # Check path traversal in put as in #1066
        with self.assertRaises(SessionError):
            client.putFile(self.share_name, join("..", self.share_unjailed_file), local_file.read)
        self.assertFalse(exists(self.share_unjailed_file))

        client.close()

    def test_smbserver_share_get(self):
        """Test reading files from a shared folder.
        """
        server = SimpleSMBServer(listenAddress=self.address, listenPort=int(self.port))
        server.addCredential(self.username, 0, self.lmhash, self.nthash)
        server.addShare(self.share_name, self.share_path)
        self.start_smbserver(server)

        client = SMBConnection(self.address, self.address, sess_port=int(self.port))
        client.login(self.username, self.password)

        local_file = BytesIO()
        client.getFile(self.share_name, self.share_file, local_file.write)
        local_file.seek(0)
        self.assertEqual(local_file.read(), b(self.share_new_content))

        # Check unexistent file
        with self.assertRaises(SessionError):
            client.getFile(self.share_name, "unexistent", local_file.write)

        client.close()


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(SMBServerUnitTests))
    suite.addTests(loader.loadTestsFromTestCase(SimpleSMBServerFuncTests))
    unittest.main(defaultTest='suite')
