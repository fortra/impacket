#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import os
import tempfile
import unittest
from unittest.mock import patch

from impacket.examples.smbclient import MiniImpacketShell


class FakeSharedFile:
    def __init__(self, longname, is_directory):
        self._longname = longname
        self._is_directory = is_directory

    def get_longname(self):
        return self._longname

    def is_directory(self):
        return self._is_directory

    def is_reparse_point(self):
        return False


class FakeSMBConnection:
    def __init__(self):
        self.downloads = []

    def getCredentials(self):
        return '', '', '', '', '', '', None, None

    def getSMBServer(self):
        return None

    def listPath(self, share, path):
        if path == '\\inside\\*':
            return [FakeSharedFile('..\\..\\outside', True)]
        if path == '\\outside\\*':
            return [FakeSharedFile('controlled.txt', False)]
        raise AssertionError('Unexpected directory listing: %r' % path)

    def getFileEx(self, share, path, callback):
        self.downloads.append(path)
        callback(b'server-controlled bytes')


class NestedFilesSMBConnection(FakeSMBConnection):
    def listPath(self, share, path):
        if path == '\\inside\\*':
            return [
                FakeSharedFile('.', True),
                FakeSharedFile('..', True),
                FakeSharedFile('nested', True),
            ]
        if path == '\\inside\\nested\\*':
            return [
                FakeSharedFile('.', True),
                FakeSharedFile('..', True),
                FakeSharedFile('nested.txt', False),
            ]
        raise AssertionError('Unexpected directory listing: %r' % path)


class MiniImpacketShellRgetTests(unittest.TestCase):
    def test_rget_rejects_traversal_in_server_directory_name(self):
        """A server listing must not make rget write outside the local download root."""
        connection = FakeSMBConnection()

        with tempfile.TemporaryDirectory() as temp_dir:
            download_root = os.path.join(temp_dir, 'download-root')
            os.mkdir(download_root)
            old_cwd = os.getcwd()
            try:
                os.chdir(download_root)
                shell = MiniImpacketShell(connection)
                shell.tid = 1
                shell.share = 'share'
                shell.pwd = '\\inside'

                shell.do_rget('*')
            finally:
                os.chdir(old_cwd)

            self.assertEqual(connection.downloads, [])
            self.assertFalse(os.path.exists(os.path.join(temp_dir, 'outside', 'controlled.txt')))
            self.assertEqual(shell.pwd, '\\inside')

    def test_rget_downloads_files_in_nested_directories(self):
        connection = NestedFilesSMBConnection()

        with tempfile.TemporaryDirectory() as temp_dir:
            old_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                shell = MiniImpacketShell(connection)
                shell.tid = 1
                shell.share = 'share'
                shell.pwd = '\\inside'

                with patch('impacket.examples.smbclient.LOG.error') as log_error:
                    shell.do_rget('*')
            finally:
                os.chdir(old_cwd)

            log_error.assert_not_called()
            local_file = os.path.join(temp_dir, 'nested', 'nested.txt')
            self.assertEqual(connection.downloads, ['\\inside\\nested\\nested.txt'])
            with open(local_file, 'rb') as file_handle:
                self.assertEqual(file_handle.read(), b'server-controlled bytes')

    def test_rget_rejects_local_directory_symlink_escape(self):
        connection = NestedFilesSMBConnection()

        with tempfile.TemporaryDirectory() as temp_dir:
            download_root = os.path.join(temp_dir, 'download-root')
            outside_dir = os.path.join(temp_dir, 'outside')
            os.mkdir(download_root)
            os.mkdir(outside_dir)

            safe_target = os.path.join(download_root, 'safe-target.txt')
            with open(safe_target, 'wb') as file_handle:
                file_handle.write(b'original bytes')

            try:
                os.symlink(outside_dir, os.path.join(download_root, 'nested'), target_is_directory=True)
                os.symlink(safe_target, os.path.join(outside_dir, 'nested.txt'))
            except OSError as error:
                self.skipTest('Creating symlinks is not available: %s' % error)

            old_cwd = os.getcwd()
            try:
                os.chdir(download_root)
                shell = MiniImpacketShell(connection)
                shell.tid = 1
                shell.share = 'share'
                shell.pwd = '\\inside'

                shell.do_rget('*')
            finally:
                os.chdir(old_cwd)

            self.assertEqual(connection.downloads, [])
            self.assertTrue(os.path.islink(os.path.join(outside_dir, 'nested.txt')))
            with open(safe_target, 'rb') as file_handle:
                self.assertEqual(file_handle.read(), b'original bytes')


if __name__ == '__main__':
    unittest.main(verbosity=1)
