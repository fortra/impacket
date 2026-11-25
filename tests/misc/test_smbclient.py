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
            return [FakeSharedFile('nested', True)]
        if path == '\\inside\\nested\\*':
            return [FakeSharedFile('nested.txt', False)]
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

                shell.do_rget('*')
            finally:
                os.chdir(old_cwd)

            local_file = os.path.join(temp_dir, 'nested', 'nested.txt')
            self.assertEqual(connection.downloads, ['\\inside\\nested\\nested.txt'])
            with open(local_file, 'rb') as file_handle:
                self.assertEqual(file_handle.read(), b'server-controlled bytes')


if __name__ == '__main__':
    unittest.main(verbosity=1)
