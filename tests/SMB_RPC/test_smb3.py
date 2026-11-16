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
#
import ntpath
import unittest
from unittest.mock import Mock

from impacket.smb3 import SMB3
from impacket.smb3structs import SMB2_DIALECT_30, SMB3Packet


class _SendReached(Exception):
    pass


class SMB3CreateTests(unittest.TestCase):

    @staticmethod
    def create_client(global_file_table=None, share_name='share'):
        client = object.__new__(SMB3)
        client._Session = {
            'TreeConnectTable': {1: {'IsDfsShare': False, 'ShareName': share_name}},
            'OpenTable': {},
        }
        client._Connection = {
            'Dialect': SMB2_DIALECT_30,
            'SupportsDirectoryLeasing': True,
            'ServerName': 'server',
        }
        client.GlobalFileTable = {} if global_file_table is None else global_file_table
        client.SMB_PACKET = SMB3Packet
        client.sendSMB = Mock(side_effect=_SendReached)
        return client

    def assert_create_reaches_send(self, client, file_name):
        with self.assertRaises(_SendReached):
            client.create(1, file_name, 0, 0, 0, 0, 0)

    def test_directory_leasing_parent_tracking(self):
        cases = (
            ('', False),
            (r'\lsarpc', True),
            (r'folder\file.txt', True),
            (r'folder\child\file.txt', True),
        )

        for file_name, has_parent in cases:
            with self.subTest(file_name=file_name):
                client = self.create_client()
                self.assert_create_reaches_send(client, file_name)

                path_name = r'\\server\share'
                if file_name:
                    normalized_name = ntpath.normpath(file_name).lstrip('\\')
                    path_name += '\\' + normalized_name
                self.assertIn(path_name, client.GlobalFileTable)

                if has_parent:
                    parent_dir = ntpath.dirname(path_name).rstrip('\\')
                    self.assertIn(parent_dir, client.GlobalFileTable)
                    self.assertEqual(len(client.GlobalFileTable), 2)
                else:
                    self.assertEqual(list(client.GlobalFileTable), [path_name])

    def test_existing_parent_entry_is_reused(self):
        file_name = r'folder\file.txt'
        path_name = '\\\\server\\share\\' + file_name
        parent_dir = ntpath.dirname(path_name)
        parent_entry = object()
        client = self.create_client({parent_dir: parent_entry})

        self.assert_create_reaches_send(client, file_name)

        self.assertIs(client.GlobalFileTable[parent_dir], parent_entry)

    def test_root_entry_is_reused_for_root_level_file(self):
        client = self.create_client(share_name='IPC$')

        self.assert_create_reaches_send(client, '')
        self.assert_create_reaches_send(client, r'\lsarpc')

        self.assertEqual(
            set(client.GlobalFileTable),
            {r'\\server\IPC$', r'\\server\IPC$\lsarpc'},
        )


if __name__ == '__main__':
    unittest.main(verbosity=1)
