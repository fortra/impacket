#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Base tests cases module
#
from os import getenv
from os.path import join
from binascii import unhexlify
from six.moves.configparser import ConfigParser


class RemoteTestCase(object):
    """Remote Test Case Base Class

    Holds configuration parameters for all remote base classes. Configuration is by
    default loaded from `tests/dctests.cfg`, but a different path can be specified with
    the REMOTE_CONFIG environment variable.

    Configuration parameters can be found in the `tests/dcetests.cfg.template` file.
    """

    def set_config_file(self):
        """Reads the configuration file
        """
        config_file_path = getenv("REMOTE_CONFIG", join("tests", "dcetests.cfg"))
        self._config_file = ConfigParser()
        self._config_file.read(config_file_path)

    def set_transport_config(self, transport, machine_account=False, aes_keys=False):
        """Set configuration for the specified transport.
        """
        self.username = self._config_file.get(transport, "username")
        self.domain = self._config_file.get(transport, "domain")
        self.serverName = self._config_file.get(transport, "servername")
        self.password = self._config_file.get(transport, "password")
        self.machine = self._config_file.get(transport, "machine")
        self.hashes = self._config_file.get(transport, "hashes")
        if len(self.hashes):
            self.lmhash, self.nthash = self.hashes.split(':')
            self.blmhash = unhexlify(self.lmhash)
            self.bnthash = unhexlify(self.nthash)
        else:
            self.lmhash = self.blmhash = ''
            self.nthash = self.bnthash = ''

        if machine_account:
            self.machine_user = self._config_file.get(transport, "machineuser")
            self.machine_user_hashes = self._config_file.get(transport, "machineuserhashes")
            if len(self.machine_user_hashes):
                self.machine_user_lmhash, self.machine_user_nthash = self.machine_user_hashes.split(':')
                self.machine_user_blmhash = unhexlify(self.machine_user_lmhash)
                self.machine_user_bnthash = unhexlify(self.machine_user_nthash)
            else:
                self.machine_user_lmhash = self.machine_user_blmhash = ''
                self.machine_user_nthash = self.machine_user_bnthash = ''

        if aes_keys:
            self.aes_key_128 = self._config_file.get(transport, 'aesKey128')
            self.aes_key_256 = self._config_file.get(transport, 'aesKey256')

    def set_smb_transport_config(self, machine_account=False, aes_keys=False):
        """Read SMB Transport parameters from the configuration file.

        :param machine_account: whether to read the machine account config or not
        :type machine_account: bool

        :param aes_keys: whether to read the AES keys config or not
        :type aes_keys: bool
        """
        self.set_config_file()
        self.set_transport_config("SMBTransport", machine_account, aes_keys)

    def set_tcp_transport_config(self, machine_account=False, aes_keys=False):
        """Read TCP Transport parameters from the configuration file.

        :param machine_account: whether to read the machine account config or not
        :type machine_account: bool

        :param aes_keys: whether to read the AES keys config or not
        :type aes_keys: bool
        """
        self.set_config_file()
        self.set_transport_config("TCPTransport", machine_account, aes_keys)
