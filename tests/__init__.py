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


# Module-scope variable to hold remote configuration in case it was set by pytest
remote_config_file_path = None


remote_config_section = "TCPTransport"


remote_config_params = [
    ("servername", "Server NetBIOS Name"),
    ("machine", "Target hostname or IP address"),
    ("username", "User's username"),
    ("password", "User's password"),
    ("hashes", "User's NTLM hashes, you can grab them with secretsdump.py or will be calculated from the password"),
    ("aesKey256", "User's Kerberos AES 256 Key, you can grab it with secretsdump.py"),
    ("aesKey128", "User's Kerberos AES 128 Key, you can grab it with secretsdump.py"),
    ("domain", "Domain FQDN"),
    ("machineuser", "Domain-joined machine NetBIOS Name"),
    ("machineuserhashes", "Domain-joined machine NTLM hashes, you can grab them with secretsdump.py"),
]
remote_config_params_names = [name for name, _ in remote_config_params]


def set_remote_config_file_path(config_file):
    """Sets the configuration file path for further considering it"""
    global remote_config_file_path
    remote_config_file_path = config_file or None


def get_remote_config_file_path():
    """Obtains the configuration file path according to the different options available
    to specify it.
    """
    if remote_config_file_path:
        return remote_config_file_path
    remote_config_file = getenv("REMOTE_CONFIG")
    if not remote_config_file:
        remote_config_file = join("tests", "dcetests.cfg")
    return remote_config_file


def get_remote_config():
    """Retrieves the remote tests configuration.
    """
    remote_config_file = ConfigParser()
    remote_config_file.read(get_remote_config_file_path())
    return remote_config_file


def set_transport_config(obj, machine_account=False, aes_keys=False):
    """Set configuration parameters in the unit test.
    """
    remote_config = get_remote_config()
    obj.username = remote_config.get(remote_config_section, "username")
    obj.domain = remote_config.get(remote_config_section, "domain")
    obj.serverName = remote_config.get(remote_config_section, "servername")
    obj.password = remote_config.get(remote_config_section, "password")
    obj.machine = remote_config.get(remote_config_section, "machine")
    obj.hashes = remote_config.get(remote_config_section, "hashes")
    if len(obj.hashes):
        obj.lmhash, obj.nthash = obj.hashes.split(':')
        obj.blmhash = unhexlify(obj.lmhash)
        obj.bnthash = unhexlify(obj.nthash)
    else:
        obj.lmhash = obj.blmhash = ''
        obj.nthash = obj.bnthash = ''

    if machine_account:
        obj.machine_user = remote_config.get(remote_config_section, "machineuser")
        obj.machine_user_hashes = remote_config.get(remote_config_section, "machineuserhashes")
        if len(obj.machine_user_hashes):
            obj.machine_user_lmhash, obj.machine_user_nthash = obj.machine_user_hashes.split(':')
            obj.machine_user_blmhash = unhexlify(obj.machine_user_lmhash)
            obj.machine_user_bnthash = unhexlify(obj.machine_user_nthash)
        else:
            obj.machine_user_lmhash = obj.machine_user_blmhash = ''
            obj.machine_user_nthash = obj.machine_user_bnthash = ''

    if aes_keys:
        obj.aes_key_128 = remote_config.get(remote_config_section, 'aesKey128')
        obj.aes_key_256 = remote_config.get(remote_config_section, 'aesKey256')


class RemoteTestCase(object):
    """Remote Test Case Base Class

    Holds configuration parameters for all remote base classes. Configuration is by
    default loaded from `tests/dctests.cfg`, but a different path can be specified with
    the REMOTE_CONFIG environment variable. When tests are loaded by pytest, a remote
    configuration file can also be specified using the `--remote-config` command line
    option or the `remote-config` ini option.

    Configuration parameters can be found in the `tests/dcetests.cfg.template` file.
    """

    def set_transport_config(self, machine_account=False, aes_keys=False):
        """Set configuration parameters in the unit test.
        """
        set_transport_config(self, machine_account=machine_account, aes_keys=aes_keys)
