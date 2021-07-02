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
from six.moves.configparser import ConfigParser


class RemoteTestCase(object):
    def set_config_file(self):
        config_file_path = getenv("REMOTE_CONFIG", join("tests", "dcetests.cfg"))
        self.config_file = ConfigParser()
        self.config_file.read(config_file_path)

    def set_transport_config(self, transport):
        self.username = self.config_file.get(transport, "username")
        self.domain = self.config_file.get(transport, "domain")
        self.serverName = self.config_file.get(transport, "servername")
        self.password = self.config_file.get(transport, "password")
        self.machine = self.config_file.get(transport, "machine")
        self.hashes = self.config_file.get(transport, "hashes")

    def set_smb_transport_config(self):
        self.set_config_file()
        self.set_transport_config("SMBTransport")

    def set_tcp_transport_config(self):
        self.set_config_file()
        self.set_transport_config("TCPTransport")
