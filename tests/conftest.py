#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tests configuration
#
import pytest
from . import set_remote_config_file_path, set_transport_config


def pytest_configure(config):
    """Hook that sets remote configuration file path as specified in pytest command line
    or ini option, and apply the configuration options to the pytest `config` object.
    """
    config_file = config.getoption("--remote-config")
    if not config_file:
        config_file = config.getini("remote-config")
    if config_file:
        set_remote_config_file_path(config_file)
        set_transport_config(config)


def pytest_addoption(parser):
    """Hook that adds pytest options for configuring the remote configuration
    file.
    """
    parser.addoption("--remote-config", dest="remote_config", metavar="FILE",
                     help="Configuration file for remote tests")
    parser.addini("remote-config", help="Configuration file for remote tests", type="pathlist")


@pytest.fixture(scope="class", name="remote")
def remote_config(request):
    """Remote Test Case configuration fixture

    Sets the configuration attributes in the test class for easier access.
    """
    set_transport_config(request.cls)
