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

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as get_version

from impacket import __path__, __version__


def _load_distribution_version():
    for distribution_name in ('impacket', 'impacket-core', 'impacket-examples'):
        try:
            return get_version(distribution_name)
        except PackageNotFoundError:
            continue

    return __version__


version = _load_distribution_version()
BANNER = "Impacket v{} - Copyright Fortra, LLC and its affiliated companies \n".format(version)
DEPRECATION_WARNING_BANNER = "".join(("===============================================================================\n",
                          "  Warning: This functionality will be deprecated in the next Impacket version  \n", 
                          "===============================================================================\n"))

def getInstallationPath():
    return 'Impacket Library Installation Path: {}'.format(__path__[0])
