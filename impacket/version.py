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

from importlib.metadata import version as get_version, PackageNotFoundError
from impacket import __path__


try:
    version = get_version('impacket')
except PackageNotFoundError:
    version = "?"
    print("Cannot determine Impacket version. "
          "If running from source you should at least run \"python setup.py egg_info\"")
BANNER = "Impacket v{} - Copyright Fortra, LLC and its affiliated companies \n".format(version)
DEPRECATION_WARNING_BANNER = "".join(("===============================================================================\n",
                          "  Warning: This functionality will be deprecated in the next Impacket version  \n", 
                          "===============================================================================\n"))

def getInstallationPath():
    return 'Impacket Library Installation Path: {}'.format(__path__[0])
