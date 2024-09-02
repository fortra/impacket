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

import pkg_resources
from impacket import __path__


try:
    version = pkg_resources.get_distribution('impacket').version
except pkg_resources.DistributionNotFound:
    version = "?"
    print("Cannot determine Impacket version. "
          "If running from source you should at least run \"python setup.py egg_info\"")
BANNER = "Impacket v{} - Copyright Fortra, LLC and its affiliated companies \n".format(version)
WARNING_BANNER = "".join(("===============================================================================\n",
                          "  Warning: This functionality will be deprecated in the next Impacket version  \n", 
                          "===============================================================================\n"))

def getInstallationPath():
    return 'Impacket Library Installation Path: {}'.format(__path__[0])
