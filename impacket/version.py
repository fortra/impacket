# SECUREAUTH LABS. Copyright 2019 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import pkg_resources
from impacket import LOG, __path__


BANNER = "Impacket v{} - Copyright 2020 SecureAuth Corporation\n".format(pkg_resources.get_distribution('impacket').version)

def getInstallationPath():
    LOG.debug('Impacket Library Installation Path: {}'.format(__path__))
