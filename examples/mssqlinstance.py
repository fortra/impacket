#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MC-SQLR] example. Retrieves the instances names from the target host
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure
#

from __future__ import division
from __future__ import print_function
import argparse
import sys
import logging

from impacket.examples import logger
from impacket import version, tds

if __name__ == '__main__':

    print(version.BANNER)
    # Init the example's logger theme
    logger.init()

    parser = argparse.ArgumentParser(add_help = True, description = "Asks the remote host for its running MSSQL Instances.")

    parser.add_argument('host', action='store', help='target host')
    parser.add_argument('-timeout', action='store', default='5', help='timeout to wait for an answer')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    ms_sql = tds.MSSQL(options.host)
    instances = ms_sql.getInstances(int(options.timeout))
    if len(instances) == 0:
        "No MSSQL Instances found"
    else:
        for i, instance in enumerate(instances):
            logging.info("Instance %d" % i)
            for key in list(instance.keys()):
               print(key + ":" + instance[key])
