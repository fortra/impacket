#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Simple MQTT example aimed at playing with different login options. Can be converted into a account/password
#   brute forcer quite easily.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   MQTT and Structure
#

from __future__ import print_function

import argparse
import logging
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.mqtt import CONNECT_ACK_ERROR_MSGS, MQTTConnection

class MQTT_LOGIN:
    def __init__(self, username, password, target, options):
        self._options = options
        self._username = username
        self._password = password
        self._target = target

        if self._username == '':
            self._username = None

    def run(self):
        mqtt = MQTTConnection(self._target, int(self._options.port), self._options.ssl)

        if self._options.client_id is None:
            clientId = ' '
        else:
            clientId = self._options.client_id

        mqtt.connect(clientId, self._username, self._password)

        logging.info(CONNECT_ACK_ERROR_MSGS[0])

if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help=False,
                                     description="MQTT login check")
    parser.add_argument("--help", action="help", help='show this help message and exit')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName>')
    parser.add_argument('-client-id', action='store', help='Client ID used when authenticating (default random)')
    parser.add_argument('-ssl', action='store_true', help='turn SSL on')
    parser.add_argument('-port', action='store', default='1883', help='port to connect to (default 1883)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    try:
        options = parser.parse_args()
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    check_mqtt = MQTT_LOGIN(username, password, address, options)
    try:
        check_mqtt.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
