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
# Description:
#   This logger is intended to be used by impacket instead
#   of printing directly. This will allow other libraries to use their
#   custom logging implementation.
#

import logging
import sys
from impacket import version

class ImpacketFormatter(logging.Formatter):
    '''
    Prefixing logged messages through the custom attribute 'bullet'.
    '''
    def __init__(self):
        super().__init__('%(bullet)s %(message)s', None)

    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = '[*]'
        elif record.levelno == logging.DEBUG:
            record.bullet = '[+]'
        elif record.levelno == logging.WARNING:
            record.bullet = '[!]'
        else:
            record.bullet = '[-]'
        return super().format(record)

class ImpacketFormatterTimeStamp(ImpacketFormatter):
    '''
    Adds timestamp to the bullet format.
    '''
    def __init__(self):
        super().__init__()
        self._style._fmt = '[%(asctime)-15s] %(bullet)s %(message)s'

    def formatTime(self, record, datefmt=None):
        return super().formatTime(record, datefmt="%Y-%m-%d %H:%M:%S")

def init(ts=False, debug=False):
    logger = logging.getLogger()

    # Avoid adding multiple handlers if init is called again
    if logger.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)

    if ts:
        handler.setFormatter(ImpacketFormatterTimeStamp())
    else:
        handler.setFormatter(ImpacketFormatter())

    logger.addHandler(handler)

    if debug:
        logger.setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logger.setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)
