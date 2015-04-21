#!/usr/bin/python
# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: This logger is intended to be used by impacket instead
# of printing directly. This will allow other libraries to use their
# custom logging implementation.
#

import logging

class ImpacketFormatter(logging.Formatter):
  '''
  Prefixing logged messages through the custom attribute 'bullet'.
  '''
  def format(self, record):
    if record.levelno in (logging.INFO, logging.DEBUG):
      record.bullet = '[*]'
    else:
      record.bullet = '[!]'

    return logging.Formatter.format(self, record)

class NullHandler(logging.Handler):
  '''
  Backporting logging.NullHandler, only available since python 2.7.
  https://docs.python.org/release/2.6/library/logging.html#configuring-logging-for-a-library
  '''
  def emit(self, record):
    pass

logger = logging.getLogger('impacket')
logger.addHandler(NullHandler())

