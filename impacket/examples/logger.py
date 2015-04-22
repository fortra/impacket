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
import sys

class ImpacketFormatter(logging.Formatter):
  '''
  Prefixing logged messages through the custom attribute 'bullet'.
  '''
  def __init__(self):
      logging.Formatter.__init__(self,'%(bullet)s:%(name)s:%(message)s', None)

  def format(self, record):
    if record.levelno in (logging.INFO, logging.DEBUG):
      record.bullet = '[*]'
    else:
      record.bullet = '[!]'

    return logging.Formatter.format(self, record)    

SLOG = logging.getLogger()

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ImpacketFormatter())

SLOG.addHandler(handler)
SLOG.setLevel(logging.INFO)
