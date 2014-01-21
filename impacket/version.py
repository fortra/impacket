# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#

import logging
import sys

VER_MAJOR = "0"
VER_MINOR = "9.11"

BANNER = "Impacket v%s.%s - Copyright 2002-2014 Core Security Technologies\n" % (VER_MAJOR,VER_MINOR)

# Here we also change the levelnames
logging.addLevelName(logging.ERROR,'[!]')
logging.addLevelName(logging.WARNING,'[!]')
logging.addLevelName(logging.CRITICAL,'[!]')
logging.addLevelName(logging.INFO,'[*]')
logging.addLevelName(logging.DEBUG,'[+]')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ch = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(levelname)s %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

