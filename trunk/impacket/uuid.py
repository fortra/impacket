# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#   Generate UUIDs complying with http://www.webdav.org/specs/draft-leach-uuids-guids-01.txt.
#   A different, much simpler (not necessarily better) algorithm is used.
#
# Author:
#   Javier Kohen (jkohen)

import re

from random import randrange
from struct import pack, unpack

def generate():
    # UHm... crappy Python has an maximum integer of 2**31-1.
    top = (1L<<31)-1
    return pack("IIII", randrange(top), randrange(top), randrange(top), randrange(top))

def bin_to_string(uuid):
    uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
    uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
    return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)

def string_to_bin(uuid):
    matches = re.match('([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})', uuid)
    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = map(lambda x: long(x, 16), matches.groups())
    uuid = pack('<LHH', uuid1, uuid2, uuid3)
    uuid += pack('>HHL', uuid4, uuid5, uuid6)
    return uuid
