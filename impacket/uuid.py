# ---
# $Id$
#
# Description:
#   Generate UUID compliant with http://www.webdav.org/specs/draft-leach-uuids-guids-01.txt.
#   A different, much simpler (not necessarily better) algorithm is used.
#
# Author:
#   Javier Kohen (jkohen)
#
# Copyright (c) 2003 CORE Security Technologies, CORE SDI Inc.
# All rights reserved.
#
# This computer software is owned by Core SDI Inc. and is
# protected by U.S. copyright laws and other laws and by international
# treaties.  This computer software is furnished by CORE SDI Inc.
# pursuant to a written license agreement and may be used, copied,
# transmitted, and stored only in accordance with the terms of such
# license and with the inclusion of the above copyright notice.  This
# computer software or any other copies thereof may not be provided or
# otherwise made available to any other person.
#
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL CORE SDI Inc. BE LIABLE
# FOR ANY DIRECT,  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
# CONSEQUENTIAL  DAMAGES RESULTING FROM THE USE OR MISUSE OF
# THIS SOFTWARE
#
#--

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
