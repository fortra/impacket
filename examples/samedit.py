#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2024 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Simple implementation for replacing a local user's password through
#   editing of a copy of the SAM and SYSTEM hives.
#
#   It still needs some improvement to handle some scenarios and expanded
#   to allow user creation/password setting as it currently only allows
#   for the replacing of an existing password for an existing user.
#
# Author:
#   Otavio Brito (@Iorpim)
#
# References:
#   The code is largely based on previous impacket work, namely
#   the secretsdump and winregistry packages. (both by @agsolino)
#

import sys
import codecs
import argparse
import logging
import binascii

from impacket import version, ntlm
from impacket.examples import logger

from impacket.examples.secretsdump import LocalOperations, SAMHashes

try:
    input = raw_input
except NameError:
    pass


if __name__ == '__main__':
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getWriter('utf8')(sys.stdout)
    
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "In-place edits a local user's password in a SAM hive file")

    parser.add_argument('user', action='store', help='Name of the user account to replace the password')
    parser.add_argument('sam', action='store', help='SAM hive file to edit')

    parser.add_argument('-password', action='store', help='New password to be set')
    parser.add_argument('-hashes', action='store', help='Replace NTLM hash directly (LM hash is optional)')

    parser.add_argument('-system', action='store', help='SYSTEM hive file containing the bootkey for password encryption')
    parser.add_argument('-bootkey', action='store', help='Bootkey used to encrypt and decrypt SAM passwords')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')


    if len(sys.argv) < 4:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    if options.system is None and options.bootkey is None:
        logging.critical('A SYSTEM hive or bootkey value is required for password changing')
        sys.exit(1)
    
    if options.system is not None and options.bootkey is not None:
        logging.critical('Only a SYSTEM hive or bootkey value can be supplied')
        sys.exit(1)
    
    if options.password is None and options.hashes is None:
        logging.critical('A password or hash argument is required')
        sys.exit(1)
    
    if options.password is not None and options.hashes is not None:
        logging.critical('Only a password or hash argument can be supplied')
        sys.exit(1)
    
    if options.bootkey:
        bootkey = binascii.unhexlify(options.bootkey)
    else:
        localOperations = LocalOperations(options.system)
        bootkey = localOperations.getBootKey()
    
    hive = SAMHashes(options.sam, bootkey, False)

    if options.hashes:
        if ':' not in options.hashes:
            LMHash = b''
            NTHash = binascii.unhexlify(options.hashes)
        else:
            LMHash, NTHash = [binascii.unhexlify(hash) for hash in options.hashes.split(":")]
    
    if options.password:
        LMHash = b''
        NTHash = ntlm.NTOWFv1(options.password)

    try:
        hive.edit(options.user, NTHash, LMHash)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)

    hive.finish()