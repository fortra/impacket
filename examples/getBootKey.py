#!/usr/bin/env python
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
#   This script computes the Windows Boot Key using the class names of 4 LSA registry keys.
#
# Author:
#   Maxime AWOUKOU (@MaxToffy)
#
# References:
#   - https://blog.whiteflag.io/blog/dumping-lsa-secrets-a-story-about-task-decorrelation/

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
import binascii

from impacket import version
from impacket.examples import logger

def getBootKey(jd, skew1, gbg, data):
    bootKey = b''
    tmpKey = jd + skew1 + gbg + data
    tmpKey = binascii.unhexlify(tmpKey.encode('utf-8'))
    
    transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
    
    for i in range(len(tmpKey)):
        bootKey += tmpKey[transforms[i]:transforms[i] + 1]
    
    logging.info('BootKey: 0x%s' % binascii.hexlify(bootKey).decode('utf-8'))

if __name__ == '__main__':
    print(version.BANNER)
    
    parser = argparse.ArgumentParser(add_help = True, description = "Computes the Windows Boot Key using the class names of 4 LSA registry keys")

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    
    parser.add_argument('jd', action='store', help='Class name of HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD')
    parser.add_argument('skew1', action='store', help='Class name of HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Skew1')
    parser.add_argument('gbg', action='store', help='Class name of HKLM\SYSTEM\CurrentControlSet\Control\Lsa\GBG')
    parser.add_argument('data', action='store', help='Class name of HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Data')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        getBootKey(options.jd, options.skew1, options.gbg, options.data)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)