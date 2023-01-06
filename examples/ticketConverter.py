#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will convert kirbi files (commonly used by mimikatz) into ccache files used by impacket,
#   and vice versa.
#
#   Examples:
#       ./ticket_converter.py admin.ccache admin.kirbi
#       ./ticket_converter.py admin.kirbi admin.ccache
#
# Author:
#   Zer1t0 (https://github.com/Zer1t0)
#
# References:
#   - https://tools.ietf.org/html/rfc4120
#   - http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html
#   - https://github.com/gentilkiwi/kekeo
#   - https://github.com/rvazarkar/KrbCredExport
#

import argparse
import struct

from impacket import version
from impacket.krb5.ccache import CCache


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', help="File in kirbi (KRB-CRED) or ccache format")
    parser.add_argument('output_file', help="Output file")
    return parser.parse_args()


def main():
    print(version.BANNER)

    args = parse_args()

    if is_kirbi_file(args.input_file):
        print('[*] converting kirbi to ccache...')
        convert_kirbi_to_ccache(args.input_file, args.output_file)
        print('[+] done')
    elif is_ccache_file(args.input_file):
        print('[*] converting ccache to kirbi...')
        convert_ccache_to_kirbi(args.input_file, args.output_file)
        print('[+] done')
    else:
        print('[X] unknown file format')


def is_kirbi_file(filename):
    with open(filename, 'rb') as fi:
        fileid = struct.unpack(">B", fi.read(1))[0]
    return fileid == 0x76


def is_ccache_file(filename):
    with open(filename, 'rb') as fi:
        fileid = struct.unpack(">B", fi.read(1))[0]
    return fileid == 0x5


def convert_kirbi_to_ccache(input_filename, output_filename):
    ccache = CCache.loadKirbiFile(input_filename)
    ccache.saveFile(output_filename)


def convert_ccache_to_kirbi(input_filename, output_filename):
    ccache = CCache.loadFile(input_filename)
    ccache.saveKirbiFile(output_filename)


if __name__ == '__main__':
    main()
