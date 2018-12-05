#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description: A Windows Registry Reader Example
#
# Reference for:
#  winregistry.py
#

import sys
import argparse
import ntpath
from binascii import unhexlify, hexlify

from impacket.examples import logger
from impacket import version
from impacket import winregistry


def bootKey(reg):
    baseClass = 'ControlSet001\\Control\\Lsa\\'
    keys = ['JD','Skew1','GBG','Data']
    tmpKey = ''

    for key in keys:
        tmpKey = tmpKey + unhexlify(reg.getClass(baseClass + key).decode('utf-16le')[:8])

    transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

    syskey = ''
    for i in xrange(len(tmpKey)):
        syskey += tmpKey[transforms[i]]

    print hexlify(syskey)

def getClass(reg, className):
    regKey = ntpath.dirname(className)
    regClass = ntpath.basename(className)

    value = reg.getClass(className)

    if value is None:
        return

    print "[%s]" % regKey

    print "Value for Class %s: \n" % regClass,

    winregistry.hexdump(value,'   ')

def getValue(reg, keyValue):
    regKey = ntpath.dirname(keyValue)
    regValue = ntpath.basename(keyValue)

    value = reg.getValue(keyValue)

    print "[%s]\n" % regKey

    if value is None:
        return

    print "Value for %s:\n    " % regValue,
    reg.printValue(value[0],value[1])

def enumValues(reg, searchKey):
    key = reg.findKey(searchKey)

    if key is None:
        return

    print "[%s]\n" % searchKey

    values = reg.enumValues(key)

    for value in values:
        print "  %-30s: " % value,
        data = reg.getValue('%s\\%s'%(searchKey,value))
        # Special case for binary string.. so it looks better formatted
        if data[0] == winregistry.REG_BINARY:
            print ''
            reg.printValue(data[0],data[1])
            print ''
        else:
            reg.printValue(data[0],data[1])

def enumKey(reg, searchKey, isRecursive, indent='  '):
    parentKey = reg.findKey(searchKey)

    if parentKey is None:
        return

    keys = reg.enumKey(parentKey)

    for key in keys:
        print "%s%s" %(indent, key)
        if isRecursive is True:
            if searchKey == '\\':
                enumKey(reg, '\\%s'%key,isRecursive,indent+'  ')
            else:
                enumKey(reg, '%s\\%s'%(searchKey,key),isRecursive,indent+'  ')

def walk(reg, keyName):
    return reg.walk(keyName)


def main():
    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Reads data from registry hives.")

    parser.add_argument('hive', action='store', help='registry hive to open')
    subparsers = parser.add_subparsers(help='actions', dest='action')
    # A enum_key command
    enumkey_parser = subparsers.add_parser('enum_key', help='enumerates the subkeys of the specified open registry key')
    enumkey_parser.add_argument('-name', action='store', required=True, help='registry key')
    enumkey_parser.add_argument('-recursive', dest='recursive', action='store_true', required=False, help='recursive search (default False)')

    # A enum_values command
    enumvalues_parser = subparsers.add_parser('enum_values', help='enumerates the values for the specified open registry key')
    enumvalues_parser.add_argument('-name', action='store', required=True, help='registry key')

    # A get_value command
    getvalue_parser = subparsers.add_parser('get_value', help='retrieves the data for the specified registry value')
    getvalue_parser.add_argument('-name', action='store', required=True, help='registry value')

    # A get_class command
    getclass_parser = subparsers.add_parser('get_class', help='retrieves the data for the specified registry class')
    getclass_parser.add_argument('-name', action='store', required=True, help='registry class name')

    # A walk command
    walk_parser = subparsers.add_parser('walk', help='walks the registry from the name node down')
    walk_parser.add_argument('-name', action='store', required=True, help='registry class name to start walking down from')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    reg = winregistry.Registry(options.hive)

    if options.action.upper() == 'ENUM_KEY':
        print "[%s]" % options.name
        enumKey(reg, options.name, options.recursive)
    elif options.action.upper() == 'ENUM_VALUES':
        enumValues(reg, options.name)
    elif options.action.upper() == 'GET_VALUE':
        getValue(reg, options.name)
    elif options.action.upper() == 'GET_CLASS':
        getClass(reg, options.name)
    elif options.action.upper() == 'WALK':
        walk(reg, options.name)

    reg.close()

if __name__ == "__main__":
    main()

