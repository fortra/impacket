#!/usr/bin/python
# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#             ESE utility. Allows dumping catalog, pages and tables.
#
# Author:
#  Alberto Solino
#
#
# Reference for:
#  Extensive Storage Engine (ese)
# 

import sys
import logging
import argparse
from impacket import version, ese
from impacket.ese import ESENT_DB

def dumpPage(ese, pageNum):
    data = ese.getPage(pageNum)
    data.dump()

def exportTable(ese, tableName):
    cursor = ese.openTable(tableName)
    if cursor is None:
        logging.error('Can"t get a cursor for table: %s' % tableName)
        return

    i = 1
    print "Table: %s" % tableName
    while True:
        record = ese.getNextRow(cursor)
        if record is None:
            break
        print "*** %d" % i
        for j in record.keys():
           if record[j] is not None:
               print "%-30s: %r" % (j, record[j])
        i += 1

def main():
    print version.BANNER
    parser = argparse.ArgumentParser()
    parser.add_argument('databaseFile', action='store', help='ESE to open')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-page', action='store', help='page to open')

    subparsers = parser.add_subparsers(help='actions', dest='action')

    # dump page
    dump_parser = subparsers.add_parser('dump', help='dumps an specific page')
    dump_parser.add_argument('-page', action='store', required=True, help='page to dump')

    # info page
    info_parser = subparsers.add_parser('info', help='dumps the catalog info for the DB')

    # export page
    export_parser = subparsers.add_parser('export', help='dumps the catalog info for the DB')
    export_parser.add_argument('-table', action='store', required=True, help='table to dump')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.basicConfig(format='%(levelname)s:%(message)s',level = logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s:%(message)s',level = logging.WARNING)


    ese = ESENT_DB(options.databaseFile)

    try:
        if options.action.upper() == 'INFO':
            ese.printCatalog()
        elif options.action.upper() == 'DUMP':
            dumpPage(ese, int(options.page))
        elif options.action.upper() == 'EXPORT':
            exportTable(ese, options.table)
        else:
            logging.error('Unknown action %s ' % options.action)
            raise
    except Exception, e:
        print e
    ese.close()


if __name__ == '__main__':
    main()
    sys.exit(1)



