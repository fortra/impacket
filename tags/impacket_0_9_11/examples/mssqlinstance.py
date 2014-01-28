#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: [MC-SQLR] example. Retrieves the instances names from the target host
#
# Author:
#  Alberto Solino (beto@coresecurity.com)
#
# Reference for:
#  Structure
#


from impacket import version, tds
import argparse
import sys
import string

if __name__ == '__main__':
    import cmd

    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('host', action='store', help='target host')
    parser.add_argument('-timeout', action='store', default='5', help='timeout to wait for an answer')

    if len(sys.argv)==1:
        print "description: asks the remote host for its running MSSQL Instances\n"
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    ms_sql = tds.MSSQL(options.host)
    instances = ms_sql.getInstances(string.atoi(options.timeout))
    if len(instances) == 0:
        print "No MSSQL Instances found"
    else:
        for i, instance in enumerate(instances):
            print "[*] Instance %d" % i
            for key in instance.keys():
               print key + ":" + instance[key]
 
