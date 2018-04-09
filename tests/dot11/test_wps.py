#!/usr/bin/env python

# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#  Tests for WPS packets
#
# Author:
# Aureliano Calvo


# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../../..")


import unittest
from impacket import wps
import array


class TestTLVContainer(unittest.TestCase):

    def testNormalUsageContainer(self):
        BUILDERS={
            1: wps.StringBuilder(),
            2: wps.ByteBuilder(),
            3: wps.NumBuilder(2)
        }
        tlvc = wps.TLVContainer(builders=BUILDERS)
        
        KINDS_N_VALUES = (
            (1, "Sarlanga"),
            (2, 1),
            (3, 1024),
            (4, array.array("B", [1,2,3]))
        )
        for k,v in KINDS_N_VALUES:
            tlvc.append(k,v)
        
        tlvc2 = wps.TLVContainer(builders=BUILDERS)
        tlvc2.from_ary(tlvc.to_ary())
        
        for k,v in KINDS_N_VALUES:
            self.assertEqual(v, tlvc2.first(k))
        
        self.assertEqual(tlvc.to_ary(), tlvc2.to_ary())
        self.assertEquals("Sarlanga", tlvc.first(1))

suite = unittest.TestLoader().loadTestsFromTestCase(TestTLVContainer)
unittest.TextTestRunner(verbosity=1).run(suite)
