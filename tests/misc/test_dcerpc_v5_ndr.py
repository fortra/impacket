#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
from __future__ import print_function
import unittest
from binascii import hexlify

from impacket.dcerpc.v5.ndr import (NDRSTRUCT, NDRLONG, NDRSHORT,
                                    NDRUniFixedArray,
                                    NDRUniVaryingArray,
                                    NDRUniConformantVaryingArray,
                                    NDRVaryingString,
                                    NDRConformantVaryingString,
                                    NDRPOINTERNULL)


def hexl(b):
    hexstr = str(hexlify(b).decode('ascii'))
    return ' '.join([hexstr[i:i + 8] for i in range(0, len(hexstr), 8)])


class NDRTest(object):

    def create(self, data=None, isNDR64=False):
        if data is not None:
            return self.theClass(data, isNDR64=isNDR64)
        else:
            return self.theClass(isNDR64=isNDR64)

    def do_test(self, isNDR64=False):
        a = self.create(isNDR64=isNDR64)
        self.populate(a)
        # packing...
        a_str = a.getData()
        self.check_data(a_str, isNDR64)
        # unpacking...
        b = self.create(a_str, isNDR64=isNDR64)
        b_str = b.getData()
        self.assertEqual(b_str, a_str)

    def test_false(self):
        self.do_test(False)

    def test_true(self):
        # Now the same tests but with NDR64
        self.do_test(True)

    def check_data(self, a_str, isNDR64):
        try:
            hexData = getattr(self, 'hexData64' if isNDR64 else 'hexData')
            # Regression check
            self.assertEqual(hexl(a_str), hexData)
        except AttributeError:
            # Show result, to aid adding regression check
            print(self.__class__.__name__, isNDR64, hexl(a_str))


class TestUniFixedArray(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('Array', NDRUniFixedArray),
        )

    def populate(self, a):
        a['Array'] = b'12345678'

    hexData = '31323334 35363738'
    hexData64 = hexData


class TestStructWithPad(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('long', NDRLONG),
            ('short', NDRSHORT),
        )

    def populate(self, a):
        a['long'] = 0xaa
        a['short'] = 0xbb

    hexData = 'aa000000 bb00'
    hexData64 = hexData


# class TestUniConformantArray(NDRTest):
#    class theClass(NDRCall):
#        structure = (
#            ('Array', PNDRUniConformantArray),
#            ('Array2', PNDRUniConformantArray),
#        )
#        def __init__(self, data = None,isNDR64 = False):
#            NDRCall.__init__(self, None, isNDR64)
#            self.fields['Array'].fields['Data'].item = RPC_UNICODE_STRING
#            self.fields['Array2'].fields['Data'].item = RPC_UNICODE_STRING
#            if data is not None:
#                self.fromString(data)
#        
#    def populate(self, a):
#        array = []
#        strstr = RPC_UNICODE_STRING()
#        strstr['Data'] = 'ThisIsMe'
#        array.append(strstr)
#        strstr = RPC_UNICODE_STRING()
#        strstr['Data'] = 'ThisIsYou'
#        array.append(strstr)
#        a['Array'] = array
#        a['Array2'] = array

class TestUniVaryingArray(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('Array', NDRUniVaryingArray),
        )

    def populate(self, a):
        a['Array'] = b'12345678'

    hexData = '00000000 08000000 31323334 35363738'
    hexData64 = '00000000 00000000 08000000 00000000 31323334 35363738'


class TestUniConformantVaryingArray(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('Array', NDRUniConformantVaryingArray),
        )

    def populate(self, a):
        a['Array'] = b'12345678'

    hexData = '08000000 00000000 08000000 31323334 35363738'
    hexData64 = '08000000 00000000 00000000 00000000 08000000 00000000 31323334 35363738'


class TestVaryingString(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('Array', NDRVaryingString),
        )

    def populate(self, a):
        a['Array'] = b'12345678'

    hexData = '00000000 09000000 31323334 35363738 00'
    hexData64 = '00000000 00000000 09000000 00000000 31323334 35363738 00'


class TestConformantVaryingString(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('Array', NDRConformantVaryingString),
        )

    def populate(self, a):
        a['Array'] = b'12345678'

    hexData = '08000000 00000000 08000000 31323334 35363738'
    hexData64 = '08000000 00000000 00000000 00000000 08000000 00000000 31323334 35363738'


class TestPointerNULL(NDRTest, unittest.TestCase):
    class theClass(NDRSTRUCT):
        structure = (
            ('Array', NDRPOINTERNULL),
        )

    def populate(self, a):
        pass

    hexData = '00000000'
    hexData64 = '00000000 00000000'


if __name__ == '__main__':
    unittest.main(verbosity=1)
