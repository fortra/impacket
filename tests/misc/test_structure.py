#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
from __future__ import print_function
import six
import unittest
from binascii import hexlify

from impacket.structure import Structure


def hexl(b):
    hexstr = str(hexlify(b).decode('ascii'))
    return ' '.join([hexstr[i:i + 8] for i in range(0, len(hexstr), 8)])


class _StructureTest(object):
    # Subclass:
    # - must define theClass
    # - may override alignment
    alignment = 0

    def create(self, data=None):
        if data is not None:
            return self.theClass(data, alignment=self.alignment)
        else:
            return self.theClass(alignment=self.alignment)

    def test_structure(self):
        # print()
        # print("-"*70)
        # testName = self.__class__.__name__
        # print("starting test: %s....." % testName)
        # Create blank structure and fill its fields
        a = self.create()
        self.populate(a)
        # a.dump("packing.....")
        # Get its binary representation
        a_str = a.getData()
        self.check_data(a_str)
        # print("packed: %r" % a_str)
        # print("unpacking.....")
        b = self.create(a_str)
        # b.dump("unpacked.....")
        # print("repacking.....")
        b_str = b.getData()
        self.assertEqual(b_str, a_str,
                         "ERROR: original packed and repacked don't match")

    def check_data(self, a_str):
        if hasattr(self, 'hexData'):
            # Regression check
            self.assertEqual(hexl(a_str), self.hexData)
        else:
            # Show result, to aid adding regression check
            print(self.__class__.__name__, hexl(a_str))


class Test_simple(_StructureTest, unittest.TestCase):
    class theClass(Structure):
        commonHdr = ()
        structure = (
            ('int1', '!L'),
            ('len1', '!L-z1'),
            ('arr1', 'B*<L'),
            ('z1', 'z'),
            ('u1', 'u'),
            ('', '"COCA'),
            ('len2', '!H-:1'),
            ('', '"COCA'),
            (':1', ':'),
            ('int3', '>L'),
            ('code1', '>L=len(arr1)*2+0x1000'),
        )

    def populate(self, a):
        a['default'] = 'hola'
        a['int1'] = 0x3131
        a['int3'] = 0x45444342
        a['z1'] = 'hola'
        a['u1'] = 'hola'.encode('utf_16_le')
        a[':1'] = ':1234:'
        a['arr1'] = (0x12341234, 0x88990077, 0x41414141)
        # a['len1'] = 0x42424242

    hexData = '00003131 00000005 03341234 12770099 88414141 41686f6c 61006800 6f006c00 61000000 434f4341 0006434f 43413a31 3233343a 45444342 00001006'


class Test_fixedLength(Test_simple):
    def test_structure(self):
        a = self.create()
        self.populate(a)
        # Set a bogus length...
        a['len1'] = 0x42424242
        a_str = a.getData()
        if hasattr(self, 'hexData'):
            # Regression check
            self.assertEqual(hexl(a_str), self.hexData)
        else:
            print(hexl(a_str))
        # ... so that unpacking will now fail
        with six.assertRaisesRegex(self, Exception, r'not NUL terminated'):
            self.create(a_str)

    hexData = '00003131 42424242 03341234 12770099 88414141 41686f6c 61006800 6f006c00 61000000 434f4341 0006434f 43413a31 3233343a 45444342 00001006'


class Test_simple_aligned4(Test_simple):
    alignment = 4
    hexData = '00003131 00000005 03341234 12770099 88414141 41000000 686f6c61 00000000 68006f00 6c006100 00000000 434f4341 00060000 434f4341 3a313233 343a0000 45444342 00001006'


class Test_nested(_StructureTest, unittest.TestCase):
    class theClass(Structure):
        class _Inner(Structure):
            structure = (('data', 'z'),)

        structure = (
            ('nest1', ':', _Inner),
            ('nest2', ':', _Inner),
            ('int', '<L'),
        )

    def populate(self, a):
        a['nest1'] = Test_nested.theClass._Inner()
        a['nest2'] = Test_nested.theClass._Inner()
        a['nest1']['data'] = 'hola manola'
        a['nest2']['data'] = 'chau loco'
        a['int'] = 0x12345678

    hexData = '686f6c61 206d616e 6f6c6100 63686175 206c6f63 6f007856 3412'


class Test_Optional(_StructureTest, unittest.TestCase):
    class theClass(Structure):
        structure = (
            ('pName', '<L&Name'),
            ('pList', '<L&List'),
            ('Name', 'w'),
            ('List', '<H*<L'),
        )

    def populate(self, a):
        a['Name'] = 'Optional test'
        a['List'] = (1, 2, 3, 4)

    def check_data(self, a_str):
        # Pointer values change between runs, so ignore them
        filtered = ''.join(['-' if h == '-' else a
                            for a, h in zip(hexl(a_str), self.hexData)])
        self.assertEqual(filtered, self.hexData)

    hexData = '-------- -------- 07000000 07000000 00000000 4f707469 6f6e616c 20746573 74000400 01000000 02000000 03000000 04000000'


class Test_Optional_sparse(Test_Optional):
    def populate(self, a):
        Test_Optional.populate(self, a)
        del a['Name']

    hexData = '00000000 -------- 04000100 00000200 00000300 00000400 0000'


class Test_AsciiZArray(_StructureTest, unittest.TestCase):
    class theClass(Structure):
        structure = (
            ('head', '<L'),
            ('array', 'B*z'),
            ('tail', '<L'),
        )

    def populate(self, a):
        a['head'] = 0x1234
        a['tail'] = 0xabcd
        a['array'] = ('hola', 'manola', 'te traje')

    hexData = '34120000 03686f6c 61006d61 6e6f6c61 00746520 7472616a 6500cdab 0000'


class Test_UnpackCode(_StructureTest, unittest.TestCase):
    class theClass(Structure):
        structure = (
            ('leni', '<L=len(uno)*2'),
            ('cuchi', '_-uno', 'leni//2'),
            ('uno', ':'),
            ('dos', ':'),
        )

    def populate(self, a):
        a['uno'] = 'soy un loco!'
        a['dos'] = 'que haces fiera'

    hexData = '18000000 736f7920 756e206c 6f636f21 71756520 68616365 73206669 657261'


class Test_AAA(_StructureTest, unittest.TestCase):
    class theClass(Structure):
        commonHdr = ()
        structure = (
            ('iv', '!L=((init_vector & 0xFFFFFF) << 8) | ((pad & 0x3f) << 2) | (keyid & 3)'),
            ('init_vector', '_', '(iv >> 8)'),
            ('pad', '_', '((iv >>2) & 0x3F)'),
            ('keyid', '_', '( iv & 0x03 )'),
            ('dataLen', '_-data', 'len(inputDataLeft)-4'),
            ('data', ':'),
            ('icv', '>L'),
        )

    def populate(self, a):
        a['init_vector'] = 0x01020304
        # a['pad']=int('01010101',2)
        a['pad'] = int('010101', 2)
        a['keyid'] = 0x07
        a['data'] = "\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9"
        a['icv'] = 0x05060708
        # a['iv'] = 0x01020304

    hexData = '02030457 a0a1a2a3 a4a5a6a7 a8a90506 0708'


if __name__ == "__main__":
    unittest.main(verbosity=1)
