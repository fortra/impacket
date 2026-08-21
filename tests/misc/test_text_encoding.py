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
import unittest

from impacket.dcerpc.v5 import rrp, samr
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING, STR, WIDESTR, WSTR
from impacket.dcerpc.v5.srvs import WCHAR_ARRAY


class TextEncodingTests(unittest.TestCase):

    def test_wide_string_types_accept_bytes(self):
        for string_type in (WIDESTR, WSTR, WCHAR_ARRAY):
            value = string_type()
            value['Data'] = b'test'

            self.assertEqual(value['Data'], 'test')
            self.assertEqual(value.fields['Data'], 'test'.encode('utf-16le'))

    def test_rpc_unicode_string_accepts_bytes(self):
        value = RPC_UNICODE_STRING()
        value['Data'] = b'test'

        self.assertEqual(value['Data'], 'test')
        self.assertEqual(value['Length'], 8)
        self.assertEqual(value['MaximumLength'], 8)

    def test_str_preserves_raw_bytes(self):
        value = STR()
        value['Data'] = b'\xff'

        self.assertEqual(value.fields['Data'], b'\xff')

    def test_registry_string_types_accept_bytes(self):
        for value_type in (rrp.REG_EXPAND_SZ, rrp.REG_SZ):
            self.assertEqual(
                rrp.packValue(value_type, b'value'),
                'value\x00'.encode('utf-16le'),
            )

        self.assertEqual(
            rrp.packValue(rrp.REG_MULTI_SZ, b'one\x00two\x00'),
            'one\x00two\x00\x00'.encode('utf-16le'),
        )

    def test_samr_password_change_accepts_bytes(self):
        class FakeDCE:
            def request(self, request):
                return request

        request = samr.hSamrUnicodeChangePasswordUser2(
            FakeDCE(),
            userName='user',
            oldPassword='OldPassword1!',
            newPassword=b'NewPassword2!',
        )

        self.assertIsInstance(request, samr.SamrUnicodeChangePasswordUser2)


if __name__ == '__main__':
    unittest.main(verbosity=1)
