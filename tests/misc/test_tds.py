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

import struct
import unittest

from impacket import tds


class TDSTests(unittest.TestCase):
    def test_info_error_length_is_computed_for_legacy_layout(self):
        token = tds.TDS_INFO_ERROR()
        token["TokenType"] = tds.TDS_ERROR_TOKEN
        token["Number"] = 18456
        token["State"] = 1
        token["Class"] = 14
        token["MsgText"] = "Login failed for user ''.".encode("utf-16le")
        token["MsgTextLen"] = len(token["MsgText"]) // 2
        token["ServerName"] = "MSSQLSERVER".encode("utf-16le")
        token["ServerNameLen"] = len(token["ServerName"]) // 2
        token["ProcName"] = b""
        token["ProcNameLen"] = 0
        token["LineNumber"] = 1

        data = token.getData()

        self.assertEqual(struct.unpack_from("<H", data, 1)[0], len(data) - 3)

    def test_info_error_length_is_computed_for_72_plus_layout(self):
        token = tds.TDS_INFO_ERROR72()
        token["TokenType"] = tds.TDS_ERROR_TOKEN
        token["Number"] = 18456
        token["State"] = 1
        token["Class"] = 14
        token["MsgText"] = "Login failed for user ''.".encode("utf-16le")
        token["MsgTextLen"] = len(token["MsgText"]) // 2
        token["ServerName"] = "MSSQLSERVER".encode("utf-16le")
        token["ServerNameLen"] = len(token["ServerName"]) // 2
        token["ProcName"] = b""
        token["ProcNameLen"] = 0
        token["LineNumber"] = 1

        data = token.getData()

        self.assertEqual(struct.unpack_from("<H", data, 1)[0], len(data) - 3)


if __name__ == "__main__":
    unittest.main(verbosity=1)
