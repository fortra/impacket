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

import unittest
from contextlib import redirect_stdout
from io import StringIO

from impacket.winregistry import REG_MULTISZ, exportRegistryParser, format_multi_sz, saveRegistryParser


class WinRegistryTests(unittest.TestCase):

    def test_format_multi_sz_splits_values_and_removes_trailing_terminators(self):
        value = "first\0second\0\0".encode("utf-16le")

        self.assertEqual(format_multi_sz(value, separator="\n\t\t"), "first\n\t\tsecond")

    def test_format_multi_sz_accepts_unpacked_remote_registry_strings(self):
        value = "first\0second\0\0"

        self.assertEqual(format_multi_sz(value, separator="\n  "), "first\n  second")

    def test_format_multi_sz_preserves_null_sentinel(self):
        self.assertEqual(format_multi_sz(0), "NULL")

    def test_save_registry_print_value_formats_reg_multi_sz(self):
        value = "first\0second\0\0".encode("utf-16le")
        output = StringIO()

        with redirect_stdout(output):
            saveRegistryParser.printValue(None, REG_MULTISZ, value, multiSzSeparator="\n     ")

        self.assertEqual(output.getvalue(), "first\n     second\n")

    def test_export_registry_print_value_formats_empty_reg_multi_sz_as_null(self):
        output = StringIO()

        with redirect_stdout(output):
            exportRegistryParser.printValue(None, REG_MULTISZ, b"\x00\x00")

        self.assertEqual(output.getvalue(), "NULL\n")


if __name__ == "__main__":
    unittest.main(verbosity=1)
