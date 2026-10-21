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
import unittest
from unittest import mock

from examples import changepasswd
from examples.changepasswd import PasswordHandler


class TimeoutValidationTests(unittest.TestCase):
    def _parse(self, *extra):
        argv = ["changepasswd.py", "dom/user:pass@host", *extra]
        with mock.patch("sys.argv", argv):
            return changepasswd.parse_args()

    def test_cli_rejects_zero_negative_and_non_integer_timeout(self):
        for value in ("0", "-5", "abc"):
            with self.subTest(value=value):
                with mock.patch("sys.stderr"), self.assertRaises(SystemExit) as ctx:
                    self._parse("-timeout", value)
                self.assertEqual(ctx.exception.code, 2)

    def test_cli_accepts_positive_timeout(self):
        self.assertEqual(self._parse("-timeout", "5").timeout, 5)

    def test_cli_timeout_defaults_to_none(self):
        self.assertIsNone(self._parse().timeout)

    def test_handler_rejects_zero_and_negative_timeout(self):
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    PasswordHandler("host", timeout=value)

    def test_handler_accepts_none_and_positive_timeout(self):
        self.assertIsNone(PasswordHandler("host").timeout)
        self.assertEqual(PasswordHandler("host", timeout=5).timeout, 5)


if __name__ == "__main__":
    unittest.main(verbosity=1)
