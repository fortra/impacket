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
from datetime import datetime, timedelta, timezone

from examples.filetime import FileTimes
from impacket import wintime


class WinTimeTests(unittest.TestCase):
    def test_zero_and_pre_unix_filetimes_are_aware_utc(self):
        cases = (
            (0, datetime(1601, 1, 1, tzinfo=timezone.utc)),
            (113288544000000000, datetime(1960, 1, 1, tzinfo=timezone.utc)),
        )
        for filetime, expected in cases:
            with self.subTest(filetime=filetime):
                self.assertEqual(wintime.filetime_to_datetime(filetime), expected)

    def test_datetime_preserves_microseconds(self):
        self.assertEqual(
            wintime.filetime_to_datetime(133485840001234567),
            datetime(2024, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc),
        )

    def test_displayed_filetimes_round_trip_through_timestamp_input(self):
        filetimes = [wintime.posix_to_filetime(1704110400.125 + i) for i in range(4)]
        lines = FileTimes(*filetimes).pretty_repr().strip().splitlines()
        self.assertEqual(len(lines), 4)
        for line, expected in zip(lines, filetimes):
            field, timestamp = line.split(': ', 1)
            with self.subTest(field=field):
                parsed = datetime.fromisoformat(timestamp)
                self.assertEqual(parsed.utcoffset(), timedelta(0))
                self.assertEqual(wintime.posix_to_filetime(parsed.timestamp()), expected)


if __name__ == '__main__':
    unittest.main(verbosity=1)
