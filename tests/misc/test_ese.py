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

from impacket.ese import (
    ESENT_PAGE,
    ESENT_PAGE_HEADER,
    FIRST_AVAILABLE_PAGE_TAG_MASK,
    FIRST_AVAILABLE_PAGE_TAG_RESERVED_SHIFT,
)


class TestESENTLargePageTags(unittest.TestCase):
    PAGE_SIZE = 32768
    VERSION = 0x620
    REVISION = 0x122

    def _build_page(self, raw_tag_state):
        tag_count = raw_tag_state & FIRST_AVAILABLE_PAGE_TAG_MASK
        header = ESENT_PAGE_HEADER(self.VERSION, self.REVISION, self.PAGE_SIZE)
        header['FirstAvailableDataOffset'] = tag_count * 4
        header['FirstAvailablePageTag'] = raw_tag_state
        header['PageFlags'] = 0x2001

        header_bytes = header.getData()
        page = bytearray(self.PAGE_SIZE)
        page[:len(header_bytes)] = header_bytes

        base_offset = len(header_bytes)
        payloads = [bytes([i, i, i, i]) for i in range(tag_count)]
        tags = []
        offset = 0
        for payload in payloads:
            page[base_offset + offset:base_offset + offset + len(payload)] = payload
            tags.append(struct.pack('<HH', len(payload), offset))
            offset += len(payload)

        page[-4 * tag_count:] = b''.join(reversed(tags))

        return ESENT_PAGE({
            'Version': self.VERSION,
            'FileFormatRevision': self.REVISION,
            'PageSize': self.PAGE_SIZE,
        }, bytes(page)), payloads

    def test_splits_large_page_tag_state(self):
        page, _ = self._build_page(0x100c)

        self.assertEqual(page.record['FirstAvailablePageTag'], 0x100c)
        self.assertEqual(page.tagReserved, (0x100c >> FIRST_AVAILABLE_PAGE_TAG_RESERVED_SHIFT) or 1)
        self.assertEqual(page.tagCount, 0x100c & FIRST_AVAILABLE_PAGE_TAG_MASK)

    def test_iterates_large_page_tags_with_high_bits_set(self):
        page, payloads = self._build_page(0x100c)

        for tag_num in range(1, page.tagCount):
            self.assertEqual(page.getTag(tag_num), (0, payloads[tag_num]))

        with self.assertRaisesRegex(Exception, r'unknown tag'):
            page.getTag(page.tagCount)


if __name__ == '__main__':
    unittest.main(verbosity=1)
