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
    ESENT_DB,
    ESENT_PAGE,
    ESENT_PAGE_HEADER,
    FIRST_AVAILABLE_PAGE_TAG_MASK,
    FIRST_AVAILABLE_PAGE_TAG_RESERVED_SHIFT,
    JET_coltypBit,
    JET_coltypLong,
    JET_coltypLongLong,
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

    def test_iter_data_tags_skips_all_reserved_large_page_tags(self):
        page, payloads = self._build_page(0x200c)

        self.assertEqual(page.tagReserved, 2)
        self.assertEqual(page.firstDataTag, 2)
        self.assertEqual(list(page.iterDataTagNums()), list(range(2, page.tagCount)))

        iterated_payloads = [page.getTag(tag_num)[1] for tag_num in page.iterDataTagNums()]
        self.assertEqual(iterated_payloads, payloads[page.firstDataTag:])


class TestESENTNullFixedColumns(unittest.TestCase):
    """Fixed-size columns are followed by a null bitmap in the record."""

    @staticmethod
    def _build_record(columns, values, null_column_ids=()):
        """Build a data record for the given fixed columns.

        The tail of the fixed-size data holds one null bit per fixed column,
        bit 0 of the first byte belonging to the first column.
        """
        fixed_columns = [(column_id, col_type, size) for column_id, col_type, size in columns]
        fixed_data = b''
        for column_id, _, size in fixed_columns:
            fixed_data += values.get(column_id, b'\x00' * size)

        bitmap_len = (len(fixed_columns) + 7) // 8
        bitmap = bytearray(bitmap_len)
        for column_id in null_column_ids:
            index = column_id - 1
            bitmap[index // 8] |= 1 << (index % 8)

        header = struct.pack(
            '<BBH',
            len(fixed_columns),   # LastFixedSize
            127,                  # LastVariableDataType, none present
            4 + len(fixed_data) + len(bitmap),  # VariableSizeOffset
        )
        return header + fixed_data + bytes(bitmap)

    @staticmethod
    def _build_cursor(columns):
        table_columns = {}
        for column_id, col_type, size in columns:
            name = 'col-%d' % column_id
            table_columns[name] = {
                'Record': {
                    'Identifier': column_id,
                    'ColumnType': col_type,
                    'SpaceUsage': size,
                    'CodePage': 1200,
                },
            }
        return {'TableData': {'Columns': table_columns}}

    def _parse(self, columns, values, null_column_ids=()):
        tag = self._build_record(columns, values, null_column_ids)
        db = ESENT_DB.__new__(ESENT_DB)
        return db._ESENT_DB__tagToRecord(self._build_cursor(columns), tag)

    def test_null_fixed_column_is_returned_as_none(self):
        columns = [
            (1, JET_coltypBit, 1),
            (2, JET_coltypBit, 1),
            (3, JET_coltypLongLong, 8),
            (4, JET_coltypLong, 4),
        ]
        values = {
            2: b'\x01',
            3: struct.pack('<q', 1234567890123),
            4: struct.pack('<l', 42),
        }
        record = self._parse(columns, values, null_column_ids=[1])

        self.assertIsNone(record['col-1'])
        self.assertEqual(record['col-2'], 1)
        self.assertEqual(record['col-3'], 1234567890123)
        self.assertEqual(record['col-4'], 42)

    def test_null_bitmap_does_not_shadow_other_columns(self):
        columns = [
            (1, JET_coltypLong, 4),
            (2, JET_coltypLong, 4),
            (3, JET_coltypLong, 4),
        ]
        values = {
            1: struct.pack('<l', 1),
            2: struct.pack('<l', 2),
            3: struct.pack('<l', 3),
        }
        record = self._parse(columns, values, null_column_ids=[2])

        self.assertEqual(record['col-1'], 1)
        self.assertIsNone(record['col-2'])
        self.assertEqual(record['col-3'], 3)

    def test_null_bit_in_second_bitmap_byte(self):
        columns = [(column_id, JET_coltypLong, 4) for column_id in range(1, 11)]
        values = {column_id: struct.pack('<l', column_id) for column_id in range(1, 11)}
        record = self._parse(columns, values, null_column_ids=[10])

        for column_id in range(1, 10):
            self.assertEqual(record['col-%d' % column_id], column_id)
        self.assertIsNone(record['col-10'])

    def test_record_without_null_bitmap_reads_all_columns(self):
        columns = [(1, JET_coltypLong, 4), (2, JET_coltypLong, 4)]
        values = {1: struct.pack('<l', 7), 2: struct.pack('<l', 9)}
        record = self._parse(columns, values)

        self.assertEqual(record['col-1'], 7)
        self.assertEqual(record['col-2'], 9)


if __name__ == '__main__':
    unittest.main(verbosity=1)
