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
# Unit tests for examples/ntfs-read.py — data run parsing, read logic,
# attribute list handling, walk() inline entries, etc.
#
import importlib.util
import io
import os
import struct
import unittest

# ---------------------------------------------------------------------------
# Import ntfs-read.py (hyphenated name requires importlib)
# ---------------------------------------------------------------------------
_NTFS_READ_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'examples', 'ntfs-read.py')
)
_spec = importlib.util.spec_from_file_location('ntfs_read', _NTFS_READ_PATH)
ntfs_read = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ntfs_read)

# Shorthand constants from the module
DATA = ntfs_read.DATA
FILE_NAME = ntfs_read.FILE_NAME
FILE_NAME_WIN32 = ntfs_read.FILE_NAME_WIN32
FILE_NAME_DOS = ntfs_read.FILE_NAME_DOS
INDEX_ROOT = ntfs_read.INDEX_ROOT

BYTES_PER_SECTOR = 512
SECTORS_PER_CLUSTER = 8
CLUSTER_SIZE = BYTES_PER_SECTOR * SECTORS_PER_CLUSTER  # 4096


# ===========================================================================
# Helpers / Fixtures
# ===========================================================================

class MockBPB:
    """Dict-like mock for volume BPB."""
    def __getitem__(self, key):
        return {
            'BytesPerSector': BYTES_PER_SECTOR,
            'SectorsPerCluster': SECTORS_PER_CLUSTER,
        }[key]


class MockVolume:
    """Minimal NTFS volume mock backed by BytesIO."""
    def __init__(self, size=0):
        self.volumeFD = io.BytesIO(b'\x00' * size)
        self.BPB = MockBPB()


class MockINode:
    """Minimal inode mock for attribute construction."""
    def __init__(self, volume=None):
        self.NTFSVolume = volume or MockVolume()
        self.INodeNumber = 100


def build_nonresident_attr(data_runs_bytes, data_size,
                           initialized_size=None, allocated_size=None):
    """Build a complete raw non-resident attribute record.

    Returns bytes: common header + non-resident header + data run bytes.
    """
    if initialized_size is None:
        initialized_size = data_size
    if allocated_size is None:
        allocated_size = max(
            ((data_size + CLUSTER_SIZE - 1) // CLUSTER_SIZE) * CLUSTER_SIZE,
            CLUSTER_SIZE,
        )

    COMMON_HDR_SIZE = 16
    NR_HDR_SIZE = 48
    runs_offset = COMMON_HDR_SIZE + NR_HDR_SIZE  # 64
    total_length = runs_offset + len(data_runs_bytes)
    total_length = (total_length + 7) & ~7  # 8-byte align

    # NTFS_ATTRIBUTE_RECORD (common header)
    buf = struct.pack('<LLBBHHH',
                      DATA,          # Type
                      total_length,  # Length
                      1,             # NonResident
                      0,             # NameLength
                      0,             # NameOffset
                      0,             # Flags
                      0)             # Instance

    # NTFS_ATTRIBUTE_RECORD_NON_RESIDENT
    buf += struct.pack('<QQ', 0, 0)                      # LowestVCN, HighestVCN
    buf += struct.pack('<HH', runs_offset, 0)            # DataRunsOffset, CompressionUnit
    buf += b'\x00' * 4                                   # Reserved1
    buf += struct.pack('<QQQ',
                       allocated_size, data_size, initialized_size)

    buf += data_runs_bytes
    buf += b'\x00' * (total_length - len(buf))
    return buf


def build_file_name_attr(name, file_name_type=FILE_NAME_WIN32):
    """Build raw NTFS_FILE_NAME_ATTR bytes."""
    encoded = name.encode('utf-16le')
    buf = struct.pack('<Q', 5)                           # ParentDirectory
    buf += struct.pack('<Q', 0)                          # CreationTime
    buf += struct.pack('<Q', 132_000_000_000_000_000)    # LastDataChangeTime
    buf += struct.pack('<Q', 0)                          # LastMftChangeTime
    buf += struct.pack('<Q', 0)                          # LastAccessTime
    buf += struct.pack('<Q', 0)                          # AllocatedSize
    buf += struct.pack('<Q', 0)                          # DataSize
    buf += struct.pack('<LL', 0, 0)                      # FileAttributes, EaSize
    buf += struct.pack('BB', len(name), file_name_type)
    buf += encoded
    return buf


def build_attr_list_entry(attr_type, starting_vcn, mft_record_num, attr_id,
                          name=None, mft_seq=0):
    """Build raw NTFS_ATTRIBUTE_LIST_ENTRY bytes (26-byte fixed + optional name)."""
    BASE_SIZE = 26
    name_bytes = b''
    name_len = 0
    name_offset = 0

    if name is not None:
        name_bytes = name.encode('utf-16le')
        name_len = len(name)
        name_offset = BASE_SIZE

    entry_length = BASE_SIZE + len(name_bytes)
    base_file_record = (
        ((mft_seq & 0xFFFF) << 48) | (mft_record_num & 0x0000FFFFFFFFFFFF)
    )

    buf = struct.pack('<LH BB Q Q H',
                      attr_type, entry_length,
                      name_len, name_offset,
                      starting_vcn,
                      base_file_record,
                      attr_id)
    buf += name_bytes
    return buf


class MockIndexEntry:
    """Minimal IndexEntry stand-in for walk() tests."""
    def __init__(self, key, inode_num, is_subnode=False, vcn=0):
        self._key = key
        self._inode_num = inode_num
        self._is_subnode = is_subnode
        self._vcn = vcn

    def isSubNode(self):
        return self._is_subnode

    def isLastNode(self):
        return False

    def getKey(self):
        return self._key

    def getINodeNumber(self):
        return self._inode_num

    def getVCN(self):
        return self._vcn


class MockIndexRoot:
    """Minimal AttributeIndexRoot stand-in for walk() tests."""
    def __init__(self, type_flag, entries):
        self._type = type_flag
        self.IndexEntries = entries

    def getType(self):
        return self._type


# ===========================================================================
# Test Classes
# ===========================================================================

class TestParseDataRuns(unittest.TestCase):
    """Verify data-run parsing inside AttributeNonResident construction."""

    def _make(self, runs_bytes, data_size=CLUSTER_SIZE, **kw):
        raw = build_nonresident_attr(runs_bytes, data_size, **kw)
        return ntfs_read.AttributeNonResident(MockINode(), raw)

    def test_single_run(self):
        # 0x11 -> 1 len byte, 1 offset byte; len=8, offset=10
        attr = self._make(b'\x11\x08\x0A\x00', data_size=8 * CLUSTER_SIZE)
        self.assertEqual(len(attr.DataRuns), 1)
        dr = attr.DataRuns[0]
        self.assertEqual(dr['LCN'], 10)
        self.assertEqual(dr['Clusters'], 8)
        self.assertEqual(dr['StartVCN'], 0)
        self.assertEqual(dr['LastVCN'], 7)

    def test_sparse_run(self):
        # 0x01 -> 1 len byte, 0 offset bytes -> sparse
        attr = self._make(b'\x01\x05\x00', data_size=5 * CLUSTER_SIZE)
        self.assertEqual(len(attr.DataRuns), 1)
        self.assertEqual(attr.DataRuns[0]['LCN'], -1)
        self.assertEqual(attr.DataRuns[0]['Clusters'], 5)

    def test_negative_delta(self):
        # Run 1: 8 clusters @ LCN 20  (delta=+20=0x14)
        # Run 2: 4 clusters @ LCN 16  (delta=-4=0xFC signed byte)
        attr = self._make(b'\x11\x08\x14\x11\x04\xFC\x00',
                          data_size=12 * CLUSTER_SIZE)
        self.assertEqual(len(attr.DataRuns), 2)
        self.assertEqual(attr.DataRuns[0]['LCN'], 20)
        self.assertEqual(attr.DataRuns[1]['LCN'], 16)
        self.assertEqual(attr.DataRuns[1]['Clusters'], 4)

    def test_multi_run(self):
        # 4@LCN10, 4@LCN20(delta+10), 4@LCN30(delta+10)
        attr = self._make(b'\x11\x04\x0A\x11\x04\x0A\x11\x04\x0A\x00',
                          data_size=12 * CLUSTER_SIZE)
        self.assertEqual(len(attr.DataRuns), 3)
        self.assertEqual([dr['LCN'] for dr in attr.DataRuns], [10, 20, 30])
        self.assertEqual(attr.DataRuns[0]['StartVCN'], 0)
        self.assertEqual(attr.DataRuns[0]['LastVCN'], 3)
        self.assertEqual(attr.DataRuns[1]['StartVCN'], 4)
        self.assertEqual(attr.DataRuns[1]['LastVCN'], 7)
        self.assertEqual(attr.DataRuns[2]['StartVCN'], 8)
        self.assertEqual(attr.DataRuns[2]['LastVCN'], 11)

    def test_empty(self):
        attr = self._make(b'\x00')
        self.assertEqual(attr.DataRuns, [])

    def test_truncated_stops_gracefully(self):
        # 0x21 -> 1 len byte + 2 offset bytes needed, but allocated_size
        # limits AttrValue so the offset bytes are absent
        attr = self._make(b'\x21\x08', allocated_size=2)
        self.assertEqual(len(attr.DataRuns), 0)


class TestReadVCN(unittest.TestCase):
    """Verify readVCN() across multiple data runs including sparse."""

    def _write_volume(self, lcn_map):
        """Return a MockVolume with known data written at given LCN offsets."""
        max_end = max(lcn * CLUSTER_SIZE + len(d) for lcn, d in lcn_map.items())
        vol = MockVolume(max_end)
        for lcn, data in lcn_map.items():
            vol.volumeFD.seek(lcn * CLUSTER_SIZE)
            vol.volumeFD.write(data)
        return vol

    def test_span_two_runs(self):
        pattern_a = b'\xAA' * (2 * CLUSTER_SIZE)
        pattern_b = b'\xBB' * (2 * CLUSTER_SIZE)
        vol = self._write_volume({10: pattern_a, 20: pattern_b})

        # 2 clusters @ LCN 10, 2 clusters @ LCN 20 (delta +10)
        runs = b'\x11\x02\x0A\x11\x02\x0A\x00'
        raw = build_nonresident_attr(runs, data_size=4 * CLUSTER_SIZE)
        attr = ntfs_read.AttributeNonResident(MockINode(vol), raw)
        attr.ClusterSize = CLUSTER_SIZE

        buf = attr.readVCN(0, 4)
        self.assertEqual(len(buf), 4 * CLUSTER_SIZE)
        self.assertEqual(buf[:2 * CLUSTER_SIZE], pattern_a)
        self.assertEqual(buf[2 * CLUSTER_SIZE:], pattern_b)

    def test_sparse_in_middle(self):
        pattern_a = b'\xAA' * (2 * CLUSTER_SIZE)
        pattern_c = b'\xCC' * (2 * CLUSTER_SIZE)
        vol = self._write_volume({10: pattern_a, 30: pattern_c})

        # 2@LCN10, 2 sparse, 2@LCN30 (delta from prevLcn=10 -> +20=0x14)
        runs = b'\x11\x02\x0A\x01\x02\x11\x02\x14\x00'
        raw = build_nonresident_attr(runs, data_size=6 * CLUSTER_SIZE)
        attr = ntfs_read.AttributeNonResident(MockINode(vol), raw)
        attr.ClusterSize = CLUSTER_SIZE

        buf = attr.readVCN(0, 6)
        self.assertEqual(len(buf), 6 * CLUSTER_SIZE)
        self.assertEqual(buf[:2 * CLUSTER_SIZE], pattern_a)
        self.assertEqual(buf[2 * CLUSTER_SIZE:4 * CLUSTER_SIZE],
                         b'\x00' * 2 * CLUSTER_SIZE)
        self.assertEqual(buf[4 * CLUSTER_SIZE:], pattern_c)


class TestRead(unittest.TestCase):
    """Verify read() clamping, zero-fill, and partial-cluster alignment."""

    def _setup(self, data_size, initialized_size=None, lcn=5, num_clusters=None):
        """Build a volume + non-resident attr backed by a repeating pattern."""
        if num_clusters is None:
            num_clusters = max((data_size + CLUSTER_SIZE - 1) // CLUSTER_SIZE, 1)
        total_bytes = num_clusters * CLUSTER_SIZE

        # Deterministic pattern: 0x00..0xFF repeating
        pattern = bytes(range(256)) * ((total_bytes // 256) + 1)
        cluster_data = pattern[:total_bytes]

        vol = MockVolume(lcn * CLUSTER_SIZE + total_bytes)
        vol.volumeFD.seek(lcn * CLUSTER_SIZE)
        vol.volumeFD.write(cluster_data)

        # Single data run: num_clusters @ lcn
        runs = (b'\x11'
                + struct.pack('B', num_clusters)
                + struct.pack('B', lcn)
                + b'\x00')
        raw = build_nonresident_attr(runs, data_size,
                                     initialized_size=initialized_size,
                                     allocated_size=total_bytes)
        attr = ntfs_read.AttributeNonResident(MockINode(vol), raw)
        return attr, cluster_data

    def test_basic_read(self):
        attr, disk = self._setup(data_size=5000)
        result = attr.read(0, 5000)
        self.assertEqual(len(result), 5000)
        self.assertEqual(result, disk[:5000])

    def test_eof_clamp(self):
        attr, disk = self._setup(data_size=5000)
        result = attr.read(4000, 2000)  # offset+length exceeds data_size
        self.assertEqual(len(result), 1000)
        self.assertEqual(result, disk[4000:5000])

    def test_past_eof(self):
        attr, _ = self._setup(data_size=5000)
        result = attr.read(5000, 100)
        self.assertEqual(result, b'')

    def test_initialized_size_zero_fill(self):
        attr, disk = self._setup(data_size=8000, initialized_size=4000)
        result = attr.read(0, 8000)
        self.assertEqual(len(result), 8000)
        self.assertEqual(result[:4000], disk[:4000])
        self.assertEqual(result[4000:], b'\x00' * 4000)

    def test_partial_cluster_offset(self):
        attr, disk = self._setup(data_size=CLUSTER_SIZE * 2)
        result = attr.read(100, 200)
        self.assertEqual(len(result), 200)
        self.assertEqual(result, disk[100:300])


class TestAttributeListEntry(unittest.TestCase):
    """Verify AttributeListEntry field extraction."""

    def test_mft_record_split(self):
        record_num = 0x123456789AB
        seq = 0x0007
        entry_bytes = build_attr_list_entry(
            DATA, starting_vcn=0, mft_record_num=record_num,
            attr_id=1, mft_seq=seq,
        )
        entry = ntfs_read.AttributeListEntry(entry_bytes)
        self.assertEqual(entry.MftRecordNumber, record_num)
        self.assertEqual(entry.MftSequenceNumber, seq)

    def test_named_attribute(self):
        entry_bytes = build_attr_list_entry(
            DATA, starting_vcn=0, mft_record_num=42,
            attr_id=3, name='$SDS',
        )
        entry = ntfs_read.AttributeListEntry(entry_bytes)
        self.assertEqual(entry.AttributeName, '$SDS')

    def test_unnamed_attribute(self):
        entry_bytes = build_attr_list_entry(
            DATA, starting_vcn=0, mft_record_num=42,
            attr_id=3,
        )
        entry = ntfs_read.AttributeListEntry(entry_bytes)
        self.assertIsNone(entry.AttributeName)


class TestAttributeListParsing(unittest.TestCase):
    """Verify AttributeList._parseEntries() with multiple entries."""

    @staticmethod
    def _make_resident_attr(raw_data):
        """Build a fake resident attribute whose getValue() returns raw_data."""
        class _Fake:
            def getValue(self):
                return raw_data
            def getDataSize(self):
                return len(raw_data)
        return _Fake()

    def test_three_entries(self):
        e1 = build_attr_list_entry(0x10, 0, 100, 1)  # STANDARD_INFORMATION
        e2 = build_attr_list_entry(0x30, 0, 100, 2)  # FILE_NAME
        e3 = build_attr_list_entry(0x80, 0, 200, 3)  # DATA
        sentinel = b'\x00' * 26  # zero-length entry terminates
        raw = e1 + e2 + e3 + sentinel

        al = ntfs_read.AttributeList(self._make_resident_attr(raw))
        self.assertEqual(len(al.Entries), 3)
        self.assertEqual(al.Entries[0].AttributeType, 0x10)
        self.assertEqual(al.Entries[1].AttributeType, 0x30)
        self.assertEqual(al.Entries[2].AttributeType, 0x80)
        self.assertEqual(al.Entries[2].MftRecordNumber, 200)

    def test_truncated_stops(self):
        """Data shorter than minimum entry size (26 bytes) -> empty list."""
        al = ntfs_read.AttributeList(self._make_resident_attr(b'\x00' * 20))
        self.assertEqual(len(al.Entries), 0)


class TestWalk(unittest.TestCase):
    """Verify INODE.walk() with inline INDEX_ROOT entries."""

    def _make_inode(self, index_root=None):
        inode = ntfs_read.INODE(MockVolume())
        inode.INodeNumber = 200
        if index_root is not None:
            inode.Attributes[INDEX_ROOT] = index_root
        return inode

    def test_inline_entries(self):
        valid_key = build_file_name_attr('report.txt', FILE_NAME_WIN32)
        dos_key = build_file_name_attr('REPORT~1.TXT', FILE_NAME_DOS)
        system_key = build_file_name_attr('$MFT', FILE_NAME_WIN32)

        entries = [
            MockIndexEntry(valid_key, inode_num=100),   # valid
            MockIndexEntry(dos_key, inode_num=101),      # DOS -> skip
            MockIndexEntry(system_key, inode_num=5),     # inode <= 16 -> skip
        ]
        ir = MockIndexRoot(type_flag=FILE_NAME, entries=entries)
        inode = self._make_inode(ir)

        files = inode.walk()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]['FileName'].decode('utf-16le'), 'report.txt')
        self.assertEqual(inode._walk_root_count, 1)

    def test_no_index_root(self):
        inode = self._make_inode()
        self.assertIsNone(inode.walk())


class TestGetDataSize(unittest.TestCase):
    """getDataSize() must return DataSize, not InitializedSize."""

    def test_returns_data_size(self):
        runs = b'\x11\x04\x05\x00'
        raw = build_nonresident_attr(runs, data_size=1000, initialized_size=500)
        attr = ntfs_read.AttributeNonResident(MockINode(), raw)
        self.assertEqual(attr.getDataSize(), 1000)


if __name__ == '__main__':
    unittest.main()
