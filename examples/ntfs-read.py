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
# Description:
#   Mini shell for browsing an NTFS volume
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure. Quick and dirty implementation.. just for fun.. ;)
#
#   NOTE: Lots of info (mainly the structs) taken from the NTFS-3G project..
#
# ToDo:
#   [] Support compressed, encrypted files
#

from __future__ import division
from __future__ import print_function
import os
import sys
import logging
import struct
import argparse
import cmd
import ntpath
from six import PY2, text_type
from datetime import datetime
from impacket.examples import logger
from impacket import version
from impacket.structure import Structure, hexdump


# Reserved/fixed MFTs
FIXED_MFTS = 16

# Attribute types
UNUSED                        = 0
STANDARD_INFORMATION          = 0x10
ATTRIBUTE_LIST                = 0x20
FILE_NAME                     = 0x30
OBJECT_ID                     = 0x40
SECURITY_DESCRIPTOR           = 0x50
VOLUME_NAME                   = 0x60
VOLUME_INFORMATION            = 0x70
DATA                          = 0x80
INDEX_ROOT                    = 0x90
INDEX_ALLOCATION              = 0xa0
BITMAP                        = 0xb0
REPARSE_POINT                 = 0xc0
EA_INFORMATION                = 0xd0
EA                            = 0xe0
PROPERTY_SET                  = 0xf0
LOGGED_UTILITY_STREAM         = 0x100
FIRST_USER_DEFINED_ATTRIBUTE  = 0x1000
END                           = 0xffffffff

# Attribute flags
ATTR_IS_COMPRESSED     = 0x0001
ATTR_COMPRESSION_MASK  = 0x00ff
ATTR_IS_ENCRYPTED      = 0x4000
ATTR_IS_SPARSE         = 0x8000

# FileName type flags
FILE_NAME_POSIX = 0x00
FILE_NAME_WIN32 = 0x01
FILE_NAME_DOS   = 0x02
FILE_NAME_WIN32_AND_DOS = 0x03

# MFT Record flags
MFT_RECORD_IN_USE        = 0x0001
MFT_RECORD_IS_DIRECTORY  = 0x0002
MFT_RECORD_IS_4          = 0x0004
MFT_RECORD_IS_VIEW_INDEX = 0x0008
MFT_REC_SPACE_FILLER     = 0xfffff

# File Attribute Flags
FILE_ATTR_READONLY            = 0x0001
FILE_ATTR_HIDDEN              = 0x0002
FILE_ATTR_SYSTEM              = 0x0004
FILE_ATTR_DIRECTORY           = 0x0010
FILE_ATTR_ARCHIVE             = 0x0020
FILE_ATTR_DEVICE              = 0x0040
FILE_ATTR_NORMAL              = 0x0080
FILE_ATTR_TEMPORARY           = 0x0100
FILE_ATTR_SPARSE_FILE         = 0x0200
FILE_ATTR_REPARSE_POINT       = 0x0400
FILE_ATTR_COMPRESSED          = 0x0800
FILE_ATTR_OFFLINE             = 0x1000
FILE_ATTR_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTR_ENCRYPTED           = 0x4000
FILE_ATTR_VALID_FLAGS         = 0x7fb7
FILE_ATTR_VALID_SET_FLAGS     = 0x31a7
FILE_ATTR_I30_INDEX_PRESENT   = 0x10000000
FILE_ATTR_VIEW_INDEX_PRESENT  = 0x20000000

# NTFS System files
FILE_MFT      = 0
FILE_MFTMirr  = 1
FILE_LogFile  = 2
FILE_Volume   = 3
FILE_AttrDef  = 4
FILE_Root     = 5
FILE_Bitmap   = 6
FILE_Boot     = 7
FILE_BadClus  = 8
FILE_Secure   = 9
FILE_UpCase   = 10
FILE_Extend   = 11

# Index Header Flags
SMALL_INDEX = 0
LARGE_INDEX = 1
LEAF_NODE   = 0
INDEX_NODE  = 1
NODE_MASK   = 0

# Index Entry Flags
INDEX_ENTRY_NODE         = 1
INDEX_ENTRY_END          = 2
INDEX_ENTRY_SPACE_FILLER = 0xffff


class NTFS_BPB(Structure):
    structure = (
        ('BytesPerSector','<H=0'),
        ('SectorsPerCluster','B=0'),
        ('ReservedSectors','<H=0'),
        ('Reserved','3s=b""'),
        ('Reserved2','2s=b""'),
        ('MediaDescription','B=0'),
        ('Reserved3','2s=b""'),
        ('Reserved4','<H=0'),
        ('Reserved5','<H=0'),
        ('Reserved6','<L=0'),
        ('Reserved7','4s=b""'),
    )

class NTFS_EXTENDED_BPB(Structure):
    structure = (
        ('Reserved','4s=b""'),
        ('TotalSectors','<Q=0'),
        ('MFTClusterNumber','<Q=0'),
        ('MFTMirrClusterNumber','<Q=0'),
        ('ClusterPerFileRecord','b=0'),
        ('Reserved2','3s=b""'),
        ('ClusterPerIndexBuffer','<b=0'),
        ('Reserved3','3s=b""'),
        ('VolumeSerialNumber','8s=b""'),
        ('CheckSum','4s=b""'),
    )

class NTFS_BOOT_SECTOR(Structure):
    structure = (
        ('JmpInstr','3s=b""'),
        ('OEM_ID','8s=b""'),
        ('BPB','25s=b""'),
        ('ExtendedBPB','48s=b""'),
        ('Bootstrap','426s=b""'),
        ('EOS','<H=0'),
    )

class NTFS_MFT_RECORD(Structure):
    structure = (
        ('MagicLabel','4s=b""'),
        ('USROffset','<H=0'), # Update Sequence Records Offset
        ('USRSize','<H=0'), # Update Sequence Records Size
        ('LogSeqNum','<Q=0'),
        ('SeqNum','<H=0'),
        ('LinkCount','<H=0'),
        ('AttributesOffset','<H=0'),
        ('Flags','<H=0'),
        ('BytesInUse','<L=0'),
        ('BytesAllocated','<L=0'),
        ('BaseMftRecord','<Q=0'),
        ('NextAttrInstance','<H=0'),
        ('Reserved','<H=0'),
        ('RecordNumber','<L=0'),
    )

class NTFS_ATTRIBUTE_RECORD(Structure):
    commonHdr = (
        ('Type','<L=0'),
        ('Length','<L=0'),
        ('NonResident','B=0'),
        ('NameLength','B=0'),
        ('NameOffset','<H=0'),
        ('Flags','<H=0'),
        ('Instance','<H=0'),
    )
    structure = ()

class NTFS_ATTRIBUTE_RECORD_NON_RESIDENT(Structure):
    structure = (
        ('LowestVCN','<Q=0'),
        ('HighestVCN','<Q=0'),
        ('DataRunsOffset','<H=0'),
        ('CompressionUnit','<H=0'),
        ('Reserved1','4s=""'),
        ('AllocatedSize','<Q=0'),
        ('DataSize','<Q=0'),
        ('InitializedSize','<Q=0'),
#        ('CompressedSize','<Q=0'),
    )

class NTFS_ATTRIBUTE_RECORD_RESIDENT(Structure):
    structure = (
        ('ValueLen','<L=0'),
        ('ValueOffset','<H=0'),
        ('Flags','B=0'),
        ('Reserved','B=0'),
    )

class NTFS_FILE_NAME_ATTR(Structure):
    structure = (
        ('ParentDirectory','<Q=0'),
        ('CreationTime','<Q=0'),
        ('LastDataChangeTime','<Q=0'),
        ('LastMftChangeTime','<Q=0'),
        ('LastAccessTime','<Q=0'),
        ('AllocatedSize','<Q=0'),
        ('DataSize','<Q=0'),
        ('FileAttributes','<L=0'),
        ('EaSize','<L=0'),
        ('FileNameLen','B=0'),
        ('FileNameType','B=0'),
        ('_FileName','_-FileName','self["FileNameLen"]*2'),
        ('FileName',':'),
    )

class NTFS_STANDARD_INFORMATION(Structure):
    structure = (
        ('CreationTime','<Q=0'),
        ('LastDataChangeTime','<Q=0'),
        ('LastMftChangeTime','<Q=0'),
        ('LastAccessTime','<Q=0'),
        ('FileAttributes','<L=0'),
    )

class NTFS_INDEX_HEADER(Structure):
    structure = (
        ('EntriesOffset','<L=0'),
        ('IndexLength','<L=0'),
        ('AllocatedSize','<L=0'),
        ('Flags','B=0'),
        ('Reserved','3s=b""'),
    )

class NTFS_INDEX_ROOT(Structure):
    structure = (
        ('Type','<L=0'),
        ('CollationRule','<L=0'),
        ('IndexBlockSize','<L=0'),
        ('ClustersPerIndexBlock','B=0'),
        ('Reserved','3s=b""'),
        ('Index',':',NTFS_INDEX_HEADER),
    )


class NTFS_INDEX_ALLOCATION(Structure):
    structure = (
        ('Magic','4s=b""'),
        ('USROffset','<H=0'), # Update Sequence Records Offset
        ('USRSize','<H=0'), # Update Sequence Records Size
        ('Lsn','<Q=0'),
        ('IndexVcn','<Q=0'),
        ('Index',':',NTFS_INDEX_HEADER),
    )

class NTFS_INDEX_ENTRY_HEADER(Structure):
    structure = (
        ('IndexedFile','<Q=0'),
        ('Length','<H=0'),
        ('KeyLength','<H=0'),
        ('Flags','<H=0'),
        ('Reserved','<H=0'),
    )

class NTFS_INDEX_ENTRY(Structure):
    alignment = 8
    structure = (
        ('EntryHeader',':',NTFS_INDEX_ENTRY_HEADER),
        ('_Key','_-Key','self["EntryHeader"]["KeyLength"]'),
        ('Key',':'),
        ('_Vcn','_-Vcn','(self["EntryHeader"]["Flags"] & 1)*8'),
        ('Vcn',':')
    )

class NTFS_DATA_RUN(Structure):
    structure = (
        ('LCN','<q=0'),
        ('Clusters','<Q=0'),
        ('StartVCN','<Q=0'),
        ('LastVCN','<Q=0'),
    )

class NTFS_ATTRIBUTE_LIST_ENTRY(Structure):
    structure = (
        ('AttributeType', '<L=0'),
        ('EntryLength', '<H=0'),
        ('AttributeNameLength', 'B=0'),
        ('AttributeNameOffset', 'B=0'),
        ('StartingVCN', '<Q=0'),
        ('BaseFileRecord', '<Q=0'),
        ('AttributeID', '<H=0'),
    )

def getUnixTime(t):
    t -= 116444736000000000
    t //= 10000000
    return t


class Attribute:
    def __init__(self, iNode, data):
        self.AttributeName = None
        self.NTFSVolume = iNode.NTFSVolume
        self.AttributeHeader = NTFS_ATTRIBUTE_RECORD(data)
        if self.AttributeHeader['NameLength'] > 0 and self.AttributeHeader['Type'] != END:
            self.AttributeName = data[self.AttributeHeader['NameOffset']:][:self.AttributeHeader['NameLength']*2].decode('utf-16le')

    def getFlags(self):
        return self.AttributeHeader['Flags']

    def getName(self):
        return self.AttributeName

    def isNonResident(self):
        return self.AttributeHeader['NonResident']

    def dump(self):
        return self.AttributeHeader.dump()

    def getTotalSize(self):
        return self.AttributeHeader['Length']

    def getType(self):
        return self.AttributeHeader['Type']

class AttributeResident(Attribute):
    def __init__(self, iNode, data):
        logging.debug("Inside AttributeResident: iNode: %s" % iNode.INodeNumber)
        Attribute.__init__(self,iNode,data)
        self.ResidentHeader = NTFS_ATTRIBUTE_RECORD_RESIDENT(data[len(self.AttributeHeader):])
        self.AttrValue = data[self.ResidentHeader['ValueOffset']:][:self.ResidentHeader['ValueLen']]

    def dump(self):
        return self.ResidentHeader.dump()

    def getFlags(self):
        return self.ResidentHeader['Flags']

    def getValue(self):
        return self.AttrValue

    def read(self,offset,length):
        logging.debug("Inside Read: offset: %d, length: %d" %(offset,length))
        return self.AttrValue[offset:][:length]

    def getDataSize(self):
        return len(self.AttrValue)

class AttributeNonResident(Attribute):
    def __init__(self, iNode, data):
        logging.debug("Inside AttributeNonResident: iNode: %s" % iNode.INodeNumber)
        Attribute.__init__(self,iNode,data)
        self._raw_attr_data = data
        self.NonResidentHeader = NTFS_ATTRIBUTE_RECORD_NON_RESIDENT(data[len(self.AttributeHeader):])
        self.AttrValue = data[self.NonResidentHeader['DataRunsOffset']:][:self.NonResidentHeader['AllocatedSize']]
        self.DataRuns = []
        self.ClusterSize = 0
        # Effective sizes for OS-like reads; default to on-disk header values.
        self.data_size = self.NonResidentHeader['DataSize']
        self.initialized_size = self.NonResidentHeader['InitializedSize']
        self.parseDataRuns()

    def dump(self):
        return self.NonResidentHeader.dump()

    def getDataSize(self):
        return self.data_size

    def getValue(self):
        return None

    def parseDataRuns(self):
        """Parse data run descriptors from the attribute value."""
        data = self.AttrValue
        if data is None:
            return

        vcn = 0
        prevLcn = 0  # LCN is delta-encoded, track previous

        while data and data[0:1] != b'\x00':
            if len(data) < 1:
                break

            header = data[0]
            data = data[1:]

            lengthBytes = header & 0x0F
            offsetBytes = header >> 4

            # Parse cluster count (length)
            if len(data) < lengthBytes:
                break
            clusterCount = struct.unpack('<Q', data[:lengthBytes].ljust(8, b'\x00'))[0]
            data = data[lengthBytes:]

            dr = NTFS_DATA_RUN()
            dr['Clusters'] = clusterCount
            dr['StartVCN'] = vcn
            dr['LastVCN'] = vcn + clusterCount - 1

            if offsetBytes == 0:
                # Sparse run - no physical location
                dr['LCN'] = -1
                logging.debug("Sparse run: VCN %d-%d, clusters %d", dr['StartVCN'], dr['LastVCN'], clusterCount)
            else:
                # Parse LCN offset (signed, delta from previous)
                if len(data) < offsetBytes:
                    break
                offsetData = data[:offsetBytes]
                # Sign extend
                if offsetData[-1] & 0x80:
                    offsetData = offsetData.ljust(8, b'\xff')
                else:
                    offsetData = offsetData.ljust(8, b'\x00')
                lcnDelta = struct.unpack('<q', offsetData)[0]
                data = data[offsetBytes:]

                prevLcn += lcnDelta
                dr['LCN'] = prevLcn

            self.DataRuns.append(dr)
            vcn += clusterCount

    def readClusters(self, clusters, lcn):
        logging.debug("Inside ReadClusters: clusters:%d, lcn:%d" % (clusters,lcn))
        if lcn == -1:
            return b'\x00'*clusters*self.ClusterSize
        self.NTFSVolume.volumeFD.seek(lcn*self.ClusterSize,0)
        buf = self.NTFSVolume.volumeFD.read(clusters*self.ClusterSize)
        while len(buf) < clusters*self.ClusterSize:
            buf+= self.NTFSVolume.volumeFD.read((clusters*self.ClusterSize)-len(buf))

        if len(buf) == 0:
            return None

        return buf

    def readVCN(self, vcn, numOfClusters):
        """Read clusters starting at VCN, spanning multiple data runs if needed."""
        logging.debug("Inside ReadVCN: vcn: %d, numOfClusters: %d" % (vcn, numOfClusters))
        buf = b''
        clustersLeft = numOfClusters

        for dr in self.DataRuns:
            if clustersLeft <= 0:
                break
            # Skip data runs before our target VCN
            if vcn > dr['LastVCN']:
                continue
            # Stop if we've passed all relevant data runs
            if vcn < dr['StartVCN']:
                break

            # Calculate how many clusters to read from this data run
            clustersInRun = dr['LastVCN'] - vcn + 1
            clustersToRead = min(clustersLeft, clustersInRun)

            # For sparse runs, LCN is -1; readClusters handles this
            if dr['LCN'] == -1:
                lcn = -1
            else:
                lcn = dr['LCN'] + (vcn - dr['StartVCN'])

            tmpBuf = self.readClusters(clustersToRead, lcn)
            if tmpBuf is None:
                break
            buf += tmpBuf
            clustersLeft -= clustersToRead
            vcn += clustersToRead

        return buf

    def read(self, offset, length):
        """Read bytes from non-resident attribute, respecting data_size and initialized_size."""
        logging.debug("Inside Read: offset: %d, length: %d" % (offset, length))

        # Clamp read to data_size (EOF)
        if offset >= self.data_size:
            return b''
        length = min(length, self.data_size - offset)

        self.ClusterSize = self.NTFSVolume.BPB['BytesPerSector'] * self.NTFSVolume.BPB['SectorsPerCluster']

        buf = b''
        curOffset = offset
        bytesLeft = length

        while bytesLeft > 0:
            vcn = curOffset // self.ClusterSize
            vcnOffset = curOffset % self.ClusterSize

            # Calculate clusters needed for remaining bytes
            bytesInFirstCluster = self.ClusterSize - vcnOffset
            if bytesLeft <= bytesInFirstCluster:
                clustersToRead = 1
            else:
                clustersToRead = 1 + ((bytesLeft - bytesInFirstCluster + self.ClusterSize - 1) // self.ClusterSize)

            clusterData = self.readVCN(vcn, clustersToRead)
            if not clusterData:
                break

            # Extract the portion we need
            chunk = clusterData[vcnOffset:vcnOffset + bytesLeft]
            buf += chunk
            curOffset += len(chunk)
            bytesLeft -= len(chunk)

            if len(chunk) == 0:
                break

        if not buf:
            return None

        # Zero-fill beyond InitializedSize (OS behavior for uninitialized data)
        if self.initialized_size < offset + len(buf):
            validBytes = max(0, self.initialized_size - offset)
            buf = buf[:validBytes] + (b'\x00' * (len(buf) - validBytes))

        return buf

class NonResidentDataAttribute(AttributeNonResident):
    @classmethod
    def _shift_runs(cls, attr, start_vcn):
        if start_vcn <= 0:
            return
        for dr in attr.DataRuns:
            dr['StartVCN'] += start_vcn
            dr['LastVCN'] += start_vcn

    @classmethod
    def _base_sizes(cls, attr):
        return attr.NonResidentHeader['DataSize'], attr.NonResidentHeader['InitializedSize']

    @classmethod
    def _ensure_base(cls, collected, base_attr, base_data_size, base_initialized_size):
        if base_attr is not None:
            return base_attr, base_data_size, base_initialized_size
        _, base_attr = collected[0]
        base_data_size, base_initialized_size = cls._base_sizes(base_attr)
        return base_attr, base_data_size, base_initialized_size

    @classmethod
    def _collect_extents(cls, iNode, matches, attribute_name):
        """Collect $DATA attributes from extent records, identifying the base extent."""
        collected = []
        base_attr = None
        base_data_size = None
        base_initialized_size = None

        for entry in matches:
            extension_inode = iNode.NTFSVolume.getINode(entry.MftRecordNumber)
            attr = extension_inode.searchAttribute(DATA, attribute_name)
            if attr is None:
                continue
            collected.append((entry, attr))
            # Base extent has StartingVCN == 0 and contains authoritative sizes
            if entry.StartingVCN == 0:
                base_attr = attr
                if isinstance(attr, AttributeNonResident):
                    base_data_size, base_initialized_size = cls._base_sizes(attr)

        return collected, base_attr, base_data_size, base_initialized_size

    def __init__(self, iNode, entries, attribute_name=None):
        """
        Build a unified $DATA stream from multiple attribute list entries.

        Args:
            iNode: Owning inode for volume access
            entries: AttributeListEntry items for the target $DATA stream
            attribute_name: Stream name (None for default $DATA)
        """
        matches = list(entries)
        if not matches:
            raise ValueError('No $DATA extents found')

        # Sort extents by StartingVCN to define logical order
        matches.sort(key=lambda e: e.StartingVCN)

        # Collect attributes and find base extent (StartingVCN == 0)
        collected, base_attr, base_data_size, base_initialized_size = self._collect_extents(
            iNode, matches, attribute_name,
        )

        if not collected:
            raise ValueError('No usable $DATA extents found')

        # Ensure we have valid base sizes
        base_attr, base_data_size, base_initialized_size = self._ensure_base(
            collected, base_attr, base_data_size, base_initialized_size,
        )

        # Initialize from base extent
        super(NonResidentDataAttribute, self).__init__(iNode, base_attr._raw_attr_data)

        if len(collected) == 1:
            # Single extent - apply VCN offset if needed
            entry, _ = collected[0]
            self._shift_runs(self, entry.StartingVCN)
        else:
            # Multi-extent - merge all runs with proper VCN offsets
            self._merge_extents_from_collected(collected, base_data_size, base_initialized_size)

    def _merge_extents_from_collected(self, collected, data_size, init_size):
        """Merge data runs from multiple extents into unified stream."""
        merged_runs = []
        for entry, attr in collected:
            if not isinstance(attr, AttributeNonResident):
                continue
            for dr in attr.DataRuns:
                new_dr = NTFS_DATA_RUN()
                new_dr['LCN'] = dr['LCN']
                new_dr['Clusters'] = dr['Clusters']
                # Apply VCN offset from attribute list entry
                new_dr['StartVCN'] = dr['StartVCN'] + entry.StartingVCN
                new_dr['LastVCN'] = dr['LastVCN'] + entry.StartingVCN
                merged_runs.append(new_dr)

        merged_runs.sort(key=lambda dr: dr['StartVCN'])
        self.DataRuns = merged_runs
        self.data_size = data_size
        self.initialized_size = init_size


class AttributeStandardInfo:
    def __init__(self, attribute):
        logging.debug("Inside AttributeStandardInfo")
        self.Attribute = attribute
        self.StandardInfo = NTFS_STANDARD_INFORMATION(self.Attribute.AttrValue)

    def getFileAttributes(self):
        return self.StandardInfo['FileAttributes']

    def getFileTime(self):
        if self.StandardInfo['LastDataChangeTime'] > 0:
            return datetime.fromtimestamp(getUnixTime(self.StandardInfo['LastDataChangeTime']))
        else:
            return 0

    def dump(self):
        return self.StandardInfo.dump()

class AttributeFileName:
    def __init__(self, attribute):
        logging.debug("Inside AttributeFileName")
        self.Attribute = attribute
        self.FileNameRecord = NTFS_FILE_NAME_ATTR(self.Attribute.AttrValue)

    def getFileNameType(self):
        return self.FileNameRecord['FileNameType']

    def getFileAttributes(self):
        return self.FileNameRecord['FileAttributes']

    def getFileName(self):
        return self.FileNameRecord['FileName'].decode('utf-16le')

    def getFileSize(self):
        return self.FileNameRecord['DataSize']

    def getFlags(self):
        return self.FileNameRecord['FileAttributes']

    def dump(self):
        return self.FileNameRecord.dump()

class AttributeIndexAllocation:
    def __init__(self, attribute):
        logging.debug("Inside AttributeIndexAllocation")
        self.Attribute = attribute

    def dump(self):
        print(self.Attribute.dump())
        for i in self.Attribute.DataRuns:
            print(i.dump())

    def read(self, offset, length):
        return self.Attribute.read(offset, length)


class AttributeIndexRoot:
    def __init__(self, attribute):
        logging.debug("Inside AttributeIndexRoot")
        self.Attribute = attribute
        self.IndexRootRecord = NTFS_INDEX_ROOT(attribute.AttrValue)
        self.IndexEntries = []
        self.parseIndexEntries()

    def parseIndexEntries(self):
        data = self.Attribute.AttrValue[len(self.IndexRootRecord):]
        while True:
            ie = IndexEntry(data)
            self.IndexEntries.append(ie)
            if ie.isLastNode():
                break
            data = data[ie.getSize():]

    def dump(self):
        self.IndexRootRecord.dump()
        for i in self.IndexEntries:
            i.dump()

    def getType(self):
        return self.IndexRootRecord['Type']

class IndexEntry:
    def __init__(self, entry):
        self.entry = NTFS_INDEX_ENTRY(entry)

    def isSubNode(self):
        return self.entry['EntryHeader']['Flags'] & INDEX_ENTRY_NODE

    def isLastNode(self):
        return self.entry['EntryHeader']['Flags'] & INDEX_ENTRY_END

    def getVCN(self):
        return struct.unpack('<Q', self.entry['Vcn'])[0]

    def getSize(self):
        return len(self.entry)

    def getKey(self):
        return self.entry['Key']

    def getINodeNumber(self):
        return self.entry['EntryHeader']['IndexedFile'] & 0x0000FFFFFFFFFFFF

    def dump(self):
        self.entry.dump()

class AttributeListEntry:
    def __init__(self, entry_data):
        self.EntryHeader = NTFS_ATTRIBUTE_LIST_ENTRY(entry_data)
        self.AttributeType = self.EntryHeader['AttributeType']
        self.EntryLength = self.EntryHeader['EntryLength']
        self.StartingVCN = self.EntryHeader['StartingVCN']
        self.AttributeID = self.EntryHeader['AttributeID']
        raw_record = self.EntryHeader['BaseFileRecord']
        self.MftRecordNumber = raw_record & 0x0000FFFFFFFFFFFF
        self.MftSequenceNumber = (raw_record >> 48) & 0xFFFF
        self.AttributeName = None
        name_len = self.EntryHeader['AttributeNameLength']
        if name_len > 0:
            name_offset = self.EntryHeader['AttributeNameOffset']
            name_bytes = entry_data[name_offset : name_offset + (name_len * 2)]
            self.AttributeName = name_bytes.decode('utf-16le')

class AttributeList:
    """Parses ATTRIBUTE_LIST attribute (can be resident or non-resident)."""

    def __init__(self, attribute):
        self.attribute = attribute
        self.Entries = []
        self._parseEntries()

    def _parseEntries(self):
        """Parse attribute list entries from raw data."""
        # getValue() works for resident, read() for non-resident
        if hasattr(self.attribute, 'getValue') and self.attribute.getValue() is not None:
            data = self.attribute.getValue()
        else:
            data = self.attribute.read(0, self.attribute.getDataSize())

        if not data:
            return

        offset = 0
        while offset < len(data):
            entry_data = data[offset:]
            if len(entry_data) < 26:  # Minimum entry size
                break
            list_entry = AttributeListEntry(entry_data)
            if list_entry.EntryLength == 0:
                break
            self.Entries.append(list_entry)
            offset += list_entry.EntryLength

    def getEntries(self):
        return self.Entries

class INODE:
    def __init__(self, NTFSVolume):
        self.NTFSVolume = NTFSVolume
        # This is the entire file record
        self.INodeNumber = None
        self.Attributes = {}
        self.AttributesRaw = None
        self.AttributesLastPos = None
        # Some interesting Attributes to parse
        self.FileAttributes = 0
        self.LastDataChangeTime = None
        self.FileName = None
        self.FileSize = 0
        # Debug counters for directory listings
        self._walk_root_count = 0
        self._walk_subnode_count = 0

    def isDirectory(self):
        return self.FileAttributes & FILE_ATTR_I30_INDEX_PRESENT

    def isCompressed(self):
        return self.FileAttributes & FILE_ATTR_COMPRESSED

    def isEncrypted(self):
        return self.FileAttributes & FILE_ATTR_ENCRYPTED

    def isSparse(self):
        return self.FileAttributes & FILE_ATTR_SPARSE_FILE

    def displayName(self):
        if self.LastDataChangeTime is not None and self.FileName is not None:
            try:
#                print "%d - %s %s %s " %( self.INodeNumber, self.getPrintableAttributes(), self.LastDataChangeTime.isoformat(' '), self.FileName)
                print("%s %s %15d %s " %( self.getPrintableAttributes(), self.LastDataChangeTime.isoformat(' '), self.FileSize, self.FileName))
            except Exception as e:
                logging.error('Exception when trying to display inode %d: %s' % (self.INodeNumber,str(e)))

    def getPrintableAttributes(self):
        mask = ''
        if self.FileAttributes & FILE_ATTR_I30_INDEX_PRESENT:
            mask += 'd'
        else:
            mask += '-'
        if self.FileAttributes & FILE_ATTR_HIDDEN:
            mask += 'h'
        else:
            mask += '-'
        if self.FileAttributes & FILE_ATTR_SYSTEM:
            mask += 'S'
        else:
            mask += '-'
        if self.isCompressed():
            mask += 'C'
        else:
            mask += '-'
        if self.isEncrypted():
            mask += 'E'
        else:
            mask += '-'
        if self.isSparse():
            mask += 's'
        else:
            mask += '-'
        return mask

    def parseAttributes(self):
        # Parse Standard Info
        attr = self.searchAttribute(STANDARD_INFORMATION, None)
        if attr is not None:
            si = AttributeStandardInfo(attr)
            self.Attributes[STANDARD_INFORMATION] = si
            self.FileAttributes |= si.getFileAttributes()
            self.LastDataChangeTime = si.getFileTime()
            self.Attributes[STANDARD_INFORMATION] = si

        # Parse Filename
        attr = self.searchAttribute(FILE_NAME, None)
        while attr is not None:
            fn = AttributeFileName(attr)
            if fn.getFileNameType() != FILE_NAME_DOS:
                self.FileName = fn.getFileName()
                self.FileSize = fn.getFileSize()
                self.FileAttributes |= fn.getFileAttributes()
                self.Attributes[FILE_NAME] = fn
                break
            attr = self.searchAttribute(FILE_NAME, None, True)

        # Parse Attribute list before Index Allocation, because it might be there
        attr = self.searchAttribute(ATTRIBUTE_LIST, None)
        if attr is not None:
            al = AttributeList(attr)
            self.Attributes[ATTRIBUTE_LIST] = al

        # Parse Index Allocation
        attr = self.searchAttribute(INDEX_ALLOCATION, u'$I30')
        if attr is not None:
            ia = AttributeIndexAllocation(attr)
            self.Attributes[INDEX_ALLOCATION] = ia

        attr = self.searchAttribute(INDEX_ROOT, u'$I30')
        if attr is not None:
            ir = AttributeIndexRoot(attr)
            self.Attributes[INDEX_ROOT] = ir

    def searchAttribute(self, attributeType, attributeName, findNext = False):
        logging.debug("Inside searchAttribute: type: 0x%x, name: %s" % (attributeType, attributeName))
        record = None

        if findNext is True:
            data = self.AttributesLastPos
        else:
            data = self.AttributesRaw

        while True:

            if len(data) <= 8:
                record = None
                break

            record = Attribute(self,data)

            if record.getType() == END:
                record = None
                break

            if record.getTotalSize() == 0:
                record = None
                break

            if record.getType() == attributeType and record.getName() == attributeName:
                if record.isNonResident() == 1:
                    record = AttributeNonResident(self, data)
                else:
                    record = AttributeResident(self, data)

                self.AttributesLastPos = data[record.getTotalSize():]

                break

            data = data[record.getTotalSize():]

        # Look for attribute on Attribute List
        if record is None and ATTRIBUTE_LIST in self.Attributes:
            attr_list = self.Attributes[ATTRIBUTE_LIST]

            if attributeType == DATA:
                entries = [
                    entry for entry in attr_list.getEntries()
                    if entry.AttributeType == DATA and entry.AttributeName == attributeName
                ]
                try:
                    return NonResidentDataAttribute(self, entries, attributeName)
                except ValueError:
                    return None

            for entry in attr_list.getEntries():
                if entry.AttributeType == attributeType and entry.AttributeName == attributeName:
                    extension_inode = self.NTFSVolume.getINode(entry.MftRecordNumber)
                    return extension_inode.searchAttribute(attributeType, attributeName)

        return record

    def PerformFixUp(self, record, buf, numSectors):
        # It fixes the sequence WORDS on every sector of a cluster
        # FixUps are used by:
        # FILE Records in the $MFT
        # INDX Records in directories and other indexes
        # RCRD Records in the $LogFile
        # RSTR Records in the $LogFile

        logging.debug("Inside PerformFixUp..." )
        magicNum = struct.unpack('<H',buf[record['USROffset']:][:2])[0]
        sequenceArray = buf[record['USROffset']+2:][:record['USRSize']*2]

        dataList = list(buf)
        index = 0
        for i in range(0,numSectors*2, 2):
            index += self.NTFSVolume.SectorSize-2
            # Let's get the last two bytes of the sector
            lastBytes = struct.unpack('<H', buf[index:][:2])[0]
            # Is it the same as the magicNum?
            if lastBytes != magicNum:
                logging.error("Magic number 0x%x doesn't match with 0x%x" % (magicNum,lastBytes))
                return None
            # Now let's replace the original bytes
            dataList[index]   = sequenceArray[i]
            dataList[index+1] = sequenceArray[i+1]
            index += 2

        if PY2:
            return "".join(dataList)
        else:
            return bytes(dataList)

    def parseIndexBlocks(self, vcn):
        IndexEntries = []
        #sectors = self.NTFSVolume.IndexBlockSize / self.NTFSVolume.SectorSize
        if INDEX_ALLOCATION in self.Attributes:
            ia = self.Attributes[INDEX_ALLOCATION]
            data = ia.read(vcn*self.NTFSVolume.IndexBlockSize, self.NTFSVolume.IndexBlockSize)
            if data:
                iaRec = NTFS_INDEX_ALLOCATION(data)
                sectorsPerIB = self.NTFSVolume.IndexBlockSize // self.NTFSVolume.SectorSize
                data = self.PerformFixUp(iaRec, data, sectorsPerIB)
                if data is None:
                    return []
                data = data[len(iaRec)-len(NTFS_INDEX_HEADER())+iaRec['Index']['EntriesOffset']:]
                while True:
                    ie = IndexEntry(data)
                    IndexEntries.append(ie)
                    if ie.isLastNode():
                        break
                    data = data[ie.getSize():]
        return IndexEntries

    def walkSubNodes(self, vcn):
        logging.debug("Inside walkSubNodes: vcn %s" % vcn)
        entries = self.parseIndexBlocks(vcn)
        files = []
        for entry in entries:
            if entry.isSubNode():
                files += self.walkSubNodes(entry.getVCN())
            else:
                if len(entry.getKey()) > 0 and entry.getINodeNumber() > 16:
                    fn = NTFS_FILE_NAME_ATTR(entry.getKey())
                    if fn['FileNameType'] != FILE_NAME_DOS:
                        #inode = INODE(self.NTFSVolume)
                        #inode.FileAttributes = fn['FileAttributes']
                        #inode.FileSize = fn['DataSize']
                        #inode.LastDataChangeTime = datetime.fromtimestamp(getUnixTime(fn['LastDataChangeTime']))
                        #inode.INodeNumber = entry.getINodeNumber()
                        #inode.FileName = fn['FileName'].decode('utf-16le')
                        #inode.displayName()
                        files.append(fn)
#                    if inode.FileAttributes & FILE_ATTR_I30_INDEX_PRESENT and entry.getINodeNumber() > 16:
#                        inode2 = self.NTFSVolume.getINode(entry.getINodeNumber())
#                        inode2.walk()
        return files

    def walk(self):
        logging.debug("Inside Walk... ")
        files = []
        self._walk_root_count = 0
        self._walk_subnode_count = 0
        if INDEX_ROOT in self.Attributes:
            ir = self.Attributes[INDEX_ROOT]

            if ir.getType() & FILE_NAME:
                for ie in ir.IndexEntries:
                    if ie.isSubNode():
                        logging.debug("walk: INDEX_ROOT entry points to subnode VCN %d", ie.getVCN())
                        sub_files = self.walkSubNodes(ie.getVCN())
                        self._walk_subnode_count += len(sub_files)
                        files += sub_files
                    else:
                        if len(ie.getKey()) > 0 and ie.getINodeNumber() > 16:
                            fn = NTFS_FILE_NAME_ATTR(ie.getKey())
                            if fn['FileNameType'] != FILE_NAME_DOS:
                                logging.debug("walk: INDEX_ROOT inline entry %s", fn['FileName'].decode('utf-16le'))
                                self._walk_root_count += 1
                                files.append(fn)
                return files
        else:
            return None

    def findFirstSubNode(self, vcn, toSearch):
        def getFileName(entry):
            if len(entry.getKey()) > 0 and entry.getINodeNumber() > 16:
                fn = NTFS_FILE_NAME_ATTR(entry.getKey())
                if fn['FileNameType'] != FILE_NAME_DOS:
                    return fn['FileName'].decode('utf-16le').upper()
            return None

        entries = self.parseIndexBlocks(vcn)
        for ie in entries:
            name = getFileName(ie)
            if name is not None:
                if name == toSearch:
                    # Found!
                    return ie
                if toSearch < name:
                    if ie.isSubNode():
                        res = self.findFirstSubNode(ie.getVCN(), toSearch)
                        if res is not None:
                            return res
                    else:
                        # Bye bye.. not found
                        return None
            else:
                if ie.isSubNode():
                        res = self.findFirstSubNode(ie.getVCN(), toSearch)
                        if res is not None:
                            return res


    def findFirst(self, fileName):
        # Searches for a file and returns an Index Entry. None if not found

        def getFileName(entry):
            if len(entry.getKey()) > 0 and entry.getINodeNumber() > 16:
                fn = NTFS_FILE_NAME_ATTR(entry.getKey())
                if fn['FileNameType'] != FILE_NAME_DOS:
                    return fn['FileName'].decode('utf-16le').upper()
            return None

        toSearch = text_type(fileName.upper())

        if INDEX_ROOT in self.Attributes:
            ir = self.Attributes[INDEX_ROOT]
            if ir.getType() & FILE_NAME or 1==1:
                for ie in ir.IndexEntries:
                    name = getFileName(ie)
                    if name is not None:
                        if name == toSearch:
                            # Found!
                            return ie
                        if toSearch < name:
                            if ie.isSubNode():
                                res = self.findFirstSubNode(ie.getVCN(), toSearch)
                                if res is not None:
                                    return res
                            else:
                                # Bye bye.. not found
                                return None
                    else:
                        if ie.isSubNode():
                                res = self.findFirstSubNode(ie.getVCN(), toSearch)
                                if res is not None:
                                    return res

    def getStream(self, name):
        return self.searchAttribute( DATA, name, findNext = False)


class NTFS:
    def __init__(self, volumeName):
        self.__volumeName = volumeName
        self.__bootSector = None
        self.__MFTStart = None
        self.volumeFD = None
        self.BPB = None
        self.ExtendedBPB = None
        self.RecordSize = None
        self.IndexBlockSize = None
        self.SectorSize = None
        self.MFTINode = None
        self.mountVolume()

    def mountVolume(self):
        logging.debug("Mounting volume...")
        self.volumeFD = open(self.__volumeName,"rb")
        self.readBootSector()
        self.MFTINode = self.getINode(FILE_MFT)
        # Check whether MFT is fragmented
        attr = self.MFTINode.searchAttribute(DATA, None)
        if attr is None:
            # It's not
            del self.MFTINode
            self.MFTINode = None

    def readBootSector(self):
        logging.debug("Reading Boot Sector for %s" % self.__volumeName)

        self.volumeFD.seek(0,0)
        data = self.volumeFD.read(512)
        while len(data) < 512:
            data += self.volumeFD.read(512)

        self.__bootSector = NTFS_BOOT_SECTOR(data)
        self.BPB = NTFS_BPB(self.__bootSector['BPB'])
        self.ExtendedBPB = NTFS_EXTENDED_BPB(self.__bootSector['ExtendedBPB'])
        self.SectorSize = self.BPB['BytesPerSector']
        self.__MFTStart = self.BPB['BytesPerSector'] * self.BPB['SectorsPerCluster'] * self.ExtendedBPB['MFTClusterNumber']
        if self.ExtendedBPB['ClusterPerFileRecord'] > 0:
            self.RecordSize = self.BPB['BytesPerSector'] * self.BPB['SectorsPerCluster'] * self.ExtendedBPB['ClusterPerFileRecord']
        else:
            self.RecordSize = 1 << (-self.ExtendedBPB['ClusterPerFileRecord'])
        if self.ExtendedBPB['ClusterPerIndexBuffer'] > 0:
            self.IndexBlockSize = self.BPB['BytesPerSector'] * self.BPB['SectorsPerCluster'] * self.ExtendedBPB['ClusterPerIndexBuffer']
        else:
            self.IndexBlockSize = 1 << (-self.ExtendedBPB['ClusterPerIndexBuffer'])

        logging.debug("MFT should start at position %d" % self.__MFTStart)

    def getINode(self, iNodeNum):
        logging.debug("Trying to fetch inode %d" % iNodeNum)

        newINode = INODE(self)
        recordLen = self.RecordSize

        # Read MFT record from disk or through fragmented $MFT
        if self.MFTINode and iNodeNum > FIXED_MFTS:
            # Fragmented $MFT - read through MFT's $DATA attribute
            attr = self.MFTINode.searchAttribute(DATA, None)
            if attr is None:
                logging.error("Cannot find MFT $DATA attribute for inode %d" % iNodeNum)
                return newINode
            record = attr.read(iNodeNum * self.RecordSize, self.RecordSize)
        else:
            diskPosition = self.__MFTStart + iNodeNum * self.RecordSize
            self.volumeFD.seek(diskPosition, 0)
            record = self.volumeFD.read(recordLen)
            while len(record) < recordLen:
                record += self.volumeFD.read(recordLen - len(record))

        if not record or len(record) < recordLen:
            logging.error("Failed to read MFT record for inode %d" % iNodeNum)
            return newINode

        mftRecord = NTFS_MFT_RECORD(record)

        record = newINode.PerformFixUp(mftRecord, record, self.RecordSize // self.SectorSize)
        if record is None:
            logging.error("FixUp failed for inode %d" % iNodeNum)
            return newINode

        newINode.INodeNumber = iNodeNum
        newINode.AttributesRaw = record[mftRecord['AttributesOffset'] - recordLen:]
        newINode.parseAttributes()

        return newINode

class MiniShell(cmd.Cmd):
    def __init__(self, volume):
        cmd.Cmd.__init__(self)
        self.volumePath = volume
        self.volume = NTFS(volume)
        self.rootINode = self.volume.getINode(FILE_Root)
        self.prompt = '\\>'
        self.intro = 'Type help for list of commands'
        self.currentINode = self.rootINode
        self.completion = []
        self.pwd = '\\'
        self.do_ls('',False)
        self.last_output = ''

    def emptyline(self):
        pass

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception as e:
            logging.debug('Exception:', exc_info=True)
            logging.error(str(e))

        return retVal

    def do_exit(self,line):
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print(output)
        self.last_output = output

    def do_help(self,line):
        print("""
 cd {path} - changes the current directory to {path}
 pwd - shows current remote directory
 ls  - lists all the files in the current directory
 lcd - change local directory
 get {filename} - downloads the filename from the current path
 cat {filename} - prints the contents of filename
 hexdump {filename} - hexdumps the contents of filename
 exit - terminates the server process (and this session)

""")

    def do_lcd(self,line):
        if line == '':
            print(os.getcwd())
        else:
            os.chdir(line)
            print(os.getcwd())

    def do_cd(self, line):
        p = line.replace('/','\\')
        oldpwd = self.pwd
        newPath = ntpath.normpath(ntpath.join(self.pwd,p))
        if newPath == self.pwd:
            # Nothing changed
            return
        common = ntpath.commonprefix([newPath,oldpwd])

        if common == oldpwd:
            res = self.findPathName(ntpath.normpath(p))
        else:
            res = self.findPathName(newPath)

        if res is None:
            logging.error("Directory not found")
            self.pwd = oldpwd
            return
        if res.isDirectory() == 0:
            logging.error("Not a directory!")
            self.pwd = oldpwd
            return
        else:
            self.currentINode = res
            self.do_ls('', False)
            self.pwd = ntpath.join(self.pwd,p)
            self.pwd = ntpath.normpath(self.pwd)
            self.prompt = self.pwd + '>'

    def findPathName(self, pathName):
        if pathName == '\\':
            return self.rootINode
        tmpINode = self.currentINode
        parts = pathName.split('\\')
        for part in parts:
            if part == '':
                tmpINode = self.rootINode
            else:
                res = tmpINode.findFirst(part)
                if res is None:
                    return res
                else:
                    tmpINode = self.volume.getINode(res.getINodeNumber())

        return tmpINode

    def do_pwd(self,line):
        print(self.pwd)

    def do_ls(self, line, display=True):
        entries = self.currentINode.walk()
        if entries is None:
            entries = []
        logging.debug(
            "ls summary for %s: total=%d index_root=%d index_allocation=%d",
            self.pwd,
            len(entries),
            self.currentINode._walk_root_count,
            self.currentINode._walk_subnode_count,
        )
        self.completion = []
        for entry in entries:
            inode = INODE(self.volume)
            inode.FileAttributes = entry['FileAttributes']
            inode.FileSize = entry['DataSize']
            inode.LastDataChangeTime = datetime.fromtimestamp(getUnixTime(entry['LastDataChangeTime']))
            inode.FileName = entry['FileName'].decode('utf-16le')
            if display is True:
                inode.displayName()
            self.completion.append((inode.FileName,inode.isDirectory()))

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def complete_cat(self,text,line,begidx,endidx):
        return self.complete_get(text, line, begidx, endidx)

    def complete_hexdump(self,text,line,begidx,endidx):
        return self.complete_get(text, line, begidx, endidx)

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        items = []
        if include == 1:
            mask = 0
        else:
            mask = FILE_ATTR_I30_INDEX_PRESENT
        for i in self.completion:
            if i[1] == mask:
                items.append(i[0])
        if text:
            return  [
                item for item in items
                if item.upper().startswith(text.upper())
            ]
        else:
            return items

    def do_hexdump(self,line):
        return self.do_cat(line,command = hexdump)

    def do_cat(self, line, command=None):
        if command is None:
            command = getattr(sys.stdout, 'buffer', sys.stdout).write
        pathName = line.replace('/', '\\')
        pathName = ntpath.normpath(ntpath.join(self.pwd, pathName))
        res = self.findPathName(pathName)
        if res is None:
            logging.error("Not found!")
            return
        if res.isDirectory() > 0:
            logging.error("It's a directory!")
            return
        if res.isCompressed() or res.isEncrypted():
            logging.error('Cannot handle compressed/encrypted files! :(')
            return

        stream = res.getStream(None)
        if stream is None:
            logging.error("Cannot read file stream!")
            return

        dataSize = stream.getDataSize()
        if dataSize == 0:
            logging.info("0 bytes read (empty file)")
            return

        chunkSize = 4096 * 10
        offset = 0
        while offset < dataSize:
            toRead = min(chunkSize, dataSize - offset)
            buf = stream.read(offset, toRead)
            if not buf:
                break
            try:
                command(buf)
            except (BrokenPipeError, OSError):
                return
            offset += len(buf)

        logging.info("%d bytes read" % offset)

    def do_get(self, line):
        pathName = line.replace('/','\\')
        pathName = ntpath.normpath(ntpath.join(self.pwd,pathName))
        fh = open(ntpath.basename(pathName),"wb")
        self.do_cat(line, command = fh.write)
        fh.close()

def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "NTFS explorer (read-only)")
    parser.add_argument('volume', action='store', help='NTFS volume to open (e.g. \\\\.\\C: or /dev/disk1s1)')
    parser.add_argument('-extract', action='store', help='extracts pathname (e.g. \\windows\\system32\\config\\sam)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()
    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    shell = MiniShell(options.volume)
    if options.extract is not None:
        shell.onecmd("get %s"% options.extract)
    else:
        shell.cmdloop()

if __name__ == '__main__':
    main()
    sys.exit(1)
