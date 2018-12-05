#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Mini shell for browsing an NTFS volume
#
# Author:
#  Alberto Solino (@agsolino)
#
#
# Reference for:
#  Structure. Quick and dirty implementation.. just for fun.. ;)
#
# NOTE: Lots of info (mainly the structs) taken from the NTFS-3G project..
#
# TODO
# [] Parse the attributes list attribute. It is unknown what would happen now if
# we face a highly fragmented file that will have many attributes that won't fit
# in the MFT Record
# [] Support compressed, encrypted and sparse files
#

import os
import sys
import logging
import struct
import argparse
import cmd
import ntpath
# If you wanna have readline like functionality in Windows, install pyreadline
try:
  import pyreadline as readline
except ImportError:
  import readline
from datetime import datetime
from impacket.examples import logger
from impacket import version
from impacket.structure import Structure


import string
def pretty_print(x):
    if x in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
       return x
    else:
       return '.'

def hexdump(data):
    x=str(data)
    strLen = len(x)
    i = 0
    while i < strLen:
        print "%04x  " % i,
        for j in range(16):
            if i+j < strLen:
                print "%02X" % ord(x[i+j]),
            else:
                print "  ",
            if j%16 == 7:
                print "",
        print " ",
        print ''.join(pretty_print(x) for x in x[i:i+16] )
        i += 16

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
        ('Reserved','3s=""'),
        ('Reserved2','2s=""'),
        ('MediaDescription','B=0'),
        ('Reserved3','2s=""'),
        ('Reserved4','<H=0'),
        ('Reserved5','<H=0'),
        ('Reserved6','<L=0'),
        ('Reserved7','4s=""'),
    )

class NTFS_EXTENDED_BPB(Structure):
    structure = (
        ('Reserved','4s=""'),
        ('TotalSectors','<Q=0'),
        ('MFTClusterNumber','<Q=0'),
        ('MFTMirrClusterNumber','<Q=0'),
        ('ClusterPerFileRecord','b=0'),
        ('Reserved2','3s=""'),
        ('ClusterPerIndexBuffer','<b=0'),
        ('Reserved3','3s=""'),
        ('VolumeSerialNumber','8s=""'),
        ('CheckSum','4s=""'),
    )

class NTFS_BOOT_SECTOR(Structure):
    structure = (
        ('JmpInstr','3s=""'),
        ('OEM_ID','8s=""'),
        ('BPB','25s=""'),
        ('ExtendedBPB','48s=""'),
        ('Bootstrap','426s=""'),
        ('EOS','<H=0'),
    )

class NTFS_MFT_RECORD(Structure):
    structure = (
        ('MagicLabel','4s=""'),
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
        ('Reserved','3s=""'),
    )

class NTFS_INDEX_ROOT(Structure):
    structure = (
        ('Type','<L=0'),
        ('CollationRule','<L=0'),
        ('IndexBlockSize','<L=0'),
        ('ClustersPerIndexBlock','B=0'),
        ('Reserved','3s=""'),
        ('Index',':',NTFS_INDEX_HEADER),
    )


class NTFS_INDEX_ALLOCATION(Structure):
    structure = (
        ('Magic','4s=""'),
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

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
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
        self.NonResidentHeader = NTFS_ATTRIBUTE_RECORD_NON_RESIDENT(data[len(self.AttributeHeader):])
        self.AttrValue = data[self.NonResidentHeader['DataRunsOffset']:][:self.NonResidentHeader['AllocatedSize']]
        self.DataRuns = []
        self.ClusterSize = 0
        self.parseDataRuns()

    def dump(self):
        return self.NonResidentHeader.dump()

    def getDataSize(self):
        return self.NonResidentHeader['InitializedSize']

    def getValue(self):
        return None

    def parseDataRuns(self):
        value = self.AttrValue
        if value is not None:
            VCN = 0
            LCN = 0
            LCNOffset = 0
            while value[0] != '\x00':
                LCN += LCNOffset
                dr = NTFS_DATA_RUN()

                size = struct.unpack('B',(value[0]))[0]

                value = value[1:]

                lengthBytes = size & 0x0F
                offsetBytes = size >> 4

                length = value[:lengthBytes]
                length = struct.unpack('<Q', value[:lengthBytes]+'\x00'*(8-len(length)))[0]
                value = value[lengthBytes:]

                fillWith = '\x00'
                if struct.unpack('B',value[offsetBytes-1])[0] & 0x80:
                    fillWith = '\xff'
                LCNOffset = value[:offsetBytes]+fillWith*(8-len(value[:offsetBytes]))
                LCNOffset = struct.unpack('<q',LCNOffset)[0]

                value = value[offsetBytes:]

                dr['LCN'] = LCN+LCNOffset
                dr['Clusters'] = length
                dr['StartVCN'] = VCN
                dr['LastVCN'] = VCN + length -1

                VCN += length
                self.DataRuns.append(dr)

                if len(value) == 0:
                    break

    def readClusters(self, clusters, lcn):
        logging.debug("Inside ReadClusters: clusters:%d, lcn:%d" % (clusters,lcn))
        if lcn == -1:
            return '\x00'*clusters*self.ClusterSize
        self.NTFSVolume.volumeFD.seek(lcn*self.ClusterSize,0)
        buf = self.NTFSVolume.volumeFD.read(clusters*self.ClusterSize)
        while len(buf) < clusters*self.ClusterSize:
            buf+= self.NTFSVolume.volumeFD.read((clusters*self.ClusterSize)-len(buf))

        if len(buf) == 0:
            return None

        return buf

    def readVCN(self, vcn, numOfClusters):
        logging.debug("Inside ReadVCN: vcn: %d, numOfClusters: %d" % (vcn,numOfClusters))
        buf = ''
        clustersLeft = numOfClusters
        for dr in self.DataRuns:
            if (vcn >= dr['StartVCN']) and (vcn <= dr['LastVCN']):

                vcnsToRead = dr['LastVCN'] - vcn + 1

                # Are we requesting to read more data outside this DataRun?
                if numOfClusters > vcnsToRead:
                    # Yes
                    clustersToRead = vcnsToRead
                else:
                    clustersToRead = numOfClusters

                tmpBuf = self.readClusters(clustersToRead,dr['LCN']+(vcn-dr['StartVCN']))
                if tmpBuf is not None:
                    buf += tmpBuf
                    clustersLeft -= clustersToRead
                    vcn += clustersToRead
                else:
                    break
                if clustersLeft == 0:
                    break
        return buf

    def read(self,offset,length):
        logging.debug("Inside Read: offset: %d, length: %d" %(offset,length))

        buf = ''
        curLength = length
        self.ClusterSize = self.NTFSVolume.BPB['BytesPerSector']*self.NTFSVolume.BPB['SectorsPerCluster']

        # Given the offset, let's calculate what VCN should be the first one to read
        vcnToStart = offset / self.ClusterSize
        #vcnOffset  = self.ClusterSize - (offset % self.ClusterSize)

        # Do we have to read partial VCNs?
        if offset % self.ClusterSize:
            # Read the whole VCN
            bufTemp = self.readVCN(vcnToStart, 1)
            if bufTemp is '':
                # Something went wrong
                return None
            buf = bufTemp[offset % self.ClusterSize:]
            curLength -= len(buf)
            vcnToStart += 1

        # Finished?
        if curLength <= 0:
            return buf[:length]

        # First partial cluster read.. now let's keep reading full clusters
        # Data left to be read is bigger than a Cluster?
        if curLength / self.ClusterSize:
            # Yep.. so let's read full clusters
            bufTemp = self.readVCN(vcnToStart, curLength / self.ClusterSize)
            if bufTemp is '':
                # Something went wrong
                return None
            if len(bufTemp) > curLength:
                # Too much data read, taking something off
                buf = buf + bufTemp[:curLength]
            else:
                buf = buf + bufTemp
            vcnToStart += curLength / self.ClusterSize
            curLength -= len(bufTemp)

        # Is there anything else left to be read in the last cluster?
        if curLength > 0:
            bufTemp = self.readVCN(vcnToStart, 1)
            buf = buf + bufTemp[:curLength]

        if buf == '':
            return None
        else:
            return buf

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
        print self.Attribute.dump()
        for i in self.Attribute.DataRuns:
            print i.dump()

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
                print "%s %s %15d %s " %( self.getPrintableAttributes(), self.LastDataChangeTime.isoformat(' '), self.FileSize, self.FileName)
            except Exception, e:
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

        # Parse Index Allocation
        attr = self.searchAttribute(INDEX_ALLOCATION, unicode('$I30'))
        if attr is not None:
            ia = AttributeIndexAllocation(attr)
            self.Attributes[INDEX_ALLOCATION] = ia

        attr = self.searchAttribute(INDEX_ROOT,unicode('$I30'))
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

        data = "".join(dataList)
        return data

    def parseIndexBlocks(self, vcn):
        IndexEntries = []
        #sectors = self.NTFSVolume.IndexBlockSize / self.NTFSVolume.SectorSize
        if self.Attributes.has_key(INDEX_ALLOCATION):
            ia = self.Attributes[INDEX_ALLOCATION]
            data = ia.read(vcn*self.NTFSVolume.IndexBlockSize, self.NTFSVolume.IndexBlockSize)
            if data:
                iaRec = NTFS_INDEX_ALLOCATION(data)
                sectorsPerIB = self.NTFSVolume.IndexBlockSize / self.NTFSVolume.SectorSize
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
        if self.Attributes.has_key(INDEX_ROOT):
            ir = self.Attributes[INDEX_ROOT]

            if ir.getType() & FILE_NAME:
                for ie in ir.IndexEntries:
                    if ie.isSubNode():
                        files += self.walkSubNodes(ie.getVCN())
                return files
        else:
            return None

    def findFirstSubNode(self, vcn, toSearch):
        def getFileName(entry):
            if len(entry.getKey()) > 0 and entry.getINodeNumber() > 16:
                fn = NTFS_FILE_NAME_ATTR(entry.getKey())
                if fn['FileNameType'] != FILE_NAME_DOS:
                    return string.upper(fn['FileName'].decode('utf-16le'))
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
                    return string.upper(fn['FileName'].decode('utf-16le'))
            return None


        toSearch = unicode(string.upper(fileName))

        if self.Attributes.has_key(INDEX_ROOT):
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

        # Let's calculate where in disk this iNode should be
        if self.MFTINode and iNodeNum > FIXED_MFTS:
            # Fragmented $MFT
            attr = self.MFTINode.searchAttribute(DATA,None)
            record = attr.read(iNodeNum*self.RecordSize, self.RecordSize)
        else:
            diskPosition = self.__MFTStart + iNodeNum * self.RecordSize
            self.volumeFD.seek(diskPosition,0)
            record = self.volumeFD.read(recordLen)
            while len(record) < recordLen:
                record += self.volumeFD.read(recordLen-len(record))

        mftRecord = NTFS_MFT_RECORD(record)

        record = newINode.PerformFixUp(mftRecord, record, self.RecordSize/self.SectorSize)
        newINode.INodeNumber = iNodeNum
        newINode.AttributesRaw = record[mftRecord['AttributesOffset']-recordLen:]
        newINode.parseAttributes()

        return newINode

class MiniShell(cmd.Cmd):
    def __init__(self, volume):
        cmd.Cmd.__init__(self)
        self.volumePath = volume
        self.volume = NTFS(volume)
        self.rootINode = self.volume.getINode(5)
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
        except Exception, e:
           logging.error(str(e))

        return retVal

    def do_exit(self,line):
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print output
        self.last_output = output

    def do_help(self,line):
        print """
 cd {path} - changes the current directory to {path}
 pwd - shows current remote directory
 ls  - lists all the files in the current directory
 lcd - change local directory
 get {filename} - downloads the filename from the current path
 cat {filename} - prints the contents of filename
 hexdump {filename} - hexdumps the contents of filename
 exit - terminates the server process (and this session)

"""

    def do_lcd(self,line):
        if line == '':
            print os.getcwd()
        else:
            os.chdir(line)
            print os.getcwd()

    def do_cd(self, line):
        p = string.replace(line,'/','\\')
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
        print self.pwd

    def do_ls(self, line, display = True):
        entries = self.currentINode.walk()
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

    def do_cat(self, line, command = sys.stdout.write):
        pathName = string.replace(line,'/','\\')
        pathName = ntpath.normpath(ntpath.join(self.pwd,pathName))
        res = self.findPathName(pathName)
        if res is None:
            logging.error("Not found!")
            return
        if res.isDirectory() > 0:
            logging.error("It's a directory!")
            return
        if res.isCompressed() or res.isEncrypted() or res.isSparse():
            logging.error('Cannot handle compressed/encrypted/sparse files! :(')
            return
        stream = res.getStream(None)
        chunks = 4096*10
        written = 0
        for i in range(stream.getDataSize()/chunks):
            buf = stream.read(i*chunks, chunks)
            written += len(buf)
            command(buf)
        if stream.getDataSize() % chunks:
            buf = stream.read(written, stream.getDataSize() % chunks)
            command(buf)
        logging.info("%d bytes read" % stream.getDataSize())

    def do_get(self, line):
        pathName = string.replace(line,'/','\\')
        pathName = ntpath.normpath(ntpath.join(self.pwd,pathName))
        fh = open(ntpath.basename(pathName),"wb")
        self.do_cat(line, command = fh.write)
        fh.close()

def main():
    print version.BANNER
    # Init the example's logger theme
    logger.init()
    parser = argparse.ArgumentParser(add_help = True, description = "NTFS explorer (read-only)")
    parser.add_argument('volume', action='store', help='NTFS volume to open (e.g. \\\\.\\C: or /dev/disk1s1)')
    parser.add_argument('-extract', action='store', help='extracts pathname (e.g. \windows\system32\config\sam)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    shell = MiniShell(options.volume)
    if options.extract is not None:
        shell.onecmd("get %s"% options.extract)
    else:
        shell.cmdloop()

if __name__ == '__main__':
    main()
    sys.exit(1)



