#!/usr/bin/env python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#             Microsoft Extensive Storage Engine parser, just focused on trying 
#             to parse NTDS.dit files (not meant as a full parser, although it might work)
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  Structure.
# 
# Excellent reference done by Joachim Metz
# http://forensic-proof.com/wp-content/uploads/2011/07/Extensible-Storage-Engine-ESE-Database-File-EDB-format.pdf
#
# ToDo: 
# [ ] Parse multi-values properly
# [ ] Support long values properly

from impacket import LOG
try:
    from collections import OrderedDict
except:
    try:
        from ordereddict.ordereddict import OrderedDict
    except:
        from ordereddict import OrderedDict
from impacket.structure import Structure
from struct import unpack
from binascii import hexlify

# Constants

FILE_TYPE_DATABASE       = 0
FILE_TYPE_STREAMING_FILE = 1

# Database state
JET_dbstateJustCreated    = 1
JET_dbstateDirtyShutdown  = 2
JET_dbstateCleanShutdown  = 3
JET_dbstateBeingConverted = 4
JET_dbstateForceDetach    = 5

# Page Flags
FLAGS_ROOT         = 1
FLAGS_LEAF         = 2
FLAGS_PARENT       = 4
FLAGS_EMPTY        = 8
FLAGS_SPACE_TREE   = 0x20
FLAGS_INDEX        = 0x40
FLAGS_LONG_VALUE   = 0x80
FLAGS_NEW_FORMAT   = 0x2000
FLAGS_NEW_CHECKSUM = 0x2000

# Tag Flags
TAG_UNKNOWN = 0x1
TAG_DEFUNCT = 0x2
TAG_COMMON  = 0x4

# Fixed Page Numbers
DATABASE_PAGE_NUMBER           = 1
CATALOG_PAGE_NUMBER            = 4
CATALOG_BACKUP_PAGE_NUMBER     = 24

# Fixed FatherDataPages
DATABASE_FDP         = 1
CATALOG_FDP          = 2
CATALOG_BACKUP_FDP   = 3

# Catalog Types
CATALOG_TYPE_TABLE        = 1
CATALOG_TYPE_COLUMN       = 2
CATALOG_TYPE_INDEX        = 3
CATALOG_TYPE_LONG_VALUE   = 4
CATALOG_TYPE_CALLBACK     = 5

# Column Types
JET_coltypNil          = 0
JET_coltypBit          = 1
JET_coltypUnsignedByte = 2
JET_coltypShort        = 3
JET_coltypLong         = 4
JET_coltypCurrency     = 5
JET_coltypIEEESingle   = 6
JET_coltypIEEEDouble   = 7
JET_coltypDateTime     = 8
JET_coltypBinary       = 9
JET_coltypText         = 10
JET_coltypLongBinary   = 11
JET_coltypLongText     = 12
JET_coltypSLV          = 13
JET_coltypUnsignedLong = 14
JET_coltypLongLong     = 15
JET_coltypGUID         = 16
JET_coltypUnsignedShort= 17
JET_coltypMax          = 18

ColumnTypeToName = {
    JET_coltypNil          : 'NULL',
    JET_coltypBit          : 'Boolean',
    JET_coltypUnsignedByte : 'Signed byte',
    JET_coltypShort        : 'Signed short',
    JET_coltypLong         : 'Signed long',
    JET_coltypCurrency     : 'Currency',
    JET_coltypIEEESingle   : 'Single precision FP',
    JET_coltypIEEEDouble   : 'Double precision FP',
    JET_coltypDateTime     : 'DateTime',
    JET_coltypBinary       : 'Binary',
    JET_coltypText         : 'Text',
    JET_coltypLongBinary   : 'Long Binary',
    JET_coltypLongText     : 'Long Text',
    JET_coltypSLV          : 'Obsolete',
    JET_coltypUnsignedLong : 'Unsigned long',
    JET_coltypLongLong     : 'Long long',
    JET_coltypGUID         : 'GUID',
    JET_coltypUnsignedShort: 'Unsigned short',
    JET_coltypMax          : 'Max',
}

ColumnTypeSize = {
    JET_coltypNil          : None,
    JET_coltypBit          : (1,'B'),
    JET_coltypUnsignedByte : (1,'B'),
    JET_coltypShort        : (2,'<h'),
    JET_coltypLong         : (4,'<l'),
    JET_coltypCurrency     : (8,'<Q'),
    JET_coltypIEEESingle   : (4,'<f'),
    JET_coltypIEEEDouble   : (8,'<d'),
    JET_coltypDateTime     : (8,'<Q'),
    JET_coltypBinary       : None,
    JET_coltypText         : None, 
    JET_coltypLongBinary   : None,
    JET_coltypLongText     : None,
    JET_coltypSLV          : None,
    JET_coltypUnsignedLong : (4,'<L'),
    JET_coltypLongLong     : (8,'<Q'),
    JET_coltypGUID         : (16,'16s'),
    JET_coltypUnsignedShort: (2,'<H'),
    JET_coltypMax          : None,
}

# Tagged Data Type Flags
TAGGED_DATA_TYPE_VARIABLE_SIZE = 1
TAGGED_DATA_TYPE_COMPRESSED    = 2
TAGGED_DATA_TYPE_STORED        = 4
TAGGED_DATA_TYPE_MULTI_VALUE   = 8
TAGGED_DATA_TYPE_WHO_KNOWS     = 10

# Code pages
CODEPAGE_UNICODE = 1200
CODEPAGE_ASCII   = 20127
CODEPAGE_WESTERN = 1252

StringCodePages = {
    CODEPAGE_UNICODE : 'utf-16le', 
    CODEPAGE_ASCII   : 'ascii',
    CODEPAGE_WESTERN : 'cp1252',
}

# Structures

TABLE_CURSOR = {
    'TableData' : '',
    'FatherDataPageNumber': 0,
    'CurrentPageData' : '',
    'CurrentTag' : 0,
}

class ESENT_JET_SIGNATURE(Structure):
    structure = (
        ('Random','<L=0'),
        ('CreationTime','<Q=0'),
        ('NetBiosName','16s=""'),
    )

class ESENT_DB_HEADER(Structure):
    structure = (
        ('CheckSum','<L=0'),
        ('Signature','"\xef\xcd\xab\x89'),
        ('Version','<L=0'),
        ('FileType','<L=0'),
        ('DBTime','<Q=0'),
        ('DBSignature',':',ESENT_JET_SIGNATURE),
        ('DBState','<L=0'),
        ('ConsistentPosition','<Q=0'),
        ('ConsistentTime','<Q=0'),
        ('AttachTime','<Q=0'),
        ('AttachPosition','<Q=0'),
        ('DetachTime','<Q=0'),
        ('DetachPosition','<Q=0'),
        ('LogSignature',':',ESENT_JET_SIGNATURE),
        ('Unknown','<L=0'),
        ('PreviousBackup','24s=""'),
        ('PreviousIncBackup','24s=""'),
        ('CurrentFullBackup','24s=""'),
        ('ShadowingDisables','<L=0'),
        ('LastObjectID','<L=0'),
        ('WindowsMajorVersion','<L=0'),
        ('WindowsMinorVersion','<L=0'),
        ('WindowsBuildNumber','<L=0'),
        ('WindowsServicePackNumber','<L=0'),
        ('FileFormatRevision','<L=0'),
        ('PageSize','<L=0'),
        ('RepairCount','<L=0'),
        ('RepairTime','<Q=0'),
        ('Unknown2','28s=""'),
        ('ScrubTime','<Q=0'),
        ('RequiredLog','<Q=0'),
        ('UpgradeExchangeFormat','<L=0'),
        ('UpgradeFreePages','<L=0'),
        ('UpgradeSpaceMapPages','<L=0'),
        ('CurrentShadowBackup','24s=""'),
        ('CreationFileFormatVersion','<L=0'),
        ('CreationFileFormatRevision','<L=0'),
        ('Unknown3','16s=""'),
        ('OldRepairCount','<L=0'),
        ('ECCCount','<L=0'),
        ('LastECCTime','<Q=0'),
        ('OldECCFixSuccessCount','<L=0'),
        ('ECCFixErrorCount','<L=0'),
        ('LastECCFixErrorTime','<Q=0'),
        ('OldECCFixErrorCount','<L=0'),
        ('BadCheckSumErrorCount','<L=0'),
        ('LastBadCheckSumTime','<Q=0'),
        ('OldCheckSumErrorCount','<L=0'),
        ('CommittedLog','<L=0'),
        ('PreviousShadowCopy','24s=""'),
        ('PreviousDifferentialBackup','24s=""'),
        ('Unknown4','40s=""'),
        ('NLSMajorVersion','<L=0'),
        ('NLSMinorVersion','<L=0'),
        ('Unknown5','148s=""'),
        ('UnknownFlags','<L=0'),
    )

class ESENT_PAGE_HEADER(Structure):
    structure_2003_SP0 = (
        ('CheckSum','<L=0'),
        ('PageNumber','<L=0'),
    )
    structure_0x620_0x0b = (
        ('CheckSum','<L=0'),
        ('ECCCheckSum','<L=0'),
    )
    structure_win7 = (
        ('CheckSum','<Q=0'),
    )
    common = (
        ('LastModificationTime','<Q=0'),
        ('PreviousPageNumber','<L=0'),
        ('NextPageNumber','<L=0'),
        ('FatherDataPage','<L=0'),
        ('AvailableDataSize','<H=0'),
        ('AvailableUncommittedDataSize','<H=0'),
        ('FirstAvailableDataOffset','<H=0'),
        ('FirstAvailablePageTag','<H=0'),
        ('PageFlags','<L=0'),
    )
    extended_win7 = (
        ('ExtendedCheckSum1','<Q=0'),
        ('ExtendedCheckSum2','<Q=0'),
        ('ExtendedCheckSum3','<Q=0'),
        ('PageNumber','<Q=0'),
        ('Unknown','<Q=0'),
    )
    def __init__(self, version, revision, pageSize=8192, data=None):
        if (version < 0x620) or (version == 0x620 and revision < 0x0b):
            # For sure the old format
            self.structure = self.structure_2003_SP0 + self.common
        elif version == 0x620 and revision < 0x11:
            # Exchange 2003 SP1 and Windows Vista and later
            self.structure = self.structure_0x620_0x0b + self.common
        else:
            # Windows 7 and later
            self.structure = self.structure_win7 + self.common
            if pageSize > 8192:
                self.structure += self.extended_win7

        Structure.__init__(self,data)

class ESENT_ROOT_HEADER(Structure):
    structure = (
        ('InitialNumberOfPages','<L=0'),
        ('ParentFatherDataPage','<L=0'),
        ('ExtentSpace','<L=0'),
        ('SpaceTreePageNumber','<L=0'),
    )

class ESENT_BRANCH_HEADER(Structure):
    structure = (
        ('CommonPageKey',':'),
    )

class ESENT_BRANCH_ENTRY(Structure):
    common = (
        ('CommonPageKeySize','<H=0'),
    )
    structure = (
        ('LocalPageKeySize','<H=0'),
        ('_LocalPageKey','_-LocalPageKey','self["LocalPageKeySize"]'),
        ('LocalPageKey',':'),
        ('ChildPageNumber','<L=0'),
    )
    def __init__(self, flags, data=None):
        if flags & TAG_COMMON > 0:
            # Include the common header
            self.structure = self.common + self.structure
        Structure.__init__(self,data)

class ESENT_LEAF_HEADER(Structure):
    structure = (
        ('CommonPageKey',':'),
    )

class ESENT_LEAF_ENTRY(Structure):
    common = (
        ('CommonPageKeySize','<H=0'),
    )
    structure = (
        ('LocalPageKeySize','<H=0'),
        ('_LocalPageKey','_-LocalPageKey','self["LocalPageKeySize"]'),
        ('LocalPageKey',':'),
        ('EntryData',':'),
    )
    def __init__(self, flags, data=None):
        if flags & TAG_COMMON > 0:
            # Include the common header
            self.structure = self.common + self.structure
        Structure.__init__(self,data)

class ESENT_SPACE_TREE_HEADER(Structure):
    structure = (
        ('Unknown','<Q=0'),
    )

class ESENT_SPACE_TREE_ENTRY(Structure):
    structure = (
        ('PageKeySize','<H=0'),
        ('LastPageNumber','<L=0'),
        ('NumberOfPages','<L=0'),
    )

class ESENT_INDEX_ENTRY(Structure):
    structure = (
        ('RecordPageKey',':'),
    )

class ESENT_DATA_DEFINITION_HEADER(Structure):
    structure = (
        ('LastFixedSize','<B=0'),
        ('LastVariableDataType','<B=0'),
        ('VariableSizeOffset','<H=0'),
    )

class ESENT_CATALOG_DATA_DEFINITION_ENTRY(Structure):
    fixed = (
        ('FatherDataPageID','<L=0'),
        ('Type','<H=0'),
        ('Identifier','<L=0'),
    )

    column_stuff = (
        ('ColumnType','<L=0'),
        ('SpaceUsage','<L=0'),
        ('ColumnFlags','<L=0'),
        ('CodePage','<L=0'),
    )

    other = (
        ('FatherDataPageNumber','<L=0'),
    )

    table_stuff = (
        ('SpaceUsage','<L=0'),
#        ('TableFlags','<L=0'),
#        ('InitialNumberOfPages','<L=0'),
    )

    index_stuff = (
        ('SpaceUsage','<L=0'),
        ('IndexFlags','<L=0'),
        ('Locale','<L=0'),
    )

    lv_stuff = (
        ('SpaceUsage','<L=0'),
#        ('LVFlags','<L=0'),
#        ('InitialNumberOfPages','<L=0'),
    )
    common = (
#        ('RootFlag','<B=0'),
#        ('RecordOffset','<H=0'),
#        ('LCMapFlags','<L=0'),
#        ('KeyMost','<H=0'),
        ('Trailing',':'),
    )

    def __init__(self,data):
        # Depending on the type of data we'll end up building a different struct
        dataType = unpack('<H', data[4:][:2])[0]
        self.structure = self.fixed

        if dataType == CATALOG_TYPE_TABLE:
            self.structure += self.other + self.table_stuff
        elif dataType == CATALOG_TYPE_COLUMN:
            self.structure += self.column_stuff
        elif dataType == CATALOG_TYPE_INDEX:
            self.structure += self.other + self.index_stuff
        elif dataType == CATALOG_TYPE_LONG_VALUE:
            self.structure += self.other + self.lv_stuff
        elif dataType == CATALOG_TYPE_CALLBACK:
            LOG.error('CallBack types not supported!')
            raise
        else:
            LOG.error('Unknown catalog type 0x%x' % dataType)
            self.structure = ()
            Structure.__init__(self,data)

        self.structure += self.common

        Structure.__init__(self,data)


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

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

class ESENT_PAGE:
    def __init__(self, db, data=None):
        self.__DBHeader = db
        self.data = data
        self.record = None
        if data is not None:
            self.record = ESENT_PAGE_HEADER(self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision'], self.__DBHeader['PageSize'], data)

    def printFlags(self):
        flags = self.record['PageFlags']
        if flags & FLAGS_EMPTY:
            print "\tEmpty"
        if flags & FLAGS_INDEX:
            print "\tIndex"
        if flags & FLAGS_LEAF:
            print "\tLeaf"
        else:
            print "\tBranch"
        if flags & FLAGS_LONG_VALUE:
            print "\tLong Value"
        if flags & FLAGS_NEW_CHECKSUM:
            print "\tNew Checksum"
        if flags & FLAGS_NEW_FORMAT:
            print "\tNew Format"
        if flags & FLAGS_PARENT:
            print "\tParent"
        if flags & FLAGS_ROOT:
            print "\tRoot"
        if flags & FLAGS_SPACE_TREE:
            print "\tSpace Tree"

    def dump(self):
        baseOffset = len(self.record)
        self.record.dump()
        tags = self.data[-4*self.record['FirstAvailablePageTag']:]

        print "FLAGS: "
        self.printFlags()

        print

        for i in range(self.record['FirstAvailablePageTag']):
            tag = tags[-4:]
            if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] > 11 and self.__DBHeader['PageSize'] > 8192:
                valueSize = unpack('<H', tag[:2])[0] & 0x7fff
                valueOffset = unpack('<H',tag[2:])[0] & 0x7fff
                hexdump((self.data[baseOffset+valueOffset:][:6]))
                pageFlags = ord(self.data[baseOffset+valueOffset:][1]) >> 5
                #print "TAG FLAG: 0x%x " % (unpack('<L', self.data[baseOffset+valueOffset:][:4]) ) >> 5
                #print "TAG FLAG: 0x " , ord(self.data[baseOffset+valueOffset:][0])
            else:
                valueSize = unpack('<H', tag[:2])[0] & 0x1fff
                pageFlags = (unpack('<H', tag[2:])[0] & 0xe000) >> 13
                valueOffset = unpack('<H',tag[2:])[0] & 0x1fff
                
            print "TAG %-8d offset:0x%-6x flags:0x%-4x valueSize:0x%x" % (i,valueOffset,pageFlags,valueSize)
            #hexdump(self.getTag(i)[1])
            tags = tags[:-4]

        if self.record['PageFlags'] & FLAGS_ROOT > 0:
            rootHeader = ESENT_ROOT_HEADER(self.getTag(0)[1])
            rootHeader.dump()
        elif self.record['PageFlags'] & FLAGS_LEAF == 0:
            # Branch Header
            flags, data = self.getTag(0)
            branchHeader = ESENT_BRANCH_HEADER(data)
            branchHeader.dump()
        else:
            # Leaf Header
            flags, data = self.getTag(0)
            if self.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                # Space Tree
                spaceTreeHeader = ESENT_SPACE_TREE_HEADER(data)
                spaceTreeHeader.dump()
            else:
                leafHeader = ESENT_LEAF_HEADER(data)
                leafHeader.dump()

        # Print the leaf/branch tags
        for tagNum in range(1,self.record['FirstAvailablePageTag']):
            flags, data = self.getTag(tagNum)
            if self.record['PageFlags'] & FLAGS_LEAF == 0:
                # Branch page
                branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                branchEntry.dump()
            elif self.record['PageFlags'] & FLAGS_LEAF > 0:
                # Leaf page
                if self.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                    # Space Tree
                    spaceTreeEntry = ESENT_SPACE_TREE_ENTRY(data)
                    #spaceTreeEntry.dump()

                elif self.record['PageFlags'] & FLAGS_INDEX > 0:
                    # Index Entry
                    indexEntry = ESENT_INDEX_ENTRY(data)
                    #indexEntry.dump()
                elif self.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
                    # Long Page Value
                    LOG.error('Long value still not supported')
                    raise
                else:
                    # Table Value
                    leafEntry = ESENT_LEAF_ENTRY(flags, data)
                    dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(leafEntry['EntryData'])
                    dataDefinitionHeader.dump()
                    catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(leafEntry['EntryData'][len(dataDefinitionHeader):])
                    catalogEntry.dump()
                    hexdump(leafEntry['EntryData'])

    def getTag(self, tagNum):
        if self.record['FirstAvailablePageTag'] < tagNum:
            LOG.error('Trying to grab an unknown tag 0x%x' % tagNum)
            raise

        tags = self.data[-4*self.record['FirstAvailablePageTag']:]
        baseOffset = len(self.record)
        for i in range(tagNum):
            tags = tags[:-4]

        tag = tags[-4:]

        if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] >= 17 and self.__DBHeader['PageSize'] > 8192:
            valueSize = unpack('<H', tag[:2])[0] & 0x7fff
            valueOffset = unpack('<H',tag[2:])[0] & 0x7fff
            tmpData = list(self.data[baseOffset+valueOffset:][:valueSize])
            pageFlags = ord(tmpData[1]) >> 5
            tmpData[1] = chr(ord(tmpData[1]) & 0x1f)
            tagData = "".join(tmpData)
        else:
            valueSize = unpack('<H', tag[:2])[0] & 0x1fff
            pageFlags = (unpack('<H', tag[2:])[0] & 0xe000) >> 13
            valueOffset = unpack('<H',tag[2:])[0] & 0x1fff
            tagData = self.data[baseOffset+valueOffset:][:valueSize]

        #return pageFlags, self.data[baseOffset+valueOffset:][:valueSize]
        return pageFlags, tagData

class ESENT_DB:
    def __init__(self, fileName, pageSize = 8192, isRemote = False):
        self.__fileName = fileName
        self.__pageSize = pageSize
        self.__DB = None
        self.__DBHeader = None
        self.__totalPages = None
        self.__tables = OrderedDict()
        self.__currentTable = None
        self.__isRemote = isRemote
        self.mountDB()

    def mountDB(self):
        LOG.debug("Mounting DB...")
        if self.__isRemote is True:
            self.__DB = self.__fileName
            self.__DB.open()
        else:
            self.__DB = open(self.__fileName,"rb")
        mainHeader = self.getPage(-1)
        self.__DBHeader = ESENT_DB_HEADER(mainHeader)
        self.__pageSize = self.__DBHeader['PageSize']
        self.__DB.seek(0,2)
        self.__totalPages = (self.__DB.tell() / self.__pageSize) -2
        LOG.debug("Database Version:0x%x, Revision:0x%x"% (self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision']))
        LOG.debug("Page Size: %d" % self.__pageSize)
        LOG.debug("Total Pages in file: %d" % self.__totalPages)
        self.parseCatalog(CATALOG_PAGE_NUMBER)

    def printCatalog(self):
        indent = '    '

        print "Database version: 0x%x, 0x%x" % (self.__DBHeader['Version'], self.__DBHeader['FileFormatRevision'] )
        print "Page size: %d " % self.__pageSize
        print "Number of pages: %d" % self.__totalPages
        print 
        print "Catalog for %s" % self.__fileName
        for table in self.__tables.keys():
            print "[%s]" % table
            print "%sColumns " % indent
            for column in self.__tables[table]['Columns'].keys():
                record = self.__tables[table]['Columns'][column]['Record']
                print "%s%-5d%-30s%s" % (indent*2, record['Identifier'], column,ColumnTypeToName[record['ColumnType']])
            print "%sIndexes"% indent
            for index in self.__tables[table]['Indexes'].keys():
                print "%s%s" % (indent*2, index)
            print ""

    def __addItem(self, entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
        catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
        itemName = self.__parseItemName(entry)

        if catalogEntry['Type'] == CATALOG_TYPE_TABLE:
            self.__tables[itemName] = OrderedDict()
            self.__tables[itemName]['TableEntry'] = entry
            self.__tables[itemName]['Columns']    = OrderedDict()
            self.__tables[itemName]['Indexes']    = OrderedDict()
            self.__tables[itemName]['LongValues'] = OrderedDict()
            self.__currentTable = itemName
        elif catalogEntry['Type'] == CATALOG_TYPE_COLUMN:
            self.__tables[self.__currentTable]['Columns'][itemName] = entry
            self.__tables[self.__currentTable]['Columns'][itemName]['Header'] = dataDefinitionHeader
            self.__tables[self.__currentTable]['Columns'][itemName]['Record'] = catalogEntry
        elif catalogEntry['Type'] == CATALOG_TYPE_INDEX:
            self.__tables[self.__currentTable]['Indexes'][itemName] = entry
        elif catalogEntry['Type'] == CATALOG_TYPE_LONG_VALUE:
            self.__addLongValue(entry)
        else:
            LOG.error('Unknown type 0x%x' % catalogEntry['Type'])
            raise

    def __parseItemName(self,entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])

        if dataDefinitionHeader['LastVariableDataType'] > 127:
            numEntries =  dataDefinitionHeader['LastVariableDataType'] - 127
        else:
            numEntries =  dataDefinitionHeader['LastVariableDataType']

        itemLen = unpack('<H',entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][:2])[0]
        itemName = entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][2*numEntries:][:itemLen]
        return itemName

    def __addLongValue(self, entry):
        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
        catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
        lvLen = unpack('<H',entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][:2])[0]
        lvName = entry['EntryData'][dataDefinitionHeader['VariableSizeOffset']:][7:][:lvLen]
        self.__tables[self.__currentTable]['LongValues'][lvName] = entry

    def parsePage(self, page):
        baseOffset = len(page.record)

        # Print the leaf/branch tags
        for tagNum in range(1,page.record['FirstAvailablePageTag']):
            flags, data = page.getTag(tagNum)
            if page.record['PageFlags'] & FLAGS_LEAF > 0:
                # Leaf page
                if page.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                    pass
                elif page.record['PageFlags'] & FLAGS_INDEX > 0:
                    pass
                elif page.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
                    pass
                else:
                    # Table Value
                    leafEntry = ESENT_LEAF_ENTRY(flags, data)
                    self.__addItem(leafEntry)

    def parseCatalog(self, pageNum):
        # Parse all the pages starting at pageNum and commit table data
        page = self.getPage(pageNum)
        self.parsePage(page)

        for i in range(1, page.record['FirstAvailablePageTag']):
            flags, data = page.getTag(i)
            if page.record['PageFlags'] & FLAGS_LEAF == 0:
                # Branch page
                branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                self.parseCatalog(branchEntry['ChildPageNumber'])


    def readHeader(self):
        LOG.debug("Reading Boot Sector for %s" % self.__volumeName)

    def getPage(self, pageNum):
        LOG.debug("Trying to fetch page %d (0x%x)" % (pageNum, (pageNum+1)*self.__pageSize))
        self.__DB.seek((pageNum+1)*self.__pageSize, 0)
        data = self.__DB.read(self.__pageSize)
        while len(data) < self.__pageSize:
            remaining = self.__pageSize - len(data)
            data += self.__DB.read(remaining)
        # Special case for the first page
        if pageNum <= 0:
            return data
        else:
            return ESENT_PAGE(self.__DBHeader, data)

    def close(self):
        self.__DB.close()

    def openTable(self, tableName):
        # Returns a cursos for later use
        
        if tableName in self.__tables:
            entry = self.__tables[tableName]['TableEntry']
            dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(entry['EntryData'])
            catalogEntry = ESENT_CATALOG_DATA_DEFINITION_ENTRY(entry['EntryData'][len(dataDefinitionHeader):])
            
            # Let's position the cursor at the leaf levels for fast reading
            pageNum = catalogEntry['FatherDataPageNumber']
            done = False
            while done is False:
                page = self.getPage(pageNum)
                if page.record['FirstAvailablePageTag'] <= 1:
                    # There are no records
                    done = True
                for i in range(1, page.record['FirstAvailablePageTag']):
                    flags, data = page.getTag(i)
                    if page.record['PageFlags'] & FLAGS_LEAF == 0:
                        # Branch page, move on to the next page
                        branchEntry = ESENT_BRANCH_ENTRY(flags, data)
                        pageNum = branchEntry['ChildPageNumber']
                        break
                    else:
                        done = True
                        break
                
            cursor = TABLE_CURSOR
            cursor['TableData'] = self.__tables[tableName]
            cursor['FatherDataPageNumber'] = catalogEntry['FatherDataPageNumber']
            cursor['CurrentPageData'] = page
            cursor['CurrentTag']  = 0
            return cursor
        else:
            return None

    def __getNextTag(self, cursor):
        page = cursor['CurrentPageData']

        if cursor['CurrentTag'] >= page.record['FirstAvailablePageTag']:
            # No more data in this page, chau
            return None

        flags, data = page.getTag(cursor['CurrentTag'])
        if page.record['PageFlags'] & FLAGS_LEAF > 0:
            # Leaf page
            if page.record['PageFlags'] & FLAGS_SPACE_TREE > 0:
                raise
            elif page.record['PageFlags'] & FLAGS_INDEX > 0:
                raise
            elif page.record['PageFlags'] & FLAGS_LONG_VALUE > 0:
                raise
            else:
                # Table Value
                leafEntry = ESENT_LEAF_ENTRY(flags, data)
                return leafEntry

        return None

    def getNextRow(self, cursor):
        cursor['CurrentTag'] += 1

        tag = self.__getNextTag(cursor)
        #hexdump(tag)

        if tag is None:
            # No more tags in this page, search for the next one on the right
            page = cursor['CurrentPageData']
            if page.record['NextPageNumber'] == 0:
                # No more pages, chau
                return None
            else:
                cursor['CurrentPageData'] = self.getPage(page.record['NextPageNumber'])
                cursor['CurrentTag'] = 0
                return self.getNextRow(cursor)
        else:
            return self.__tagToRecord(cursor, tag['EntryData'])

        # We never should get here
        raise

    def __tagToRecord(self, cursor, tag):
        # So my brain doesn't forget, the data record is composed of:
        # Header
        # Fixed Size Data (ID < 127)
        #     The easiest to parse. Their size is fixed in the record. You can get its size
        #     from the Column Record, field SpaceUsage
        # Variable Size Data (127 < ID < 255)
        #     At VariableSizeOffset you get an array of two bytes per variable entry, pointing
        #     to the length of the value. Values start at:
        #                numEntries = LastVariableDataType - 127
        #                VariableSizeOffset + numEntries * 2 (bytes)
        # Tagged Data ( > 255 )
        #     After the Variable Size Value, there's more data for the tagged values.
        #     Right at the beggining there's another array (taggedItems), pointing to the
        #     values, size.
        #
        # The interesting thing about this DB records is there's no need for all the columns to be there, hence
        # saving space. That's why I got over all the columns, and if I find data (of any type), i assign it. If 
        # not, the column's empty.
        #
        # There are a lot of caveats in the code, so take your time to explore it. 
        #
        # ToDo: Better complete this description
        #

        record = OrderedDict()
        taggedItems = OrderedDict()
        taggedItemsParsed = False

        dataDefinitionHeader = ESENT_DATA_DEFINITION_HEADER(tag)
        #dataDefinitionHeader.dump()
        variableDataBytesProcessed = (dataDefinitionHeader['LastVariableDataType'] - 127) * 2
        prevItemLen = 0
        tagLen = len(tag)
        fixedSizeOffset = len(dataDefinitionHeader)
        variableSizeOffset = dataDefinitionHeader['VariableSizeOffset'] 
 
        columns = cursor['TableData']['Columns'] 
        
        for column in columns.keys():
            columnRecord = columns[column]['Record']
            #columnRecord.dump()
            if columnRecord['Identifier'] <= dataDefinitionHeader['LastFixedSize']:
                # Fixed Size column data type, still available data
                record[column] = tag[fixedSizeOffset:][:columnRecord['SpaceUsage']]
                fixedSizeOffset += columnRecord['SpaceUsage']

            elif 127 < columnRecord['Identifier'] <= dataDefinitionHeader['LastVariableDataType']:
                # Variable data type
                index = columnRecord['Identifier'] - 127 - 1
                itemLen = unpack('<H',tag[variableSizeOffset+index*2:][:2])[0]

                if itemLen & 0x8000:
                    # Empty item
                    itemLen = prevItemLen
                    record[column] = None
                else:
                    itemValue = tag[variableSizeOffset+variableDataBytesProcessed:][:itemLen-prevItemLen]
                    record[column] = itemValue

                #if columnRecord['Identifier'] <= dataDefinitionHeader['LastVariableDataType']:
                variableDataBytesProcessed +=itemLen-prevItemLen

                prevItemLen = itemLen

            elif columnRecord['Identifier'] > 255:
                # Have we parsed the tagged items already?
                if taggedItemsParsed is False and (variableDataBytesProcessed+variableSizeOffset) < tagLen:
                    index = variableDataBytesProcessed+variableSizeOffset
                    #hexdump(tag[index:])
                    endOfVS = self.__pageSize
                    firstOffsetTag = (unpack('<H', tag[index+2:][:2])[0] & 0x3fff) + variableDataBytesProcessed+variableSizeOffset
                    while True:
                        taggedIdentifier = unpack('<H', tag[index:][:2])[0]
                        index += 2
                        taggedOffset = (unpack('<H', tag[index:][:2])[0] & 0x3fff) 
                        # As of Windows 7 and later ( version 0x620 revision 0x11) the 
                        # tagged data type flags are always present
                        if self.__DBHeader['Version'] == 0x620 and self.__DBHeader['FileFormatRevision'] >= 17 and self.__DBHeader['PageSize'] > 8192: 
                            flagsPresent = 1
                        else:
                            flagsPresent = (unpack('<H', tag[index:][:2])[0] & 0x4000)
                        index += 2
                        if taggedOffset < endOfVS:
                            endOfVS = taggedOffset
                        taggedItems[taggedIdentifier] = (taggedOffset, tagLen, flagsPresent)
                        #print "ID: %d, Offset:%d, firstOffset:%d, index:%d, flag: 0x%x" % (taggedIdentifier, taggedOffset,firstOffsetTag,index, flagsPresent)
                        if index >= firstOffsetTag:
                            # We reached the end of the variable size array
                            break
                
                    # Calculate length of variable items
                    # Ugly.. should be redone
                    prevKey = taggedItems.keys()[0]
                    for i in range(1,len(taggedItems)):
                        offset0, length, flags = taggedItems[prevKey]
                        offset, _, _ = taggedItems.items()[i][1]
                        taggedItems[prevKey] = (offset0, offset-offset0, flags)
                        #print "ID: %d, Offset: %d, Len: %d, flags: %d" % (prevKey, offset0, offset-offset0, flags)
                        prevKey = taggedItems.keys()[i]
                    taggedItemsParsed = True
 
                # Tagged data type
                if taggedItems.has_key(columnRecord['Identifier']):
                    offsetItem = variableDataBytesProcessed + variableSizeOffset + taggedItems[columnRecord['Identifier']][0] 
                    itemSize = taggedItems[columnRecord['Identifier']][1]
                    # If item have flags, we should skip them
                    if taggedItems[columnRecord['Identifier']][2] > 0:
                        itemFlag = ord(tag[offsetItem:offsetItem+1])
                        offsetItem += 1
                        itemSize -= 1
                    else:
                        itemFlag = 0

                    #print "ID: %d, itemFlag: 0x%x" %( columnRecord['Identifier'], itemFlag)
                    if itemFlag & (TAGGED_DATA_TYPE_COMPRESSED ):
                        LOG.error('Unsupported tag column: %s, flag:0x%x' % (column, itemFlag))
                        record[column] = None
                    elif itemFlag & TAGGED_DATA_TYPE_MULTI_VALUE:
                        # ToDo: Parse multi-values properly
                        LOG.debug('Multivalue detected in column %s, returning raw results' % (column))
                        record[column] = (hexlify(tag[offsetItem:][:itemSize]),)
                    else:
                        record[column] = tag[offsetItem:][:itemSize]

                else:
                    record[column] = None
            else:
                record[column] = None

            # If we understand the data type, we unpack it and cast it accordingly
            # otherwise, we just encode it in hex
            if type(record[column]) is tuple:
                # A multi value data, we won't decode it, just leave it this way
                record[column] = record[column][0]
            elif columnRecord['ColumnType'] == JET_coltypText or columnRecord['ColumnType'] == JET_coltypLongText: 
                # Let's handle strings
                if record[column] is not None:
                    if columnRecord['CodePage'] not in StringCodePages:
                        LOG.error('Unknown codepage 0x%x'% columnRecord['CodePage'])
                        raise
                    stringDecoder = StringCodePages[columnRecord['CodePage']]

                    record[column] = record[column].decode(stringDecoder)
                
            else:
                unpackData = ColumnTypeSize[columnRecord['ColumnType']]
                if record[column] is not None:
                    if unpackData is None:
                        record[column] = hexlify(record[column])
                    else:
                        unpackStr = unpackData[1]
                        unpackSize = unpackData[0]
                        record[column] = unpack(unpackStr, record[column])[0]

        return record


