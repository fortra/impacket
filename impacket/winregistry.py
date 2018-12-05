# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description: A Windows Registry Library Parser
#
# Data taken from https://bazaar.launchpad.net/~guadalinex-members/dumphive/trunk/view/head:/winreg.txt
# http://sentinelchicken.com/data/TheWindowsNTRegistryFileFormat.pdf
#
#
# ToDo:
#
# [ ] Parse li records, probable the same as the ri but couldn't find any to probe


import sys
from struct import unpack
import ntpath

from impacket import LOG
from impacket.structure import Structure


# Constants

ROOT_KEY        = 0x2c
REG_NONE        = 0x00
REG_SZ          = 0x01
REG_EXPAND_SZ   = 0x02
REG_BINARY      = 0x03
REG_DWORD       = 0x04
REG_MULTISZ     = 0x07
REG_QWORD       = 0x0b

# Structs
class REG_REGF(Structure):
    structure = (
        ('Magic','"regf'),
        ('Unknown','<L=0'),
        ('Unknown2','<L=0'),
        ('lastChange','<Q=0'),
        ('MajorVersion','<L=0'),
        ('MinorVersion','<L=0'),
        ('0','<L=0'),
        ('11','<L=0'),
        ('OffsetFirstRecord','<L=0'),
        ('DataSize','<L=0'),
        ('1111','<L=0'),
        ('Name','48s=""'),
        ('Remaining1','411s=""'),
        ('CheckSum','<L=0xffffffff'), # Sum of all DWORDs from 0x0 to 0x1FB
        ('Remaining2','3585s=""'),
    )

class REG_HBIN(Structure):
    structure = (
        ('Magic','"hbin'),
        ('OffsetFirstHBin','<L=0'),
        ('OffsetNextHBin','<L=0'),
        ('BlockSize','<L=0'),
    )

class REG_HBINBLOCK(Structure):
    structure = (
        ('DataBlockSize','<l=0'),
        ('_Data','_-Data','self["DataBlockSize"]*(-1)-4'),
        ('Data',':'),
    )

class REG_NK(Structure):
    structure = (
        ('Magic','"nk'),
        ('Type','<H=0'),
        ('lastChange','<Q=0'),
        ('Unknown','<L=0'),
        ('OffsetParent','<l=0'),
        ('NumSubKeys','<L=0'),
        ('Unknown2','<L=0'),
        ('OffsetSubKeyLf','<l=0'),
        ('Unknown3','<L=0'),
        ('NumValues','<L=0'),
        ('OffsetValueList','<l=0'),
        ('OffsetSkRecord','<l=0'),
        ('OffsetClassName','<l=0'),
        ('UnUsed','20s=""'),
        ('NameLength','<H=0'),
        ('ClassNameLength','<H=0'),
        ('_KeyName','_-KeyName','self["NameLength"]'),
        ('KeyName',':'),
    )

class REG_VK(Structure):
    structure = (
        ('Magic','"vk'),
        ('NameLength','<H=0'),
        ('DataLen','<l=0'),
        ('OffsetData','<L=0'),
        ('ValueType','<L=0'),
        ('Flag','<H=0'),
        ('UnUsed','<H=0'),
        ('_Name','_-Name','self["NameLength"]'),
        ('Name',':'),
    )

class REG_LF(Structure):
    structure = (
        ('Magic','"lf'),
        ('NumKeys','<H=0'),
        ('HashRecords',':'),
    )

class REG_LH(Structure):
    structure = (
        ('Magic','"lh'),
        ('NumKeys','<H=0'),
        ('HashRecords',':'),
    )

class REG_RI(Structure):
    structure = (
        ('Magic','"ri'),
        ('NumKeys','<H=0'),
        ('HashRecords',':'),
    )

class REG_SK(Structure):
    structure = (
        ('Magic','"sk'),
        ('UnUsed','<H=0'),
        ('OffsetPreviousSk','<l=0'),
        ('OffsetNextSk','<l=0'),
        ('UsageCounter','<L=0'),
        ('SizeSk','<L=0'),
        ('Data',':'),
    )

class REG_HASH(Structure):
    structure = (
        ('OffsetNk','<L=0'),
        ('KeyName','4s=""'),
    )

StructMappings = {'nk': REG_NK,
                  'vk': REG_VK,
                  'lf': REG_LF,
                  'lh': REG_LH,
                  'ri': REG_RI,
                  'sk': REG_SK,
                 }

class Registry:
    def __init__(self, hive, isRemote = False):
        self.__hive = hive
        if isRemote is True:
            self.fd = self.__hive
            self.__hive.open()
        else:
            self.fd = open(hive,'rb')
        data = self.fd.read(4096)
        self.__regf = REG_REGF(data)
        self.indent = ''
        self.rootKey = self.__findRootKey()
        if self.rootKey is None:
            LOG.error("Can't find root key!")
        elif self.__regf['MajorVersion'] != 1 and self.__regf['MinorVersion'] > 5:
            LOG.warning("Unsupported version (%d.%d) - things might not work!" % (self.__regf['MajorVersion'], self.__regf['MinorVersion']))

    def close(self):
        self.fd.close()

    def __del__(self):
        self.close()

    def __findRootKey(self):
        self.fd.seek(0,0)
        data = self.fd.read(4096)
        while len(data) > 0:
            try:
                hbin = REG_HBIN(data[:0x20])
                # Read the remaining bytes for this hbin
                data += self.fd.read(hbin['OffsetNextHBin']-4096)
                data = data[0x20:]
                blocks = self.__processDataBlocks(data)
                for block in blocks:
                    if isinstance(block, REG_NK):
                        if block['Type'] == ROOT_KEY:
                            return block
            except:
                 pass
            data = self.fd.read(4096)

        return None


    def __getBlock(self, offset):
        self.fd.seek(4096+offset,0)
        sizeBytes = self.fd.read(4)
        data = sizeBytes + self.fd.read(unpack('<l',sizeBytes)[0]*-1-4)
        if len(data) == 0:
            return None
        else:
            block = REG_HBINBLOCK(data)
            if StructMappings.has_key(block['Data'][:2]):
                return StructMappings[block['Data'][:2]](block['Data'])
            else:
                LOG.debug("Unknown type 0x%s" % block['Data'][:2])
                return block
            return None

    def __getValueBlocks(self, offset, count):
        valueList = []
        res = []
        self.fd.seek(4096+offset,0)
        for i in range(count):
            valueList.append(unpack('<l',self.fd.read(4))[0])

        for valueOffset in valueList:
            if valueOffset > 0:
                block = self.__getBlock(valueOffset)
                res.append(block)
        return res

    def __getData(self, offset, count):
        self.fd.seek(4096+offset, 0)
        return self.fd.read(count)[4:]

    def __processDataBlocks(self,data):
        res = []
        while len(data) > 0:
            #blockSize = unpack('<l',data[:calcsize('l')])[0]
            blockSize = unpack('<l',data[:4])[0]
            block = REG_HBINBLOCK()
            if blockSize > 0:
                tmpList = list(block.structure)
                tmpList[1] = ('_Data','_-Data','self["DataBlockSize"]-4')
                block.structure =  tuple(tmpList)

            block.fromString(data)
            blockLen = len(block)

            if StructMappings.has_key(block['Data'][:2]):
                block = StructMappings[block['Data'][:2]](block['Data'])

            res.append(block)
            data = data[blockLen:]
        return res

    def __getValueData(self, rec):
        # We should receive a VK record
        if rec['DataLen'] == 0:
            return ''
        if rec['DataLen'] < 0:
            # if DataLen < 5 the value itself is stored in the Offset field
            return rec['OffsetData']
        else:
            return self.__getData(rec['OffsetData'], rec['DataLen']+4)

    def __getLhHash(self, key):
        res = 0
        for b in key.upper():
            res *= 37
            res += ord(b)
        return res % 0x100000000

    def __compareHash(self, magic, hashData, key):
        if magic == 'lf':
            hashRec = REG_HASH(hashData)
            if hashRec['KeyName'].strip('\x00') == key[:4]:
                return hashRec['OffsetNk']
        elif magic == 'lh':
            hashRec = REG_HASH(hashData)
            if unpack('<L',hashRec['KeyName'])[0] == self.__getLhHash(key):
                return hashRec['OffsetNk']
        elif magic == 'ri':
            # Special case here, don't know exactly why, an ri pointing to a NK :-o
            offset = unpack('<L', hashData[:4])[0]
            nk = self.__getBlock(offset)
            if nk['KeyName'] == key:
                return offset
        else:
            LOG.critical("UNKNOWN Magic %s" % magic)
            sys.exit(1)

        return None

    def __findSubKey(self, parentKey, subKey):
        lf = self.__getBlock(parentKey['OffsetSubKeyLf'])
        if lf is not None:
            data = lf['HashRecords']
            # Let's search the hash records for the name
            if lf['Magic'] == 'ri':
                # ri points to lf/lh records, so we must parse them before
                records = ''
                for i in range(lf['NumKeys']):
                    offset = unpack('<L', data[:4])[0]
                    l = self.__getBlock(offset)
                    records = records + l['HashRecords'][:l['NumKeys']*8]
                    data = data[4:]
                data = records

            #for record in range(lf['NumKeys']):
            for record in range(parentKey['NumSubKeys']):
                hashRec = data[:8]
                res = self.__compareHash(lf['Magic'], hashRec, subKey)
                if res is not None:
                    # We have a match, now let's check the whole record
                    nk = self.__getBlock(res)
                    if nk['KeyName'] == subKey:
                        return nk
                data = data[8:]

        return None

    def __walkSubNodes(self, rec):
        nk = self.__getBlock(rec['OffsetNk'])
        if isinstance(nk, REG_NK):
            print "%s%s" % (self.indent, nk['KeyName'])
            self.indent += '  '
            if nk['OffsetSubKeyLf'] < 0:
                self.indent = self.indent[:-2]
                return
            lf = self.__getBlock(nk['OffsetSubKeyLf'])
        else:
            lf = nk

        data = lf['HashRecords']

        if lf['Magic'] == 'ri':
            # ri points to lf/lh records, so we must parse them before
            records = ''
            for i in range(lf['NumKeys']):
                offset = unpack('<L', data[:4])[0]
                l = self.__getBlock(offset)
                records = records + l['HashRecords'][:l['NumKeys']*8]
                data = data[4:]
            data = records

        for key in range(lf['NumKeys']):
            hashRec = REG_HASH(data[:8])
            self.__walkSubNodes(hashRec)
            data = data[8:]

        if isinstance(nk, REG_NK):
            self.indent = self.indent[:-2]

    def walk(self, parentKey):
        key = self.findKey(parentKey)

        if key is None or key['OffsetSubKeyLf'] < 0:
            return

        lf = self.__getBlock(key['OffsetSubKeyLf'])
        data = lf['HashRecords']
        for record in range(lf['NumKeys']):
            hashRec = REG_HASH(data[:8])
            self.__walkSubNodes(hashRec)
            data = data[8:]

    def findKey(self, key):
        # Let's strip '\' from the beginning, except for the case of
        # only asking for the root node
        if key[0] == '\\' and len(key) > 1:
            key = key[1:]

        parentKey = self.rootKey
        if len(key) > 0 and key[0]!='\\':
            for subKey in key.split('\\'):
                res = self.__findSubKey(parentKey, subKey)
                if res is not None:
                    parentKey = res
                else:
                    #LOG.error("Key %s not found!" % key)
                    return None

        return parentKey

    def printValue(self, valueType, valueData):
        if valueType == REG_SZ or valueType == REG_EXPAND_SZ:
            if type(valueData) is int:
                print 'NULL'
            else:
                print "%s" % (valueData.decode('utf-16le'))
        elif valueType == REG_BINARY:
            print ''
            hexdump(valueData, self.indent)
        elif valueType == REG_DWORD:
            print "%d" % valueData
        elif valueType == REG_QWORD:
            print "%d" % (unpack('<Q',valueData)[0])
        elif valueType == REG_NONE:
            try:
                if len(valueData) > 1:
                    print ''
                    hexdump(valueData, self.indent)
                else:
                    print " NULL"
            except:
                print " NULL"
        elif valueType == REG_MULTISZ:
            print "%s" % (valueData.decode('utf-16le'))
        else:
            print "Unknown Type 0x%x!" % valueType
            hexdump(valueData)

    def enumKey(self, parentKey):
        res = []
        # If we're here.. we have a valid NK record for the key
        # Now let's searcht the subkeys
        if parentKey['NumSubKeys'] > 0:
            lf = self.__getBlock(parentKey['OffsetSubKeyLf'])
            data = lf['HashRecords']

            if lf['Magic'] == 'ri':
                # ri points to lf/lh records, so we must parse them before
                records = ''
                for i in range(lf['NumKeys']):
                    offset = unpack('<L', data[:4])[0]
                    l = self.__getBlock(offset)
                    records = records + l['HashRecords'][:l['NumKeys']*8]
                    data = data[4:]
                data = records

            for i in range(parentKey['NumSubKeys']):
                hashRec = REG_HASH(data[:8])
                nk = self.__getBlock(hashRec['OffsetNk'])
                data = data[8:]
                res.append('%s'%nk['KeyName'])
        return res

    def enumValues(self,key):
        # If we're here.. we have a valid NK record for the key
        # Now let's search its values
        resp = []
        if key['NumValues'] > 0:
            valueList = self.__getValueBlocks(key['OffsetValueList'], key['NumValues']+1)

            for value in valueList:
                if value['Flag'] > 0:
                    resp.append(value['Name'])
                else:
                    resp.append('default')

        return resp

    def getValue(self, keyValue):
        # returns a tuple with (ValueType, ValueData) for the requested keyValue
        regKey = ntpath.dirname(keyValue)
        regValue = ntpath.basename(keyValue)

        key = self.findKey(regKey)

        if key is None:
            return None

        if key['NumValues'] > 0:
            valueList = self.__getValueBlocks(key['OffsetValueList'], key['NumValues']+1)

            for value in valueList:
                if value['Name'] == regValue:
                    return value['ValueType'], self.__getValueData(value)
                elif regValue == 'default' and value['Flag'] <=0:
                    return value['ValueType'], self.__getValueData(value)

        return None

    def getClass(self, className):

        key = self.findKey(className)

        if key is None:
            return None

        #print key.dump()
        if key['OffsetClassName'] > 0:
            value = self.__getBlock(key['OffsetClassName'])
            return value['Data']

def pretty_print(x):
    if x in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
       return x
    else:
       return '.'

def hexdump(data, indent = ''):
    x=str(data)
    strLen = len(x)
    i = 0
    while i < strLen:
        print indent,
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

