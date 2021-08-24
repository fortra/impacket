# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [C706] Transfer NDR Syntax implementation
#
# Author:
#   Alberto Solino (@agsolino)
#
# ToDo:
#   [X] Unions and rest of the structured types
#   [ ] Documentation for this library, especially the support for Arrays
#
from __future__ import division
from __future__ import print_function
import random
import inspect
from struct import pack, unpack_from, calcsize
from six import with_metaclass, PY3

from impacket import LOG
from impacket.dcerpc.v5.enum import Enum
from impacket.uuid import uuidtup_to_bin

# Something important to have in mind:
# Diagrams do not depict the specified alignment gaps, which can appear in the octet stream
# before an item (see Section 14.2.2 on page 620.)
# Where necessary, an alignment gap, consisting of octets of unspecified value, *precedes* the
# representation of a primitive. The gap is of the smallest size sufficient to align the primitive

class NDR(object):
    """
    This will be the base class for all DCERPC NDR Types and represents a NDR Primitive Type
    """
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    item           = None
    _isNDR64       = False

    def __init__(self, data = None, isNDR64 = False):
        object.__init__(self)
        self._isNDR64 = isNDR64
        self.fields = {}

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if self.isNDR(fieldTypeOrClass):
               self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
            elif fieldTypeOrClass == ':':
               self.fields[fieldName] = b''
            elif len(fieldTypeOrClass.split('=')) == 2: 
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = []

        if data is not None:
            self.fromString(data)

    def changeTransferSyntax(self, newSyntax): 
        NDR64Syntax = uuidtup_to_bin(('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
        if newSyntax == NDR64Syntax:
            if self._isNDR64 is False:
                # Ok, let's change everything
                self._isNDR64 = True
                for fieldName in list(self.fields.keys()):
                    if isinstance(self.fields[fieldName], NDR):
                        self.fields[fieldName].changeTransferSyntax(newSyntax)
                # Finally, I change myself
                if self.commonHdr64 != ():
                    self.commonHdr = self.commonHdr64
                if self.structure64 != ():
                    self.structure = self.structure64
                if hasattr(self, 'align64'):
                    self.align = self.align64
                # And check whether the changes changed the data types
                # if so, I need to instantiate the new ones and copy the
                # old values
                for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
                    if isinstance(self.fields[fieldName], NDR):
                        if fieldTypeOrClass != self.fields[fieldName].__class__ and isinstance(self.fields[fieldName], NDRPOINTERNULL) is False:
                            backupData = self[fieldName]
                            self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
                            if 'Data' in self.fields[fieldName].fields:
                                self.fields[fieldName].fields['Data'] = backupData
                            else:
                                self[fieldName] = backupData
  
        else:
            if self._isNDR64 is True:
                # Ok, nothing for now
                raise Exception('Shouldn\'t be here')

    def __setitem__(self, key, value):
        if isinstance(value, NDRPOINTERNULL):
            value = NDRPOINTERNULL(isNDR64 = self._isNDR64)
            if isinstance(self.fields[key], NDRPOINTER):
                self.fields[key] = value
            elif 'Data' in self.fields[key].fields:
                if isinstance(self.fields[key].fields['Data'], NDRPOINTER):
                    self.fields[key].fields['Data'] = value
        elif isinstance(value, NDR):
            # It's not a null pointer, ok. Another NDR type, but it 
            # must be the same same as the iteam already in place
            if self.fields[key].__class__.__name__ == value.__class__.__name__:
                self.fields[key] = value
            elif isinstance(self.fields[key]['Data'], NDR):
                if self.fields[key]['Data'].__class__.__name__ == value.__class__.__name__:
                    self.fields[key]['Data'] = value
                else:
                    LOG.error("Can't setitem with class specified, should be %s" % self.fields[key]['Data'].__class__.__name__)
            else:
                LOG.error("Can't setitem with class specified, should be %s" % self.fields[key].__class__.__name__)
        elif isinstance(self.fields[key], NDR):
            self.fields[key]['Data'] = value
        else:
            self.fields[key] = value

    def __getitem__(self, key):
        if isinstance(self.fields[key], NDR):
            if 'Data' in self.fields[key].fields:
                return self.fields[key]['Data']
        return self.fields[key]

    def __str__(self):
        return self.getData()

    def __len__(self):
        # XXX: improve
        return len(self.getData())

    def getDataLen(self, data, offset=0):
        return len(data) - offset

    @staticmethod
    def isNDR(field):
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDR):
                return True
        return False

    def dumpRaw(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        print("\n%s" % msg)
        for field in self.commonHdr+self.structure+self.referent:
            i = field[0] 
            if i in self.fields:
                if isinstance(self.fields[i], NDR):
                    self.fields[i].dumpRaw('%s%s:{' % (ind,i), indent = indent + 4)
                    print("%s}" % ind)

                elif isinstance(self.fields[i], list):
                    print("%s[" % ind)
                    for num,j in enumerate(self.fields[i]):
                       if isinstance(j, NDR):
                           j.dumpRaw('%s%s:' % (ind,i), indent = indent + 4)
                           print("%s," % ind)
                       else:
                           print("%s%s: {%r}," % (ind, i, j))
                    print("%s]" % ind)

                else:
                    print("%s%s: {%r}" % (ind,i,self[i]))

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print("%s" % msg, end=' ')
        for fieldName, fieldType in self.commonHdr+self.structure+self.referent:
            if fieldName in self.fields:
                if isinstance(self.fields[fieldName], NDR):
                    self.fields[fieldName].dump('\n%s%-31s' % (ind, fieldName+':'), indent = indent + 4),
                else:
                    print(" %r" % (self[fieldName]), end=' ')

    def getAlignment(self):
        return self.align

    @staticmethod
    def calculatePad(fieldType, soFar):
        if isinstance(fieldType, str):
            try:
                alignment = calcsize(fieldType.split('=')[0])
            except:
                alignment = 0
        else:
            alignment = 0

        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
        else:
            pad = 0

        return pad

    def getData(self, soFar = 0):
        data = b''
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                # Alignment of Primitive Types

                # NDR enforces NDR alignment of primitive data; that is, any primitive of size n
                # octets is aligned at a octet stream index that is a multiple of n.
                # (In this version of NDR, n is one of {1, 2, 4, 8}.) An octet stream index indicates
                # the number of an octet in an octet stream when octets are numbered, beginning with 0,
                # from the first octet in the stream. Where necessary, an alignment gap, consisting of
                # octets of unspecified value, precedes the representation of a primitive. The gap is
                # of the smallest size sufficient to align the primitive.
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xbf'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)

                data += res
                soFar += len(res)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                # Alignment of Primitive Types

                # NDR enforces NDR alignment of primitive data; that is, any primitive of size n
                # octets is aligned at a octet stream index that is a multiple of n.
                # (In this version of NDR, n is one of {1, 2, 4, 8}.) An octet stream index indicates
                # the number of an octet in an octet stream when octets are numbered, beginning with 0,
                # from the first octet in the stream. Where necessary, an alignment gap, consisting of
                # octets of unspecified value, precedes the representation of a primitive. The gap is
                # of the smallest size sufficient to align the primitive.
                offset += self.calculatePad(fieldTypeOrClass, offset)

                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0

    def pack(self, fieldName, fieldTypeOrClass, soFar = 0):
        if isinstance(self.fields[fieldName], NDR):
            return self.fields[fieldName].getData(soFar)

        data = self.fields[fieldName]
        # void specifier
        if fieldTypeOrClass[:1] == '_':
            return b''

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            try:
                return self.pack(fieldName, two[0], soFar)
            except:
                self.fields[fieldName] = eval(two[1], {}, self.fields)
                return self.pack(fieldName, two[0], soFar)

        if data is None:
            raise Exception('Trying to pack None')

        # literal specifier
        if fieldTypeOrClass[:1] == ':':
            if hasattr(data, 'getData'):
                return data.getData()
            return data

        # struct like specifier
        return pack(fieldTypeOrClass, data)

    def unpack(self, fieldName, fieldTypeOrClass, data, offset=0):
        if isinstance(self.fields[fieldName], NDR):
            return self.fields[fieldName].fromString(data, offset)

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.unpack(fieldName, two[0], data, offset)

        # literal specifier
        if fieldTypeOrClass == ':':
            if isinstance(fieldTypeOrClass, NDR):
                return self.fields[fieldName].fromString(data, offset)
            else:
                dataLen = self.getDataLen(data, offset)
                self.fields[fieldName] =  data[offset:offset+dataLen]
                return dataLen

        # struct like specifier
        self.fields[fieldName] = unpack_from(fieldTypeOrClass, data, offset)[0]

        return calcsize(fieldTypeOrClass)

    def calcPackSize(self, fieldTypeOrClass, data):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data)

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.calcPackSize(two[0], data)

        # literal specifier
        if fieldTypeOrClass[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(fieldTypeOrClass)

    def calcUnPackSize(self, fieldTypeOrClass, data, offset=0):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data) - offset

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.calcUnPackSize(two[0], data, offset)

        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            return len(data) - offset

        # literal specifier
        if fieldTypeOrClass[:1] == ':':
            return len(data) - offset

        # struct like specifier
        return calcsize(fieldTypeOrClass)

# NDR Primitives
class NDRSMALL(NDR):
    align = 1
    structure = (
        ('Data', 'b=0'),
    )

class NDRUSMALL(NDR):
    align = 1
    structure = (
        ('Data', 'B=0'),
    )

class NDRBOOLEAN(NDRSMALL):
    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print(msg, end=' ')

        if self['Data'] > 0:
            print(" TRUE")
        else:
            print(" FALSE")

class NDRCHAR(NDR):
    align = 1
    structure = (
        ('Data', 'c'),
    )

class NDRSHORT(NDR):
    align = 2
    structure = (
        ('Data', '<h=0'),
    )

class NDRUSHORT(NDR):
    align = 2
    structure = (
        ('Data', '<H=0'),
    )

class NDRLONG(NDR):
    align = 4
    structure = (
        ('Data', '<l=0'),
    )

class NDRULONG(NDR):
    align = 4
    structure = (
        ('Data', '<L=0'),
    )

class NDRHYPER(NDR):
    align = 8
    structure = (
        ('Data', '<q=0'),
    )

class NDRUHYPER(NDR):
    align = 8
    structure = (
        ('Data', '<Q=0'),
    )

class NDRFLOAT(NDR):
    align = 4
    structure = (
        ('Data', '<f=0'),
    )

class NDRDOUBLEFLOAT(NDR):
    align = 8
    structure = (
        ('Data', '<d=0'),
    )

class EnumType(type):
    def __getattr__(self, attr):
        return self.enumItems[attr].value

class NDRENUM(with_metaclass(EnumType, NDR)):
    align = 2
    align64 = 4
    structure = (
        ('Data', '<H'),
    )

    # 2.2.5.2 NDR64 Simple Data Types
    # NDR64 supports all simple types defined by NDR (as specified in [C706] section 14.2)
    # with the same alignment requirements except for enumerated types, which MUST be 
    # represented as signed long integers (4 octets) in NDR64.
    structure64 = (
        ('Data', '<L'),
    )
    # enum MUST be an python enum (see enum.py)
    class enumItems(Enum):
        pass

    def __setitem__(self, key, value):
       if isinstance(value, Enum):
           self['Data'] = value.value
       else:
           return NDR.__setitem__(self,key,value)

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print(msg, end=' ')

        print(" %s" % self.enumItems(self.fields['Data']).name, end=' ')

# NDR Constructed Types (arrays, strings, structures, unions, variant structures, pipes and pointers)
class NDRCONSTRUCTEDTYPE(NDR):
    @staticmethod
    def isPointer(field):
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRPOINTER):
                return True
        return False

    @staticmethod
    def isUnion(field):
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRUNION):
                return True
        return False

    def getDataReferents(self, soFar = 0):
        data = b''
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
               data += self.fields[fieldName].getDataReferents(len(data)+soFar)
               data += self.fields[fieldName].getDataReferent(len(data)+soFar)
        return data

    def getDataReferent(self, soFar=0):
        data = b''
        soFar0 = soFar
        if hasattr(self,'referent') is False:
            return b''

        if 'ReferentID' in self.fields:
            if self['ReferentID'] == 0:
                return b''

        for fieldName, fieldTypeOrClass in self.referent:
            try:
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                    # So we have an array, first item in the structure must be the array size, although we
                    # will need to build it later.
                    if self._isNDR64:
                        arrayItemSize = 8
                        arrayPackStr = '<Q'
                    else:
                        arrayItemSize = 4
                        arrayPackStr = '<L'

                    # The size information is itself aligned according to the alignment rules for
                    # primitive data types. (See Section 14.2.2 on page 620.) The data of the constructed
                    # type is then aligned according to the alignment rules for the constructed type.
                    # In other words, the size information precedes the structure and is aligned
                    # independently of the structure alignment.
                    # We need to check whether we need padding or not
                    pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize
                    if pad0 > 0:
                        soFar += pad0
                        arrayPadding = b'\xef'*pad0
                    else:
                        arrayPadding = b''
                    # And now, let's pretend we put the item in
                    soFar += arrayItemSize
                    data = self.fields[fieldName].getData(soFar)
                    data = arrayPadding + pack(arrayPackStr, self.getArrayMaximumSize(fieldName)) + data
                else:
                    pad = self.calculatePad(fieldTypeOrClass, soFar)
                    if pad > 0:
                        soFar += pad
                        data += b'\xcc'*pad

                    data += self.pack(fieldName, fieldTypeOrClass, soFar)

                # Any referent information to pack?
                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    data += self.fields[fieldName].getDataReferents(soFar0 + len(data))
                    data += self.fields[fieldName].getDataReferent(soFar0 + len(data))
                soFar = soFar0 + len(data)

            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def calcPackSize(self, fieldTypeOrClass, data):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data)

        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            answer = 0
            for each in data:
                if self.isNDR(self.item):
                    item = ':'
                else:
                    item = self.item
                answer += self.calcPackSize(item, each)
            return answer
        else:
            return NDR.calcPackSize(self, fieldTypeOrClass, data)

    def getArrayMaximumSize(self, fieldName):
        if self.fields[fieldName].fields['MaximumCount'] is not None and self.fields[fieldName].fields['MaximumCount'] > 0:
            return self.fields[fieldName].fields['MaximumCount']
        else:
            return self.fields[fieldName].getArraySize()

    def getArraySize(self, fieldName, data, offset=0):
        if self._isNDR64:
            arrayItemSize = 8
            arrayUnPackStr = '<Q'
        else:
            arrayItemSize = 4
            arrayUnPackStr = '<L'

        pad = (arrayItemSize - (offset % arrayItemSize)) % arrayItemSize
        offset += pad

        if isinstance(self.fields[fieldName], NDRUniConformantArray):
            # Array Size is at the very beginning
            arraySize = unpack_from(arrayUnPackStr, data, offset)[0]
        elif isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
            # NDRUniConformantVaryingArray Array
            # Unpack the Maximum Count
            maximumCount = unpack_from(arrayUnPackStr, data, offset)[0]
            # Let's store the Maximum Count for later use
            self.fields[fieldName].fields['MaximumCount'] = maximumCount
            # Unpack the Actual Count
            arraySize = unpack_from(arrayUnPackStr, data, offset+arrayItemSize*2)[0]
        else:
            # NDRUniVaryingArray Array
            arraySize = unpack_from(arrayUnPackStr, data, offset+arrayItemSize)[0]

        return arraySize, arrayItemSize+pad

    def fromStringReferents(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                offset += self.fields[fieldName].fromStringReferents(data, offset)
                offset += self.fields[fieldName].fromStringReferent(data, offset)
        return offset - offset0

    def fromStringReferent(self, data, offset=0):
        if hasattr(self, 'referent') is not True:
            return 0

        offset0 = offset

        if 'ReferentID' in self.fields:
            if self['ReferentID'] == 0:
                # NULL Pointer, there's no referent for it
                return 0

        for fieldName, fieldTypeOrClass in self.referent:
            try:
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                    # Get the array size
                    arraySize, advanceStream = self.getArraySize(fieldName, data, offset)
                    offset += advanceStream

                    # Let's tell the array how many items are available
                    self.fields[fieldName].setArraySize(arraySize)
                    size = self.fields[fieldName].fromString(data, offset)
                else:
                    # ToDo: Align only if not NDR
                    offset += self.calculatePad(fieldTypeOrClass, offset)

                    size = self.unpack(fieldName, fieldTypeOrClass, data, offset)

                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    size += self.fields[fieldName].fromStringReferents(data, offset+size)
                    size += self.fields[fieldName].fromStringReferent(data, offset+size)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset-offset0

    def calcUnPackSize(self, fieldTypeOrClass, data, offset=0):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data) - offset

        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            return len(data) - offset
        else:
            return NDR.calcUnPackSize(self, fieldTypeOrClass, data, offset)

# Uni-dimensional Fixed Arrays
class NDRArray(NDRCONSTRUCTEDTYPE):
    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print(msg, end=' ')

        if isinstance(self['Data'], list):
            print("\n%s[" % ind)
            ind += ' '*4
            for num,j in enumerate(self.fields['Data']):
               if isinstance(j, NDR):
                   j.dump('%s' % ind, indent = indent + 4),
                   print(",") 
               else:
                   print("%s %r," % (ind,j))
            print("%s]" % ind[:-4], end=' ')
        else:
            print(" %r" % self['Data'], end=' ')

    def setArraySize(self, size):
        self.arraySize = size

    def getArraySize(self):
        return self.arraySize

    def changeTransferSyntax(self, newSyntax): 
        # Here we gotta go over each item in the array and change the TS 
        # Only if the item type is NDR
        if hasattr(self, 'item') and self.item is not None:
            if self.isNDR(self.item):
                for item in self.fields['Data']:
                    item.changeTransferSyntax(newSyntax)
        return NDRCONSTRUCTEDTYPE.changeTransferSyntax(self, newSyntax)

    def getAlignment(self):
        # Array alignment is the largest alignment of the array element type and 
        # the size information type, if any.
        align = 0
        # And now the item
        if hasattr(self, "item") and self.item is not None:
            if self.isNDR(self.item):
                tmpAlign = self.item().getAlignment()
            else:
                tmpAlign = self.calcPackSize(self.item, b'')
            if tmpAlign > align:
                align = tmpAlign
        return align

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.structure:
            try:
                if self.isNDR(fieldTypeOrClass) is False:
                    # If the item is not NDR (e.g. ('MaximumCount', '<L=len(Data)'))
                    # we have to align it
                    pad = self.calculatePad(fieldTypeOrClass, soFar)
                    if pad > 0:
                        soFar += pad
                        data += b'\xca'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def pack(self, fieldName, fieldTypeOrClass, soFar = 0):
        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            answer = b''
            if self.isNDR(self.item):
                item = ':'
                dataClass = self.item
                self.fields['_tmpItem'] = dataClass(isNDR64=self._isNDR64)
            else:
                item = self.item
                dataClass = None
                self.fields['_tmpItem'] = item

            for each in (self.fields[fieldName]):
                pad = self.calculatePad(self.item, len(answer)+soFar)
                if pad > 0:
                    answer += b'\xdd' * pad
                if dataClass is None:
                    if item == 'c' and PY3 and isinstance(each, int):
                        # Special case when dealing with PY3, here we have an integer we need to convert
                        each = bytes([each])
                    answer += pack(item, each)
                else:
                    answer += each.getData(len(answer)+soFar)

            if dataClass is not None:
                for each in self.fields[fieldName]:
                    if isinstance(each, NDRCONSTRUCTEDTYPE):
                        answer += each.getDataReferents(len(answer)+soFar)
                        answer += each.getDataReferent(len(answer)+soFar)

            del(self.fields['_tmpItem'])
            if isinstance(self, NDRUniConformantArray) or isinstance(self, NDRUniConformantVaryingArray):
                # First field points to a field with the amount of items
                self.setArraySize(len(self.fields[fieldName]))
            else:
                self.fields[two[1]] = len(self.fields[fieldName])

            return answer
        else:
            return NDRCONSTRUCTEDTYPE.pack(self, fieldName, fieldTypeOrClass, soFar)

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                if self.isNDR(fieldTypeOrClass) is False:
                    # If the item is not NDR (e.g. ('MaximumCount', '<L=len(Data)'))
                    # we have to align it
                    offset += self.calculatePad(fieldTypeOrClass, offset)

                size = self.unpack(fieldName, fieldTypeOrClass, data, offset)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0

    def unpack(self, fieldName, fieldTypeOrClass, data, offset=0):
        # array specifier
        two = fieldTypeOrClass.split('*')
        answer = []
        soFarItems = 0
        offset0 = offset
        if len(two) == 2:
            if isinstance(self, NDRUniConformantArray):
                # First field points to a field with the amount of items
                numItems = self.getArraySize()
            elif isinstance(self, NDRUniConformantVaryingArray):
                # In this case we have the MaximumCount but it could be different from the ActualCount.
                # Let's make the unpack figure this out.
                #self.fields['MaximumCount'] = self.getArraySize()
                numItems = self[two[1]]
            else:
                numItems = self[two[1]]

            # The item type is determined by self.item
            if self.isNDR(self.item):
                item = ':'
                dataClassOrCode = self.item
                self.fields['_tmpItem'] = dataClassOrCode(isNDR64=self._isNDR64)
            else:
                item = self.item
                dataClassOrCode = None
                self.fields['_tmpItem'] = item

            nsofar = 0
            while numItems and soFarItems < len(data) - offset:
                pad = self.calculatePad(self.item, soFarItems+offset)
                if pad > 0:
                    soFarItems +=pad
                if dataClassOrCode is None:
                    nsofar = soFarItems + calcsize(item)
                    answer.append(unpack_from(item, data, offset+soFarItems)[0])
                else:
                    itemn = dataClassOrCode(isNDR64=self._isNDR64)
                    size = itemn.fromString(data, offset+soFarItems)
                    answer.append(itemn)
                    nsofar += size + pad
                numItems -= 1
                soFarItems = nsofar

            if dataClassOrCode is not None and isinstance(dataClassOrCode(), NDRCONSTRUCTEDTYPE):
                # We gotta go over again, asking for the referents
                answer2 = []
                for itemn in answer:
                    size = itemn.fromStringReferents(data, soFarItems+offset)
                    soFarItems += size
                    size = itemn.fromStringReferent(data, soFarItems+offset)
                    soFarItems += size
                    answer2.append(itemn)
                answer = answer2
                del answer2

            del(self.fields['_tmpItem'])

            self.fields[fieldName] = answer
            return soFarItems + offset - offset0
        else:
            return NDRCONSTRUCTEDTYPE.unpack(self, fieldName, fieldTypeOrClass, data, offset)

class NDRUniFixedArray(NDRArray):
    structure = (
        ('Data',':'),
    )

# Uni-dimensional Conformant Arrays
class NDRUniConformantArray(NDRArray):
    item = 'c'
    structure = (
        #('MaximumCount', '<L=len(Data)'),
        ('Data', '*MaximumCount'),
    )

    structure64 = (
        #('MaximumCount', '<Q=len(Data)'),
        ('Data', '*MaximumCount'),
    )

    def __init__(self, data = None, isNDR64 = False):
        NDRArray.__init__(self, data, isNDR64)
        # Let's store the hidden MaximumCount field
        self.fields['MaximumCount'] = 0

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        return NDRArray.__setitem__(self, key, value)


# Uni-dimensional Varying Arrays
class NDRUniVaryingArray(NDRArray):
    item = 'c'
    structure = (
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
        ('Data','*ActualCount'),
    )
    structure64 = (
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
        ('Data','*ActualCount'),
    )

    def __setitem__(self, key, value):
        self.fields['ActualCount'] = None
        return NDRArray.__setitem__(self, key, value)

# Uni-dimensional Conformant-varying Arrays
class NDRUniConformantVaryingArray(NDRArray):
    item = 'c'
    commonHdr = (
        #('MaximumCount', '<L=len(Data)'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
    )
    commonHdr64 = (
        #('MaximumCount', '<Q=len(Data)'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
    )

    structure = (
        ('Data','*ActualCount'),
    )

    def __init__(self, data = None, isNDR64 = False):
        NDRArray.__init__(self, data, isNDR64)
        # Let's store the hidden MaximumCount field
        self.fields['MaximumCount'] = 0

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        self.fields['ActualCount'] = None
        return NDRArray.__setitem__(self, key, value)

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xcb'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

# Multidimensional arrays not implemented for now

# Varying Strings
class NDRVaryingString(NDRUniVaryingArray):
    def getData(self, soFar = 0):
        # The last element of a string is a terminator of the same size as the other elements. 
        # If the string element size is one octet, the terminator is a NULL character. 
        # The terminator for a string of multi-byte characters is the array element zero (0).
        if self["Data"][-1:] != b'\x00':
            if PY3 and isinstance(self["Data"],list) is False:
                self["Data"] = self["Data"] + b'\x00'
            else:
                self["Data"] = b''.join(self["Data"]) + b'\x00'
        return NDRUniVaryingArray.getData(self, soFar)

    def fromString(self, data, offset = 0):
        ret = NDRUniVaryingArray.fromString(self, data, offset)
        # Let's take out the last item
        self["Data"] = self["Data"][:-1] 
        return ret

# Conformant and Varying Strings
class NDRConformantVaryingString(NDRUniConformantVaryingArray):
    pass

# Structures
# Structures Containing a Conformant Array 
# Structures Containing a Conformant and Varying Array 
class NDRSTRUCT(NDRCONSTRUCTEDTYPE):
    def getData(self, soFar = 0):
        data = b''
        arrayPadding = b''
        soFar0 = soFar
        # 14.3.7.1 Structures Containing a Conformant Array
        # A structure can contain a conformant array only as its last member.
        # In the NDR representation of a structure that contains a conformant array, 
        # the unsigned long integers that give maximum element counts for dimensions of the array 
        # are moved to the beginning of the structure, and the array elements appear in place at 
        # the end of the structure.
        # 14.3.7.2 Structures Containing a Conformant and Varying Array
        # A structure can contain a conformant and varying array only as its last member.
        # In the NDR representation of a structure that contains a conformant and varying array, 
        # the maximum counts for dimensions of the array are moved to the beginning of the structure, 
        # but the offsets and actual counts remain in place at the end of the structure, 
        # immediately preceding the array elements
        lastItem = (self.commonHdr+self.structure)[-1][0]
        if isinstance(self.fields[lastItem], NDRUniConformantArray) or isinstance(self.fields[lastItem], NDRUniConformantVaryingArray):
            # So we have an array, first item in the structure must be the array size, although we
            # will need to build it later.
            if self._isNDR64:
                arrayItemSize = 8
                arrayPackStr = '<Q'
            else:
                arrayItemSize = 4
                arrayPackStr = '<L'

            # The size information is itself aligned according to the alignment rules for 
            # primitive data types. (See Section 14.2.2 on page 620.) The data of the constructed 
            # type is then aligned according to the alignment rules for the constructed type. 
            # In other words, the size information precedes the structure and is aligned 
            # independently of the structure alignment.
            # We need to check whether we need padding or not
            pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize 
            if pad0 > 0:
                soFar += pad0
                arrayPadding = b'\xee'*pad0
            else:
                arrayPadding = b''
            # And now, let's pretend we put the item in
            soFar += arrayItemSize
        else:
            arrayItemSize = 0

        # Now we need to align the structure 
        # The alignment of a structure in the octet stream is the largest of the alignments of the fields it
        # contains. These fields may also be constructed types. The same alignment rules apply 
        # recursively to nested constructed types.
        alignment = self.getAlignment()

        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
            if pad > 0:
                soFar += pad
                data += b'\xAB'*pad

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                    res = self.fields[fieldName].getData(soFar)
                    if isinstance(self, NDRPOINTER):
                        pointerData = data[:arrayItemSize]
                        data = data[arrayItemSize:]
                        data = pointerData + arrayPadding + pack(arrayPackStr ,self.getArrayMaximumSize(fieldName)) + data
                    else:
                        data = arrayPadding + pack(arrayPackStr, self.getArrayMaximumSize(fieldName)) + data
                    arrayPadding = b''
                    arrayItemSize = 0
                else:
                    res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data) + len(arrayPadding) + arrayItemSize
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        # 2.2.5.3.4.1 Structure with Trailing Gap
        # NDR64 represents a structure as an ordered sequence of representations of the
        # structure members. The trailing gap from the last nonconformant and nonvarying
        # field to the alignment of the structure MUST be represented as a trailing pad.
        # The size of the structure MUST be a multiple of its alignment.
        # See the following figure.

        # 4.8 Example of Structure with Trailing Gap in NDR64
        # This example shows a structure with a trailing gap in NDR64.
        #     typedef struct _StructWithPad
        #     {
        #         long l;
        #         short s;
        #     } StructWithPad;
        # The size of the structure in the octet stream MUST contain a 2-byte trailing
        # gap to make its size 8, a multiple of the structure's alignment, 4.
#        if self._isNDR64 is True:
#            # ToDo add trailing gap here
#            if alignment > 0:
#                pad = (alignment - (soFar % alignment)) % alignment
#                if pad > 0:
#                    soFar += pad
#                    data += '\xcd'*pad
#            print self.__class__ , alignment, pad, hex(soFar)
        return data

    def fromString(self, data, offset = 0 ):
        offset0 = offset
        # 14.3.7.1 Structures Containing a Conformant Array
        # A structure can contain a conformant array only as its last member.
        # In the NDR representation of a structure that contains a conformant array, 
        # the unsigned long integers that give maximum element counts for dimensions of the array 
        # are moved to the beginning of the structure, and the array elements appear in place at 
        # the end of the structure.
        # 14.3.7.2 Structures Containing a Conformant and Varying Array
        # A structure can contain a conformant and varying array only as its last member.
        # In the NDR representation of a structure that contains a conformant and varying array, 
        # the maximum counts for dimensions of the array are moved to the beginning of the structure, 
        # but the offsets and actual counts remain in place at the end of the structure, 
        # immediately preceding the array elements
        lastItem = (self.commonHdr+self.structure)[-1][0]

        # If it's a pointer, let's parse it here because
        # we are going to parse the next MaximumCount field(s) manually
        # when it's a Conformant or Conformant and Varying array
        if isinstance(self, NDRPOINTER):
            structureFields = self.structure

            alignment = self.getAlignment()
            if alignment > 0:
                offset += (alignment - (offset % alignment)) % alignment

            for fieldName, fieldTypeOrClass in self.commonHdr:
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
        else:
            structureFields = self.commonHdr+self.structure

        if isinstance(self.fields[lastItem], NDRUniConformantArray) or isinstance(self.fields[lastItem], NDRUniConformantVaryingArray):
            # So we have an array, first item in the structure must be the array size, although we
            # will need to build it later.
            if self._isNDR64:
                arrayItemSize = 8
                arrayUnPackStr = '<Q'
            else:
                arrayItemSize = 4
                arrayUnPackStr = '<L'

            # The size information is itself aligned according to the alignment rules for
            # primitive data types. (See Section 14.2.2 on page 620.) The data of the constructed 
            # type is then aligned according to the alignment rules for the constructed type. 
            # In other words, the size information precedes the structure and is aligned 
            # independently of the structure alignment.
            # We need to check whether we need padding or not
            offset += (arrayItemSize - (offset % arrayItemSize)) % arrayItemSize

            # And let's extract the array size for later use
            if isinstance(self.fields[lastItem], NDRUniConformantArray):
                # NDRUniConformantArray
                arraySize = unpack_from(arrayUnPackStr, data, offset)[0]
                self.fields[lastItem].setArraySize(arraySize)
            else:
                # NDRUniConformantVaryingArray
                maximumCount = unpack_from(arrayUnPackStr, data, offset)[0]
                self.fields[lastItem].fields['MaximumCount'] = maximumCount

            offset += arrayItemSize

        # Now we need to align the structure
        # The alignment of a structure in the octet stream is the largest of the alignments of the fields it
        # contains. These fields may also be constructed types. The same alignment rules apply 
        # recursively to nested constructed types.
        alignment = self.getAlignment()
        if alignment > 0:
            offset += (alignment - (offset % alignment)) % alignment

        for fieldName, fieldTypeOrClass in structureFields:
            try:
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset - offset0

    def getAlignment(self):
        # Alignment of Constructed Types
        #
        # NDR enforces NDR alignment of structured data. As with primitive data types, an alignment, n, is determined
        # for the structure. Where necessary, an alignment gap of octets of unspecified value precedes the data in
        # the NDR octet stream. This gap is the smallest size sufficient to align the first field of the structure
        # on an NDR octet stream index of n.

        # The rules for calculating the alignment of constructed types are as follows:

        # 1) If a conformant structure-that is, a conformant or conformant varying array, or a structure containing
        # a conformant or conformant varying array-is embedded in the constructed type, and is the outermost
        # structure-that is, is not contained in another structure-then the size information from the contained
        # conformant structure is positioned so that it precedes both the containing constructed type and any
        # alignment gap for the constructed type. (See Section 14.3.7 for information about structures containing
        # arrays.) The size information is itself aligned according to the alignment rules for primitive data
        # types. (See Section 14.2.2 on page 620.) The data of the constructed type is then aligned according to
        # the alignment rules for the constructed type. In other words, the size information precedes the structure
        # and is aligned independently of the structure alignment.

        # 2) The alignment of a structure in the octet stream is the largest of the alignments of the fields it
        # contains. These fields may also be constructed types. The same alignment rules apply recursively to nested
        # constructed types.

        align = 0
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if isinstance(self.fields[fieldName], NDR):
                tmpAlign = self.fields[fieldName].getAlignment()
            else:
                tmpAlign = self.calcPackSize(fieldTypeOrClass, b'')
            if tmpAlign > align:
                align = tmpAlign
        return align

# Unions 
class NDRUNION(NDRCONSTRUCTEDTYPE):
    commonHdr = (
        ('tag', NDRUSHORT),
    )
    commonHdr64 = (
        ('tag', NDRULONG),
    )
   
    union = {
        # For example
        #1: ('pStatusChangeParam1', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1),
        #2: ('pStatusChangeParams', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2),
    }
    def __init__(self, data = None, isNDR64=False, topLevel = False):
        #ret = NDR.__init__(self,None, isNDR64=isNDR64)
        self.topLevel = topLevel
        self._isNDR64 = isNDR64
        self.fields = {}

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if self.isNDR(fieldTypeOrClass):
               if self.isPointer(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = topLevel)
               elif self.isUnion(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = topLevel)
               else:
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
            elif fieldTypeOrClass == ':':
               self.fields[fieldName] = None
            elif len(fieldTypeOrClass.split('=')) == 2: 
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = 0

        if data is not None:
            self.fromString(data)

    def __setitem__(self, key, value):
        if key == 'tag':
            # We're writing the tag, we now should set the right item for the structure
            self.structure = ()
            if value in self.union:
                self.structure = (self.union[value]),
                # Init again the structure
                self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                self.fields['tag']['Data'] = value
            else:
                # Let's see if we have a default value
                if 'default' in self.union:
                    if self.union['default'] is None:
                        self.structure = ()
                    else:
                        self.structure = (self.union['default']),
                        # Init again the structure
                        self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                    self.fields['tag']['Data'] = 0xffff
                else:
                    raise Exception("Unknown tag %d for union!" % value)
        else:
            return NDRCONSTRUCTEDTYPE.__setitem__(self,key,value)

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar

        # Let's align ourselves
        alignment = self.getAlignment()
        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
        else:
            pad = 0
        if pad > 0:
            soFar += pad
            data += b'\xbc'*pad

        for fieldName, fieldTypeOrClass in self.commonHdr:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xbb'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        # WARNING
        # Now we need to align what's coming next.
        # This doesn't come from the documentation but from seeing the packets in the wire
        # for some reason, even if the next field is a SHORT, it should be aligned to
        # a DWORD, or HYPER if NDR64. 
        if self._isNDR64:
            align = 8
        else:
            if hasattr(self, 'notAlign'):
                align = 1
            else:
                align = 4

        pad = (align - (soFar % align)) % align
        if pad > 0:
            data += b'\xbd'*pad
            soFar += pad

        if self.structure == ():
            return data

        for fieldName, fieldTypeOrClass in self.structure:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xbe'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def fromString(self, data, offset=0):
        offset0 = offset
        # Let's align ourselves
        alignment = self.getAlignment()
        if alignment > 0:
            pad = (alignment - (offset % alignment)) % alignment
        else:
            pad = 0
        if pad > 0:
            offset += pad

        if len(data)-offset > 4:
            # First off, let's see what the tag is:
            # We need to know the tag type and unpack it
            tagtype = self.commonHdr[0][1].structure[0][1].split('=')[0]
            tag = unpack_from(tagtype, data, offset)[0]
            if tag in self.union:
                self.structure = (self.union[tag]),
                self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
            else:
                # Let's see if we have a default value
                if 'default' in self.union:
                    if self.union['default'] is None:
                        self.structure = ()
                    else:
                        self.structure = (self.union['default']),
                        # Init again the structure
                        self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                    self.fields['tag']['Data'] = 0xffff
                else:
                    raise Exception("Unknown tag %d for union!" % tag)

        for fieldName, fieldTypeOrClass in self.commonHdr:
            try:
                offset += self.calculatePad(fieldTypeOrClass, offset)
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        # WARNING
        # Now we need to align what's coming next.
        # This doesn't come from the documentation but from seeing the packets in the wire
        # for some reason, even if the next field is a SHORT, it should be aligned to
        # a DWORD, or HYPER if NDR64. 
        if self._isNDR64:
            align = 8
        else:
            if hasattr(self, 'notAlign'):
                align = 1
            else:
                align = 4

        offset += (align - (offset % align)) % align

        if self.structure == ():
            return offset-offset0

        for fieldName, fieldTypeOrClass in self.structure:
            try:
                offset += self.calculatePad(fieldTypeOrClass, offset)
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset - offset0

    def getAlignment(self):
        # Union alignment is the largest alignment of the union discriminator 
        # and all of the union arms.
        # WRONG, I'm calculating it just with the tag, if I do it with the 
        # arms I get bad stub data. Something wrong I'm doing or the standard
        # is wrong (most probably it's me :s )
        align = 0
        if self._isNDR64:
            fields =  self.commonHdr+self.structure
        else: 
            fields =  self.commonHdr
        for fieldName, fieldTypeOrClass in fields:
            if isinstance(self.fields[fieldName], NDR):
                tmpAlign = self.fields[fieldName].getAlignment()
            else:
                tmpAlign = self.calcPackSize(fieldTypeOrClass, b'')
            if tmpAlign > align:
                align = tmpAlign

        if self._isNDR64:
            for fieldName, fieldTypeOrClass in self.union.values():
                tmpAlign = fieldTypeOrClass(isNDR64 = self._isNDR64).getAlignment()
                if tmpAlign > align:
                    align = tmpAlign
        return align
   
# Pipes not implemented for now

# Pointers
class NDRPOINTERNULL(NDR):
    align = 4
    align64 = 8
    structure = (
        ('Data', '<L=0'),
    )
    structure64 = (
        ('Data', '<Q=0'),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
        # Here we just print NULL
        print(" NULL", end=' ')

NULL = NDRPOINTERNULL()

class NDRPOINTER(NDRSTRUCT):
    align = 4
    align64 = 8
    commonHdr = (
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('ReferentID','<Q=0xff'),
    )

    referent = (
        # This is the representation of the Referent
        ('Data',':'),
    )
    def __init__(self, data = None, isNDR64=False, topLevel = False):
        NDRSTRUCT.__init__(self,None, isNDR64=isNDR64)
        # If we are being called from a NDRCALL, it's a TopLevelPointer,
        # if not, it's a embeeded pointer.
        # It is *very* important, for every subclass of NDRPointer
        # you have to declare the referent in the referent variable
        # Not in the structure one!
        if topLevel is True:
            self.structure = self.referent
            self.referent = ()
       
        if data is None:
            self.fields['ReferentID'] = random.randint(1,65535)
        else:
           self.fromString(data)

    def __setitem__(self, key, value):
        if (key in self.fields) is False:
            # Key not found.. let's send it to the referent to handle, maybe it's there
            return self.fields['Data'].__setitem__(key,value)
        else:
            return NDRSTRUCT.__setitem__(self,key,value)

    def __getitem__(self, key):
        if key in self.fields:
            if isinstance(self.fields[key], NDR):
                if 'Data' in self.fields[key].fields:
                    return self.fields[key]['Data']
            return self.fields[key]
        else:
            # Key not found, let's send it to the referent, maybe it's there
            return self.fields['Data'].__getitem__(key)

    def getData(self, soFar = 0):
        # First of all we need to align ourselves
        data = b''
        pad = self.calculatePad(self.commonHdr[0][1], soFar)
        if pad > 0:
            soFar += pad
            data = b'\xaa'*pad
        # If we have a ReferentID == 0, means there's no data
        if self.fields['ReferentID'] == 0:
            if len(self.referent) > 0:
                self['Data'] = b''
            else:
                if self._isNDR64 is True:
                    return data+b'\x00'*8
                else:
                    return data+b'\x00'*4

        return data + NDRSTRUCT.getData(self, soFar)

    def fromString(self, data, offset=0):
        # First of all we need to align ourselves
        pad = self.calculatePad(self.commonHdr[0][1], offset)
        offset += pad

        # Do we have a Referent ID == 0?
        if self._isNDR64 is True:
            unpackStr = '<Q'
        else:
            unpackStr = '<L'

        if unpack_from(unpackStr, data, offset)[0] == 0:
            # Let's save the value
            self['ReferentID'] = 0
            self.fields['Data'] = b''
            if self._isNDR64 is True:
                return pad + 8
            else:
                return pad + 4
        else:
            retVal = NDRSTRUCT.fromString(self, data, offset)
            return retVal + pad

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
        # Here we just print the referent
        if isinstance(self.fields['Data'], NDR):
            self.fields['Data'].dump('', indent = indent)
        else:
            if self['ReferentID'] == 0:
                print(" NULL", end=' ')
            else:
                print(" %r" % (self['Data']), end=' ')

    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4


# Embedded Reference Pointers not implemented for now

################################################################################
# Common RPC Data Types

class PNDRUniConformantVaryingArray(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantVaryingArray),
    )

class PNDRUniConformantArray(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False, topLevel = False):
        NDRPOINTER.__init__(self,data,isNDR64,topLevel)

class NDRCALL(NDRCONSTRUCTEDTYPE):
    # This represents a group of NDR instances that conforms an NDR Call.
    # The only different between a regular NDR instance is a NDR call must
    # represent the referents when building the final octet stream
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    def __init__(self, data = None, isNDR64 = False):
        self._isNDR64 = isNDR64
        self.fields = {}

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if self.isNDR(fieldTypeOrClass):
               if self.isPointer(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = True)
               elif self.isUnion(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = True)
               else:
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
            elif fieldTypeOrClass == ':':
               self.fields[fieldName] = None
            elif len(fieldTypeOrClass.split('=')) == 2:
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = 0

        if data is not None:
            self.fromString(data)

    def dump(self, msg = None, indent = 0):
        NDRCONSTRUCTEDTYPE.dump(self, msg, indent)
        print('\n\n')

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xab'*pad

                # Are we dealing with an array?
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName],
                              NDRUniConformantVaryingArray):
                    # Align size item
                    if self._isNDR64:
                        pad = (8 - (soFar % 8)) % 8
                    else:
                        pad = (4 - (soFar % 4)) % 4
                    # Pack the item
                    res = self.pack(fieldName, fieldTypeOrClass, soFar+pad)
                    # Yes, get the array size
                    arraySize = self.getArrayMaximumSize(fieldName)
                    if self._isNDR64:
                        pad = (8 - (soFar % 8)) % 8
                        data += b'\xce'*pad + pack('<Q', arraySize) + res
                    else:
                        pad = (4 - (soFar % 4)) % 4
                        data += b'\xce'*pad + pack('<L', arraySize) + res
                else:
                    data += self.pack(fieldName, fieldTypeOrClass, soFar)

                soFar = soFar0 + len(data)
                # Any referent information to pack?
                # I'm still not sure whether this should go after processing
                # all the fields at the call level.
                # Guess we'll figure it out testing.
                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    data += self.fields[fieldName].getDataReferents(soFar)
                    soFar = soFar0 + len(data)
                    data += self.fields[fieldName].getDataReferent(soFar)
                    soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                # Are we dealing with an array?
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName],
                              NDRUniConformantVaryingArray):
                    # Yes, get the array size
                    arraySize, advanceStream = self.getArraySize(fieldName, data, offset)
                    self.fields[fieldName].setArraySize(arraySize)
                    offset += advanceStream

                size = self.unpack(fieldName, fieldTypeOrClass, data, offset)

                # Any referent information to unpack?
                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    size += self.fields[fieldName].fromStringReferents(data, offset+size)
                    size += self.fields[fieldName].fromStringReferent(data, offset+size)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset - offset0

# Top Level Struct == NDRCALL
NDRTLSTRUCT = NDRCALL

class UNKNOWNDATA(NDR):
    align = 1
    structure = (
        ('Data', ':'),
    )
