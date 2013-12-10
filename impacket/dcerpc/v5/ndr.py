# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# [C706] Transfer NDR Syntax implementation
# 
# Author:
#
#     Alberto Solino
#
# ToDo:
# [ ] Unions and rest of the structured types
# [ ] Finalize documentation of NDR, especially the support for Arrays
#

import random
import inspect
from struct import *
from impacket import uuid
from impacket.winregistry import hexdump
from impacket.dcerpc.v5.enum import Enum

# Something important to have in mind:
# Diagrams do not depict the specified alignment gaps, which can appear in the octet stream
# before an item (see Section 14.2.2 on page 620.)
# Where necessary, an alignment gap, consisting of octets of unspecified value, *precedes* the 
# representation of a primitive. The gap is of the smallest size sufficient to align the primitive

class NDR(object):
    """
    This will be the base class for all DCERPC NDR Types.
    It changes the structure behaviour, plus it adds the possibility
    of specifying the NDR encoding to be used. Pads are automatically calculated
    Some data types are taken off as well.

        format specifiers:
          specifiers from module pack can be used with the same format 
          see struct.__doc__ (pack/unpack is finally called)
            c       [character]
            b       [signed byte]
            B       [unsigned byte]
            h       [signed short]
            H       [unsigned short]
            l       [signed long]
            L       [unsigned long]
            i       [signed integer]
            I       [unsigned integer]
            q       [signed long long (quad)]
            Q       [unsigned long long (quad)]
            f       [float]
            d       [double]
            =       [native byte ordering, size and alignment]
            @       [native byte ordering, standard size and alignment]
            !       [network byte ordering]
            <       [little endian]
            >       [big endian]

    """
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    align64        = 4
    debug          = False

    def __init__(self, data = None, isNDR64 = False):
        self._isNDR64 = isNDR64
        self.fields = {}
        self.data = None
        self.rawData = None

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
               self.fields[fieldName] = ''
            elif len(fieldTypeOrClass.split('=')) == 2: 
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = []

        if data is not None:
            self.fromString(data)
        else:
            self.data = None

        return None

    def __setitem__(self, key, value):
        if isinstance(value, NDRPointerNULL):
            self.fields[key] = value
        elif isinstance(value, NDR):
            # It's not a null pointer, ok. Another NDR type, but it 
            # must be the same same as the iteam already in place
            if self.fields[key].__class__.__name__ == value.__class__.__name__:
                self.fields[key] = value
            elif isinstance(self.fields[key]['Data'], NDR):
                if self.fields[key]['Data'].__class__.__name__ == value.__class__.__name__:
                    self.fields[key]['Data'] = value
                else:
                    print "Can't setitem with class specified, should be %s" % self.fields[key]['Data'].__class__.__name__
            else:
                print "Can't setitem with class specified, should be %s" % self.fields[key].__class__.__name__
        elif isinstance(self.fields[key], NDR):
            self.fields[key]['Data'] = value
        else:
            self.fields[key] = value
        self.data = None        # force recompute

    def __getitem__(self, key):
        if isinstance(self.fields[key], NDR):
            if self.fields[key].fields.has_key('Data'):
                return self.fields[key]['Data']
        return self.fields[key]

    def __str__(self):
        return self.getData()

    def __len__(self):
        # XXX: improve
        return len(self.getData())

    def getDataLen(self, data):
        return len(data)

    def isNDR(self, field):
        if self.debug:
            print "isNDR %r" % field, type(field),
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDR):
                if self.debug:
                    print "True"
                return True
        if self.debug:
            print 'False'
        return False

    def dumpRaw(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        print "\n%s" % (msg)
        for field in self.commonHdr+self.structure+self.referent:
            i = field[0] 
            if i in self.fields:
                if isinstance(self.fields[i], NDR):
                    self.fields[i].dumpRaw('%s%s:{' % (ind,i), indent = indent + 4)
                    print "%s}" % ind

                elif isinstance(self.fields[i], list):
                    print "%s[" % ind
                    for num,j in enumerate(self.fields[i]):
                       if isinstance(j, NDR):
                           j.dumpRaw('%s%s:' % (ind,i), indent = indent + 4)
                           print "%s," % ind
                       else:
                           print "%s%s: {%r}," % (ind, i, j)
                    print "%s]" % ind

                else:
                    print "%s%s: {%r}" % (ind,i,self[i])

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        for fieldName, fieldType in self.commonHdr+self.structure+self.referent:
            if fieldName in self.fields:
                if isinstance(self.fields[fieldName], NDR):
                    self.fields[fieldName].dump('\n%s%-31s' % (ind, fieldName+':'), indent = indent + 4),
                else:
                    print " %r" % (self[fieldName]),

    def calculatePad(self, fieldName, fieldType, data, soFar, packing):
        # PAD Calculation
        if self.debug:
            print "Calculate PAD: name: %s, type:%s, soFar:%d" % (fieldName, fieldType, soFar)
        alignment = 0
        size = 0
        if isinstance(self.fields[fieldName], NDR):
            alignment = self.fields[fieldName].align
        else:
            if fieldType == ':':
                return 0
            # Special case for arrays, fieldType is the array item type
            if len(fieldType.split('*')) == 2:
                if self.isNDR(self.item):
                    fieldType = ':'
                    # ToDo: Careful here.. I don't know this is right.. 
                    # But, if we're inside an array, data should be aligned already, by means
                    # of the previous fields
                    return 0
                else:
                    fieldType = self.item
            if packing:
                alignment = self.calcPackSize(fieldType, self.fields[fieldName])
            else:
                alignment = self.calcUnPackSize(fieldType, data)
        if alignment > 0 and alignment <= 8:
            # Ok, here we gotta see if we're aligned with the size of the field
            # we're about to unpack.
            #print "field: %s, soFar:%d, size:%d, align: %d " % (fieldName, soFar, size, alignment)
            alignment = (alignment - (soFar % alignment)) % alignment
        else:
            alignment = 0

        return alignment

    def getData(self, soFar = 0):
        data = ''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xbb'*pad
                    #data = data + '\x00'*pad

                data += self.pack(fieldName, fieldTypeOrClass, soFar)
                soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        self.data = data

        return data

    def getDataReferents(self, soFar = 0):
        data = ''
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure: 
            if isinstance(self.fields[fieldName], NDR):
               data += self.fields[fieldName].getDataReferents(len(data)+soFar)
               data += self.fields[fieldName].getDataReferent(len(data)+soFar)
        self.data = data
        return data

    def getDataReferent(self, soFar=0):
        data = ''
        soFar0 = soFar
        if hasattr(self,'referent') is False:
            return ''

        if self.fields.has_key('ReferentID'):
            if self['ReferentID'] == 0:
                return ''

        for fieldName, fieldTypeOrClass in self.referent:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xcc'*pad
                    #data = data + '\x00'*pad

                data += self.pack(fieldName, fieldTypeOrClass, soFar)
                soFar = soFar0 + len(data)
                # Any referent information to pack?
                if isinstance(self.fields[fieldName], NDR):
                    data += self.fields[fieldName].getDataReferents(soFar)
                soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        return data

    def fromString(self, data, soFar = 0):
        if self.rawData is None:
            self.rawData = data

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName])

                data = data[size:]
                soFar += size
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        return self

    def fromStringReferents(self, data, soFar = 0):
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            if isinstance(self.fields[fieldName], NDR):
                data = self.fields[fieldName].fromStringReferents(data, soFar)
                soFar += len(self.fields[fieldName].getDataReferents(soFar))
                data = self.fields[fieldName].fromStringReferent(data, soFar)
                soFar += len(self.fields[fieldName].getDataReferent(soFar))
        return data

    def fromStringReferent(self, data, soFar = 0):
        if hasattr(self, 'referent') is not True:
            return data

        if self.fields.has_key('ReferentID'):
            if self['ReferentID'] == 0:
                # NULL Pointer, there's no referent for it
                return data

        for fieldName, fieldTypeOrClass in self.referent:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = len(self.rawData) - len(data), packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size])
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

            if isinstance(self.fields[fieldName], NDR):
                size = len(self.fields[fieldName]) + len(self.fields[fieldName].getDataReferents())

            data = data[size:]
            soFar += size
        return data 

    def pack(self, fieldName, fieldTypeOrClass, soFar = 0):
        if self.debug:
            print "  pack( %s | %s )" %  (fieldName, fieldTypeOrClass)

        if isinstance(self.fields[fieldName], NDR):
            return self.fields[fieldName].getData(soFar)

        data = self.fields[fieldName]
        # void specifier
        if fieldTypeOrClass[:1] == '_':
            return ''

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            try:
                return self.pack(fieldName, two[0], soFar)
            except:
                self.fields[fieldName] = eval(two[1], {}, self.fields)
                return self.pack(fieldName, two[0], soFar)

        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            answer = ''
            if self.isNDR(self.item):
                item = ':'
                dataClass = self.item
                self.fields['_tmpItem'] = dataClass()
            else:
                item = self.item
                dataClass = None
                self.fields['_tmpItem'] = item

            for each in data:
                pad = self.calculatePad('_tmpItem', self.item, answer, len(answer)+soFar, packing = True)
                if pad > 0:
                    answer += '\xdd' * pad
                if dataClass is None:
                    answer += pack(item, each)
                else:
                    answer += each.getData(len(answer)+soFar)


            if dataClass is not None:
                for each in data:
                    pad = self.calculatePad('_tmpItem', self.item, answer, len(answer)+soFar, packing = True)
                    if pad > 0:
                        answer += '\xdd' * pad
                    answer += each.getDataReferents(len(answer)+soFar)
                    # ToDo, still to work out this
                    answer += each.getDataReferent(len(answer)+soFar)

            del(self.fields['_tmpItem'])
            self.fields[two[1]] = len(data)
            return answer

        if data is None:
            raise Exception, "Trying to pack None"
        
        # literal specifier
        if fieldTypeOrClass[:1] == ':':
            return str(data)

        # struct like specifier
        return pack(fieldTypeOrClass, data)

    def unpack(self, fieldName, fieldTypeOrClass, data, soFar = 0):
        if self.debug:
            print "  unpack( %s | %s | %r | %d)" %  (fieldName, fieldTypeOrClass, data, soFar)

        if isinstance(self.fields[fieldName], NDR):
            return self.fields[fieldName].fromString(data, soFar)

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.unpack(fieldName,two[0], data, soFar)

        # array specifier
        two = fieldTypeOrClass.split('*')
        answer = []
        soFarItems = 0
        if len(two) == 2:
            # First field points to a field with the amount of items
            numItems = self[two[1]]
            # The item type is determined by self.item
            if self.isNDR(self.item):
                item = ':'
                dataClassOrCode = self.item
                self.fields['_tmpItem'] = dataClassOrCode()
            else:
                item = self.item
                dataClassOrCode = None
                self.fields['_tmpItem'] = item

            nsofar = 0
            while numItems and soFarItems < len(data):
                pad = self.calculatePad('_tmpItem', self.item, data[soFar:], soFarItems+soFar, packing = False)
                if pad > 0:
                    soFarItems +=pad
                if dataClassOrCode is None:
                    nsofar = soFarItems + calcsize(item)
                    answer.append(unpack(item, data[soFarItems:nsofar])[0])
                else:
                    itemn = dataClassOrCode(data[soFarItems:])
                    itemn.rawData = data[soFarItems+len(itemn):] 
                    answer.append(itemn)
                    nsofar += len(itemn) + pad
                numItems -= 1
                soFarItems = nsofar

            pad = self.calculatePad('_tmpItem', self.item, data[soFarItems:], soFarItems+soFar, packing = False)
            if pad > 0:
                soFarItems +=pad

            if dataClassOrCode is not None:
                # We gotta go over again, asking for the referents
                data = data[soFarItems:]
                answer2 = []
                soFarItems = 0
                for itemn in answer:
                    pad = self.calculatePad('_tmpItem', self.item, data, soFarItems+soFar, packing = False)
                    if pad > 0:
                        data = data[pad:]
                    itemn.fromStringReferents(data)
                    # ToDo, still to work out this
                    itemn.fromStringReferent(data, soFar + soFarItems)
                    soFarItems = len(itemn.getDataReferents(len(data)+soFar))
                    itemn.rawData = data[len(itemn.getDataReferents(len(data)+soFar))+len(itemn.getDataReferent(len(data)+soFar)):] 
                    data = itemn.rawData
                    answer2.append(itemn)
                    numItems -= 1
                answer = answer2
                del(answer2)

            del(self.fields['_tmpItem'])
            return answer

        # literal specifier
        if fieldTypeOrClass == ':':
            if isinstance(fieldTypeOrClass, NDR):
                return self.fields[field].fromString(data, soFar)
            else:
                return data[:self.getDataLen(data)]

        # struct like specifier
        return unpack(fieldTypeOrClass, data)[0]

    def calcPackSize(self, fieldTypeOrClass, data):
        if self.debug:
            print "  calcPackSize  %s:%r" %  (fieldTypeOrClass, data)

        if isinstance(fieldTypeOrClass, str) is False:
            return len(data)

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.calcPackSize(two[0], data)

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

        # literal specifier
        if fieldTypeOrClass[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(fieldTypeOrClass)

    def calcUnPackSize(self, fieldTypeOrClass, data):
        if self.debug:
            print "  calcUnPackSize  %s:%r" %  (fieldTypeOrClass, data)

        if isinstance(fieldTypeOrClass, str) is False:
            return len(data)

        # code specifier
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.calcUnPackSize(two[0], data)

        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            return len(data)

        # literal specifier
        if fieldTypeOrClass[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(fieldTypeOrClass)

class NDRCall(NDR):
    # This represents a group of NDR instances that conforms an NDR Call. 
    # The only different between a regular NDR instance is a NDR call must 
    # represent the referents when building the final octet stream
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    align64        = 4
    debug          = False
    consistencyCheck = False
    def __init__(self, data = None, isNDR64 = False):
        #NDR.__init__(self,data, isNDR64, False) 
        self._isNDR64 = isNDR64
        self.fields = {}
        self.data = None
        self.rawData = None

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
        else:
            self.data = None

        return None

    def isPointer(self, field):
        if self.debug:
            print "isPointer %r" % field, type(field),
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRPointer):
                if self.debug:
                    print "True"
                return True
        if self.debug:
            print 'False'
        return False

    def dump(self, msg = None, indent = 0):
        NDR.dump(self, msg, indent)
        print '\n\n'

    def getData(self, soFar = 0):
        data = ''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xaa'*pad
                    #data = data + '\x00'*pad

                data += self.pack(fieldName, fieldTypeOrClass, len(data)+soFar)
                soFar = soFar0 + len(data)
                # Any referent information to pack?
                # I'm still not sure whether this should go after processing 
                # all the fields at the call level.
                # Guess we'll figure it out testing.
                if isinstance(self.fields[fieldName], NDR):
                    data += self.fields[fieldName].getDataReferents(soFar)
                    soFar = soFar0 + len(data)
                    data += self.fields[fieldName].getDataReferent(soFar)
                    soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        self.data = data

        return data

    def fromString(self, data, soFar = 0):
        if self.rawData is None:
            self.rawData = data

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName])
                    # Any referent information to unpack?
                    if isinstance(self.fields[fieldName], NDR):
                        res = self.fields[fieldName].fromStringReferents(data[size:], soFar+size)
                        self.fields[fieldName].fromStringReferent(data[size:])
                    size+= len(data[size:]) - len(res)

                data = data[size:]
                soFar += size
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        if self.consistencyCheck is True:
            res = self.getData()
            # Padding PDU to 4
            res = res + '\x00' * (4 - (len(res) & 3) & 3)
            # Stripping the return code, if it's there
            if res != self.rawData[:-4]:
                    print "Pack/Unpack doesnt match!"
                    print "UNPACKED"
                    hexdump(self.rawData)
                    print "PACKED"
                    hexdump(res)

        return self

# NDR Primitives

class NDRSMALL(NDR):
    align = 1
    structure = (
        ('Data', 'B=0'),
    )

NDRBOOLEAN = NDRSMALL

class NDRCHAR(NDR):
    align = 1
    structure = (
        ('Data', 'c'),
    )

class NDRSHORT(NDR):
    align = 2
    structure = (
        ('Data', '<H=0'),
    )

class NDRLONG(NDR):
    align = 4
    structure = (
        ('Data', '<L=0'),
    )

class NDRHYPER(NDR):
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

class NDRENUM(NDRSHORT):
    __metaclass__ = EnumType
    align = 2
    # enum MUST be an python enum (see enum.py)
    class enumItems(Enum):
        pass

    def __setitem__(self, key, value):
       if isinstance(value, Enum):
           self['Data'] = value.value
       else:
           return NDR.__setitem__(self,key,value)

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print msg,

        print " %s" % self.enumItems(self.fields['Data']).name

# NDR Constructed Types (arrays, strings, structures, unions, variant structures, pipes and pointers)

# Uni-dimensional Fixed Arrays
class NDRArray(NDR):
    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print msg,

        if isinstance(self['Data'], list):
            print "\n%s[" % ind
            ind += ' '*4
            for num,j in enumerate(self.fields['Data']):
               if isinstance(j, NDR):
                   j.dump('%s' % ind, indent = indent + 4),
                   print "," 
               else:
                   print "%s %r," % (ind,j)
            print "%s]" % ind[:-4],
        else:
            print " %r" % self['Data'],

class NDRUniFixedArray(NDRArray):
    structure = (
        ('Data',':'),
    )
        

# Uni-dimensional Conformant Arrays
class NDRUniConformantArray(NDRArray):
    item = 'c'
    structure = (
        ('MaximumCount', '<L=len(Data)'),
        ('Data', '*MaximumCount'),
    )

    structure64 = (
        ('MaximumCount', '<Q=len(Data)'),
        ('Data', '*MaximumCount'),
    )

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

# Uni-dimensional Conformant-varying Arrays
class NDRUniConformantVaryingArray(NDRArray):
    item = 'c'
    commonHdr = (
        ('MaximumCount', '<L=len(Data)'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
    )
    commonHdr64 = (
        ('MaximumCount', '<Q=len(Data)'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
    )

    structure = (
        ('Data','*ActualCount'),
    )

# Multidimensional arrays not implemented for now

# Varying Strings
class NDRVaryingString(NDRUniVaryingArray):
    def getData(self, soFar = 0):
        # The last element of a string is a terminator of the same size as the other elements. 
        # If the string element size is one octet, the terminator is a NULL character. 
        # The terminator for a string of multi-byte characters is the array element zero (0).
        if self["Data"][-1:] != '\x00':
            self["Data"] = ''.join(self["Data"]) + '\x00'
        return NDRUniVaryingArray.getData(self, soFar)

    def fromString(self, data, soFar = 0):
        ret = NDRUniVaryingArray.fromString(self,data, soFar = 0)
        # Let's take out the last item
        self["Data"] = self["Data"][:-1] 
        return ret

# Conformant and Varying Strings
class NDRConformantVaryingString(NDRUniConformantVaryingArray):
    pass

# Arrays of Strings not implemented for now

# Structures

# Structures Containing a Conformant Array not implemented for now

# Structures Containing a Conformant and Varying Array not implemented for now

# Unions 

class NDRUnion(NDR):
    align = 2
    commonHdr = (
        ('tag', NDRSHORT),
        #('SwitchValue', NDRLONG),
    )
    union = {
        # For example
        #1: ('pStatusChangeParam1', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_1),
        #2: ('pStatusChangeParams', PSERVICE_NOTIFY_STATUS_CHANGE_PARAMS_2),
    }
    def __init__(self, data = None, isNDR64=False):
        ret = NDR.__init__(self,None, isNDR64=isNDR64)
        if data is not None:
            self.fromString(self, data)

    def __setitem__(self, key, value):
        if key == 'tag':
            # We're writing the tag, we now should set the right item for the structure
            self.structure = ()
            if self.union.has_key(value):
                self.structure = (self.union[value]),
                # Init again the structure
                NDR.__init__(self, None, isNDR64=self._isNDR64)
                self.fields['tag']['Data'] = value
                #self.fields['SwitchValue']['Data'] = value
            else:
                raise Exception("Unknown tag %d for union!" % value)
        else:
            return NDR.__setitem__(self,key,value)

    def fromString(self, data, soFar = 0 ):
        if len(data) > 4:
            # First off, let's see what the tag is:
            # We need to know the tag type and unpack it
            tagtype = self.commonHdr[0][1].structure[0][1].split('=')[0]
            tag = unpack(tagtype, data[:calcsize(tagtype)])[0]
            if self.union.has_key(tag):
                self.structure = (self.union[tag]),
                NDR.__init__(self, None, isNDR64=self._isNDR64)
                return NDR.fromString(self, data, soFar)
            else:
                raise Exception("Unknown tag %d for union!" % tag)
        return NDR.fromString(self,data,soFar)

   
# Pipes not implemented for now

# Pointers

class NDRPointerNULL(NDR):
    align = 4
    align64 = 8
    structure = (
        ('Data', '<L=0'),
    )
    structure64 = (
        ('Data', '<Q=0'),
    )

NULL = NDRPointerNULL()

class NDRReferencePointer(NDR):
    structure = (
        # This is the representation of the Referent
        ('Data',':'),
    )

class NDRPointer(NDR):
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
        ret = NDR.__init__(self,None, isNDR64=isNDR64)
        # If we are being called from a NDRCall, it's a TopLevelPointer, 
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
        if self.fields.has_key(key) is False:
            # Key not found.. let's send it to the referent to handle, maybe it's there
            return self.fields['Data'].__setitem__(key,value)
        else:
            return NDR.__setitem__(self,key,value)

    def __getitem__(self, key):
        if self.fields.has_key(key):
            if isinstance(self.fields[key], NDR):
                if self.fields[key].fields.has_key('Data'):
                    return self.fields[key]['Data']
            return self.fields[key]
        else:
            # Key not found, let's send it to the referent, maybe it's there
            return self.fields['Data'].__getitem__(key)

    def getData(self, soFar = 0):
        # If we have a ReferentID == 0, means there's no data
        if self.fields['ReferentID'] == 0:
            if len(self.referent) > 0:
                self['Data'] = ''
            else:
                if self._isNDR64 is True:
                    return '\x00'*8
                else:
                    return '\x00'*4

        return NDR.getData(self, soFar)

    def fromString(self,data,soFar = 0):
        # Do we have a Referent ID == 0?
        if unpack('<L', data[:4])[0] == 0:
            self['ReferentID'] = 0
            self.fields['Data'] = ''
            return self
        else:
            return NDR.fromString(self,data, soFar)

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here we just print the referent
        if isinstance(self.fields['Data'], NDR):
            self.fields['Data'].dump('', indent = indent)
        else:
            print " %r" % (self['Data']),


# Embedded Reference Pointers not implemented for now

################################################################################
# Common RPC Data Types

class PNDRUniConformantVaryingArray(NDRPointer):
    referent = (
        ('Data', NDRUniConformantVaryingArray),
    )

class PNDRUniConformantArray(NDRPointer):
    referent = (
        ('Data', NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False, topLevel = False):
        NDRPointer.__init__(self,data,isNDR64,topLevel)
        
################################################################################
# Tests

class NDRTest:
    def create(self,data = None, isNDR64 = False):
        if data is not None:
            return self.theClass(data, isNDR64 = isNDR64)
        else:
            return self.theClass(isNDR64 = isNDR64)

    def test(self, isNDR64 = False):
        print
        print "-"*70
        testName = self.__class__.__name__
        print "starting test: %s (NDR64 = %s)....." % (testName, isNDR64)
        a = self.create(isNDR64 = isNDR64)
        self.populate(a)
        a.dump("packing.....")
        a_str = str(a)
        print "packed:" 
        hexdump(a_str)
        print "unpacking....."
        b = self.create(a_str, isNDR64 = isNDR64)
        b.dump("unpacked.....")
        print "\nrepacking....."
        b_str = str(b)
        if b_str != a_str:
            print "ERROR: original packed and repacked don't match"
            print "packed: " 
            hexdump(b_str)
            raise

    def run(self):
        self.test(False)
        # Now the same tests but with NDR64
        self.test(True)

class TestUniFixedArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array', NDRUniFixedArray),
        )
    def populate(self, a):
        a['Array'] = '12345678'

#class TestUniConformantArray(NDRTest):
#    class theClass(NDRCall):
#        structure = (
#            ('Array', PNDRUniConformantArray),
#            ('Array2', PNDRUniConformantArray),
#        )
#        def __init__(self, data = None,isNDR64 = False):
#            NDRCall.__init__(self, None, isNDR64)
#            self.fields['Array'].fields['Data'].item = RPC_UNICODE_STRING
#            self.fields['Array2'].fields['Data'].item = RPC_UNICODE_STRING
#            if data is not None:
#                self.fromString(data)
#        
#    def populate(self, a):
#        array = []
#        strstr = RPC_UNICODE_STRING()
#        strstr['Data'] = 'ThisIsMe'
#        array.append(strstr)
#        strstr = RPC_UNICODE_STRING()
#        strstr['Data'] = 'ThisIsYou'
#        array.append(strstr)
#        a['Array'] = array
#        a['Array2'] = array

class TestUniVaryingArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array', NDRUniVaryingArray),
        )
    def populate(self, a):
        a['Array'] = '12345678'

class TestUniConformantVaryingArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array', NDRUniConformantVaryingArray),
        )
    def populate(self, a):
        a['Array'] = '12345678'

class TestVaryingString(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array', NDRVaryingString),
        )
    def populate(self, a):
        a['Array'] = '12345678'

class TestConformantVaryingString(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array', NDRConformantVaryingString),
        )
        
    def populate(self, a):
        a['Array'] = '12345678'

class TestPointerNULL(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array', NDRPointerNULL),
        )
    def populate(self, a):
        pass

#class TestServerAuthenticate(NDRTest):
#    class NETLOGON_CREDENTIAL(NDR):
#        structure = (
#            ('Data','8s=""'),
#        )
#
#    class theClass(NDRCall):
#        class NETLOGON_CREDENTIAL(NDR):
#            structure = (
#                ('Data','8s=""'),
#            )
#        structure = (
#            ('PrimaryName', UNIQUE_RPC_UNICODE_STRING),
#            ('AccountName', RPC_UNICODE_STRING),
#            ('SecureChannelType',NDRSHORT),
#            ('ComputerName', RPC_UNICODE_STRING),
#            ('ClientCredential',NETLOGON_CREDENTIAL),
#            ('NegotiateFlags',NDRLONG),
#        )
#
#    def populate(self, a):
#        a['PrimaryName'] = 'XXX1DC001\x00'
#        a['AccountName'] = 'TEST-MACHINE$\x00'
#        a['SecureChannelType'] = 0xffff
#        a['ComputerName'] = 'TEST-MACHINE\x00'
#        a['ClientCredential']  = '12345678'
#        a['NegotiateFlags'] = 0xabcdabcd

if __name__ == '__main__':
    from impacket.dcerpc.netlogon import NETLOGON_CREDENTIAL
    TestUniFixedArray().run()
    #TestUniConformantArray().run()
    TestUniVaryingArray().run()
    TestUniConformantVaryingArray().run()
    TestVaryingString().run()
    TestConformantVaryingString().run()
    TestPointerNULL().run()
    #TestServerAuthenticate().run()
