# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# [C706] Transfer NDR Syntax implementation
# 
# Author:
#
#     Alberto Solino
#
# ToDo:
# [X] Unions and rest of the structured types
# [ ] Documentation for this library, especially the support for Arrays
#

import random
import inspect
from struct import *
from impacket import uuid, LOG
from impacket.winregistry import hexdump
from impacket.dcerpc.v5.enum import Enum
from impacket.uuid import uuidtup_to_bin

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

    """
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    debug          = False
    _isNDR64       = False

    def __init__(self, data = None, isNDR64 = False):
        object.__init__(self)
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

    def changeTransferSyntax(self, newSyntax): 
        NDR64Syntax = uuidtup_to_bin(('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
        if newSyntax == NDR64Syntax:
            if self._isNDR64 is False:
                # Ok, let's change everything
                self._isNDR64 = True
                for fieldName in self.fields.keys():
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
                            if self.fields[fieldName].fields.has_key('Data'):
                                self.fields[fieldName].fields['Data'] = backupData
                            else:
                                self[fieldName] = backupData
  
        else:
            if self._isNDR64 is True:
                # Ok, nothing for now
                raise

    def __setitem__(self, key, value):
        if isinstance(value, NDRPOINTERNULL):
            value = NDRPOINTERNULL(isNDR64 = self._isNDR64)
            if isinstance(self.fields[key], NDRPOINTER):
                self.fields[key] = value
            elif self.fields[key].fields.has_key('Data'):
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

    def isPointer(self, field):
        if self.debug:
            print "isPointer %r" % field, type(field),
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRPOINTER):
                if self.debug:
                    print "True"
                return True
        if self.debug:
            print 'False'
        return False

    def isUnion(self, field):
        if self.debug:
            print "isUnion %r" % field, type(field),
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRUNION):
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

    def getAlignment(self):
        return self.align

    def calculatePad(self, fieldName, fieldType, data, soFar, packing):
        # PAD Calculation
        if self.debug:
            print "Calculate PAD: name: %s, type:%s, soFar:%d" % (fieldName, fieldType, soFar)
        alignment = 0
        size = 0
        if isinstance(self.fields[fieldName], NDR):
            alignment = self.fields[fieldName].getAlignment()
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
        pad0 = 0
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xbb'*pad
                    #data = data + '\x00'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
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
                    data += self.fields[fieldName].getDataReferent(len(data)+soFar)
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

        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName].getData(soFar))
                data = data[size:]
                soFar += size
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        return self

    def fromStringReferents(self, data, soFar = 0):
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            if isinstance(self.fields[fieldName], NDR):
                nSoFar = self.fields[fieldName].fromStringReferents(data, soFar)
                soFar += nSoFar
                nSoFar2 = self.fields[fieldName].fromStringReferent(data[nSoFar:], soFar)
                soFar += nSoFar2
                data = data[nSoFar+nSoFar2:]
        return soFar - soFar0

    def fromStringReferent(self, data, soFar = 0):
        if hasattr(self, 'referent') is not True:
            return 0

        soFar0 = soFar

        if self.fields.has_key('ReferentID'):
            if self['ReferentID'] == 0:
                # NULL Pointer, there's no referent for it
                return 0

        for fieldName, fieldTypeOrClass in self.referent:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

            if isinstance(self.fields[fieldName], NDR):
                size = len(self.fields[fieldName].getData(soFar))
                nSoFar = self.fields[fieldName].fromStringReferents(data[size:], soFar + size)
                nSoFar2 = self.fields[fieldName].fromStringReferent(data[size + nSoFar:], soFar + size + nSoFar)
                size += nSoFar + nSoFar2 
            data = data[size:]
            soFar += size

        return soFar-soFar0

    def pack(self, fieldName, fieldTypeOrClass, soFar = 0):
        if self.debug:
            print "  pack( %s | %s | %d )" %  (fieldName, fieldTypeOrClass, soFar)

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
                self.fields['_tmpItem'] = dataClass(isNDR64=self._isNDR64)
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
                    # ToDo: I'm not sure about commenting this
                    #pad = self.calculatePad('_tmpItem', self.item, answer, len(answer)+soFar, packing = True)
                    #if pad > 0:
                    #    answer += '\xda' * pad
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
                self.fields['_tmpItem'] = dataClassOrCode(isNDR64=self._isNDR64)
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
                    itemn = dataClassOrCode(isNDR64=self._isNDR64)
                    itemn.fromString(data[soFarItems:], soFar+soFarItems)
                    itemn.rawData = data[soFarItems+len(itemn.getData(soFar+soFarItems)):] 
                    answer.append(itemn)
                    nsofar += len(itemn.getData(soFarItems)) + pad
                numItems -= 1
                soFarItems = nsofar

            pad = self.calculatePad('_tmpItem', self.item, data[soFarItems:], soFarItems+soFar, packing = False)
            if pad > 0:
                soFarItems +=pad

            if dataClassOrCode is not None:
                # We gotta go over again, asking for the referents
                data = data[soFarItems:]
                answer2 = []
                #soFarItems = 0
                for itemn in answer:
                    # ToDo: I'm not sure about this is right
                    if self._isNDR64 is False:
                        pad = self.calculatePad('_tmpItem', self.item, data, soFarItems+soFar, packing = False)
                        if pad > 0:
                            soFarItems += pad
                            data = data[pad:]
                    nSoFar = itemn.fromStringReferents(data, soFarItems+soFar)
                    soFarItems += nSoFar
                    data = data[nSoFar:]
                    nSoFar2 = itemn.fromStringReferent(data, soFarItems+soFar)
                    soFarItems += nSoFar2
                    data = data[nSoFar2:]
                    answer2.append(itemn)
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

class NDRCALL(NDR):
    # This represents a group of NDR instances that conforms an NDR Call. 
    # The only different between a regular NDR instance is a NDR call must 
    # represent the referents when building the final octet stream
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    debug          = False
    consistencyCheck = False
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
        else:
            self.data = None

        return None

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

                data += self.pack(fieldName, fieldTypeOrClass, soFar)
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
                    size = len(self.fields[fieldName].getData(soFar))
                    # Any referent information to unpack?
                    if isinstance(self.fields[fieldName], NDR):
                        nSoFar = self.fields[fieldName].fromStringReferents(data[size:], soFar + size)
                        nSoFar2 = self.fields[fieldName].fromStringReferent(data[size + nSoFar:], soFar + size + nSoFar)
                        size += nSoFar + nSoFar2 

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
                    LOG.error("Pack/Unpack doesnt match!")
                    LOG.error("UNPACKED")
                    hexdump(self.rawData)
                    LOG.error("PACKED")
                    hexdump(res)

        return self

# Top Level Struct == NDRCALL 
NDRTLSTRUCT = NDRCALL

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
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print msg,

        if self['Data'] > 0:
            print " TRUE"
        else:
            print " FALSE"

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

class NDRENUM(NDR):
    __metaclass__ = EnumType
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
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print msg,

        print " %s" % self.enumItems(self.fields['Data']).name,

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

    def changeTransferSyntax(self, newSyntax): 
        # Here we gotta go over each item in the array and change the TS 
        # Only if the item type is NDR
        if hasattr(self, 'item'):
            if self.isNDR(self.item):
                for item in self.fields['Data']:
                    item.changeTransferSyntax(newSyntax)
        return NDR.changeTransferSyntax(self, newSyntax)

    def getAlignment(self):
        # Array alignment is the largest alignment of the array element type and 
        # the size information type, if any.
        tmpAlign = 0
        align = 0
        #for fieldName, fieldTypeOrClass in self.structure:
        ##    if isinstance(self.fields[fieldName], NDR):
        #        tmpAlign = self.fields[fieldName].getAlignment()
        #    else:
        #        tmpAlign = self.calcPackSize(fieldTypeOrClass, '')
        #    if tmpAlign > align:
        #        align = tmpAlign

        # And now the item
        if hasattr(self, "item"):
            if isinstance(self.item, NDR):
                tmpAlign = self.item.getAlignment()
            else:
                tmpAlign = self.calcPackSize(self.item, '')
            if tmpAlign > align:
                align = tmpAlign
        return align

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

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        self.data = None        # force recompute
        return NDRArray.__setitem__(self, key, value)

    def getDataArray(self, soFar = 0):
        # Since we're unpacking an array, the MaximumCount was already processed
        # hence, we don't have to calculate the pad again.
        data = ''
        soFar0 = soFar
        pad0 = 0
        fieldNum = 0
        for fieldName, fieldTypeOrClass in self.structure:
            try:
                if fieldNum > 0:
                    pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                    if pad > 0:
                        soFar += pad
                        data = data + '\xbb'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        self.data = data

        return data

    def fromStringArray(self, data, soFar = 0):
        # Since we're unpacking an array, the MaximumCount was already processed
        # hence, we don't have to calculate the pad again.
        if self.rawData is None:
            self.rawData = data

        soFar0 = soFar
        fieldNum = 0
        for fieldName, fieldTypeOrClass in self.structure:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            if fieldNum > 0:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
                if pad > 0:
                    soFar += pad
                    data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName].getData(soFar))
                data = data[size:]
                soFar += size
                fieldNum += 1
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        return self

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
        self.data = None        # force recompute
        return NDRArray.__setitem__(self, key, value)

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

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        self.fields['ActualCount'] = None
        self.data = None        # force recompute
        return NDRArray.__setitem__(self, key, value)

    def getDataArray(self, soFar = 0):
        # Since we're unpacking an array, the MaximumCount/Offset/ActualCount
        # was already processed
        # hence, we don't have to calculate the pad again.
        data = ''
        soFar0 = soFar
        pad0 = 0
        fieldNum = 0
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                if fieldNum > 1:
                    pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                    if pad > 0:
                        soFar += pad
                        data = data + '\xbb'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        self.data = data

        return data

    def fromStringArray(self, data, soFar = 0):
        # Since we're unpacking an array, the MaximumCount/Offset/ActualCount
        # was already processed
        # hence, we don't have to calculate the pad again.
        if self.rawData is None:
            self.rawData = data

        soFar0 = soFar
        fieldNum = 0
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            if fieldNum > 1:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
                if pad > 0:
                    soFar += pad
                    data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName].getData(soFar))
                data = data[size:]
                soFar += size
                fieldNum += 1
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        return self


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
        #ret = NDRUniVaryingArray.fromString(self,data, soFar = 0)
        ret = NDRUniVaryingArray.fromString(self,data)
        # Let's take out the last item
        self["Data"] = self["Data"][:-1] 
        return ret

# Conformant and Varying Strings
class NDRConformantVaryingString(NDRUniConformantVaryingArray):
    pass

# Structures
# Structures Containing a Conformant Array 
# Structures Containing a Conformant and Varying Array 
class NDRSTRUCT(NDR):
    # Now it does nothing, but we will need this to work on the NDR64 stuff
    # We should do this:
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
    def getData(self, soFar = 0):
        data = ''
        soFar0 = soFar
        pad0 = 0
        arrayPresent = False
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
            arrayPresent = True 
            if self._isNDR64:
                arrayItemSize = 8
            else:
                arrayItemSize = 4

            # The size information is itself aligned according to the alignment rules for 
            # primitive data types. (See Section 14.2.2 on page 620.) The data of the constructed 
            # type is then aligned according to the alignment rules for the constructed type. 
            # In other words, the size information precedes the structure and is aligned 
            # independently of the structure alignment.
            # We need to check whether we need padding or not
            pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize 
            if pad0 > 0:
                soFar += pad0
                arrayPadding = '\xee'*pad0
            else:
                arrayPadding = ''
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
                data = data + '\xAB'*pad
 
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xbb'*pad
                    #data = data + '\x00'*pad

                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                    # Okey.. here it is.. so we should remove the first arrayItemSize bytes from res
                    # and stick them at the beginning of the data, except when we're inside a pointer
                    # where we should go after the referent id
                    res = self.fields[fieldName].getDataArray(soFar)
                    arraySize = res[:arrayItemSize]
                    res = res[arrayItemSize:]
                    if isinstance(self, NDRPOINTER):
                        pointerData = data[:arrayItemSize]    
                        data = data[arrayItemSize:]
                        data = pointerData + arrayPadding + arraySize + data
                    else:
                        data = arrayPadding + arraySize + data
                    arrayItemSize = 0
                else:
                    res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data) + arrayItemSize
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        self.data = data

        return data

    def fromString(self, data, soFar = 0 ):
        if self.rawData is None:
            self.rawData = data

        soFar0 = soFar
        pad0 = 0
        arrayPresent = False
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
            arrayPresent = True 
            if self._isNDR64:
                arrayItemSize = 8
            else:
                arrayItemSize = 4

            # The size information is itself aligned according to the alignment rules for 
            # primitive data types. (See Section 14.2.2 on page 620.) The data of the constructed 
            # type is then aligned according to the alignment rules for the constructed type. 
            # In other words, the size information precedes the structure and is aligned 
            # independently of the structure alignment.
            # We need to check whether we need padding or not
            pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize 
            if pad0 > 0:
                soFar += pad0
                data = data[pad0:]
            # And now, let's pretend we put the item in
            soFar += arrayItemSize
            # And let's extract the array size for later use, if it is a pointer, it is after the referent ID
            if isinstance(self, NDRPOINTER):
                arraySize = data[arrayItemSize:][:arrayItemSize]
            else:
                arraySize = data[:arrayItemSize]
            # And move on data
            data = data[arrayItemSize:]

        # Now we need to align the structure 
        # The alignment of a structure in the octet stream is the largest of the alignments of the fields it
        # contains. These fields may also be constructed types. The same alignment rules apply 
        # recursively to nested constructed types.
        alignment = self.getAlignment()
        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
            if pad > 0:
                soFar += pad
                data = data[pad:]

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                size = self.calcUnPackSize(fieldTypeOrClass, data)
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
                if pad > 0:
                    soFar += pad
                    data = data[pad:]

                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                    # Okey.. here it is.. so we should add the first arrayItemSize bytes to data
                    # and move from there
                    data = arraySize + data
                    # and substract soFar times arrayItemSize (that we already counted at the beggining)
                    soFar -= arrayItemSize
                    # and add sizeItemSize to the size variable
                    size += arrayItemSize
                    self.fields[fieldName].fromStringArray(data[:size], soFar)
                else:
                    self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName].getData(soFar))
                data = data[size:]
                soFar += size
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        return self

    def getAlignment(self):
        tmpAlign = 0
        align = 0
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if isinstance(self.fields[fieldName], NDR):
                tmpAlign = self.fields[fieldName].getAlignment()
            else:
                tmpAlign = self.calcPackSize(fieldTypeOrClass, '')
            if tmpAlign > align:
                align = tmpAlign
        return align

# Unions 
class NDRUNION(NDR):
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
        else:
            self.data = None

        return None

    def __setitem__(self, key, value):
        if key == 'tag':
            # We're writing the tag, we now should set the right item for the structure
            self.structure = ()
            if self.union.has_key(value):
                self.structure = (self.union[value]),
                # Init again the structure
                self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                self.fields['tag']['Data'] = value
            else:
                # Let's see if we have a default value
                if self.union.has_key('default'):
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
            return NDR.__setitem__(self,key,value)

    def getData(self, soFar = 0):
        data = ''
        soFar0 = soFar
        pad0 = 0
        for fieldName, fieldTypeOrClass in self.commonHdr:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xbb'*pad
                    #data = data + '\x00'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
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
            data = data + '\xbb'*pad
            soFar += pad

        if self.structure is ():
            self.data = data
            return data

        for fieldName, fieldTypeOrClass in self.structure:
            try:
                pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar, packing = True)
                if pad > 0:
                    soFar += pad
                    data = data + '\xbb'*pad
                    #data = data + '\x00'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception, e:
                if self.fields.has_key(fieldName):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (fieldName, fieldTypeOrClass, self.fields[fieldName], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__),)
                raise

        self.data = data

        return data

    def fromString(self, data, soFar = 0 ):
        if len(data) > 4:
            # First off, let's see what the tag is:
            # We need to know the tag type and unpack it
            tagtype = self.commonHdr[0][1].structure[0][1].split('=')[0]
            tag = unpack(tagtype, data[:calcsize(tagtype)])[0]
            if self.union.has_key(tag):
                self.structure = (self.union[tag]),
                self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
            else:
                # Let's see if we have a default value
                if self.union.has_key('default'):
                    if self.union['default'] is None:
                        self.structure = ()
                    else:
                        self.structure = (self.union['default']),
                        # Init again the structure
                        self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                    self.fields['tag']['Data'] = 0xffff
                else:
                    raise Exception("Unknown tag %d for union!" % tag)

        if self.rawData is None:
            self.rawData = data

        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName].getData(soFar))
                data = data[size:]
                soFar += size
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
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
            data = data[pad:]
            soFar += pad

        if self.structure is ():
            return self

        for fieldName, fieldTypeOrClass in self.structure:
            size = self.calcUnPackSize(fieldTypeOrClass, data)
            pad = self.calculatePad(fieldName, fieldTypeOrClass, data, soFar = soFar, packing = False)
            if pad > 0:
                soFar += pad
                data = data[pad:]
            try:
                self.fields[fieldName] = self.unpack(fieldName, fieldTypeOrClass, data[:size], soFar)
                if isinstance(self.fields[fieldName], NDR):
                    size = len(self.fields[fieldName].getData(soFar))
                data = data[size:]
                soFar += size
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (fieldName, fieldTypeOrClass, data, size),)
                raise

        return self

    def getAlignment(self):
        # Union alignment is the largest alignment of the union discriminator 
        # and all of the union arms.
        # WRONG, I'm calculating it just with the tag, if I do it with the 
        # arms I get bad stub data. Something wrong I'm doing or the standard
        # is wrong (most probably it's me :s )
        tmpAlign = 0
        align = 0
        if self._isNDR64:
            fields =  self.commonHdr+self.structure
        else: 
            fields =  self.commonHdr
        for fieldName, fieldTypeOrClass in fields:
            if isinstance(self.fields[fieldName], NDR):
                tmpAlign = self.fields[fieldName].getAlignment()
            else:
                tmpAlign = self.calcPackSize(fieldTypeOrClass, '')
            if tmpAlign > align:
                align = tmpAlign

        if self._isNDR64:
            for fieldName, fieldTypeOrClass in self.union.itervalues():
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
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print "%s" % (msg),
        # Here we just print NULL
        print " NULL",

NULL = NDRPOINTERNULL()

class NDRPOINTER(NDR):
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
            if self['ReferentID'] == 0:
                print " NULL",
            else:
                print " %r" % (self['Data']),


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
            ('Array', NDRPOINTERNULL),
        )
    def populate(self, a):
        pass

if __name__ == '__main__':
    TestUniFixedArray().run()
    #TestUniConformantArray().run()
    TestUniVaryingArray().run()
    TestUniConformantVaryingArray().run()
    TestVaryingString().run()
    TestConformantVaryingString().run()
    TestPointerNULL().run()
