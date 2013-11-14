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
from impacket import structure
from impacket.structure import Structure
from impacket.winregistry import hexdump

# Something important to have in mind:
# Diagrams do not depict the specified alignment gaps, which can appear in the octet stream
# before an item (see Section 14.2.2 on page 620.)
# Where necessary, an alignment gap, consisting of octets of unspecified value, *precedes* the 
# representation of a primitive. The gap is of the smallest size sufficient to align the primitive

class NDR(Structure):
    """
    This will be the base class for all DCERPC NDR Types.
    It changes slightly the structure behaviour, plus it adds the possibility
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
    referent = ()
    commonHdr = ()
    commonHdr64 = ()
    structure = ()
    structure64 = ()
    align = 0
    align64 = 0

    def __init__(self, data = None, alignment = 0, isNDR64 = False):
        Structure.__init__(self)
        self.__isNDR64 = isNDR64

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for field in self.commonHdr+self.structure+self.referent:
            if len(field) == 3:
                if self.isNDR(field[2]):
                    self.fields[field[0]] = field[2](isNDR64 = self.__isNDR64)
            elif len(field) == 2:
                if field[1] == ':':
                    self.fields[field[0]] = ''

        self.rawData = None

        if data is not None:
            self.fromString(data)
        else:
            self.data = None

        return None

    def dump(self, msg = None, indent = 0):
        import types
        if msg is None: msg = self.__class__.__name__
        ind = ' '*indent
        print "\n%s" % (msg)
        fixedFields = []
        for field in self.commonHdr+self.structure:
            i = field[0] 
            if i in self.fields:
                fixedFields.append(i)
                if isinstance(self[i], Structure):
                    self[i].dump('%s%s:{' % (ind,i), indent = indent + 4)
                    print "%s}" % ind
                elif isinstance(self[i], list):
                    print "%s[" % ind
                    for num,j in enumerate(self[i]):
                       if isinstance(j, Structure):
                           j.dump('%s%s:' % (ind,i), indent = indent + 4)
                           print "%s," % ind
                       else:
                           print "%s%s: {%r}," % (ind, i, j)
                    print "%s]" % ind
                else:
                    print "%s%s: {%r}" % (ind,i,self[i])
        # Do we have remaining fields not defined in the structures? let's 
        # print them
        remainingFields = list(set(self.fields) - set(fixedFields))
        for i in remainingFields:
            if isinstance(self[i], Structure):
                self[i].dump('%s%s:{' % (ind,i), indent = indent + 4)
                print "%s}" % ind
            else:
                print "%s%s: {%r}" % (ind,i,self[i])

    def isNDR(self, field):
        #print "isNDR %r" % field, type(field)
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDR):
                return True
        return False

    def calculatePad(self, fieldName, fieldType, fieldLen, data, soFar):
        # PAD Calculation
        #print "Calculate PAD: name: %s, type:%s, fieldLen:%d, soFar:%d" % (fieldName, fieldType, fieldLen, soFar)
        alignment = 0
        size = 0
        if fieldType == ':' and fieldLen > 2:
            try:
                alignment = self[fieldName].align
            except: 
                alignment = 0
 
        elif fieldType == ':' and fieldLen == 2:
            # For manual string input we don't compute pads
            alignment = 0
        else:
            #size = self.calcUnpackSize(fieldType, data, fieldName)
            # Special case for arrays, fieldType is the array item type
            if len(fieldType.split('*')) == 2:
                if self.isNDR(self.item):
                    fieldType = ':'
                else:
                    fieldType = self.item
            size = self.calcPackSize(fieldType, data, fieldName)
            alignment = size

        if alignment > 0 and alignment <= 8:
            # Ok, here we gotta see if we're aligned with the size of the field
            # we're about to unpack.
            #print "field: %s, soFar:%d, size:%d, align: %d " % (fieldName, soFar, size, alignment)
            pad = (alignment - (soFar % alignment)) % alignment
            return pad
        else:
            alignment = 0

        return alignment

    def getData(self):
        if self.data is not None:
            return self.data

        data = ''
        for field in self.commonHdr+self.structure:
            try:
                #size = self.calcUnpackSize(field[1], data, field[0])
                pad = self.calculatePad(field[0], field[1], len(field), data, len(data))
                if pad > 0:
                    data = data + '\xbb'*pad

                data += self.packField(field[0], field[1])
            except Exception, e:
                if self.fields.has_key(field[0]):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (field[0], field[1], self[field[0]], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (field[0], field[1], self.__class__),)
                raise

        data += self.getReferentData()
        return data

    def getStaticDataLen(self):
        return len(Structure.getData(self))

    def getReferentData(self):
        data = ''
        for field in self.commonHdr+self.structure:
            if len(field) == 3:
                if self.isNDR(field[2]):
                   data += self[field[0]].getReferents()
        return data

    def getReferents(self):
        if hasattr(self,'referent') is False:
            return ''

        if self.fields.has_key('ReferentID'):
            if self['ReferentID'] == 0:
                return ''

        data = ''
        for field in self.referent:
            try:
                pad = self.calculatePad(field[0], field[1], len(field), data, len(data))
                if pad > 0:
                    data = data + '\xbb'*pad

                data += self.packField(field[0], field[1])
            except Exception, e:
                if self.fields.has_key(field[0]):
                    e.args += ("When packing field '%s | %s | %r' in %s" % (field[0], field[1], self[field[0]], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (field[0], field[1], self.__class__),)
                raise
        return data

    def fromString(self, data):
        if self.rawData is None:
            self.rawData = data

        for field in self.commonHdr+self.structure:
            size = self.calcUnpackSize(field[1], data, field[0])
            pad = self.calculatePad(field[0], field[1], len(field), data, soFar = len(self.rawData) - len(data))
            if pad > 0:
                data = data[pad:]

            dataClassOrCode = str

            if len(field) > 2:
                dataClassOrCode = field[2]
            try:
                self[field[0]] = self.unpack(field[1], data[:size], dataClassOrCode = dataClassOrCode, field = field[0])
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (field[0], field[1], data, size),)
                raise

            size = self.calcPackSize(field[1], self[field[0]], field[0])
            data = data[size:]

        #data = data[self.getStaticDataLen():]
        for field in self.commonHdr+self.structure:
            if len(field) == 3:
                if self.isNDR(field[2]):
                    data = self[field[0]].fromStringReferent(data)
        return self

    def fromStringReferent(self, data):
        if hasattr(self, 'referent') is not True:
            return

        if self.fields.has_key('ReferentID'):
            if self['ReferentID'] == 0:
                # NULL Pointer, there's no referent for it
                return

        for field in self.referent:
            if self.debug:
                print "fromString( %s | %s | %r )" % (field[0], field[1], data)
            pad = self.calculatePad(field[0], field[1], len(field), data, soFar = len(self.rawData) - len(data))
            if pad > 0:
                data = data[pad:]
            size = self.calcUnpackSize(field[1], data, field[0])
            dataClassOrCode = str
            if len(field) > 2:
                dataClassOrCode = field[2]
            try:
                self[field[0]] = self.unpack(field[1], data[:size], dataClassOrCode = dataClassOrCode, field = field[0])
            except Exception,e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (field[0], field[1], data, size),)
                raise

            size = self.calcPackSize(field[1], self[field[0]], field[0])
            data = data[size:]
        return data 

    def pack(self, format, data, field = None):
        if self.debug:
            print "  pack( %s | %r | %s)" %  (format, data, field)

        if field:
            addressField = self.findAddressFieldFor(field)
            if (addressField is not None) and (data is None):
                return ''

        # void specifier
        if format[:1] == '_':
            return ''

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return format[1:]

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            try:
                return self.pack(two[0], data)
            except:
                fields = {'self':self}
                fields.update(self.fields)
                return self.pack(two[0], eval(two[1], {}, fields))

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            try:
                return self.pack(two[0],data)
            except:
                return self.pack(two[0], self.calcPackFieldSize(two[1]))

        # array specifier
        two = format.split('*')
        if len(two) == 2:
            answer = ''
            if self.isNDR(self.item):
                item = ':'
                dataClass = self.item
            else:
                item = self.item
                dataClass = None

            for each in data:
                if dataClass is None:
                    answer += self.pack(item, each)
                else:
                    answer += each.getData()
                    answer += each.getReferents()

            self[two[1]] = len(data)
            return answer

        if data is None:
            raise Exception, "Trying to pack None"
        
        # literal specifier
        if format[:1] == ':':
            return str(data)

        # struct like specifier
        return pack(format, data)

    def unpack(self, format, data, dataClassOrCode = str, field = None):
        if self.debug:
            print "  unpack( %s | %r )" %  (format, data)

        if field:
            addressField = self.findAddressFieldFor(field)
            if addressField is not None:
                if not self[addressField]:
                    return

        # void specifier
        if format[:1] == '_':
            if dataClassOrCode != str:
                fields = {'self':self, 'inputDataLeft':data}
                fields.update(self.fields)
                return eval(dataClassOrCode, {}, fields)
            else:
                return None

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            answer = format[1:]
            if answer != data:
                raise Exception, "Unpacked data doesn't match constant value '%r' should be '%r'" % (data, answer)
            return answer

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            return self.unpack(two[0],data)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            return self.unpack(two[0],data)

        # array specifier
        two = format.split('*')
        answer = []
        soFar = 0
        if len(two) == 2:
            # First field points to a field with the amount of items
            numItems = self[two[1]]
            # The item type is determined by self.item
            if self.isNDR(self.item):
                item = ':'
                dataClassOrCode = self.item
            else:
                item = self.item
                dataClassOrCode = None
            nsofar = 0
            while numItems and soFar < len(data):
                if dataClassOrCode is None:
                    nsofar = soFar + self.calcUnpackSize(item,data[soFar:])
                    answer.append(self.unpack(item, data[soFar:nsofar], dataClassOrCode))
                else:
                    itemn = dataClassOrCode(data[soFar:])
                    itemn.rawData = data[soFar+len(itemn):] 
                    itemn.fromStringReferent(data[soFar+len(itemn):])
                    answer.append(itemn)
                    nsofar += len(itemn)
                numItems -= 1
                soFar = nsofar
            return answer

        # literal specifier
        if format == ':':
            if self.isNDR(dataClassOrCode):
                #if dataClassOrCode != str:
                #    largo = 3
                #else:
                #    largo = 2
                #pad = self.calculatePad(field, format, largo, data, soFar = (len(self.rawData) - len(data)))
                #print "PAD ", pad
                return self[field].fromString(data)
            else:
                return dataClassOrCode(data)

        # struct like specifier
        return unpack(format, data)[0]

    def calcPackSize(self, format, data, field = None):
        #print "  calcPackSize  %s:%r" %  (format, data)
        if field:
            addressField = self.findAddressFieldFor(field)
            if addressField is not None:
                if not self[addressField]:
                    return 0

        # void specifier
        if format[:1] == '_':
            return 0

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return len(format)-1

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            return self.calcPackSize(two[0], data)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            return self.calcPackSize(two[0], data)

        # array specifier
        two = format.split('*')
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
        if format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(format)

    def calcUnpackSize(self, format, data, field = None):
        if self.debug:
            print "  calcUnpackSize( %s | %s | %r)" %  (field, format, data)

        # void specifier
        if format[:1] == '_':
            return 0

        addressField = self.findAddressFieldFor(field)
        if addressField is not None:
            if not self[addressField]:
                return 0

        try:
            lengthField = self.findLengthFieldFor(field)
            return self[lengthField]
        except:
            pass

        # XXX: Try to match to actual values, raise if no match
        
        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return len(format)-1

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            return self.calcUnpackSize(two[0], data)

        # length specifier
        two = format.split('-')
        if len(two) == 2:
            return self.calcUnpackSize(two[0], data)

        # array specifier
        two = format.split('*')
        if len(two) == 2:
            answer = 0
            numItems = self[two[1]]
            while numItems:
                numItems -= 1
                if self.isNDR(self.item):
                    answer += self.calcUnpackSize(':', data[answer:]) 
                else:
                    answer += self.calcUnpackSize(self.item, data[answer:])
            return answer


        # literal specifier
        if format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(format)

# NDR Primitives
NDRBOOLEAN     = 'B'
NDRCHAR        = 'c'
NDRSMALL       = 'B'
NDRSHORT       = '<H'
NDRLONG        = '<L'
NDRHYPER       = '<Q'
NDRFLOAT       = '<f'
NDRDOUBLEFLOAT = '<d'

# NDR Constructed Types (arrays, strings, structures, unions, variant structures, pipes and pointers)

# Uni-dimensional Fixed Arrays
class NDRUniFixedArray(NDR):
    structure = (
        ('Data',':'),
    )

# Uni-dimensional Conformant Arrays
class NDRUniConformantArray(NDR):
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
class NDRUniVaryingArray(NDR):
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
class NDRUniConformantVaryingArray(NDR):
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
    def getData(self):
        # The last element of a string is a terminator of the same size as the other elements. 
        # If the string element size is one octet, the terminator is a NULL character. 
        # The terminator for a string of multi-byte characters is the array element zero (0).
        if self["Data"][-1:] != '\x00':
            self["Data"] = ''.join(self["Data"]) + '\x00'
        return NDRUniVaryingArray.getData(self)

    def fromString(self, data):
        ret = NDRUniVaryingArray.fromString(self,data)
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

# Unions not implemented for now

# Pipes not implemented for now

# Pointers

class NDRPointerNULL(NDR):
    structure = (
        ('Data', '4s=""'),
    )
    structure64 = (
        ('Data', '8s=""'),
    )

class NDRTopLevelPointer(NDR):
    align = 4
    align64 = 8
    commonHdr = (
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('ReferentID','<Q=0xff'),
    )

    structure = (
        # This is the representation of the Referent
        ('Data',':'),
    )
    def __init__(self, data = None, alignment = 0, isNDR64=False):
        NDR.__init__(self,data, alignment, isNDR64=isNDR64)
        if data is None:
            self['ReferentID'] = random.randint(1,65535)

class NDRTopLevelReferencePointer(NDR):
    structure = (
        # This is the representation of the Referent
        ('Data',':'),
    )

class NDREmbeddedFullPointer(NDR):
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
    def __init__(self, data = None, alignment = 0, isNDR64=False):
        ret = NDR.__init__(self,None, alignment, isNDR64=isNDR64)
        if data is None:
            self['ReferentID'] = random.randint(1,65535)
        else:
           self.fromString(data)

    #def getData(self):
    #    return Structure.getData(self)

    #def fromString(self, data):
    #    return Structure.fromString(self, data)

# Embedded Reference Pointers not implemented for now

################################################################################
# Common RPC Data Types

class RPC_UNICODE_STRING(NDR):
    align = 4
    align64 = 8
    commonHdr = (
        ('MaximumCount', '<L=len(Data)/2'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)/2'),
    )
    commonHdr64 = (
        ('MaximumCount', '<Q=len(Data)/2'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)/2'),
    )
    structure = (
        ('_Data', '_-Data', 'self["ActualCount"]*2'),
        ('Data',':'),
    )

class PRPC_UNICODE_STRING(NDREmbeddedFullPointer):
    align = 2
    align64 = 2
    commonHdr = (
        ('MaximumLength','<H=0'),
        ('Length','<H=0'),
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('MaximumLength','<H=0'),
        ('Length','<H=0'),
        ('ReferentID','<Q=0xff'),
    )

    referent = (
        ('pString',':',RPC_UNICODE_STRING),
    )

NDRString = RPC_UNICODE_STRING

# Special treatment for UniqueString to avoid nesting ['Data']['Data'] .. for now
class NDRUniqueString(NDRString, NDRTopLevelPointer):
    def __init__(self, data = None, alignment = 0, isNDR64 = False):
        self.commonHdr = NDRTopLevelPointer.commonHdr + NDRString.commonHdr
        self.commonHdr64 = NDRTopLevelPointer.commonHdr64 + NDRString.commonHdr64
        NDRString.__init__(self,data,alignment,isNDR64)
        NDRTopLevelPointer.__init__(self,data,alignment,isNDR64)

#class NDRUniqueString(NDRTopLevelPointer):
#    structure = (
#        ('Data',':',NDRString),
#    ) 

class PNDRUniConformantArray(NDREmbeddedFullPointer):
    referent = (
        ('Data',':', NDRUniConformantArray),
    )
    def __init__(self, data = None, alignment = 0, isNDR64 = False):
        NDREmbeddedFullPointer.__init__(self,data,alignment,isNDR64)
        


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
        print "repacking....."
        b_str = str(b)
        if b_str != a_str:
            print "ERROR: original packed and repacked don't match"
            print "packed: " 
            hexdump(b_str)
            raise

    def run(self):
        self.test(False)
        # Now the same tests but with NDR64
        #self.test(True)

class TestUniFixedArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', NDRUniFixedArray),
        )
    def populate(self, a):
        a['Array']['Data'] = '12345678'

class TestUniConformantArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', PNDRUniConformantArray),
        )
        def __init__(self, data = None, alignment = 0, isNDR64 = False):
            NDR.__init__(self, None, alignment,isNDR64)
            self['Array']['Data'].item = NDRString
            if data is not None:
                self.fromString(data)
        
    def populate(self, a):
        array = []
        strstr = NDRString()
        strstr['Data'] = 'ThisIsMe'.encode('utf-16le')
        array.append(strstr)
        strstr = NDRString()
        strstr['Data'] = 'ThisIsYou'.encode('utf-16le')
        array.append(strstr)
        a['Array']['Data']['Data'] = array

class TestUniVaryingArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', NDRUniVaryingArray),
        )
    def populate(self, a):
        a['Array']['Data'] = '12345678'

class TestUniConformantVaryingArray(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', NDRUniConformantVaryingArray),
        )
    def populate(self, a):
        a['Array']['Data'] = '12345678'

class TestVaryingString(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', NDRVaryingString),
        )
    def populate(self, a):
        a['Array']['Data'] = '12345678'

class TestConformantVaryingString(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', NDRConformantVaryingString),
        )
        
    def populate(self, a):
        a['Array']['Data'] = '12345678'

class TestPointerNULL(NDRTest):
    class theClass(NDR):
        structure = (
            ('Array',':', NDRPointerNULL),
        )
    def populate(self, a):
        pass

class TestTopLevelPointer(NDRTest):
    class theClass(NDR):
        structure = (
            ('Pointer',':', NDRTopLevelPointer),
        )

    def populate(self, a):
        a["Pointer"]["Data"] = 'hola loco como te va'

class TestEmbeddedFullPointer(NDRTest):
    class theClass(NDR):
        structure = (
            ('Pointer',':', NDREmbeddedFullPointer),
            ('AAA', '<L=0xffffffff'),
        )

    def populate(self, a):
        a["Pointer"]["Data"] = 'hola loco como te va'

class TestServerAuthenticate(NDRTest):
    class NETLOGON_CREDENTIAL(NDR):
        structure = (
            ('data','8s=""'),
        )

    class theClass(NDR):
        class NETLOGON_CREDENTIAL(NDR):
            structure = (
                ('data','8s=""'),
            )
        structure = (
            ('PrimaryName',':', NDRUniqueString),
            ('AccountName',':', NDRString ),
            ('SecureChannelType','<H=0'),
            ('ComputerName',':', NDRString ),
            ('ClientCredential',':',NETLOGON_CREDENTIAL),
            ('NegotiateFlags','<L=0'),
        )
    def populate(self, a):
        a['PrimaryName']['Data'] = 'XXX1DC001\x00'.encode('utf-16le')
        a['AccountName']['Data'] = 'TEST-MACHINE$\x00'.encode('utf-16le')
        a['SecureChannelType'] = 0xffff
        a['ComputerName']['Data'] = 'TEST-MACHINE\x00'.encode('utf-16le')
        a['ClientCredential']['data']  = '12345678'
        a['NegotiateFlags'] = 0xabcdabcd

if __name__ == '__main__':
    from impacket.dcerpc.netlogon import NETLOGON_CREDENTIAL
    TestUniFixedArray().run()
    TestUniConformantArray().run()
    TestUniVaryingArray().run()
    TestUniConformantVaryingArray().run()
    TestVaryingString().run()
    TestConformantVaryingString().run()
    TestPointerNULL().run()
    TestTopLevelPointer().run()
    TestEmbeddedFullPointer().run()
    TestServerAuthenticate().run()
