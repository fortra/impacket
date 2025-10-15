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

from __future__ import division
from __future__ import print_function
from struct import pack, unpack, calcsize

import six
from six import b, PY3
from binascii import hexlify


class Structure:
    """ sublcasses can define commonHdr and/or structure.
        each of them is an tuple of either two: (fieldName, format) or three: (fieldName, ':', class) fields.
        [it can't be a dictionary, because order is important]
        
        where format specifies how the data in the field will be converted to/from bytes (string)
        class is the class to use when unpacking ':' fields.

        each field can only contain one value (or an array of values for *)
           i.e. struct.pack('Hl',1,2) is valid, but format specifier 'Hl' is not (you must use 2 dfferent fields)

        format specifiers:
          specifiers from module pack can be used with the same format 
          see struct.__doc__ (pack/unpack is finally called)
            x       [padding byte]
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
            s       [string (array of chars), must be preceded with length in format specifier, padded with zeros]
            p       [pascal string (includes byte count), must be preceded with length in format specifier, padded with zeros]
            f       [float]
            d       [double]
            =       [native byte ordering, size and alignment]
            @       [native byte ordering, standard size and alignment]
            !       [network byte ordering]
            <       [little endian]
            >       [big endian]

          usual printf like specifiers can be used (if started with %) 
          [not recommended, there is no way to unpack this]

            %08x    will output an 8 bytes hex
            %s      will output a string
            %s\\x00  will output a NUL terminated string
            %d%d    will output 2 decimal digits (against the very same specification of Structure)
            ...

          some additional format specifiers:
            :       just copy the bytes from the field into the output string (input may be string, other structure, or anything responding to __str__()) (for unpacking, all what's left is returned)
            z       same as :, but adds a NUL byte at the end (asciiz) (for unpacking the first NUL byte is used as terminator)  [asciiz string]
            u       same as z, but adds two NUL bytes at the end (after padding to an even size with NULs). (same for unpacking) [unicode string]
            w       DCE-RPC/NDR string (it's a macro for [  '<L=(len(field)+1)/2','"\\x00\\x00\\x00\\x00','<L=(len(field)+1)/2',':' ]
            ?-field length of field named 'field', formatted as specified with ? ('?' may be '!H' for example). The input value overrides the real length
            ?1*?2   array of elements. Each formatted as '?2', the number of elements in the array is stored as specified by '?1' (?1 is optional, or can also be a constant (number), for unpacking)
            'xxxx   literal xxxx (field's value doesn't change the output. quotes must not be closed or escaped)
            "xxxx   literal xxxx (field's value doesn't change the output. quotes must not be closed or escaped)
            _       will not pack the field. Accepts a third argument, which is an unpack code. See _Test_UnpackCode for an example
            ?=packcode  will evaluate packcode in the context of the structure, and pack the result as specified by ?. Unpacking is made plain
            ?&fieldname "Address of field fieldname".
                        For packing it will simply pack the id() of fieldname. Or use 0 if fieldname doesn't exists.
                        For unpacking, it's used to know weather fieldname has to be unpacked or not, i.e. by adding a & field you turn another field (fieldname) in an optional field.
            
    """
    commonHdr = ()
    structure = ()
    debug = 0
    # Encoding defaults to latin-1 which already was the de facto encoding for structures and works for most use cases.
    # Now it can be configured to another encoding if needed.
    ENCODING = 'latin-1'   # https://github.com/fortra/impacket/pull/1958

    def __init__(self, data = None, alignment = 0):
        if not hasattr(self, 'alignment'):
            self.alignment = alignment

        self.fields    = {}
        self.rawData   = data

        self.b = lambda x: six.ensure_binary(x, encoding=self.ENCODING)

        if data is not None:
            self.fromString(data)
        else:
            self.data = None

    @classmethod
    def fromFile(self, file):
        answer = self()
        answer.fromString(file.read(len(answer)))
        return answer

    def setAlignment(self, alignment):
        self.alignment = alignment

    def setData(self, data):
        self.data = data

    def packField(self, fieldName, format = None):
        if self.debug:
            print("packField( %s | %s )" % (fieldName, format))

        if format is None:
            format = self.formatForField(fieldName)

        if fieldName in self.fields:
            ans = self.pack(format, self.fields[fieldName], field = fieldName)
        else:
            ans = self.pack(format, None, field = fieldName)

        if self.debug:
            print("\tanswer %r" % ans)

        return ans

    def getData(self):
        if self.data is not None:
            return self.data
        data = bytes()
        for field in self.commonHdr+self.structure:
            try:
                data += self.packField(field[0], field[1])
            except Exception as e:
                if field[0] in self.fields:
                    e.args += ("When packing field '%s | %s | %r' in %s" % (field[0], field[1], self[field[0]], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (field[0], field[1], self.__class__),)
                raise
            if self.alignment:
                if len(data) % self.alignment:
                    data += (b'\x00'*self.alignment)[:-(len(data) % self.alignment)]
            
        #if len(data) % self.alignment: data += ('\x00'*self.alignment)[:-(len(data) % self.alignment)]
        return data

    def fromString(self, data):
        self.rawData = data
        for field in self.commonHdr+self.structure:
            if self.debug:
                print("fromString( %s | %s | %r )" % (field[0], field[1], data))
            size = self.calcUnpackSize(field[1], data, field[0])
            if self.debug:
                print("  size = %d" % size)
            dataClassOrCode = b
            if len(field) > 2:
                dataClassOrCode = field[2]
            try:
                self[field[0]] = self.unpack(field[1], data[:size], dataClassOrCode = dataClassOrCode, field = field[0])
            except Exception as e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (field[0], field[1], data, size),)
                raise

            size = self.calcPackSize(field[1], self[field[0]], field[0])
            if self.alignment and size % self.alignment:
                size += self.alignment - (size % self.alignment)
            data = data[size:]

        return self

    def __setitem__(self, key, value):
        self.fields[key] = value
        self.data = None        # force recompute

    def __getitem__(self, key):
        return self.fields[key]

    def __delitem__(self, key):
        del self.fields[key]

    def __str__(self):
        return str(hexlify(self.getData()).decode("ascii"))

    def __len__(self):
        # XXX: improve
        return len(self.getData())

    def pack(self, format, data, field = None):
        if self.debug:
            print("  pack( %s | %r | %s)" %  (format, data, field))

        if field:
            addressField = self.findAddressFieldFor(field)
            if (addressField is not None) and (data is None):
                return b''

        # void specifier
        if format[:1] == '_':
            return b''

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return self.b(format[1:])

        # code specifier
        two = format.split('=')
        if len(two) >= 2:
            try:
                return self.pack(two[0], data)
            except:
                fields = {'self':self}
                fields.update(self.fields)
                return self.pack(two[0], eval(two[1], {}, fields))

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            try:
                return self.pack(two[0], data)
            except:
                if (two[1] in self.fields) and (self[two[1]] is not None):
                    return self.pack(two[0], id(self[two[1]]) & ((1<<(calcsize(two[0])*8))-1) )
                else:
                    return self.pack(two[0], 0)

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
            answer = bytes()
            for each in data:
                answer += self.pack(two[1], each)
            if two[0]:
                if two[0].isdigit():
                    if int(two[0]) != len(data):
                        raise Exception("Array field has a constant size, and it doesn't match the actual value")
                else:
                    return self.pack(two[0], len(data))+answer
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            # format string like specifier
            return self.b(format % data)

        # asciiz specifier
        if format[:1] == 'z':
            if isinstance(data,bytes):
                return data + self.b('\0')
            return bytes(self.b(data)+self.b('\0'))

        # unicode specifier
        if format[:1] == 'u':
            return bytes(data+self.b('\0\0') + (len(data) & 1 and self.b('\0') or b''))

        # DCE-RPC/NDR string specifier
        if format[:1] == 'w':
            if len(data) == 0:
                data = self.b('\0\0')
            elif len(data) % 2:
                data = self.b(data) + self.b('\0')
            l = pack('<L', len(data)//2)
            return b''.join([l, l, self.b('\0\0\0\0'), data])

        if data is None:
            raise Exception("Trying to pack None")
        
        # literal specifier
        if format[:1] == ':':
            if isinstance(data, Structure):
                return data.getData()
            # If we have an object that can serialize itself, go ahead
            elif hasattr(data, "getData"):
                return data.getData()
            elif isinstance(data, int):
                return bytes(data)
            elif isinstance(data, bytes) is not True:
                return bytes(self.b(data))
            else:
                return data

        if format[-1:] == 's':
            # Let's be sure we send the right type
            if isinstance(data, bytes) or isinstance(data, bytearray):
                return pack(format, data)
            else:
                return pack(format, self.b(data))

        # struct like specifier
        return pack(format, data)

    def unpack(self, format, data, dataClassOrCode = b, field = None):
        if self.debug:
            print("  unpack( %s | %r )" %  (format, data))

        if field:
            addressField = self.findAddressFieldFor(field)
            if addressField is not None:
                if not self[addressField]:
                    return

        # void specifier
        if format[:1] == '_':
            if dataClassOrCode != b:
                fields = {'self':self, 'inputDataLeft':data}
                fields.update(self.fields)
                return eval(dataClassOrCode, {}, fields)
            else:
                return None

        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            answer = format[1:]
            if self.b(answer) != data:
                raise Exception("Unpacked data doesn't match constant value '%r' should be '%r'" % (data, answer))
            return answer

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            return self.unpack(two[0],data)

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
        if len(two) == 2:
            answer = []
            sofar = 0
            if two[0].isdigit():
                number = int(two[0])
            elif two[0]:
                sofar += self.calcUnpackSize(two[0], data)
                number = self.unpack(two[0], data[:sofar])
            else:
                number = -1

            while number and sofar < len(data):
                nsofar = sofar + self.calcUnpackSize(two[1],data[sofar:])
                answer.append(self.unpack(two[1], data[sofar:nsofar], dataClassOrCode))
                number -= 1
                sofar = nsofar
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            # format string like specifier
            return format % data

        # asciiz specifier
        if format == 'z':
            if data[-1:] != self.b('\x00'):
                raise Exception("%s 'z' field is not NUL terminated: %r" % (field, data))
            if PY3:
                return data[:-1].decode('latin-1')
            else:
                return data[:-1]

        # unicode specifier
        if format == 'u':
            if data[-2:] != self.b('\x00\x00'):
                raise Exception("%s 'u' field is not NUL-NUL terminated: %r" % (field, data))
            return data[:-2] # remove trailing NUL

        # DCE-RPC/NDR string specifier
        if format == 'w':
            l = unpack('<L', data[:4])[0]
            return data[12:12+l*2]

        # literal specifier
        if format == ':':
            if isinstance(data, bytes) and dataClassOrCode is b:
                return data
            return dataClassOrCode(data)

        # struct like specifier
        return unpack(format, data)[0]

    def calcPackSize(self, format, data, field = None):
#        # print "  calcPackSize  %s:%r" %  (format, data)
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

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            return self.calcPackSize(two[0], data)

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
            if two[0].isdigit():
                    if int(two[0]) != len(data):
                        raise Exception("Array field has a constant size, and it doesn't match the actual value")
            elif two[0]:
                answer += self.calcPackSize(two[0], len(data))

            for each in data:
                answer += self.calcPackSize(two[1], each)
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            # format string like specifier
            return len(format % data)

        # asciiz specifier
        if format[:1] == 'z':
            return len(data)+1

        # asciiz specifier
        if format[:1] == 'u':
            l = len(data)
            return l + (l & 1 and 3 or 2)

        # DCE-RPC/NDR string specifier
        if format[:1] == 'w':
            l = len(data)
            return 12+l+l % 2

        # literal specifier
        if format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(format)

    def calcUnpackSize(self, format, data, field = None):
        if self.debug:
            print("  calcUnpackSize( %s | %s | %r)" %  (field, format, data))

        # void specifier
        if format[:1] == '_':
            return 0

        addressField = self.findAddressFieldFor(field)
        if addressField is not None:
            if not self[addressField]:
                return 0

        try:
            lengthField = self.findLengthFieldFor(field)
            return int(self[lengthField])
        except Exception:
            pass

        # XXX: Try to match to actual values, raise if no match
        
        # quote specifier
        if format[:1] == "'" or format[:1] == '"':
            return len(format)-1

        # address specifier
        two = format.split('&')
        if len(two) == 2:
            return self.calcUnpackSize(two[0], data)

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
            if two[0]:
                if two[0].isdigit():
                    number = int(two[0])
                else:
                    answer += self.calcUnpackSize(two[0], data)
                    number = self.unpack(two[0], data[:answer])

                while number:
                    number -= 1
                    answer += self.calcUnpackSize(two[1], data[answer:])
            else:
                while answer < len(data):
                    answer += self.calcUnpackSize(two[1], data[answer:])
            return answer

        # "printf" string specifier
        if format[:1] == '%':
            raise Exception("Can't guess the size of a printf like specifier for unpacking")

        # asciiz specifier
        if format[:1] == 'z':
            return data.index(self.b('\x00'))+1

        # asciiz specifier
        if format[:1] == 'u':
            l = data.index(self.b('\x00\x00'))
            return l + (l & 1 and 3 or 2)

        # DCE-RPC/NDR string specifier
        if format[:1] == 'w':
            l = unpack('<L', data[:4])[0]
            return 12+l*2

        # literal specifier
        if format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(format)

    def calcPackFieldSize(self, fieldName, format = None):
        if format is None:
            format = self.formatForField(fieldName)

        return self.calcPackSize(format, self[fieldName])

    def formatForField(self, fieldName):
        for field in self.commonHdr+self.structure:
            if field[0] == fieldName:
                return field[1]
        raise Exception("Field %s not found" % fieldName)

    def findAddressFieldFor(self, fieldName):
        descriptor = '&%s' % fieldName
        l = len(descriptor)
        for field in self.commonHdr+self.structure:
            if field[1][-l:] == descriptor:
                return field[0]
        return None
        
    def findLengthFieldFor(self, fieldName):
        descriptor = '-%s' % fieldName
        l = len(descriptor)
        for field in self.commonHdr+self.structure:
            if field[1][-l:] == descriptor:
                return field[0]
        return None
        
    def zeroValue(self, format):
        two = format.split('*')
        if len(two) == 2:
            if two[0].isdigit():
                return (self.zeroValue(two[1]),)*int(two[0])
                        
        if not format.find('*') == -1:
            return ()
        if 's' in format:
            return b''
        if format in ['z',':','u']:
            return b''
        if format == 'w':
            return self.b('\x00\x00')

        return 0

    def clear(self):
        for field in self.commonHdr + self.structure:
            self[field[0]] = self.zeroValue(field[1])

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        print("\n%s" % msg)
        fixedFields = []
        for field in self.commonHdr+self.structure:
            i = field[0] 
            if i in self.fields:
                fixedFields.append(i)
                if isinstance(self[i], Structure):
                    self[i].dump('%s%s:{' % (ind,i), indent = indent + 4)
                    print("%s}" % ind)
                else:
                    print("%s%s: {%r}" % (ind,i,self[i]))
        # Do we have remaining fields not defined in the structures? let's 
        # print them
        remainingFields = list(set(self.fields) - set(fixedFields))
        for i in remainingFields:
            if isinstance(self[i], Structure):
                self[i].dump('%s%s:{' % (ind,i), indent = indent + 4)
                print("%s}" % ind)
            else:
                print("%s%s: {%r}" % (ind,i,self[i]))

def pretty_print(x):
    if chr(x) in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
       return chr(x)
    else:
       return u'.'

def hexdump(data, indent = ''):
    if data is None:
        return
    if isinstance(data, int):
        data = str(data).encode('utf-8')
    x=bytearray(data)
    strLen = len(x)
    i = 0
    while i < strLen:
        line = " %s%04x   " % (indent, i)
        for j in range(16):
            if i+j < strLen:
                line += "%02X " % x[i+j]
            else:
                line += u"   "
            if j%16 == 7:
                line += " "
        line += "  "
        line += ''.join(pretty_print(x) for x in x[i:i+16] )
        print (line)
        i += 16

def parse_bitmask(dict, value):
    ret = ''
    
    for i in range(0, 31):
        flag = 1 << i

        if value & flag == 0:
            continue

        if flag in dict:
            ret += '%s | ' % dict[flag]
        else:
            ret += "0x%.8X | " % flag

    if len(ret) == 0:
        return '0'
    else:
        return ret[:-3]
