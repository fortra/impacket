# Author: Patrick Welzel (@kcirtapw)
#
# Description:
#   Kerberos Keytab format implementation
#   based on file format described at:
#   https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt
#   As the ccache implementation, pretty lame and quick
#   Feel free to improve
#
from datetime import datetime
from enum import Enum
from six import b

from binascii import hexlify

from impacket.structure import Structure


class Enctype(Enum):
    DES_CRC = 1
    DES_MD4 = 2
    DES_MD5 = 3
    DES3 = 16
    AES128 = 17
    AES256 = 18
    RC4 = 23


class CountedOctetString(Structure):
    """
    Note: This is very similar to the CountedOctetString structure in ccache, except:
      * `length` is uint16 instead of uint32
    """
    structure = (
        ('length','!H=0'),
        ('_data','_-data','self["length"]'),
        ('data',':'),
    )

    def prettyPrint(self, indent=''):
        return "%s%s" % (indent, hexlify(self['data']))


class KeyBlock(Structure):
    structure = (
        ('keytype','!H=0'),
        ('keyvalue',':', CountedOctetString),
    )

    def prettyPrint(self):
        try:
            keytype = Enctype(int(self['keytype'])).name
        except:
            keytype = "UNKNOWN:0x%x" % (self['keytype'])
        return "(%s)%s" % (keytype, hexlify(self['keyvalue']['data']))


class KeytabPrincipal:
    """
    Note: This is very similar to the principal structure in ccache, except:
      * `num_components` is just uint16
      * using other size type for CountedOctetString
      * `name_type` field follows the other fields behind.
    """
    class PrincipalHeader1(Structure):
        structure = (
            ('num_components', '!H=0'),
        )

    class PrincipalHeader2(Structure):
        structure = (
            ('name_type', '!L=0'),
        )

    def __init__(self, data=None):
        self.components = []
        self.realm = None
        if data is not None:
            self.header1 = self.PrincipalHeader1(data)
            data = data[len(self.header1):]
            self.realm = CountedOctetString(data)
            data = data[len(self.realm):]
            self.components = []
            for component in range(self.header1['num_components']):
                comp = CountedOctetString(data)
                data = data[len(comp):]
                self.components.append(comp)
            self.header2 = self.PrincipalHeader2(data)
        else:
            self.header1 = self.PrincipalHeader1()
            self.header2 = self.PrincipalHeader2()

    def __len__(self):
        totalLen = len(self.header1) + len(self.header2) + len(self.realm)
        for i in self.components:
            totalLen += len(i)
        return totalLen

    def getData(self):
        data = self.header1.getData() + self.realm.getData()
        for component in self.components:
            data += component.getData()
        data += self.header2.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self):
        principal = b''
        for component in self.components:
            if isinstance(component['data'], bytes) is not True:
                component = b(component['data'])
            else:
                component = component['data']
            principal += component + b'/'

        principal = principal[:-1]
        if isinstance(self.realm['data'], bytes):
            realm = self.realm['data']
        else:
            realm = b(self.realm['data'])
        principal += b'@' + realm
        return principal


class KeytabEntry:
    class KeytabEntryMainpart(Structure):
        """
      keytab_entry {
          int32_t size;     # wtf, signed size. what could possibly ...
          uint16_t num_components;    /* sub 1 if version 0x501 */  |\
          counted_octet_string realm;                               | \  Keytab
          counted_octet_string components[num_components];          | /  Princial
          uint32_t name_type;   /* not present if version 0x501 */  |/
          uint32_t timestamp;
          uint8_t vno8;
          keyblock key;
          uint32_t vno; /* only present if >= 4 bytes left in entry */
      };
        """
        structure = (
            ('size', '!l=0'),
            ('principal', ':', KeytabPrincipal),
            ('timestamp', '!L=0'),
            ('vno8', '!B=0'),
            ('keyblock', ':', KeyBlock),
        )

    def __init__(self, data):
        self.rest = b''
        if data:
            self.main_part = self.KeytabEntryMainpart(data)
            if self.main_part['size'] > len(self.main_part):
                rest_size = self.main_part['size'] - len(self.main_part)
                self.rest = data[len(self.main_part):rest_size]
        else:
            self.main_part = self.KeytabEntryMainpart()

    def __len__(self):
        return max(self.main_part['size'], len(self.main_part))

    def getData(self):
        data = self.main_part.getData()
        if self.rest:
            data += self.rest
        return data

    def prettyPrint(self, indent=''):
        text = "%sPrincipal: %s\n" %(indent, self.main_part['principal'].prettyPrint())
        text += "%sTimestamp: %s\n" % (indent, datetime.fromtimestamp(self.main_part['timestamp']).isoformat())
        text += "%sKey: %s" % (indent, self.main_part['keyblock'].prettyPrint())
        if self.rest:
            text += "\n%sRest: %s" % (indent, self.rest)
        return text


class Keytab:
    class MiniHeader(Structure):
        structure = (
            ('file_format_version', '!H=0x0502'),
        )

    def __init__(self, data=None):
        self.miniHeader = None
        self.entries = []
        if data is not None:
            self.miniHeader = self.MiniHeader(data)
            data = data[len(self.miniHeader):]
            while len(data):
                entry = KeytabEntry(data)
                self.entries.append(entry)
                data = data[len(entry):]

    def getData(self):
        data = self.MiniHeader().getData()
        for entry in self.entries:
            data += entry.getData()
        return data


    @classmethod
    def loadFile(cls, fileName):
        with open(fileName, 'rb') as f:
            data = f.read()
        return cls(data)

    def saveFile(self, fileName):
        with open(fileName, 'wb+') as f:
            f.write(self.getData())

    def prettyPrint(self):
        print("Keytab Entries:")
        for i, entry in enumerate(self.entries):
            print(("[%d]" % i))
            print(entry.prettyPrint('\t'))


if __name__ == '__main__':
    import sys
    keytab = Keytab.loadFile(sys.argv[1])
    keytab.prettyPrint()
