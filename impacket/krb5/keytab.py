# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Kerberos Keytab format implementation
#   based on file format described at:
#   https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt
#   As the ccache implementation, pretty lame and quick
#   Feel free to improve
#
# Author:
#   Patrick Welzel (@kcirtapw)
#
from datetime import datetime
from enum import Enum
from six import b

from struct import pack, unpack, calcsize
from binascii import hexlify

from impacket.structure import Structure
from impacket import LOG


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

    def prettyKeytype(self):
        try:
            return Enctype(self['keytype']).name
        except:
            return "UNKNOWN:0x%x" % (self['keytype'])

    def hexlifiedValue(self):
        return hexlify(self['keyvalue']['data'])

    def prettyPrint(self):
        return "(%s)%s" % (self.prettyKeytype(), self.hexlifiedValue())


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
          counted_octet_string realm;                               | \\  Keytab
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

    def __init__(self, data=None):
        self.rest = b''
        if data:
            self.main_part = self.KeytabEntryMainpart(data)
            self.size = abs(self.main_part['size']) + 4  # size field itself not included
            self.kvno = self.main_part['vno8']
            self.deleted = self.main_part['size'] < 0
            len_main = len(self.main_part)
            if self.size > len_main:
                self.rest = data[len_main:self.size]
                if len(self.rest) >= 4 and \
                        self.rest[:4] != [0, 0, 0, 0]:  # if "field" is present but all 0, it seems to gets ignored
                    self.kvno = unpack('!L', self.rest[:4])[0]
        else:
            self.main_part = self.KeytabEntryMainpart()
            self.deleted = True
            self.size = len(self.main_part)
            self.kvno = 0

    def __len__(self):
        return self.size

    def getData(self):
        data = self.main_part.getData()
        if self.rest:
            data += self.rest
        return data

    def prettyPrint(self, indent=''):
        if self.deleted:
            return "%s[DELETED]" % indent
        else:
            text = "%sPrincipal: %s\n" %(indent, self.main_part['principal'].prettyPrint())
            text += "%sTimestamp: %s" % (indent, datetime.fromtimestamp(self.main_part['timestamp']).isoformat())
            text += "\tKVNO: %i\n" % self.kvno
            text += "%sKey: %s" % (indent, self.main_part['keyblock'].prettyPrint())
            #if self.rest:
            #    text += "\n%sRest: %s" % (indent, self.rest)
            return text


class Keytab:

    GetkeyEnctypePreference = (Enctype.AES256.value,
                                 Enctype.AES128.value,
                                 Enctype.RC4.value)

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

    def getKey(self, principal, specificEncType=None, ignoreRealm=True):
        principal = b(principal.upper())
        if ignoreRealm:
            principal = principal.split(b'@')[0]
        matching_keys = {}
        for entry in self.entries:
            entry_principal = entry.main_part['principal'].prettyPrint().upper()
            if entry_principal == principal or (ignoreRealm and entry_principal.split(b'@')[0] == principal):
                keytype = entry.main_part["keyblock"]["keytype"]
                if keytype == specificEncType:
                    LOG.debug('Returning %s key for %s' % (entry.main_part['keyblock'].prettyKeytype(),
                                                           entry.main_part['principal'].prettyPrint()))
                    return entry.main_part["keyblock"]
                elif specificEncType is None:
                    matching_keys[keytype] = entry

        if specificEncType is None and matching_keys:
            for preference in self.GetkeyEnctypePreference:
                if preference in matching_keys:
                    entry = matching_keys[preference]
                    LOG.debug('Returning %s key for %s' % (entry.main_part['keyblock'].prettyKeytype(),
                                                           entry.main_part['principal'].prettyPrint()))
                    return entry.main_part["keyblock"]

        LOG.debug('Principal %s not found in keytab' % principal)
        return None

    @classmethod
    def loadFile(cls, fileName):
        f = open(fileName, 'rb')
        data = f.read()
        f.close()
        return cls(data)

    @classmethod
    def loadKeysFromKeytab(cls, fileName, username, domain, options):
        keytab = Keytab.loadFile(fileName)
        keyblock = keytab.getKey("%s@%s" % (username, domain))
        if keyblock:
            if keyblock["keytype"] == Enctype.AES256.value or keyblock["keytype"] == Enctype.AES128.value:
                options.aesKey = keyblock.hexlifiedValue()
            elif keyblock["keytype"] == Enctype.RC4.value:
                options.hashes= ':' + keyblock.hexlifiedValue().decode('ascii')
        else:
            LOG.warning("No matching key for SPN '%s' in given keytab found!", username)


    def saveFile(self, fileName):
        f = open(fileName, 'wb+')
        f.write(self.getData())
        f.close()

    def prettyPrint(self):
        print("Keytab Entries:")
        for i, entry in enumerate(self.entries):
            print(("[%d]" % i))
            print(entry.prettyPrint('\t'))


if __name__ == '__main__':
    import sys
    keytab = Keytab.loadFile(sys.argv[1])
    keytab.prettyPrint()
