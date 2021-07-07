# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Structures and types used in LDAP
#   Contains the Structures for the NT Security Descriptor (non-RPC format) and
#   all ACL related structures
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
from struct import unpack, pack
from impacket.structure import Structure

# Global constant if the library should recalculate ACE sizes in objects that are decoded/re-encoded.
# This defaults to True, but this causes the ACLs to not match on a binary level
# since Active Directory for some reason sometimes adds null bytes to the end of ACEs.
# This is valid according to the spec (see 2.4.4), but since impacket encodes them more efficiently
# this should be turned off if running unit tests.
RECALC_ACE_SIZE = True

# LDAP SID structure - based on SAMR_RPC_SID, except the SubAuthority is LE here
class LDAP_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )

class LDAP_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',LDAP_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % ( unpack('<L',self['SubAuthority'][i*4:i*4+4])[0])
        return ans

    def fromCanonical(self, canonical):
        items = canonical.split('-')
        self['Revision'] = int(items[1])
        self['IdentifierAuthority'] = LDAP_SID_IDENTIFIER_AUTHORITY()
        self['IdentifierAuthority']['Value'] = b'\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
        self['SubAuthorityCount'] = len(items) - 3
        self['SubAuthority'] = b''
        for i in range(self['SubAuthorityCount']):
            self['SubAuthority'] += pack('<L', int(items[i+3]))

"""
Self-relative security descriptor as described in 2.4.6
https://msdn.microsoft.com/en-us/library/cc230366.aspx
"""
class SR_SECURITY_DESCRIPTOR(Structure):
    structure = (
        ('Revision','c'),
        ('Sbz1','c'),
        ('Control','<H'),
        ('OffsetOwner','<L'),
        ('OffsetGroup','<L'),
        ('OffsetSacl','<L'),
        ('OffsetDacl','<L'),
        ('Sacl',':'),
        ('Dacl',':'),
        ('OwnerSid',':'),
        ('GroupSid',':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        # All these fields are optional, if the offset is 0 they are empty
        # there are also flags indicating if they are present
        # TODO: parse those if it adds value
        if self['OffsetOwner'] != 0:
            self['OwnerSid'] = LDAP_SID(data=data[self['OffsetOwner']:])
        else:
            self['OwnerSid'] = b''

        if self['OffsetGroup'] != 0:
            self['GroupSid'] = LDAP_SID(data=data[self['OffsetGroup']:])
        else:
            self['GroupSid'] = b''

        if self['OffsetSacl'] != 0:
            self['Sacl'] = ACL(data=data[self['OffsetSacl']:])
        else:
            self['Sacl'] = b''

        if self['OffsetDacl'] != 0:
            self['Dacl'] = ACL(data=data[self['OffsetDacl']:])
        else:
            self['Sacl'] = b''

    def getData(self):
        headerlen = 20
        # Reconstruct the security descriptor
        # flags are currently not set automatically
        # TODO: do this?
        datalen = 0
        if self['Sacl'] != b'':
            self['OffsetSacl'] = headerlen + datalen
            datalen += len(self['Sacl'].getData())
        else:
            self['OffsetSacl'] = 0

        if self['Dacl'] != b'':
            self['OffsetDacl'] = headerlen + datalen
            datalen += len(self['Dacl'].getData())
        else:
            self['OffsetDacl'] = 0

        if self['OwnerSid'] != b'':
            self['OffsetOwner'] = headerlen + datalen
            datalen += len(self['OwnerSid'].getData())
        else:
            self['OffsetOwner'] = 0

        if self['GroupSid'] != b'':
            self['OffsetGroup'] = headerlen + datalen
            datalen += len(self['GroupSid'].getData())
        else:
            self['OffsetGroup'] = 0
        return Structure.getData(self)

"""
ACE as described in 2.4.4
https://msdn.microsoft.com/en-us/library/cc230295.aspx
"""
class ACE(Structure):
    # Flag constants
    CONTAINER_INHERIT_ACE       = 0x02
    FAILED_ACCESS_ACE_FLAG      = 0x80
    INHERIT_ONLY_ACE            = 0x08
    INHERITED_ACE               = 0x10
    NO_PROPAGATE_INHERIT_ACE    = 0x04
    OBJECT_INHERIT_ACE          = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG  = 0x40

    structure = (
        #
        # ACE_HEADER as described in 2.4.4.1
        # https://msdn.microsoft.com/en-us/library/cc230296.aspx
        #
        ('AceType','B'),
        ('AceFlags','B'),
        ('AceSize','<H'),
        # Virtual field to calculate data length from AceSize
        ('AceLen', '_-Ace', 'self["AceSize"]-4'),
        #
        # ACE body, is parsed depending on the type
        #
        ('Ace',':')
    )

    def fromString(self, data):
        # This will parse the header
        Structure.fromString(self, data)
        # Now we parse the ACE body according to its type
        self['TypeName'] = ACE_TYPE_MAP[self['AceType']].__name__
        self['Ace'] = ACE_TYPE_MAP[self['AceType']](data=self['Ace'])

    def getData(self):
        if RECALC_ACE_SIZE or 'AceSize' not in self.fields:
            self['AceSize'] = len(self['Ace'].getData())+4 # Header size (4 bytes) is included
        if self['AceSize'] % 4 != 0:
            # Make sure the alignment is correct
            self['AceSize'] += self['AceSize'] % 4
        data = Structure.getData(self)
        # For some reason ACEs are sometimes longer than they need to be
        # we fill this space up with null bytes to make sure the object
        # we create is identical to the original object
        if len(data) < self['AceSize']:
            data += '\x00' * (self['AceSize'] - len(data))
        return data

    def hasFlag(self, flag):
        return self['AceFlags'] & flag == flag

"""
ACCESS_MASK as described in 2.4.3
https://msdn.microsoft.com/en-us/library/cc230294.aspx
"""
class ACCESS_MASK(Structure):
    # Flag constants
    GENERIC_READ            = 0x80000000
    GENERIC_WRITE           = 0x40000000
    GENERIC_EXECUTE         = 0x20000000
    GENERIC_ALL             = 0x10000000
    MAXIMUM_ALLOWED         = 0x02000000
    ACCESS_SYSTEM_SECURITY  = 0x01000000
    SYNCHRONIZE             = 0x00100000
    WRITE_OWNER             = 0x00080000
    WRITE_DACL              = 0x00040000
    READ_CONTROL            = 0x00020000
    DELETE                  = 0x00010000

    structure = (
        ('Mask', '<L'),
    )

    def hasPriv(self, priv):
        return self['Mask'] & priv == priv

    def setPriv(self, priv):
        self['Mask'] |= priv

    def removePriv(self, priv):
        self['Mask'] ^= priv

"""
ACCESS_ALLOWED_ACE as described in 2.4.4.2
https://msdn.microsoft.com/en-us/library/cc230286.aspx
"""
class ACCESS_ALLOWED_ACE(Structure):
    ACE_TYPE = 0x00
    structure = (
        ('Mask', ':', ACCESS_MASK),
        ('Sid', ':', LDAP_SID)
    )

"""
ACCESS_ALLOWED_OBJECT_ACE as described in 2.4.4.3
https://msdn.microsoft.com/en-us/library/cc230289.aspx
"""
class ACCESS_ALLOWED_OBJECT_ACE(Structure):
    ACE_TYPE = 0x05

    # Flag contstants
    ACE_OBJECT_TYPE_PRESENT             = 0x01
    ACE_INHERITED_OBJECT_TYPE_PRESENT   = 0x02

    # ACE type specific mask constants
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    ADS_RIGHT_DS_CONTROL_ACCESS         = 0x00000100
    ADS_RIGHT_DS_CREATE_CHILD           = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD           = 0x00000002
    ADS_RIGHT_DS_READ_PROP              = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP             = 0x00000020
    ADS_RIGHT_DS_SELF                   = 0x00000008


    structure = (
        ('Mask', ':', ACCESS_MASK),
        ('Flags', '<L'),
        # Optional field
        ('ObjectTypeLen','_-ObjectType','self.checkObjectType(self["Flags"])'),
        ('ObjectType', ':=""'),
        # Optional field
        ('InheritedObjectTypeLen','_-InheritedObjectType','self.checkInheritedObjectType(self["Flags"])'),
        ('InheritedObjectType', ':=""'),
        ('Sid', ':', LDAP_SID)
    )

    @staticmethod
    def checkInheritedObjectType(flags):
        if flags & ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            return 16
        return 0

    @staticmethod
    def checkObjectType(flags):
        if flags & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
            return 16
        return 0

    def getData(self):
        # Set the correct flags
        if self['ObjectType'] != b'':
            self['Flags'] |= self.ACE_OBJECT_TYPE_PRESENT
        if self['InheritedObjectType'] != b'':
            self['Flags'] |= self.ACE_INHERITED_OBJECT_TYPE_PRESENT
        return Structure.getData(self)

    def hasFlag(self, flag):
        return self['Flags'] & flag == flag

"""
ACCESS_DENIED_ACE as described in 2.4.4.4
https://msdn.microsoft.com/en-us/library/cc230291.aspx
Structure is identical to ACCESS_ALLOWED_ACE
"""
class ACCESS_DENIED_ACE(ACCESS_ALLOWED_ACE):
    ACE_TYPE = 0x01

"""
ACCESS_DENIED_OBJECT_ACE as described in 2.4.4.5
https://msdn.microsoft.com/en-us/library/gg750297.aspx
Structure is identical to ACCESS_ALLOWED_OBJECT_ACE
"""
class ACCESS_DENIED_OBJECT_ACE(ACCESS_ALLOWED_OBJECT_ACE):
    ACE_TYPE = 0x06

"""
ACCESS_ALLOWED_CALLBACK_ACE as described in 2.4.4.6
https://msdn.microsoft.com/en-us/library/cc230287.aspx
"""
class ACCESS_ALLOWED_CALLBACK_ACE(Structure):
    ACE_TYPE = 0x09
    structure = (
        ('Mask', ':', ACCESS_MASK),
        ('Sid', ':', LDAP_SID),
        ('ApplicationData', ':')
    )

"""
ACCESS_DENIED_OBJECT_ACE as described in 2.4.4.7
https://msdn.microsoft.com/en-us/library/cc230292.aspx
Structure is identical to ACCESS_ALLOWED_CALLBACK_ACE
"""
class ACCESS_DENIED_CALLBACK_ACE(ACCESS_ALLOWED_CALLBACK_ACE):
    ACE_TYPE = 0x0A

"""
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE as described in 2.4.4.8
https://msdn.microsoft.com/en-us/library/cc230288.aspx
"""
class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE(ACCESS_ALLOWED_OBJECT_ACE):
    ACE_TYPE = 0x0B
    structure = (
        ('Mask', ':', ACCESS_MASK),
        ('Flags', '<L'),
        # Optional field
        ('ObjectTypeLen','_-ObjectType','self.checkObjectType(self["Flags"])'),
        ('ObjectType', ':=""'),
        # Optional field
        ('InheritedObjectTypeLen','_-InheritedObjectType','self.checkInheritedObjectType(self["Flags"])'),
        ('InheritedObjectType', ':=""'),
        ('Sid', ':', LDAP_SID),
        ('ApplicationData', ':')
    )

"""
ACCESS_DENIED_CALLBACK_OBJECT_ACE as described in 2.4.4.7
https://msdn.microsoft.com/en-us/library/cc230292.aspx
Structure is identical to ACCESS_ALLOWED_OBJECT_OBJECT_ACE
"""
class ACCESS_DENIED_CALLBACK_OBJECT_ACE(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE):
    ACE_TYPE = 0x0C

"""
SYSTEM_AUDIT_ACE as described in 2.4.4.10
https://msdn.microsoft.com/en-us/library/cc230376.aspx
Structure is identical to ACCESS_ALLOWED_ACE
"""
class SYSTEM_AUDIT_ACE(ACCESS_ALLOWED_ACE):
    ACE_TYPE = 0x02


"""
SYSTEM_AUDIT_OBJECT_ACE as described in 2.4.4.11
https://msdn.microsoft.com/en-us/library/gg750298.aspx
Structure is identical to ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
"""
class SYSTEM_AUDIT_OBJECT_ACE(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE):
    ACE_TYPE = 0x07


"""
SYSTEM_AUDIT_CALLBACK_ACE as described in 2.4.4.12
https://msdn.microsoft.com/en-us/library/cc230377.aspx
Structure is identical to ACCESS_ALLOWED_CALLBACK_ACE
"""
class SYSTEM_AUDIT_CALLBACK_ACE(ACCESS_ALLOWED_CALLBACK_ACE):
    ACE_TYPE = 0x0D

"""
SYSTEM_AUDIT_CALLBACK_ACE as described in 2.4.4.13
https://msdn.microsoft.com/en-us/library/cc230379.aspx
Structure is identical to ACCESS_ALLOWED_ACE, but with custom masks and meanings.
Lets keep it separate for now
"""
class SYSTEM_MANDATORY_LABEL_ACE(Structure):
    ACE_TYPE = 0x11
    structure = (
        ('Mask', ':', ACCESS_MASK),
        ('Sid', ':', LDAP_SID)
    )

"""
SYSTEM_AUDIT_CALLBACK_ACE as described in 2.4.4.14
https://msdn.microsoft.com/en-us/library/cc230378.aspx
Structure is identical to ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
"""
class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE):
    ACE_TYPE = 0x0F

"""
SYSTEM_RESOURCE_ATTRIBUTE_ACE as described in 2.4.4.15
https://msdn.microsoft.com/en-us/library/hh877837.aspx
Structure is identical to ACCESS_ALLOWED_CALLBACK_ACE
The application data however is encoded in CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
format as described in section 2.4.10.1
Todo: implement this substructure if needed
"""
class SYSTEM_RESOURCE_ATTRIBUTE_ACE(ACCESS_ALLOWED_CALLBACK_ACE):
    ACE_TYPE = 0x12


"""
SYSTEM_SCOPED_POLICY_ID_ACE as described in 2.4.4.16
https://msdn.microsoft.com/en-us/library/hh877846.aspx
Structure is identical to ACCESS_ALLOWED_ACE
The Sid data MUST match a CAPID of a CentralAccessPolicy
contained in the CentralAccessPoliciesList
Todo: implement this substructure if needed
Also the ACCESS_MASK must always be 0
"""
class SYSTEM_SCOPED_POLICY_ID_ACE(ACCESS_ALLOWED_ACE):
    ACE_TYPE = 0x13

# All the ACE types in a list
ACE_TYPES = [
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_DENIED_ACE,
    ACCESS_DENIED_OBJECT_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_DENIED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE,
    SYSTEM_AUDIT_ACE,
    SYSTEM_AUDIT_OBJECT_ACE,
    SYSTEM_AUDIT_CALLBACK_ACE,
    SYSTEM_MANDATORY_LABEL_ACE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE,
    SYSTEM_SCOPED_POLICY_ID_ACE
]

# A dict of all the ACE types indexed by their type number
ACE_TYPE_MAP = {ace.ACE_TYPE: ace for ace in ACE_TYPES}

"""
ACL as described in 2.4.5
https://msdn.microsoft.com/en-us/library/cc230297.aspx
"""
class ACL(Structure):
    structure = (
        ('AclRevision', 'B'),
        ('Sbz1', 'B'),
        ('AclSize', '<H'),
        ('AceCount', '<H'),
        ('Sbz2', '<H'),
        # Virtual field to calculate data length from AclSize
        ('DataLen', '_-Data', 'self["AclSize"]-8'),
        ('Data', ':'),
    )

    def fromString(self, data):
        self.aces = []
        Structure.fromString(self, data)
        for i in range(self['AceCount']):
            # If we don't have any data left, return
            if len(self['Data']) == 0:
                raise Exception("ACL header indicated there are more ACLs to unpack, but there is no more data")
            ace = ACE(data=self['Data'])
            self.aces.append(ace)
            self['Data'] = self['Data'][ace['AceSize']:]
        self['Data'] = self.aces

    def getData(self):
        self['AceCount'] = len(self.aces)
        # We modify the data field to be able to use the
        # parent class parsing
        self['Data'] = b''.join([ace.getData() for ace in self.aces])
        self['AclSize'] = len(self['Data'])+8 # Header size (8 bytes) is included
        data = Structure.getData(self)
        # Put the ACEs back in data
        self['Data'] = self.aces
        return data

"""
objectClass mapping to GUID for some common classes (index is the ldapDisplayName).
Reference:
    https://msdn.microsoft.com/en-us/library/ms680938(v=vs.85).aspx
Can also be queried from the Schema
"""
OBJECTTYPE_GUID_MAP = {
    b'group': 'bf967a9c-0de6-11d0-a285-00aa003049e2',
    b'domain': '19195a5a-6da0-11d0-afd3-00c04fd930c9',
    b'organizationalUnit': 'bf967aa5-0de6-11d0-a285-00aa003049e2',
    b'user': 'bf967aba-0de6-11d0-a285-00aa003049e2',
    b'groupPolicyContainer': 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
}
