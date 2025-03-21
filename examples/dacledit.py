#!/usr/bin/env python3
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
# Description:
#   Python script to read and manage the Discretionary Access Control List of an object
#
# Authors:
#   Charlie BROMBERG (@_nwodtuhs)
#   Guillaume DAUMAS (@BlWasp_)
#   Lucien DOUSTALY (@Wlayzz)
#

import argparse
import binascii
import codecs
import json
import logging
import os
import sys
import traceback
import datetime

import ldap3
import ldapdomaindump
from enum import Enum
from ldap3.protocol.formatters.formatters import format_sid

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldaptypes
from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.uuid import string_to_bin, bin_to_string

from impacket.examples.utils import init_ldap_session, parse_identity

OBJECT_TYPES_GUID = {}
OBJECT_TYPES_GUID.update(SCHEMA_OBJECTS)
OBJECT_TYPES_GUID.update(EXTENDED_RIGHTS)

# Universal SIDs
WELL_KNOWN_SIDS = {
    'S-1-0': 'Null Authority',
    'S-1-0-0': 'Nobody',
    'S-1-1': 'World Authority',
    'S-1-1-0': 'Everyone',
    'S-1-2': 'Local Authority',
    'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon',
    'S-1-3': 'Creator Authority',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-3-2': 'Creator Owner Server',
    'S-1-3-3': 'Creator Group Server',
    'S-1-3-4': 'Owner Rights',
    'S-1-5-80-0': 'All Services',
    'S-1-4': 'Non-unique Authority',
    'S-1-5': 'NT Authority',
    'S-1-5-1': 'Dialup',
    'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch',
    'S-1-5-4': 'Interactive',
    'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous',
    'S-1-5-8': 'Proxy',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-12': 'Restricted Code',
    'S-1-5-13': 'Terminal Server Users',
    'S-1-5-14': 'Remote Interactive Logon',
    'S-1-5-15': 'This Organization',
    'S-1-5-17': 'This Organization',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority',
    'S-1-5-20': 'NT Authority',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-547': 'Power Users',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-64-10': 'NTLM Authentication',
    'S-1-5-64-14': 'SChannel Authentication',
    'S-1-5-64-21': 'Digest Authority',
    'S-1-5-80': 'NT Service',
    'S-1-5-83-0': 'NT VIRTUAL MACHINE\\Virtual Machines',
    'S-1-16-0': 'Untrusted Mandatory Level',
    'S-1-16-4096': 'Low Mandatory Level',
    'S-1-16-8192': 'Medium Mandatory Level',
    'S-1-16-8448': 'Medium Plus Mandatory Level',
    'S-1-16-12288': 'High Mandatory Level',
    'S-1-16-16384': 'System Mandatory Level',
    'S-1-16-20480': 'Protected Process Mandatory Level',
    'S-1-16-28672': 'Secure Process Mandatory Level',
    'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
    'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
    'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
    'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
    'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
    'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
    'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
    'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
    'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
    'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
    'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
    'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
    'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
    'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
}


# GUID rights enum
# GUID thats permits to identify extended rights in an ACE
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-rightsguid
class RIGHTS_GUID(Enum):
    WriteMembers = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    ResetPassword = "00299570-246d-11d0-a768-00aa006e0529"
    DS_Replication_Get_Changes = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    DS_Replication_Get_Changes_All = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


# ACE flags enum
# New ACE at the end of SACL for inheritance and access return system-audit
# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
class ACE_FLAGS(Enum):
    CONTAINER_INHERIT_ACE = ldaptypes.ACE.CONTAINER_INHERIT_ACE
    FAILED_ACCESS_ACE_FLAG = ldaptypes.ACE.FAILED_ACCESS_ACE_FLAG
    INHERIT_ONLY_ACE = ldaptypes.ACE.INHERIT_ONLY_ACE
    INHERITED_ACE = ldaptypes.ACE.INHERITED_ACE
    NO_PROPAGATE_INHERIT_ACE = ldaptypes.ACE.NO_PROPAGATE_INHERIT_ACE
    OBJECT_INHERIT_ACE = ldaptypes.ACE.OBJECT_INHERIT_ACE
    SUCCESSFUL_ACCESS_ACE_FLAG = ldaptypes.ACE.SUCCESSFUL_ACCESS_ACE_FLAG


# ACE flags enum
# For an ACE, flags that indicate if the ObjectType and the InheritedObjecType are set with a GUID
# Since these two flags are the same for Allowed and Denied access, the same class will be used from 'ldaptypes'
# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
class OBJECT_ACE_FLAGS(Enum):
    ACE_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    ACE_INHERITED_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT


# Access Mask enum
# Access mask permits to encode principal's rights to an object. This is the rights the principal behind the specified SID has
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
# https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum?redirectedfrom=MSDN
class ACCESS_MASK(Enum):
    # Generic Rights
    GenericRead = 0x80000000 # ADS_RIGHT_GENERIC_READ
    GenericWrite = 0x40000000 # ADS_RIGHT_GENERIC_WRITE
    GenericExecute = 0x20000000 # ADS_RIGHT_GENERIC_EXECUTE
    GenericAll = 0x10000000 # ADS_RIGHT_GENERIC_ALL

    # Maximum Allowed access type
    MaximumAllowed = 0x02000000

    # Access System Acl access type
    AccessSystemSecurity = 0x01000000 # ADS_RIGHT_ACCESS_SYSTEM_SECURITY

    # Standard access types
    Synchronize = 0x00100000 # ADS_RIGHT_SYNCHRONIZE
    WriteOwner = 0x00080000 # ADS_RIGHT_WRITE_OWNER
    WriteDACL = 0x00040000 # ADS_RIGHT_WRITE_DAC
    ReadControl = 0x00020000 # ADS_RIGHT_READ_CONTROL
    Delete = 0x00010000 # ADS_RIGHT_DELETE

    # Specific rights
    AllExtendedRights = 0x00000100 # ADS_RIGHT_DS_CONTROL_ACCESS
    ListObject = 0x00000080 # ADS_RIGHT_DS_LIST_OBJECT
    DeleteTree = 0x00000040 # ADS_RIGHT_DS_DELETE_TREE
    WriteProperties = 0x00000020 # ADS_RIGHT_DS_WRITE_PROP
    ReadProperties = 0x00000010 # ADS_RIGHT_DS_READ_PROP
    Self = 0x00000008 # ADS_RIGHT_DS_SELF
    ListChildObjects = 0x00000004 # ADS_RIGHT_ACTRL_DS_LIST
    DeleteChild = 0x00000002 # ADS_RIGHT_DS_DELETE_CHILD
    CreateChild = 0x00000001 # ADS_RIGHT_DS_CREATE_CHILD


# Simple permissions enum
# Simple permissions are combinaisons of extended permissions
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)?redirectedfrom=MSDN
class SIMPLE_PERMISSIONS(Enum):
    FullControl = 0xf01ff
    Modify = 0x0301bf
    ReadAndExecute = 0x0200a9
    ReadAndWrite = 0x02019f
    Read = 0x20094
    Write = 0x200bc


# Mask ObjectType field enum
# Possible values for the Mask field in object-specific ACE (permitting to specify extended rights in the ObjectType field for example)
# Since these flags are the same for Allowed and Denied access, the same class will be used from 'ldaptypes'
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ALLOWED_OBJECT_ACE_MASK_FLAGS(Enum):
    ControlAccess = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    CreateChild = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD
    DeleteChild = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD
    ReadProperty = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP
    WriteProperty = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    Self = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF


class DACLedit(object):
    """docstring for setrbcd"""

    def __init__(self, ldap_server, ldap_session, args):
        super(DACLedit, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

        self.target_sAMAccountName = args.target_sAMAccountName
        self.target_SID = args.target_SID
        self.target_DN = args.target_DN

        self.principal_sAMAccountName = args.principal_sAMAccountName
        self.principal_SID = args.principal_SID
        self.principal_DN = args.principal_DN

        self.ace_type = args.ace_type
        self.rights = args.rights
        self.rights_guid = args.rights_guid
        self.filename = args.filename
        self.inheritance = args.inheritance
        if self.inheritance:
            logging.info("NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU")

        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

        if self.target_sAMAccountName or self.target_SID or self.target_DN:
            # Searching for target account with its security descriptor
            self.search_target_principal_security_descriptor()
            # Extract security descriptor data
            self.principal_raw_security_descriptor = self.target_principal['nTSecurityDescriptor'].raw_values[0]
            self.principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.principal_raw_security_descriptor)

        # Searching for the principal SID if any principal argument was given and principal_SID wasn't
        if self.principal_SID is None and self.principal_sAMAccountName is not None or self.principal_DN is not None:
            _lookedup_principal = ""
            if self.principal_sAMAccountName is not None:
                _lookedup_principal = self.principal_sAMAccountName
                self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(_lookedup_principal), attributes=['objectSid'])
            elif self.principal_DN is not None:
                _lookedup_principal = self.principal_DN
                self.ldap_session.search(self.domain_dumper.root, '(distinguishedName=%s)' % _lookedup_principal, attributes=['objectSid'])
            try:
                self.principal_SID = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
                logging.debug("Found principal SID: %s" % self.principal_SID)
            except IndexError:
                logging.error('Principal SID not found in LDAP (%s)' % _lookedup_principal)
                exit(1)


    # Main read funtion
    # Prints the parsed DACL
    def read(self):
        parsed_dacl = self.parseDACL(self.principal_security_descriptor['Dacl'])
        self.printparsedDACL(parsed_dacl)
        return


    # Main write function
    # Attempts to add a new ACE to a DACL
    def write(self):
        # Creates ACEs with the specified GUIDs and the SID, or FullControl if no GUID is specified
        # Append the ACEs in the DACL locally
        if self.rights == "FullControl" and self.rights_guid is None:
            logging.debug("Appending ACE (%s --(FullControl)--> %s)" % (self.principal_SID, format_sid(self.target_SID)))
            self.principal_security_descriptor['Dacl'].aces.append(self.create_ace(SIMPLE_PERMISSIONS.FullControl.value, self.principal_SID, self.ace_type))
        else:
            for rights_guid in self.build_guids_for_rights():
                logging.debug("Appending ACE (%s --(%s)--> %s)" % (self.principal_SID, rights_guid, format_sid(self.target_SID)))
                self.principal_security_descriptor['Dacl'].aces.append(self.create_object_ace(rights_guid, self.principal_SID, self.ace_type))
        # Backups current DACL before add the new one
        self.backup()
        # Effectively push the DACL with the new ACE
        self.modify_secDesc_for_dn(self.target_principal.entry_dn, self.principal_security_descriptor)
        return


    # Attempts to remove an ACE from the DACL
    # To do it, a new DACL is built locally with all the ACEs that must NOT BE removed, and this new DACL is pushed on the server
    def remove(self):
        compare_aces = []
        # Creates ACEs with the specified GUIDs and the SID, or FullControl if no GUID is specified
        # These ACEs will be used as comparison templates
        if self.rights == "FullControl" and self.rights_guid is None:
            compare_aces.append(self.create_ace(SIMPLE_PERMISSIONS.FullControl.value, self.principal_SID, self.ace_type))
        else:
            for rights_guid in self.build_guids_for_rights():
                compare_aces.append(self.create_object_ace(rights_guid, self.principal_SID, self.ace_type))
        new_dacl = []
        i = 0
        dacl_must_be_replaced = False
        for ace in self.principal_security_descriptor['Dacl'].aces:
            ace_must_be_removed = False
            for compare_ace in compare_aces:
                # To be sure the good ACEs are removed, multiple fields are compared between the templates and the ACEs in the DACL
                #   - ACE type
                #   - ACE flags
                #   - Access masks
                #   - Revision
                #   - SubAuthorityCount
                #   - SubAuthority
                #   - IdentifierAuthority value
                if ace['AceType'] == compare_ace['AceType'] \
                    and ace['AceFlags'] == compare_ace['AceFlags']\
                    and ace['Ace']['Mask']['Mask'] == compare_ace['Ace']['Mask']['Mask']\
                    and ace['Ace']['Sid']['Revision'] == compare_ace['Ace']['Sid']['Revision']\
                    and ace['Ace']['Sid']['SubAuthorityCount'] == compare_ace['Ace']['Sid']['SubAuthorityCount']\
                    and ace['Ace']['Sid']['SubAuthority'] == compare_ace['Ace']['Sid']['SubAuthority']\
                    and ace['Ace']['Sid']['IdentifierAuthority']['Value'] == compare_ace['Ace']['Sid']['IdentifierAuthority']['Value']:
                    # If the ACE has an ObjectType, the GUIDs must match
                    if 'ObjectType' in ace['Ace'].fields.keys() and 'ObjectType' in compare_ace['Ace'].fields.keys():
                        if ace['Ace']['ObjectType'] == compare_ace['Ace']['ObjectType']:
                            ace_must_be_removed = True
                            dacl_must_be_replaced = True
                    else:
                        ace_must_be_removed = True
                        dacl_must_be_replaced = True
            # If the ACE doesn't match any ACEs from the template list, it is added to the DACL that will be pushed
            if not ace_must_be_removed:
                new_dacl.append(ace)
            elif logging.getLogger().level == logging.DEBUG:
                logging.debug("This ACE will be removed")
                self.printparsedACE(self.parseACE(ace))
            i += 1
        # If at least one ACE must been removed
        if dacl_must_be_replaced:
            self.principal_security_descriptor['Dacl'].aces = new_dacl
            self.backup()
            self.modify_secDesc_for_dn(self.target_principal.entry_dn, self.principal_security_descriptor)
        else:
            logging.info("Nothing to remove...")

    
    # Permits to backup a DACL before a modification
    # This function is called before any writing action (write, remove or restore)
    def backup(self):
        backup = {}
        backup["sd"] = binascii.hexlify(self.principal_raw_security_descriptor).decode('utf-8')
        backup["dn"] = self.target_principal.entry_dn
        if not self.filename:
            self.filename = 'dacledit-%s.bak' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        else:
            if os.path.exists(self.filename):
                logging.info("File %s already exists, I'm refusing to overwrite it, setting another filename" % self.filename)
                self.filename = 'dacledit-%s.bak' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        with codecs.open(self.filename, 'w', 'utf-8') as outfile:
            json.dump(backup, outfile)
        logging.info('DACL backed up to %s', self.filename)

    
    # Permits to restore a saved DACL
    def restore(self):
        # Opens and load the file where the DACL has been saved
        with codecs.open(self.filename, 'r', 'utf-8') as infile:
            restore = json.load(infile)
            assert "sd" in restore.keys()
            assert "dn" in restore.keys()
        # Extracts the Security Descriptor and converts it to the good ldaptypes format
        new_raw_security_descriptor = binascii.unhexlify(restore["sd"].encode('utf-8'))
        new_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=new_raw_security_descriptor)

        self.target_DN = restore["dn"]
        # Searching for target account with its security descriptor
        self.search_target_principal_security_descriptor()
        # Extract security descriptor data
        self.principal_raw_security_descriptor = self.target_principal['nTSecurityDescriptor'].raw_values[0]
        self.principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.principal_raw_security_descriptor)

        # Do a backup of the actual DACL and push the restoration
        self.backup()
        logging.info('Restoring DACL')
        self.modify_secDesc_for_dn(self.target_DN, new_security_descriptor)
    
    # Attempts to retrieve the DACL in the Security Descriptor of the specified target
    def search_target_principal_security_descriptor(self):
        _lookedup_principal = ""
        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        if self.target_sAMAccountName is not None:
            _lookedup_principal = self.target_sAMAccountName
            self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(_lookedup_principal), attributes=['nTSecurityDescriptor'], controls=controls)
        elif self.target_SID is not None:
            _lookedup_principal = self.target_SID
            self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % _lookedup_principal, attributes=['nTSecurityDescriptor'], controls=controls)
        elif self.target_DN is not None:
            _lookedup_principal = self.target_DN
            self.ldap_session.search(self.domain_dumper.root, '(distinguishedName=%s)' % _lookedup_principal, attributes=['nTSecurityDescriptor'], controls=controls)
        try:
            self.target_principal = self.ldap_session.entries[0]
            logging.debug('Target principal found in LDAP (%s)' % _lookedup_principal)
        except IndexError:
            logging.error('Target principal not found in LDAP (%s)' % _lookedup_principal)
            exit(0)

    
    # Attempts to retieve the SID and Distinguisehd Name from the sAMAccountName
    # Not used for the moment
    #   - samname : a sAMAccountName
    def get_user_info(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    
    # Attempts to resolve a SID and return the corresponding samaccountname
    #   - sid : the SID to resolve
    def resolveSID(self, sid):
        # Tries to resolve the SID from the well known SIDs
        if sid in WELL_KNOWN_SIDS.keys():
            return WELL_KNOWN_SIDS[sid]
        # Tries to resolve the SID from the LDAP domain dump
        else:
            self.ldap_session.search(self.domain_dumper.root, '(objectSid=%s)' % sid, attributes=['samaccountname'])
            try:
                dn = self.ldap_session.entries[0].entry_dn
                samname = self.ldap_session.entries[0]['samaccountname']
                return samname
            except IndexError:
                logging.debug('SID not found in LDAP: %s' % sid)
                return ""

    
    # Parses a full DACL
    #   - dacl : the DACL to parse, submitted in a Security Desciptor format
    def parseDACL(self, dacl):
        parsed_dacl = []
        logging.info("Parsing DACL")
        i = 0
        for ace in dacl['Data']:
            parsed_ace = self.parseACE(ace)
            parsed_dacl.append(parsed_ace)
            i += 1
        return parsed_dacl

    
    # Parses an access mask to extract the different values from a simple permission
    # https://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
    #   - fsr : the access mask to parse
    def parsePerms(self, fsr):
        _perms = []
        for PERM in SIMPLE_PERMISSIONS:
            if (fsr & PERM.value) == PERM.value:
                _perms.append(PERM.name)
                fsr = fsr & (not PERM.value)
        for PERM in ACCESS_MASK:
            if fsr & PERM.value:
                _perms.append(PERM.name)
        return _perms

    
    # Parses a specified ACE and extract the different values (Flags, Access Mask, Trustee, ObjectType, InheritedObjectType)
    #   - ace : the ACE to parse
    def parseACE(self, ace):
        # For the moment, only the Allowed and Denied Access ACE are supported
        if ace['TypeName'] in [ "ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_ACE", "ACCESS_DENIED_OBJECT_ACE" ]:
            parsed_ace = {}
            parsed_ace['ACE Type'] = ace['TypeName']
            # Retrieves ACE's flags
            _ace_flags = []
            for FLAG in ACE_FLAGS:
                if ace.hasFlag(FLAG.value):
                    _ace_flags.append(FLAG.name)
            parsed_ace['ACE flags'] = ", ".join(_ace_flags) or "None"

            # For standard ACE
            # Extracts the access mask (by parsing the simple permissions) and the principal's SID
            if ace['TypeName'] in [ "ACCESS_ALLOWED_ACE", "ACCESS_DENIED_ACE" ]:
                parsed_ace['Access mask'] = "%s (0x%x)" % (", ".join(self.parsePerms(ace['Ace']['Mask']['Mask'])), ace['Ace']['Mask']['Mask'])
                parsed_ace['Trustee (SID)'] = "%s (%s)" % (self.resolveSID(ace['Ace']['Sid'].formatCanonical()) or "UNKNOWN", ace['Ace']['Sid'].formatCanonical())

            # For object-specific ACE
            elif ace['TypeName'] in [ "ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_OBJECT_ACE" ]:
                # Extracts the mask values. These values will indicate the ObjectType purpose
                _access_mask_flags = []
                for FLAG in ALLOWED_OBJECT_ACE_MASK_FLAGS:
                    if ace['Ace']['Mask'].hasPriv(FLAG.value):
                        _access_mask_flags.append(FLAG.name)
                parsed_ace['Access mask'] = ", ".join(_access_mask_flags)
                # Extracts the ACE flag values and the trusted SID
                _object_flags = []
                for FLAG in OBJECT_ACE_FLAGS:
                    if ace['Ace'].hasFlag(FLAG.value):
                        _object_flags.append(FLAG.name)
                parsed_ace['Flags'] = ", ".join(_object_flags) or "None"
                # Extracts the ObjectType GUID values
                if ace['Ace']['ObjectTypeLen'] != 0:
                    obj_type = bin_to_string(ace['Ace']['ObjectType']).lower()
                    try:
                        parsed_ace['Object type (GUID)'] = "%s (%s)" % (OBJECT_TYPES_GUID[obj_type], obj_type)
                    except KeyError:
                        parsed_ace['Object type (GUID)'] = "UNKNOWN (%s)" % obj_type
                # Extracts the InheritedObjectType GUID values
                if ace['Ace']['InheritedObjectTypeLen'] != 0:
                    inh_obj_type = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                    try:
                        parsed_ace['Inherited type (GUID)'] = "%s (%s)" % (OBJECT_TYPES_GUID[inh_obj_type], inh_obj_type)
                    except KeyError:
                        parsed_ace['Inherited type (GUID)'] = "UNKNOWN (%s)" % inh_obj_type
                # Extract the Trustee SID (the object that has the right over the DACL bearer)
                parsed_ace['Trustee (SID)'] = "%s (%s)" % (self.resolveSID(ace['Ace']['Sid'].formatCanonical()) or "UNKNOWN", ace['Ace']['Sid'].formatCanonical())

        else:
            # If the ACE is not an access allowed
            logging.debug("ACE Type (%s) unsupported for parsing yet, feel free to contribute" % ace['TypeName'])
            parsed_ace = {}
            parsed_ace['ACE type'] = ace['TypeName']
            _ace_flags = []
            for FLAG in ACE_FLAGS:
                if ace.hasFlag(FLAG.value):
                    _ace_flags.append(FLAG.name)
            parsed_ace['ACE flags'] = ", ".join(_ace_flags) or "None"
            parsed_ace['DEBUG'] = "ACE type not supported for parsing by dacleditor.py, feel free to contribute"
        return parsed_ace


    # Prints a full DACL by printing each parsed ACE
    #   - parsed_dacl : a parsed DACL from parseDACL()
    def printparsedDACL(self, parsed_dacl):
        # Attempts to retrieve the principal's SID if it's a write action
        if self.principal_SID is None and self.principal_sAMAccountName or self.principal_DN:
            if self.principal_sAMAccountName is not None:
                _lookedup_principal = self.principal_sAMAccountName
                self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(_lookedup_principal), attributes=['objectSid'])
            elif self.principal_DN is not None:
                _lookedup_principal = self.principal_DN
                self.ldap_session.search(self.domain_dumper.root, '(distinguishedName=%s)' % _lookedup_principal, attributes=['objectSid'])
            try:
                self.principal_SID = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            except IndexError:
                logging.error('Principal not found in LDAP (%s)' % _lookedup_principal)
                return False
            logging.debug("Found principal SID to write in ACE(s): %s" % self.principal_SID)

        logging.info("Printing parsed DACL")
        i = 0
        # If a principal has been specified, only the ACE where he is the trustee will be printed
        if self.principal_SID is not None:
            logging.info("Filtering results for SID (%s)" % self.principal_SID)
        for parsed_ace in parsed_dacl:
            print_ace = True
            if self.principal_SID is not None:
                try:
                    if self.principal_SID not in parsed_ace['Trustee (SID)']:
                        print_ace = False
                except Exception as e:
                    logging.error("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)
            if print_ace:
                logging.info("  %-28s" % "ACE[%d] info" % i)
                self.printparsedACE(parsed_ace)
            i += 1


    # Prints properly a parsed ACE
    #   - parsed_ace : a parsed ACE from parseACE()
    def printparsedACE(self, parsed_ace):
        elements_name = list(parsed_ace.keys())
        for attribute in elements_name:
            logging.info("    %-26s: %s" % (attribute, parsed_ace[attribute]))


    # Retrieves the GUIDs for the specified rights
    def build_guids_for_rights(self):
        _rights_guids = []
        if self.rights_guid is not None:
            _rights_guids = [self.rights_guid]
        elif self.rights == "WriteMembers":
            _rights_guids = [RIGHTS_GUID.WriteMembers.value]
        elif self.rights == "ResetPassword":
            _rights_guids = [RIGHTS_GUID.ResetPassword.value]
        elif self.rights == "DCSync":
            _rights_guids = [RIGHTS_GUID.DS_Replication_Get_Changes.value, RIGHTS_GUID.DS_Replication_Get_Changes_All.value]
        logging.debug('Built GUID: %s', _rights_guids)
        return _rights_guids


    # Attempts to push the locally built DACL to the remote server into the security descriptor of the specified principal
    # The target principal is specified with its Distinguished Name
    #   - dn : the principal's Distinguished Name to modify
    #   - secDesc : the Security Descriptor with the new DACL to push
    def modify_secDesc_for_dn(self, dn, secDesc):
        data = secDesc.getData()
        controls = security_descriptor_control(sdflags=0x04)
        logging.debug('Attempts to modify the Security Descriptor.')
        self.ldap_session.modify(dn, {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.ldap_session.result['result'] == 0:
            logging.info('DACL modified successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])


    # Builds a standard ACE for a specified access mask (rights) and a specified SID (the principal who obtains the right)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
    #   - access_mask : the allowed access mask
    #   - sid : the principal's SID
    #   - ace_type : the ACE type (allowed or denied)
    def create_ace(self, access_mask, sid, ace_type):
        nace = ldaptypes.ACE()
        if ace_type == "allowed":
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        else:
            nace['AceType'] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_ACE()
        if self.inheritance:
            nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
        else:
            nace['AceFlags'] = 0x00
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = access_mask
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        logging.debug('ACE created.')
        return nace


    # Builds an object-specific for a specified ObjectType (an extended right, a property, etc, to add) for a specified SID (the principal who obtains the right)
    # The Mask is "ADS_RIGHT_DS_CONTROL_ACCESS" (the ObjectType GUID will identify an extended access right)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
    #   - privguid : the ObjectType (an Extended Right here)
    #   - sid : the principal's SID
    #   - ace_type : the ACE type (allowed or denied)
    def create_object_ace(self, privguid, sid, ace_type):
        nace = ldaptypes.ACE()
        if ace_type == "allowed":
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        else:
            nace['AceType'] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_OBJECT_ACE()           
        if self.inheritance:
            nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
        else:
            nace['AceFlags'] = 0x00
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        # WriteMembers not an extended right, we need read and write mask on the attribute (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
        if privguid == RIGHTS_GUID.WriteMembers.value:
            acedata['Mask'][
                'Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP + ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
        # Other rights in this script are extended rights and need the DS_CONTROL_ACCESS mask
        else:
            acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
        acedata['ObjectType'] = string_to_bin(privguid)
        acedata['InheritedObjectType'] = b''
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        assert sid == acedata['Sid'].formatCanonical()
        # This ACE flag verifes if the ObjectType is valid
        acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        nace['Ace'] = acedata
        logging.debug('Object-specific ACE created.')
        return nace




def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python editor for a principal\'s DACL.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth_con.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auth_con.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_con.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

    principal_parser = parser.add_argument_group("principal", description="Object, controlled by the attacker, to reference in the ACE to create or to filter when printing a DACL")
    principal_parser.add_argument("-principal", dest="principal_sAMAccountName", metavar="NAME", type=str, required=False, help="sAMAccountName")
    principal_parser.add_argument("-principal-sid", dest="principal_SID", metavar="SID", type=str, required=False, help="Security IDentifier")
    principal_parser.add_argument("-principal-dn", dest="principal_DN", metavar="DN", type=str, required=False, help="Distinguished Name")

    target_parser = parser.add_argument_group("target", description="Principal object to read/edit the DACL of")
    target_parser.add_argument("-target", dest="target_sAMAccountName", metavar="NAME", type=str, required=False, help="sAMAccountName")
    target_parser.add_argument("-target-sid", dest="target_SID", metavar="SID", type=str, required=False, help="Security IDentifier")
    target_parser.add_argument("-target-dn", dest="target_DN", metavar="DN", type=str, required=False, help="Distinguished Name")

    dacl_parser = parser.add_argument_group("dacl editor")
    dacl_parser.add_argument('-action', choices=['read', 'write', 'remove', 'backup', 'restore'], nargs='?', default='read', help='Action to operate on the DACL')
    dacl_parser.add_argument('-file', dest="filename", type=str, help='Filename/path (optional for -action backup, required for -restore))')
    dacl_parser.add_argument('-ace-type', choices=['allowed', 'denied'], nargs='?', default='allowed', help='The ACE Type (access allowed or denied) that must be added or removed (default: allowed)')
    dacl_parser.add_argument('-rights', choices=['FullControl', 'ResetPassword', 'WriteMembers', 'DCSync'], nargs='?', default='FullControl', help='Rights to write/remove in the target DACL (default: FullControl)')
    dacl_parser.add_argument('-rights-guid', type=str, help='Manual GUID representing the right to write/remove')
    dacl_parser.add_argument('-inheritance', action="store_true", help='Enable the inheritance in the ACE flag with CONTAINER_INHERIT_ACE and OBJECT_INHERIT_ACE. Useful when target is a Container or an OU, '
                                                                       'ACE will be inherited by objects within the container/OU (except objects with adminCount=1)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    if args.action == 'write' and args.principal_sAMAccountName is None and args.principal_SID is None and args.principal_DN is None:
        logging.critical('-principal, -principal-sid, or -principal-dn should be specified when using -action write')
        sys.exit(1)

    if args.action == "restore" and not args.filename:
        logging.critical('-file is required when using -action restore')

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.aesKey, args.use_ldaps)
        dacledit = DACLedit(ldap_server, ldap_session, args)
        if args.action == 'read':
            dacledit.read()
        elif args.action == 'write':
            dacledit.write()
        elif args.action == 'remove':
            dacledit.remove()
        elif args.action == 'flush':
            dacledit.flush()
        elif args.action == 'backup':
            dacledit.backup()
        elif args.action == 'restore':
            dacledit.restore()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
