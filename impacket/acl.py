<<<<<<< HEAD
=======
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
#   Windows ACL (Access Control List) handling for SMB file permissions.
#   Provides structures and utilities for reading and modifying NTFS security descriptors.
#
# Author:
#   Gefen Altshuler (@gaffner)
#

>>>>>>> master
from impacket.structure import Structure
from impacket.dcerpc.v5 import lsad, lsat
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import GENERIC_ALL
from impacket.smb3structs import FileSecInformation

import struct

# ACE FLAGS
SMB_ACE_FLAG_OI = 0x1
SMB_ACE_FLAG_CI = 0x2
SMB_ACE_FLAG_IO = 0x8
SMB_ACE_FLAG_NP = 0x4
SMB_ACE_FLAG_I = 0x10

# STANDARD RIGHTS
SEC_INFO_STANDARD_WRITE = 0x8
SEC_INFO_STANDARD_READ = 0x2
SEC_INFO_STANDARD_DELETE = 0x1

# SPECIFIC RIGHTS
SEC_INFO_SPECIFIC_WRITE = 0x116
SEC_INFO_SPECIFIC_EXECUTE = 0x20
SEC_INFO_SPECIFIC_FULL = 0x1FF

# COMBINED RIGHTS
SEC_READ_RIGHT = 0x00120089

SUPPORTED_PERMISSIONS = {
    "R": 0x00120089,
    "W": 0x00100116,
    "D": 0x00110000,
    "X": 0x00000020,
    "F": 0x001F01FF,
}


# NT User (DACL) ACL
class FileNTUser( Structure ):
    structure = (
        ("Revision", "<H=1"),
        ("Size", "<H=1"),
        ("NumACEs", "<I=1"),
        ("Buffer", ":"),
    )


# SID
class ACL_SID( Structure ):
    structure = (
        ("Revision", "<B"),
        ("NumAuth", "<B"),
<<<<<<< HEAD
        ("Authority", "<6B"),
=======
        ("Authority", "6s"),
>>>>>>> master
        ("Subauthorities", ":"),
    )

    def __repr__(self):
<<<<<<< HEAD
        n = len( self["Subauthorities"] ) / 4
        return "-".join(
            map(
                str,
                ["S", int( self["Revision"] ), int( self["NumAuth"] )]
=======
        n = len( self["Subauthorities"] ) // 4
        # Authority is 6 bytes stored as big-endian (most significant byte last for Windows SIDs)
        authority = struct.unpack(">H", self["Authority"][4:6])[0]
        return "-".join(
            map(
                str,
                ["S", int( self["Revision"] ), authority]
>>>>>>> master
                + list( struct.unpack( "<{}I".format(int(n)), self["Subauthorities"] ) ),
            )
        )

    @staticmethod
    def build_from_string(data):
        items = data.split( "-" )[1:]  # delete the S prefix
        revision = int( items[0] )
        numAuth = int( items[1] )
        sub_length = len( items ) - 2  # minus the revision and numAuth
        subauthorities = struct.pack( "<{}I".format(sub_length), *tuple( map( int, items[2:] ) ) )
        raw_sid = (
                struct.pack( "<2B", revision, numAuth )
                + b"\x00" * 5
                + struct.pack( "<B", numAuth )
                + subauthorities
        )
        return ACL_SID( raw_sid )

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

    def __hash__(self):
        return self.__repr__().__hash__()

    def split(self, *args, **kwargs):
        return self.__str__().split( *args, **kwargs )


# NT ACE
class FileNTACE( Structure ):
    structure = (
        ("Type", "<B"),
        ("NTACE_Flags", "<B"),
        ("Size", "<H"),
        ("SpecificRights", "<H"),
        ("StandardRights", "<B"),
        ("GenericRights", "<B"),
        ("_SID", "_-SID", '(self["Size"] - 8)'),
        ("SID", ':=""', ACL_SID),
    )

    def __str__(self):
<<<<<<< HEAD
        return (
            "{}:{}:{}".format(self.get_readable_ntace_flags(),
                              self.get_readable_standard_rights(),
                              self.get_readable_specific_rights())
        )

    def get_readable_ntace_flags(self):
        """
        return the NTACE Flags in readable format
=======
        flags = self.get_readable_ntace_flags()
        specific = self.get_readable_specific_rights()
        
        # If we have full control (F), don't show redundant standard rights
        if specific == "(F)":
            return flags + specific
        
        # Otherwise show standard rights along with any specific rights
        standard = self.get_readable_standard_rights()
        return flags + standard + specific

    def get_readable_ntace_flags(self):
        """
        Return the NTACE flags in readable format
>>>>>>> master
        (OI) - object inherit
        (CI) - container inherit
        (IO) - inherit only
        (NP) - don't propagate inherit
        (I) - permission inherited from parent container
        """
        flags = ""
        if self["NTACE_Flags"] & SMB_ACE_FLAG_OI:
            flags += "(OI)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_CI:
            flags += "(CI)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_IO:
            flags += "(IO)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_NP:
            flags += "(NP)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_I:
            flags += "(I)"

        if flags == "":
<<<<<<< HEAD
            return "\b"  # delete one char (the colons)
=======
            return ""  # No flags set
>>>>>>> master

        return flags

    def get_readable_standard_rights(self):
        """
<<<<<<< HEAD
        return the standard rights in readable format
        NOTE: not covering all the standard rights (WRITE DAC and SYNC)
=======
        Return the standard rights in readable format
        NOTE: does not cover all standard rights (WRITE_DAC and SYNC)
>>>>>>> master
        R - read-only access
        W - write-only access
        D - delete access
        """
        flags = ""
        if self["StandardRights"] & SEC_INFO_STANDARD_READ:
            flags += "(R)"
        if self["StandardRights"] & SEC_INFO_STANDARD_WRITE:
            flags += "(w)"
        if self["StandardRights"] & SEC_INFO_STANDARD_DELETE:
            flags += "(D)"

        return flags

    def get_readable_specific_rights(self):
        """
<<<<<<< HEAD
        return the specific rights in readable format
        NOTE: not covering all the specific rights (only write, execute, full control)
=======
        Return the specific rights in readable format
        NOTE: does not cover all specific rights (only write, execute, full control)
>>>>>>> master
        W - write access
        X - execute access
        F - full control
        """
        if self["SpecificRights"] & SEC_INFO_SPECIFIC_FULL == SEC_INFO_SPECIFIC_FULL:
            return "(F)"  # Full control, no need to waste time

        flags = ""
        if self["SpecificRights"] & SEC_INFO_SPECIFIC_WRITE == SEC_INFO_SPECIFIC_WRITE:
            flags += "(W)"
        if (
                self["SpecificRights"] & SEC_INFO_SPECIFIC_EXECUTE
                == SEC_INFO_SPECIFIC_EXECUTE
        ):
            flags += "(X)"

        return flags


class SecurityAttributes:
    """
<<<<<<< HEAD
    This class represent the security attribute of file
=======
    This class represents the security attributes of a file
>>>>>>> master
    """

    def __init__(self, owner, group):
        self.owner = owner
        self.group = group
        self.dacls = {}
<<<<<<< HEAD
        self.readable_dacls = {}  # {mame: dacls}
=======
        self.readable_dacls = {}  # {name: dacls}
>>>>>>> master

    def __repr__(self):
        return (
            "Owner:\t{}\n"
            "Group:\t{}\n"
<<<<<<< HEAD
            "Dacl's:\t"
            "{}".format(self.owner, self.group,
                        "\n        ".join([str( self.readable_dacls[sid] ) for sid in self.readable_dacls])))
=======
            "ACLs:\t"
            "{}".format(self.owner, self.group,
                        "\n\t".join([str( self.readable_dacls[sid] ) for sid in self.readable_dacls])))
>>>>>>> master

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()


<<<<<<< HEAD
class Permissions:
    """
    Manage windows file permissions. you can show, set or remove acl's.
    You must have the appropriate permission to do so.
    """

    def __init__(self, ip, remote_name, username, password, domain):
=======
class SMBFileACL:
    """
    Manage Windows file ACLs over SMB. You can view, set, or remove ACLs.
    You must have the appropriate permissions to do so.
    """

    def __init__(self, ip=None, remote_name=None, username='', password='', domain='', lmhash='', nthash='', aesKey=None, doKerberos=False, kdcHost=None, smb_connection=None):
>>>>>>> master
        """
        @param ip: target server's remote address (IPv4, IPv6) or FQDN
        @param remote_name: Remote NetBIOS name
        @param username: username
        @param password: password
        @param domain: domain where the account is valid for
<<<<<<< HEAD
        """
        self.sid_to_name = {
            ACL_SID.build_from_string( "S-1-1-18" ): "NT AUTHORITY\\SYSTEM"
=======
        @param lmhash: LM hash for NTLM authentication
        @param nthash: NT hash for NTLM authentication
        @param aesKey: AES key for Kerberos authentication
        @param doKerberos: Use Kerberos authentication
        @param kdcHost: KDC hostname or IP address
        @param smb_connection: existing SMBConnection to reuse (if provided, other auth params are ignored)
        """
        self.sid_to_name = {
            ACL_SID.build_from_string("S-1-5-18"): "NT AUTHORITY\\SYSTEM"
>>>>>>> master
        }

        self.rid_to_name = {
            "544": "BUILTIN\\Administrators",
            "513": "Domain Users",
        }

<<<<<<< HEAD
        self.connection = SMBConnection( remote_name, ip )
        self.connection.login( username, password, domain )
=======
        self._owns_connection = smb_connection is None
        
        if smb_connection is not None:
            self.connection = smb_connection
        else:
            self.connection = SMBConnection(remote_name, ip)
            if doKerberos:
                self.connection.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, kdcHost)
            else:
                self.connection.login(username, password, domain, lmhash, nthash)
        
>>>>>>> master
        self.dce_rpc = self.start_dce_rpc()
        self.policy_handle = self.open_policy_handle()
        self.transport = None
        self.tid = None
        self.fid = None

    def close_connection(self):
        """
        Disconnect from the tree id, close the file
        and disconnect from the smb server
        """

        # close policy handle and transport
<<<<<<< HEAD
        lsad.hLsarClose( self.dce_rpc, self.policy_handle )
        self.transport.disconnect()

        # close the smb connection
        self.connection.close()

    def close_file(self):
        """
        close the tree id and file id handles
        """
        if self.fid:
            self.connection.closeFile( self.tid, self.fid )
            self.connection.disconnectTree( self.tid )

    def open_file(self, share_name, file_name):
        """
        Open given file name in the share name
        @param share_name: share to connect to
        @param file_name: file to open
        """
        self.tid = self.connection.connectTree( share_name )
        self.fid = self.connection.openFile(
            self.tid, file_name, desiredAccess=GENERIC_ALL
        )

    def start_dce_rpc(self):
        """
        Start new dce rpc over smb
        @return: dce rpc
=======
        if self.policy_handle:
            lsad.hLsarClose(self.dce_rpc, self.policy_handle)
        if self.transport:
            self.transport.disconnect()

        # close the smb connection only if we created it
        if self._owns_connection:
            self.connection.close()

    def close_file(self):
        """
        Close the tree ID and file ID handles
        """
        if self.fid:
            self.connection.closeFile(self.tid, self.fid)
        if self.tid:
            self.connection.disconnectTree(self.tid)

    def open_file(self, share_name, file_name):
        """
        Open the given file in the specified share
        @param share_name: share to connect to
        @param file_name: file to open
        @return: tuple of (tid, fid)
        """
        self.tid = self.connection.connectTree(share_name)
        self.fid = self.connection.openFile(
            self.tid, file_name, desiredAccess=GENERIC_ALL
        )
        return self.tid, self.fid

    def start_dce_rpc(self):
        """
        Start a new DCE/RPC connection over SMB
        @return: DCE/RPC connection
>>>>>>> master
        """
        self.transport = SMBTransport(
            self.connection.getRemoteName(),
            smb_connection=self.connection,
            filename="lsarpc",
        )
        self.transport.connect()
        dce = self.transport.get_dce_rpc()

        return dce

    def open_policy_handle(self):
        """
<<<<<<< HEAD
        Open new handle the to MSRPC_UUID_LSAD
        @return: policy handle
        """
        self.dce_rpc.bind( lsad.MSRPC_UUID_LSAD )
        policy_handle = lsad.hLsarOpenPolicy2( self.dce_rpc, lsad.POLICY_LOOKUP_NAMES )[
=======
        Open a new handle to MSRPC_UUID_LSAD
        @return: policy handle
        """
        self.dce_rpc.bind(lsad.MSRPC_UUID_LSAD)
        policy_handle = lsad.hLsarOpenPolicy2(self.dce_rpc, lsad.POLICY_LOOKUP_NAMES)[
>>>>>>> master
            "PolicyHandle"
        ]

        return policy_handle

    def set_sid_to_name(self, sids, resp):
        """
<<<<<<< HEAD
        Set the sid_to_name dictionary according to the given sids
        :param sids: sids to translate for there names
=======
        Set the sid_to_name dictionary according to the given SIDs
        :param sids: SIDs to translate to their names
>>>>>>> master
        :param resp: the response containing the names
        :return: None
        """
        names = [name["Name"] for name in resp["TranslatedNames"]["Names"]]
<<<<<<< HEAD
        for i, name in enumerate( names ):
            # should check here if the name is real sid
            if name in ("None", b""):
                name = sids[i]
            rid = name.split( "-" )[-1]
            if rid in self.rid_to_name:
                self.sid_to_name[ACL_SID.build_from_string( name )] = self.rid_to_name[rid]
=======
        for i, name in enumerate(names):
            # should check here if the name is real sid
            if name in ("None", b""):
                name = sids[i]
            rid = name.split("-")[-1]
            if rid in self.rid_to_name:
                self.sid_to_name[ACL_SID.build_from_string(name)] = self.rid_to_name[rid]
>>>>>>> master
            elif sids[i] not in self.sid_to_name:
                self.sid_to_name[sids[i]] = name

    def sids_to_names(self, sids):
        """
<<<<<<< HEAD
        Resolve sid to name using LSA_LookupSids
        :param sids: list of sids
        :return: list of usernames
        """
        try:
            resp = lsat.hLsarLookupSids2( self.dce_rpc, self.policy_handle, sids )
        except lsat.DCERPCSessionError as session_error:
            resp = session_error.packet

        self.set_sid_to_name( sids, resp )

    def name_to_sid(self, name):
        """
        Translate name to sid using LSA_LookupNames
        """
        resp = lsat.hLsarLookupNames3( self.dce_rpc, self.policy_handle, [name] )

        return resp["TranslatedSids"]["Sids"][0]["Sid"].getData()[
               4:
               ]  # don't include the 'count' attribute

    def permissions_to_ace(self, username, permissions):
        """
        Convert the given permissions and user to binary format
        @param username: username to add / remove permissions
        @param permissions: permissions in the icacls format
        """
        access_required = 0x00000000
        if permissions:
            for permission in permissions.split( "," ):
                try:
                    access_required |= SUPPORTED_PERMISSIONS[permission]
                except KeyError:
                    pass

            # check if we couldn't resolve any of the permissions
            if not access_required:
                raise Exception("Unsupported permissions")


        sid_bytes = self.name_to_sid( username )
        total_size = 8 + len( sid_bytes )  # nt ace attributes length + sid length

        permissions_as_bytes = (
                struct.pack( "<BBHI", 0x00, 0x00, total_size, access_required ) + sid_bytes
        )

        return FileNTACE( permissions_as_bytes )

    def get_security_attributes(self, sec):
        """
        Get's the security information of the given FileSecInformation object
=======
        Resolve SIDs to names using LSA_LookupSids
        :param sids: list of SIDs
        :return: list of usernames
        """
        try:
            resp = lsat.hLsarLookupSids2(self.dce_rpc, self.policy_handle, sids)
        except lsat.DCERPCSessionError as session_error:
            resp = session_error.packet

        self.set_sid_to_name(sids, resp)

    def name_to_sid(self, name):
        """
        Translate name to SID using LSA_LookupNames
        """
        try:
            resp = lsat.hLsarLookupNames3(self.dce_rpc, self.policy_handle, [name])
            return resp["TranslatedSids"]["Sids"][0]["Sid"].getData()[4:]  # don't include the 'count' attribute
        except Exception as e:
            raise Exception(f"Failed to resolve name '{name}' to SID: {str(e)}")

    def permissions_to_ace(self, username, permissions, action='grant'):
        """
        Convert given permissions and user to binary format
        @param username: username to add/remove permissions
        @param permissions: permissions in the icacls format
        @param action: 'grant', 'revoke', or 'delete'
        """
        access_required = 0x00000000
        invalid_perms = []
        if permissions:
            for permission in permissions.split(","):
                try:
                    access_required |= SUPPORTED_PERMISSIONS[permission.upper()]
                except KeyError:
                    invalid_perms.append(permission)

            # Warn about invalid permissions
            if invalid_perms:
                import logging
                logging.warning(f"Ignoring unsupported permissions: {', '.join(invalid_perms)}")

            # check if we couldn't resolve any of the permissions
            if not access_required:
                raise Exception("No valid permissions specified")

        sid_bytes = self.name_to_sid(username)
        total_size = 8 + len(sid_bytes)  # nt ace attributes length + sid length

        permissions_as_bytes = (
                struct.pack("<BBHI", 0x00, 0x00, total_size, access_required) + sid_bytes
        )

        ace = FileNTACE(permissions_as_bytes)
        # Store the action type in the ACE for later use
        ace.action = action
        return ace

    def get_security_attributes(self, sec):
        """
        Gets the security information of the given FileSecInformation object
>>>>>>> master
        :param sec: FileSecInformation instance
        :return: SecurityAttributes
        """
        # get owner SID and Group SID
<<<<<<< HEAD
        owner = ACL_SID( sec.rawData[sec["OffsetToOwner"]: sec["OffsetToGroup"]] )
        group = ACL_SID( sec.rawData[sec["OffsetToGroup"]: sec["OffsetToDACL"]] )

        self.sids_to_names( [owner, group] )
=======
        owner = ACL_SID(sec.rawData[sec["OffsetToOwner"]: sec["OffsetToGroup"]])
        group = ACL_SID(sec.rawData[sec["OffsetToGroup"]: sec["OffsetToDACL"]])

        self.sids_to_names([owner, group])
>>>>>>> master

        try:
            owner_name = self.sid_to_name[owner]
        except KeyError:
            owner_name = owner

        try:
            group_name = self.sid_to_name[group]
        except KeyError:
            group_name = group
<<<<<<< HEAD
        security_attributes = SecurityAttributes( owner_name, group_name )

        # get all dacl's
        nt = sec.rawData[sec["OffsetToDACL"]:]
        ntuser = FileNTUser( nt )
        ntace = ntuser["Buffer"]

        while len( ntace ):
            face = FileNTACE( ntace )  # set new FileNTACE
            sid = ACL_SID( face["SID"] )  # get the DACL SID
            ntace = ntace[face["Size"]:]  # slice the buffer
            security_attributes.dacls[sid] = face

        self.sids_to_names( list( security_attributes.dacls.keys() ) )  # ugly
=======
        security_attributes = SecurityAttributes(owner_name, group_name)

        # get all dacl's
        nt = sec.rawData[sec["OffsetToDACL"]:]
        ntuser = FileNTUser(nt)
        ntace = ntuser["Buffer"]

        while len(ntace):
            face = FileNTACE(ntace)  # set new FileNTACE
            sid = ACL_SID(face["SID"])  # get the DACL SID
            ntace = ntace[face["Size"]:]  # slice the buffer
            security_attributes.dacls[sid] = face

        # Resolve all DACL SIDs to names
        self.sids_to_names(list(security_attributes.dacls.keys()))
>>>>>>> master

        for sid, permissions in security_attributes.dacls.items():
            try:
                name = self.sid_to_name[sid]
            except KeyError:
                name = sid

            security_attributes.readable_dacls[sid] = "{}:{}".format(name, permissions)

        return security_attributes

    def get_permissions(self, share_name, file_name):
        """
<<<<<<< HEAD
        Connect to the given share and get the filename permissions
        :return: SecurityAttributes
        @param share_name: the share name where the file is to be opened
        @param file_name: file to get permissions from
        @return:
        """
        # set the file and tree handles for the given file
        self.open_file( share_name=share_name, file_name=file_name )
=======
        Connect to the given share and get the file permissions
        @param share_name: the share name where the file is to be opened
        @param file_name: file to get permissions from
        @return: SecurityAttributes
        """
        # set the file and tree handles for the given file
        self.open_file(share_name=share_name, file_name=file_name)
>>>>>>> master

        # query the file security information
        result = self.connection._SMBConnection.queryInfo(
            self.tid,
            self.fid,
            fileInfoClass=0,
            infoType=3,
            additionalInformation=0x00000017,
        )
<<<<<<< HEAD
        sec = FileSecInformation( result )

        # get security attributes
        security_attributes = self.get_security_attributes( sec )
=======
        sec = FileSecInformation(result)

        # get security attributes
        security_attributes = self.get_security_attributes(sec)
>>>>>>> master
        self.close_file()

        return security_attributes

    @staticmethod
    def insert_permission(sec, permission):
        """
        This function will get the current security descriptor, and then
<<<<<<< HEAD
        insert the given permission to it. will follow this logic:
        - if the sid already exists in the current security descriptor,
        find his index and change his access masks.
        - if the sid not exists, insert it on the top of the other permissions.
        this stage is important because unordered set of permissions can cause to
        invalid behaviour.
        @param sec: current security descriptor
        @param permission: new permission to insert. None for delete existing permission.
        """
        ntuser = FileNTUser( sec.rawData[sec["OffsetToDACL"]:] )
=======
        insert the given permission to it. Supports different actions:
        - grant: Add permissions to existing ACE (OR operation)
        - revoke: Remove specific permissions from existing ACE (AND NOT operation)
        - delete: Remove the entire ACE
        @param sec: current security descriptor
        @param permission: new permission ACE with action attribute
        """
        ntuser = FileNTUser(sec.rawData[sec["OffsetToDACL"]:])
>>>>>>> master
        ntace = ntuser["Buffer"]

        new_buffer = b""
        sid_found = False
<<<<<<< HEAD
        delete_mode = (permission["SpecificRights"] | permission["StandardRights"] | permission["GenericRights"]) == 0

        # enumerate the current permissions and search for the given permission sid
        while len( ntace ):
            delete_ace = False
            face = FileNTACE( ntace )  # set new FileNTACE
            sid = ACL_SID( face["SID"] )  # get the DACL SID
=======
        ace_deleted = False
        action = permission.action

        # enumerate the current permissions and search for the given permission sid
        while len(ntace):
            delete_ace = False
            face = FileNTACE(ntace)  # set new FileNTACE
            sid = ACL_SID(face["SID"])  # get the DACL SID
>>>>>>> master

            if sid.rawData == permission["SID"]:
                sid_found = True

<<<<<<< HEAD
                # add the new permissions to the current permission
                face["SpecificRights"] |= permission["SpecificRights"]
                face["StandardRights"] |= permission["StandardRights"]
                face["GenericRights"] |= permission["GenericRights"]

                delete_ace = delete_mode

            # permission not contain anything, then we should delete it
=======
                if action == 'grant':
                    # Add the new permissions to the current permission (OR operation)
                    face["SpecificRights"] |= permission["SpecificRights"]
                    face["StandardRights"] |= permission["StandardRights"]
                    face["GenericRights"] |= permission["GenericRights"]
                elif action == 'revoke':
                    # Remove specific permissions (AND NOT operation)
                    face["SpecificRights"] &= ~permission["SpecificRights"]
                    face["StandardRights"] &= ~permission["StandardRights"]
                    face["GenericRights"] &= ~permission["GenericRights"]
                    
                    # If all permissions are revoked, remove the ACE entirely (Windows behavior)
                    if (face["SpecificRights"] == 0 and 
                        face["StandardRights"] == 0 and 
                        face["GenericRights"] == 0):
                        delete_ace = True
                        ace_deleted = True
                elif action == 'delete':
                    delete_ace = True
                    ace_deleted = True

            # Only keep ACE if not marked for deletion
>>>>>>> master
            if not delete_ace:
                new_buffer += face.getData()

            ntace = ntace[face["Size"]:]  # slice the buffer

        if sid_found:
<<<<<<< HEAD
            # replace the current buffer in the one containing the new rights
            ntuser["Buffer"] = new_buffer
            ntuser["Size"] = len( new_buffer ) + 8  # add the nt user attribute size
            ntuser["NumACEs"] -= 1
        elif not delete_mode:
            # insert the permissions on the top of the other permissions
            ntuser["Size"] += len(
                permission.getData()
            )  # add the nt user attribute size
            ntuser["Buffer"] = permission.getData() + ntuser["Buffer"]
            ntuser["NumACEs"] += 1

        # create the new security descriptor
=======
            # replace the current buffer with the modified one
            ntuser["Buffer"] = new_buffer
            ntuser["Size"] = len(new_buffer) + 8  # add the nt user attribute size
            # Decrement ACE count if an ACE was deleted
            if ace_deleted:
                ntuser["NumACEs"] -= 1
        elif action != 'delete' and action != 'revoke':
            # insert the permissions on the top of the other permissions
            # (only for grant when ACE doesn't exist yet)
            ntuser["Size"] += len(
                permission.getData()
            )  # add the nt user attribute size
            ntuser["NumACEs"] += 1
            ntuser["Buffer"] = permission.getData() + ntuser["Buffer"]

>>>>>>> master
        owner = sec.rawData[sec["OffsetToOwner"]: sec["OffsetToGroup"]]
        group = sec.rawData[sec["OffsetToGroup"]: sec["OffsetToDACL"]]

        sec_info_blob = sec.getData() + owner + group + ntuser.getData()
        return sec_info_blob

<<<<<<< HEAD
    def set_permissions(self, share_name, file_name, user, permissions):
        """
        Add or remove permissions for a given user to the given file
        @param share_name: the share name where the file is to be opened
        @param file_name: file to set permissions to
        @param user: user to edit his permissions. can be sid either.
        @param permissions: permissions in the icacls format (example: R,W,X,D,I).
        NOTE: not all the permission types supported. currently supporting:
=======
    def set_permissions(self, share_name, file_name, user, permissions, action='grant'):
        """
        Add, remove, or modify permissions for a given user to the given file
        @param share_name: the share name where the file is to be opened
        @param file_name: file to set permissions to
        @param user: user to edit permissions for; can be a SID as well
        @param permissions: permissions in the icacls format (example: R,W,X,D).
        NOTE: not all permission types are supported; currently supporting:
>>>>>>> master
        R - read-only access
        W - write-only access
        D - delete access
        X - execute access
        F - full control
<<<<<<< HEAD
        @return: bool. whether the operation succeeded or not
        """
        self.open_file(share_name=share_name, file_name=file_name)

        permission = self.permissions_to_ace(user, permissions)
=======
        @param action: action to perform - 'grant' (add), 'revoke' (remove), 'delete' (remove ACE)
        @return: bool. whether the operation succeeded or not
        """
        # open file descriptor
        self.tid, self.fid = self.open_file(share_name, file_name)

        # permissions_to_ace function returns the new ACE to add
        permission = self.permissions_to_ace(user, permissions, action)

>>>>>>> master
        result = self.connection._SMBConnection.queryInfo(
            self.tid,
            self.fid,
            fileInfoClass=0,
            infoType=3,
            additionalInformation=0x00000017,
        )

        sec = FileSecInformation(result)
        security_descriptor = self.insert_permission(sec=sec, permission=permission)

        result = self.connection._SMBConnection.setInfo(
            self.tid,
            self.fid,
            fileInfoClass=0,
            infoType=3,
            additionalInformation=0x04,
            inputBlob=security_descriptor,
        )

        # disconnect from server
        self.close_file()

        return result
