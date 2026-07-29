#!/usr/bin/env python3
# Created by : PN-Tester
#
# rpcclient.py - A Python port of Samba's rpcclient, built on impacket.
# Usage:
#   ./rpcclient.py [domain/]user[:password]@target
#   ./rpcclient.py -hashes LM:NT domain/user@target
#   ./rpcclient.py -no-pass domain/user@target          (anonymous / prompt)
#   ./rpcclient.py -k domain/user@target                (Kerberos)
#   ./rpcclient.py -c "srvinfo;enumdomusers" domain/user@target
#
# Requires: impacket (pip install impacket)

import argparse
import cmd
import getpass
import os
import shlex
import socket
import struct
import sys
import traceback
from hashlib import md5

try:
    import socks  # PySocks; optional, only needed for -socks-proxy
    HAVE_PYSOCKS = True
except ImportError:
    HAVE_PYSOCKS = False

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, samr, lsat, lsad, srvs, wkst, epm, rrp, scmr
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_SID
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import USER_NORMAL_ACCOUNT
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30,
                                   SMB2_DIALECT_302, SMB2_DIALECT_311)
from impacket.uuid import uuidtup_to_bin
from Cryptodome.Cipher import ARC4


# ---------------------------------------------------------------------------
# SMB dialect selection for -dialect.
#
# Relevant background (see do_setuserpass / do_createdomuser docstrings):
# impacket only derives the SMB3 "ApplicationKey" -- what getSessionKey()
# returns, and what the password-set SAMR calls encrypt with -- if the
# connection actually negotiated SMB3 message encryption (dialect >= 3.0
# *and* the encryption capability was negotiated). If that didn't happen
# (e.g. the session landed on SMB 2.x, or encryption capability didn't come
# through cleanly over a proxied/relayed path), the key is simply never
# computed and stays empty, which crashes impacket's key-splitting code.
# Forcing SMB1 (-dialect 1) sidesteps this entirely, since SMB1's session
# key comes straight from the NTLM/Kerberos exchange with no additional
# negotiation step required -- at the cost of needing the target to still
# have the (increasingly rare, off-by-default-since-Win10-1709) SMB1
# server component enabled.
# ---------------------------------------------------------------------------
SMB_DIALECT_MAP = {
    '1':     SMB_DIALECT,
    '2.02':  SMB2_DIALECT_002,
    '2.1':   SMB2_DIALECT_21,
    '3.0':   SMB2_DIALECT_30,
    '3.0.2': SMB2_DIALECT_302,
    '3.1.1': SMB2_DIALECT_311,
}


# ---------------------------------------------------------------------------
# Well known interface UUIDs / named pipes.
# ---------------------------------------------------------------------------
PIPES = {
    'samr':   (r'\pipe\samr',    samr.MSRPC_UUID_SAMR),
    'lsarpc': (r'\pipe\lsarpc',  lsat.MSRPC_UUID_LSAT),
    'srvsvc': (r'\pipe\srvsvc',  srvs.MSRPC_UUID_SRVS),
    'wkssvc': (r'\pipe\wkssvc',  wkst.MSRPC_UUID_WKST),
    'winreg': (r'\pipe\winreg',  rrp.MSRPC_UUID_RRP),
    'svcctl': (r'\pipe\svcctl',  scmr.MSRPC_UUID_SCMR),
}


def sid_to_str(sid):
    return sid.formatCanonical() if hasattr(sid, 'formatCanonical') else str(sid)


def ndr_int(value):
    """Coerce a SAMR/NDR-returned numeric value to a plain Python int.

    impacket is inconsistent about whether a given field comes back already unwrapped to a native int or
    as a raw NDRULONG object -- direct NDRSTRUCT field access (e.g. info['LogonCount']) auto-unwraps to a
    plain int, but array/list elements (e.g. RelativeIds['Element'][0], or iterating GetMembersInGroup's
    Members/Attributes arrays) come back as bare NDRULONG instances instead. Critically, NDRULONG has no
    __int__/__index__ of its own -- calling int() directly on one raises TypeError, and using it straight in
    '%x' formatting raises a different, differently-worded error -- so neither "always call int()" nor
    "assume it's already an int" is safe; this checks which case it is and extracts accordingly (the actual
    value lives under ['Data'] for the wrapped case).
    """
    if isinstance(value, int):
        return value
    return value['Data']


class RPCClientError(Exception):
    pass


class RPCClientShell(cmd.Cmd):
    """Interactive shell mimicking Samba's rpcclient prompt."""

    def __init__(self, address, username, password, domain, lmhash, nthash,
                 aesKey, doKerberos, dcHost, port, timeout=30, dialect=None):
        cmd.Cmd.__init__(self)
        self.address = address
        self.username = username
        self.password = password
        self.domain = domain or ''
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.dcHost = dcHost
        self.port = port
        self.timeout = timeout
        self.dialect = dialect  # forced SMB dialect constant, or None for impacket's default negotiation

        self.prompt = 'rpcclient $> '
        self.intro = None

        # cache of pipe-name -> bound dce connection
        self._dce_cache = {}
        # cache of samr server/domain handles
        self._samr_server_handle = None
        self._samr_domain_handle = None
        self._samr_domain_sid = None
        self._samr_builtin_handle = None
        # cache of lsa policy handle
        self._lsa_policy_handle = None
        # Services this session auto-re-enabled from Disabled -> Manual (via _ensure_service_running)
        # so a "fix" command's undo path can put them back the way it found them.
        self._services_we_enabled = set()
        # generic/arbitrary interface, set via `bind`
        self._custom_dce = None
        self._custom_binding = None

    # ------------------------------------------------------------------
    # Connection plumbing
    # ------------------------------------------------------------------
    def _get_dce(self, pipe_name):
        """Return a bound DCE/RPC handle for the given named pipe, caching it."""
        if pipe_name in self._dce_cache:
            return self._dce_cache[pipe_name]

        pipe, uuid = PIPES[pipe_name]
        string_binding = r'ncacn_np:%s[%s]' % (self.address, pipe)
        rpctransport = transport.DCERPCTransportFactory(string_binding)

        if self.dialect is not None and hasattr(rpctransport, 'preferred_dialect'):
            rpctransport.preferred_dialect(self.dialect)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain,
                                          self.lmhash, self.nthash, self.aesKey)
        if hasattr(rpctransport, 'set_kerberos'):
            rpctransport.set_kerberos(self.doKerberos, kdcHost=self.dcHost)
        if hasattr(rpctransport, 'setRemoteHost'):
            rpctransport.setRemoteHost(self.address)
        if hasattr(rpctransport, 'set_dport'):
            rpctransport.set_dport(self.port)
        if hasattr(rpctransport, 'set_connect_timeout'):
            rpctransport.set_connect_timeout(self.timeout)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(uuid)
        self._dce_cache[pipe_name] = dce
        return dce

    def _samr_domain(self):
        """Lazily open SAMR server + the target's (non-Builtin) domain handle."""
        if self._samr_domain_handle is not None:
            return self._samr_domain_handle

        dce = self._get_dce('samr')
        resp = samr.hSamrConnect5(dce)
        self._samr_server_handle = resp['ServerHandle']

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, self._samr_server_handle)
        domains = [d['Name'] for d in resp['Buffer']['Buffer']]
        if not domains:
            raise RPCClientError('No domains enumerated via SAMR')

        target_domain = None
        for d in domains:
            if d.lower() != 'builtin':
                target_domain = d
                break
        if target_domain is None:
            target_domain = domains[0]

        resp = samr.hSamrLookupDomainInSamServer(dce, self._samr_server_handle, target_domain)
        self._samr_domain_sid = resp['DomainId']

        resp = samr.hSamrOpenDomain(dce, self._samr_server_handle,
                                     domainId=self._samr_domain_sid)
        self._samr_domain_handle = resp['DomainHandle']
        self._samr_domain_name = target_domain
        return self._samr_domain_handle

    def _samr_builtin(self):
        if self._samr_builtin_handle is not None:
            return self._samr_builtin_handle
        dce = self._get_dce('samr')
        if self._samr_server_handle is None:
            self._samr_domain()  # populates server handle as a side effect
        resp = samr.hSamrLookupDomainInSamServer(dce, self._samr_server_handle, 'Builtin')
        builtin_sid = resp['DomainId']
        resp = samr.hSamrOpenDomain(dce, self._samr_server_handle, domainId=builtin_sid)
        self._samr_builtin_handle = resp['DomainHandle']
        return self._samr_builtin_handle

    def _lsa_policy(self):
        if self._lsa_policy_handle is not None:
            return self._lsa_policy_handle
        dce = self._get_dce('lsarpc')
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES)
        self._lsa_policy_handle = resp['PolicyHandle']
        return self._lsa_policy_handle

    # ------------------------------------------------------------------
    # cmd.Cmd plumbing
    # ------------------------------------------------------------------
    def onecmd(self, line):
        try:
            return cmd.Cmd.onecmd(self, line)
        except DCERPCException as e:
            print('DCERPC error: %s' % e)
            if '-debug' in sys.argv:
                traceback.print_exc()
        except RPCClientError as e:
            print('error: %s' % e)
            if '-debug' in sys.argv:
                traceback.print_exc()
        except Exception as e:
            print('error: %s' % e)
            if '-debug' in sys.argv:
                traceback.print_exc()

    def emptyline(self):
        return  # don't repeat last command on blank input

    def default(self, line):
        print('unknown command: %s (try "help")' % line.split()[0])

    def do_exit(self, line):
        return True

    def do_quit(self, line):
        return True

    def do_EOF(self, line):
        print('')
        return True

    def do_help(self, line):
        cmds = sorted(m[3:] for m in dir(self) if m.startswith('do_') and m not in
                       ('do_exit', 'do_quit', 'do_EOF', 'do_help'))
        print('Available commands (see rpcclient(1) for semantics of the originals):')
        print('  ' + '  '.join(cmds))

    # ------------------------------------------------------------------
    # SRVSVC
    # ------------------------------------------------------------------
    def do_srvinfo(self, line):
        """srvinfo - Server information"""
        dce = self._get_dce('srvsvc')
        resp = srvs.hNetrServerGetInfo(dce, 102)
        info = resp['InfoStruct']['ServerInfo102']
        print('%-16s %-10s %s' % ('Server name', 'OS/Ver',
                                   'Comment'))
        print('%-16s %d.%d %s' % (info['sv102_name'][:-1], info['sv102_version_major'],
                                   info['sv102_version_minor'],
                                   info['sv102_comment'][:-1] if info['sv102_comment'] else ''))
        print('platform_id     :\t%d' % info['sv102_platform_id'])
        print('server type     :\t0x%x' % ndr_int(info['sv102_type']))
        print('users           :\t%d' % info['sv102_users'])

    def do_netshareenum(self, line):
        """netshareenum - Enumerate shares (level 1: name/type/comment)"""
        dce = self._get_dce('srvsvc')
        resp = srvs.hNetrShareEnum(dce, 1)
        print('%-15s %-10s %s' % ('Share', 'Type', 'Comment'))
        print('%-15s %-10s %s' % ('-----', '----', '-------'))
        type_names = {0: 'Disk', 1: 'PrintQ', 2: 'Device', 3: 'IPC'}
        for share in resp['InfoStruct']['ShareInfo']['Level1']['Buffer']:
            stype = share['shi1_type'] & 0x0FFFFFFF
            hidden = ' (hidden)' if share['shi1_type'] & 0x80000000 else ''
            print('%-15s %-10s %s' % (
                share['shi1_netname'][:-1],
                type_names.get(stype, hex(stype)) + hidden,
                share['shi1_remark'][:-1] if share['shi1_remark'] else ''))

    def do_netsharegetinfo(self, line):
        """netsharegetinfo <share> - Get Share Info"""
        share = line.strip()
        if not share:
            print('usage: netsharegetinfo <share>')
            return
        dce = self._get_dce('srvsvc')
        resp = srvs.hNetrShareGetInfo(dce, share, 502)
        info = resp['ShareInfo']['ShareInfo502']
        print('netname: %s' % info['shi502_netname'][:-1])
        print('remark: %s' % (info['shi502_remark'][:-1] if info['shi502_remark'] else ''))
        print('path: %s' % (info['shi502_path'][:-1] if info['shi502_path'] else ''))
        print('permissions: 0x%x' % ndr_int(info['shi502_permissions']))
        print('max users: %d' % info['shi502_max_uses'])
        print('current users: %d' % info['shi502_current_uses'])

    def do_netserverdiskenum(self, line):
        """netserverdiskenum - Enumerate disks"""
        dce = self._get_dce('srvsvc')
        resp = srvs.hNetrServerDiskEnum(dce, 0)
        for disk in resp['DiskInfoStruct']['Buffer']:
            raw = disk['Disk']['Data']
            name = raw.decode('utf-16le', errors='ignore').rstrip('\x00') if isinstance(raw, bytes) else str(raw).rstrip('\x00')
            if name:
                print(name)

    # ------------------------------------------------------------------
    # SAMR
    # ------------------------------------------------------------------
    def do_querydominfo(self, line):
        """querydominfo - Query domain info"""
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        resp = samr.hSamrQueryInformationDomain2(dce, dom_handle,
                                                  samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
        info = resp['Buffer']['General']
        print('Domain:       %s' % self._samr_domain_name)
        print('Server:       %s' % info['OemInformation'])
        print('Total Users:  %d' % info['UserCount'])
        print('Total Groups: %d' % info['GroupCount'])
        print('Total Aliases:%d' % info['AliasCount'])
        print('Domain SID:   %s' % sid_to_str(self._samr_domain_sid))

    def do_getdompwinfo(self, line):
        """getdompwinfo - Retrieve domain password info"""
        dce = self._get_dce('samr')
        resp = samr.hSamrGetDomainPasswordInformation(dce)
        info = resp['PasswordInformation']
        print('min_password_length: %d' % info['MinPasswordLength'])
        print('password_properties: 0x%08x' % info['PasswordProperties'])

    def do_enumdomusers(self, line):
        """enumdomusers - Enumerate domain users"""
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        resp = samr.hSamrEnumerateUsersInDomain(dce, dom_handle)
        for user in resp['Buffer']['Buffer']:
            print('user:[%s] rid:[0x%x]' % (user['Name'], ndr_int(user['RelativeId'])))

    def do_enumdomgroups(self, line):
        """enumdomgroups - Enumerate domain groups"""
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        resp = samr.hSamrEnumerateGroupsInDomain(dce, dom_handle)
        for grp in resp['Buffer']['Buffer']:
            print('group:[%s] rid:[0x%x]' % (grp['Name'], ndr_int(grp['RelativeId'])))

    def do_enumalsgroups(self, line):
        """enumalsgroups <builtin|domain> - Enumerate alias groups"""
        which = line.strip().lower() or 'domain'
        dce = self._get_dce('samr')
        handle = self._samr_builtin() if which == 'builtin' else self._samr_domain()
        resp = samr.hSamrEnumerateAliasesInDomain(dce, handle)
        for alias in resp['Buffer']['Buffer']:
            print('group:[%s] rid:[0x%x]' % (alias['Name'], ndr_int(alias['RelativeId'])))

    def _resolve_user_rid(self, dce, dom_handle, ident):
        if ident.lower().startswith('0x'):
            return int(ident, 16)
        if ident.isdigit():
            return int(ident)
        resp = samr.hSamrLookupNamesInDomain(dce, dom_handle, [ident])
        # Explicit int() -- this comes back as a raw NDR-wrapped integer (NDRULONG), not a plain Python int.
        # %d/%s formatting happens to tolerate that, but strict %x formatting doesn't, so without this cast
        # any command that resolves a RID from a *name* (rather than being given a numeric RID/0x.. directly)
        # crashes the moment it tries to print that RID in hex.
        return ndr_int(resp['RelativeIds']['Element'][0])

    def _resolve_sid(self, ident):
        """Resolve <SID|rid|username> to a full SID string, for use as a group/alias MEMBER identifier.
        A raw SID (starts with 'S-1-') is passed through as-is -- this is how you add a member that isn't a
        plain user/group in the currently open main domain: a BUILTIN principal (e.g. 'S-1-5-32-544' for
        Administrators), a well-known SID, or a user/group from a different domain than the one SAMR has open.
        Get the SID for those via `lookupnames` on the relevant domain or `lookupsids`, then paste it in here.
        A bare rid/name is resolved against the main (non-Builtin) domain from `_samr_domain()`, since group
        and alias members are essentially always users or groups from that domain."""
        if ident.upper().startswith('S-1-'):
            return ident
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, ident)
        return '%s-%d' % (sid_to_str(self._samr_domain_sid), rid)

    def do_queryuser(self, line):
        """queryuser <rid|username> - Query user info"""
        ident = line.strip()
        if not ident:
            print('usage: queryuser <rid|username>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, ident)
        resp = samr.hSamrOpenUser(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp['UserHandle']
        try:
            info = samr.hSamrQueryInformationUser2(
                dce, user_handle,
                samr.USER_INFORMATION_CLASS.UserAllInformation)['Buffer']['All']
            print('User Name   :   %s' % info['UserName'])
            print('Full Name   :   %s' % info['FullName'])
            print('Home Drive  :   %s' % info['HomeDirectory'])
            print('Home Dir    :   %s' % info['HomeDirectory'])
            print('Logon Script:   %s' % info['ScriptPath'])
            print('Profile Path:   %s' % info['ProfilePath'])
            print('Description :   %s' % info['AdminComment'])
            print('Workstations:   %s' % info['WorkStations'])
            print('Comment     :   %s' % info['UserComment'])
            print('Logon Count :   %d' % info['LogonCount'])
            print('Bad PW Count:   %d' % info['BadPasswordCount'])
            print('User RID    :   0x%x' % ndr_int(rid))
            print('Group RID   :   0x%x' % ndr_int(info['PrimaryGroupId']))
            print('Account Flags:  0x%08x' % ndr_int(info['UserAccountControl']))
        finally:
            samr.hSamrCloseHandle(dce, user_handle)

    def do_querygroup(self, line):
        """querygroup <rid> - Query group info"""
        ident = line.strip()
        if not ident:
            print('usage: querygroup <rid>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = int(ident, 16) if ident.lower().startswith('0x') else int(ident)
        resp = samr.hSamrOpenGroup(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        grp_handle = resp['GroupHandle']
        try:
            info = samr.hSamrQueryInformationGroup(
                dce, grp_handle,
                samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)['Buffer']['General']
            print('Group Name  :   %s' % info['Name'])
            print('Description :   %s' % info['AdminComment'])
            print('Group Attribute:0x%08x' % info['Attributes'])
            print('Num Members :   %d' % info['MemberCount'])
        finally:
            samr.hSamrCloseHandle(dce, grp_handle)

    def do_querygroupmem(self, line):
        """querygroupmem <rid> - Query group membership"""
        ident = line.strip()
        if not ident:
            print('usage: querygroupmem <rid>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = int(ident, 16) if ident.lower().startswith('0x') else int(ident)
        resp = samr.hSamrOpenGroup(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        grp_handle = resp['GroupHandle']
        try:
            members = samr.hSamrGetMembersInGroup(dce, grp_handle)
            rids = members['Members']['Members']
            attrs = members['Members']['Attributes']
            for r, a in zip(rids, attrs):
                print('rid:[0x%x] attr:[0x%x]' % (ndr_int(r), ndr_int(a)))
        finally:
            samr.hSamrCloseHandle(dce, grp_handle)

    def do_createdomgroup(self, line):
        """createdomgroup <name> - Create a domain global group"""
        name = line.strip()
        if not name:
            print('usage: createdomgroup <name>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        samr.hSamrCreateGroupInDomain(dce, dom_handle, name, MAXIMUM_ALLOWED)
        print('Creating group: %s' % name)

    def do_deletedomgroup(self, line):
        """deletedomgroup <rid|name> - Delete a domain global group"""
        ident = line.strip()
        if not ident:
            print('usage: deletedomgroup <rid|name>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, ident)
        resp = samr.hSamrOpenGroup(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        samr.hSamrDeleteGroup(dce, resp['GroupHandle'])
        print('Deleted group: %s' % ident)

    def do_addgroupmem(self, line):
        """addgroupmem <group rid|name> <user rid|name> - Add a user to a domain global group.
        Quote multi-word group names: addgroupmem "Domain Admins" jdoe"""
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print('error: %s' % e)
            return
        if len(parts) != 2:
            print('usage: addgroupmem <group rid|name> <user rid|name>')
            return
        group_ident, user_ident = parts
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        group_rid = self._resolve_user_rid(dce, dom_handle, group_ident)
        user_rid = self._resolve_user_rid(dce, dom_handle, user_ident)
        resp = samr.hSamrOpenGroup(dce, dom_handle, MAXIMUM_ALLOWED, group_rid)
        try:
            samr.hSamrAddMemberToGroup(dce, resp['GroupHandle'], user_rid,
                                        samr.SE_GROUP_MANDATORY | samr.SE_GROUP_ENABLED_BY_DEFAULT |
                                        samr.SE_GROUP_ENABLED)
            print('Added %s to group %s' % (user_ident, group_ident))
        finally:
            samr.hSamrCloseHandle(dce, resp['GroupHandle'])

    def do_delgroupmem(self, line):
        """delgroupmem <group rid|name> <user rid|name> - Remove a user from a domain global group.
        Quote multi-word group names: delgroupmem "Domain Admins" jdoe"""
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print('error: %s' % e)
            return
        if len(parts) != 2:
            print('usage: delgroupmem <group rid|name> <user rid|name>')
            return
        group_ident, user_ident = parts
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        group_rid = self._resolve_user_rid(dce, dom_handle, group_ident)
        user_rid = self._resolve_user_rid(dce, dom_handle, user_ident)
        resp = samr.hSamrOpenGroup(dce, dom_handle, MAXIMUM_ALLOWED, group_rid)
        try:
            samr.hSamrRemoveMemberFromGroup(dce, resp['GroupHandle'], user_rid)
            print('Removed %s from group %s' % (user_ident, group_ident))
        finally:
            samr.hSamrCloseHandle(dce, resp['GroupHandle'])

    # ------------------------------------------------------------------
    # Aliases == "local groups": both the machine's own local groups (the
    # non-Builtin domain SAMR opens on a workstation/member server -- on a
    # DC this same non-Builtin domain instead holds domain-local groups)
    # and the predefined BUILTIN groups (Administrators, Remote Desktop
    # Users, etc, reached via --builtin / `_samr_builtin()`). This mirrors
    # how `net localgroup` / Computer Management draw the same distinction.
    # ------------------------------------------------------------------
    def do_createdomalias(self, line):
        """createdomalias <name> [--builtin] - Create a local group (alias). --builtin targets the BUILTIN
        domain instead of the main one, but Windows normally only allows creating custom groups in the main
        (non-Builtin) domain -- BUILTIN's membership is generally fixed and only its members are editable."""
        tokens = shlex.split(line)
        builtin = '--builtin' in tokens
        tokens = [t for t in tokens if t != '--builtin']
        if not tokens:
            print('usage: createdomalias <name> [--builtin]')
            return
        name = tokens[0]
        dce = self._get_dce('samr')
        handle = self._samr_builtin() if builtin else self._samr_domain()
        samr.hSamrCreateAliasInDomain(dce, handle, name, MAXIMUM_ALLOWED)
        print('Creating alias: %s' % name)

    def do_deletedomalias(self, line):
        """deletedomalias <rid|name> [--builtin] - Delete a local group (alias)"""
        tokens = shlex.split(line)
        builtin = '--builtin' in tokens
        tokens = [t for t in tokens if t != '--builtin']
        if not tokens:
            print('usage: deletedomalias <rid|name> [--builtin]')
            return
        ident = tokens[0]
        dce = self._get_dce('samr')
        handle = self._samr_builtin() if builtin else self._samr_domain()
        rid = self._resolve_user_rid(dce, handle, ident)
        resp = samr.hSamrOpenAlias(dce, handle, MAXIMUM_ALLOWED, rid)
        samr.hSamrDeleteAlias(dce, resp['AliasHandle'])
        print('Deleted alias: %s' % ident)

    def do_addaliasmem(self, line):
        """addaliasmem [--builtin] <alias rid|name> <member: sid|rid|username> - Add a member to a local group
        (alias). Use --builtin for a BUILTIN group (e.g. local Administrators). The member is looked up in
        the main domain by default; pass a raw SID (see `help lookupnames`/`help lookupsids`) for a BUILTIN,
        well-known, or foreign-domain member -- see `_resolve_sid`'s docstring in the source for details.

        Examples:
          addaliasmem "Remote Desktop Users" jdoe
          addaliasmem --builtin Administrators jdoe
          addaliasmem --builtin Administrators S-1-5-21-1234567890-1234567890-1234567890-1105
        """
        tokens = shlex.split(line)
        builtin = '--builtin' in tokens
        tokens = [t for t in tokens if t != '--builtin']
        if len(tokens) != 2:
            print('usage: addaliasmem [--builtin] <alias rid|name> <member: sid|rid|username>')
            return
        alias_ident, member_ident = tokens
        dce = self._get_dce('samr')
        handle = self._samr_builtin() if builtin else self._samr_domain()
        alias_rid = self._resolve_user_rid(dce, handle, alias_ident)
        member_sid_str = self._resolve_sid(member_ident)
        member_sid = RPC_SID()
        member_sid.fromCanonical(member_sid_str)
        resp = samr.hSamrOpenAlias(dce, handle, MAXIMUM_ALLOWED, alias_rid)
        try:
            samr.hSamrAddMemberToAlias(dce, resp['AliasHandle'], member_sid)
            print('Added %s (%s) to alias %s' % (member_ident, member_sid_str, alias_ident))
        finally:
            samr.hSamrCloseHandle(dce, resp['AliasHandle'])

    def do_delaliasmem(self, line):
        """delaliasmem [--builtin] <alias rid|name> <member: sid|rid|username> - Remove a member from a local
        group (alias). Same member-resolution rules as addaliasmem."""
        tokens = shlex.split(line)
        builtin = '--builtin' in tokens
        tokens = [t for t in tokens if t != '--builtin']
        if len(tokens) != 2:
            print('usage: delaliasmem [--builtin] <alias rid|name> <member: sid|rid|username>')
            return
        alias_ident, member_ident = tokens
        dce = self._get_dce('samr')
        handle = self._samr_builtin() if builtin else self._samr_domain()
        alias_rid = self._resolve_user_rid(dce, handle, alias_ident)
        member_sid_str = self._resolve_sid(member_ident)
        member_sid = RPC_SID()
        member_sid.fromCanonical(member_sid_str)
        resp = samr.hSamrOpenAlias(dce, handle, MAXIMUM_ALLOWED, alias_rid)
        try:
            samr.hSamrRemoveMemberFromAlias(dce, resp['AliasHandle'], member_sid)
            print('Removed %s (%s) from alias %s' % (member_ident, member_sid_str, alias_ident))
        finally:
            samr.hSamrCloseHandle(dce, resp['AliasHandle'])

    def do_listaliasmem(self, line):
        """listaliasmem [--builtin] <alias rid|name> - List members (SIDs) of a local group (alias).
        Pipe the SIDs into `lookupsids` to resolve them to names."""
        tokens = shlex.split(line)
        builtin = '--builtin' in tokens
        tokens = [t for t in tokens if t != '--builtin']
        if not tokens:
            print('usage: listaliasmem [--builtin] <alias rid|name>')
            return
        ident = tokens[0]
        dce = self._get_dce('samr')
        handle = self._samr_builtin() if builtin else self._samr_domain()
        rid = self._resolve_user_rid(dce, handle, ident)
        resp = samr.hSamrOpenAlias(dce, handle, MAXIMUM_ALLOWED, rid)
        try:
            members = samr.hSamrGetMembersInAlias(dce, resp['AliasHandle'])
            for entry in members['Members']['Sids']:
                print(sid_to_str(entry['SidPointer']))
        finally:
            samr.hSamrCloseHandle(dce, resp['AliasHandle'])

    def do_lookupnames(self, line):
        """lookupnames <name> [name ...] - Resolve names to SIDs (via SAMR domain)"""
        names = line.split()
        if not names:
            print('usage: lookupnames <name> [name...]')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        resp = samr.hSamrLookupNamesInDomain(dce, dom_handle, names)
        for name, rid in zip(names, resp['RelativeIds']['Element']):
            rid = ndr_int(rid)
            sid = '%s-%d' % (sid_to_str(self._samr_domain_sid), rid)
            print('%s %s (%d)' % (name, sid, rid))

    def do_lookupsids(self, line):
        """lookupsids <sid> [sid ...] - Resolve SIDs to names (via LSA)"""
        sids = line.split()
        if not sids:
            print('usage: lookupsids <sid> [sid...]')
            return
        dce = self._get_dce('lsarpc')
        policy_handle = self._lsa_policy()
        resp = lsat.hLsarLookupSids(dce, policy_handle, sids,
                                     lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        for sid, item in zip(sids, resp['TranslatedNames']['Names']):
            domain_idx = item['DomainIndex']
            if domain_idx == -1 or domain_idx >= len(resp['ReferencedDomains']['Domains']):
                domain = '?'
            else:
                domain = resp['ReferencedDomains']['Domains'][domain_idx]['Name']
            print('%s %s\\%s (%d)' % (sid, domain, item['Name'], item['Use']))

    def _clear_password_expired(self, dce, user_handle, expired=False):
        """Set or clear the PasswordExpired flag via SamrSetInformationUser2(UserAllInformation), touching
        ONLY that one field (WhichFields = USER_ALL_PASSWORDEXPIRED) -- no password blob, no NtOwfPassword/
        LmOwfPassword, and therefore no RC4/session-key crypto involved at all.

        This exists because `_set_user_password` can only clear PasswordExpired as a side effect of actually
        setting a password (it's bundled into the same UserInternal4InformationNew structure) -- which means
        two real gaps: (1) `createdomuser <user>` with no password argument has no password-set call to
        piggyback on, so the account was silently left in Windows' default "must change at next logon" state
        for every passwordless account created this way, and (2) even when a password IS given, clearing the
        flag was tied to the same fragile SMB-session-key-dependent encryption `_set_user_password` needs --
        so a session-key problem (STATUS_WRONG_PASSWORD, covered in that method's docstring) left the account
        both without its intended password AND still stuck requiring a change, with no independent way to at
        least fix the second part.

        SAMPR_USER_ALL_INFORMATION (the 'I1' structure embedded inside UserInternal4InformationNew, also
        addressable directly as its own top-level info class, UserAllInformation/21) is the same structure
        either way -- the only difference is this path never touches the password fields, so it has none of
        that dependency. Called unconditionally (unless --must-change) by createdomuser/setuserpass now,
        independent of whether the password-set call itself succeeded.
        """
        request = samr.SamrSetInformationUser2()
        request['UserHandle'] = user_handle
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserAllInformation
        request['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserAllInformation
        all_info = request['Buffer']['All']
        all_info['WhichFields'] = samr.USER_ALL_PASSWORDEXPIRED
        all_info['UserName'] = NULL
        all_info['FullName'] = NULL
        all_info['HomeDirectory'] = NULL
        all_info['HomeDirectoryDrive'] = NULL
        all_info['ScriptPath'] = NULL
        all_info['ProfilePath'] = NULL
        all_info['AdminComment'] = NULL
        all_info['WorkStations'] = NULL
        all_info['UserComment'] = NULL
        all_info['Parameters'] = NULL
        all_info['LmOwfPassword']['Buffer'] = NULL
        all_info['NtOwfPassword']['Buffer'] = NULL
        all_info['PrivateData'] = NULL
        all_info['SecurityDescriptor']['SecurityDescriptor'] = NULL
        all_info['LogonHours']['LogonHours'] = NULL
        all_info['PasswordExpired'] = 1 if expired else 0
        dce.request(request)

    def _set_user_password(self, dce, user_handle, password, password_expired=False):
        """Admin-side password reset via SamrSetInformationUser2 / UserInternal4InformationNew (level 26).
        This is the RC4+MD5-salted mechanism modern admin tooling (RSAT, CrackMapExec, etc.) uses for exactly
        this purpose -- resetting an account's password without knowing the old one, given a handle with
        sufficient access. It's used instead of SamrChangePasswordUser (which implements the *self-service*
        "I know my old password" flow and Windows will reject with STATUS_ACCESS_DENIED if you try to use it
        to reset a different account as an admin -- that's a real, permanent restriction, not a bug) and
        instead of the older UserInternal1Information/level 18 (hSamrSetNTInternal1), which encrypts with a
        legacy DES scheme requiring an exact-length session key and crashes outright on a short/empty one.

        Both this and the legacy method still need SOME valid SMB session key to produce ciphertext the server
        can decrypt, though. impacket only derives that key (SMB3's "ApplicationKey") when the connection
        negotiated SMB3 message encryption; if the session landed on SMB 2.x, or encryption capability wasn't
        negotiated (common over some proxied/relayed paths), the key is never computed and stays empty. Level
        26's MD5-based scheme tolerates that without crashing (unlike level 18's DES splitting), but the
        server will still reject the result with STATUS_WRONG_PASSWORD if the key is genuinely wrong/missing.
        If you hit that, run `smbinfo` to check the negotiated dialect and session-key length. "-dialect 1"
        (legacy SMB1) sidesteps the SMB3 encryption-negotiation dependency entirely, but ONLY if the target
        still has the SMB1 server component enabled -- most current Windows targets do not, and forcing it
        against one that doesn't just breaks the connection outright with a protocol-mismatch error, not a
        graceful fallback. If SMB1 genuinely isn't available, there is no other admin-reset path in SAMR that
        avoids this dependency either: every admin-side password-set mechanism (level 18, level 26, this one)
        requires session-key-based encryption of some form. The one SAMR mechanism that doesn't depend on the
        session key at all (SamrChangePasswordUser2, keyed on the account's own NT hash instead) is restricted
        by Windows to self-service use -- the authenticated identity must match the account being changed, so
        an admin session can't invoke it on someone else's account (STATUS_ACCESS_DENIED). In that situation
        this is a genuine, unavoidable-from-this-angle blocker, not a bug still waiting to be found here.

        NOTE: this deliberately does NOT call impacket's own samr.hSamrSetPasswordInternal4New() helper.
        That helper hard-codes `PasswordExpired = 1` in the request, which unconditionally marks the account
        as needing a password change at next logon as a side effect of setting the password at all -- this is
        impacket's own doing, not a Windows default we're working around. That single hard-coded bit is what
        was actually landing every account this tool set a password for into STATUS_PASSWORD_MUST_CHANGE,
        which (as we found the hard way) blocks essentially all remote authentication as that account,
        including the workarounds this file already had in place for it. This is a byte-for-byte copy of
        that helper's request-building logic with PasswordExpired controllable via the password_expired
        argument (default False, i.e. don't force a mandatory change) instead of hard-coded True.
        """
        request = samr.SamrSetInformationUser2()
        request['UserHandle'] = user_handle
        request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        request['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        request['Buffer']['Internal4New']['I1']['WhichFields'] = 0x01000000 | 0x08000000

        request['Buffer']['Internal4New']['I1']['UserName'] = NULL
        request['Buffer']['Internal4New']['I1']['FullName'] = NULL
        request['Buffer']['Internal4New']['I1']['HomeDirectory'] = NULL
        request['Buffer']['Internal4New']['I1']['HomeDirectoryDrive'] = NULL
        request['Buffer']['Internal4New']['I1']['ScriptPath'] = NULL
        request['Buffer']['Internal4New']['I1']['ProfilePath'] = NULL
        request['Buffer']['Internal4New']['I1']['AdminComment'] = NULL
        request['Buffer']['Internal4New']['I1']['WorkStations'] = NULL
        request['Buffer']['Internal4New']['I1']['UserComment'] = NULL
        request['Buffer']['Internal4New']['I1']['Parameters'] = NULL
        request['Buffer']['Internal4New']['I1']['LmOwfPassword']['Buffer'] = NULL
        request['Buffer']['Internal4New']['I1']['NtOwfPassword']['Buffer'] = NULL
        request['Buffer']['Internal4New']['I1']['PrivateData'] = NULL
        request['Buffer']['Internal4New']['I1']['SecurityDescriptor']['SecurityDescriptor'] = NULL
        request['Buffer']['Internal4New']['I1']['LogonHours']['LogonHours'] = NULL
        request['Buffer']['Internal4New']['I1']['PasswordExpired'] = 1 if password_expired else 0

        pwdbuff = password.encode('utf-16le')
        bufflen = len(pwdbuff)
        pwdbuff = pwdbuff.rjust(512, b'\0')
        pwdbuff += struct.pack('<I', bufflen)
        salt = os.urandom(16)
        session_key = dce.get_rpc_transport().get_smb_connection().getSessionKey()
        keymd = md5()
        keymd.update(salt)
        keymd.update(session_key)
        key = keymd.digest()

        cipher = ARC4.new(key)
        buffercrypt = cipher.encrypt(pwdbuff) + salt

        request['Buffer']['Internal4New']['UserPassword']['Buffer'] = buffercrypt
        dce.request(request)

    def do_smbinfo(self, line):
        """smbinfo - Show the negotiated SMB dialect and session-key state for the underlying connection.
        Diagnostic for setuserpass/createdomuser password-set failures: those calls need a non-empty SMB
        session key to encrypt the password with, and impacket only derives one for SMB3 connections when the
        session negotiated message encryption. This prints exactly what got negotiated so we're not guessing.
        """
        dce = self._get_dce('samr')
        smb_conn = dce.get_rpc_transport().get_smb_connection()
        dialect = smb_conn.getDialect()
        dialect_names = {
            SMB_DIALECT: 'SMB1 (NT LM 0.12)',
            SMB2_DIALECT_002: 'SMB 2.0.2',
            SMB2_DIALECT_21: 'SMB 2.1',
            SMB2_DIALECT_30: 'SMB 3.0',
            SMB2_DIALECT_302: 'SMB 3.0.2',
            SMB2_DIALECT_311: 'SMB 3.1.1',
        }
        print('Negotiated dialect: %s' % dialect_names.get(dialect, repr(dialect)))
        try:
            key = smb_conn.getSessionKey()
        except Exception as e:
            print('getSessionKey() raised: %s' % e)
            return
        print('Session key length: %d bytes' % len(key))
        if len(key) == 0:
            print('-> empty session key. setuserpass / createdomuser <user> <pass> will fail against this '
                  'session. On SMB3 this means message encryption was not negotiated for the connection; '
                  'on SMB1 it would mean something went wrong in the NTLM/Kerberos exchange itself.')
        else:
            print('-> non-empty session key; password-set SAMR calls should work against this session.')

    def _set_account_enabled(self, dce, user_handle, enabled):
        """Set or clear the ACB_DISABLE bit on a user account via SamrSetInformationUser2(UserControlInformation).
        Shared by `createdomuser --enable` and the standalone `enableuser`/`disableuser` commands."""
        control_resp = samr.hSamrQueryInformationUser2(
            dce, user_handle, samr.USER_INFORMATION_CLASS.UserControlInformation)
        current_control = control_resp['Buffer']['Control']['UserAccountControl']
        if enabled:
            new_control = (current_control & ~samr.USER_ACCOUNT_DISABLED) | samr.USER_NORMAL_ACCOUNT
        else:
            new_control = current_control | samr.USER_ACCOUNT_DISABLED

        info_buffer = samr.SAMPR_USER_INFO_BUFFER()
        info_buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        info_buffer['Control']['UserAccountControl'] = new_control
        samr.hSamrSetInformationUser2(dce, user_handle, info_buffer)

    def _samr_create_user(self, dce, dom_handle, name, account_type=USER_NORMAL_ACCOUNT):
        """Create a user via SamrCreateUser2InDomain, deliberately NOT using impacket's own
        samr.hSamrCreateUser2InDomain() helper. That helper catches STATUS_ACCESS_DENIED (and a couple of
        other codes) on this specific call and re-raises them as a generic Exception with hard-coded text
        like "Authenticating account doesn't have the right to create a new machine account!" -- written with
        addcomputer.py-style machine-account creation in mind, but it fires for ANY access-denied reason on
        this RPC, including a plain user creation attempt by an account that just doesn't have SAM write
        rights. That's misleading here since we're never creating machine accounts. Building the request
        ourselves lets the real samr.DCERPCSessionError (with the actual NTSTATUS code/name, e.g.
        STATUS_ACCESS_DENIED) propagate up normally instead, which the shell's existing exception handler
        already prints in a readable form.
        """
        request = samr.SamrCreateUser2InDomain()
        request['DomainHandle'] = dom_handle
        request['Name'] = name
        request['AccountType'] = account_type
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        return dce.request(request)

    def do_createdomuser(self, line):
        """createdomuser <username> [password] [--enable] [--must-change] - Create domain user, optionally
        setting a password and/or enabling the account in the same step.
        NOTE: unlike the real Samba rpcclient's createdomuser (which takes no password/enable parameters at
        all -- it only calls SamrCreateUser2, leaving the account passwordless and disabled), this version
        optionally chains extra SAMR calls on the handle CreateUser2 already hands back:
          - a password is set via self._set_user_password if one was given (see its docstring for the full
            story on why it's implemented the way it is, and what to do if it fails with an empty-session-key
            error).
          - regardless of whether a password was given, or whether the password-set call above succeeded,
            self._clear_password_expired always runs to guarantee the account does NOT come up requiring a
            password change at next logon (Windows' own default for any newly created account, blank
            password or not) -- unless --must-change was passed, in which case that state is set instead.
            This call has no session-key dependency, so it works even in cases where password-setting itself
            hit the empty-session-key problem.
          - --enable clears the ACB_DISABLE bit via a SamrSetInformationUser2(UserControlInformation) call,
            which is what's needed for the account to actually be usable -- new accounts come back disabled
            by default regardless of whether a password was set.
        Passing the password as a positional arg means it will be visible in shell history / process listings;
        if that's a concern for your environment, run `createdomuser <username>` with no password and follow
        up with `setuserpass <username>` instead, which will prompt interactively.

        Examples:
          createdomuser newuser
          createdomuser newuser Sup3rSecretPass!
          createdomuser newuser Sup3rSecretPass! --enable
          createdomuser newuser Sup3rSecretPass! --enable --must-change
        """
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            print('error: %s' % e)
            return

        enable = '--enable' in tokens
        must_change = '--must-change' in tokens
        tokens = [t for t in tokens if t not in ('--enable', '--must-change')]

        if not tokens:
            print('usage: createdomuser <username> [password] [--enable] [--must-change]')
            return
        name = tokens[0]
        password = tokens[1] if len(tokens) > 1 else None

        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        resp = self._samr_create_user(dce, dom_handle, name)
        print('Creating user: %s' % name)

        # _samr_create_user (SamrCreateUser2InDomain) already hands back an
        # open handle on the newly created user -- no need to look up the
        # RID and re-open it the way setuserpass does for an existing account.
        user_handle = resp['UserHandle']
        try:
            if password is not None:
                try:
                    self._set_user_password(dce, user_handle, password, password_expired=must_change)
                    print('Password set for %s%s' % (name, ' (must change at next logon)' if must_change else ''))
                except DCERPCException as e:
                    print('warning: failed to set password for %s (%s); account was still created. '
                          'Run `smbinfo` to check whether this is the empty-session-key issue -- see '
                          '`help setuserpass` for the full explanation. Note that the "-dialect 1" '
                          'workaround only helps if the target still has legacy SMB1 enabled, which most '
                          'current Windows targets do not; if so, it is not a usable fix here.' % (name, e))

            # Always clear (or set, if --must-change) PasswordExpired via the standalone, session-key-
            # independent path -- not just as a side effect of _set_user_password succeeding. This covers
            # two cases that call above doesn't: no password was given at all (nothing to piggyback the flag
            # on), and the password-set call above failed but we can still guarantee the account isn't
            # stuck requiring a change nobody asked for. Windows' own default for a brand-new account is
            # "must change at next logon" regardless of whether a password was ever set on it, so this has
            # to run even in the no-password case for the account to actually come up immediately usable.
            try:
                self._clear_password_expired(dce, user_handle, expired=must_change)
                if password is None and not must_change:
                    print('Password-change-at-next-logon cleared for %s (no password was set -- account has '
                          'a blank password)' % name)
            except DCERPCException as e:
                print('warning: failed to clear must-change-password flag for %s (%s)' % (name, e))

            if enable:
                self._set_account_enabled(dce, user_handle, True)
                print('Account enabled for %s' % name)
        finally:
            samr.hSamrCloseHandle(dce, user_handle)

    def do_deletedomuser(self, line):
        """deletedomuser <username> - Delete domain user"""
        name = line.strip()
        if not name:
            print('usage: deletedomuser <username>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, name)
        resp = samr.hSamrOpenUser(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        samr.hSamrDeleteUser(dce, resp['UserHandle'])
        print('Deleted user: %s' % name)

    def do_enableuser(self, line):
        """enableuser <rid|username> - Clear the disabled flag on a user account (same effect as
        createdomuser's --enable, as a standalone command for accounts created without it)."""
        ident = line.strip()
        if not ident:
            print('usage: enableuser <rid|username>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, ident)
        resp = samr.hSamrOpenUser(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        try:
            self._set_account_enabled(dce, resp['UserHandle'], True)
            print('Account enabled for %s' % ident)
        finally:
            samr.hSamrCloseHandle(dce, resp['UserHandle'])

    def do_disableuser(self, line):
        """disableuser <rid|username> - Set the disabled flag on a user account."""
        ident = line.strip()
        if not ident:
            print('usage: disableuser <rid|username>')
            return
        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, ident)
        resp = samr.hSamrOpenUser(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        try:
            self._set_account_enabled(dce, resp['UserHandle'], False)
            print('Account disabled for %s' % ident)
        finally:
            samr.hSamrCloseHandle(dce, resp['UserHandle'])

    # ------------------------------------------------------------------
    # LSA
    # ------------------------------------------------------------------
    def do_lsaquery(self, line):
        """lsaquery - Query LSA policy for domain name/SID"""
        dce = self._get_dce('lsarpc')
        policy_handle = self._lsa_policy()
        resp = lsad.hLsarQueryInformationPolicy2(
            dce, policy_handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        info = resp['PolicyInformation']['PolicyAccountDomainInfo']
        print('Domain Name: %s' % info['DomainName'])
        print('Domain Sid: %s' % (sid_to_str(info['DomainSid']) if info['DomainSid'] else '(NULL SID)'))

    def do_lsaenumsid(self, line):
        """lsaenumsid - Enumerate accounts known to LSA"""
        dce = self._get_dce('lsarpc')
        policy_handle = self._lsa_policy()
        enum_ctx = 0
        while True:
            request = lsad.LsarEnumerateAccounts()
            request['PolicyHandle'] = policy_handle
            request['EnumerationContext'] = enum_ctx
            request['PreferedMaximumLength'] = 32 * 1024
            try:
                resp = dce.request(request)
            except DCERPCException as e:
                if 'STATUS_NO_MORE_ENTRIES' in str(e):
                    break
                raise
            entries = resp['EnumerationBuffer']['Information']
            if not entries:
                break
            for account in entries:
                print(sid_to_str(account['Sid']))
            enum_ctx = resp['EnumerationContext']

    def do_enumprivs(self, line):
        """enumprivs - Enumerate LSA privileges"""
        dce = self._get_dce('lsarpc')
        resp = lsad.hLsarEnumeratePrivileges(dce, 0, 1000)
        for priv in resp['EnumerationBuffer']['Privileges']:
            print('%s (%d:%d)' % (priv['Name'], priv['LocalValue']['HighPart'],
                                   priv['LocalValue']['LowPart']))

    # ------------------------------------------------------------------
    # Remote Registry (winreg/MS-RRP) + SVCCTL
    #
    # A handful of security-relevant settings (this file's leading example:
    # "Accounts: Limit local account use of blank passwords to console
    # logon only" / LimitBlankPasswordUse) live in the registry rather than
    # being exposed through a dedicated SAMR/LSA policy call. Reaching them
    # remotely means talking to the Remote Registry service over its own
    # RPC pipe (winreg), same as impacket's own reg.py/secretsdump.py.
    #
    # The Remote Registry *service* itself is commonly set to manual-start
    # (or disabled) on current Windows -- the pipe simply won't accept
    # connections until it's actually running, so _ensure_service_running
    # starts it via SCM first (svcctl) if needed, same as secretsdump.py's
    # RemoteOperations class does.
    # ------------------------------------------------------------------
    def _ensure_service_running(self, service_name):
        """Start a service via SCM (svcctl) if it isn't already running. Tolerates "already running" as
        success. If the service's start type is set to Disabled (common for RemoteRegistry specifically on
        a lot of current Windows builds -- it's not merely stopped, SCM refuses to start it at all until its
        start type changes), reconfigures it to demand-start (SERVICE_DEMAND_START, i.e. "Manual") via
        hRChangeServiceConfigW and retries once. Anything else propagates."""
        dce = self._get_dce('svcctl')
        sc_handle = scmr.hROpenSCManagerW(dce)['lpScHandle']
        try:
            svc_handle = scmr.hROpenServiceW(dce, sc_handle, service_name)['lpServiceHandle']
            try:
                status = scmr.hRQueryServiceStatus(dce, svc_handle)['lpServiceStatus']
                if status['dwCurrentState'] == scmr.SERVICE_RUNNING:
                    return
                try:
                    scmr.hRStartServiceW(dce, svc_handle)
                except DCERPCException as e:
                    if 'ERROR_SERVICE_ALREADY_RUNNING' in str(e):
                        pass
                    elif 'ERROR_SERVICE_DISABLED' in str(e):
                        scmr.hRChangeServiceConfigW(dce, svc_handle, dwStartType=scmr.SERVICE_DEMAND_START)
                        scmr.hRStartServiceW(dce, svc_handle)
                        self._services_we_enabled.add(service_name)
                    else:
                        raise
            finally:
                scmr.hRCloseServiceHandle(dce, svc_handle)
        finally:
            scmr.hRCloseServiceHandle(dce, sc_handle)

    def _restore_service_disabled(self, service_name):
        """Stop a service (best-effort) and set its start type back to Disabled. Undoes what
        `_ensure_service_running` does automatically when it finds a service Disabled rather than merely
        stopped -- used to put RemoteRegistry back the way `fixblankpasswordpolicy` found it, rather than
        leaving it permanently re-enabled as an unintended side effect of running that command once."""
        dce = self._get_dce('svcctl')
        sc_handle = scmr.hROpenSCManagerW(dce)['lpScHandle']
        try:
            svc_handle = scmr.hROpenServiceW(dce, sc_handle, service_name)['lpServiceHandle']
            try:
                status = scmr.hRQueryServiceStatus(dce, svc_handle)['lpServiceStatus']
                if status['dwCurrentState'] != scmr.SERVICE_STOPPED:
                    try:
                        scmr.hRControlService(dce, svc_handle, scmr.SERVICE_CONTROL_STOP)
                    except DCERPCException:
                        pass  # best-effort -- still set the start type below even if the stop didn't take
                scmr.hRChangeServiceConfigW(dce, svc_handle, dwStartType=scmr.SERVICE_DISABLED)
            finally:
                scmr.hRCloseServiceHandle(dce, svc_handle)
        finally:
            scmr.hRCloseServiceHandle(dce, sc_handle)
        self._services_we_enabled.discard(service_name)

    def _winreg_dce(self):
        """Get a bound winreg DCE handle, making sure the Remote Registry service is actually
        running first (it's off/manual-start by default on a lot of current Windows builds)."""
        self._ensure_service_running('RemoteRegistry')
        return self._get_dce('winreg')

    def do_regsetdword(self, line):
        """regsetdword <HKLM\\key\\path> <ValueName> <dword_value> - Set (creating if needed) a REG_DWORD
        value under HKEY_LOCAL_MACHINE via the Remote Registry service. Only HKLM is supported (by far the
        common case for policy-type settings, including the one `fixblankpasswordpolicy` below wraps).
        Starts the Remote Registry service automatically if it isn't already running.

        Example:
          regsetdword HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa LimitBlankPasswordUse 0
        """
        parts = line.split()
        if len(parts) != 3:
            print(r'usage: regsetdword <HKLM\key\path> <ValueName> <dword_value>')
            return
        key_path, value_name, value = parts
        if key_path.upper().startswith('HKLM\\'):
            key_path = key_path[5:]
        elif key_path.upper().startswith('HKEY_LOCAL_MACHINE\\'):
            key_path = key_path[len('HKEY_LOCAL_MACHINE\\'):]
        try:
            dword_value = int(value, 0)
        except ValueError:
            print('error: value must be an integer (decimal or 0x-prefixed hex)')
            return

        dce = self._winreg_dce()
        hklm = rrp.hOpenLocalMachine(dce)['phKey']
        try:
            key_handle = rrp.hBaseRegOpenKey(dce, hklm, key_path)['phkResult']
            try:
                rrp.hBaseRegSetValue(dce, key_handle, value_name, rrp.REG_DWORD, dword_value)
                print('Set HKLM\\%s\\%s = 0x%x (%d)' % (key_path, value_name, dword_value, dword_value))
            finally:
                rrp.hBaseRegCloseKey(dce, key_handle)
        finally:
            rrp.hBaseRegCloseKey(dce, hklm)

    def do_fixblankpasswordpolicy(self, line):
        """fixblankpasswordpolicy [on|off] - Toggle "Accounts: Limit local account use of blank passwords
        to console logon only" (registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse).
        Enabled (the Windows default) by default on essentially every current Windows install, this policy
        blocks ANY network logon -- SMB, RDP, and (per Microsoft's own docs) other network services -- for a
        local account with a blank password, regardless of that account's other settings (enabled,
        PasswordExpired=0, etc). It does not affect domain accounts or console/physical logon.
        `off` (the default if no argument given) sets the registry value to 0, disabling the restriction so a
        blank-password local account can authenticate over the network; `on` restores it to 1 -- this is also
        the undo for `off`. Takes effect immediately -- Microsoft's documentation notes no reboot is required.

        `on` additionally undoes the OTHER side effect this command can cause: if RemoteRegistry had to be
        auto-re-enabled from Disabled (see `_ensure_service_running`'s docstring) to reach the registry at
        all, running `fixblankpasswordpolicy on` afterwards stops it again and sets its start type back to
        Disabled, so running this command doesn't leave a service permanently re-enabled on the target as an
        unintended side effect. If RemoteRegistry was already enabled/running before you ever ran this
        command (i.e. this session never had to touch its start type), `on` leaves it alone -- only a
        service *this session* changed gets reverted.
        """
        arg = line.strip().lower() or 'off'
        if arg not in ('on', 'off'):
            print('usage: fixblankpasswordpolicy [on|off]')
            return
        value = 1 if arg == 'on' else 0
        self.do_regsetdword(r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa LimitBlankPasswordUse %d' % value)
        if value == 0:
            print('Blank-password network logon restriction disabled.')
        else:
            print('Blank-password network logon restriction re-enabled.')
            if 'RemoteRegistry' in self._services_we_enabled:
                try:
                    self._restore_service_disabled('RemoteRegistry')
                    print('RemoteRegistry service start type restored to Disabled (as it was before this '
                          'session touched it).')
                except DCERPCException as e:
                    print('warning: failed to restore RemoteRegistry to Disabled (%s); it was left enabled '
                          'and running' % e)

    def do_fixuactokenfilter(self, line):
        """fixuactokenfilter [on|off] - Toggle UAC remote restrictions for local accounts (registry:
        HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy).

        This is the explanation for a specific, very confusing-looking symptom: a LOCAL account that is
        genuinely a member of the local Administrators group (confirmed via `net user` on the box itself, or
        via this shell's own `listaliasmem --builtin Administrators`) still behaves like an unprivileged user
        the moment it authenticates over the network -- SMB session establishes and IPC$/share listing work,
        but ADMIN$ and C$ are denied, remote command execution (psexec/wmiexec/smbexec-style tooling) fails,
        and netexec-style "pwned" indicators never light up, all while `queryuser`/`net user` genuinely show
        the account enabled, unrestricted, and in Administrators.

        The cause: by default (value 0, or the key simply not existing -- same effect either way), Windows
        gives ANY local account a UAC-FILTERED token on network logon, stripping Administrators membership
        and admin privileges from that specific token even though the account's real group membership is
        unchanged -- it's the network session's token that's neutered, not the account. This is Microsoft's
        own documented "Apply UAC restrictions to local accounts on network logons" behavior/KB951016, and it
        does NOT apply to domain accounts (a domain admin logging on remotely always gets a full token) or to
        the actual built-in RID-500 "Administrator" account (exempt via a separate, also-default-0 registry
        value, FilterAdministratorToken, in the same key) -- which is exactly why an `Administrator@target`
        session in this tool has full access while a different local admin account you just created doesn't.

        `off` (the default if no argument given) sets LocalAccountTokenFilterPolicy to 1, disabling the
        filtering so local admin accounts get a full token over the network; `on` sets it back to 0 (the
        secure default) -- this is also the undo for `off`. Takes effect immediately, no reboot needed.

        Like `fixblankpasswordpolicy`, `on` also undoes RemoteRegistry auto-re-enablement if this session was
        the one that had to do it to reach the registry at all.
        """
        arg = line.strip().lower() or 'off'
        if arg not in ('on', 'off'):
            print('usage: fixuactokenfilter [on|off]')
            return
        value = 1 if arg == 'off' else 0
        self.do_regsetdword(
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System LocalAccountTokenFilterPolicy %d'
            % value)
        if value == 1:
            print('UAC remote restrictions disabled -- local admin accounts now get a full token over the '
                  'network.')
        else:
            print('UAC remote restrictions re-enabled (secure default).')
            if 'RemoteRegistry' in self._services_we_enabled:
                try:
                    self._restore_service_disabled('RemoteRegistry')
                    print('RemoteRegistry service start type restored to Disabled (as it was before this '
                          'session touched it).')
                except DCERPCException as e:
                    print('warning: failed to restore RemoteRegistry to Disabled (%s); it was left enabled '
                          'and running' % e)

    # ------------------------------------------------------------------
    # WKSSVC
    # ------------------------------------------------------------------
    def do_wkstainfo(self, line):
        """wkstainfo - Retrieve workstation info"""
        dce = self._get_dce('wkssvc')
        resp = wkst.hNetrWkstaGetInfo(dce, 100)
        info = resp['WkstaInfo']['WkstaInfo100']
        print('Version:    %d.%d' % (info['wki100_ver_major'], info['wki100_ver_minor']))
        print('Platform ID:%d' % info['wki100_platform_id'])
        print('Computer:   %s' % info['wki100_computername'][:-1])
        print('Domain:     %s' % info['wki100_langroup'][:-1])

    def _samr_dce_anonymous_tcp(self):
        """Bind to SAMR over ncacn_ip_tcp (resolved via the endpoint mapper on port 135) as a fully bare,
        unauthenticated null-session RPC bind -- auth_level left at its default (RPC_C_AUTHN_LEVEL_NONE), no
        NTLM exchange attempted at all.

        This now deliberately matches netexec's change-password module byte-for-byte (verified against its
        actual source, nxc/helpers/rpc.py's NXCRPCConnection.setup_credentials with anonymous_rpc=True; not
        inferred from its behavior) rather than an earlier, wrong guess in this file that it needed a real
        (if anonymous-identity) NTLM handshake:

        - nxc calls rpc_transport.set_credentials("", "", "", "", "", "") -- but that's a TRANSPORT-level
          call that only stores values for later retrieval; it does NOT set the DCE object's auth_level.
        - nxc never calls dce.set_auth_level() or dce.set_auth_type() for the anonymous path (its `auth_level`
          parameter, which would trigger that, is left as its default None and simply never passed for this
          call site).
        - dce.bind()'s NTLM-attachment logic is entirely gated behind `if self.__auth_level !=
          RPC_C_AUTHN_LEVEL_NONE`, so with auth_level never touched, this really is a bare bind with zero
          auth data in the BIND PDU -- not an anonymous-identity NTLM handshake, which was this file's
          previous (incorrect) attempt.

        If this still gets rpc_s_access_denied against a given target, that's no longer this tool doing
        something wrong relative to a known-working reference -- it means that target's SAMR RPC interface
        has anonymous/null-session access hardened off (Windows' "Network access: Restrict clients allowed
        to make remote calls to SAM" / RestrictRemoteSam policy, on by default since Windows 10 1607 for
        workstations), which would block netexec's identical technique too. That's a genuine target-side
        restriction, not a bug to keep chasing in this file.

        Requires TCP port 135 (the endpoint mapper) plus whatever dynamic high port it hands back to be
        reachable -- if you're pivoting through a narrow SOCKS/proxychains setup that only forwards 445, this
        will fail to connect; you'd need port 135 (and the ephemeral RPC port range) tunneled too.
        """
        string_binding = epm.hept_map(self.address, samr.MSRPC_UUID_SAMR, protocol='ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.setRemoteHost(self.address)
        rpctransport.set_credentials('', '', '', '', '', '')
        rpctransport.set_kerberos(False, None)
        if hasattr(rpctransport, 'set_connect_timeout'):
            rpctransport.set_connect_timeout(self.timeout)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        # Deliberately no set_auth_level()/set_auth_type() call -- see docstring above.
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    # ------------------------------------------------------------------
    # Self-service password change (SAMR) -- this is the "own account,
    # know-your-old-password" flow, equivalent to real rpcclient's
    # `chgpasswd`. It does NOT require domain admin rights; it requires
    # the caller to supply their own current password, same as pressing
    # Ctrl-Alt-Del -> Change Password on a Windows box.
    # ------------------------------------------------------------------
    def do_chgpasswd(self, line):
        """chgpasswd <username> [old_nthash] - Change a user's password (self-service; you must know the
        current password or its NT hash). If old_nthash is given (32 hex chars), it's used instead of
        prompting for the old plaintext password -- handy when you only have the hash (e.g. a blank-password
        account's well-known 31d6cfe0d16ae931b73c59d7e0c089c0).

        Reaches SAMR via `_samr_dce_anonymous_tcp` -- an unauthenticated ncacn_ip_tcp bind -- which is what
        actually makes this work for an account whose password has expired / must change at first logon, the
        scenario every other command's connection path treats as fatal. See that method's docstring for the
        full mechanism and for the record of what didn't work and why.

        NOTE: Some servers (Samba in particular) explicitly reject this exchange when the old-password hash
        equals the well-known "empty password" hash, as a hardening measure -- even though the account
        genuinely has that hash. If you hit that against a Samba target specifically, and you have SAM write
        access, use `setuserpass` instead (admin-side reset, doesn't touch the old password at all).
        """
        parts = line.split()
        if not parts:
            print('usage: chgpasswd <username> [old_nthash]')
            return
        username = parts[0]
        old_nthash = parts[1] if len(parts) > 1 else ''
        if old_nthash:
            old_password = ''
        else:
            old_password = getpass.getpass('Old password: ')
        new_password = getpass.getpass('New password: ')
        confirm = getpass.getpass('Retype new password: ')
        if new_password != confirm:
            print('error: new passwords do not match')
            return
        dce = self._samr_dce_anonymous_tcp()
        try:
            samr.hSamrUnicodeChangePasswordUser2(
                dce, userName=username,
                oldPassword=old_password, newPassword=new_password,
                oldPwdHashNT=old_nthash)
            print('Password changed for %s' % username)
        finally:
            dce.disconnect()

    def do_setuserpass(self, line):
        """setuserpass <username> [newpassword] [--must-change] - Administratively set a user's password (no
        old password needed; requires SAM write access on the target account, same as net.py's
        `user -newPasswd`). If newpassword is omitted, you'll be prompted (recommended, keeps it out of shell
        history) -- --must-change can still be given after an omitted password.

        Uses the same self._set_user_password mechanism as `createdomuser`'s optional password arg -- see
        that method's docstring for how it encrypts the password and what to do (`-dialect 1` at startup) if
        it fails with an empty-session-key error. By default the account is NOT marked as needing a password
        change at next logon; pass --must-change if you want that.
        """
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            print('error: %s' % e)
            return
        must_change = '--must-change' in tokens
        tokens = [t for t in tokens if t != '--must-change']

        if not tokens:
            print('usage: setuserpass <username> [newpassword] [--must-change]')
            return
        username = tokens[0]
        if len(tokens) > 1:
            new_password = tokens[1]
        else:
            new_password = getpass.getpass('New password: ')
            confirm = getpass.getpass('Retype new password: ')
            if new_password != confirm:
                print('error: new passwords do not match')
                return

        dce = self._get_dce('samr')
        dom_handle = self._samr_domain()
        rid = self._resolve_user_rid(dce, dom_handle, username)
        resp = samr.hSamrOpenUser(dce, dom_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp['UserHandle']
        try:
            password_set_ok = False
            try:
                self._set_user_password(dce, user_handle, new_password, password_expired=must_change)
                print('Password set for %s%s' % (username, ' (must change at next logon)' if must_change else ''))
                password_set_ok = True
            except DCERPCException as e:
                print('error: failed to set password for %s (%s). Run `smbinfo` to check whether this is '
                      'the empty-session-key issue -- see `help setuserpass` for the full explanation. Note '
                      'that "-dialect 1" only helps if the target still has legacy SMB1 enabled; most '
                      'current Windows targets do not, in which case this is a hard blocker on this path, '
                      'not something restarting with a different flag will fix.' % (username, e))

            # Even if the password-set call above failed, don't leave the account stuck requiring a change
            # nobody asked for -- clear (or set, if --must-change) that flag independently. See
            # _clear_password_expired's docstring: this path has no session-key dependency, so it can
            # succeed even when _set_user_password's RC4/session-key-based path just failed.
            if not password_set_ok:
                try:
                    self._clear_password_expired(dce, user_handle, expired=must_change)
                except DCERPCException as e:
                    print('warning: also failed to clear must-change-password flag for %s (%s)' % (username, e))
        finally:
            samr.hSamrCloseHandle(dce, user_handle)

    # ------------------------------------------------------------------
    # Generic / arbitrary RPC interfaces
    #
    # Anything impacket ships a typed stub module for (svcctl, winreg,
    # eventlog, drsuapi, epm, atsvc, nrpc/netlogon, scmr, browser, ...)
    # can be added to PIPES the same way samr/lsarpc/srvsvc/wkssvc are:
    #
    #   from impacket.dcerpc.v5 import svcctl
    #   PIPES['svcctl'] = (r'\pipe\svcctl', svcctl.MSRPC_UUID_SCMR)
    #
    # then self._get_dce('svcctl') gives a bound handle to drive with
    # svcctl's own hXxx() helpers, exactly like the SAMR/LSA commands
    # above.
    #
    # For an interface that has NO impacket stub at all -- an unknown
    # or vendor-specific RPC service -- `bind` + `rawcall` below let you
    # talk to it directly: you supply the pipe name and interface UUID,
    # and hand the opnum body in as hex (you're responsible for the NDR
    # encoding yourself, same as you would be shelling raw bytes at any
    # other unstubbed RPC service).
    # ------------------------------------------------------------------
    def do_bind(self, line):
        """bind <pipe> <uuid> [major.minor] - Bind to an arbitrary named pipe/interface for use with rawcall.
        Example: bind \\pipe\\svcctl 367abb81-9844-35f1-ad32-98f038001003 2.0"""
        parts = line.split()
        if len(parts) < 2:
            print(r'usage: bind <\pipe\name> <interface-uuid> [major.minor]')
            return
        pipe_path, iface_uuid = parts[0], parts[1]
        major, minor = 1, 0
        if len(parts) >= 3 and '.' in parts[2]:
            major, minor = (int(x) for x in parts[2].split('.', 1))

        if not pipe_path.startswith('\\'):
            pipe_path = '\\' + pipe_path

        string_binding = r'ncacn_np:%s[%s]' % (self.address, pipe_path)
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        if self.dialect is not None and hasattr(rpctransport, 'preferred_dialect'):
            rpctransport.preferred_dialect(self.dialect)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain,
                                          self.lmhash, self.nthash, self.aesKey)
        if hasattr(rpctransport, 'set_kerberos'):
            rpctransport.set_kerberos(self.doKerberos, kdcHost=self.dcHost)
        if hasattr(rpctransport, 'setRemoteHost'):
            rpctransport.setRemoteHost(self.address)
        if hasattr(rpctransport, 'set_dport'):
            rpctransport.set_dport(self.port)
        if hasattr(rpctransport, 'set_connect_timeout'):
            rpctransport.set_connect_timeout(self.timeout)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(uuidtup_to_bin((iface_uuid, '%d.%d' % (major, minor))))

        self._custom_dce = dce
        self._custom_binding = (pipe_path, iface_uuid, major, minor)
        print('bound to %s interface %s v%d.%d' % (pipe_path, iface_uuid, major, minor))

    def do_rawcall(self, line):
        """rawcall <opnum> [hex-payload] - Send a raw opnum + NDR-encoded hex body on the interface from `bind`, print the raw hex response."""
        if self._custom_dce is None:
            print('error: no custom interface bound; run "bind" first')
            return
        parts = line.split(None, 1)
        if not parts:
            print('usage: rawcall <opnum> [hex-payload]')
            return
        opnum = int(parts[0], 0)
        payload = bytes.fromhex(parts[1].strip()) if len(parts) > 1 and parts[1].strip() else b''
        self._custom_dce.call(opnum, payload)
        answer = self._custom_dce.recv()
        print('response (%d bytes): %s' % (len(answer), answer.hex()))
def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help=True, description=(
        'Python port of rpcclient, built on impacket DCE/RPC transport.'))
    parser.add_argument('target', action='store',
                         help='[[domain/]username[:password]@]<address>')
    parser.add_argument('-c', action='store', metavar='commands', default=None,
                         help='semicolon separated list of commands to run non-interactively')
    parser.add_argument('-port', choices=['139', '445'], nargs='?', default='445',
                         help='destination port (default 445)')
    parser.add_argument('-debug', action='store_true', help='verbose error output')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                        help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help="don't prompt for password")
    group.add_argument('-k', action='store_true',
                        help='use Kerberos authentication, pull creds from ccache')
    group.add_argument('-aesKey', action='store', metavar='hex key',
                        help='AES key for Kerberos auth (128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar='ip address',
                        help='IP of a domain controller, for Kerberos')

    net = parser.add_argument_group('connection')
    net.add_argument('-timeout', action='store', type=int, default=30, metavar='seconds',
                      help='connection timeout in seconds (raise this over slow SOCKS/proxychains tunnels; default 30)')
    net.add_argument('-socks-proxy', action='store', metavar='host:port', default=None,
                      help='route all traffic through a SOCKS5 proxy natively (alternative to running under '
                           'proxychains; requires PySocks: pip install PySocks)')
    net.add_argument('-dialect', choices=sorted(SMB_DIALECT_MAP.keys()), default=None,
                      help='force a specific SMB dialect instead of letting impacket negotiate the best one. '
                           'Run the `smbinfo` in-shell command first to see the negotiated dialect and whether '
                           'the session key impacket needs for setuserpass/createdomuser password-setting is '
                           'actually available before reaching for this -- forcing "1" (legacy SMB1) only '
                           'helps if the target still has the SMB1 server component enabled; most modern '
                           'Windows targets have it off by default and will reject the connection outright.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init()

    if options.socks_proxy:
        if not HAVE_PYSOCKS:
            print('error: -socks-proxy requires PySocks (pip install PySocks --break-system-packages)')
            sys.exit(1)
        proxy_host, _, proxy_port = options.socks_proxy.partition(':')
        if not proxy_port:
            print('error: -socks-proxy must be host:port, e.g. 127.0.0.1:1080')
            sys.exit(1)
        # Monkey-patch the default socket so every connection impacket opens
        # (SMB, DCE/RPC, and Kerberos-to-KDC if -k/-dc-ip is also used) is
        # routed through the SOCKS5 proxy. This must happen before any
        # transport/connection objects are created below.
        socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port), rdns=True)
        socket.socket = socks.socksocket
        print('routing all traffic through SOCKS5 proxy %s:%s' % (proxy_host, proxy_port))

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = nthash = ''

    if password == '' and username != '' and options.hashes is None and not options.no_pass \
            and options.aesKey is None:
        password = getpass.getpass('Password:')

    dialect = SMB_DIALECT_MAP[options.dialect] if options.dialect else None
    shell = RPCClientShell(address, username, password, domain, lmhash, nthash,
                            options.aesKey, options.k, options.dc_ip,
                            int(options.port), options.timeout, dialect)

    if options.c:
        for command in options.c.split(';'):
            command = command.strip()
            if command:
                shell.onecmd(command)
    else:
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print('')


if __name__ == '__main__':
    main()
