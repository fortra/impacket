#!/usr/bin/env python
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
#   Impacket alternative for windows net.exe commandline utility.
#   Thanks to rpc protocol, the special feature of this tool is 
#   making net.exe functionalities available from remote computer.
#
#   e.g:
#       python net.py Administrator:password@targetMachine localgroup
#       python net.py Administrator:password@targetMachine user
#       python net.py Administrator:password@targetMachine group
#       python net.py Administrator:password@targetMachine computer
#       python net.py Administrator:password@targetMachine localgroup -name Administrators
#       python net.py Administrator:password@targetMachine user -name Administrator
#       python net.py Administrator:password@targetMachine group -name "Domain Admins"
#       python net.py Administrator:password@targetMachine computer -name DC$
#       python net.py Administrator:password@targetMachine group -name "Domain Admins" -join EvilUs3r
#       python net.py Administrator:password@targetMachine user -enable EvilUs3r
#       python net.py Administrator:password@targetMachine user -disable EvilUs3r
#
# Author:
#   Alex Romero (@NtAlexio2)
#
# Reference for:
#   [MS-SAMR]
# 

import sys
import argparse
import logging
from datetime import datetime

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, samr, lsad, lsat
from impacket.smbconnection import SMBConnection


class LsaTranslator:
    def __init__(self, smbConnection):
        self._smbConnection = smbConnection
        self.__stringBindingSamr = r'ncacn_np:445[\pipe\lsarpc]'
        self._lsat_dce = None
        self.Connect()

    def Connect(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSamr)
        rpc.set_smb_connection(self._smbConnection)
        self._lsat_dce = rpc.get_dce_rpc()
        self._lsat_dce.connect()
        self._lsat_dce.bind(lsat.MSRPC_UUID_LSAT)

    def LookupName(self, name):
        policyHandle = lsad.hLsarOpenPolicy2(self._lsat_dce)['PolicyHandle']
        resp = lsat.hLsarLookupNames3(self._lsat_dce, policyHandle, (name, ))
        lsad.hLsarClose(self._lsat_dce, policyHandle)
        return resp['TranslatedSids']['Sids'][0]['Sid']

    def LookupSids(self, sid_list):
        policyHandle = lsad.hLsarOpenPolicy2(self._lsat_dce)['PolicyHandle']
        resp = lsat.hLsarLookupSids2(self._lsat_dce, policyHandle, sid_list)
        lsad.hLsarClose(self._lsat_dce, policyHandle)
        return resp['TranslatedNames']['Names']


class SamrObject:
    def __init__(self, smbConnection):
        self._smbConnection = smbConnection
        self.__stringBindingSamr = r'ncacn_np:445[\pipe\samr]'
        self._dce = None
        self._domain_handle = None
        self._translator = None
        self._connect()

    def _connect(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSamr)
        rpc.set_smb_connection(self._smbConnection)
        self._dce = rpc.get_dce_rpc()
        self._dce.connect()
        self._dce.bind(samr.MSRPC_UUID_SAMR)

    def _get_user_sid(self, username):
        if self._translator is None:
            self._translator = LsaTranslator(self._smbConnection)
        return self._translator.LookupName(username)

    def _resolve_sid(self, sid_list):
        if self._translator is None:
            self._translator = LsaTranslator(self._smbConnection)
        return self._translator.LookupSids(sid_list)

    def _get_object_rid(self, domain_handle, object_name):
        response = samr.hSamrLookupNamesInDomain(self._dce, domain_handle, (object_name,))
        object_id = response['RelativeIds']['Element'][0]['Data']
        return object_id

    def _get_user_handle(self, domain_handle, username):
        user_rid = self._get_object_rid(domain_handle, username)
        response = samr.hSamrOpenUser(self._dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)
        return response['UserHandle']

    def _get_group_handle(self, domain_handle, alias_name):
        group_rid = self._get_object_rid(domain_handle, alias_name)
        response = samr.hSamrOpenGroup(self._dce, domain_handle, samr.MAXIMUM_ALLOWED, group_rid)
        return response['GroupHandle']

    def _get_alias_handle(self, domain_handle, alias_name):
        alias_rid = self._get_object_rid(domain_handle, alias_name)
        response = samr.hSamrOpenAlias(self._dce, domain_handle, samr.MAXIMUM_ALLOWED, alias_rid)
        return response['AliasHandle']

    def _open_domain(self, builtin=False):
        if self._domain_handle is None:
            self._domain_handle = self.__get_domain_handle(builtin)
        return self._domain_handle

    def _close_domain(self):
        if self._domain_handle != None:
            samr.hSamrCloseHandle(self._dce, self._domain_handle)
            self._domain_handle = None

    def __get_domain_handle(self, builtin=False):
        index = 1 if builtin else 0
        server_handle = samr.hSamrConnect(self._dce)['ServerHandle']
        domain_name = samr.hSamrEnumerateDomainsInSamServer(self._dce, server_handle)['Buffer']['Buffer'][index]['Name']
        domain_id = samr.hSamrLookupDomainInSamServer(self._dce, server_handle, domain_name)['DomainId']
        domain_handle = samr.hSamrOpenDomain(self._dce, server_handle, domainId=domain_id)['DomainHandle']
        return domain_handle


class User(SamrObject):
    def __init__(self, smbConnection):
        super().__init__(smbConnection)
        self._create_account_type = samr.USER_NORMAL_ACCOUNT
        self._enum_account_type = samr.USER_NORMAL_ACCOUNT

    def Enumerate(self):
        domain_handle = self._open_domain()
        try:
            response = samr.hSamrEnumerateUsersInDomain(self._dce, domain_handle, self._enum_account_type)
            for item in response['Buffer']['Buffer']:
                yield item
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
        finally:
            self._close_domain()
    
    def Query(self, name):
        domain_handle = self._open_domain(False)
        try:
            user_handle = self._get_user_handle(domain_handle, name)
            response = samr.hSamrQueryInformationUser2(self._dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
            response = response['Buffer']['All']

            # Get groups that user is member of
            groups = samr.hSamrGetGroupsForUser(self._dce, user_handle)['Groups']['Groups']
            group_id_list = list(map(lambda g: g['RelativeId'], groups))

            sidArray = samr.SAMPR_PSID_ARRAY()
            for gid in group_id_list:
                group_handle = samr.hSamrOpenGroup(self._dce, domain_handle, groupId=gid)['GroupHandle']
                group_sid = samr.hSamrRidToSid(self._dce, group_handle, gid)['Sid']
                si = samr.PSAMPR_SID_INFORMATION()
                si['SidPointer'] = group_sid
                sidArray['Sids'].append(si)
                samr.hSamrCloseHandle(self._dce, group_handle)
            
            global_lookup_ids = samr.hSamrLookupIdsInDomain(self._dce, domain_handle, group_id_list)
            response.fields['GlobalGroups'] = list(map(lambda a: a['Data'], global_lookup_ids['Names']['Element']))

            self._close_domain()
            domain_handle = self._open_domain(True)

            alias_membership = samr.hSamrGetAliasMembership(self._dce, domain_handle, sidArray)
            alias_id_list = list(map(lambda a: a['Data'], alias_membership['Membership']['Element']))

            local_lookup_ids = samr.hSamrLookupIdsInDomain(self._dce, domain_handle, alias_id_list)
            response.fields['LocalGroups'] = list(map(lambda a: a['Data'], local_lookup_ids['Names']['Element']))
            return response

        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
        finally:
            self._close_domain()

    def Create(self, name, new_password, new_nt_hash=''):
        domain_handle = self._open_domain()
        user_handle = samr.hSamrCreateUser2InDomain(self._dce, domain_handle, name, self._create_account_type, samr.USER_ALL_ACCESS)['UserHandle']
        try:
            samr.hSamrSetNTInternal1(self._dce, user_handle, new_password, new_nt_hash)
        except samr.DCERPCSessionError as e:
            samr.hSamrDeleteUser(self._dce, user_handle)
            raise
        else:
            self._hEnableAccount(user_handle)
        finally:
            self._close_domain()

    def Remove(self, name):
        domain_handle = self._open_domain()
        try:
            user_handle = self._get_user_handle(domain_handle, name)
            samr.hSamrDeleteUser(self._dce, user_handle)
        finally:
            self._close_domain()

    def _hEnableAccount(self, user_handle):
        user_account_control = samr.hSamrQueryInformationUser2(self._dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)['Buffer']['All']['UserAccountControl']
        buffer = samr.SAMPR_USER_INFO_BUFFER()
        buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        buffer['Control']['UserAccountControl'] = user_account_control ^ samr.USER_ACCOUNT_DISABLED
        samr.hSamrSetInformationUser2(self._dce, user_handle, buffer)

    def _hDisableAccount(self, user_handle):
        user_account_control = samr.hSamrQueryInformationUser2(self._dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)['Buffer']['All']['UserAccountControl']
        buffer = samr.SAMPR_USER_INFO_BUFFER()
        buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
        buffer['Control']['UserAccountControl'] = samr.USER_ACCOUNT_DISABLED | user_account_control
        samr.hSamrSetInformationUser2(self._dce, user_handle, buffer)

    def SetUserAccountControl(self, name, action):
        info = self.Query(name)
        domain_handle = self._open_domain()
        try:
            user_handle = self._get_user_handle(domain_handle, name)
            if action == 'enable':
                self._hEnableAccount(user_handle)
            else:
                self._hDisableAccount(user_handle)
        finally:
            self._close_domain()



class Computer(User):
    def __init__(self, smbConnection):
        super().__init__(smbConnection)
        self._create_account_type = samr.USER_WORKSTATION_TRUST_ACCOUNT
        self._enum_account_type = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT


class Group(SamrObject):
    def Enumerate(self):
        domain_handle = self._open_domain()
        try:
            response = samr.hSamrEnumerateGroupsInDomain(self._dce, domain_handle)
            for item in response['Buffer']['Buffer']:
                yield item
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
        finally:
            self._close_domain()
    
    def Query(self, group_name):
        domain_handle = self._open_domain()
        try:
            group_handle = self._get_group_handle(domain_handle, group_name)
            response = samr.hSamrGetMembersInGroup(self._dce, group_handle)
            response = samr.hSamrLookupIdsInDomain(self._dce, domain_handle, list(map(lambda a: a['Data'], response['Members']['Members'])))
            return list(map(lambda a: a['Data'], response['Names']['Element']))
        finally:
            self._close_domain()

    def Join(self, group_name, username):
        domain_handle = self._open_domain()
        try:
            group_handle = self._get_group_handle(domain_handle, group_name)
            user_rid = self._get_object_rid(domain_handle, username)
            samr.hSamrAddMemberToGroup(self._dce, group_handle, user_rid, samr.SE_GROUP_ENABLED_BY_DEFAULT)
        finally:
            self._close_domain()

    def UnJoin(self, group_name, username):
        domain_handle = self._open_domain()
        try:
            group_handle = self._get_group_handle(domain_handle, group_name)
            user_rid = self._get_object_rid(domain_handle, username)
            samr.hSamrRemoveMemberFromGroup(self._dce, group_handle, user_rid)
        finally:
            self._close_domain()


class Localgroup(Group):
    def Enumerate(self):
        domain_handle = self._open_domain(True)
        try:
            response = samr.hSamrEnumerateAliasesInDomain(self._dce, domain_handle)
            for item in response['Buffer']['Buffer']:
                yield item
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
        finally:
            self._close_domain()
    
    def Query(self, group_name):
        domain_handle = self._open_domain(True)
        try:
            alias_handle = self._get_alias_handle(domain_handle, group_name)
            response = samr.hSamrGetMembersInAlias(self._dce, alias_handle)
            response = self._resolve_sid(list(map(lambda s: s['Data']['SidPointer'].formatCanonical(), response['Members']['Sids'])))
            return list(map(lambda x: x['Name'], response))
        finally:
            self._close_domain()

    def Join(self, group_name, username):
        domain_handle = self._open_domain(True)
        try:
            alias_handle = self._get_alias_handle(domain_handle, group_name)
            user_sid = self._get_user_sid(username)
            samr.hSamrAddMemberToAlias(self._dce, alias_handle, user_sid)
        finally:
            self._close_domain()

    def UnJoin(self, group_name, username):
        domain_handle = self._open_domain(True)
        try:
            alias_handle = self._get_alias_handle(domain_handle, group_name)
            user_sid = self._get_user_sid(username)
            samr.hSamrRemoveMemberFromAlias(self._dce, alias_handle, user_sid)
        finally:
            self._close_domain()


class Net:
    def __init__(self, domain, username, password, options):
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__options = options
        self.__action = options.entry.lower()
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.__smbConnection = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self, remoteName, remoteHost):
        self.__smbConnection = SMBConnection(remoteName, remoteHost, sess_port=int(self.__options.port))

        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def disconnect(self):
        self.__smbConnection.close()
        self.__smbConnection = None

    def run(self, remoteName, remoteHost):
        self.connect(remoteName, remoteHost)

        actionClass = self.__get_action_class(self.__action)
        actionObject = actionClass(self.__smbConnection)

        if self.__is_option_present(self.__options, 'create'):
            print("[*] Creating {} account '{}'".format(self.__action, self.__options.create))
            actionObject.Create(self.__options.create, self.__options.newPasswd)
            print("[+] {} account created succesfully: {}:{}".format(self.__action, self.__options.create, self.__options.newPasswd))

        elif self.__is_option_present(self.__options, 'remove'):
            print("[*] Deleting {} account '{}'".format(self.__action, self.__options.remove))
            actionObject.Remove(self.__options.remove)
            print("[+] {} account deleted succesfully!".format(self.__action))

        elif self.__is_option_present(self.__options, 'enable'):
            print("[*] Enabling {} account '{}'".format(self.__action, self.__options.enable))
            actionObject.SetUserAccountControl(self.__options.enable, "enable")
            print("[+] {} account enabled succesfully!".format(self.__action))

        elif self.__is_option_present(self.__options, 'disable'):
            print("[*] Disabling {} account '{}'".format(self.__action, self.__options.disable))
            actionObject.SetUserAccountControl(self.__options.disable, "disable")
            print("[+] {} account disabled succesfully!".format(self.__action))

        elif self.__is_option_present(self.__options, 'join'):
            print("[*] Adding user account '{}' to group '{}'".format(self.__options.join,self.__options.name))
            actionObject.Join(self.__options.name, self.__options.join)
            print("[+] User account added to {} succesfully!".format(self.__options.name))

        elif self.__is_option_present(self.__options, 'unjoin'):
            print("[*] Removing user account '{}' from group '{}'".format(self.__options.unjoin,self.__options.name))
            actionObject.UnJoin(self.__options.name, self.__options.unjoin)
            print("[+] User account removed from {} succesfully!".format(self.__options.name))

        elif self.__is_option_present(self.__options, 'name'):
            info = actionObject.Query(self.__options.name)
            if type(info) == list:
                i = 1
                for member in info:
                    print("  {0}. {1}".format(i, member))
                    i += 1
            else:
                print("User name".ljust(30), info['UserName'])
                print("Full name".ljust(30), info['FullName'])
                print("Comment".ljust(30), info['AdminComment'])
                print("User's comment".ljust(30), info['UserComment'])
                print("Country/region code".ljust(30), "000 (System Default)" if info['CountryCode'] == 0 else info['CountryCode'])
                print("Account active".ljust(30), self.__b2s(info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED != samr.USER_ACCOUNT_DISABLED))
                print("Account expires".ljust(30), self.__get_time_string(info['AccountExpires']))
                print('')
                print("Password last set".ljust(30), self.__get_time_string(info['PasswordLastSet']))
                print("Password expires".ljust(30), self.__get_time_string(info['PasswordMustChange']))
                print("Password changeable".ljust(30), self.__get_time_string(info['PasswordCanChange']))
                print("Password required".ljust(30), self.__b2s(info['WhichFields'] & samr.USER_PASSWORD_NOT_REQUIRED == samr.USER_PASSWORD_NOT_REQUIRED))
                print("User may change password".ljust(30), self.__b2s(info['WhichFields'] & samr.UF_PASSWD_CANT_CHANGE == samr.UF_PASSWD_CANT_CHANGE))
                print('')
                print("Workstations allowed".ljust(30), "All" if not info['WorkStations'] else info['WorkStations'])
                print("Logon script".ljust(30), info['ScriptPath'])
                print("User profile".ljust(30), info['ProfilePath'])
                print("Home directory".ljust(30), info['HomeDirectory'])
                print("Last logon".ljust(30), self.__get_time_string(info['LastLogon']))
                print("Logon count".ljust(30), info['LogonCount'])
                print('')
                print("Logon hours allowed".ljust(30), self.__format_logon_hours(info['LogonHours']['LogonHours']))
                print('')
                print("Local Group Memberships")
                for group in info['LocalGroups']:
                    print("  * {}".format(group))
                print('')
                print("Global Group memberships")
                for group in info['GlobalGroups']:
                    print("  * {}".format(group))

        else:
            print("[*] Enumerating {}s ..".format(self.__action))
            i = 1
            for object in actionObject.Enumerate():
                messae = "  {0}. {1}".format(i, object['Name'])
                if self.__options.debug:
                    messae += " ({0})".format(object['RelativeId'])
                print(messae)
                i += 1

        self.disconnect()

    def __getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def __get_time_string(self, large_integer):
        time = (large_integer['HighPart'] << 32) + large_integer['LowPart']
        if time == 0 or time == 0x7FFFFFFFFFFFFFFF:
            time = 'Never'
        else:
            time = datetime.fromtimestamp(self.__getUnixTime(time))
            time = time.strftime("%m/%d/%Y %H:%M:%S %p")
        return time
    
    def __format_logon_hours(self, s):
        logon_hours = ''.join(map(lambda b: b.hex(), s))
        if logon_hours == ('f' * 42):
            logon_hours = "All"
        return logon_hours
    
    def __b2s(self, b):
        return "Yes" if b else "No"

    def __get_action_class(self, action):
        return getattr(sys.modules[__name__], action.capitalize())
    
    def __is_option_present(self, options, option):
        return hasattr(options, option) and getattr(options, option)



if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "SAMR rpc client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    subparsers = parser.add_subparsers(help='An account entry name', dest='entry', required=True)

    user_parser = subparsers.add_parser('user', help='Enumerate all domain/local user accounts')
    user_parser.add_argument('-name', action="store", metavar = "NAME", help='Display single user information.')
    user_parser.add_argument('-create', action="store", metavar = "NAME", help='Add new user account to domain/computer.')
    user_parser.add_argument('-remove', action="store", metavar = "NAME", help='Remove existing user account from domain/computer.')
    user_parser.add_argument('-newPasswd', action="store", metavar = "PASSWORD", help='New password to set for creating account.')
    user_parser.add_argument('-enable', action="store", metavar = "NAME", help='Enables account.')
    user_parser.add_argument('-disable', action="store", metavar = "NAME", help='Disables account.')

    computer_parser = subparsers.add_parser('computer', help='Enumerate all computers in domain level')
    computer_parser.add_argument('-name', action="store", metavar = "NAME", help='Display single computer information.')
    computer_parser.add_argument('-create', action="store", metavar = "NAME", help='Add new computer account to domain.')
    computer_parser.add_argument('-remove', action="store", metavar = "NAME", help='Remove existing computer account from domain.')
    computer_parser.add_argument('-newPasswd', action="store", metavar = "PASSWORD", help='New password to set for creating account.')
    computer_parser.add_argument('-enable', action="store", metavar = "NAME", help='Enables account.')
    computer_parser.add_argument('-disable', action="store", metavar = "NAME", help='Disables account.')

    localgroup_parser = subparsers.add_parser('localgroup', help='Enumerate local groups (aliases) of local computer')
    localgroup_parser.add_argument('-name', action="store", metavar = "NAME", help='Operate on single specific domain group account.')
    localgroup_parser.add_argument('-join', action="store", metavar = "USER", help='Add user account to specific group.')
    localgroup_parser.add_argument('-unjoin', action="store", metavar = "USER", help='Remove user account from specific group.')

    group_parser = subparsers.add_parser('group', help='Enumerate domain groups registered in domain controller')
    group_parser.add_argument('-name', action="store", metavar = "NAME", help='Operate on single specific localgroup account.')
    group_parser.add_argument('-join', action="store", metavar = "USER", help='Add user account to specific group.')
    group_parser.add_argument('-unjoin', action="store", metavar = "USER", help='Remove user account from specific group.')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if ((hasattr(options, 'join') and options.join) or hasattr(options, 'unjoin') and options.unjoin) and not options.name:
        logging.error("argument '-name' is required with join/unjoin operations.")
        sys.exit(1)

    if (hasattr(options, 'create') and options.create) and (not hasattr(options, 'create') or not options.newPasswd):
        logging.error("argument '-newPasswd' is required for creating new account.")
        sys.exit(1)

    logger.init(options.ts, options.debug)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password: ")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    net = Net(domain, username, password, options)
    try:
        net.run(address, options.target_ip)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
