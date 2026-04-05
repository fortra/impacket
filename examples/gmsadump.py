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
#   Queries Active Directory via LDAP to enumerate all or a specific/target Group Managed Service
#   Accounts (gMSAs) and dumps their managed password as NT hash, AES-128, and AES-256 kerberos keys.
#   Can be used to only enumerate, using the -enum flag. Additionally you can use -gmsa to specify a specific object
#   or using wildcard.
#
#
#
# Author:
#   Abdul Mhanni And Alexander Chin-Lenn
#
# Inspired by / based on the following(Note we heavily took from these from actual content to formating style etc):
#   Alberto Solino (@agsolino) - GetAdUsers
#   Fowz Masood - GetADComputers
#   micahvandeusen - gMSADumper (https://github.com/micahvandeusen/gMSADumper)
#
# References:
#   MS-ADTS 2.2.18  MSDS-MANAGEDPASSWORD_BLOB
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import logging
import sys
from binascii import hexlify

from Cryptodome.Hash import MD4

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_identity
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure



# MS-ADTS MSDS-MANAGEDPASSWORD_BLOB parser
# Ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
#      section 2.2.18


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    """
    Parses the binary value of the msDS-ManagedPassword LDAP attribute. The full structure is documented below for future users reference

    Wire layout (all fields little-endian):
        USHORT  Version                         must be 1
        USHORT  Reserved
        ULONG   Length                          total size of the blob in bytes
        USHORT  CurrentPasswordOffset
        USHORT  PreviousPasswordOffset          0 if no prior password exists
        USHORT  QueryPasswordIntervalOffset
        USHORT  UnchangedPasswordIntervalOffset
        BYTE[]  <variable-length password / interval data>
    """

    structure = (
        ('Version',                         '<H'),
        ('Reserved',                        '<H'),
        ('Length',                          '<L'),
        ('CurrentPasswordOffset',           '<H'),
        ('PreviousPasswordOffset',          '<H'),
        ('QueryPasswordIntervalOffset',     '<H'),
        ('UnchangedPasswordIntervalOffset', '<H'),
        # Variable-length fields — populated in fromString()
        ('CurrentPassword',                 ':'),
        ('PreviousPassword',                ':'),
        ('QueryPasswordInterval',           ':'),
        ('UnchangedPasswordInterval',       ':'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)

        cur_off  = self['CurrentPasswordOffset']
        prev_off = self['PreviousPasswordOffset']
        qpi_off  = self['QueryPasswordIntervalOffset']
        upi_off  = self['UnchangedPasswordIntervalOffset']

        # CurrentPassword ends at PreviousPassword (if present) or QueryPasswordInterval
        cur_end = prev_off if prev_off != 0 else qpi_off
        self['CurrentPassword'] = self.rawData[cur_off:cur_end]

        if prev_off != 0:
            self['PreviousPassword'] = self.rawData[prev_off:qpi_off]
        else:
            self['PreviousPassword'] = b''

        self['QueryPasswordInterval']     = self.rawData[qpi_off:upi_off]
        self['UnchangedPasswordInterval'] = self.rawData[upi_off:]




class GetGMSAPasswords:
    """
    Enumerates gMSA objects and dumps credentials from AD.
    """

    def __init__(self, username, password, domain, cmdLineOptions):
        self.options        = cmdLineOptions
        self.__username     = username
        self.__password     = password
        self.__domain       = domain
        self.__target       = None
        self.__lmhash       = ''
        self.__nthash       = ''
        self.__aesKey       = cmdLineOptions.aesKey
        self.__doKerberos   = cmdLineOptions.k
        self.__kdcIP        = cmdLineOptions.dc_ip
        self.__kdcHost      = cmdLineOptions.dc_host
        self.__useLdaps     = cmdLineOptions.use_ldaps
        self.__enumOnly     = cmdLineOptions.enum_only
        # either a specific gMSA name (wildcards allowed) or a
        # raw LDAP filter string supplied by the operator
        self.__gmsaName     = cmdLineOptions.gmsa        #you can use 'svcWeb$' or 'svc*'
        self.__gmsaFilter   = cmdLineOptions.gmsa_filter # raw LDAP addon

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Build the LDAP base DN from the domain FQDN
        self.baseDN = ','.join('dc=%s' % part for part in self.__domain.split('.'))

        # Live connection reference — needed for secondary SID-resolution lookups
        self.__ldapConn = None

        # Tracks whether the channel is confidential (LDAPS, or NTLM session security ENCRYPT)
        # The DC will only return msDS-ManagedPassword over a confidential channel.
        self.__tlsActive = False

    
    # Static helpers that claud said would be more useful than the inline processing I previously had.
    #Apperntly it means others who find similar situations can just copy paste the static helpers and call them instead of reimplement
    #Credit goes to claud, thanks legend.

    @staticmethod
    def _attr_value(item_attributes, attr_type):
        """
        Return the first decoded UTF-8 value for *attr_type* from an
        ldapasn1 attribute list, or '' if the attribute is absent.
        """
        for attribute in item_attributes:
            if str(attribute['type']) == attr_type:
                try:
                    return attribute['vals'][0].asOctets().decode('utf-8')
                except Exception:
                    return ''
        return ''

    @staticmethod
    def _attr_raw(item_attributes, attr_type):
        """
        Return the raw bytes for a binary *attr_type*, or None if absent.
        Used for msDS-ManagedPassword and msDS-GroupMSAMembership.
        """
        for attribute in item_attributes:
            if str(attribute['type']) == attr_type:
                try:
                    return bytes(attribute['vals'][0])
                except Exception:
                    return None
        return None


    @staticmethod
    def _nt_hash(password_bytes):
        # password_bytes is already UTF-16LE encoded I believe so nothing more is needed
        md4 = MD4.new()
        md4.update(password_bytes)
        return hexlify(md4.digest()).decode('ascii')

    @staticmethod
    def _kerberos_keys(sam, domain, password_bytes):
        """
        Derive AES-128 and AES-256 kerberos long term. their format is:

            <DOMAIN_UPPER>host<sam_no_dollar_lower>.<domain_lower>
        """
        password = password_bytes.decode('utf-16-le', errors='replace').encode('utf-8')
        #Kinda concenerd this one is not right but I have seen no evidence to suggest why this shouldnt work
        salt = '{}host{}.{}'.format(
            domain.upper(),
            sam.rstrip('$').lower(),
            domain.lower(),
        )

        aes128 = string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt)
        aes256 = string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt)

        return (hexlify(aes128.contents).decode('ascii'), hexlify(aes256.contents).decode('ascii'))


    def _resolve_sid(self, sid_canonical):
        
        results = []

        def _collect(item):
            if isinstance(item, ldapasn1.SearchResultEntry):
                results.append(item)

        try:
            self.__ldapConn.search(
                self.baseDN,
                searchFilter='(objectSid={})'.format(sid_canonical),
                attributes=['sAMAccountName', 'name', 'cn'],
                perRecordCallback=_collect,
            )
            if results:
                attrs = results[0]['attributes']
                resolved = (
                    self._attr_value(attrs, 'sAMAccountName') or
                    self._attr_value(attrs, 'name') or
                    self._attr_value(attrs, 'cn')
                )
                if resolved:
                    return '{} ({})'.format(resolved, sid_canonical)
        except Exception as exc:
            logging.debug('SID resolution error for %s: %s', sid_canonical, exc)

        return sid_canonical

    def _parse_gmsa_acl(self, raw_sd):
        
        principals = []
        try:
            sd   = SR_SECURITY_DESCRIPTOR(data=raw_sd)
            aces = sd['Dacl']['Data']
        except Exception as exc:
            logging.debug('Failed to parse GroupMSAMembership SD: %s', exc)
            return principals

        for ace in aces:
            try:
                sid = ace['Ace']['Sid'].formatCanonical()
                principals.append(self._resolve_sid(sid))
            except Exception as exc:
                logging.debug('ACE parse error: %s', exc)

        return principals


    def processGMSAEntry(self, item):

        #Process a single LDAP SearchResultEntry representing a gMSA object.
    
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        try:
            attrs = item['attributes']
            sam   = self._attr_value(attrs, 'sAMAccountName')
            if not sam:
                return

            #which principals may read this account's password?
            acl_raw    = self._attr_raw(attrs, 'msDS-GroupMSAMembership')
            principals = []
            if acl_raw:
                principals = self._parse_gmsa_acl(acl_raw)

            print('\n[*] Account:    {}'.format(sam))
            if principals:
                print('    Readable by: {}'.format(', '.join(principals)))
            else:
                print('    Readable by: (no principals resolved)')

            # the target Managed password
            pw_raw = self._attr_raw(attrs, 'msDS-ManagedPassword')
            if pw_raw:
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(pw_raw)

                # Strip the trailing UTF-16LE null terminator (2 bytes)
                current_pw     = blob['CurrentPassword'][:-2]
                nt             = self._nt_hash(current_pw)
                aes128, aes256 = self._kerberos_keys(sam, self.__domain, current_pw)

                
                print('    {}::::{}'.format(sam, nt))
                print('    {}:aes256-cts-hmac-sha1-96:{}'.format(sam, aes256))
                print('    {}:aes128-cts-hmac-sha1-96:{}'.format(sam, aes128))

                # Previous password (if the DC has cycled it at least once)
                if blob['PreviousPassword']:
                    prev_pw         = blob['PreviousPassword'][:-2]
                    prev_nt         = self._nt_hash(prev_pw)
                    prev128, prev256 = self._kerberos_keys(sam, self.__domain, prev_pw)
                    print('\n    [Previous Password]')
                    print('    {}::::{}'.format(sam, prev_nt))
                    print('    {}:aes256-cts-hmac-sha1-96:{}'.format(sam, prev256))
                    print('    {}:aes128-cts-hmac-sha1-96:{}'.format(sam, prev128))
            else:
                if self.__tlsActive:
                    print('    [-] msDS-ManagedPassword not returned '
                          '(this account may not be authorised to read it)')
                else:
                    print('    [-] msDS-ManagedPassword requires a confidential channel '
                          '(use -use-ldaps, or ensure NTLM session security is active)')

        except Exception as exc:
            logging.debug('Exception in processGMSAEntry()', exc_info=True)
            logging.error('Skipping item, cannot process due to error %s', str(exc))


    def _build_GMSA_locate_filter(self):
        
        base = '(objectClass=msDS-GroupManagedServiceAccount)'

        if self.__gmsaFilter:
            
            return '(&{}{})'.format(base, self.__gmsaFilter)

        if self.__gmsaName:
            name = self.__gmsaName
            # Append the computer-account '$' suffix if the caller omitted it and the name is not a wildcard pattern
            if not name.endswith('$') and '*' not in name:
                name += '$'
            return '(&{}(sAMAccountName={}))'.format(base, name)

       
        return '(&{})'.format(base)

    def ldap_auth(self):
        
        target = self.__kdcIP or self.__kdcHost or self.__domain
        self.__target = target

        scheme  = 'ldaps' if self.__useLdaps else 'ldap'
        url     = '{}://{}'.format(scheme, target)
        basedn  = self.baseDN

        logging.debug('[*] Connecting to %s', url)
        ldapConn = ldap.LDAPConnection(url, basedn, self.__kdcIP)

        if self.__doKerberos:
            logging.debug('[*] Authenticating with Kerberos')
            ldapConn.kerberosLogin(
                self.__username, self.__password, self.__domain,
                self.__lmhash, self.__nthash, self.__aesKey,
                kdcHost=self.__kdcIP,
            )
        else:
            logging.debug('[*] Authenticating with NTLM')
            ldapConn.login(
                self.__username, self.__password, self.__domain,
                self.__lmhash, self.__nthash,
            )

        return ldapConn
    

    def run(self):
        
        try:
            self.__ldapConn = self.ldap_auth()
        except Exception as e:
            logging.error('Authentication failed: %s', e)
            sys.exit(1)

        
        self.__tlsActive = True
        if self.__useLdaps:
            logging.info('[+] Using LDAPS (port 636).')
        else:
            logging.info('[+] Using plain LDAP with NTLM Sign+Seal.')

        logging.info('Querying %s for gMSA objects.', self.__target)

    
        attrs = ['sAMAccountName', 'msDS-GroupMSAMembership']
        if not self.__enumOnly:
            attrs.append('msDS-ManagedPassword')

        search_filter = self._build_GMSA_locate_filter()
        logging.debug('Search filter: %s', search_filter)
        logging.debug('Attributes requested: %s', attrs)

        sc = ldap.SimplePagedResultsControl(size=100)
        try:
            self.__ldapConn.search(
                self.baseDN,
                searchFilter=search_filter,
                attributes=attrs,
                sizeLimit=0,
                searchControls=[sc],
                perRecordCallback=self.processGMSAEntry,
            )
        except ldap.LDAPSearchError as exc:
            if exc.error == 0:
                logging.info('No gMSA objects found in the directory.')
            else:
                raise


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description='Queries target domain for gMSA data')
    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-use-ldaps', action='store_true', default=False, help='Connect via LDAPS (port 636) instead of plain LDAP.')
    parser.add_argument('-enum', action='store_true', dest='enum_only', help='ACL enumeration only show which principals can read each gMSA password, without credential extraction')

    group = parser.add_argument_group('targeting')
    group2 = group.add_mutually_exclusive_group()
    group2.add_argument('-gmsa', action='store', metavar='account name', help='Requests data for specific gMSA account')
    group2.add_argument('-gmsa-filter', action='store', metavar='LDAP filter', help='Custom LDAP filter')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts, options.debug)

    if options.gmsa_filter is not None:
        if options.gmsa_filter.startswith('(') is False:
            logging.critical('Bad LDAP filter')
            sys.exit(1)

    domain, username, password, _, _, options.k = parse_identity(options.target, options.hashes, options.no_pass, options.aesKey, options.k)

    if domain is None or domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    try:
        executer = GetGMSAPasswords(username, password, domain, options)
        executer.run()
    except Exception:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error('Error')
