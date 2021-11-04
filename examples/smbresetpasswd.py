#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  	This script allows the password for a user to be reset remotely over 
#  	SMB (MSRPC-SAMR) by another account with appropriate privileges.  
#   It supports reseting of the password value to an NTLM hash as well as 
#   a plaintext password. If the password is changed via specifying the 
#   NTLM hash, kerberos keys for the target user will no longer be stored
#   in the account.
#
# 	Examples:
#  		smbresetpasswd.py contoso.local/administrator@DC1 -resetuser j.doe -newpass 'Passw0rd1!'
#  		smbresetpasswd.py contoso.local/administrator@DC1 -hashes :2788f309aad0b3f06fdec31587b24ea6 -resetuser j.doe -newpass 'Passw0rd1!'
#  		smbresetpasswd.py contoso.local/administrator:'AdminPass'@DC1 -resetuser j.doe -newhashes :b2bdbe60565b677dfb133866722317fd -dc-ip 192.168.1.1
#
# Author:
#  	@stephenbradshaw
#
# References:
#   https://malicious.link/post/2017/reset-ad-user-password-with-linux/
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/50d17755-c6b8-40bd-8cac-bd6cfa31adf2
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1d2be36a-754e-46b1-8697-d8aaa62bc450
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/23f9ef4c-cf3e-4330-9287-ea4799b03201
#   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/99ee9f39-43e8-4bba-ac3a-82e0c0e0699e
#   https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/cc325729(v=vs.85)
#   https://github.com/samba-team/samba/blob/e742661bd2507d39dfa47e40531dc1dca636cbbe/python/samba/tests/dcerpc/samr_change_password.py
#

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, samr
from impacket.crypto import SamEncryptNTLMHash
from Cryptodome.Cipher import ARC4
from Cryptodome.Random import get_random_bytes
from binascii import unhexlify
import argparse
import sys
import logging


class SamrResetPassword():

    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, port=445, dc_ip=None): 
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = dc_ip
        self.__port = port
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

        if self.__kdcHost is not None:
            domainController = self.__kdcHost
        elif self.__domain != '':
            domainController = self.__domain
        else:
            print('\nAn exception occurred during an attempt to connect to a domain controlled:\n\nA domain value is required!')
            sys.exit(1)

        logging.info('Creating authenticated SMB connection to domain controller {}'.format(domainController))
        try:
            self.rpctransport = transport.SMBTransport(domainController, self.__port, r'\samr', self.__username, self.__password,
                                                self.__domain, self.__lmhash, self.__nthash, self.__aesKey,
                                                doKerberos=self.__doKerberos, kdcHost = self.__kdcHost)
            
            self.dce = self.rpctransport.get_dce_rpc()
            self.dce.connect()
            logging.info('Authentication succeeded to domain controller {}!'.format(domainController))
            self.dce.bind(samr.MSRPC_UUID_SAMR)
            self.sessionKey = self.dce.get_rpc_transport().get_smb_connection().getSessionKey()
        except Exception as e:
            print('\nAn exception occurred during an attempt to create an authenticated SAMR connection:\n\n{}'.format(e))
            sys.exit(1)


    def sampr_encrypt_user_password(self, password):
        encoded_password = password.encode('utf-16-le')
        encoded_length = len(encoded_password)

        buffer  = get_random_bytes(512-encoded_length)
        buffer += encoded_password
        buffer += encoded_length.to_bytes(4, byteorder='little')

        cipher = ARC4.new(self.sessionKey)

        pwd = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
        pwd['Buffer'] = cipher.encrypt(buffer)
        return pwd


    def reset_password(self, user, newpassword=None, newhashes=None):
        if not (newpassword or newhashes):
            print('\nAn exception occurred during an attempt to reset the password:\n\nA new password value is required')
            sys.exit(1)
        
        resp = samr.hSamrConnect(self.dce)
        serverHandle = resp['ServerHandle'] 
        resp = samr.hSamrEnumerateDomainsInSamServer(self.dce, serverHandle)
        domains = resp['Buffer']['Buffer']
        domainName = domains[0]['Name']
        logging.info('Identified domain {} from domain controller.'.format(domainName))

        resp = samr.hSamrLookupDomainInSamServer(self.dce, serverHandle,  domainName)
        domainSid = resp['DomainId'].formatCanonical() 
        logging.info('SID of domain {} is {}'.format(domainName, domainSid))
        
        resp = samr.hSamrOpenDomain(self.dce, serverHandle = serverHandle, domainId = resp['DomainId'])
        domainHandle = resp['DomainHandle']

        if user.lower().startswith(domainSid.lower()):
            userRid = int(user.split('-')[-1])
            logging.info('Identified user RID {} from user SID {}'.format(userRid, user))
        else:
            resp = samr.hSamrLookupNamesInDomain(self.dce, domainHandle, [user])
            userRid = resp['RelativeIds']['Element'][0]['Data']
            logging.info('Identified user RID {} by name lookup for {}'.format(userRid, user))

        logging.info('Requesting USER_FORCE_PASSWORD_CHANGE handle for user RID {}'.format(userRid))
        request = samr.SamrOpenUser()
        request['DomainHandle'] = domainHandle
        request['DesiredAccess'] = samr.USER_FORCE_PASSWORD_CHANGE
        request['UserId'] = userRid

        try:
            resp = self.dce.request(request)
            logging.info('Obtained handle for user RID {}'.format(userRid))
        except Exception as e:
            print('\nAn exception occurred during an attempt to create a handle for user {}:\n\n{}'.format(user, e))
            sys.exit(1)

        request = samr.SamrSetInformationUser2()
        request['UserHandle'] = resp['UserHandle']

        buffer = samr.SAMPR_USER_INFO_BUFFER()

        if newhashes:
            logging.info('Performing password reset by specifying new hashes (Kerberos key credentials will no longer be available)')
            lm, nt = newhashes.split(':')
            unhashable = False 
            try:
                nthash = unhexlify(nt)
                lmhash = unhexlify(lm)
            except:
                unhashable = True 
            if (len(nt) != 32) or unhashable or not (len(lm) == 0 or len(lm) == 32):
                print('\nAn error occurred when setting new password!\n\nNew password hashes were provided in incorrect format!')
                sys.exit(1)
            request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal1Information
            buffer['tag'] = samr.USER_INFORMATION_CLASS.UserInternal1Information
            buffer['Internal1']['EncryptedNtOwfPassword'] = SamEncryptNTLMHash(nthash, self.sessionKey)
            buffer['Internal1']['EncryptedLmOwfPassword'] = SamEncryptNTLMHash(lmhash, self.sessionKey) if lm else bytes([0]) * 16
            buffer['Internal1']['NtPasswordPresent'] = 1
            buffer['Internal1']['LmPasswordPresent'] = 1 if lm else 0
            buffer['Internal1']['PasswordExpired'] = 0
        else:
            logging.info('Performing password reset by specifying new password')
            request['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
            buffer['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
            buffer['Internal5']['UserPassword'] = self.sampr_encrypt_user_password(newpassword)
            buffer['Internal5']['PasswordExpired'] = 0

        request['Buffer'] = buffer
        try:
            resp = self.dce.request(request)
        except Exception as e:
            print('\nAn unexpected error occurred when attempting to reset the password:\n\n{}'.format(e))
            sys.exit(1)
        logging.info('Password reset request peformed, response code is {}'.format(resp['ErrorCode']))
        return resp['ErrorCode']


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-port', type=int, default=445, action='store', help='Port to use for connection. Default is 445')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    resetparametersgroup = parser.add_argument_group('reset target')

    resetparametersgroup.add_argument('-resetuser', action='store', required=True, help='Name or SID of user to reset password for')
    
    xgroup = resetparametersgroup.add_mutually_exclusive_group()
    xgroup.add_argument('-newpass', action='store', default=None, help='new SMB password')
    xgroup.add_argument('-newhashes', action='store', default=None, metavar = 'LMHASH:NTHASH', help='new NTLM hashes, format is LMHASH:NTHASH ')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address", default=None, help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)


    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True


    reseter = SamrResetPassword(username=username, domain=domain, hashes=options.hashes, aesKey=options.aesKey, doKerberos=options.k, port=options.port, dc_ip=options.dc_ip)
    result = reseter.reset_password(options.resetuser, newpassword=options.newpass, newhashes=options.newhashes)

    if result == 0:
        print('Password for user {} reset successfully!'.format(options.resetuser))
    else: 
        print('Error code {} received when attempting to reset password for user {}!'.format(result, options.resetuser))
