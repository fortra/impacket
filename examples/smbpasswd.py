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
#  	This script is an alternative to smbpasswd tool and intended to be used
#  	for changing passwords remotely over SMB (MSRPC-SAMR). It can perform the
#  	password change when the current password is expired, and supports NTLM
#  	hashes as a new password value instead of a plaintext value. As for the
#  	latter approach the new password is flagged as expired after the change
#  	due to how SamrChangePasswordUser function works.
#
# 	Examples:
#  		smbpasswd.py j.doe@192.168.1.11
#  		smbpasswd.py contoso.local/j.doe@DC1 -hashes :fc525c9683e8fe067095ba2ddc971889
#  		smbpasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#  		smbpasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb
#
# Author:
# 	@snovvcrash
#  	@bransh
#
# References:
#  	https://snovvcrash.github.io/2020/10/31/pretending-to-be-smbpasswd-with-impacket.html
#  	https://github.com/samba-team/samba/blob/master/source3/utils/smbpasswd.c
#  	https://github.com/SecureAuthCorp/impacket/pull/381
#  	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880
#  	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476
#

import sys
import logging
from getpass import getpass
from argparse import ArgumentParser

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, samr


class SMBPasswd:

	def __init__(self, domain, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT, hostname):
		self.domain = domain
		self.username = username
		self.oldPassword = oldPassword
		self.newPassword = newPassword
		self.oldPwdHashLM = oldPwdHashLM
		self.oldPwdHashNT = oldPwdHashNT
		self.newPwdHashLM = newPwdHashLM
		self.newPwdHashNT = newPwdHashNT
		self.hostname = hostname
		self.dce = None

	def connect(self, anonymous=False):
		rpctransport = transport.SMBTransport(self.hostname, filename=r'\samr')
		if anonymous:
			rpctransport.set_credentials(username='', password='', domain='', lmhash='', nthash='', aesKey='')
		else:
			rpctransport.set_credentials(self.username, self.oldPassword, self.domain, self.oldPwdHashLM, self.oldPwdHashNT, aesKey='')

		self.dce = rpctransport.get_dce_rpc()
		self.dce.connect()
		self.dce.bind(samr.MSRPC_UUID_SAMR)

	def hSamrUnicodeChangePasswordUser2(self):
		try:
			resp = samr.hSamrUnicodeChangePasswordUser2(self.dce, '\x00', self.username, self.oldPassword, self.newPassword, self.oldPwdHashLM, self.oldPwdHashNT)
		except Exception as e:
			if 'STATUS_PASSWORD_RESTRICTION' in str(e):
				logging.critical('Some password update rule has been violated. For example, the password may not meet length criteria.')
			else:
				raise e
		else:
			if resp['ErrorCode'] == 0:
				logging.info('Password was changed successfully.')
			else:
				logging.error('Non-zero return code, something weird happened.')
				resp.dump()

	def hSamrChangePasswordUser(self):
		serverHandle = samr.hSamrConnect(self.dce, self.hostname + '\x00')['ServerHandle']
		domainSID = samr.hSamrLookupDomainInSamServer(self.dce, serverHandle, self.domain)['DomainId']
		domainHandle = samr.hSamrOpenDomain(self.dce, serverHandle, domainId=domainSID)['DomainHandle']   
		userRID = samr.hSamrLookupNamesInDomain(self.dce, domainHandle, (self.username,))['RelativeIds']['Element'][0]
		userHandle = samr.hSamrOpenUser(self.dce, domainHandle, userId=userRID)['UserHandle']

		try:
			resp = samr.hSamrChangePasswordUser(self.dce, userHandle, self.oldPassword, newPassword='', oldPwdHashNT=self.oldPwdHashNT,
                                                newPwdHashLM=self.newPwdHashLM, newPwdHashNT=self.newPwdHashNT)
		except Exception as e:
			if 'STATUS_PASSWORD_RESTRICTION' in str(e):
				logging.critical('Some password update rule has been violated. For example, the password history policy may prohibit the use of recent passwords.')
			else:
				raise e
		else:
			if resp['ErrorCode'] == 0:
				logging.info('NTLM hashes were changed successfully.')
			else:
				logging.error('Non-zero return code, something weird happened.')
				resp.dump()


def init_logger(options):
	logger.init(options.ts)
	if options.debug is True:
		logging.getLogger().setLevel(logging.DEBUG)
		logging.debug(version.getInstallationPath())
	else:
		logging.getLogger().setLevel(logging.INFO)


def parse_args():
	parser = ArgumentParser(description='Change password over SMB.')

	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
	parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
	parser.add_argument('-debug', action='store_true', help='turn DEBUG output ON')
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-newpass', action='store', default=None, help='new SMB password')
	group.add_argument('-newhashes', action='store', default=None, metavar='LMHASH:NTHASH', help='new NTLM hashes, format is LMHASH:NTHASH '
                                                                           '(the user will be asked to change their password at next logon)')
	group = parser.add_argument_group('authentication')
	group.add_argument('-hashes', action='store', default=None, metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')

	return parser.parse_args()


if __name__ == '__main__':
	print(version.BANNER)

	options = parse_args()
	init_logger(options)

	domain, username, oldPassword, address = parse_target(options.target)

	if domain is None:
		domain = 'Builtin'

	if options.hashes is not None:
		try:
			oldPwdHashLM, oldPwdHashNT = options.hashes.split(':')
		except ValueError:
			logging.critical('Wrong hashes string format. For more information run with --help option.')
			sys.exit(1)
	else:
		oldPwdHashLM = ''
		oldPwdHashNT = ''

	if oldPassword == '' and oldPwdHashNT == '':
		oldPassword = getpass('Current SMB password: ')

	if options.newhashes is not None:
		try:
			newPwdHashLM, newPwdHashNT = options.newhashes.split(':')
		except ValueError:
			logging.critical('Wrong new hashes string format. For more information run with --help option.')
			sys.exit(1)
		newPassword = ''
	else:
		newPwdHashLM = ''
		newPwdHashNT = ''
		if options.newpass is None:
			newPassword = getpass('New SMB password: ')
			if newPassword != getpass('Retype new SMB password: '):
				logging.critical('Passwords do not match, try again.')
				sys.exit(1)
		else:
			newPassword = options.newpass

	smbpasswd = SMBPasswd(domain, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT, address)

	try:
		smbpasswd.connect()
	except Exception as e:
		if any(msg in str(e) for msg in ['STATUS_PASSWORD_MUST_CHANGE', 'STATUS_PASSWORD_EXPIRED']):
			if newPassword:
				logging.warning('Password is expired, trying to bind with a null session.')
				smbpasswd.connect(anonymous=True)
			else:
				logging.critical('Cannot set new NTLM hashes when current password is expired. Provide a plaintext value for the new password.')
				sys.exit(1)
		elif 'STATUS_LOGON_FAILURE' in str(e):
			logging.critical('Authentication failure.')
			sys.exit(1)
		else:
			raise e

	if newPassword:
		# If using a plaintext value for the new password
		smbpasswd.hSamrUnicodeChangePasswordUser2()
	else:
		# If using NTLM hashes for the new password
		smbpasswd.hSamrChangePasswordUser()
