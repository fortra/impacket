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
#  	This script is an alternative to smbpasswd.py and intended to be used
#  	for changing passwords remotely over TCP (MSRPC-SAMR). This was created
#   to be able to reset machine account passwords for pre created machines where the 
# 	password is known and you get STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT when authenticating. 
#
#   Script also works for normal accounts as long as you have the permission to change the password
#   with the credentials supplied. 
# 	However, have not found a way to set a new password if existing password is blank :-(
#
# 	Examples:
#  		rpcchangepwd.py contoso.local/pc1\$:'pc1'@DC1 -newpass 'N3wPassw0rd!'
#  		rpcchangepwd.py contoso.local/pc1\$@DC1 -hashes :0D5DF42F9DA45F03752735FAABC2FD10 -newpass 'N3wPassw0rd!'
#
# Author:
# 	@Oddvarmoe
#
# References:
#   https://www.trustedsec.com/blog/
#  	https://snovvcrash.github.io/2020/10/31/pretending-to-be-smbpasswd-with-impacket.html
#  	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880
#

import sys
import logging
from getpass import getpass
from argparse import ArgumentParser

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, samr, epm



class RPCChangePWD:

	def __init__(self, domain, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, hostname):
		self.domain = domain
		self.username = username
		self.oldPassword = oldPassword
		self.newPassword = newPassword
		self.oldPwdHashLM = oldPwdHashLM
		self.oldPwdHashNT = oldPwdHashNT
		self.hostname = hostname
		self.dce = None

	def connect(self, anonymous=False):
		stringBinding = epm.hept_map(self.hostname, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_ip_tcp')
		rpctransport = transport.DCERPCTransportFactory(stringBinding)
		rpctransport.setRemoteHost(self.hostname)

		if hasattr(rpctransport, 'set_credentials'):
			# This method exists only for selected protocol sequences.
			rpctransport.set_credentials(self.username, self.oldPassword, self.domain, self.oldPwdHashLM,
                                         self.oldPwdHashNT, '')
		
		rpctransport.set_kerberos(False, None)
		self.dce = rpctransport.get_dce_rpc()
		self.dce.connect()
		self.dce.bind(samr.MSRPC_UUID_SAMR)
		
	def hSamrUnicodeChangePasswordUser2(self):
		try:
			resp = samr.hSamrUnicodeChangePasswordUser2(self.dce, '\x00', self.username, self.oldPassword, self.newPassword, self.oldPwdHashLM, self.oldPwdHashNT)
		except Exception as e:
			print(str(e))
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

	
def init_logger(options):
	logger.init(options.ts)
	if options.debug is True:
		logging.getLogger().setLevel(logging.DEBUG)
		logging.debug(version.getInstallationPath())
	else:
		logging.getLogger().setLevel(logging.INFO)


def parse_args():
	parser = ArgumentParser(description='Change password over MS-RPC.')

	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
	parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
	parser.add_argument('-debug', action='store_true', help='turn DEBUG output ON')
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-newpass', action='store', default=None, help='new SMB password')
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
		oldPassword = getpass('Current account password: ')

	if options.newpass == None:
		newPassword = getpass('New account password: ')
	else:
		newPassword = options.newpass

	rpcchangepwd = RPCChangePWD(domain, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, address)

	try:
		rpcchangepwd.connect()
	except Exception as e:
		if any(msg in str(e) for msg in ['STATUS_PASSWORD_MUST_CHANGE', 'STATUS_PASSWORD_EXPIRED']):
			if newPassword:
				logging.warning('Password is expired, trying to bind with a null session.')
				rpcchangepwd.connect(anonymous=True)
			else:
				logging.critical('Cannot set new NTLM hashes when current password is expired. Provide a plaintext value for the new password.')
				sys.exit(1)
		elif 'STATUS_LOGON_FAILURE' in str(e):
			logging.critical('Authentication failure.')
			sys.exit(1)
		else:
			raise e

	# Connected - Lets change the password
	rpcchangepwd.hSamrUnicodeChangePasswordUser2()
	