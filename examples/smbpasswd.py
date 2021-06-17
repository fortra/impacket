#!/usr/bin/env python
#
# SECUREAUTH LABS. Copyright 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  This script is an alternative to smbpasswd tool and intended to be used
#  for changing expired passwords remotely over SMB (MSRPC-SAMR).
#
# Author:
#  Sam Freeside (@snovvcrash)
#
# Examples:
#  smbpasswd.py j.doe@PC01.megacorp.local
#  smbpasswd.py j.doe:'Passw0rd!'@10.10.13.37 -newpass 'N3wPassw0rd!'
#  smbpasswd.py -hashes :fc525c9683e8fe067095ba2ddc971889 j.doe@10.10.13.37 -newpass 'N3wPassw0rd!'
#
# References:
#  https://snovvcrash.github.io/2020/10/31/pretending-to-be-smbpasswd-with-impacket.html
#  https://github.com/samba-team/samba/blob/master/source3/utils/smbpasswd.c
#  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880

import sys
from getpass import getpass
from argparse import ArgumentParser

from impacket.dcerpc.v5 import transport, samr
from impacket import version


class SMBPasswd:

	def __init__(self, userName, oldPwd, newPwd, oldPwdHashLM, oldPwdHashNT, target):
		self.userName = userName
		self.oldPwd = oldPwd
		self.newPwd = newPwd
		self.oldPwdHashLM = oldPwdHashLM
		self.oldPwdHashNT = oldPwdHashNT
		self.target = target
		self.dce = None

		try:
			self.connect()
		except Exception as e:
			if 'STATUS_ACCESS_DENIED' in str(e):
				print('[-] Access was denied when attempting to initialize a null session. Try changing the password with smbclient.py.')
			else:
				raise e

	def connect(self):
		rpctransport = transport.SMBTransport(self.target, filename=r'\samr')
		if hasattr(rpctransport, 'set_credentials'):
			# Initializing a null session to be able to change an expired password
			rpctransport.set_credentials(username='', password='', domain='', lmhash='', nthash='', aesKey='')

		self.dce = rpctransport.get_dce_rpc()
		self.dce.connect()
		self.dce.bind(samr.MSRPC_UUID_SAMR)

	def hSamrUnicodeChangePasswordUser2(self):
		try:
			resp = samr.hSamrUnicodeChangePasswordUser2(self.dce, '\x00', self.userName, self.oldPwd, self.newPwd, self.oldPwdHashLM, self.oldPwdHashNT)
		except Exception as e:
			if 'STATUS_WRONG_PASSWORD' in str(e):
				print('[-] Current SMB password is not correct.')
			elif 'STATUS_PASSWORD_RESTRICTION' in str(e):
				print('[-] Some password update rule has been violated. For example, the password may not meet length criteria.')
			else:
				raise e
		else:
			if resp['ErrorCode'] == 0:
				print('[+] Password was changed successfully.')
			else:
				print('[?] Non-zero return code, something weird happened.')
				resp.dump()


def normalize_args(args):
	try:
		credentials, target = args.target.rsplit('@', 1)
	except ValueError:
		print('Wrong target string format. For more information run with --help option.')
		sys.exit(1)

	if args.hashes is not None:
		try:
			oldPwdHashLM, oldPwdHashNT = args.hashes.split(':')
		except ValueError:
			print('Wrong hashes string format. For more information run with --help option.')
			sys.exit(1)
	else:
		oldPwdHashLM = ''
		oldPwdHashNT = ''

	try:
		userName, oldPwd = credentials.split(':', 1)
	except ValueError:
		userName = credentials
		if oldPwdHashNT == '':
			oldPwd = getpass('Current SMB password: ')
		else:
			oldPwd = ''

	if args.newpass is None:
		newPwd = getpass('New SMB password: ')
		if newPwd != getpass('Retype new SMB password: '):
			print('Password does not match, try again.')
			sys.exit(1)
	else:
		newPwd = args.newpass

	return (userName, oldPwd, newPwd, oldPwdHashLM, oldPwdHashNT, target)


if __name__ == '__main__':
	print (version.BANNER)

	parser = ArgumentParser(description='Change password over SMB.')
	parser.add_argument('target', action='store', help='<username[:password]>@<target_hostname_or_IP_address>')
	parser.add_argument('-newpass', action='store', default=None, help='new SMB password')
	group = parser.add_argument_group('authentication')
	group.add_argument('-hashes', action='store', default=None, metavar='LMHASH:NTHASH', help='current NTLM hashes, format is LMHASH:NTHASH')
	args = parser.parse_args()

	userName, oldPwd, newPwd, oldPwdHashLM, oldPwdHashNT, target = normalize_args(args)

	smbpasswd = SMBPasswd(userName, oldPwd, newPwd, oldPwdHashLM, oldPwdHashNT, target)
	smbpasswd.hSamrUnicodeChangePasswordUser2()
