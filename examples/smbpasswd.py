#!/usr/bin/env python
#
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  This script is an alternative to smbpasswd tool for changing Windows
#  passwords over SMB (MSRPC-SAMR) remotely from Linux with a single shot to
#  SamrUnicodeChangePasswordUser2 function (Opnum 55).
#
# Author:
#  Sam Freeside (@snovvcrash)
#
# References:
#  https://github.com/samba-team/samba/blob/master/source3/utils/smbpasswd.c
#  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/acb3204a-da8b-478e-9139-1ea589edb880

from argparse import ArgumentParser

from impacket.dcerpc.v5 import transport, samr


def connect(host_name_or_ip):
	rpctransport = transport.SMBTransport(host_name_or_ip, filename=r'\samr')
	if hasattr(rpctransport, 'set_credentials'):
		rpctransport.set_credentials(username='', password='', domain='', lmhash='', nthash='', aesKey='') # null session

	dce = rpctransport.get_dce_rpc()
	dce.connect()
	dce.bind(samr.MSRPC_UUID_SAMR)

	return dce


def hSamrUnicodeChangePasswordUser2(username, oldpass, newpass, target):
	dce = connect(target)
	resp = samr.hSamrUnicodeChangePasswordUser2(dce, '\x00', username, oldpass, newpass)
	resp.dump()


parser = ArgumentParser()
parser.add_argument('username', help='username to change password for')
parser.add_argument('oldpass', help='old password')
parser.add_argument('newpass', help='new password')
parser.add_argument('target', help='hostname or IP')
args = parser.parse_args()

hSamrUnicodeChangePasswordUser2(args.username, args.oldpass, args.newpass, args.target)
