#!/usr/bin/env python
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
#   Simple Temporary SMB Server example.
#   This example showcases the use of SimpleTempSMBServer as well as PromiscuousSMBServer. It is meant to be a comfortable
#   but versatile delivery platform over SMB without taking many shortcuts ie doing the proper protocol dances.
#   This way any user will have a proper authenticated SMB session instead of having to rely on guest connections or
#   juggling credentials.
#   This aims to be mostly compatible with the smbserver example
#   Examples:
#       impacket-tempsmbserver -file "/tmp/potato.exe=legit.exe" -file "/tmp/stage.ps1=legitimate.ps1" -await-file samdump LEGIT
#       - starts the temporary share "LEGIT"
#       - copies /tmp/potato.exe into the temporary share and shares it as "legit.exe"
#       - copies /tmp/stage.ps1 into the temporary share and shares it as "legitimate.ps1"
#       - waits for a file "samdump" to be written into the share and then exits
#       - lets ANY username with ANY password authenticate and opens a authenticated session (not a guest  or anonymous session)
#
#       impacket-tempsmbserver -username admin -password doesntmatter -auth-name -file "/tmp/potato.exe=legit.exe" -file "/tmp/stage.ps1=legitimate.ps1" -await-file samdump LEGIT
#       - does the same as above but only allows the user "admin" to authenticate with ANY password
#
#       impacket-tempsmbserver -username admin -password Sup3S3cret -auth-classic -file "/tmp/potato.exe=legit.exe" -file "/tmp/stage.ps1=legitimate.ps1" -await-file samdump LEGIT
#       - does the same as above but only allows the user "admin" to authenticate with "Sup3S3cret"
#
#       impacket-tempsmbserver -file "/tmp/potato.exe=legit.exe" -file "/tmp/stage.ps1=legitimate.ps1" LEGIT
#       - starts the temporary share "LEGIT"
#       - copies /tmp/potato.exe into the temporary share and shares it as "legit.exe"
#       - copies /tmp/stage.ps1 into the temporary share and shares it as "legitimate.ps1"
#       - lets ANY username with ANY password authenticate and opens a authenticated session (not a guest  or anonymous session)
#       - runs indefinitely until it receives KeyboardInterrupt
#
#
# Author:
#   dotpy
#
import shutil
import sys
import argparse
import logging
import tempfile
import time

from impacket.examples import logger
from impacket import smbserver, version
from impacket.ntlm import compute_lmhash, compute_nthash

if __name__ == '__main__':

    # Init the example's logger theme
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Run a temporary SMB server which cleans up after itself. There are different authentication modes which are described below.\nExample: impacket-tempsmbserver LEGIT")

    parser.add_argument('shareName', action='store', help='name of the share to add')
    parser.add_argument('-comment', action='store', help='share\'s comment to display when asked for shares')
    parser.add_argument('-file', action='append', help='file paths AND names (as they should appear in the share) that should be served by the server. Use the argument multiple times for multiple files! Example: "/tmp/reverse_shell.exe=legit.exe"')
    parser.add_argument('-await-file', action='append', help='wait for certain files to be written to the server and then stop. Use the argument multiple times for multiple files! This waits for ALL files to be written!')
    parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')

    parser.add_argument('-ip', '--interface-address', action='store', default=argparse.SUPPRESS, help='ip address of listening interface ("0.0.0.0" or "::" if omitted)')
    parser.add_argument('-port', action='store', default='445', help='TCP port for listening incoming connections (default 445)')
    parser.add_argument('-dropssp', action='store_true', default=False, help='Disable NTLM ESS/SSP during negotiation')
    parser.add_argument('-6','--ipv6', action='store_true',help='Listen on IPv6')

    parser.add_argument("-auth-any", action="store_true", default=True, help="allows ANY user with ANY password to successfully authenticate - this is the default behaviour")
    parser.add_argument("-auth-name", action="store_true", default=False, help="allows SPECIFIED user with ANY password to successfully authenticate")
    parser.add_argument("-auth-classic", action="store_true", default=False, help="allows SPECIFIED user with SPECIFIED password to successfully authenticate (normal authentication)")

    parser.add_argument('-username', action="store", help='Username to authenticate clients')
    parser.add_argument('-password', action="store", help='Password for the Username')
    parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes for the Username, format is LMHASH:NTHASH')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-outputfile', action='store', default=None, help='Output file to log smbserver output messages')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.critical(str(e))
       sys.exit(1)

    logger.init(ts=options.ts, debug=options.debug)

    if options.comment is None:
        comment = ''
    else:
        comment = options.comment

    if 'interface_address' not in options:
        options.interface_address = '::' if options.ipv6 else '0.0.0.0'

    with smbserver.SimpleTempSMBServer(listenAddress=options.interface_address, listenPort=int(options.port), ipv6=options.ipv6, smbserverclass=smbserver.PromiscuousSMBServer) as server:
        if options.outputfile:
            logging.info('Switching output to file %s' % options.outputfile)
            server.setLogFile(options.outputfile)

        server.addShare(options.shareName.upper(), comment)
        server.setSMB2Support(options.smb2support)
        server.setDropSSP(options.dropssp)

        # If a user was specified, let's add it to the credentials for the SMBServer.
        if options.username is not None:
            # we either need a password or hashes, if not, ask
            if options.password is None and options.hashes is None:
                from getpass import getpass
                password = getpass("Password:")
                # Let's convert to hashes
                lmhash = compute_lmhash(password)
                nthash = compute_nthash(password)
            elif options.password is not None:
                lmhash = compute_lmhash(options.password)
                nthash = compute_nthash(options.password)
            else:
                lmhash, nthash = options.hashes.split(':')

            server.addCredential(options.username, 0, lmhash, nthash)

        if options.auth_classic:
            server.getServer().classic_auth()
        elif options.auth_name:
            server.getServer().allow_by_name()
        elif options.auth_any:
            server.getServer().allow_any()
        else:
            # this should never happen
            server.getServer().allow_any()

        for file in options.file:
            path, name = file.split("=")
            server.add_file(options.shareName.upper(), name, path)

        try:
            if options.await_file:
                print(f"Waiting for {len(options.await_file)} files!")
                for filename in options.await_file:
                    print(f"Waiting for {filename}")
                    awaited_file = server.await_file(options.shareName.upper(), filename, None)
                    if awaited_file:
                        copied_file = shutil.copy(awaited_file, tempfile.gettempdir())
                        print(f"{awaited_file} has been written and copied to {copied_file}")

            else:
                # its a trap!
                while True:
                    time.sleep(0.25)
        except KeyboardInterrupt:
            print("\nInterrupted, exiting...")
            sys.exit(0)
