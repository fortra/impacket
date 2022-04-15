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
#   Scan for listening MSRPC interfaces
#
#   This binds to the MGMT interface and gets a list of interface UUIDs.
#   If the MGMT interface is not available, it takes a list of interface UUIDs
#   seen in the wild and tries to bind to each interface.
#
#   If -brute-opnums is specified, the script tries to call each of the first N
#   operation numbers for each UUID in turn and reports the outcome of each call.
#
#   This can generate a burst of connections to the given endpoint!
#
# Authors:
#   Catalin Patulea <cat@vv.carleton.ca>
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#
# TODO:
#  [ ] The rpcmap.py connections are never closed. We need to close them.
#      This will require changing SMB and RPC libraries.
#

from __future__ import division
from __future__ import print_function
import re
import sys
import logging
import argparse

from impacket.http import AUTH_BASIC
from impacket.examples import logger, rpcdatabase
from impacket.examples.utils import parse_credentials
from impacket import uuid, version
from impacket.dcerpc.v5.epm import KNOWN_UUIDS
from impacket.dcerpc.v5 import transport, rpcrt, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCStringBinding, \
    SMBTransport
from impacket.dcerpc.v5 import mgmt
from impacket.dcerpc.v5.rpch import RPC_PROXY_CONN_A1_401_ERR, \
    RPC_PROXY_INVALID_RPC_PORT_ERR, RPC_PROXY_HTTP_IN_DATA_401_ERR, \
    RPC_PROXY_CONN_A1_0X6BA_ERR, RPC_PROXY_CONN_A1_404_ERR, \
    RPC_PROXY_RPC_OUT_DATA_404_ERR


class RPCMap():
    def __init__(self, stringbinding='', authLevel=6, bruteUUIDs=False, uuids=(),
        bruteOpnums=False, opnumMax=64, bruteVersions=False, versionMax=64):
        try:
            self.__stringbinding = DCERPCStringBinding(stringbinding)
        except:
            raise Exception("Provided stringbinding is not correct")

        # Empty network address is used to specify that the network address
        # must be obtained from NTLMSSP of RPC proxy.
        if self.__stringbinding.get_network_address() == '' and \
           not self.__stringbinding.is_option_set("RpcProxy"):
            raise Exception("Provided stringbinding is not correct")

        self.__authLevel      = authLevel
        self.__brute_uuids    = bruteUUIDs
        self.__uuids          = uuids
        self.__brute_opnums   = bruteOpnums
        self.__opnum_max      = opnumMax
        self.__brute_versions = bruteVersions
        self.__version_max    = versionMax

        self.__msrpc_lockout_protection = False
        self.__rpctransport   = transport.DCERPCTransportFactory(stringbinding)
        self.__dce            = self.__rpctransport.get_dce_rpc()

    def get_rpc_transport(self):
        return self.__rpctransport

    def set_transport_credentials(self, username, password, domain='', hashes=None):
        if hashes is not None:
            lmhash, nthash = hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(username, password, domain, lmhash, nthash)

    def set_rpc_credentials(self, username, password, domain='', hashes=None):
        if hashes is not None:
            lmhash, nthash = hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        if hasattr(self.__dce, 'set_credentials'):
            self.__dce.set_credentials(username, password, domain, lmhash, nthash)

        if username != '' or password != '' or hashes != '':
            self.__msrpc_lockout_protection = True

    def set_smb_info(self, smbhost=None, smbport=None):
        if isinstance(self.__rpctransport, SMBTransport):
            if smbhost:
                self.__rpctransport.setRemoteHost(smbhost)
            if smbport:
                self.__rpctransport.set_dport(smbport)

    def connect(self):
        self.__dce.set_auth_level(self.__authLevel)
        self.__dce.connect()

    def disconnect(self):
        self.__dce.disconnect()

    def do(self):
        try:
            # Connecting to MGMT interface
            self.__dce.bind(mgmt.MSRPC_UUID_MGMT)

            # Retrieving interfaces UUIDs from the MGMT interface
            ifids = mgmt.hinq_if_ids(self.__dce)

            # If -brute-uuids is set, bruteforcing UUIDs instead of parsing ifids
            # We must do it after mgmt.hinq_if_ids to prevent a specified account from being locked out
            if self.__brute_uuids:
                self.bruteforce_uuids()
                return

            uuidtups = set(
                uuid.bin_to_uuidtup(ifids['if_id_vector']['if_id'][index]['Data'].getData())
                for index in range(ifids['if_id_vector']['count'])
              )

            # Adding MGMT interface itself
            uuidtups.add(('AFA8BD80-7D8A-11C9-BEF4-08002B102989', '1.0'))

            for tup in sorted(uuidtups):
                self.handle_discovered_tup(tup)
        except DCERPCException as e:
            # nca_s_unk_if for Windows SMB
            # reason_not_specified for Samba 4
            # abstract_syntax_not_supported for Samba 3
            if str(e).find('nca_s_unk_if') >= 0 or \
               str(e).find('reason_not_specified') >= 0 or \
               str(e).find('abstract_syntax_not_supported') >= 0:
                logging.info("Target MGMT interface not available")
                logging.info("Bruteforcing UUIDs. The result may not be complete.")
                self.bruteforce_uuids()
            elif str(e).find('rpc_s_access_denied') and self.__msrpc_lockout_protection == False:
                logging.info("Target MGMT interface requires authentication, but no credentials provided.")
                logging.info("Bruteforcing UUIDs. The result may not be complete.")
                self.bruteforce_uuids()
            else:
                raise

    def bruteforce_versions(self, interface_uuid):
        results = []

        for i in range(self.__version_max + 1):
            binuuid = uuid.uuidtup_to_bin((interface_uuid, "%d.0" % i))
            # Is there a way to test multiple opnums in a single rpc channel?
            self.__dce.connect()

            try:
                self.__dce.bind(binuuid)
            except Exception as e:
                if str(e).find("abstract_syntax_not_supported") >= 0:
                    results.append("abstract_syntax_not_supported (version not supported)")
                else:
                    results.append(str(e))
            else:
                results.append("success")

        if len(results) > 1 and results[-1] == results[-2]:
            suffix = results[-1]
            while results and results[-1] == suffix:
                results.pop()

            for i, result in enumerate(results):
                print("Versions %d: %s" % (i, result))

            print("Versions %d-%d: %s" % (len(results), self.__version_max, suffix))
        else:
            for i, result in enumerate(results):
                print("Versions %d: %s" % (i, result))

    def bruteforce_opnums(self, binuuid):
        results = []

        for i in range(self.__opnum_max + 1):
            # Is there a way to test multiple opnums in a single rpc channel?
            self.__dce.connect()
            self.__dce.bind(binuuid)
            self.__dce.call(i, b"")

            try:
                self.__dce.recv()
            except Exception as e:
                if str(e).find("nca_s_op_rng_error") >= 0:
                    results.append("nca_s_op_rng_error (opnum not found)")
                else:
                    results.append(str(e))
            else:
                results.append("success")

        if len(results) > 1 and results[-1] == results[-2]:
            suffix = results[-1]
            while results and results[-1] == suffix:
                results.pop()

            for i, result in enumerate(results):
                print("Opnum %d: %s" % (i, result))

            print("Opnums %d-%d: %s" % (len(results), self.__opnum_max, suffix))
        else:
            for i, result in enumerate(results):
                print("Opnum %d: %s" % (i, result))

    def bruteforce_uuids(self):
        for tup in sorted(self.__uuids):
            # Is there a way to test multiple UUIDs in a single rpc channel?
            self.__dce.connect()
            binuuid = uuid.uuidtup_to_bin(tup)

            try:
                self.__dce.bind(binuuid)
            except rpcrt.DCERPCException as e:
                # For Windows SMB
                if str(e).find('abstract_syntax_not_supported') >= 0:
                   continue
                # For Samba
                if str(e).find('nca_s_proto_error') >= 0:
                   continue
                # For Samba
                if str(e).find('reason_not_specified') >= 0:
                   continue

            self.handle_discovered_tup(tup)

        logging.info("Tested %d UUID(s)", len(self.__uuids))

    def handle_discovered_tup(self, tup):
        if tup[0] in epm.KNOWN_PROTOCOLS:
            print("Protocol: %s" % (epm.KNOWN_PROTOCOLS[tup[0]]))
        else:
            print("Procotol: N/A")

        if uuid.uuidtup_to_bin(tup)[: 18] in KNOWN_UUIDS:
            print("Provider: %s" % (KNOWN_UUIDS[uuid.uuidtup_to_bin(tup)[:18]]))
        else:
            print("Provider: N/A")

        print("UUID: %s v%s" % (tup[0], tup[1]))

        if self.__brute_versions:
            self.bruteforce_versions(tup[0])

        if self.__brute_opnums:
            try:
                self.bruteforce_opnums(uuid.uuidtup_to_bin(tup))
            except DCERPCException as e:
                if str(e).find('abstract_syntax_not_supported') >= 0:
                    print("Listening: False")
                else:
                    raise
        print()

if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    class SmartFormatter(argparse.HelpFormatter):
        def _split_lines(self, text, width):
            if text.startswith('R|'):
                return text[2:].splitlines()  
            else:
                return argparse.HelpFormatter._split_lines(self, text, width)

    parser = argparse.ArgumentParser(add_help=True, formatter_class=SmartFormatter, description="Lookups listening MSRPC interfaces.")
    parser.add_argument('stringbinding', help='R|String binding to connect to MSRPC interface, for example:\n'
                                              'ncacn_ip_tcp:192.168.0.1[135]\n'
                                              'ncacn_np:192.168.0.1[\\pipe\\spoolss]\n'
                                              'ncacn_http:192.168.0.1[593]\n'
                                              'ncacn_http:[6001,RpcProxy=exchange.contoso.com:443]\n'
                                              'ncacn_http:localhost[3388,RpcProxy=rds.contoso:443]'
                                               )
    parser.add_argument('-brute-uuids', action='store_true', help='Bruteforce UUIDs even if MGMT interface is available')
    parser.add_argument('-brute-opnums', action='store_true', help='Bruteforce opnums for found UUIDs')
    parser.add_argument('-brute-versions', action='store_true', help='Bruteforce major versions of found UUIDs')
    parser.add_argument('-opnum-max', action='store', type=int, default=64, help='Bruteforce opnums from 0 to N, default 64')
    parser.add_argument('-version-max', action='store', type=int, default=64, help='Bruteforce versions from 0 to N, default 64')
    parser.add_argument('-auth-level', action='store', type=int, default=6, help='MS-RPCE auth level, from 1 to 6, default 6 '
                                                                                 '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)')
    parser.add_argument('-uuid', action='store', help='Test only this UUID')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('ncacn-np-details')

    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. '
                       'If omitted it will use whatever was specified as target. This is useful when target is the '
                       'NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')
    group.add_argument('-auth-rpc', action='store', default='', help='[domain/]username[:password]')
    group.add_argument('-auth-transport', action='store', default='', help='[domain/]username[:password]')
    group.add_argument('-hashes-rpc', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-hashes-transport', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for passwords')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    rpcdomain, rpcuser, rpcpass = parse_credentials(options.auth_rpc)
    transportdomain, transportuser, transportpass = parse_credentials(options.auth_transport)

    if options.brute_opnums and options.brute_versions:
       logging.error("Specify only -brute-opnums or -brute-versions")
       sys.exit(1)

    if rpcdomain is None:
        rpcdomain = ''

    if transportdomain is None:
        transportdomain = ''

    if rpcpass == '' and rpcuser != '' and options.hashes_rpc is None and options.no_pass is False:
         from getpass import getpass
         rpcpass = getpass("Password for MSRPC communication:")

    if transportpass == '' and transportuser != '' and options.hashes_transport is None and options.no_pass is False:
        from getpass import getpass
        transportpass = getpass("Password for RPC transport (SMB or HTTP):")

    if options.uuid is not None:
        uuids = [uuid.string_to_uuidtup(options.uuid)]
        options.brute_uuids = True
    else:
        uuids = rpcdatabase.uuid_database

    try:
        lookuper = RPCMap(options.stringbinding, options.auth_level, options.brute_uuids, uuids,
                          options.brute_opnums, options.opnum_max, options.brute_versions, options.version_max)
        lookuper.set_rpc_credentials(rpcuser, rpcpass, rpcdomain, options.hashes_rpc)
        lookuper.set_transport_credentials(transportuser, transportpass, transportdomain, options.hashes_transport)
        lookuper.set_smb_info(options.target_ip, options.port)
        lookuper.connect()
        lookuper.do()
        lookuper.disconnect()
    except Exception as e:
        #raise

        # This may contain UTF-8
        error_text = 'Protocol failed: %s' % e
        logging.critical(error_text)

        # Exchange errors
        if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text:
            logging.critical("This usually means the target is a MS Exchange Server, "
                             "and connections to this rpc port on this host are not allowed (try port 6001)")

        if RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or \
           RPC_PROXY_CONN_A1_404_ERR in error_text:
            logging.critical("This usually means the target is a MS Exchange Server, "
                             "and connections to the specified RPC server are not allowed")

        # Other errors
        if RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
            logging.critical("This usually means the target has no ACL to connect to this endpoint using RpcProxy")

        if RPC_PROXY_HTTP_IN_DATA_401_ERR in error_text or RPC_PROXY_CONN_A1_401_ERR in error_text:
           if lookuper.get_rpc_transport().get_auth_type() == AUTH_BASIC and transportdomain == '':
                logging.critical("RPC proxy basic authentication might require you to specify the domain. "
                                 "Your domain is empty!")

        if RPC_PROXY_CONN_A1_401_ERR in error_text or \
           RPC_PROXY_CONN_A1_404_ERR in error_text:
            logging.info("A proxy in front of the target server detected (may be WAF / SIEM)")

        if 'rpc_s_access_denied' in error_text:
             logging.critical("This usually means the credentials on the MSRPC level are invalid!")
