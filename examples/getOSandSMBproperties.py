#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: This script will connect against a target (or list of targets) machine/s and export in CSV:
#              - The OS version
#              - The SMB properties :
#                   * SMBv1 support
#                   * Enabled shares
#                   * Trafic signature
#
# Author:
#  Thomas Debize (github.com/maaaaz)
#
#
# Reference for:
#  SMB DCE/RPC

from __future__ import print_function

import sys
import os
import logging
import argparse
import unicodecsv as csv
import socket
import struct
import itertools
import time
import pprint
import functools
from concurrent import futures

from impacket.examples import logger
from impacket import version
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT

def dottedquad_to_num(ip):
    """
        Convert decimal dotted quad string IP to long integer
    """
    return struct.unpack('!L',socket.inet_aton(ip))[0]

def num_to_dottedquad(n):
    """
        Convert long int IP to dotted quad string
    """
    return socket.inet_ntoa(struct.pack('!L',n))

def is_format_valid(fmt):
    """
        Check for the supplied custom output format
        @param fmt : the supplied format
        
        @rtype : True or False
    """ 
    supported_format_objects = [ 'server_ip', 'server_domain', 'server_name', 'os_version', 'smbv1_supported', 'signing_required', 'share_name', 'share_remark' ]
    unknown_items = []
    
    for fmt_object in fmt.split('-'):
        if not(fmt_object in supported_format_objects):
            unknown_items.append(fmt_object)
    
    if unknown_items:
        return False, unknown_items
    else:
        return True, None

def try_smb_connection(address, target_ip, options, preferredDialect, existingConnection):
        try:
            conn = SMBConnection(remoteName=address, remoteHost=target_ip, myName=None, sess_port=options.port, timeout=options.timeout, preferredDialect=preferredDialect, existingConnection=existingConnection)
            return True, conn
        
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            print("[!] {}: {}".format(address, str(e)))
            return False, None
        
def try_authenticate(target, options, lmhash, nthash, connection):
    try:
        if options.k is True:
            connection.kerberosLogin(options.username, options.password, options.domain, lmhash, nthash, options.aesKey, options.dc_ip)
            return True
        elif options.username and options.password:
            connection.login(options.username, options.password, options.domain, lmhash, nthash)
            return True
        else:
            return False
        
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print("[!] {}: {}".format(target, str(e)))
        return False

def enum_shares(connection):
    """
        Just enumerating name, no read or write access tried (so far, it might change in a near future)
    """
    result = []
    shares = connection.listShares()
    
    for share in shares:
        current_share = {}
        current_share['share_name'] = share['shi1_netname'][:-1].strip()
        current_share['share_remark'] = share['shi1_remark'][:-1].strip()
        
        result.append(current_share)
    
    return result

def grab_properties(target, target_ip, options, lmhash, nthash, connection, current_result):
    current_result['server_ip'] = target_ip if target_ip is not None else target
    
    authenticate_success = try_authenticate(target, options, lmhash, nthash, connection)
    if authenticate_success:
        current_result['server_domain'] = connection.getServerDomain()
        current_result['server_name'] = connection.getServerName()
        current_result['os_version'] = connection.getServerOS()
        current_result['signing_required'] = 'true' if connection.isSigningRequired() else 'false'
        current_result['shares'] = enum_shares(connection)
        
        connection.close()
    
    return current_result

def enum_target(options, target, lmhash, nthash):
    target = target.strip()
    try:
        target_ip = socket.gethostbyname(target)
    except:
        target_ip = None
    
    print("[+] Enumerating %s in SMBv1" % target)
    
    current_result = {}
    
    # Try SMBv1 unauthenticated
    support_smbv1, connection = try_smb_connection(target, target_ip, options, SMB_DIALECT, None)
    if support_smbv1:
        current_result['smbv1_supported'] = 'true'
        current_result = grab_properties(target, target_ip, options, lmhash, nthash, connection, current_result)
    
    else:
        print("[+] Enumerating %s in SMBv2/v3" % target)
        logging.debug('[!] {}: SMBv1 might be disabled'.format(target.strip()))
        current_result['smbv1_supported'] = 'false'
    
        # Try SMB2/3 unauthenticated
        connection_success, connection = try_smb_connection(target, target, options, None, None)
        
        if connection_success:
            current_result = grab_properties(target, target_ip, options, lmhash, nthash, connection, current_result)
        
    return target_ip, target, current_result

def extract_information(options, lmhash, nthash, targets):
    results = {}
    
    with futures.ThreadPoolExecutor(max_workers=options.workers) as executor:
        futs = [
            (target, executor.submit(functools.partial(enum_target, options, target, lmhash, nthash)))
            for target in targets
        ]
        
        for target, fut in futs:
            target_ip, target_name, current_result = fut.result()
            if current_result:
                current_host_num_ip = dottedquad_to_num(target_ip) if target_ip else target_name
                if current_host_num_ip not in results:
                    results[current_host_num_ip] = current_result
            
    return results

def formatted_item(elem, format_item):
    """
        return the attribute value related to the host
        
        @param elem : elem object
        @param format_item : the attribute supplied in the custom format
        
        @rtype : the <list> attribute value
    """
    if format_item in elem.keys():
        if format_item != ('share_name' or 'share_remark'):
            return [elem[format_item]]
        
    elif format_item == 'share_name' and 'shares' in elem.keys():
        return list(i['share_name'] for i in elem['shares'])
    
    elif format_item == 'share_remark' and 'shares' in elem.keys():
        return list(i['share_remark'] for i in elem['shares'])
    
    else:
        return ''

def repeat_attributes(attribute_list):
    """
        repeat attribute lists to the maximum for the 
        
        @param attribute_list : raw list with different attribute list length
        
        @rtype : a list consisting of length equal attribute list
    """
    max_number = len(max(attribute_list, key=len))
    attribute_list = map(lambda x: x * max_number, attribute_list)
    
    return attribute_list

def generate_results(results, options):
    if results:
        with open(options.output, 'w') as fout:
            splitted_options_format = options.format.split('-')
            spamwriter = csv.writer(fout, delimiter=options.delimiter, quoting=csv.QUOTE_ALL, lineterminator='\n')
            
            if not options.skip_header:
                csv_header = [format_item.upper() for format_item in splitted_options_format]
                spamwriter.writerow(csv_header)
            
            for IP in sorted(results.iterkeys()):
                formatted_attribute_list = []
                
                for index,format_item in enumerate(splitted_options_format):
                    item = formatted_item(results[IP], format_item)
                    formatted_attribute_list.insert(index, item)
                
                formatted_attribute_list = repeat_attributes(formatted_attribute_list)
                
                for line_to_write in itertools.izip(*formatted_attribute_list):
                    spamwriter.writerow(list(line_to_write))
                
                if not options.no_newline:
                    spamwriter.writerow('')
        
    return None

def main():
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "Gets the target system OS version and SMB properties (smbv1 support, shares, signing)")

    group_input = parser.add_argument_group('input parameters')
    group_input.add_argument('-t', '--target', help='IP or FQDN', type=str, default='')
    group_input.add_argument('-d', '--domain', help="Domain (default '')", type=str, default='')
    group_input.add_argument('-u', '--username', help="Username (default 'anonymous')", type=str, default='anonymous')
    group_input.add_argument('-p', '--password', help="Password (default 'anonymous')", type=str, default='anonymous')
    group_input.add_argument('-i','--input', type=argparse.FileType('rb'), help='Input file with targets')
    group_input.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group_output = parser.add_argument_group('output format')
    group_output.add_argument('-o', '--output', help='CSV output filename (default "./output_<timestamp>.csv")', type=str, default=os.path.join(os.getcwdu(),"output_{}.csv".format(str(int(time.time())))))
    group_output.add_argument('-f', '--format', help='CSV column format { server_ip, server_domain, server_name, os_version, smbv1_supported, signing_required, share_name, share_remark } (default: server_ip-server_domain-server_name-os_version-smbv1_supported-signing_required-share_name-share_remark)', default='server_ip-server_domain-server_name-os_version-smbv1_supported-signing_required-share_name-share_remark', type=str)
    group_output.add_argument('-s', '--skip-header', help='Do not print the CSV header', action='store_true', default=False)
    group_output.add_argument('-n', '--no-newline', help='Do not insert a newline between each host. By default, a newline is added for better readability', action='store_true', default=False)
    group_output.add_argument('-l', '--delimiter', help='CSV output delimiter (default ";"). Ex: -d ","', default=';', type=str)
    
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
    group.add_argument('-port', choices=[139, 445], type=int, default=445, metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-timeout', type=int, default=10, help='Timeout in seconds (default 10)')
    group.add_argument('-w', '--workers', type=int, default=10, help='Number of workers (default 10)')

    options = parser.parse_args()
    
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    logging.debug("Options %s" % options)
    
    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''
    
    valid_format, unknown_items = is_format_valid(options.format)
    if not valid_format:
        parser.error("Please specify a valid output format: '%s' is invalid \n\
         Supported objects are { server_ip, server_domain, server_name, os_version, smbv1_supported, signing_required, share_name, share_remark }" % ', '.join(unknown_items))
    
    if (options.input is not None and options.target) or (options.input is None and not(options.target)):
        parser.error("Please specify either a single target or either a file")
    
    elif (options.input is not None) and (options.target == ''):
        targets = options.input
    
    elif (options.input is None) and options.target:
        targets = [options.target]
    
    results = extract_information(options, lmhash, nthash, targets)
    logging.debug("Raw results:\n{}\n".format(pprint.pformat(results)))
    
    generate_results(results, options)
    
    return
    
if __name__ == "__main__":
    main()