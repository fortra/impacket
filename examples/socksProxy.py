#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Transforms a remote host for which you have administrative
#              credentials into a network pivot, without installing software
#              or executing non-Windows code on it. Sets up port forwardings
#              on the pivot as they are needed, and exposes this functionality
#              as a local SOCKS server.
#
#              Using a host as pivot allows reaching all its directly attached
#              subnets (which you might not be able to reach directly), and
#              impersonate it, to reach all services its IP is allowed to reach.
#              In particular, you can impersonate the pivot on itself, to make
#              your connections appear as coming from 127.0.0.1, which has the
#              added bonus of bypassing any local firewalling
#              (e.g. proxychains xfreerdp /v:127.0.0.1 even if TCP 3389 is
#              explicitely blocked)
#
#              Warning: if the target's port is filtered (doesn't send TCP
#              reset packets), it will still be reported as opened by the
#              SOCKS server (e.g. proxychains will report "<><>- OK") because
#              the pivot will still maintain the first half of the TCP
#              connection and try the second half indefinitely.
#              So, scanning using "proxychains nmap -sT" will report closed
#              ports as closed, and filtered or open ports as open.
#
#              This server should support SOCKSv4, SOCKSv4a and SOCKSv5
#              with IPv4, IPv6, and raw hostname addressing.
#
#  .____Attacker_____________________________________________________________.
#  |                                                                         |
#  |  $> proxychains xfreerdp Administrator@10.0.0.2                         |
#  |                     ^                                                   |
#  |                     | (1) SOCKS connection                              |
#  |                     v                                                   |
#  |            +--------------+                                             |
#  |            |127.0.0.1:1080|                                             |
#  |  $> examples/socksProxy.py Administrator@10.0.0.1                       |
#  |                    ^     |                                              |
#  | (4) Connection to  |     | (2) wmiexec netstat -> 58937 is free!        |
#  |     forwarded port |     | (3) netsh portproxy add 58937=>10.0.0.2:3389 |
#  .____________________|_____|______________________________________________.
#                       v     v
#  .__Pivot__10.0.0.1:58937___10.0.0.1:445,dynamic port______________________.
#  |                    |                                                    |
#  .____________________|____________________________________________________.
#                       `-------------------.
#                                           v
#  .__Target_____________________10.0.0.2:3389_______________________________.
#  | (5) sees an incoming RDP connection from 10.0.0.1, not the attacker     |
#  ._________________________________________________________________________.
#
# Author:
#  Matthieu Buffet (@mtth_bfft)
#
# References:
# https://www.openssh.com/txt/socks4.protocol SOCKS v4
# https://tools.ietf.org/html/rfc1928 SOCKS v5 RFC

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import ipaddress
import logging
import random
import re
import select
import socket
import string
import struct
import sys
import threading
import time

from impacket import version
from impacket.examples import logger
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import scmr, transport
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab

try:
    input = raw_input
except NameError:
    pass


class SocksServer:
    def __init__(self, remote_name, local_ip, local_port, target_ip, exec_method,
                 username='', password='', domain='', aes_key=None, do_kerberos=False,
                 dc_ip=None, hashes=None):
        self.__remote_name = remote_name
        self.__local_ip = local_ip
        self.__local_port = local_port
        self.__remoteHost = target_ip
        self.__exec_method = exec_method
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__aes_key = aes_key
        self.__do_kerberos = do_kerberos
        self.__dc_ip = dc_ip
        if hashes is None:
            self.__lmhash, self.__nthash = '', ''
        else:
            self.__lmhash, self.__nthash = hashes.split(':')
        self.__clients = set()
        self.__smb_connection = None
        self.__remote_ops = None

    def connect(self):
        self.__smb_connection = SMBConnection(self.__remote_name, self.__remoteHost)
        if self.__do_kerberos:
            self.__smb_connection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                                self.__nthash, self.__aes_key, self.__dc_ip)
        else:
            self.__smb_connection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def serve_connections(self):
        try:
            self.connect()
        except Exception as e:
            logging.warning('OPSEC: SMB Connection failed (%s), cannot check which ports are in use.', str(e))
            ans = input('     Continue in blind? (small risk of resetting production connections) [y/N]')
            if ans.lower() != 'y':
                raise

        self.__remote_ops = RemoteOperations(self.__smb_connection, self.__exec_method,
                                             self.__do_kerberos, self.__dc_ip)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.__local_ip, self.__local_port))
                logging.info('Listening on %s port %s', self.__local_ip, self.__local_port)
                s.listen(1)
                while True:
                    conn, (client_addr, client_port) = s.accept()
                    logging.debug('Client connection from %s port %u', client_addr, client_port)
                    client = SocksClient(conn, self.__smb_connection.getRemoteHost(), client_addr, client_port,
                                         self.__remote_ops)
                    client.start()
                    self.__clients.add(client)
        except KeyboardInterrupt:
            logging.info('Received interrupt from user')
        finally:
            self.cleanup()

    def cleanup(self):
        logging.info('Cleaning up...')
        for client in self.__clients:
            client.force_stop()
        for client in self.__clients:
            client.join()
        logging.info('Cleaned up.')


class SocksClient(threading.Thread):
    COMMAND_CONNECT = 1
    COMMAND_BIND = 2

    AUTH_NONE_REQUIRED = 0

    ADDRESS_TYPE_IPV4 = 1
    ADDRESS_TYPE_DOMAINNAME = 3
    ADDRESS_TYPE_IPV6 = 4

    RST_GRACE_SECONDS = 2.0

    def __init__(self, conn, pivot_ip, client_ip, client_port, remote_ops):
        threading.Thread.__init__(self)
        self.__client_sock = conn
        self.__forwarded_sock = None
        self.__remote_ops = remote_ops
        self.__pivot_ip = pivot_ip
        self.__bind_port = None
        self.__client_ip = ipaddress.ip_address(client_ip)
        self.__client_port = client_port
        self.__dest_ip = None
        self.__dest_port = None
        self.__must_terminate = False

    def __find_free_port(self):
        logging.debug('Looking for an available port for %s', str(self))
        free_ports = set(p for p in range(49888, 65535))
        protocol = 'tcpv6' if self.__client_ip.version == 6 else 'tcp'
        netstat = self.__remote_ops.execute_remote('netstat -an -p ' + protocol)
        netstat = netstat.decode('utf-8', 'replace')
        for row in filter(None, netstat.replace('\r\n', '\n').split('\n')):
            binding = re.match(r'^\s*TCP\s+\S+:(?P<port>\d+).+LISTENING\s*$', row, re.IGNORECASE)
            if binding is None:
                continue
            port = int(binding.group('port'))
            if port in free_ports:
                free_ports.remove(port)
        if len(free_ports) > 0:
            return random.choice(list(free_ports))
        else:
            raise RuntimeError('No free TCP port available on remote host')

    def run(self):
        try:
            version = self.__recv_exactly(1)[0]
            if version == 0x04:
                cmd, ip, port = self.__read_socks4a_header()
            elif version == 0x05:
                cmd, ip, port = self.__read_socks5_header()
            else:
                raise NotImplementedError("Client requests unknown SOCKS protocol %u" % version)
            logging.debug('Client %s uses SOCKSv%u', str(self), version)
            if cmd == SocksClient.COMMAND_CONNECT:
                self.__bind_port = self.__find_free_port()
                self.__dest_ip = ip
                self.__dest_port = port
                logging.info('Adding port forward from *:%u to %s:%u',
                             self.__bind_port, self.__dest_ip, self.__dest_port)
                cmd = 'netsh interface portproxy add v4tov4 listenport=%u connectaddress=%s connectport=%u' % (
                    self.__bind_port, self.__dest_ip, self.__dest_port)
                self.__remote_ops.execute_remote(cmd)
                self.__forwarded_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.__forwarded_sock.connect((self.__pivot_ip, self.__bind_port))

                # Wait for 1 byte of incoming data (if the protocol on this port is
                # "server talks first"), or the time it would take for a RST to get
                # to the pivot and back to us
                r, _, _ = select.select([self.__forwarded_sock], [], [self.__forwarded_sock],
                                        self.RST_GRACE_SECONDS)
                server_spoke_first = b''
                if len(r) > 0:
                    server_spoke_first = self.__forwarded_sock.recv(1)
                    if len(server_spoke_first) == 0:
                        logging.warning('Pivot received RST when connecting to the target')
                        return
                # Send response header
                if version == 0x04:
                    self.__send_socks4a_accept()
                elif version == 0x05:
                    self.__send_socks5_accept()
                # Send the first byte received from the server, if any
                if len(server_spoke_first) > 0:
                    self.__client_sock.sendall(server_spoke_first)
                # Connect the SOCKS client socket and the forwarded socket together
                # by looping and passing data between them
                while not self.__must_terminate:
                    socks = [self.__client_sock, self.__forwarded_sock]
                    r, w, _ = select.select(socks, socks, [], 0.5)
                    if self.__client_sock in r and self.__forwarded_sock in w:
                        data = self.__client_sock.recv(1024)
                        if len(data) == 0:
                            logging.debug('Received disconnect from client')
                            break
                        self.__forwarded_sock.sendall(data)
                    if self.__client_sock in w and self.__forwarded_sock in r:
                        data = self.__forwarded_sock.recv(1024)
                        if len(data) == 0:
                            logging.debug('Received disconnect from pivot')
                            break
                        self.__client_sock.sendall(data)
            elif cmd == SocksClient.COMMAND_BIND:
                raise NotImplementedError('Client requests a port bind for active protocol callback')
            else:
                raise NotImplementedError('Client requests unknown command %u' % cmd)
        except ConnectionResetError as e:
            logging.warning('Connection reset by peer: %s', str(e))
        finally:
            logging.debug('Client %s disconnected', str(self))
            if self.__forwarded_sock is not None:
                self.__forwarded_sock.close()
            if self.__client_sock is not None:
                self.__client_sock.close()
            if self.__bind_port is not None:
                logging.debug('Cleaning up port forward from *:%u to %s:%u',
                              self.__bind_port, self.__dest_ip, self.__dest_port)
                cmd = 'netsh interface portproxy delete v4tov4 listenport=%u' % self.__bind_port
                self.__remote_ops.execute_remote(cmd)
                logging.info('Cleaned up port forward from *:%u to %s:%u',
                             self.__bind_port, self.__dest_ip, self.__dest_port)

    def force_stop(self):
        self.__must_terminate = True

    def __recv_exactly(self, num_bytes):
        data = self.__client_sock.recv(num_bytes)
        if len(data) == 0:
            raise RuntimeError('Connection reset by client')
        if len(data) != num_bytes:
            raise RuntimeError('Expected %u bytes, received %u' % (num_bytes, len(data)))
        return data

    def __send(self, buf):
        self.__client_sock.sendall(buf)

    def __read_socks4a_header(self):
        header = self.__recv_exactly(7)
        command, port, ip = struct.unpack('!BHI', header)
        # Read the NULL-terminated client userID, but discard it, we don't need it
        while self.__recv_exactly(1) != b'\x00':
            continue
        # 4A extension of SOCKSv4: read an appended DNS hostname
        if (ip & 0xffffff00) == 0 and ip != 0:
            logging.debug('Client uses SOCKS 4a extension')
            hostname = b''
            while len(hostname) == 0 or hostname[-1] != 0x00:
                hostname += self.__recv_exactly(1)
            try:
                hostname = hostname.decode('utf-8')
            except UnicodeDecodeError as e:
                logging.error('Client requests invalid hostname through SOCKS4a: %s', str(e))
                raise
            logging.debug('Resolving hostname %s', hostname)
            try:
                ip = socket.getaddrinfo(hostname, port, family=self.__client_ip.family)[0][4][0]
            except socket.gaierror as e:
                logging.error('Client requests invalid hostname through SOCKS4a: %s', str(e))
                raise
        else:
            ip = '%u.%u.%u.%u' % ((ip & 0xff000000) >> 24, (ip & 0xff0000) >> 16, (ip & 0xff00) >> 8, ip & 0xff)
        return command, ip, port

    def __read_socks5_header(self):
        num_methods = self.__recv_exactly(1)[0]
        if num_methods > 0:
            methods = set(int(i) for i in self.__recv_exactly(num_methods))
            if SocksClient.AUTH_NONE_REQUIRED not in methods:
                self.__send(b'\x05\xFF')  # No acceptable method
                raise NotImplementedError('Client requests authentication methods %s' % ', '.join(
                    str(m) for m in methods))
        self.__send(b'\x05\x00')  # select the "none" auth method
        header = self.__recv_exactly(4)
        version, command, mbz, atyp = struct.unpack('!BBBB', header)
        if version != 5:
            raise NotImplementedError('Client switched to SOCKS version %u unexpectedly' % version)
        if atyp == SocksClient.ADDRESS_TYPE_IPV4:
            ip, = struct.unpack('!I', self.__recv_exactly(4))
            ip = '%u.%u.%u.%u' % ((ip & 0xff000000) >> 24, (ip & 0xff0000) >> 16, (ip & 0xff00) >> 8, ip & 0xff)
        elif atyp == SocksClient.ADDRESS_TYPE_IPV6:
            ip_h, ip_l = struct.unpack('!QQ', self.__recv_exactly(8))
            ip = (ip_h << 64) | ip_l
        elif atyp == SocksClient.ADDRESS_TYPE_DOMAINNAME:
            domain_name_len = struct.unpack('!B', self.__recv_exactly(1))
            domain_name = self.__recv_exactly(domain_name_len)
            try:
                ip = socket.getaddrinfo(domain_name, 80)[0][4][0]
            except socket.gaierror:
                raise RuntimeError('Client requested domain name %s but DNS resolution failed' % domain_name)
        else:
            raise NotImplementedError('Client uses unknown addressing mode 0x%02X' % atyp)
        port, = struct.unpack('!H', self.__recv_exactly(2))
        return command, ip, port

    def __send_socks4a_accept(self):
        ip = [int(i) for i in self.__pivot_ip.split('.')]
        ip = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]
        buf = struct.pack('!BBHI',
                          0x00,  # version
                          0x5A,  # status code: accept
                          self.__bind_port,
                          ip)
        self.__client_sock.sendall(buf)

    def __send_socks5_accept(self):
        ip = [int(i) for i in self.__pivot_ip.split('.')]
        ip = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]
        buf = struct.pack('!BBBBIH',
                          0x05,  # version
                          0x00,  # status code: accept
                          0x00,  # must be zero
                          SocksClient.ADDRESS_TYPE_IPV4,
                          ip,
                          self.__bind_port)
        self.__client_sock.sendall(buf)

    def __str__(self):
        return '%s:%u' % (str(self.__client_ip), self.__client_port)


class RemoteOperations:
    def __init__(self, smb_connection, exec_method, do_kerberos, dc_ip=None):
        self.__smb_connection = smb_connection
        if self.__smb_connection is not None:
            self.__smb_connection.setTimeout(5 * 60)

        self.__do_kerberos = do_kerberos
        self.__dc_ip = dc_ip

        self.__batchFile = '%TEMP%\\execute.bat'
        self.__shell = '%COMSPEC% /Q /c '
        self.__output = '%SYSTEMROOT%\\Temp\\__output'
        self.__answerTMP = b''

        self.__exec_method = exec_method

    def __smb_exec(self, command):
        rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\svcctl]')
        rpc.set_smb_connection(self.__smb_connection)
        h_scmr = rpc.get_dce_rpc()
        h_scmr.connect()
        h_scmr.bind(scmr.MSRPC_UUID_SCMR)
        h_scmanager = scmr.hROpenSCManagerW(h_scmr)['lpScHandle']
        # Ensure we use a unique service name
        tmp_svc_name = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        logging.debug('Creating service %s', tmp_svc_name)
        resp = scmr.hRCreateServiceW(h_scmr, h_scmanager, tmp_svc_name, tmp_svc_name,
                                     lpBinaryPathName=command)
        service = resp['lpServiceHandle']
        try:
            scmr.hRStartServiceW(h_scmr, service)
        except Exception:
            pass
        logging.debug('Deleting service %s', tmp_svc_name)
        scmr.hRDeleteService(h_scmr, service)
        scmr.hRCloseServiceHandle(h_scmr, service)
        h_scmr.disconnect()

    def __wmi_exec(self, command):
        # Convert command to wmi exec friendly format
        command = command.replace('%COMSPEC%', 'cmd.exe')
        username, password, domain, lmhash, nthash, aes_key, _, _ = self.__smb_connection.getCredentials()
        dcom = DCOMConnection(self.__smb_connection.getRemoteHost(), username, password, domain, lmhash, nthash,
                              aes_key, oxidResolver=False, doKerberos=self.__do_kerberos, kdcHost=self.__dc_ip)
        i_interface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iwbemlevel1login = wmi.IWbemLevel1Login(i_interface)
        iwbemservices = iwbemlevel1login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iwbemlevel1login.RemRelease()
        win32_process, _ = iwbemservices.GetObject('Win32_Process')
        win32_process.Create(command, '\\', None)
        dcom.disconnect()

    def execute_remote(self, cmd):
        # Format a command to run
        command = self.__shell + 'echo ' + cmd + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile + ' & ' + 'del ' + self.__batchFile
        logging.debug('Executing remote command through %s : %s', self.__exec_method, cmd)
        if self.__exec_method == 'smbexec':
            self.__smb_exec(command)
        elif self.__exec_method == 'wmiexec':
            self.__wmi_exec(command)
        else:
            raise ValueError('Invalid exec method %s, aborting' % self.__exec_method)
        time.sleep(1)
        tries = 0
        while True:
            tries += 1
            self.__answerTMP = b''
            try:
                self.__smb_connection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
                break
            except Exception as e:
                if tries > 30:
                    logging.error(
                        'Giving up on command "%s" execution in %s after %u tries to get output file %s (error %s)',
                        cmd, self.__batchFile, tries, self.__output, str(e))
                    raise
                if str(e).find('SHARING') > 0 or (
                        isinstance(e, SessionError) and e.error == 0xc000003a):  # or STATUS_OBJECT_PATH_NOT_FOUND
                    # Stuff didn't finish yet.. wait more
                    time.sleep(5)
                    pass
                else:
                    raise
        return self.__answerTMP

    def __answer(self, data):
        self.__answerTMP += data


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
                                     description="Transforms a remote host for which you have administrative"
                                                 " credentials into a network pivot, without installing software"
                                                 " or executing non-Windows code on it. Sets up port forwardings"
                                                 " on the pivot as they are needed, and exposes this functionality"
                                                 " as a local SOCKS server.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-local-ip', default='127.0.0.1', help='local IP the socks server should listen on')
    parser.add_argument('-local-port', type=int, default=1080, help='local TCP port the socks server should listen on')
    parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec'], nargs='?', default='wmiexec',
                        help='Remote exec method to use at target. Default: wmiexec')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot '
                            'be found, it will use the ones specified in the command line')
    group.add_argument('-aes_key', action="store", metavar="hex key",
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it use the domain part (FQDN)'
                            ' specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was '
                            'specified as target. This is useful when target is the NetBIOS name '
                            'and you cannot resolve it')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = remote_name

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and \
            options.no_pass is False and options.aes_key is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aes_key is not None:
        options.k = True

    server = SocksServer(remote_name, options.local_ip, options.local_port, options.target_ip,
                         options.exec_method, username, password, domain, options.aes_key,
                         options.k, options.dc_ip, options.hashes)
    try:
        server.serve_connections()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
