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
# Description: Executes commands through WinRM/WinRS.
# Originaly writen by @Ozelis
# Reviewed by @gabrielg5 and @Defte

import cmd
import sys
import base64
import logging
import argparse
from ipaddress import ip_address
from urllib.parse import urlparse

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from impacket.krb5.kerberosv5 import SessionError

from impacket.winrm import (
    BasicTransport,
    ClientCertificateTransport,
    CredSSPTransport,
    KerberosTransport,
    NegotiateTransport,
    NTCredential,
    WinRSClient,
    WinRMAuthError,
    WinRMFaultError,
    WinRMTransportError,
    get_kerberos_credential,
)


CODEC = sys.stdout.encoding


def _parse_hashes(hashes):
    if not hashes:
        return b'', b''

    if ':' in hashes:
        lmhash, nthash = hashes.split(':', 1)
        return bytes.fromhex(lmhash) if lmhash else b'', bytes.fromhex(nthash) if nthash else b''

    return b'', bytes.fromhex(hashes)


def _is_ip_address(value):
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def _build_command(command, shell_type):
    if shell_type == 'powershell':
        command = '$ProgressPreference="SilentlyContinue";%s' % command
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        return 'powershell.exe', ['-NoP', '-NoL', '-sta', '-NonI', '-W', 'Hidden', '-Exec', 'Bypass', '-Enc', encoded]

    return 'cmd.exe', ['/Q', '/c', command]


class KerberosFallbackTransport:
    def __init__(self, url, credentials, timeout):
        self._url = url
        self._credentials = credentials
        self._timeout = timeout
        self._transport = KerberosTransport(url, credentials, timeout=timeout)
        self._fallback_attempted = False

    def send(self, request):
        try:
            return self._transport.send(request)
        except WinRMAuthError:
            if self._fallback_attempted:
                raise

            self._fallback_attempted = True
            self._transport.close()
            logging.info('Kerberos via GSS failed, falling back to Negotiate')
            self._transport = NegotiateTransport(self._url, self._credentials, timeout=self._timeout)
            return self._transport.send(request)

    def close(self):
        self._transport.close()


class RemoteShell(cmd.Cmd):
    def __init__(self, client, shell_type, codec):
        cmd.Cmd.__init__(self)
        self._client = client
        self._shell_type = shell_type
        self._codec = codec
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'
        self.prompt = 'PS > ' if shell_type == 'powershell' else 'CMD > '

    def cmdloop(self, intro=None):
        while True:
            try:
                return cmd.Cmd.cmdloop(self, intro=intro)
            except KeyboardInterrupt:
                print()

    def emptyline(self):
        return False

    def do_exit(self, line):
        return True

    def do_EOF(self, line):
        print()
        return self.do_exit(line)

    def default(self, line):
        line = line.strip()
        if not line:
            return

        try:
            self.run_command(line)
        except (WinRMAuthError, WinRMFaultError, WinRMTransportError) as error:
            logging.error(str(error))

    def run_command(self, line):
        command, arguments = _build_command(line, self._shell_type)
        remote_command = self._client.execute(command, arguments=arguments)
        output = remote_command.iter_output()
        interrupted = False

        while True:
            try:
                stream_name, data = next(output)
            except StopIteration:
                break
            except KeyboardInterrupt:
                print()
                if interrupted:
                    raise

                interrupted = True
                logging.info('Sending Ctrl+C to the remote command')
                remote_command.interrupt()
                continue

            self._write_output(stream_name, data)

    def _write_output(self, stream_name, data):
        if not data:
            return

        try:
            text = data.decode(self._codec)
        except UnicodeDecodeError:
            logging.error('Decoding error detected, run chcp.com at the target and retry with -codec if output looks wrong')
            text = data.decode(self._codec, errors='replace')

        if stream_name == 'stderr':
            sys.stderr.write(text)
            sys.stderr.flush()
            return

        sys.stdout.write(text)
        sys.stdout.flush()


def create_transport(options):
    domain, username, password, target_name = parse_target(options.target)

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)

    lmhash, nthash = _parse_hashes(options.hashes)

    if options.cert_pem or options.cert_key:
        options.ssl = True

    if options.aesKey and not options.k:
        options.k = True

    if sum((bool(options.k), bool(options.basic), bool(options.cert_pem or options.cert_key))) > 1:
        raise WinRMTransportError("'-k', '-basic', and '-cert-*' are mutually exclusive")

    if options.credssp and (options.basic or options.cert_pem or options.cert_key):
        raise WinRMTransportError("'-credssp' does not support '-basic' or '-cert-*'")

    has_secret = any((password, lmhash, nthash, options.aesKey))
    if username and not has_secret and not options.no_pass and not (options.cert_pem or options.cert_key):
        from getpass import getpass

        password = getpass('Password:')

    connect_host = options.target_ip or target_name
    use_ssl = options.ssl

    if options.url:
        url = options.url
        parsed = urlparse(url)
        use_ssl = parsed.scheme == 'https'
    else:
        port = options.port or (5986 if use_ssl else 5985)
        scheme = 'https' if use_ssl else 'http'
        url = '%s://%s:%d/wsman' % (scheme, connect_host, port)

    if options.basic:
        if not username or password is None or password == '':
            raise WinRMTransportError('Basic authentication requires a username and password')
        return BasicTransport(url, username, password, timeout=options.timeout)

    if options.cert_pem or options.cert_key:
        if not options.cert_pem or not options.cert_key:
            raise WinRMTransportError('Client certificate authentication requires both -cert-pem and -cert-key')
        if not use_ssl:
            raise WinRMTransportError('Client certificate authentication requires HTTPS')
        return ClientCertificateTransport(url, options.cert_pem, options.cert_key, timeout=options.timeout)

    if options.k:
        if not options.spn:
            if _is_ip_address(target_name):
                raise WinRMTransportError("Specify -spn when the target is an IP address")
            spn = 'HTTP/%s' % target_name
            logging.info("'-spn' not specified, using %s", spn)
        else:
            spn = options.spn

        kdc_host = options.dc_ip or None
        
        try:
            kerberos_credentials = get_kerberos_credential(
                spn,
                domain=domain,
                username=username,
                password=password,
                lmhash=lmhash,
                nthash=nthash,
                aes_key=options.aesKey,
                kdc_host=kdc_host,
                use_cache=True,
            )
        except SessionError as e:
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                raise WinRMTransportError("KDC_ERR_S_PRINCIPAL_UNKNOWN: domain names specified in ticket and in target do not match.")
            raise WinRMTransportError(str(e))

        if options.credssp:
            if not kerberos_credentials.password:
                raise WinRMTransportError('CredSSP needs a plaintext password, even when using Kerberos')
            return CredSSPTransport(url, kerberos_credentials, timeout=options.timeout)

        return KerberosFallbackTransport(url, kerberos_credentials, timeout=options.timeout)

    nt_credentials = NTCredential(
        domain=domain,
        username=username,
        password=password,
        lmhash=lmhash,
        nthash=nthash,
    )

    if options.credssp:
        if not nt_credentials.username or not nt_credentials.password:
            raise WinRMTransportError('CredSSP needs a username and plaintext password')
        return CredSSPTransport(url, nt_credentials, timeout=options.timeout)

    return NegotiateTransport(url, nt_credentials, timeout=options.timeout)


def build_arg_parser():
    parser = argparse.ArgumentParser(add_help=True, description='Executes commands through WinRM/WinRS.')

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', nargs='*', default=' ', help='command to execute at the target. If empty it will launch a semi-interactive shell')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used from the target output (default "%s")' % CODEC)
    parser.add_argument('-shell-type', action='store', default='cmd', choices=['cmd', 'powershell'], help='choose a command processor for the semi-interactive shell')
    parser.add_argument('-timeout', action='store', type=int, default=1, metavar='SECONDS', help='operation timeout used for WinRM receive requests')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller')
    group.add_argument('-target-ip', action='store', metavar='ip address', help='IP Address of the target machine')
    group.add_argument('-port', action='store', type=int, metavar='port', help='Destination port to connect to WinRM')
    group.add_argument('-ssl', action='store_true', help='Use HTTPS')
    group.add_argument('-url', action='store', help='Exact WSMan endpoint, e.g. http(s)://host:port/wsman')

    group = parser.add_argument_group('authentication')
    group.add_argument('-spn', action='store', help='Specify the SPN to request for the TGS')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', default='', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help="don't ask for password")
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) if available')
    group.add_argument('-aesKey', action='store', metavar='hex key', default='', help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-keytab', action='store', help='Read keys for SPN from keytab file')
    group.add_argument('-basic', action='store_true', help='Use Basic authentication')
    group.add_argument('-cert-pem', action='store', default='', help='Client certificate file')
    group.add_argument('-cert-key', action='store', default='', help='Client certificate private key file')
    group.add_argument('-credssp', action='store_true', help='Use CredSSP if enabled')

    return parser


def main():
    global CODEC

    print(version.BANNER)
    parser = build_arg_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return 1

    options = parser.parse_args()
    logger.init(options.ts, options.debug)

    if options.codec is not None:
        CODEC = options.codec
    elif CODEC is None:
        CODEC = 'utf-8'

    try:
        transport = create_transport(options)
        client = WinRSClient(transport, timeout=options.timeout)

        with client:
            shell = RemoteShell(client, options.shell_type, CODEC)
            command = ' '.join(options.command)
            if command != ' ':
                shell.run_command(command)
            else:
                shell.cmdloop()
        return 0
    except (WinRMAuthError, WinRMFaultError, WinRMTransportError, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            print()
            return 1
        logging.error(str(error))
        return 1
    except Exception as error:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(error))
        return 1


if __name__ == '__main__':
    sys.exit(main())
