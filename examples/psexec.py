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
#   PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   DCE/RPC and SMB.
#

import sys
import os
import re
import cmd
import logging
from threading import Thread, Lock
import argparse
import random
import string
import time
from six import PY3

from impacket.examples import logger
from impacket import version, smb
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab

CODEC = sys.stdout.encoding

class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT = "RemCom_stdout"
RemComSTDIN = "RemCom_stdin"
RemComSTDERR = "RemCom_stderr"

lock = Lock()

class PSEXEC:
    def __init__(self, command, path, exeFile, copyFile, port=445,
                 username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, serviceName=None,
                 remoteBinaryName=None):
        self.__username = username
        self.__password = password
        self.__port = port
        self.__command = command
        self.__path = path
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__exeFile = exeFile
        self.__copyFile = copyFile
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__serviceName = serviceName
        self.__remoteBinaryName = remoteBinaryName
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doStuff(rpctransport)

    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid,pipe)
                pipeReady = True
            except:
                tries -= 1
                time.sleep(2)
                pass

        if tries == 0:
            raise Exception('Pipe not ready, aborting')

        fid = s.openFile(tid,pipe,accessMask, creationOption = 0x40, fileAttributes = 0x80)

        return fid

    def doStuff(self, rpctransport):

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()

        try:
            unInstalled = False
            s = rpctransport.get_smb_connection()

            # We don't wanna deal with timeouts from now on.
            s.setTimeout(100000)
            if self.__exeFile is None:
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), remcomsvc.RemComSvc(), self.__serviceName, self.__remoteBinaryName)
            else:
                try:
                    f = open(self.__exeFile, 'rb')
                except Exception as e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), f)

            if installService.install() is False:
                return

            if self.__exeFile is not None:
                f.close()

            # Check if we need to copy a file for execution
            if self.__copyFile is not None:
                installService.copy_file(self.__copyFile, installService.getShare(), os.path.basename(self.__copyFile))
                # And we change the command to be executed to this filename
                self.__command = os.path.basename(self.__copyFile) + ' ' + self.__command

            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s,tid,r'\RemCom_communicaton',0x12019f)

            packet = RemComMessage()
            pid = os.getpid()

            packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
            if self.__path is not None:
                packet['WorkingDir'] = self.__path
            packet['Command'] = self.__command
            packet['ProcessID'] = pid

            s.writeNamedPipe(tid, fid_main, packet.getData())

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe = RemoteStdInPipe(rpctransport,
                                         r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
                                         smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare())
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stderr_pipe.start()

            # And we stay here till the end
            ans = s.readNamedPipe(tid,fid_main,8)

            if len(ans):
                retCode = RemComResponse(ans)
                logging.info("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (
                self.__command, retCode['ErrorCode'], retCode['ReturnCode']))
            installService.uninstall()
            if self.__copyFile is not None:
                # We copied a file for execution, let's remove it
                s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            unInstalled = True
            sys.exit(retCode['ErrorCode'])

        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.debug(str(e))
            if unInstalled is False:
                installService.uninstall()
                if self.__copyFile is not None:
                    s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            sys.stdout.flush()
            sys.exit(1)


class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            #self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
            self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()

        global LastDataSent

        if PY3:
            __stdoutOutputBuffer, __stdoutData = b"", b""

            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if stdout_ans != LastDataSent:
                            if len(stdout_ans) != 0:
                                # Append new data to the buffer while there is data to read
                                __stdoutOutputBuffer += stdout_ans

                        promptRegex = b'([a-zA-Z]:[\\\/])((([a-zA-Z0-9 -\.]*)[\\\/]?)+(([a-zA-Z0-9 -\.]+))?)?>$'

                        endsWithPrompt = bool(re.match(promptRegex, __stdoutOutputBuffer) is not None)
                        if endsWithPrompt == True:
                            # All data, we shouldn't have encoding errors
                            # Adding a space after the prompt because it's beautiful
                            __stdoutData = __stdoutOutputBuffer + b" "
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = b""

                            # print("[+] endsWithPrompt")
                            # print(" | __stdoutData:",__stdoutData)
                            # print(" | __stdoutOutputBuffer:",__stdoutOutputBuffer)
                        elif b'\n' in __stdoutOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stdoutOutputBuffer.split(b"\n")
                            # All lines, we shouldn't have encoding errors
                            __stdoutData = b"\n".join(lines[:-1]) + b"\n"
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = lines[-1]
                            # print("[+] newline in __stdoutOutputBuffer")
                            # print(" | __stdoutData:",__stdoutData)
                            # print(" | __stdoutOutputBuffer:",__stdoutOutputBuffer)

                        if len(__stdoutData) != 0:
                            # There is data to print
                            try:
                                sys.stdout.write(__stdoutData.decode(CODEC))
                                sys.stdout.flush()
                                __stdoutData = b""
                            except UnicodeDecodeError:
                                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                                              'again with -codec and the corresponding codec')
                                print(__stdoutData.decode(CODEC, errors='replace'))
                                __stdoutData = b""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = b""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except:
                        pass
        else:
            __stdoutOutputBuffer, __stdoutData = "", ""

            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if stdout_ans != LastDataSent:
                            if len(stdout_ans) != 0:
                                # Append new data to the buffer while there is data to read
                                __stdoutOutputBuffer += stdout_ans

                        promptRegex = r'([a-zA-Z]:[\\\/])((([a-zA-Z0-9 -\.]*)[\\\/]?)+(([a-zA-Z0-9 -\.]+))?)?>$'

                        endsWithPrompt = bool(re.match(promptRegex, __stdoutOutputBuffer) is not None)
                        if endsWithPrompt:
                            # All data, we shouldn't have encoding errors
                            # Adding a space after the prompt because it's beautiful
                            __stdoutData = __stdoutOutputBuffer + " "
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = ""

                        elif '\n' in __stdoutOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stdoutOutputBuffer.split("\n")
                            # All lines, we shouldn't have encoding errors
                            __stdoutData = "\n".join(lines[:-1]) + "\n"
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = lines[-1]

                        if len(__stdoutData) != 0:
                            # There is data to print
                            sys.stdout.write(__stdoutData.decode(CODEC))
                            sys.stdout.flush()
                            __stdoutData = ""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = ""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except Exception as e:
                        pass


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()

        if PY3:
            __stderrOutputBuffer, __stderrData = b'', b''

            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if len(stderr_ans) != 0:
                            # Append new data to the buffer while there is data to read
                            __stderrOutputBuffer += stderr_ans

                        if b'\n' in __stderrOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stderrOutputBuffer.split(b"\n")
                            # All lines, we shouldn't have encoding errors
                            __stderrData = b"\n".join(lines[:-1]) + b"\n"
                            # Remainder data for next iteration
                            __stderrOutputBuffer = lines[-1]

                        if len(__stderrData) != 0:
                            # There is data to print
                            try:
                                sys.stdout.write(__stderrData.decode(CODEC))
                                sys.stdout.flush()
                                __stderrData = b""
                            except UnicodeDecodeError:
                                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                                              'again with -codec and the corresponding codec')
                                print(__stderrData.decode(CODEC, errors='replace'))
                                __stderrData = b""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = b""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except Exception as e:
                        pass
        else:
            __stderrOutputBuffer, __stderrData = '', ''

            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if len(stderr_ans) != 0:
                            # Append new data to the buffer while there is data to read
                            __stderrOutputBuffer += stderr_ans

                        if '\n' in __stderrOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stderrOutputBuffer.split("\n")
                            # All lines, we shouldn't have encoding errors
                            __stderrData = "\n".join(lines[:-1]) + "\n"
                            # Remainder data for next iteration
                            __stderrOutputBuffer = lines[-1]

                        if len(__stderrData) != 0:
                            # There is data to print
                            sys.stdout.write(__stderrData.decode(CODEC))
                            sys.stdout.flush()
                            __stderrData = ""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = ""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except:
                        pass


class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share, transport):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.transport = transport
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        #self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port=self.port,
                                            preferredDialect=dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        if self.transport.get_kerberos() is True:
            self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey,
                                              kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
        else:
            self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 lput {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 lget {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share))
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_lget(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

        self.send_data('\r\n')

    def do_lput(self, s):
        try:
            if self.transferClient is None:
                self.connect_transferClient()
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = '/'

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            f = dst_path + '/' + src_file
            pathname = f.replace('/','\\')
            logging.info("Uploading %s to %s\\%s" % (src_file, self.share, dst_path))
            if PY3:
                self.transferClient.putFile(self.share, pathname, fh.read)
            else:
                self.transferClient.putFile(self.share, pathname.decode(sys.stdin.encoding), fh.read)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            pass

        self.send_data('\r\n')

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        if PY3:
            self.send_data(line.encode(CODEC)+b'\r\n')
        else:
            self.send_data(line.decode(sys.stdin.encoding).encode(CODEC)+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share, self.transport)
        self.shell.cmdloop()

# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "PSEXEC like functionality example using RemComSvc.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', nargs='*', default = ' ', help='command (or arguments if -c is used) to execute at '
                                                                  'the target (w/o path) - (default:cmd.exe)')
    parser.add_argument('-c', action='store',metavar = "pathname",  help='copy the filename for later execution, '
                                                                         'arguments are passed in the command option')
    parser.add_argument('-path', action='store', help='path of the command to execute')
    parser.add_argument('-file', action='store', help="alternative RemCom binary (be sure it doesn't require CRT)")
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute smbexec.py '
                          'again with -codec and the corresponding codec ' % CODEC)

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-service-name', action='store', metavar="service_name", default = '', help='The name of the service'
                                                                                ' used to trigger the payload')
    group.add_argument('-remote-binary-name', action='store', metavar="remote_binary_name", default = None, help='This will '
                                                            'be the name of the executable uploaded on the target')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if options.target_ip is None:
        options.target_ip = remoteName

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    command = ' '.join(options.command)
    if command == ' ':
        command = 'cmd.exe'

    executer = PSEXEC(command, options.path, options.file, options.c, int(options.port), username, password, domain, options.hashes,
                      options.aesKey, options.k, options.dc_ip, options.service_name, options.remote_binary_name)
    executer.run(remoteName, options.target_ip)
