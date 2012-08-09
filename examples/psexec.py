#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)
#
# Author:
#  beto (bethus@gmail.com)
#
# Reference for:
#  DCE/RPC and SMB.

import sys
import os
import cmd

from impacket import smb, version
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, svcctl, srvsvc
from impacket.structure import Structure
from threading import Thread, Lock
from impacket.examples import remcomsvc, serviceinstall
import argparse
import random
import string
import time

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

RemComSTDOUT         = "RemCom_stdout"
RemComSTDIN          = "RemCom_stdin"
RemComSTDERR         = "RemCom_stderr"

lock = Lock()

class PSEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, command, path, exeFile, protocols = None, 
                 username = '', password = '', domain = '', hashes = None):
        if not protocols:
            protocols = PSEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__command = command
        self.__path = path
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__exeFile = exeFile
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        for protocol in self.__protocols:
            protodef = PSEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s...\n" % protocol
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

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
            print '[!] Pipe not ready, aborting'
            raise

        ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
        ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
        ntCreate['Data']       = smb.SMBNtCreateAndX_Data()
        ntCreate['Parameters']['FileNameLength'] = len(pipe)
        ntCreate['Parameters']['FileAttributes'] = 0x80
        ntCreate['Parameters']['CreateFlags'] = 0x0
        ntCreate['Parameters']['AccessMask'] = accessMask
        ntCreate['Parameters']['CreateOptions'] = 0x40
        ntCreate['Parameters']['ShareAccess'] = 0x7
        ntCreate['Data']['FileName'] = pipe

        fid = s.nt_create_andx(tid,pipe,cmd=ntCreate)

        return fid

    def doStuff(self, rpctransport):

        dce = dcerpc.DCERPC_v5(rpctransport)
        try:
            dce.connect()
        except Exception, e:
            print e
            sys.exit(1)

        try:
            unInstalled = False
            s = rpctransport.get_smb_server()

            # We don't wanna deal with timeouts from now on.
            s.set_timeout(100000)
            if self.__exeFile is None:
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_server(), remcomsvc.RemComSvc())
            else:
                try:
                    f = open(self.__exeFile)
                except Exception, e:
                    print e
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_server(), f)
    
            installService.install()

            if self.__exeFile is not None:
                f.close()

            tid = s.tree_connect_andx('\\\\%s\\IPC$' % s.get_remote_name())
            fid_main = self.openPipe(s,tid,'\RemCom_communicaton',0x12019f)

            packet = RemComMessage()
            pid = os.getpid()

            packet['Machine'] = ''.join([random.choice(string.letters) for i in range(4)])
            if self.__path is not None:
                packet['WorkingDir'] = self.__path
            packet['Command'] = self.__command
            packet['ProcessID'] = pid

            s.write_andx(tid, fid_main, str(packet), write_pipe_mode = True)

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe  = RemoteStdInPipe(rpctransport,'\%s%s%d' % (RemComSTDIN ,packet['Machine'],packet['ProcessID']), smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare() )
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,'\%s%s%d' % (RemComSTDOUT,packet['Machine'],packet['ProcessID']), smb.FILE_READ_DATA )
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,'\%s%s%d' % (RemComSTDERR,packet['Machine'],packet['ProcessID']), smb.FILE_READ_DATA )
            stderr_pipe.start()
            
            # And we stay here till the end
            ans = s.read_andx(tid,fid_main,8, wait_answer = 0)
            readAndXResponse   = smb.SMBCommand(ans['Data'][0])
            readAndXParameters = smb.SMBReadAndXResponse_Parameters(readAndXResponse['Parameters'])
            offset = readAndXParameters['DataOffset']
            count = readAndXParameters['DataCount']+0x10000*readAndXParameters['DataCount_Hi']
            if count > 0:
               retCode = RemComResponse(str(ans)[offset:offset+count])
               print "[*] Process %s finished with ErrorCode: %d, ReturnCode: %d" % (self.__command, retCode['ErrorCode'], retCode['ReturnCode'])
            installService.uninstall()
            unInstalled = True
            sys.exit(retCode['ErrorCode'])

        except:
            if unInstalled is False:
                installService.uninstall()
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
            self.server = smb.SMB('*SMBSERVER', self.transport.get_smb_server().get_remote_host(), sess_port = self.port)
            user, passwd, domain, lm, nt = self.credentials
            self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.tree_connect_andx('\\\\%s\\IPC$' % self.transport.get_smb_server().get_remote_name())

            self.server.waitNamedPipe(self.tid, self.pipe)

            ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
            ntCreate['Data']       = smb.SMBNtCreateAndX_Data()
            ntCreate['Parameters']['FileNameLength'] = len(self.pipe)
            ntCreate['Parameters']['FileAttributes'] = 0x80
            ntCreate['Parameters']['CreateFlags'] = 0x0
            ntCreate['Parameters']['AccessMask'] = self.permissions
            ntCreate['Parameters']['CreateOptions'] = 0x40
            ntCreate['Parameters']['ShareAccess'] = 0x7
            ntCreate['Data']['FileName'] = self.pipe

            self.fid = self.server.nt_create_andx(self.tid,self.pipe,cmd=ntCreate)
 
            self.server.set_timeout(1000000)
        except:
            print "[!] Something wen't wrong connecting the pipes(%s), try again" % self.__class__


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.read_andx(self.tid,self.fid, max_size = 1024, wait_answer = 0 )
            except Exception, e: 
                pass
            else:
                if ans['Command'] == smb.SMB.SMB_COM_READ_ANDX:
                    try:
                        readAndXResponse   = smb.SMBCommand(ans['Data'][0])
                        readAndXParameters = smb.SMBReadAndXResponse_Parameters(readAndXResponse['Parameters'])
                        offset = readAndXParameters['DataOffset']
                        count = readAndXParameters['DataCount']+0x10000*readAndXParameters['DataCount_Hi']
                        if count > 0:
                            data = str(ans)[offset:offset+count]
                            global LastDataSent
                            if data != LastDataSent:
                                sys.stdout.write(str(ans)[offset:offset+count])
                                sys.stdout.flush()
                            else:
                                # Don't echo what I sent, and clear it up
                                LastDataSent = ''
                            # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars, 
                            # it will give false positives tho.. we should find a better way to handle this.
                            if LastDataSent > 10:
                                LastDataSent = ''
                        ans['Command'] = 0
                    except:
                        pass

class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.read_andx(self.tid,self.fid, max_size = 1024, wait_answer = 0 )
            except Exception, e: 
                pass
            else:
                if ans['Command'] == smb.SMB.SMB_COM_READ_ANDX:
                    try:
                        readAndXResponse   = smb.SMBCommand(ans['Data'][0])
                        readAndXParameters = smb.SMBReadAndXResponse_Parameters(readAndXResponse['Parameters'])
                        offset = readAndXParameters['DataOffset']
                        count = readAndXParameters['DataCount']+0x10000*readAndXParameters['DataCount_Hi']
                        if count > 0:
                            sys.stderr.write(str(ans)[offset:offset+count])
                            sys.stderr.flush()
                        ans['Command'] = 0
                    except:
                        pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        self.transferClient = smb.SMB('*SMBSERVER', self.server.get_remote_host(), sess_port = self.port)
        user, passwd, domain, lm, nt = self.credentials
        self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print """
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share)
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_get(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            print "[*] Downloading %s\%s" % (self.share, src_path)
            self.transferClient.retr_file(self.share, src_path, fh.write)
            fh.close()
        except Exception, e:
            print e
            pass

        self.send_data('\r\n')
 
    def do_put(self, s):
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
            pathname = string.replace(f,'/','\\')
            print "[*] Uploading %s to %s\%s" % (src_file, self.share, dst_path)
            self.transferClient.stor_file(self.share, pathname, fh.read)
            fh.close()
        except Exception, e:
            print e
            pass

        self.send_data('\r\n')


    def do_lcd(self, s):
        if s == '':
            print os.getcwd()
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        self.send_data(line+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.write_andx(self.tid, self.fid, data, wait_answer = 0)


class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share)
        self.shell.cmdloop()


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('command', action='store', help='command to execute at the target (w/o path)')
    parser.add_argument('-path', action='store', help='path of the command to execute')
    parser.add_argument('-file', action='store', help="alternative RemCom binary (be sure it doesn't require CRT)")
    parser.add_argument('protocol', choices=PSEXEC.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if domain is None:
        domain = ''

    executer = PSEXEC(options.command, options.path, options.file, options.protocol, username, password, domain, options.hashes)
    executer.run(address)
