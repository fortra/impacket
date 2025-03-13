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
#   Mini shell using some of the SMB funcionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#
from __future__ import division
from __future__ import print_function
from io import BytesIO
import sys
import time
import cmd
import os
import ntpath

from six import PY2
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY

import charset_normalizer as chardet


class MiniImpacketShell(cmd.Cmd):
    def __init__(self, smbClient, tcpShell=None, outputfile=None):
        #If the tcpShell parameter is passed (used in ntlmrelayx),
        # all input and output is redirected to a tcp socket
        # instead of to stdin / stdout

        import readline
        readline.backend = 'readline'

        if tcpShell is not None:
            cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
            sys.stdout = tcpShell.stdout
            sys.stdin = tcpShell.stdin
            sys.stderr = tcpShell.stdout
            self.use_rawinput = False
            self.shell = tcpShell
        else:
            cmd.Cmd.__init__(self)
            self.shell = None

        self.prompt = '# '
        self.smb = smbClient
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.outputfile = outputfile

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
            f.write('> ' + line + "\n")
            f.close()
        if PY2:
            return line.decode('utf-8')
        return line

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception as e:
           LOG.error(e)
           LOG.debug('Exception info', exc_info=True)

        return retVal

    def do_exit(self,line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print(output)
        self.last_output = output

    def do_help(self,line):
        print("""
 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 lls {dirname} - lists all the files on the local filesystem.
 tree {filepath} - recursively lists all files in folder and sub folders
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

""")

    def do_password(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        from getpass import getpass
        newPassword = getpass("New Password:")
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\samr', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        samr.hSamrUnicodeChangePasswordUser2(dce, '\x00', self.username, self.password, newPassword, self.lmhash, self.nthash)
        self.password = newPassword
        self.lmhash = None
        self.nthash = None

    def do_open(self,line):
        l = line.split(' ')
        port = 445
        if len(l) > 0:
           host = l[0]
        if len(l) > 1:
           port = int(l[1])


        if port == 139:
            self.smb = SMBConnection('*SMBSERVER', host, sess_port=port)
        else:
            self.smb = SMBConnection(host, host, sess_port=port)

        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            LOG.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            LOG.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            LOG.info("SMBv2.1 dialect used")
        else:
            LOG.info("SMBv3.0 dialect used")

        self.share = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.login(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_kerberos_login(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]

        if username.find('/') > 0:
           domain, username = username.split('/')

        if domain == '':
            LOG.error("Domain must be specified for Kerberos login")
            return

        if password == '' and username != '':
            from getpass import getpass
            password = getpass("Password:")

        self.smb.kerberosLogin(username, password, domain=domain)
        self.password = password
        self.username = username

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_login_hash(self,line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        l = line.split(' ')
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           hashes = l[1]
        else:
           LOG.error("Hashes needed. Format is lmhash:nthash")
           return

        if username.find('/') > 0:
           domain, username = username.split('/')

        lmhash, nthash = hashes.split(':')

        self.smb.login(username, '', domain,lmhash=lmhash, nthash=nthash)
        self.username = username
        self.lmhash = lmhash
        self.nthash = nthash

        if self.smb.isGuestSession() > 0:
            LOG.info("GUEST Session Granted")
        else:
            LOG.info("USER Session Granted")
        self.loggedIn = True

    def do_logoff(self, line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        self.smb.logoff()
        del self.smb
        self.share = None
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def do_info(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrServerGetInfo(dce, 102)

        print("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
        print("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
        print("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
        print("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
        print("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
        print("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])

    def do_who(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            print("host: %15s, user: %5s, active: %5d, idle: %5d" % (
            session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
            session['sesi10_idle_time']))

    def do_shares(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        resp = self.smb.listShares()
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        for i in range(len(resp)):
            if self.outputfile:
                f.write(resp[i]['shi1_netname'][:-1] + '\n')
            print(resp[i]['shi1_netname'][:-1])
        if self.outputfile:
            f.close()

    def do_use(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        self.share = line
        self.tid = self.smb.connectTree(line)
        self.pwd = '\\'
        self.do_ls('', False)

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def do_cd(self, line):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = line.replace('/','\\')
        oldpwd = self.pwd
        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE, desiredAccess = FILE_READ_DATA |
                                   FILE_LIST_DIRECTORY, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE )
            self.smb.closeFile(self.tid,fid)
        except SessionError:
            self.pwd = oldpwd
            raise

    def do_lcd(self, s):
        print(s)
        if s == '':
           print(os.getcwd())
        else:
           os.chdir(s)

    def do_pwd(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        print(self.pwd.replace("\\","/"))
        if self.outputfile is not None:        
            f = open(self.outputfile, 'a')
            f.write(self.pwd.replace("\\","/"))
            f.close()

    def do_ls(self, wildcard, display = True):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        if wildcard == '':
           pwd = ntpath.join(self.pwd,'*')
        else:
           pwd = ntpath.join(self.pwd, wildcard)
        self.completion = []
        pwd = pwd.replace('/','\\')
        pwd = ntpath.normpath(pwd)
        if self.outputfile is not None:
            of = open(self.outputfile, 'a')
        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                if self.outputfile:
                    of.write("%crw-rw-rw- %10d  %s %s" % (
                    'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                    f.get_longname()) + "\n")
                
                print("%crw-rw-rw- %10d  %s %s" % (
                'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                f.get_longname()))
            self.completion.append((f.get_longname(), f.is_directory()))
        if self.outputfile:
            of.close()
    
    def do_lls(self, currentDir):
        if currentDir == "":
            currentDir = "./"
        else:
            pass
        for LINE in os.listdir(currentDir):
            print(LINE)

    def do_listFiles(self, share, ip):
        retList = []
        retFiles = []
        retInt = 0
        try:                
            for LINE in self.smb.listPath(self.share, ip):
                if(LINE.get_longname() == "." or LINE.get_longname() == ".."):
                    pass
                else:
                    retInt = retInt + 1
                    print(ip.strip("*").replace("//","/") + LINE.get_longname())
                    if(LINE.is_directory()):
                        retval = ip.strip("*").replace("//","/") + LINE.get_longname()
                        retList.append(retval)
                    else:
                        retval = ip.strip("*").replace("//","/") + LINE.get_longname()
                        retFiles.append(retval)
        except:
            pass
        return retList,retFiles,retInt

    def do_tree(self, filepath):
        folderList = []
        retList = []
        totalFilesRead = 0
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return

        filepath = filepath.replace("\\", "/")
        if not filepath.startswith("/"):
            filepath = self.pwd.replace("\\", "/")  + "/" + filepath
        if(not filepath.endswith("/*")):
            filepath = filepath + "/*"
        filepath = os.path.abspath(filepath).replace("//","/")

        for LINE in self.smb.listPath(self.share, filepath):
            if(LINE.is_directory()):
                if(LINE.get_longname() == "." or LINE.get_longname() == ".."):
                    pass
                else:
                    totalFilesRead = totalFilesRead + 1 
                    folderList.append(filepath.strip("*") + LINE.get_longname())
            else:
                print(filepath.strip("*") + LINE.get_longname())
        for ITEM in folderList:
            ITEM = ITEM + "/*"
            try: 
                retList, retFiles, retInt = self.do_listFiles(self.share,ITEM)
                for q in retList:
                    folderList.append(q)
                totalFilesRead = totalFilesRead + retInt
            except:
                pass
        print("Finished - " + str(totalFilesRead) + " files and folders")

    def do_rm(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = f.replace('/','\\')
        self.smb.deleteFile(self.share, file)

    def do_mkdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/','\\')
        self.smb.deleteDirectory(self.share, pathname)

    def do_put(self, pathname):
        if self.tid is None:
            LOG.error("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = f.replace('/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = line.replace('/','\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return  [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def do_mget(self, mask):
        if mask == '':
            LOG.error("A mask must be provided")
            return
        if self.tid is None:
            LOG.error("No share selected")
            return
        self.do_ls(mask,display=False)
        if len(self.completion) == 0:
            LOG.error("No files found matching the provided mask")
            return 
        for file_tuple in self.completion:
            if file_tuple[1] == 0:
                filename = file_tuple[0]
                filename = filename.replace('/', '\\')
                fh = open(ntpath.basename(filename), 'wb')
                pathname = ntpath.join(self.pwd, filename)
                try:
                    LOG.info("Downloading %s" % (filename))
                    self.smb.getFile(self.share, pathname, fh.write)
                except:
                    fh.close()
                    os.remove(filename)
                    raise
                fh.close()

    def do_get(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = open(ntpath.basename(filename),'wb')
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFile(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

    def do_cat(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = BytesIO()
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFile(self.share, pathname, fh.write)
        except:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
        if self.outputfile is not None:
            f = open(self.outputfile, 'a')
        if encoding:
            try:
                if self.outputfile:
                    f.write(output.decode(encoding) + '\n')
                    f.close()
                print(output.decode(encoding))
            except:
                if self.outputfile:
                    f.write(error_msg + '\n')
                    f.close()
                print(error_msg)
            finally:
                fh.close()
        else:
            if self.outpufile:
                f.write(error_msg + '\n')
                f.close()
            print(error_msg)
            fh.close()

    def do_close(self, line):
        self.do_logoff(line)

    def do_list_snapshots(self, line):
        l = line.split(' ')
        if len(l) > 0:
            pathName= l[0].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        snapshotList = self.smb.listSnapshots(self.tid, pathName)

        if not snapshotList:
            print("No snapshots found")
            return

        for timestamp in snapshotList:
            print(timestamp)

    def do_mount(self, line):
        l = line.split(' ')
        if len(l) > 1:
            target  = l[0].replace('/','\\')
            pathName= l[1].replace('/','\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        self.smb.createMountPoint(self.tid, pathName, target)

    def do_umount(self, mountpoint):
        mountpoint = mountpoint.replace('/','\\')

        # Relative or absolute path?
        if mountpoint.startswith('\\') is not True:
            mountpoint = ntpath.join(self.pwd, mountpoint)

        mountPath = ntpath.join(self.pwd, mountpoint)

        self.smb.removeMountPoint(self.tid, mountPath)

    def do_EOF(self, line):
        print('Bye!\n')
        return True
