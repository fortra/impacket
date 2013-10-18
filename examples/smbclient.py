#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: Mini shell using some of the SMB funcionality of the library
#
# Author:
#  Alberto Solino
#
# 
# Reference for:
#  SMB DCE/RPC 
#

import sys
import string
from impacket import smb, version, smb3, nt_errors
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, srvsvc
from impacket.nt_errors import *
from impacket.smbconnection import *
import argparse
import ntpath
import cmd
import os

class MiniImpacketShell(cmd.Cmd):    
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = '# '
        self.smb = None
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None

    def emptyline(self):
        pass

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception, e:
           #import traceback
           #print traceback.print_exc()
           print "ERROR: %s" % e

        return retVal

    def do_exit(self,line):
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print output
        self.last_output = output

    def do_help(self,line):
        print """
 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 pwd - shows current remote directory
 ls {wildcard} - lists all the files in the current directory
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 info - Return NetrServerInfo main results
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

"""

    def do_open(self,line):
        l = line.split(' ')
        port = 445
        if len(l) > 0:
           host = l[0]
        if len(l) > 1:
           port = l[1]

        self.smb = SMBConnection(host, host, sess_port=int(port))

        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            print "SMBv1 dialect used"
        elif dialect == SMB2_DIALECT_002:
            print "SMBv2.0 dialect used"
        elif dialect == SMB2_DIALECT_21:
            print "SMBv2.1 dialect used"
        else:
            print "SMBv3.0 dialect used"

    def do_login(self,line):
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

        if self.smb.isGuestSession() > 0:
            print "GUEST Session Granted"
        else:
            print "USER Session Granted" 

    def do_login_hash(self,line): 
        l = line.split(' ')
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           hashes = l[1]
        else:
           print "Hashes needed. Format is lmhash:nthash"
           return

        if username.find('/') > 0:
           domain, username = username.split('/')
       
        lmhash, nthash = hashes.split(':')

        self.smb.login(username, '', domain,lmhash=lmhash, nthash=nthash)

        if self.smb.isGuestSession() > 0:
            print "GUEST Session Granted"
        else:
            print "USER Session Granted"

    def do_logoff(self, line):
        self.smb.logoff()

    def do_info(self, line):
        rpctransport = transport.SMBTransport(self.smb.getServerName(), self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = dcerpc.DCERPC_v5(rpctransport)
        dce.connect()                     
        dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        srv_svc = srvsvc.DCERPCSrvSvc(dce)
        resp = srv_svc.get_server_info_102(rpctransport.get_dip())
        print "Version Major: %d" % resp['VersionMajor']
        print "Version Minor: %d" % resp['VersionMinor']
        print "Server Name: %s" % resp['Name']
        print "Server Comment: %s" % resp['Comment']
        print "Server UserPath: %s" % resp['UserPath']
        print "Simultaneous Users: %d" % resp['Users']
         
    def do_shares(self, line):
        resp = self.smb.listShares()
        for i in range(len(resp)):                        
            print resp[i]['NetName'].decode('utf-16')

    def do_use(self,line):
        self.share = line
        self.tid = self.smb.connectTree(line)
        self.pwd = '\\'

    def do_cd(self, line):
        p = string.replace(line,'/','\\')
        oldpwd = self.pwd
        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd)
            self.smb.closeFile(self.tid,fid)
            self.pwd = oldpwd
        except Exception, e:
            if (e.get_error_code() & 0xff) == (STATUS_FILE_IS_A_DIRECTORY & 0xff):
               pass
            else:
               self.pwd = oldpwd
               raise
            

    def do_pwd(self,line):
        print self.pwd

    def do_ls(self, wildcard):
        if wildcard == '':
           pwd = ntpath.join(self.pwd,'*')
        else:
           pwd = ntpath.join(self.pwd, wildcard)
        pwd = string.replace(pwd,'/','\\')
        pwd = ntpath.normpath(pwd)
        for f in self.smb.listPath(self.share, pwd):
           print "%s" % f.get_longname()

    def do_rm(self, filename):
        f = ntpath.join(self.pwd, filename)
        file = string.replace(f,'/','\\')
        self.smb.deleteFile(self.share, file)
 
    def do_mkdir(self, path):
        p = ntpath.join(self.pwd, path)
        pathname = string.replace(p,'/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        p = ntpath.join(self.pwd, path)
        pathname = string.replace(p,'/','\\')
        self.smb.deleteDirectory(self.share, pathname)

    def do_put(self, pathname):
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = string.replace(f,'/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def do_get(self, filename):
        filename = string.replace(filename,'/','\\')
        fh = open(ntpath.basename(filename),'wb')
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFile(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

    def do_close(self, line):
        del(self.smb);

def main():
    print version.BANNER

    shell = MiniImpacketShell()
    if len(sys.argv)==1:
        shell.cmdloop()
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
        options = parser.parse_args()
        print "Executing commands from %s" % options.file.name
        for line in options.file.readlines():
            if line[0] != '#':
                print "# %s" % line,
                shell.onecmd(line)
            else:
                print line,

if __name__ == "__main__":
    try:
        main()
    except:
        print "\n"
        pass

