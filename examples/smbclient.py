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
from impacket import smb, version
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, srvsvc
import argparse
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
 open {host,port,remote_name = '*SMBSERVER'} - opens a SMB connection against the target host/port
 login {username,passwd,domain} - logs into the current SMB connection, no parameters for NULL connection
 login_hash {username,lmhash,nthash} - logs into the current SMB connection using the password hashes
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
        if len(l) > 2:
           remote_name = l[2]
        else:
           remote_name = '*SMBSERVER'

        self.smb = smb.SMB(remote_name, host, sess_port=int(port))

    def do_login(self,line):
        l = line.split(' ')
        username = ''
        password = ''
        domain = ''
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           password = l[1]
        if len(l) > 2:
           domain = l[2]

        self.smb.login(username, password, domain=domain)
        if self.smb.isGuestSession() > 0:
            print "GUEST Session Granted"
        else:
            print "USER Session Granted" 

    def do_login_hash(self,line): 
        l = line.split(' ')
        if len(l) > 0:
           username = l[0]
        if len(l) > 1:
           lmhash = l[1]
        if len(l) > 2:
           nthash = l[2]

        self.smb.login(username, '', lmhash=lmhash, nthash=nthash)

    def do_logoff(self, line):
        self.smb.logoff()

    def do_info(self, line):
        rpctransport = transport.SMBTransport(self.smb.get_remote_name(), self.smb.get_remote_host(), filename = r'\srvsvc', smb_server = self.smb)
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
        try:
            rpctransport = transport.SMBTransport(self.smb.get_remote_name(), self.smb.get_remote_host(), filename = r'\srvsvc', smb_server = self.smb)
            dce = dcerpc.DCERPC_v5(rpctransport)
            dce.connect()                     
            dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
            srv_svc = srvsvc.DCERPCSrvSvc(dce)
            resp = srv_svc.get_share_enum_1(rpctransport.get_dip())
            for i in range(len(resp)):                        
                print resp[i]['NetName'].decode('utf-16')
        except:
	    # Old Code in case you want to use the old SMB shares commands
            for share in self.smb.list_shared():
                print "%s" % share.get_name()

    def do_use(self,line):
        self.share = line
        self.tid = self.smb.connect_tree(line)
        self.pwd = ''

    def do_cd(self, line):
        p = string.replace(line,'/','\\')
        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd += '/' + line

    def do_pwd(self,line):
        print self.pwd

    def do_ls(self, wildcard):
        if wildcard == '':
           pwd = self.pwd + '/*'
        else:
           pwd = self.pwd + '/' + wildcard
        for f in self.smb.list_path(self.share, pwd):
           print "%s" % f.get_longname()

    def do_rm(self, filename):
        f = self.pwd + '/' + filename
        file = string.replace(f,'/','\\')
        self.smb.remove(self.share, file)
 
    def do_mkdir(self, path):
        p = self.pwd + '/' + path
        pathname = string.replace(p,'/','\\')
        self.smb.mkdir(self.share,pathname)

    def do_rmdir(self, path):
        p = self.pwd + '/' + path
        pathname = string.replace(p,'/','\\')
        self.smb.rmdir(self.share, pathname)

    def do_put(self, pathname):
        params = pathname.split(' ')
        if len(params) > 1:
            src_path = params[0]
            dst_name = params[1]
        elif len(params) == 1:
            src_path = params[0]
            dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = self.pwd + '/' + dst_name
        finalpath = string.replace(f,'/','\\')
        self.smb.stor_file(self.share, finalpath, fh.read)
        fh.close()

    def do_get(self, filename):
        fh = open(filename,'wb')
        f = self.pwd + '/' + filename
        pathname = string.replace(f,'/','\\')
        self.smb.retr_file(self.share, pathname, fh.write)
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
            print "# %s" % line,
            shell.onecmd(line)




if __name__ == "__main__":
    try:
        main()
    except:
        print "\n"
        pass

