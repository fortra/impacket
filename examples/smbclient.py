#!/usr/bin/python
# Copyright (c) 2003-2011, Core SDI S.A., Argentina
# All rights reserved
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither name of the Core SDI S.A. nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# $Id$
# 
# mini shell to be used with impacket
#

import sys
import string
from impacket import smb
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, srvsvc
import cmd

class MiniImpacketShell(cmd.Cmd):    
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = '# '
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.share = None

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception, e:
           print "ERROR: %s" % e

        return retVal

    def do_exit(self,line):
        return True

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
        rpctransport = transport.SMBTransport(self.smb.get_remote_name(), self.smb.get_remote_host(), filename = r'\srvsvc', smb_server = self.smb)
        dce = dcerpc.DCERPC_v5(rpctransport)
        dce.connect()                     
        dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        srv_svc = srvsvc.DCERPCSrvSvc(dce)
        resp = srv_svc.get_share_enum_1(rpctransport.get_dip())
        for i in range(len(resp)):                        
                print resp[i]['NetName'].decode('utf-16')
	# Old Code in case you want to use the old SMB shares commands
        #for share in self.smb.list_shared():
        #    print "%s" % share.get_name()

    def do_use(self,line):
        self.share = line
        self.tid = self.smb.connect_tree(line)

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

    def do_put(self, filename):
        fh = open(filename, 'rb')
        f = self.pwd + '/' + filename
        pathname = string.replace(f,'/','\\')
        self.smb.stor_file(self.share, pathname, fh.read)
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
    shell = MiniImpacketShell()
    shell.cmdloop()

if __name__ == "__main__":
    main()

