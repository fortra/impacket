#!/usr/bin/python

# Copyright (c) 2002, Core SDI S.A., Argentina
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

# 
# mini shell to be used with impacket
#

import sys
import string
from impacket import smb


class MiniImpacketShell:    
    def __init__(self):
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.share = None

    def eval(self, s):
        l = string.split(s, ' ')
        cmd = l[0]
        
        try:        
            f = MiniImpacketShell.__dict__[cmd]
            l[0] = self
            f(*l)
        except Exception, e:
            print "exception! %s" % e

    def run(self):
        s = raw_input('# ')
        while s:
            if s == 'exit':
              break
            self.eval(s)
            s = raw_input('# ')

    def help(self):
        print """
 open {host,port} - opens a SMB connection against the target host/port
 login {username,passwd} - logs into the current SMB connection
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
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

 An empty line finishes the session
 NOTE: the server is not terminated, although it is left unusable
"""

    def open(self,host,port):
        self.smb = smb.SMB("*SMBSERVER", host, port)

    def login(self,username, password):
        self.smb.login(username, password)

    def login_hash(self,username, lmhash, nthash):
        self.smb.login(username, '', lmhash=lmhash, nthash=nthash)

    def logoff(self):
        self.smb.logoff()

    def shares(self):
        for share in self.smb.list_shared():
            print "%s" % share.get_name()

    def use(self,sharename):
        self.share = sharename
        self.tid = self.smb.tree_connect(sharename)

    def cd(self, path):
        p = string.replace(path,'/','\\')
        if p[0] == '\\':
           self.pwd = path
        else:
           self.pwd += '/' + path

    def pwd(self):
        print self.pwd

    def ls(self, wildcard = None):
        if wildcard == None:
           pwd = self.pwd + '/*'
        else:
           pwd = self.pwd + '/' + wildcard
        for f in self.smb.list_path(self.share, pwd):
           print "%s" % f.get_longname()

    def rm(self, filename):
        f = self.pwd + '/' + filename
        file = string.replace(f,'/','\\')
        self.smb.remove(self.share, file)
 
    def mkdir(self, path):
        p = self.pwd + '/' + path
        pathname = string.replace(p,'/','\\')
        self.smb.mkdir(self.share,pathname)

    def rmdir(self, path):
        p = self.pwd + '/' + path
        pathname = string.replace(p,'/','\\')
        self.smb.rmdir(self.share, pathname)

    def put(self, filename):
        fh = open(filename, 'rb')
        f = self.pwd + '/' + filename
        pathname = string.replace(f,'/','\\')
        self.smb.stor_file(self.share, pathname, fh.read)
        fh.close()

    def get(self, filename):
        fh = open(filename,'wb')
        f = self.pwd + '/' + filename
        pathname = string.replace(f,'/','\\')
        self.smb.retr_file(self.share, pathname, fh.write)
        fh.close()

    def close(self):
        self.smb.close();

def main():
    shell = MiniImpacketShell()
    shell.run()

if __name__ == "__main__":
    main()

