# Copyright (c) 2003-2018 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Mini shell using some of the SMB funcionality of the library
#
# Author:
#  Alberto Solino (@agsolino)
#
#
# Reference for:
#  SMB DCE/RPC
#

import sys
import time
import cmd
import os
import random

from impacket import LOG
from impacket.dcerpc.v5 import samr, transport, srvs, lsad, lsat, tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *
from impacket.dcerpc.v5.samr import USER_NORMAL_ACCOUNT, GROUP_ALL_ACCESS
from impacket.dcerpc.v5.samr import USER_CONTROL_INFORMATION, \
    SAMPR_USER_INFO_BUFFER, MAXIMUM_ALLOWED
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.samr import USER_INFORMATION_CLASS

# convert all strings to unicode
def ensure_unicode(v):
    if isinstance(v, str):
        v = v.decode('utf-16-le')
    return unicode(v)


# If you wanna have readline like functionality in Windows, install pyreadline
try:
  import pyreadline as readline
except ImportError:
  import readline

class MiniImpacketShell(cmd.Cmd):
    def __init__(self, smbClient,tcpShell=None):
        #If the tcpShell parameter is passed (used in ntlmrelayx),
        # all input and output is redirected to a tcp socket
        # instead of to stdin / stdout
        if tcpShell is not None:
            cmd.Cmd.__init__(self,stdin=tcpShell,stdout=tcpShell)
            sys.stdout = tcpShell
            sys.stdin = tcpShell
            sys.stderr = tcpShell
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

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        return line.decode('utf-8')

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception, e:
           import traceback
           traceback.print_exc()
           LOG.error(e)

        return retVal

    def do_exit(self,line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_shell(self, line):
        output = os.popen(line).read()
        print output
        self.last_output = output

    def do_help(self,line):
        print """
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
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

"""

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

        print "Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major']
        print "Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor']
        print "Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name']
        print "Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment']
        print "Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath']
        print "Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users']

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
            print "host: %15s, user: %5s, active: %5d, idle: %5d" % (
            session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
            session['sesi10_idle_time'])

    def do_shares(self, line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        resp = self.smb.listShares()
        for i in range(len(resp)):
            print resp[i]['shi1_netname'][:-1]

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
        p = string.replace(line,'/','\\')
        oldpwd = self.pwd
        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE \
                                    , desiredAccess = FILE_READ_DATA | FILE_LIST_DIRECTORY \
                                    , shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE \
                                    )
            self.smb.closeFile(self.tid,fid)
        except SessionError:
            self.pwd = oldpwd
            raise

    def do_lcd(self, s):
        print s
        if s == '':
           print os.getcwd()
        else:
           os.chdir(s)

    def do_pwd(self,line):
        if self.loggedIn is False:
            LOG.error("Not logged in")
            return
        print self.pwd

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
        pwd = string.replace(pwd,'/','\\')
        pwd = ntpath.normpath(pwd)
        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                print "%crw-rw-rw- %10d  %s %s" % (
                'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                f.get_longname())
            self.completion.append((f.get_longname(), f.is_directory()))


    def do_rm(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = string.replace(f,'/','\\')
        self.smb.deleteFile(self.share, file)

    def do_mkdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = string.replace(p,'/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = string.replace(p,'/','\\')
        self.smb.deleteDirectory(self.share, pathname)

    def do_put(self, pathname):
        if self.tid is None:
            LOG.error("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = string.replace(f,'/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = string.replace(line,'/','\\')
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

    def do_get(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
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
        self.do_logoff(line)

    # different when sending over network or printed directly
    def _doprint(self, msg):
        if self.use_rawinput == True:
            print msg
        else:
            print msg.encode('utf-16-le')

    def do_enumgroups(self, line):
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        for domain in resp['Buffer']['Buffer']:
            domainName = domain['Name']
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domainName)
            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
            domain_handle = resp['DomainHandle']
            enumeration_context = 0
            while True:
                resp = samr.hSamrEnumerateGroupsInDomain(dce, domain_handle,
                                enumerationContext=enumeration_context)
                for group in resp['Buffer']['Buffer']:
                    groupName = group['Name']
                    if line != '':
                        if groupName == line:
                            group_rid = group['RelativeId']
                            resp2 = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)
                            alias_handle = resp2['GroupHandle']
                            resp2 = samr.hSamrGetMembersInGroup(dce, alias_handle)
                            rids = resp2['Members']['Members']
                            for rid in rids:
                                rid = rid['Data']
                                resp2 = samr.hSamrLookupIdsInDomain(dce, domain_handle, (rid,))
                                userName = resp2['Names']['Element'][0]['Data']
                                msg = u"{}\\{}".format(ensure_unicode(domainName), ensure_unicode(userName))
                                self._doprint(msg)

                    else:
                        msg = ensure_unicode(groupName)
                        self._doprint(msg)

                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break
            enumeration_context = 0
            while True:
                resp = samr.hSamrEnumerateAliasesInDomain(dce, domain_handle,
                                enumerationContext=enumeration_context)
                for group in resp['Buffer']['Buffer']:
                    groupName = group['Name']
                    if line != '':
                        if groupName == line:
                            group_rid = group['RelativeId']
                            resp2 = samr.hSamrOpenAlias(dce, domain_handle, aliasId=group_rid)
                            alias_handle = resp2['AliasHandle']
                            resp2 = samr.hSamrGetMembersInAlias(dce, alias_handle)
                            sids = [x['Data']['SidPointer'].formatCanonical() for x in resp2['Members']['Sids']]
                            rpctransport2 = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
                            dce2 = rpctransport.get_dce_rpc()
                            dce2.connect()
                            dce2.bind(lsad.MSRPC_UUID_LSAD)
                            resp3 = lsad.hLsarOpenPolicy2(dce2)
                            policy_handle = resp3['PolicyHandle']
                            resp3 = lsat.hLsarLookupSids(dce2, policy_handle, sids)
                            for user in resp3['TranslatedNames']['Names']:
                                userName = user['Name']
                                msg = u"{}\\{}".format(ensure_unicode(domainName), ensure_unicode(userName))
                                self._doprint(msg)
                    else:
                        msg = ensure_unicode(groupName)
                        self._doprint(msg)

                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break

    def do_enumusers(self, line):
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        #print 'Get ServerHandle'
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)

        for domain in resp['Buffer']['Buffer']:
            domainName = domain['Name']

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domainName)
            domainId = resp['DomainId']

            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=domainId)
            domain_handle = resp['DomainHandle']

            # we enumerate the users
            enumeration_context = 0
            while True:
                resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle,
                            enumerationContext=enumeration_context)
                for user in resp['Buffer']['Buffer']:
                    userName = user['Name']
                    msg = u"{}\\{}".format(ensure_unicode(domainName), ensure_unicode(userName))
                    self._doprint(msg)
                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break
            samr.hSamrCloseHandle(dce, domain_handle)
        samr.hSamrCloseHandle(dce, server_handle)

    def do_enumdomain(self, line):
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)

        #FIXME
        print [x['Name'] for x in resp['Buffer']['Buffer']]
        samr.hSamrCloseHandle(dce, server_handle)

    def do_adduser(self, line):
        if ' ' in line:
            newUser, newPassword = line.split(' ', 1)
        else:
            newUser = line
            from getpass import getpass
            newPassword = getpass("New Password:")
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        #print 'Get ServerHandle'
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        for domain in resp['Buffer']['Buffer']:
            domainName = domain['Name']

            if domainName == u'Builtin':
                continue

            #print 'Get domainsid'
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domainName)
            domain_sid = resp['DomainId']

            #print 'Get domain handle'
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp['DomainHandle']

            #print 'creating user'
            resp = samr.hSamrCreateUser2InDomain(dce, domain_handle, newUser, accountType=USER_NORMAL_ACCOUNT, desiredAccess=GROUP_ALL_ACCESS)
            user_handle = resp['UserHandle']
            user_rid = resp['RelativeId']

            #print 'setting password'
            samr.hSamrChangePasswordUser(dce, user_handle, '', newPassword)

            samr.hSamrCloseHandle(dce, user_handle)

            #print 'getting user handle'
            resp = samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)
            user_handle = resp['UserHandle']

            #print 'activating'
            control = USER_CONTROL_INFORMATION()
            control['UserAccountControl'] = 0x10
            newbuf = SAMPR_USER_INFO_BUFFER()
            newbuf.__setitem__('tag', USER_INFORMATION_CLASS.UserControlInformation)
            newbuf['Control'] = control
            samr.hSamrSetInformationUser2(dce, user_handle, newbuf)
            #print 'activated'
            samr.hSamrCloseHandle(dce, user_handle)
            samr.hSamrCloseHandle(dce, domain_handle)
        samr.hSamrCloseHandle(dce, server_handle)

    def do_deluser(self, line):
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        #print 'Get ServerHandle'
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']

        user_sid = None
        alias_handle = None

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        for domain in resp['Buffer']['Buffer']:
            domainName = domain['Name']

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domainName)
            domainId = resp['DomainId']

            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=domainId)
            domain_handle = resp['DomainHandle']

            enumeration_context = 0
            while user_sid is None:
                resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=enumeration_context)
                for user in resp['Buffer']['Buffer']:
                    if user['Name'] == line:
                        user_rid = user['RelativeId']
                        resp2 = samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)
                        user_handle = resp2['UserHandle']
                        samr.hSamrDeleteUser(dce, user_handle)
                        break
                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break
            samr.hSamrCloseHandle(dce, domain_handle)
        samr.hSamrCloseHandle(dce, server_handle)

    def do_addusertoadmingroup(self, line):
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost, filename=r'\samr', smb_connection=self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        #print 'Get ServerHandle'
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']

        user_sid = None
        alias_handle = None

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        for domain in resp['Buffer']['Buffer']:
            domainName = domain['Name']

            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domainName)
            domainId = resp['DomainId']

            resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=domainId)
            domain_handle = resp['DomainHandle']

            # we enumerate the users
            enumeration_context = 0
            while user_sid is None:
                resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=enumeration_context)
                for user in resp['Buffer']['Buffer']:
                    if user['Name'] == line:
                        user_rid = user['RelativeId']
                        resp2 = samr.hSamrRidToSid(dce, domain_handle, user_rid)
                        user_sid = resp2['Sid']
                        break
                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break

            # Then we can finally enumerate the groups
            enumeration_context = 0
            while alias_handle is None:
                resp = samr.hSamrEnumerateAliasesInDomain(dce, domain_handle, enumerationContext=enumeration_context)
                for alias in resp['Buffer']['Buffer']:
                    rid = alias['RelativeId']
                    # add to Domain Admins or Administrators group
                    if rid == 520 or rid == 544:
                        groupName = alias['Name']
                        resp2 = samr.hSamrOpenAlias(dce, domain_handle, aliasId=rid)
                        alias_handle = resp2['AliasHandle']
                        break
                enumeration_context = resp['EnumerationContext']
                if resp['ErrorCode'] != STATUS_MORE_ENTRIES:
                    break
            samr.hSamrCloseHandle(dce, domain_handle)

        if user_sid is not None and alias_handle is not None:
            LOG.info('adding to group {}'.format(ensure_unicode(groupName)))
            samr.hSamrAddMemberToAlias(dce, alias_handle, user_sid)

        samr.hSamrCloseHandle(dce, alias_handle)
        samr.hSamrCloseHandle(dce, server_handle)
