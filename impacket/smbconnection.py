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
#   Wrapper class for SMB1/2/3 so it's transparent for the client.
#   You can still play with the low level methods (version dependent)
#   by calling getSMBServer()
#
# Author: Alberto Solino (@agsolino)
#

import ntpath
import socket

from impacket import smb, smb3, smb3structs, nmb, nt_errors, LOG
from impacket.ntlm import compute_lmhash, compute_nthash

# Propagated imports to clients.
## Dialects.
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_311

## Create Disposition.
from impacket.smb import FILE_OPEN, FILE_OVERWRITE, FILE_OVERWRITE_IF
from impacket.smb3structs import FILE_OPEN_REPARSE_POINT

## Create Options.
from impacket.smb import FILE_NON_DIRECTORY_FILE
from impacket.smb3structs import FILE_ATTRIBUTE_NORMAL, FILE_SYNCHRONOUS_IO_NONALERT

## Access Mask.
from impacket.smb import FILE_READ_DATA , FILE_WRITE_DATA, GENERIC_READ, GENERIC_WRITE, GENERIC_ALL, READ_CONTROL, \
                         FILE_READ_ATTRIBUTES, FILE_READ_EA, SYNCHRONIZE

## Share Access Modes.
from impacket.smb import FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE


class SMBConnection:
    """
    SMBConnection class

    :param str remoteName: The name of the remote host, can be its NETBIOS name, IP or *\\*SMBSERVER*.  
                           If the later, and port is 139, the library will try to get the target's server name.
    :param str remoteHost: Target server's remote address (IPv4, IPv6) or FQDN
    :param optional str myName: The client's NETBIOS name
    :param optional int sess_port: A target port to connect
    :param optional int timeout: Timeout in seconds when receiving packets
    :param optional int/str preferredDialect: The dialect desired to talk with the target server. If not specified the highest
           one available will be used
    :param optional bool manualNegotiate: Lets the user manually perform SMB_COM_NEGOTIATE.

    :return: An SMBConnection instance.
    :raise SessionError: If encountered an error.
    """
    def __init__(self, remoteName='', remoteHost='', myName=None, sess_port=nmb.SMB_SESSION_PORT, timeout=60, preferredDialect=None,
                 existingConnection=None, manualNegotiate=False):

        self._SMBConnection = 0
        self._dialect       = ''
        self._nmbSession    = 0
        self._sess_port     = sess_port
        self._myName        = myName
        self._remoteHost    = remoteHost
        self._remoteName    = remoteName
        self._timeout       = timeout
        self._preferredDialect = preferredDialect
        self._existingConnection = existingConnection
        self._manualNegotiate = manualNegotiate
        self._doKerberos = False
        self._kdcHost = None
        self._useCache = True
        self._ntlmFallback = True

        if existingConnection is not None:
            # Existing Connection must be a smb or smb3 instance
            assert ( isinstance(existingConnection,smb.SMB) or isinstance(existingConnection, smb3.SMB3))
            self._SMBConnection = existingConnection
            self._preferredDialect = self._SMBConnection.getDialect()
            self._doKerberos = self._SMBConnection.getKerberos()
            return

        ##preferredDialect = smb.SMB_DIALECT

        if manualNegotiate is False:
            self.negotiateSession(preferredDialect)

    def negotiateSession(self, preferredDialect=None,
                         flags1=smb.SMB.FLAGS1_PATHCASELESS | smb.SMB.FLAGS1_CANONICALIZED_PATHS,
                         flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES,
                         negoData='\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'):
        """
        Perform SMB protocol negotiation.

        :param optional int/str preferredDialect: The dialect desired to talk with the target server. 
                                                  If None is specified the highest one available will be used
        :param optional int flags1: The SMB FLAGS capabilities
        :param optional int flags2: The SMB FLAGS2 capabilities
        :param optional bytes negoData: Data to be sent as part of the nego handshake.

        :return: True
        :raise SessionError: If encountered an error.
        """

        # If port 445 and the name sent is *SMBSERVER we're setting the name to the IP. This is to help some old
        # applications still believing
        # *SMSBSERVER will work against modern OSes. If port is NETBIOS_SESSION_PORT the user better know about i
        # *SMBSERVER's limitations
        if self._sess_port == nmb.SMB_SESSION_PORT and self._remoteName == '*SMBSERVER':
            self._remoteName = self._remoteHost
        elif self._sess_port == nmb.NETBIOS_SESSION_PORT and self._remoteName == '*SMBSERVER':
            # If remote name is *SMBSERVER let's try to query its name.. if can't be guessed, continue and hope for the best
            nb = nmb.NetBIOS()
            try:
                res = nb.getnetbiosname(self._remoteHost)
            except:
                pass
            else:
                self._remoteName = res

        if self._sess_port == nmb.NETBIOS_SESSION_PORT:
            negoData = '\x02NT LM 0.12\x00\x02SMB 2.002\x00'

        hostType = nmb.TYPE_SERVER
        if preferredDialect is None:
            # If no preferredDialect sent, we try the highest available one.
            packet = self.negotiateSessionWildcard(self._myName, self._remoteName, self._remoteHost, self._sess_port,
                                                   self._timeout, True, flags1=flags1, flags2=flags2, data=negoData)
            if packet[0:1] == b'\xfe':
                # Answer is SMB2 packet
                self._SMBConnection = smb3.SMB3(self._remoteName, self._remoteHost, self._myName, hostType,
                                                self._sess_port, self._timeout, session=self._nmbSession,
                                                negSessionResponse=smb3structs.SMB2Packet(packet))
            else:
                # Answer is SMB packet, sticking to SMBv1
                self._SMBConnection = smb.SMB(self._remoteName, self._remoteHost, self._myName, hostType,
                                              self._sess_port, self._timeout, session=self._nmbSession,
                                              negPacket=packet)
        else:
            if preferredDialect == smb.SMB_DIALECT:
                self._SMBConnection = smb.SMB(self._remoteName, self._remoteHost, self._myName, hostType,
                                              self._sess_port, self._timeout)
            elif preferredDialect in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_311]:
                self._SMBConnection = smb3.SMB3(self._remoteName, self._remoteHost, self._myName, hostType,
                                                self._sess_port, self._timeout, preferredDialect=preferredDialect)
            else:
                raise Exception("Unknown dialect %s")

        # propagate flags to the smb sub-object, except for Unicode (if server supports)
        # does not affect smb3 objects
        if isinstance(self._SMBConnection, smb.SMB):
            if self._SMBConnection.get_flags()[1] & smb.SMB.FLAGS2_UNICODE:
                flags2 |= smb.SMB.FLAGS2_UNICODE
            self._SMBConnection.set_flags(flags1=flags1, flags2=flags2)

        return True

    def negotiateSessionWildcard(self, myName, remoteName, remoteHost, sess_port, timeout, extended_security=True, flags1=0,
                                 flags2=0, data=None):
        # Here we follow [MS-SMB2] negotiation handshake trying to understand what dialects
        # (including SMB1) is supported on the other end.

        if not myName:
            myName = socket.gethostname()
            i = myName.find('.')
            if i > -1:
                myName = myName[:i]

        tries = 0
        smbp = smb.NewSMBPacket()
        smbp['Flags1'] = flags1
        # FLAGS2_UNICODE is required by some stacks to continue, regardless of subsequent support
        smbp['Flags2'] = flags2 | smb.SMB.FLAGS2_UNICODE
        resp = None
        while tries < 2:
            self._nmbSession = nmb.NetBIOSTCPSession(myName, remoteName, remoteHost, nmb.TYPE_SERVER, sess_port,
                                                     timeout)

            negSession = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
            if extended_security is True:
                smbp['Flags2'] |= smb.SMB.FLAGS2_EXTENDED_SECURITY
            negSession['Data'] = data
            smbp.addCommand(negSession)
            self._nmbSession.send_packet(smbp.getData())

            try:
                resp = self._nmbSession.recv_packet(timeout)
                break
            except nmb.NetBIOSError:
                # OSX Yosemite asks for more Flags. Let's give it a try and see what happens
                smbp['Flags2'] |= smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | smb.SMB.FLAGS2_UNICODE
                smbp['Data'] = []

            tries += 1

        if resp is None:
            # No luck, quitting
            raise Exception('No answer!')

        return resp.get_trailer()

    def getNMBServer(self):
        return self._nmbSession

    def getSMBServer(self):
        """
        Returns the SMB/SMB3 instance being used. Useful for calling low level methods.
        """
        return self._SMBConnection

    def getDialect(self):
        return self._SMBConnection.getDialect()

    def getServerName(self):
        return self._SMBConnection.get_server_name()

    def getClientName(self):
        return self._SMBConnection.get_client_name()

    def getRemoteHost(self):
        return self._SMBConnection.get_remote_host()

    def getRemoteName(self):
        return self._SMBConnection.get_remote_name()

    def setRemoteName(self, name):
        return self._SMBConnection.set_remote_name(name)

    def getServerDomain(self):
        return self._SMBConnection.get_server_domain()

    def getServerDNSDomainName(self):
        return self._SMBConnection.get_server_dns_domain_name()

    def getServerDNSHostName(self):
        return self._SMBConnection.get_server_dns_host_name()

    def getServerOS(self):
        return self._SMBConnection.get_server_os()

    def getServerOSMajor(self):
        return self._SMBConnection.get_server_os_major()

    def getServerOSMinor(self):
        return self._SMBConnection.get_server_os_minor()

    def getServerOSBuild(self):
        return self._SMBConnection.get_server_os_build()

    def doesSupportNTLMv2(self):
        return self._SMBConnection.doesSupportNTLMv2()

    def isLoginRequired(self):
        return self._SMBConnection.is_login_required()

    def isSigningRequired(self):
        return self._SMBConnection.is_signing_required()

    def getCredentials(self):
        return self._SMBConnection.getCredentials()

    def getIOCapabilities(self):
        return self._SMBConnection.getIOCapabilities()

    def login(self, user, password, domain = '', lmhash = '', nthash = '', ntlmFallback = True):
        """
        Authenticates against the target system using NTLM.

        :param str user: Username.
        :param str password: Password for the user.
        :param optional str domain: Domain where the account is valid for.
        :param optional str lmhash: LMHASH used to authenticate using hashes (password is not used).
        :param optional str nthash: NTHASH used to authenticate using hashes (password is not used).
        :param optional bool ntlmFallback: If True it will try NTLMv1 authentication if NTLMv2 fails. 
                                           Only available for SMBv1.

        :return: None
        :raise SessionError: If encountered an error.
        """
        self._ntlmFallback = ntlmFallback
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                return self._SMBConnection.login(user, password, domain, lmhash, nthash, ntlmFallback)
            else:
                return self._SMBConnection.login(user, password, domain, lmhash, nthash)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def kerberosLogin(self, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
        """
        Authenticates against the target system using Kerberos.
        Hashes are used if RC4_HMAC is supported.

        :param str user: Username.
        :param str password: Password for the user.
        :param optional str domain: Domain where the account is valid for (required).
        :param optional str lmhash: LMHASH used to authenticate using hashes (password is not used).
        :param optional str nthash: NTHASH used to authenticate using hashes (password is not used).
        :param optional str aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication.
        :param optional str kdcHost: Hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho).
        :param optional struct TGT: If there's a TGT available, send the structure here and it will be used.
        :param optional struct TGS: Same for TGS. See smb3.py for the format.
        :param optional bool useCache: Whether or not we should use the ccache for credentials lookup.
                                       If TGT or TGS are specified this is False

        :return: None
        :raise SessionError: If encountered an error.
        """
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import KerberosError
        from impacket.krb5 import constants

        self._kdcHost = kdcHost
        self._useCache = useCache

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache:
            domain, user, TGT, TGS = CCache.parseFile(domain, user, 'cifs/%s' % self.getRemoteName())

        while True:
            try:
                if self.getDialect() == smb.SMB_DIALECT:
                    return self._SMBConnection.kerberos_login(user, password, domain, lmhash, nthash, aesKey, kdcHost,
                                                              TGT, TGS)
                return self._SMBConnection.kerberosLogin(user, password, domain, lmhash, nthash, aesKey, kdcHost, TGT,
                                                         TGS)
            except (smb.SessionError, smb3.SessionError) as e:
                raise SessionError(e.get_error_code(), e.get_error_packet())
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES.
                    # So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. 
                    # If that's already done, byebye.
                    if lmhash == '' and nthash == '' and (aesKey == '' or aesKey is None) and TGT is None and TGS is None:
                        lmhash = compute_lmhash(password)
                        nthash = compute_nthash(password)
                    else:
                        raise e
                else:
                    raise e

    def isGuestSession(self):
        try:
            return self._SMBConnection.isGuestSession()
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def logoff(self):
        try:
            return self._SMBConnection.logoff()
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def connectTree(self, share):
        """
        Connect to a remote share / resource (tree).
        
        :return int: Tree ID (used later in other operations).
        """
        if self.getDialect() == smb.SMB_DIALECT:
            # If we already have a UNC we do nothing.
            if ntpath.ismount(share) is False:
                # Else we build it
                share = ntpath.basename(share)
                share = '\\\\' + self.getRemoteHost() + '\\' + share
        try:
            return self._SMBConnection.connect_tree(share)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def disconnectTree(self, treeId):
        try:
            return self._SMBConnection.disconnect_tree(treeId)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def listShares(self):
        """
        Get a list of available shares at the connected target.

        :return: List containing dict entries for each share.
        :raise SessionError: If encountered an error.
        """
        # Get the shares through RPC
        from impacket.dcerpc.v5 import transport, srvs
        rpctransport = transport.SMBTransport(self.getRemoteName(), self.getRemoteHost(), filename=r'\srvsvc',
                                              smb_connection=self)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrShareEnum(dce, 1, serverName="\\\\" + self.getRemoteHost())
        return resp['InfoStruct']['ShareInfo']['Level1']['Buffer']

    def listPath(self, shareName, path, password = None):
        """
        List the files/directories under shareName/path.

        :param str shareName: A valid name for the share where the files/directories are going to be searched.
        :param str path: A base path relative to shareName.
        :param optional str password: The password for the share.

        :return: List containing smb.SharedFile items.
        :raise SessionError: If encountered an error.
        """

        try:
            return self._SMBConnection.list_path(shareName, path, password)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def createFile(self, treeId, pathName, desiredAccess=GENERIC_ALL,
                   shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   creationOption=FILE_NON_DIRECTORY_FILE, creationDisposition=FILE_OVERWRITE_IF,
                   fileAttributes=FILE_ATTRIBUTE_NORMAL, impersonationLevel=smb3structs.SMB2_IL_IMPERSONATION, securityFlags=0,
                   oplockLevel=smb3structs.SMB2_OPLOCK_LEVEL_NONE, createContexts=None):
        """
        Creates a remote file, returning a handle to it.

        :param HANDLE treeId: A valid handle for the share where the file is to be created.
        :param str pathName: The path name of the file to create.
        :param optional int desiredAccess: The level of access that is required, as specified in https://msdn.microsoft.com/en-us/library/cc246503.aspx
        :param optional int shareMode: Specifies the sharing mode for the open.
        :param optional int creationOption: Specifies the options to be applied when creating or opening the file.
        :param optional int creationDisposition: Defines the action the server MUST take if the file that is specified in the name
                                                 field already exists.
        :param optional int fileAttributes: This field MUST be a combination of the values specified in [MS-FSCC] section 2.6, 
                                            and MUST NOT include any values other than those specified in that section.
        :param optional int impersonationLevel: This field specifies the impersonation level requested by the application that is issuing 
                                                the create request.
        :param optional int securityFlags: This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, 
                                           and the server MUST ignore it.
        :param optional int oplockLevel: The requested oplock level.
        :param optional createContexts: A variable-length attribute that is sent with an SMB2 CREATE Request or SMB2 CREATE Response 
                                        that either gives extra information about how the create will be processed, or returns extra
                                        information about how the create was processed.

        :return: A valid file descriptor.
        :raise SessionError: If encountered an error.
        """
        if self.getDialect() == smb.SMB_DIALECT:
            _, flags2 = self._SMBConnection.get_flags()

            pathName = pathName.replace('/', '\\')
            packetPathName = pathName.encode('utf-16le') if flags2 & smb.SMB.FLAGS2_UNICODE else pathName

            ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
            ntCreate['Data']       = smb.SMBNtCreateAndX_Data(flags=flags2)
            ntCreate['Parameters']['FileNameLength']= len(packetPathName)
            ntCreate['Parameters']['AccessMask']    = desiredAccess
            ntCreate['Parameters']['FileAttributes']= fileAttributes
            ntCreate['Parameters']['ShareAccess']   = shareMode
            ntCreate['Parameters']['Disposition']   = creationDisposition
            ntCreate['Parameters']['CreateOptions'] = creationOption
            ntCreate['Parameters']['Impersonation'] = impersonationLevel
            ntCreate['Parameters']['SecurityFlags'] = securityFlags
            ntCreate['Parameters']['CreateFlags']   = 0x16
            ntCreate['Data']['FileName'] = packetPathName

            if flags2 & smb.SMB.FLAGS2_UNICODE:
                ntCreate['Data']['Pad'] = 0x0

            if createContexts is not None:
                LOG.error("CreateContexts not supported in SMB1")

            try:
                return self._SMBConnection.nt_create_andx(treeId, pathName, cmd = ntCreate)
            except (smb.SessionError, smb3.SessionError) as e:
                raise SessionError(e.get_error_code(), e.get_error_packet())
        else:
            try:
                return self._SMBConnection.create(treeId, pathName, desiredAccess, shareMode, creationOption,
                                                  creationDisposition, fileAttributes, impersonationLevel,
                                                  securityFlags, oplockLevel, createContexts)
            except (smb.SessionError, smb3.SessionError) as e:
                raise SessionError(e.get_error_code(), e.get_error_packet())

    def openFile(self, treeId, pathName, desiredAccess = FILE_READ_DATA | FILE_WRITE_DATA, shareMode = FILE_SHARE_READ,
                 creationOption = FILE_NON_DIRECTORY_FILE, creationDisposition = FILE_OPEN,
                 fileAttributes = FILE_ATTRIBUTE_NORMAL, impersonationLevel = smb3structs.SMB2_IL_IMPERSONATION, securityFlags = 0,
                 oplockLevel = smb3structs.SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        """
        Opens a handle to a remote file.

        :param HANDLE treeId: A valid handle for the share where the file is to be opened.
        :param str pathName: The path name to open.
        :param optional int desiredAccess: The level of access that is required, as specified in https://msdn.microsoft.com/en-us/library/cc246503.aspx
        :param optional int shareMode: Specifies the sharing mode for the open.
        :param optional int creationOption: Specifies the options to be applied when creating or opening the file.
        :param optional int creationDisposition: Defines the action the server MUST take if the file that is specified in the name
                                                 field already exists.
        :param optional int fileAttributes: This field MUST be a combination of the values specified in [MS-FSCC] section 2.6, 
                                            and MUST NOT include any values other than those specified in that section.
        :param optional int impersonationLevel: This field specifies the impersonation level requested by the application that is issuing 
                                                the create request.
        :param optional int securityFlags: This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, 
                                           and the server MUST ignore it.
        :param optional int oplockLevel: The requested oplock level
        :param optional createContexts: A variable-length attribute that is sent with an SMB2 CREATE Request or SMB2 CREATE Response 
                                        that either gives extra information about how the create will be processed, or returns extra
                                        information about how the create was processed.

        :return: A valid file descriptor.
        :raise SessionError: If encountered an error.
        """

        if self.getDialect() == smb.SMB_DIALECT:
            _, flags2 = self._SMBConnection.get_flags()

            pathName = pathName.replace('/', '\\')
            packetPathName = pathName.encode('utf-16le') if flags2 & smb.SMB.FLAGS2_UNICODE else pathName

            ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
            ntCreate['Data']       = smb.SMBNtCreateAndX_Data(flags=flags2)
            ntCreate['Parameters']['FileNameLength']= len(packetPathName)
            ntCreate['Parameters']['AccessMask']    = desiredAccess
            ntCreate['Parameters']['FileAttributes']= fileAttributes
            ntCreate['Parameters']['ShareAccess']   = shareMode
            ntCreate['Parameters']['Disposition']   = creationDisposition
            ntCreate['Parameters']['CreateOptions'] = creationOption
            ntCreate['Parameters']['Impersonation'] = impersonationLevel
            ntCreate['Parameters']['SecurityFlags'] = securityFlags
            ntCreate['Parameters']['CreateFlags']   = 0x16
            ntCreate['Data']['FileName'] = packetPathName

            if flags2 & smb.SMB.FLAGS2_UNICODE:
                ntCreate['Data']['Pad'] = 0x0

            if createContexts is not None:
                LOG.error("CreateContexts not supported in SMB1")

            try:
                return self._SMBConnection.nt_create_andx(treeId, pathName, cmd = ntCreate)
            except (smb.SessionError, smb3.SessionError) as e:
                raise SessionError(e.get_error_code(), e.get_error_packet())
        else:
            try:
                return self._SMBConnection.create(treeId, pathName, desiredAccess, shareMode, creationOption,
                                                  creationDisposition, fileAttributes, impersonationLevel,
                                                  securityFlags, oplockLevel, createContexts)
            except (smb.SessionError, smb3.SessionError) as e:
                raise SessionError(e.get_error_code(), e.get_error_packet())

    def writeFile(self, treeId, fileId, data, offset = 0):
        """
        Writes data to a remote file.

        :param HANDLE treeId: A valid handle for the share where the file is to be written.
        :param HANDLE fileId: A valid handle for the file.
        :param str data: A buffer with the data to write.
        :param optional int offset: An offset where to start writing the data.

        :return: The amount of bytes successfully written.
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.writeFile(treeId, fileId, data, offset)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def readFile(self, treeId, fileId, offset = 0, bytesToRead = None, singleCall = True):
        """
        Reads data from a file.

        :param HANDLE treeId: A valid handle for the share where the file is to be read.
        :param HANDLE fileId: A valid handle for the file to be read.
        :param optional int offset: An offset where to start reading the data.
        :param optional int bytesToRead: The amount of bytes to attempt reading. 
                                         If None, it will attempt to read Dialect['MaxBufferSize'] bytes.
        :param optional bool singleCall: If True it won't attempt to read all bytesToRead. 
                                         It will only make a single read call.

        :return: The data read. Length of data read is not always bytesToRead.
        :raise SessionError: If encountered an error.
        """
        finished = False
        data = b''
        maxReadSize = self._SMBConnection.getIOCapabilities()['MaxReadSize']
        if bytesToRead is None:
            bytesToRead = maxReadSize
        remainingBytesToRead = bytesToRead
        while not finished:
            if remainingBytesToRead > maxReadSize:
                toRead = maxReadSize
            else:
                toRead = remainingBytesToRead
            try:
                bytesRead = self._SMBConnection.read_andx(treeId, fileId, offset, toRead)
            except (smb.SessionError, smb3.SessionError) as e:
                if e.get_error_code() == nt_errors.STATUS_END_OF_FILE:
                    toRead = b''
                    break
                else:
                    raise SessionError(e.get_error_code(), e.get_error_packet())

            data += bytesRead
            if len(data) >= bytesToRead:
                finished = True
            elif len(bytesRead) == 0:
                # End of the file achieved.
                finished = True
            elif singleCall is True:
                finished = True
            else:
                offset += len(bytesRead)
                remainingBytesToRead -= len(bytesRead)

        return data

    def closeFile(self, treeId, fileId):
        """
        Closes a file handle.

        :param HANDLE treeId: A valid handle for the share where the file is to be opened.
        :param HANDLE fileId: A valid handle for the file/directory to be closed.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.close(treeId, fileId)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def deleteFile(self, shareName, pathName):
        """
        Removes a file.

        :param str shareName: A valid name for the share where the file is to be deleted.
        :param str pathName: The path name to remove.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.remove(shareName, pathName)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())
    
    def getFile(self, shareName, pathName, callback, shareAccessMode = FILE_SHARE_READ,
        mode = FILE_OPEN, offset = 0, password = None):
        """
        Reads a remote file and sends the read data to a callback method.

        :param str shareName: The name for the share where the file is to be retrieved.
        :param str pathName: The path name to retrieve.
        :param callback callback: A function called to write the contents read - the method receives bytes as an argument.
        :param optional int shareAccessMode: Binary flags stating what file access permissions we would like to allow other 
                                             processes to have when accessing our opened file.
        :param optional int mode: Binary flags indicating what file operation we expect to happen when we open our file.
        :param optional int offset: An offset for reading data from the file (used like `seek`).
        :param optional str password: A password for password protected files & shares (Not Implemented in SMBv3).

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.retr_file(shareName, pathName, callback, mode=mode, offset=offset, password=password, shareAccessMode=shareAccessMode)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def putFile(self, shareName, pathName, callback, shareAccessMode = FILE_SHARE_READ,
        mode = FILE_OVERWRITE_IF, offset = 0, password = None):
        """
        Uploads data read from a callback method to a remote file.

        :param str shareName: The name for the share where the file is to be uploaded.
        :param str pathName: The path name to upload.
        :param callback callback: A function called to read the contents to be written - method should receive 
                                  length of data as a value and return bytes (in the requested amount) to write.
        :param optional int shareAccessMode: Binary flags stating what file access permissions we would like to allow other 
                                             processes to have when accessing our opened file.
        :param optional int mode: Binary flags indicating what file operation we expect to happen when we open our file.
        :param optional int offset: An offset for writing data to the file (used like `seek`).
        :param optional str password: A password for password protected files & shares (Not Implemented in SMBv3).

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.stor_file(shareName, pathName, callback, mode=mode, offset=offset, password=password, shareAccessMode=shareAccessMode)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def queryInfo(self, treeId, fileId, fileInfoClass = None):
        """
        Queries the desired information class of an opened file/directory.

        :param HANDLE treeId: A valid handle for the share where the file is to be queried.
        :param HANDLE fileId: A valid handle for the file/directory to be queried.
        :param optional int fileInfoClass: The desired file information class to query.

        :return: An smb.SMBQueryFileStandardInfo structure if not given any file info class.
                Otherwise, returns raw bytes - which can be converted into any file information struct by the user.
        :raise SessionError: If encountered an error.
        """
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                if not fileInfoClass:
                    res = self._SMBConnection.query_file_info(treeId, fileId)
                    return smb.SMBQueryFileStandardInfo(res)
                else:
                    res = self._SMBConnection.query_file_info(treeId, fileId, fileInfoClass=fileInfoClass)
            else:
                if not fileInfoClass:
                    res = self._SMBConnection.queryInfo(treeId, fileId)
                    return smb.SMBQueryFileStandardInfo(res)
                else:
                    res = self._SMBConnection.queryInfo(treeId, fileId, fileInfoClass=fileInfoClass)
            return res
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())
    
    def setInfo(self, treeId, fileId, fileInfoClass, infoData):
        """
        Set the given information data of the desired file information class onto the file/directory.

        :param HANDLE treeId: A valid handle for the share where the file to be modified resides.
        :param HANDLE fileId: A valid handle for the file/directory to be modified.
        :param int fileInfoClass: The desired file information class to modify.
        :param struct infoData: The desired file information data to set onto the file/directory.

        :return: Underlying connection set info result.
        :raise SessionError: If encountered an error.
        """
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                return self._SMBConnection.set_file_info(treeId, fileId, fileInfoClass=fileInfoClass, file_info_data=infoData)
            else:
                return self._SMBConnection.setInfo(
                    treeId,
                    fileId,
                    inputBlob = infoData,
                    fileInfoClass = fileInfoClass,
                )
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def createDirectory(self, shareName, pathName):
        """
        Creates a directory.

        :param str shareName: A valid name for the share where the directory is to be created.
        :param str pathName: The path name or the directory to create.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.mkdir(shareName, pathName)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def deleteDirectory(self, shareName, pathName):
        """
        Deletes a directory.

        :param str shareName: A valid name for the share where directory is to be deleted.
        :param str pathName: The path name or the directory to delete.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.rmdir(shareName, pathName)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def waitNamedPipe(self, treeId, pipeName, timeout = 5):
        """
        Waits for a named pipe.

        :param HANDLE treeId: A valid handle for the share where the pipe is.
        :param str pipeName: The pipe name to check.
        :param optional int timeout: Time to wait for an answer.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.waitNamedPipe(treeId, pipeName, timeout = timeout)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def transactNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        Writes to a named pipe using a transaction command.

        :param HANDLE treeId: A valid handle for the share where the pipe is.
        :param HANDLE fileId: A valid handle for the pipe.
        :param bytes data: A buffer with the data to write.
        :param bool waitAnswer: Whether or not to wait for an answer.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.TransactNamedPipe(treeId, fileId, data, waitAnswer = waitAnswer)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def transactNamedPipeRecv(self):
        """
        Reads from a named pipe using a transaction command.

        :return: The data read from the remote pipe.
        :raise SessionError: If encountered an error.
        """
        try:
            return self._SMBConnection.TransactNamedPipeRecv()
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def writeNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        Writes to a named pipe.

        :param HANDLE treeId: A valid handle for the share where the pipe is.
        :param HANDLE fileId: A valid handle for the pipe.
        :param bytes data: A buffer with the data to write.
        :param optional bool waitAnswer: Whether or not to wait for an answer.

        :return: None
        :raise SessionError: If encountered an error.
        """
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                return self._SMBConnection.write_andx(treeId, fileId, data, wait_answer = waitAnswer, write_pipe_mode = True)
            else:
                return self.writeFile(treeId, fileId, data, 0)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def readNamedPipe(self, treeId, fileId, bytesToRead = None):
        """
        Reads from a named pipe.

        :param HANDLE treeId: A valid handle for the share where the pipe resides.
        :param HANDLE fileId: A valid handle for the pipe.
        :param optional int bytesToRead: The amount of data to read.

        :return: The bytes read from the named pipe.
        :raise SessionError: If encountered an error.
        """

        try:
            return self.readFile(treeId, fileId, bytesToRead = bytesToRead, singleCall = True)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())
    
    def listSnapshots(self, tid, path):
        """
        Lists the VSS snapshots for the given directory on the remote share.

        :param HANDLE tid: A vaild handle for the share where the path resides.
        :param str path: A path of a directory to list the snapshots of.

        :return list: List of snapshot identifiers.
        :raise SessionError: If encountered an error.
        """

        # Verify we're under SMB2+ session
        if self.getDialect() not in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
            raise SessionError(error = nt_errors.STATUS_NOT_SUPPORTED)

        fid = self.openFile(tid, path, FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                            fileAttributes=None, creationOption=FILE_SYNCHRONOUS_IO_NONALERT,
                            shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE)

        # first send with maxOutputResponse=16 to get the required size
        try:
            snapshotData = smb3structs.SRV_SNAPSHOT_ARRAY(self._SMBConnection.ioctl(tid, fid, smb3structs.FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                  flags=smb3structs.SMB2_0_IOCTL_IS_FSCTL, maxOutputResponse=16))
        except (smb.SessionError, smb3.SessionError) as e:
            self.closeFile(tid, fid)
            raise SessionError(e.get_error_code(), e.get_error_packet())

        if snapshotData['SnapShotArraySize'] >= 52:
            # now send an appropriate sized buffer
            try:
               snapshotData = smb3structs.SRV_SNAPSHOT_ARRAY(self._SMBConnection.ioctl(tid, fid, smb3structs.FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                  flags=smb3structs.SMB2_0_IOCTL_IS_FSCTL, maxOutputResponse=snapshotData['SnapShotArraySize']+12))
            except (smb.SessionError, smb3.SessionError) as e:
               self.closeFile(tid, fid)
               raise SessionError(e.get_error_code(), e.get_error_packet())

        self.closeFile(tid, fid)
        return list(filter(None, snapshotData['SnapShots'].decode('utf16').split('\x00')))

    def createMountPoint(self, tid, path, target):
        """
        Creates a mount point at an existing directory

        :param HANDLE tid: A vaild handle for the share where the path resides.
        :param str path: A path to a directory at which to create mount point (must already exist).
        :param str target: A target address of mount point.

        :raise SessionError: If encountered an error.
        """

        # Verify we're under SMB2+ session
        if self.getDialect() not in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
            raise SessionError(error = nt_errors.STATUS_NOT_SUPPORTED)

        fid = self.openFile(tid, path, GENERIC_READ | GENERIC_WRITE,
                            creationOption=FILE_OPEN_REPARSE_POINT)

        if target.startswith("\\"):
            fixed_name  = target.encode('utf-16le')
        else:
            fixed_name  = ("\\??\\" + target).encode('utf-16le')

        name        = target.encode('utf-16le')

        reparseData = smb3structs.MOUNT_POINT_REPARSE_DATA_STRUCTURE()

        reparseData['PathBuffer']           = fixed_name + b"\x00\x00" + name + b"\x00\x00"
        reparseData['SubstituteNameLength'] = len(fixed_name)
        reparseData['PrintNameOffset']      = len(fixed_name) + 2
        reparseData['PrintNameLength']      = len(name)

        self._SMBConnection.ioctl(tid, fid, smb3structs.FSCTL_SET_REPARSE_POINT, flags=smb3structs.SMB2_0_IOCTL_IS_FSCTL,
                                  inputBlob=reparseData)

        self.closeFile(tid, fid)

    def removeMountPoint(self, tid, path):
        """
        Removes a mount point without deleting the underlying directory.

        :param HANDLE tid: A vaild handle for the share where the path resides.
        :param str path: A path to a directory to remote a mount point from.

        :raise SessionError: If encountered an error.
        """

        # Verify we're under SMB2+ session
        if self.getDialect() not in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
            raise SessionError(error = nt_errors.STATUS_NOT_SUPPORTED)

        fid = self.openFile(tid, path, GENERIC_READ | GENERIC_WRITE,
                            creationOption=FILE_OPEN_REPARSE_POINT)

        reparseData = smb3structs.MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE()

        reparseData['DataBuffer'] = b""

        try:
            self._SMBConnection.ioctl(tid, fid, smb3structs.FSCTL_DELETE_REPARSE_POINT, flags=smb3structs.SMB2_0_IOCTL_IS_FSCTL,
                                      inputBlob=reparseData)
        except (smb.SessionError, smb3.SessionError) as e:
            self.closeFile(tid, fid)
            raise SessionError(e.get_error_code(), e.get_error_packet())

        self.closeFile(tid, fid)

    def rename(self, shareName, oldPath, newPath):
        """
        Renames a file/directory.

        :param str shareName: The name for the share where the files/directories are.
        :param str oldPath: The old path name of the directory/file to rename.
        :param str newPath: The new path name of the directory/file to rename.

        :return: True
        :raise SessionError: If encountered an error.
        """

        try:
            return self._SMBConnection.rename(shareName, oldPath, newPath)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def reconnect(self):
        """
        Reconnects the SMB object based on the original options and credentials used. 
        Only exception is that manualNegotiate will not be honored.
        Not only the connection will be created but also a login attempt using the original credentials and method (Kerberos, PtH, etc)

        :return: True
        :raise SessionError: If encountered an error.
        """
        userName, password, domain, lmhash, nthash, aesKey, TGT, TGS = self.getCredentials()
        self.negotiateSession(self._preferredDialect)
        if self._doKerberos is True:
            self.kerberosLogin(userName, password, domain, lmhash, nthash, aesKey, self._kdcHost, TGT, TGS, self._useCache)
        else:
            self.login(userName, password, domain, lmhash, nthash, self._ntlmFallback)

        return True

    def setTimeout(self, timeout):
        try:
            return self._SMBConnection.set_timeout(timeout)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def getSessionKey(self):
        if self.getDialect() == smb.SMB_DIALECT:
            return self._SMBConnection.get_session_key()
        else:
            return self._SMBConnection.getSessionKey()

    def setSessionKey(self, key):
        if self.getDialect() == smb.SMB_DIALECT:
            return self._SMBConnection.set_session_key(key)
        else:
            return self._SMBConnection.setSessionKey(key)

    def setHostnameValidation(self, validate, accept_empty, hostname):
        return self._SMBConnection.set_hostname_validation(validate, accept_empty, hostname)

    def close(self):
        """
        Logs off and closes the underlying _NetBIOSSession()

        :return: None
        """
        try:
            self.logoff()
        except:
            pass
        self._SMBConnection.close_session()

    def getFileEx(self, shareName, pathName, callback,
        mode = FILE_OPEN, offset = 0, password = None):
        """
        retrieve regular files and also those locked with open (weak) handles by remote process ( #1894 )
        """
        return self.getFile(shareName ,pathName ,callback ,shareAccessMode = FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                               mode = mode, offset=offset, password = password )

class SessionError(Exception):
    """
    This is the exception every client should catch regardless of the underlying SMB version used. 
    We'll take care of that. 
    NETBIOS exceptions are NOT included, since all SMB versions share the same NETBIOS instances.
    """
    def __init__( self, error = 0, packet=0):
        Exception.__init__(self)
        self.error = error
        self.packet = packet

    def getErrorCode( self ):
        return self.error

    def getErrorPacket( self ):
        return self.packet

    def getErrorString( self ):
        return nt_errors.ERROR_MESSAGES[self.error]

    def __str__( self ):
        key = self.error
        if key in nt_errors.ERROR_MESSAGES:
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1]
            return 'SMB SessionError: code: 0x%x - %s - %s' % (self.error, error_msg_short, error_msg_verbose)
        else:
            return 'SMB SessionError: unknown error code: 0x%x' % self.error
