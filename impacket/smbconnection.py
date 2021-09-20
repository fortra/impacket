# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
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

from impacket import smb, smb3, nmb, nt_errors, LOG
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smb3structs import SMB2Packet, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, GENERIC_ALL, FILE_SHARE_READ, \
    FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, FILE_ATTRIBUTE_NORMAL, \
    SMB2_IL_IMPERSONATION, SMB2_OPLOCK_LEVEL_NONE, FILE_READ_DATA , FILE_WRITE_DATA, FILE_OPEN, GENERIC_READ, GENERIC_WRITE, \
    FILE_OPEN_REPARSE_POINT, MOUNT_POINT_REPARSE_DATA_STRUCTURE, FSCTL_SET_REPARSE_POINT, SMB2_0_IOCTL_IS_FSCTL, \
    MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE, FSCTL_DELETE_REPARSE_POINT, FSCTL_SRV_ENUMERATE_SNAPSHOTS, SRV_SNAPSHOT_ARRAY, \
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_READ_EA, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE, SMB2_DIALECT_311


# So the user doesn't need to import smb, the smb3 are already in here
SMB_DIALECT = smb.SMB_DIALECT

class SMBConnection:
    """
    SMBConnection class

    :param string remoteName: name of the remote host, can be its NETBIOS name, IP or *\\*SMBSERVER*.  If the later,
           and port is 139, the library will try to get the target's server name.
    :param string remoteHost: target server's remote address (IPv4, IPv6) or FQDN
    :param string/optional myName: client's NETBIOS name
    :param integer/optional sess_port: target port to connect
    :param integer/optional timeout: timeout in seconds when receiving packets
    :param optional preferredDialect: the dialect desired to talk with the target server. If not specified the highest
           one available will be used
    :param optional boolean manualNegotiate: the user manually performs SMB_COM_NEGOTIATE

    :return: a SMBConnection instance, if not raises a SessionError exception
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
        Perform protocol negotiation

        :param string preferredDialect: the dialect desired to talk with the target server. If None is specified the highest one available will be used
        :param string flags1: the SMB FLAGS capabilities
        :param string flags2: the SMB FLAGS2 capabilities
        :param string negoData: data to be sent as part of the nego handshake

        :return: True
        :raise SessionError: if error
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
                                                negSessionResponse=SMB2Packet(packet))
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
        returns the SMB/SMB3 instance being used. Useful for calling low level methods
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
        logins into the target system

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param bool ntlmFallback: If True it will try NTLMv1 authentication if NTLMv2 fails. Only available for SMBv1

        :return: None
        :raise SessionError: if error
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
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False

        :return: None
        :raise SessionError: if error
        """
        import os
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import KerberosError
        from impacket.krb5 import constants

        self._kdcHost = kdcHost
        self._useCache = useCache

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache is True:
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            except:
                # No cache present
                pass
            else:
                LOG.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
                # retrieve domain information from CCache file if needed
                if domain == '':
                    domain = ccache.principal.realm['data'].decode('utf-8')
                    LOG.debug('Domain retrieved from CCache: %s' % domain)

                principal = 'cifs/%s@%s' % (self.getRemoteName().upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/%s@%s' % (domain.upper(),domain.upper())
                    creds =  ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        LOG.debug('Using TGT from cache')
                    else:
                        LOG.debug("No valid credentials found in cache. ")
                else:
                    TGS = creds.toTGS(principal)
                    LOG.debug('Using TGS from cache')

                # retrieve user information from CCache file if needed
                if user == '' and creds is not None:
                    user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    LOG.debug('Username retrieved from CCache: %s' % user)
                elif user == '' and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]['data'].decode('utf-8')
                    LOG.debug('Username retrieved from CCache: %s' % user)

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
                    # We might face this if the target does not support AES
                    # So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
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


    def connectTree(self,share):
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
        get a list of available shares at the connected target

        :return: a list containing dict entries for each share
        :raise SessionError: if error
        """
        # Get the shares through RPC
        from impacket.dcerpc.v5 import transport, srvs
        rpctransport = transport.SMBTransport(self.getRemoteName(), self.getRemoteHost(), filename=r'\srvsvc',
                                              smb_connection=self)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrShareEnum(dce, 1)
        return resp['InfoStruct']['ShareInfo']['Level1']['Buffer']

    def listPath(self, shareName, path, password = None):
        """
        list the files/directories under shareName/path

        :param string shareName: a valid name for the share where the files/directories are going to be searched
        :param string path: a base path relative to shareName
        :param string password: the password for the share

        :return: a list containing smb.SharedFile items
        :raise SessionError: if error
        """

        try:
            return self._SMBConnection.list_path(shareName, path, password)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def createFile(self, treeId, pathName, desiredAccess=GENERIC_ALL,
                   shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   creationOption=FILE_NON_DIRECTORY_FILE, creationDisposition=FILE_OVERWRITE_IF,
                   fileAttributes=FILE_ATTRIBUTE_NORMAL, impersonationLevel=SMB2_IL_IMPERSONATION, securityFlags=0,
                   oplockLevel=SMB2_OPLOCK_LEVEL_NONE, createContexts=None):
        """
        Creates a remote file

        :param HANDLE treeId: a valid handle for the share where the file is to be created
        :param string pathName: the path name of the file to create
        :param int desiredAccess: The level of access that is required, as specified in https://msdn.microsoft.com/en-us/library/cc246503.aspx
        :param int shareMode: Specifies the sharing mode for the open.
        :param int creationOption: Specifies the options to be applied when creating or opening the file.
        :param int creationDisposition: Defines the action the server MUST take if the file that is specified in the name
        field already exists.
        :param int fileAttributes: This field MUST be a combination of the values specified in [MS-FSCC] section 2.6, and MUST NOT include any values other than those specified in that section.
        :param int impersonationLevel: This field specifies the impersonation level requested by the application that is issuing the create request.
        :param int securityFlags: This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it.
        :param int oplockLevel: The requested oplock level
        :param createContexts: A variable-length attribute that is sent with an SMB2 CREATE Request or SMB2 CREATE Response that either gives extra information about how the create will be processed, or returns extra information about how the create was processed.

        :return: a valid file descriptor
        :raise SessionError: if error
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

    def openFile(self, treeId, pathName, desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA, shareMode=FILE_SHARE_READ,
                 creationOption=FILE_NON_DIRECTORY_FILE, creationDisposition=FILE_OPEN,
                 fileAttributes=FILE_ATTRIBUTE_NORMAL, impersonationLevel=SMB2_IL_IMPERSONATION, securityFlags=0,
                 oplockLevel=SMB2_OPLOCK_LEVEL_NONE, createContexts=None):
        """
        opens a remote file

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param string pathName: the path name to open
        :param int desiredAccess: The level of access that is required, as specified in https://msdn.microsoft.com/en-us/library/cc246503.aspx
        :param int shareMode: Specifies the sharing mode for the open.
        :param int creationOption: Specifies the options to be applied when creating or opening the file.
        :param int creationDisposition: Defines the action the server MUST take if the file that is specified in the name
        field already exists.
        :param int fileAttributes: This field MUST be a combination of the values specified in [MS-FSCC] section 2.6, and MUST NOT include any values other than those specified in that section.
        :param int impersonationLevel: This field specifies the impersonation level requested by the application that is issuing the create request.
        :param int securityFlags: This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it.
        :param int oplockLevel: The requested oplock level
        :param createContexts: A variable-length attribute that is sent with an SMB2 CREATE Request or SMB2 CREATE Response that either gives extra information about how the create will be processed, or returns extra information about how the create was processed.

        :return: a valid file descriptor
        :raise SessionError: if error
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

    def writeFile(self, treeId, fileId, data, offset=0):
        """
        writes data to a file

        :param HANDLE treeId: a valid handle for the share where the file is to be written
        :param HANDLE fileId: a valid handle for the file
        :param string data: buffer with the data to write
        :param integer offset: offset where to start writing the data

        :return: amount of bytes written
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.writeFile(treeId, fileId, data, offset)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def readFile(self, treeId, fileId, offset = 0, bytesToRead = None, singleCall = True):
        """
        reads data from a file

        :param HANDLE treeId: a valid handle for the share where the file is to be read
        :param HANDLE fileId: a valid handle for the file to be read
        :param integer offset: offset where to start reading the data
        :param integer bytesToRead: amount of bytes to attempt reading. If None, it will attempt to read Dialect['MaxBufferSize'] bytes.
        :param boolean singleCall: If True it won't attempt to read all bytesToRead. It will only make a single read call

        :return: the data read. Length of data read is not always bytesToRead
        :raise SessionError: if error
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
        closes a file handle

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param HANDLE fileId: a valid handle for the file/directory to be closed

        :return: None
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.close(treeId, fileId)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def deleteFile(self, shareName, pathName):
        """
        removes a file

        :param string shareName: a valid name for the share where the file is to be deleted
        :param string pathName: the path name to remove

        :return: None
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.remove(shareName, pathName)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def queryInfo(self, treeId, fileId):
        """
        queries basic information about an opened file/directory

        :param HANDLE treeId: a valid handle for the share where the file is to be queried
        :param HANDLE fileId: a valid handle for the file/directory to be queried

        :return: a smb.SMBQueryFileStandardInfo structure.
        :raise SessionError: if error
        """
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                res = self._SMBConnection.query_file_info(treeId, fileId)
            else:
                res = self._SMBConnection.queryInfo(treeId, fileId)
            return smb.SMBQueryFileStandardInfo(res)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def createDirectory(self, shareName, pathName ):
        """
        creates a directory

        :param string shareName: a valid name for the share where the directory is to be created
        :param string pathName: the path name or the directory to create

        :return: None
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.mkdir(shareName, pathName)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def deleteDirectory(self, shareName, pathName):
        """
        deletes a directory

        :param string shareName: a valid name for the share where directory is to be deleted
        :param string pathName: the path name or the directory to delete

        :return: None
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.rmdir(shareName, pathName)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def waitNamedPipe(self, treeId, pipeName, timeout = 5):
        """
        waits for a named pipe

        :param HANDLE treeId: a valid handle for the share where the pipe is
        :param string pipeName: the pipe name to check
        :param integer timeout: time to wait for an answer

        :return: None
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.waitNamedPipe(treeId, pipeName, timeout = timeout)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def transactNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        writes to a named pipe using a transaction command

        :param HANDLE treeId: a valid handle for the share where the pipe is
        :param HANDLE fileId: a valid handle for the pipe
        :param string data: buffer with the data to write
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.TransactNamedPipe(treeId, fileId, data, waitAnswer = waitAnswer)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def transactNamedPipeRecv(self):
        """
        reads from a named pipe using a transaction command

        :return: data read
        :raise SessionError: if error
        """
        try:
            return self._SMBConnection.TransactNamedPipeRecv()
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def writeNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        writes to a named pipe

        :param HANDLE treeId: a valid handle for the share where the pipe is
        :param HANDLE fileId: a valid handle for the pipe
        :param string data: buffer with the data to write
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None
        :raise SessionError: if error
        """
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                return self._SMBConnection.write_andx(treeId, fileId, data, wait_answer = waitAnswer, write_pipe_mode = True)
            else:
                return self.writeFile(treeId, fileId, data, 0)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def readNamedPipe(self,treeId, fileId, bytesToRead = None ):
        """
        read from a named pipe

        :param HANDLE treeId: a valid handle for the share where the pipe resides
        :param HANDLE fileId: a valid handle for the pipe
        :param integer bytesToRead: amount of data to read

        :return: None
        :raise SessionError: if error
        """

        try:
            return self.readFile(treeId, fileId, bytesToRead = bytesToRead, singleCall = True)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())


    def getFile(self, shareName, pathName, callback, shareAccessMode = None):
        """
        downloads a file

        :param string shareName: name for the share where the file is to be retrieved
        :param string pathName: the path name to retrieve
        :param callback callback: function called to write the contents read.
        :param int shareAccessMode:

        :return: None
        :raise SessionError: if error
        """
        try:
            if shareAccessMode is None:
                # if share access mode is none, let's the underlying API deals with it
                return self._SMBConnection.retr_file(shareName, pathName, callback)
            else:
                return self._SMBConnection.retr_file(shareName, pathName, callback, shareAccessMode=shareAccessMode)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def putFile(self, shareName, pathName, callback, shareAccessMode = None):
        """
        uploads a file

        :param string shareName: name for the share where the file is to be uploaded
        :param string pathName: the path name to upload
        :param callback callback: function called to read the contents to be written.
        :param int shareAccessMode:

        :return: None
        :raise SessionError: if error
        """
        try:
            if shareAccessMode is None:
                # if share access mode is none, let's the underlying API deals with it
                return self._SMBConnection.stor_file(shareName, pathName, callback)
            else:
                return self._SMBConnection.stor_file(shareName, pathName, callback, shareAccessMode)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def listSnapshots(self, tid, path):
        """
        lists the snapshots for the given directory

        :param int tid: tree id of current connection
        :param string path: directory to list the snapshots of

        :raise SessionError: if error
        """

        # Verify we're under SMB2+ session
        if self.getDialect() not in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
            raise SessionError(error = nt_errors.STATUS_NOT_SUPPORTED)

        fid = self.openFile(tid, path, FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                            fileAttributes=None, creationOption=FILE_SYNCHRONOUS_IO_NONALERT,
                            shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE)

        # first send with maxOutputResponse=16 to get the required size
        try:
            snapshotData = SRV_SNAPSHOT_ARRAY(self._SMBConnection.ioctl(tid, fid, FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                  flags=SMB2_0_IOCTL_IS_FSCTL, maxOutputResponse=16))
        except (smb.SessionError, smb3.SessionError) as e:
            self.closeFile(tid, fid)
            raise SessionError(e.get_error_code(), e.get_error_packet())

        if snapshotData['SnapShotArraySize'] >= 52:
            # now send an appropriate sized buffer
            try:
               snapshotData = SRV_SNAPSHOT_ARRAY(self._SMBConnection.ioctl(tid, fid, FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                  flags=SMB2_0_IOCTL_IS_FSCTL, maxOutputResponse=snapshotData['SnapShotArraySize']+12))
            except (smb.SessionError, smb3.SessionError) as e:
               self.closeFile(tid, fid)
               raise SessionError(e.get_error_code(), e.get_error_packet())

        self.closeFile(tid, fid)
        return list(filter(None, snapshotData['SnapShots'].decode('utf16').split('\x00')))

    def createMountPoint(self, tid, path, target):
        """
        creates a mount point at an existing directory

        :param int tid: tree id of current connection
        :param string path: directory at which to create mount point (must already exist)
        :param string target: target address of mount point

        :raise SessionError: if error
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

        reparseData = MOUNT_POINT_REPARSE_DATA_STRUCTURE()

        reparseData['PathBuffer']           = fixed_name + b"\x00\x00" + name + b"\x00\x00"
        reparseData['SubstituteNameLength'] = len(fixed_name)
        reparseData['PrintNameOffset']      = len(fixed_name) + 2
        reparseData['PrintNameLength']      = len(name)

        self._SMBConnection.ioctl(tid, fid, FSCTL_SET_REPARSE_POINT, flags=SMB2_0_IOCTL_IS_FSCTL,
                                  inputBlob=reparseData)

        self.closeFile(tid, fid)

    def removeMountPoint(self, tid, path):
        """
        removes a mount point without deleting the underlying directory

        :param int tid: tree id of current connection
        :param string path: path to mount point to remove

        :raise SessionError: if error
        """

        # Verify we're under SMB2+ session
        if self.getDialect() not in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
            raise SessionError(error = nt_errors.STATUS_NOT_SUPPORTED)

        fid = self.openFile(tid, path, GENERIC_READ | GENERIC_WRITE,
                            creationOption=FILE_OPEN_REPARSE_POINT)

        reparseData = MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE()

        reparseData['DataBuffer'] = b""

        try:
            self._SMBConnection.ioctl(tid, fid, FSCTL_DELETE_REPARSE_POINT, flags=SMB2_0_IOCTL_IS_FSCTL,
                                      inputBlob=reparseData)
        except (smb.SessionError, smb3.SessionError) as e:
            self.closeFile(tid, fid)
            raise SessionError(e.get_error_code(), e.get_error_packet())

        self.closeFile(tid, fid)

    def rename(self, shareName, oldPath, newPath):
        """
        renames a file/directory

        :param string shareName: name for the share where the files/directories are
        :param string oldPath: the old path name or the directory/file to rename
        :param string newPath: the new path name or the directory/file to rename

        :return: True
        :raise SessionError: if error
        """

        try:
            return self._SMBConnection.rename(shareName, oldPath, newPath)
        except (smb.SessionError, smb3.SessionError) as e:
            raise SessionError(e.get_error_code(), e.get_error_packet())

    def reconnect(self):
        """
        reconnects the SMB object based on the original options and credentials used. Only exception is that
        manualNegotiate will not be honored.
        Not only the connection will be created but also a login attempt using the original credentials and
        method (Kerberos, PtH, etc)

        :return: True
        :raise SessionError: if error
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
        logs off and closes the underlying _NetBIOSSession()

        :return: None
        """
        try:
            self.logoff()
        except:
            pass
        self._SMBConnection.close_session()


class SessionError(Exception):
    """
    This is the exception every client should catch regardless of the underlying
    SMB version used. We'll take care of that. NETBIOS exceptions are NOT included,
    since all SMB versions share the same NETBIOS instances.
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
        if self.error in nt_errors.ERROR_MESSAGES:
            return 'SMB SessionError: %s(%s)' % (nt_errors.ERROR_MESSAGES[self.error])
        else:
            return 'SMB SessionError: 0x%x' % self.error
