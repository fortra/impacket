# Copyright (c) 2003-2012 CORE Security Technologies)
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (beto@coresecurity.com)
#
# Description:
#
# Wrapper class for SMB1/2/3 so it's transparent for the client.
# You can still play with the low level methods (version dependant)
# by calling getSMBServer()
#

import ntpath
import string
import socket
from impacket import smb, smb3, nmb, nt_errors, LOG
from smb3structs import *

# So the user doesn't need to import smb, the smb3 are already in here
SMB_DIALECT = smb.SMB_DIALECT

class SMBConnection():
    """
    SMBConnection class - beto

    :param string remoteName: name of the remote host, can be it's NETBIOS name, IP or *\*SMBSERVER*.  If the later, and port is 139, the library will try to get the target's server name.
    :param string remoteHost: target server's remote address (IPv4, IPv6)
    :param string/optional myName: client's NETBIOS name
    :param integer/optional sess_port: target port to connect
    :param integer/optional timeout: timeout in seconds when receiving packets
    :param optional preferredDialect: the dialect desired to talk with the target server. If not specified the highest one available will be used

    :return: a SMBConnection instance, if not raises a SessionError exception
    """
    def __init__(self, remoteName='', remoteHost='', myName = None, sess_port = 445, timeout=60, preferredDialect = None, existingConnection = None):

        self._SMBConnection = 0
        self._dialect       = ''
        self._nmbSession    = 0
        hostType = nmb.TYPE_SERVER

        if existingConnection is not None:
            # Existing Connection must be a smb or smb3 instance
            assert ( isinstance(existingConnection,smb.SMB) or isinstance(existingConnection, smb3.SMB3))
            self._SMBConnection = existingConnection
            return

        ##preferredDialect = smb.SMB_DIALECT
        if preferredDialect is None:
            # If no preferredDialect sent, we try the highest available one.
            packet = self._negotiateSession(myName, remoteName, remoteHost, sess_port, timeout)
            if packet[0] == '\xfe':
                # Answer is SMB2 packet
                self._SMBConnection = smb3.SMB3(remoteName, remoteHost, myName, hostType, sess_port, timeout, session = self._nmbSession )
            else:
                # Answer is SMB packet, sticking to SMBv1
                self._SMBConnection = smb.SMB(remoteName, remoteHost, myName, hostType, sess_port, timeout, session = self._nmbSession, negPacket = packet)
        else:
            if preferredDialect == smb.SMB_DIALECT:
                self._SMBConnection = smb.SMB(remoteName, remoteHost, myName, hostType, sess_port, timeout)
            elif preferredDialect in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
                self._SMBConnection = smb3.SMB3(remoteName, remoteHost, myName, hostType, sess_port, timeout, preferredDialect = preferredDialect)
            else:
                LOG.critical("Unknown dialect ", preferredDialect)
                raise

    def _negotiateSession(self, myName, remoteName, remoteHost, sess_port, timeout, extended_security = True):
        # Here we follow [MS-SMB2] negotiation handshake trying to understand what dialects
        # (including SMB1) is supported on the other end.

        if not myName:
            myName = socket.gethostname()
            i = string.find(myName, '.')
            if i > -1:
                myName = myName[:i]

        # If port 445 and the name sent is *SMBSERVER we're setting the name to the IP. This is to help some old applications still believing
        # *SMSBSERVER will work against modern OSes. If port is NETBIOS_SESSION_PORT the user better know about *SMBSERVER's limitations
        if sess_port == 445 and remoteName == '*SMBSERVER':
           remoteName = remoteHost

        self._nmbSession = nmb.NetBIOSTCPSession(myName, remoteName, remoteHost, nmb.TYPE_SERVER, sess_port, timeout)

        smbp = smb.NewSMBPacket()
        negSession = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        if extended_security == True:
            smbp['Flags2']=smb.SMB.FLAGS2_EXTENDED_SECURITY
        negSession['Data'] = '\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
        smbp.addCommand(negSession)
        self._nmbSession.send_packet(str(smbp))

        r = self._nmbSession.recv_packet(timeout)

        return r.get_trailer()


    def getSMBServer(self):
        """
        returns the SMB/SMB3 instance being used. Useful for calling low level methods
        """
        return self._SMBConnection

    def getDialect(self):
        return self._SMBConnection.getDialect()

    def getServerName(self):
        return self._SMBConnection.get_server_name()

    def getRemoteHost(self):
        return self._SMBConnection.get_remote_host()

    def getServerDomain(self):
        return self._SMBConnection.get_server_domain()

    def getServerDNSDomainName(self):
        return self._SMBConnection.get_server_dns_domain_name()

    def getServerOS(self):
        return self._SMBConnection.get_server_os()

    def doesSupportNTLMv2(self):
        return self._SMBConnection.doesSupportNTLMv2()

    def isLoginRequired(self):
        return self._SMBConnection.is_login_required()

    def getCredentials(self):
        return self._SMBConnection.getCredentials()

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):
        """
        logins into the target system

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)

        :return: None, raises a Session Error if error.
        """
        try: 
            return self._SMBConnection.login(user, password, domain, lmhash, nthash)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def kerberosLogin(self, user, password, domain = '', lmhash = '', nthash = '', aesKey = '', kdcHost=None, TGT=None, TGS=None, useCache = True):
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

        :return: None, raises a Session Error if error.
        """
        import os
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import KerberosError
        from impacket.krb5 import constants
        from impacket.ntlm import compute_lmhash, compute_nthash

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
                principal = 'cifs/%s@%s' % (self.getRemoteHost().upper(), domain.upper())
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
                    TGS = creds.toTGS()
                    LOG.debug('Using TGS from cache')

        while True:
            try:
                if self.getDialect() == smb.SMB_DIALECT:
                    return self._SMBConnection.kerberos_login(user, password, domain, lmhash, nthash, aesKey, kdcHost, TGT, TGS)
                return self._SMBConnection.kerberosLogin(user, password, domain, lmhash, nthash, aesKey, kdcHost, TGT, TGS)
            except (smb.SessionError, smb3.SessionError), e:
                raise SessionError(e.get_error_code())
            except KerberosError, e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES
                    # So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
                    if lmhash is '' and nthash is '' and (aesKey is '' or aesKey is None) and TGT is None and TGS is None:
                        from impacket.ntlm import compute_lmhash, compute_nthash
                        lmhash = compute_lmhash(password) 
                        nthash = compute_nthash(password) 
                    else:
                        raise e
                else:
                    raise e
            else:
                break

    def isGuestSession(self):
        try:
            return self._SMBConnection.isGuestSession()
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def logoff(self):
        try:
            return self._SMBConnection.logoff()
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def connectTree(self,share):
        if self.getDialect() == smb.SMB_DIALECT:
            share = ntpath.basename(share)
            share = '\\\\' + self.getRemoteHost() + '\\' + share
        try:
            return self._SMBConnection.connect_tree(share)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def disconnectTree(self, treeId):
        try:
            return self._SMBConnection.disconnect_tree(treeId)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def listShares(self):
        """
        get a list of available shares at the connected target

        :return: a list containing dict entries for each share, raises exception if error
        """
        # Get the shares through RPC
        from impacket.dcerpc.v5 import transport, rpcrt, srvs
        rpctransport = transport.SMBTransport(self.getRemoteHost(), self.getRemoteHost(), filename = r'\srvsvc', smb_connection = self)
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

        :return: a list containing smb.SharedFile items, raises a SessionError exception if error.
        """

        try:
            return self._SMBConnection.list_path(shareName, path, password)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def createFile(self, treeId, pathName, desiredAccess = GENERIC_ALL, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, creationOption = FILE_NON_DIRECTORY_FILE, creationDisposition = FILE_OVERWRITE_IF , fileAttributes = FILE_ATTRIBUTE_NORMAL, impersonationLevel = SMB2_IL_IMPERSONATION, securityFlags = 0, oplockLevel = SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        """
        creates a remote file

        :param HANDLE treeId: a valid handle for the share where the file is to be created
        :param string pathName: the path name of the file to create
        :return: a valid file descriptor, if not raises a SessionError exception.
        """

        if self.getDialect() == smb.SMB_DIALECT:
            pathName = string.replace(pathName, '/', '\\')
            ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
            ntCreate['Data']       = smb.SMBNtCreateAndX_Data()
            ntCreate['Parameters']['FileNameLength']= len(pathName)
            ntCreate['Parameters']['AccessMask']    = desiredAccess
            ntCreate['Parameters']['FileAttributes']= fileAttributes
            ntCreate['Parameters']['ShareAccess']   = shareMode
            ntCreate['Parameters']['Disposition']   = creationDisposition
            ntCreate['Parameters']['CreateOptions'] = creationOption
            ntCreate['Parameters']['Impersonation'] = impersonationLevel
            ntCreate['Parameters']['SecurityFlags'] = securityFlags
            ntCreate['Parameters']['CreateFlags']   = 0x16
            ntCreate['Data']['FileName'] = pathName

            if createContexts is not None:
                LOG.error("CreateContexts not supported in SMB1")

            try:
                return self._SMBConnection.nt_create_andx(treeId, pathName, cmd = ntCreate)
            except (smb.SessionError, smb3.SessionError), e:
                raise SessionError(e.get_error_code())
        else:
            try:
                return self._SMBConnection.create(treeId, pathName, desiredAccess, shareMode, creationOption, creationDisposition, fileAttributes, impersonationLevel, securityFlags, oplockLevel, createContexts)
            except (smb.SessionError, smb3.SessionError), e:
                raise SessionError(e.get_error_code())


    def openFile(self, treeId, pathName, desiredAccess = FILE_READ_DATA | FILE_WRITE_DATA, shareMode = FILE_SHARE_READ, creationOption = FILE_NON_DIRECTORY_FILE, creationDisposition = FILE_OPEN, fileAttributes = FILE_ATTRIBUTE_NORMAL, impersonationLevel = SMB2_IL_IMPERSONATION, securityFlags = 0, oplockLevel = SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        """
        opens a remote file

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param string pathName: the path name to open
        :return: a valid file descriptor, if not raises a SessionError exception.
        """

        if self.getDialect() == smb.SMB_DIALECT:
            pathName = string.replace(pathName, '/', '\\')
            ntCreate = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = smb.SMBNtCreateAndX_Parameters()
            ntCreate['Data']       = smb.SMBNtCreateAndX_Data()
            ntCreate['Parameters']['FileNameLength']= len(pathName)
            ntCreate['Parameters']['AccessMask']    = desiredAccess
            ntCreate['Parameters']['FileAttributes']= fileAttributes
            ntCreate['Parameters']['ShareAccess']   = shareMode
            ntCreate['Parameters']['Disposition']   = creationDisposition
            ntCreate['Parameters']['CreateOptions'] = creationOption
            ntCreate['Parameters']['Impersonation'] = impersonationLevel
            ntCreate['Parameters']['SecurityFlags'] = securityFlags
            ntCreate['Parameters']['CreateFlags']   = 0x16
            ntCreate['Data']['FileName'] = pathName

            if createContexts is not None:
                LOG.error("CreateContexts not supported in SMB1")

            try:
                return self._SMBConnection.nt_create_andx(treeId, pathName, cmd = ntCreate)
            except (smb.SessionError, smb3.SessionError), e:
                raise SessionError(e.get_error_code())
        else:
            try:
                return self._SMBConnection.create(treeId, pathName, desiredAccess, shareMode, creationOption, creationDisposition, fileAttributes, impersonationLevel, securityFlags, oplockLevel, createContexts)
            except (smb.SessionError, smb3.SessionError), e:
                raise SessionError(e.get_error_code())

    def writeFile(self, treeId, fileId, data, offset=0):
        """
        writes data to a file

        :param HANDLE treeId: a valid handle for the share where the file is to be written
        :param HANDLE fileId: a valid handle for the file
        :param string data: buffer with the data to write
        :param integer offset: offset where to start writing the data

        :return: amount of bytes written, if not raises a SessionError exception.
        """
        try:
            return self._SMBConnection.writeFile(treeId, fileId, data, offset)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def readFile(self, treeId, fileId, offset = 0, bytesToRead = None):
        """
        reads data from a file

        :param HANDLE treeId: a valid handle for the share where the file is to be read
        :param HANDLE fileId: a valid handle for the file to be read
        :param integer offset: offset where to start reading the data
        :param integer bytesToRead: amount of bytes to read. If None, it will read Dialect['MaxBufferSize'] bytes.

        :return: the data read, if not raises a SessionError exception.
        """
        try:
            return self._SMBConnection.read_andx(treeId, fileId, offset, bytesToRead)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def closeFile(self, treeId, fileId):
        """
        closes a file handle

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param HANDLE fileId: a valid handle for the file/directory to be closed

        :return: None, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.close(treeId, fileId)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def deleteFile(self, shareName, pathName):
        """
        removes a file

        :param string shareName: a valid name for the share where the file is to be deleted 
        :param string pathName: the path name to remove

        :return: None, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.remove(shareName, pathName)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def createDirectory(self, shareName, pathName ):
        """
        creates a directory

        :param string shareName: a valid name for the share where the directory is to be created
        :param string pathName: the path name or the directory to create

        :return: None, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.mkdir(shareName, pathName)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def deleteDirectory(self, shareName, pathName):
        """
        deletes a directory

        :param string shareName: a valid name for the share where directory is to be deleted
        :param string pathName: the path name or the directory to delete

        :return: None, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.rmdir(shareName, pathName)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def waitNamedPipe(self, treeId, pipeName, timeout = 5):
        """
        waits for a named pipe

        :param HANDLE treeId: a valid handle for the share where the pipe is
        :param string pipeName: the pipe name to check
        :param integer timeout: time to wait for an answer

        :return: None, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.waitNamedPipe(treeId, pipeName, timeout = timeout)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def transactNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        writes to a named pipe using a transaction command

        :param HANDLE treeId: a valid handle for the share where the pipe is
        :param HANDLE fileId: a valid handle for the pipe
        :param string data: buffer with the data to write
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.TransactNamedPipe(treeId, fileId, data, waitAnswer = waitAnswer)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def transactNamedPipeRecv(self):
        """
        reads from a named pipe using a transaction command

        :return: data read, raises a SessionError exception if error.

        """
        try:
            return self._SMBConnection.TransactNamedPipeRecv()
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def writeNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        writes to a named pipe

        :param HANDLE treeId: a valid handle for the share where the pipe is
        :param HANDLE fileId: a valid handle for the pipe
        :param string data: buffer with the data to write
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None, raises a SessionError exception if error.

        """
        try:
            if self.getDialect() == smb.SMB_DIALECT:
                return self._SMBConnection.write_andx(treeId, fileId, data, wait_answer = waitAnswer, write_pipe_mode = True)
            else:
                return self.writeFile(treeId, fileId, data, 0)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def readNamedPipe(self,treeId, fileId, bytesToRead = None ):
        """
        read from a named pipe

        :param HANDLE treeId: a valid handle for the share where the pipe resides
        :param HANDLE fileId: a valid handle for the pipe
        :param integer bytestToRead: amount of data to read
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None, raises a SessionError exception if error.

        """

        try:
            return self.readFile(treeId, fileId, bytesToRead = bytesToRead)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())


    def getFile(self, shareName, pathName, callback, shareAccessMode = None):
        """
        downloads a file

        :param string shareName: name for the share where the file is to be retrieved
        :param string pathName: the path name to retrieve
        :param callback callback:

        :return: None, raises a SessionError exception if error.

        """
        try:
	    if shareAccessMode is None:
		# if share access mode is none, let's the underlying API deals with it
            	return self._SMBConnection.retr_file(shareName, pathName, callback)
	    else:
            	return self._SMBConnection.retr_file(shareName, pathName, callback, shareAccessMode = shareAccessMode)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def putFile(self, shareName, pathName, callback, shareAccessMode = None):
        """
        uploads a file

        :param string shareName: name for the share where the file is to be uploaded
        :param string pathName: the path name to upload
        :param callback callback:

        :return: None, raises a SessionError exception if error.

        """
        try:
	    if shareAccessMode is None:
		# if share access mode is none, let's the underlying API deals with it
            	return self._SMBConnection.stor_file(shareName, pathName, callback)
	    else: 
            	return self._SMBConnection.stor_file(shareName, pathName, callback, shareAccessMode)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def rename(self, shareName, oldPath, newPath):
        """
        rename a file/directory

        :param string shareName: name for the share where the files/directories are
        :param string oldPath: the old path name or the directory/file to rename
        :param string newPath: the new path name or the directory/file to rename

        :return: True, raises a SessionError exception if error.

        """

        try:
            return self._SMBConnection.rename(shareName, oldPath, newPath)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

    def setTimeout(self, timeout):
        try:
            return self._SMBConnection.set_timeout(timeout)
        except (smb.SessionError, smb3.SessionError), e:
            raise SessionError(e.get_error_code())

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
        return 'SMB SessionError: %s(%s)' % (nt_errors.ERROR_MESSAGES[self.error])


