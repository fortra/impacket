# Copyright (c) 2003-2012 CORE Security Technologies)
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino (beto@coresecurity.com)
#
# Description:
#            
# Wrapper class for SMB1/2/3 so it's transparent for the client.
# You can still play with the low level methods (version dependant)
# by calling getSMBServer()
#

from impacket import smb, smb3, nmb
from impacket.dcerpc import transport, dcerpc, srvsvc
from smb3structs import *
import ntpath, string

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
    def __init__(self, remoteName, remoteHost, myName = None, sess_port = 445, timeout=10, preferredDialect = None):

        self._SMBConnection = 0
        self._dialect       = ''
        hostType = nmb.TYPE_SERVER

        # If no preferredDialect sent, we try the highest available one.
        if preferredDialect is None:
            try:
                self._SMBConnection = smb3.SMB3(remoteName, remoteHost, myName, hostType, sess_port, timeout)
            except:
                # No SMB2/3 available.. let's try the old SMB1
                self._SMBConnection = smb.SMB(remoteName, remoteHost, myName, hostType, sess_port, timeout)
        else:
            if preferredDialect == smb.SMB_DIALECT:
                self._SMBConnection = smb.SMB(remoteName, remoteHost, myName, hostType, sess_port, timeout)
            elif preferredDialect in [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]:
                self._SMBConnection = smb3.SMB3(remoteName, remoteHost, myName, hostType, sess_port, timeout, preferredDialect = preferredDialect)
            else:
                print "Unknown dialect ", preferredDialect
                raise 

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

    def getServerOS(self):
        return self._SMBConnection.get_server_os()

    def doesSupportNTLMv2(self):
        return self._SMBConnection.doesSupportNTLMv2()

    def isLoginRequired(self):
        return self._SMBConnection.is_login_required()

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
        return self._SMBConnection.login(user, password, domain = '', lmhash = '', nthash = '')

    def isGuestSession(self):
        return self._SMBConnection.isGuestSession()

    def logoff(self):
        return self._SMBConnection.logoff()

    def connectTree(self,share):
        if self.getDialect() == smb.SMB_DIALECT:
            share = ntpath.basename(share)
            share = '\\\\' + self.getRemoteHost() + '\\' + share
        return self._SMBConnection.connect_tree(share)

    def disconnectTree(self, treeId):
        return self._SMBConnection.disconnect_tree(treeId)

    def listShares(self):
        if self.getDialect() == smb.SMB_DIALECT:
            # For SMB1 we should try LANMAN first. Most probably won't work but oh well
            try: 
                return self._SMBConnection.list_shared()
            except:
                pass
        # Get the shares through RPC
        rpctransport = transport.SMBTransport(self.getRemoteHost(), self.getRemoteHost(), filename = r'\srvsvc', smb_server = self.getSMBServer())
        dce = dcerpc.DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        srv_svc = srvsvc.DCERPCSrvSvc(dce)
        resp = srv_svc.get_share_enum_1(rpctransport.get_dip())
        for i in range(len(resp)):
            print resp[i]['NetName'].decode('utf-16')
        return resp

    def listPath(self, shareName, path, password = None):
        return self._SMBConnection.list_path(shareName, path, password)

    def createFile(self, treeId, pathName, desiredAccess = GENERIC_ALL, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, creationOption = FILE_NON_DIRECTORY_FILE, creationDisposition = FILE_OVERWRITE_IF , fileAttributes = FILE_ATTRIBUTE_NORMAL, impersonationLevel = SMB2_IL_IMPERSONATION, securityFlags = 0, oplockLevel = SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        """
        creates a remote file

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
                print "CreateContexts not supported in SMB1"
      
            return self._SMBConnection.nt_create_andx(treeId, pathName, cmd = ntCreate)
        else:
            return self._SMBConnection.create(treeId, pathName, desiredAccess, shareMode, creationOption, creationDisposition, fileAttributes, impersonationLevel, securityFlags, oplockLevel, createContexts)

    def openFile(self, treeId, pathName, desiredAccess = FILE_READ_DATA, shareMode = FILE_SHARE_READ, creationOption = FILE_NON_DIRECTORY_FILE, creationDisposition = FILE_OPEN, fileAttributes = FILE_ATTRIBUTE_NORMAL, impersonationLevel = SMB2_IL_IMPERSONATION, securityFlags = 0, oplockLevel = SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        """
        opens a remote file

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param string pathName: the path name to open
        :return: a valid file descriptor, if not raises a SessionError exception.
        """

        if self.getDialect == smb.SMB_DIALECT:
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
            ntCreate['Data']['FileName'] = pathName

            if createContexts is not None:
                print "CreateContexts not supported in SMB1"
      
            return self._SMBConnection.nt_create_andx(treeId, pathName, cmd = ntCreate)
        else:
            return self._SMBConnection.create(treeId, pathName, desiredAccess, shareMode, creationOption, creationDisposition, fileAttributes, impersonationLevel, securityFlags, oplockLevel, createContexts)
        
    def writeFile(self, treeId, fileId, data, offset=0):
        """
        writes data to a file

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param HANDLE fileId: a valid handle for the file/directory to be closed
        :param string data: buffer with the data to write
        :param integer offset: offset where to start writing the data

        :return: amount of bytes written, if not raises a SessionError exception.
        """
        return self._SMBConnection.writeFile(treeId, fileId, data, offset)

    def readFile(self, treeId, fileId, offset = 0, bytesToRead = None):
        """
        reads data from a file

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param HANDLE fileId: a valid handle for the file/directory to be closed
        :param integer offset: offset where to start writing the data
        :param integer bytesToRead: amount of bytes to read. If None, it will read Dialect['MaxBufferSize'] bytes.

        :return: the data read, if not raises a SessionError exception.
        """
        return self._SMBConnection.read_andx(treeId, fileId, offset, bytesToRead)


    def closeFile(self, treeId, fileId):
        """
        closes a file handle

        :param HANDLE treeId: a valid handle for the share where the file is to be opened
        :param HANDLE fileId: a valid handle for the file/directory to be closed

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.close(treeId, fileId)

    def deleteFile(self, shareName, pathName):
        """
        removes a file

        :param string shareName: a valid handle for the share where the file is to be opened
        :param string pathName: the path name to remove

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.remove(shareName, pathName)

    def createDirectory(self, shareName, pathName ):
        """
        creates a directory

        :param string shareName: a valid handle for the share where the file is to be opened
        :param string pathName: the path name or the directory to create

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.mkdir(shareName, pathName)

    def deleteDirectory(self, shareName, pathName):
        """
        deletes a directory

        :param string shareName: a valid handle for the share where the file is to be opened
        :param string pathName: the path name or the directory to delete

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.rmdir(shareName, pathName)

    def waitNamedPipe(self, treeId, pipeName, timeout = 5):
        """
        waits for a named pipe

        :param HANDLE treeId: a valid handle for the share where the file is to be checked
        :param string pipeName: the pipe name to check
        :param integer timeout: time to wait for an answer

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.waitNamedPipe(treeId, pipeName, timeout = timeout)

    def transactNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        writes to a named pipe using a transaction command

        :param HANDLE treeId: a valid handle for the share where the file is to be checked
        :param HANDLE fileId: a valid handle for the file/directory to be closed
        :param string data: buffer with the data to write
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.TransactNamedPipe(treeId, fileId, data, waitAnswer = waitAnswer)

    def writeNamedPipe(self, treeId, fileId, data, waitAnswer = True):
        """
        writes to a named pipe 

        :param HANDLE treeId: a valid handle for the share where the file is to be checked
        :param HANDLE fileId: a valid handle for the file/directory to be closed
        :param string data: buffer with the data to write
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None, raises a SessionError exception if error.
            
        """
        if self.getDialect() == smb.SMB_DIALECT:
            return write_andx(treeId, fileId, data, waitAnswer = waitAnswer, write_pipe_mode = True)
        else:
            return self._SMBConnection.TransactNamedPipe(treeId, fileId, data, waitAnswer = waitAnswer)

    def readNamedPipe(self,treeId, fileId, bytesToRead = None ):
        """
        read from a named pipe 

        :param HANDLE treeId: a valid handle for the share where the file is to be checked
        :param HANDLE fileId: a valid handle for the file/directory to be closed
        :param integer bytestToRead: amount of data to read
        :param boolean waitAnswer: whether or not to wait for an answer

        :return: None, raises a SessionError exception if error.
            
        """

        return self.readFile(treeId, fileId, bytesToRead = bytesToRead)  

    def getFile(self, shareName, pathName, callback):
        """
        downloads a file

        :param string shareName: a valid handle for the share where the file is to be opened
        :param string pathName: the path name or the directory to delete
        :param callback callback: 

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.retr_file(shareName, pathName, callback)

    def putFile(self, shareName, pathName, callback):
        """
        uploads a file

        :param string shareName: a valid handle for the share where the file is to be opened
        :param string pathName: the path name or the directory to delete
        :param callback callback: 

        :return: None, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.stor_file(shareName, pathName, callback)

    def rename(self, shareName, oldPath, newPath):
        """
        rename a file/directory

        :param string shareName: a valid handle for the share where the file is to be opened
        :param string oldPath: the old path name or the directory/file to rename
        :param string newPath: the new path name or the directory/file to rename

        :return: True, raises a SessionError exception if error.
            
        """

        return self._SMBConnection.rename(shareName, oldPath, newPath)
 
