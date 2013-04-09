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

import ntpath
import string
import socket
from impacket import smb, smb3, nmb
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
    def __init__(self, remoteName='', remoteHost='', myName = None, sess_port = 445, timeout=10, preferredDialect = None, existingConnection = None):

        self._SMBConnection = 0
        self._dialect       = ''
        self._nmbSession    = 0
        hostType = nmb.TYPE_SERVER

        if existingConnection is not None:
            # Existing Connection must be a smb or smb3 instance
            assert ( isinstance(existingConnection,smb.SMB) or isinstance(existingConnection, smb3.SMB3))
            self._SMBConnection = existingConnection
            return


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
                print "Unknown dialect ", preferredDialect
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
        return self._SMBConnection.login(user, password, domain, lmhash, nthash)

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
        # Get the shares through RPC
        from impacket.dcerpc import transport, dcerpc, srvsvc
        rpctransport = transport.SMBTransport(self.getRemoteHost(), self.getRemoteHost(), filename = r'\srvsvc', smb_connection = self)
        dce = dcerpc.DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
        srv_svc = srvsvc.DCERPCSrvSvc(dce)
        resp = srv_svc.get_share_enum_1(rpctransport.get_dip())
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

    def transactNamedPipeRecv(self):
        """
        reads from a named pipe using a transaction command

        :return: data read, raises a SessionError exception if error.
            
        """
        return self._SMBConnection.TransactNamedPipeRecv()

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
            return self._SMBConnection.write_andx(treeId, fileId, data, wait_answer = waitAnswer, write_pipe_mode = True)
        else:
            return self.writeFile(treeId, fileId, data, 0)

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

    def setTimeout(self, timeout):
        return self._SMBConnection.set_timeout(timeout)
 
