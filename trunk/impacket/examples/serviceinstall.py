# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Service Install Helper library used by psexec and smbrelayx
# You provide an already established connection and an exefile 
# (or class that mimics a file class) and this will install and 
# execute the service, and then uninstall (install(), uninstall().
# It tries to take care as much as possible to leave everything clean.
#
# Author:
#  Alberto Solino (bethus@gmail.com)
#

import random
from impacket.dcerpc import srvsvc, dcerpc, svcctl, transport
from impacket import smb
import string

class ServiceInstall():
    def __init__(self, SMBClient, exeFile):
        self._rpctransport = 0
        self.__service_name = ''.join([random.choice(string.letters) for i in range(4)])
        self.__binary_service_name = ''.join([random.choice(string.letters) for i in range(8)]) + '.exe'
        self.__exeFile = exeFile
        self.client = SMBClient

    def getShares(self):
        # Setup up a DCE SMBTransport with the connection already in place
        print "[*] Requesting shares on %s....." % (self.client.get_remote_host())
        try: 
            self._rpctransport = transport.SMBTransport('','',filename = r'\srvsvc', smb_server = self.client)
            self._dce = dcerpc.DCERPC_v5(self._rpctransport)
            self._dce.connect()

            self._dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
            srv_svc = srvsvc.DCERPCSrvSvc(self._dce)
            resp = srv_svc.get_share_enum_1(self._rpctransport.get_dip())
            return resp
        except:
            print "[!] Error requesting shares on %s, aborting....." % (self.client.get_remote_host())
            raise

        
    def createService(self, handle, share, path):
        print "[*] Creating service %s on %s....." % (self.__service_name, self.client.get_remote_host())


        # First we try to open the service in case it exists. If it does, we remove it.
        try:
            resp = self.rpcsvc.OpenServiceW(handle, self.__service_name.encode('utf-16le'))
        except Exception, e:
            if e.get_error_code() == svcctl.ERROR_SERVICE_DOES_NOT_EXISTS:
                # We're good, pass the exception
                pass
            else:
                raise
        else:
            # It exists, remove it
            self.rpcsvc.DeleteService(resp['ContextHandle'])
            self.rpcsvc.CloseServiceHandle(resp['ContextHandle'])

        # Create the service
        command = '%s\\%s' % (path, self.__binary_service_name)
        try: 
            resp = self.rpcsvc.CreateServiceW(handle, self.__service_name.encode('utf-16le'), self.__service_name.encode('utf-16le'), command.encode('utf-16le'))
        except:
            print "[!] Error creating service %s on %s" % (self.__service_name, self.client.get_remote_host())
            raise
        else:
            return resp['ContextHandle']

    def openSvcManager(self):
        print "[*] Opening SVCManager on %s....." % self.client.get_remote_host()
        # Setup up a DCE SMBTransport with the connection already in place
        self._rpctransport = transport.SMBTransport('','',filename = r'\svcctl', smb_server = self.client)
        self._dce = dcerpc.DCERPC_v5(self._rpctransport)
        self._dce.connect()
        self._dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.rpcsvc = svcctl.DCERPCSvcCtl(self._dce)
        try:
            resp = self.rpcsvc.OpenSCManagerW()
        except:
            print "[!] Error opening SVCManager on %s....." % self.client.get_remote_host()
            return 0
        else:
            return resp['ContextHandle']

    def copy_file(self, src, tree, dst):
        print "[*] Uploading file %s" % dst
        if isinstance(src, str):
            # We have a filename
            fh = open(src, 'rb')
        else:
            # We have a class instance, it must have a read method
            fh = src
        f = dst
        pathname = string.replace(f,'/','\\')
        try:
            self.client.stor_file(tree, pathname, fh.read)
        except:
            print "[!] Error uploading file %s, aborting....." % dst
            raise
        fh.close()

    def findWritableShare(self, shares):
        # Check we can write a file on the shares, stop in the first one
        for i in shares:
            if i['Type'] == smb.SHARED_DISK or i['Type'] == smb.SHARED_DISK_HIDDEN:
               share = i['NetName'].decode('utf-16le')[:-1]
               try:
                   self.client.mkdir(share,'BETO')
               except:
                   # Can't create, pass
                   print '[!] No written share found, aborting...'
                   raise
               else:
                   print '[*] Found writable share %s' % share
                   self.client.rmdir(share,'BETO')
                   return str(share)
        return None
        

    def install(self):
        if self.client.isGuestSession():
            print "[!] Authenticated as Guest. Aborting"
            self.client.logoff()
            del(self.client)
        else:
            fileCopied = False
            serviceCreated = False
            # Do the stuff here
            try:
                # Let's get the shares
                shares = self.getShares()
                self.share = self.findWritableShare(shares)
                res = self.copy_file(self.__exeFile ,self.share,self.__binary_service_name)
                fileCopied = True
                svcManager = self.openSvcManager()
                if svcManager != 0:
                    path = '\\\\127.0.0.1\\' + self.share 
                    service = self.createService(svcManager, self.share, path)
                    serviceCreated = True
                    if service != 0:
                        parameters = [ '%s\\%s' % (path,self.__binary_service_name), '%s\\%s' % (path, '') ]            
                        # Start service
                        print '[*] Starting service %s.....' % self.__service_name
                        try:
                            self.rpcsvc.StartServiceW(service)
                        except:
                            pass
                        self.rpcsvc.CloseServiceHandle(service)
                    self.rpcsvc.CloseServiceHandle(svcManager)
            except Exception, e:
                print "[!] Error performing the installation, cleaning up: %s" %e
                try:
                    self.rpcsvc.StopService(service)
                except:
                    pass
                if fileCopied is True:
                    try:
                        self.client.remove(self.share, self.__binary_service_name)
                    except:
                        pass
                if serviceCreated is True:
                    try:
                        self.rpcsvc.DeleteService(service)
                    except:
                        pass
      
    def uninstall(self):
        fileCopied = True
        serviceCreated = True
        # Do the stuff here
        try:
            # Let's get the shares
            svcManager = self.openSvcManager()
            if svcManager != 0:
                resp = self.rpcsvc.OpenServiceA(svcManager, self.__service_name)
                service = resp['ContextHandle'] 
                print '[*] Stoping service %s.....' % self.__service_name
                try:
                    self.rpcsvc.StopService(service)
                except:
                    pass
                print '[*] Removing service %s.....' % self.__service_name
                self.rpcsvc.DeleteService(service)
                self.rpcsvc.CloseServiceHandle(service)
                self.rpcsvc.CloseServiceHandle(svcManager)
            print '[*] Removing file %s.....' % self.__binary_service_name
            self.client.remove(self.share, self.__binary_service_name)
        except Exception, e:
            print "[!] Error performing the uninstallation, cleaning up" 
            try:
                self.rpcsvc.StopService(service)
            except:
                pass
            if fileCopied is True:
                try:
                    self.client.remove(self.share, self.__binary_service_name)
                except:
                    try:
                        self.client.remove(self.share, self.__binary_service_name)
                    except:
                        pass
                    pass
            if serviceCreated is True:
                try:
                    self.rpcsvc.DeleteService(service)
                except:
                    pass

