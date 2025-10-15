#!/usr/bin/env python3
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
#   Terminal Services manipulation tool.
#   Initial idea was to provide similar functionality as the QWINSTA and other TS* windows commands:
#   
#   qwinsta:  Display information about Remote Desktop Services sessions.
#   tasklist: Display a list of currently running processes on the system.
#   taskkill: Terminate tasks by process id (PID) or image name
#   tscon:    Attaches a user session to a remote desktop session
#   tsdiscon: Disconnects a Remote Desktop Services session
#   tslogoff: Signs-out a Remote Desktop Services session
#   shutdown: Remote shutdown
#   msg:      Send a message to Remote Desktop Services session (MSGBOX)
#
# Author:
#   Alexander Korznikov (@nopernik)
#
# Reference for:
#   [MS-TSTS]
#

import argparse
import codecs
import logging
import sys
from struct import unpack

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket import LOG
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

from impacket.dcerpc.v5 import tsts as TSTS
import traceback


class TSHandler:
    def __init__(self, username, password, domain, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__action = options.action.lower()
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.__smbConnection = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self, remoteName, remoteHost):
        self.remoteName = remoteName
        self.__smbConnection = SMBConnection(remoteName, remoteHost, sess_port=int(self.__options.port))

        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def run(self, remoteName, remoteHost):
        if self.__options.action == 'shutdown':
            if not max([options.logoff, options.shutdown, options.reboot, options.poweroff]):
                LOG.error('At least one flag is required: -logoff, -shutdown, -reboot or -poweroff')
                exit(1)

        self.connect(remoteName, remoteHost)
        getattr(self,'do_'+self.__action)()

    def get_session_list(self):
        # Retreive session list
        with TSTS.TermSrvEnumeration(self.__smbConnection, self.__options.target_ip, self.__doKerberos) as lsm:
            handle = lsm.hRpcOpenEnum()
            rsessions = lsm.hRpcGetEnumResult(handle, Level=1)['ppSessionEnumResult']
            lsm.hRpcCloseEnum(handle)
            self.sessions = {}
            for i in rsessions:
                sess = i['SessionInfo']['SessionEnum_Level1']
                state = TSTS.enum2value(TSTS.WINSTATIONSTATECLASS, sess['State']).split('_')[-1]
                self.sessions[sess['SessionId']] = { 'state'        :state,
                                                    'SessionName'   :sess['Name'],
                                                    'RemoteIp'      :'',
                                                    'ClientName'    :'',
                                                    'Username'      :'',
                                                    'Domain'        :'',
                                                    'Resolution'    :'',
                                                    'ClientTimeZone':''
                                                }

    def enumerate_sessions_config(self):
        # Get session config one by one
        if len(self.sessions):
            with TSTS.RCMPublic(self.__smbConnection, self.__options.target_ip, self.__doKerberos) as termsrv:
                for SessionId in self.sessions:
                    resp = termsrv.hRpcGetClientData(SessionId)
                    if resp is not None:
                        self.sessions[SessionId]['RemoteIp']       = resp['ppBuff']['ClientAddress']
                        self.sessions[SessionId]['ClientName']     = resp['ppBuff']['ClientName']
                        if len(resp['ppBuff']['UserName']) and not len(self.sessions[SessionId]['Username']):
                            self.sessions[SessionId]['Username']   = resp['ppBuff']['UserName']
                        if len(resp['ppBuff']['Domain']) and not len(self.sessions[SessionId]['Domain']):
                            self.sessions[SessionId]['Domain']     = resp['ppBuff']['Domain']
                        self.sessions[SessionId]['Resolution']     = '{}x{}'.format(
                                                                        resp['ppBuff']['HRes'],
                                                                        resp['ppBuff']['VRes']
                                                                    )
                        self.sessions[SessionId]['ClientTimeZone'] = resp['ppBuff']['ClientTimeZone']['StandardName']

    def enumerate_sessions_info(self):
        # Get session info one by one
        if len(self.sessions):
            with TSTS.TermSrvSession(self.__smbConnection, self.__options.target_ip, self.__doKerberos) as TermSrvSession:
                for SessionId in self.sessions.keys():
                    sessdata = TermSrvSession.hRpcGetSessionInformationEx(SessionId)
                    sessflags = TSTS.enum2value(TSTS.SESSIONFLAGS, sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['SessionFlags'])
                    self.sessions[SessionId]['flags']    = sessflags
                    domain = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DomainName']
                    if not len(self.sessions[SessionId]['Domain']) and len(domain):
                        self.sessions[SessionId]['Domain'] = domain
                    username = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['UserName']
                    if not len(self.sessions[SessionId]['Username']) and len(username):
                        self.sessions[SessionId]['Username'] = username
                    self.sessions[SessionId]['ConnectTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['ConnectTime']
                    self.sessions[SessionId]['DisconnectTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DisconnectTime']
                    self.sessions[SessionId]['LogonTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LogonTime']
                    self.sessions[SessionId]['LastInputTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LastInputTime']

    def do_qwinsta(self):
        options = self.__options
        desktop_states = {
            'WTS_SESSIONSTATE_UNKNOWN': '',
            'WTS_SESSIONSTATE_LOCK'   : 'Locked',
            'WTS_SESSIONSTATE_UNLOCK' : 'Unlocked',
        }
        self.get_session_list()
        if not len(self.sessions):
            print('No sessions found...')
            return
        self.enumerate_sessions_info()
        if options.verbose:
            self.enumerate_sessions_config()
        
        maxSessionNameLen = max([len(self.sessions[i]['SessionName'])+1 for i in self.sessions])
        maxSessionNameLen = maxSessionNameLen if len('SESSIONNAME') < maxSessionNameLen else len('SESSIONNAME')+1
        
        # maxUsernameLen = max([len(self.sessions[i]['Username'])+1 for i in self.sessions])
        maxUsernameLen = max([len(self.sessions[i]['Username']+self.sessions[i]['Domain'])+1 for i in self.sessions])+1

        maxUsernameLen = maxUsernameLen if len('Username') < maxUsernameLen else len('Username')+1
        
        
        maxIdLen = max([len(str(i)) for i in self.sessions])
        maxIdLen = maxIdLen if len('ID') < maxIdLen else len('ID')+1

        maxStateLen = max([len(self.sessions[i]['state'])+1 for i in self.sessions])
        maxStateLen = maxStateLen if len('STATE') < maxStateLen else len('STATE')+1

        maxRemoteIp = max([len(self.sessions[i]['RemoteIp'])+1 for i in self.sessions])
        maxRemoteIp = maxRemoteIp if len('RemoteAddress') < maxRemoteIp else len('RemoteAddress')+1

        maxClientName = max([len(self.sessions[i]['ClientName'])+1 for i in self.sessions])
        maxClientName = maxClientName if len('ClientName') < maxClientName else len('ClientName')+1

        template = ('{SESSIONNAME: <%d} '
                    '{USERNAME: <%d} '
                    '{ID: <%d} '
                    '{STATE: <%d} '
                    '{DSTATE: <9} '
                    '{CONNTIME: <20} '
                    '{DISCTIME: <20} ') % (maxSessionNameLen, maxUsernameLen, maxIdLen, maxStateLen)

        template_verbose = ('{CLIENTNAME: <%d} '
                            '{REMOTEIP: <%d} '
                            '{RESOLUTION: <11} '
                            '{TIMEZONE: <15}') % (maxClientName,maxRemoteIp)

        result = []
        header = template.format(
                SESSIONNAME = 'SESSIONNAME',
                USERNAME    = 'USERNAME',
                ID          = 'ID',
                STATE       = 'STATE',
                DSTATE      = 'Desktop',
                CONNTIME    = 'ConnectTime',
                DISCTIME    = 'DisconnectTime',
            )
        
        header2 = template.replace(' <','=<').format(
                SESSIONNAME = '',
                USERNAME    = '',
                ID          = '',
                STATE       = '',
                DSTATE      = '',
                CONNTIME    = '',
                DISCTIME    = '',
            )

        header_verbose = ''
        header2_verbose = ''
        if options.verbose:
            header_verbose = template_verbose.format(
                                  CLIENTNAME = 'ClientName',
                                  REMOTEIP = 'RemoteAddress',
                                  RESOLUTION = 'Resolution',
                                  TIMEZONE = 'ClientTimeZone'
                              )
            header2_verbose = template_verbose.replace(' <','=<').format(
                                  CLIENTNAME = '',
                                  REMOTEIP = '',
                                  RESOLUTION = '',
                                  TIMEZONE = ''
                              )
        result.append(header+header_verbose)
        result.append(header2+header2_verbose+'\n')
        
        for i in self.sessions:
            connectTime = self.sessions[i]['ConnectTime']
            connectTime = connectTime.strftime(r'%Y/%m/%d %H:%M:%S') if connectTime.year > 1601 else 'None'

            disconnectTime = self.sessions[i]['DisconnectTime']
            disconnectTime = disconnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if disconnectTime.year > 1601 else 'None'
            userName = self.sessions[i]['Domain'] + '\\' + self.sessions[i]['Username'] if len(self.sessions[i]['Username']) else ''

            row = template.format(
                SESSIONNAME = self.sessions[i]['SessionName'],
                USERNAME    = userName,
                ID          = i,
                STATE       = self.sessions[i]['state'],
                DSTATE      = desktop_states[self.sessions[i]['flags']],
                CONNTIME    = connectTime,
                DISCTIME    = disconnectTime,
            )
            row_verbose = ''
            if options.verbose:
                row_verbose = template_verbose.format(
                                    CLIENTNAME = self.sessions[i]['ClientName'],
                                    REMOTEIP = self.sessions[i]['RemoteIp'],
                                    RESOLUTION = self.sessions[i]['Resolution'],
                                    TIMEZONE = self.sessions[i]['ClientTimeZone']
                                )                
            result.append(row+row_verbose)

        for row in result:
            print(row)

    def lookupSids(self):
        # Slightly modified code from lookupsid.py
        try:
            stringbinding = r'ncacn_np:%s[\pipe\lsarpc]' % self.__options.target_ip
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_smb_connection(self.__smbConnection)
            dce = rpctransport.get_dce_rpc()
            if self.__doKerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()

            dce.bind(lsat.MSRPC_UUID_LSAT)
            sids = list(self.sids.keys())
            if len(sids) > 32:
                sids = sids[:32] # TODO in future update
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp['PolicyHandle']
            try:
                resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else: 
                    raise
            for sid, item in zip(sids,resp['TranslatedNames']['Names']):
                # if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                domainIndex = item['DomainIndex']
                if domainIndex == -1: # Unknown domain
                    self.sids[sid] = '{}\\{}'.format('???', item['Name'])
                elif domainIndex >= 0:
                    name = '{}\\{}'.format(resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'])
                    self.sids[sid] = name
            dce.disconnect()
        except:
            logging.debug(traceback.format_exc())

    def sidToUser(self, sid):
        if sid[:2] == 'S-' and sid in self.sids:
            return self.sids[sid]
        return sid

    def do_tasklist(self):
        options = self.__options
        with TSTS.LegacyAPI(self.__smbConnection, options.target_ip, self.__doKerberos) as legacy:
            handle = legacy.hRpcWinStationOpenServer()
            r = legacy.hRpcWinStationGetAllProcesses(handle)
            if not len(r):
                return None

            self.sids = {}
            for procInfo in r:
                sid = procInfo['pSid']
                if sid[:2] == 'S-' and sid not in self.sids:
                    self.sids[sid] = sid
            
            self.lookupSids()

            maxImageNameLen = max([len(i['ImageName']) for i in r])
            maxSidLen = max([len(i['pSid']) for i in r])
            if options.verbose:
                self.get_session_list()
                self.enumerate_sessions_config()
                maxUserNameLen = max([len(self.sessions[i]['Username']+self.sessions[i]['Domain'])+1 for i in self.sessions])+1
                if maxUserNameLen < 11:
                    maxUserNameLen = 11
                template = ('{imagename: <%d} '
                            '{pid: <6} '
                            '{sessid: <6} '
                            '{sessionName: <16} '
                            '{sessstate: <11} '
                            '{sessionuser: <%d} '
                            '{sid: <%d} '
                            '{workingset: <12}') % (maxImageNameLen, maxUserNameLen, maxSidLen)
                           
                print(template.format(imagename   = 'Image Name',
                                      pid         = 'PID',
                                      sessionName = 'SessName',
                                      sessid      = 'SessID',
                                      sessionuser = 'SessUser',
                                      sessstate   = 'State',
                                      sid         = 'SID',
                                      workingset  = 'Mem Usage'
                            )
                     )
                
                print(template.replace(' <','=<').format(imagename   = '',
                                                         pid         = '',
                                                         sessionName = '',
                                                         sessid      = '',
                                                         sessionuser = '',
                                                         sessstate   = '',
                                                         sid         = '',
                                                         workingset  = ''
                                                        )+'\n'
                     )

                for procInfo in r:
                    sessId = procInfo['SessionId']
                    fullUserName = ''
                    if len(self.sessions[sessId]['Domain']):
                        fullUserName += self.sessions[sessId]['Domain'] + '\\'
                    if len(self.sessions[sessId]['Username']):
                        fullUserName += self.sessions[sessId]['Username']
                    row = template.replace('{workingset: <12}','{workingset: >10,} K').format(
                                          imagename   = procInfo['ImageName'],
                                          pid         = procInfo['UniqueProcessId'],
                                          sessionName = self.sessions[sessId]['SessionName'],
                                          sessid      = procInfo['SessionId'],
                                          sessstate   = self.sessions[sessId]['state'].replace('Disconnected','Disc'),
                                          sid         = self.sidToUser(procInfo['pSid']),
                                          sessionuser = fullUserName,
                                          workingset  = procInfo['WorkingSetSize']//1000
                                         )
                    print(row)
            else:
                template = '{: <%d} {: <8} {: <11} {: <%d} {: >12}' % (maxImageNameLen, maxSidLen)
                print(template.format('Image Name', 'PID', 'Session#', 'SID', 'Mem Usage'))
                print(template.replace(': ',':=').format('','','','','')+'\n')
                for procInfo in r:
                    row = template.format(
                                procInfo['ImageName'],
                                procInfo['UniqueProcessId'],
                                procInfo['SessionId'],
                                self.sidToUser(procInfo['pSid']),
                                '{:,} K'.format(procInfo['WorkingSetSize']//1000),
                            )
                    print(row)

    def do_taskkill(self):
        options = self.__options
        if options.pid is None and options.name is None:
            LOG.error('One of the following is required: -pid, -name')
            return
        pidList = []
        with TSTS.LegacyAPI(self.__smbConnection, options.target_ip, self.__doKerberos) as legacy:
            handle = legacy.hRpcWinStationOpenServer()
            if options.pid is None and options.name is not None:
                r = legacy.hRpcWinStationGetAllProcesses(handle)
                if not len(r):
                    LOG.error('Could not get process list')
                    return
                pidList = [i['UniqueProcessId'] for i in r if i['ImageName'].lower() == options.name.lower()]
                if not len(pidList):
                    LOG.error('Could not find %r in process list' % options.name)
                    return
            else:
                pidList = [options.pid]

            for pid in pidList:
                print('Terminating PID: %d ...' % pid, end='')
                try:
                    if legacy.hRpcWinStationTerminateProcess(handle, pid)['ErrorCode']:
                        print('OK')
                    else:
                        print('FAIL')
                except Exception as e:
                    LOG.error('Error terminating pid: %d' % pid)
                    LOG.error(str(e))

    def do_tscon(self):
        options = self.__options
        with TSTS.TermSrvSession(self.__smbConnection, options.target_ip, self.__doKerberos) as TSSession:
            try:
                session_handle = None
                print('Connecting SessionID %d to %d ...' % (options.source, options.dest), end='')
                try:
                    session_handle = TSSession.hRpcOpenSession(options.source)
                except Exception as e:
                    print('FAIL')
                    if e.error_code == 0x80070002:
                        LOG.error('Could not find source SessionID: %d' % options.source)
                    else:
                        LOG.error(str(e))
                    return
                if TSSession.hRpcConnect(hSession = session_handle,
                                         TargetSessionId = options.dest,
                                         Password = options.password)['ErrorCode'] == 0:
                    print('OK')
                else:
                    print('FAIL')
            except Exception as e:
                print('FAIL')
                if e.error_code == 0x80070002:
                    LOG.error('Could not find destination SessionID: %d' % options.dest)
                elif e.error_code == 0x8007139f:
                    LOG.error('Session in the invalid state. Did you mean %d -> %d?' % (options.dest, options.source))
                else:
                    LOG.error(str(e))

    def do_tsdiscon(self):
        options = self.__options
        with TSTS.TermSrvSession(self.__smbConnection, options.target_ip, self.__doKerberos) as TSSession:
            try:
                print('Disconnecting SessionID: %d ...' % options.session, end='')
                session_handle = TSSession.hRpcOpenSession(options.session)
                if TSSession.hRpcDisconnect(session_handle)['ErrorCode'] == 0:
                    print('OK')
                else:
                    print('FAIL')
            except Exception as e:
                print('FAIL')
                if e.error_code == 1:
                    LOG.error('Maybe it is already disconnected?')
                elif e.error_code == 0x80070002:
                    LOG.error('Could not find SessionID: %d' % options.session)
                else:
                    LOG.error(str(e))

    def do_logoff(self):
        options = self.__options
        with TSTS.TermSrvSession(self.__smbConnection, options.target_ip, self.__doKerberos) as TSSession:
            try:
                print('Signing-out SessionID: %d ...' % options.session, end='')
                session_handle = TSSession.hRpcOpenSession(options.session)
                
                if TSSession.hRpcLogoff(session_handle)['ErrorCode'] == 0:
                    print('OK')
                else:
                    print('FAIL')
            except Exception as e:
                if e.error_code == 0x10000000:
                    print('OK')
                    return
                print('FAIL')
                if e.error_code == 0x80070002:
                    LOG.error('Could not find SessionID: %d' % options.session)
                else:
                    LOG.error(str(e))

    def do_shutdown(self):
        options = self.__options
        with TSTS.LegacyAPI(self.__smbConnection, options.target_ip, self.__doKerberos) as legacy:
            handle = legacy.hRpcWinStationOpenServer()
            flags = 0
            flagsList = []
            ShutdownFlags = [options.logoff, options.shutdown, options.reboot, options.poweroff]
            for k,v in zip(ShutdownFlags, ['logoff', 'shutdown', 'reboot', 'poweroff']):
                if k:
                    flagsList.append(v)
            flagsList = '|'.join(flagsList)
            for k,v in zip(ShutdownFlags, [1,2,4,8]):
                if k:
                    flags |= v
            try:
                print('Sending shutdown (%s) event ...' % (flagsList), end='')
                resp = legacy.hRpcWinStationShutdownSystem(handle, 0, flags)
                if resp['ErrorCode']:
                    print('OK')
                else:
                    resp.dump()
                    print('FAIL')
            except Exception as e:
                print('FAIL')
                LOG.error(str(e))
    

    def do_msg(self):
        options = self.__options
        with TSTS.TermSrvSession(self.__smbConnection, options.target_ip, self.__doKerberos) as TSSession:
            try:
                print('Sending message to SessionID: %d ...' % options.session, end='')
                session_handle = TSSession.hRpcOpenSession(options.session)
                if TSSession.hRpcShowMessageBox(session_handle, options.title, options.message)['ErrorCode'] == 0:
                    print('OK')
                else:
                    print('FAIL')
            except Exception as e:
                print('FAIL')
                if e.error_code == 0x80070002:
                    LOG.error('Could not find SessionID: %d' % options.session)
                else:
                    LOG.error(str(e))
    

if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Terminal Services manipulation tool.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    subparsers = parser.add_subparsers(help='actions', dest='action')

    # qwinsta: Display information about Remote Desktop Services sessions.
    qwinsta_parser = subparsers.add_parser('qwinsta', help='Display information about Remote Desktop Services sessions.')
    qwinsta_parser.add_argument('-v', action='store_true', dest='verbose', help='Turn VERBOSE output ON')

    # tasklist: Display a list of currently running processes on the system.
    tasklist_parser = subparsers.add_parser('tasklist', help='Display a list of currently running processes on the system.')
    tasklist_parser.add_argument('-v', action='store_true', dest='verbose', help='Turn VERBOSE output ON')
 
    # taskkill: Terminate tasks by process id (PID) or image name
    taskkill_parser = subparsers.add_parser('taskkill', help='Terminate tasks by process id (PID) or image name.')
    taskkill_parser.add_argument('-pid', action='store', metavar="PID", type=int, help='Specifies process id (PID)')
    taskkill_parser.add_argument('-name', action='store', help='Specifies process name (ImageName). Internally it will'
                                                               'execute tasklist to retrieve PID by ImageName.')

    # tscon: Attaches a user session to a remote desktop session
    tscon_parser = subparsers.add_parser('tscon', help='Attaches a user session to a remote desktop session.')
    tscon_parser.add_argument('-source', action='store', metavar="SessionID", type=int, required=True, help='Source SessionId')
    tscon_parser.add_argument('-dest', action='store', metavar="SessionID", type=int, required=True, help='Destination SessionId')
    tscon_parser.add_argument('-password', action='store', type=str, required=False, help='Destination Session\'s password')

    # tsdiscon: Disconnects a Remote Desktop Services session
    tsdiscon_parser = subparsers.add_parser('tsdiscon', help='Disconnects a Remote Desktop Services session.')
    tsdiscon_parser.add_argument('-session', action='store', metavar="SessionID", type=int, required=True, help='SessionId to disconnect')

    # logoff: Sign out a Remote Desktop Services session
    logoff_parser = subparsers.add_parser('logoff', help='Sign out a Remote Desktop Services session.')
    logoff_parser.add_argument('-session', action='store', metavar="SessionID", type=int, required=True, help='SessionId to sign out')
    
    # shutdown: Remote shutdown
    shutdown_parser = subparsers.add_parser('shutdown', help='Remote shutdown, affects ALL sessions and logged-in users!',
                        description="Send Remote Shutdown event. Affects ALL sessions and logged-in users!")
    shutdown_parser_group = shutdown_parser.add_argument_group('Shutdown Flags [Multiple Choice]')

    shutdown_parser_group.add_argument('-logoff', action='store_true', help='Forces sessions to logoff.')
    shutdown_parser_group.add_argument('-shutdown', action='store_true', help='Shuts down the system.')
    shutdown_parser_group.add_argument('-reboot', action='store_true', help='Reboots after shutdown.')
    shutdown_parser_group.add_argument('-poweroff', action='store_true', help='Powers off after shutdown.')

    # msg: Send a message to Remote Desktop Services session (MSGBOX)
    msg_parser = subparsers.add_parser('msg', help='Send a message to Remote Desktop Services session (MSGBOX).')
    msg_parser.add_argument('-session', action='store', metavar="SessionID", type=int, required=True, help='Receiver SessionId')
    msg_parser.add_argument('-title', action='store', metavar="'Your Title'", type=str, required=False, help='Title of the MessageBox [Optional]')
    msg_parser.add_argument('-message', action='store', metavar="'Your Message'", type=str, required=True, help='Contents of the MessageBox')

    # Authentication options
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on '
                            'target parameters. If valid credentials cannot be found, it will use the ones specified '
                            'in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key",
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    if options.action is None:
        parser.print_help()
        LOG.error('Too few arguments...')
        sys.exit(1)

    domain, username, password, remoteName = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    tsHandler = TSHandler(username, password, domain, options)
    try:
        tsHandler.run(remoteName, options.target_ip)
    except Exception as e:
        traceback.print_exc()
        logging.error(str(e))
