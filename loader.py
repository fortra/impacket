#!/usr/bin/env python3
"""
adfind.py — derive the internal Active Directory domain from a public FQDN/host.

Single-file, impacket-based. Two operating modes:

  PASSIVE (default, no authorization needed):
    Makes NO connection to the target's hosts. Derives candidate internal
    domains from the FQDN (public-suffix aware) and resolves public DNS SRV
    records only.
        python3 adfind.py --fqdn holon.muni.il

  ACTIVE (requires --authorized and an in-scope --scope CIDR):
    Runs the intrusive methods against a host you are authorized to test:
    SMB/NTLM, LDAP rootDSE, Kerberos realm, NetBIOS, RDP/HTTP NTLM, LDAPS
    cert, RPC/SAMR null session, endpoint mapper, DNS AXFR, subnet sweep.
        python3 adfind.py --fqdn lab.example.com --host 10.0.0.10 \
                --authorized --scope 10.0.0.0/24 -A
        python3 adfind.py --host 10.0.0.10 --authorized --scope 10.0.0.0/24 -s

The active methods only fire when the target IP falls inside --scope AND
--authorized is passed. This is a deliberate safety gate, not an obstacle:
point --scope at the range your signed engagement covers. Scanning networks
you do not have written permission to test is illegal in most jurisdictions.

Requires: impacket, dnspython
    pip install impacket dnspython --break-system-packages
"""

import argparse
import base64
import ipaddress
import json
import socket
import ssl
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

RESULTS = {}
_LOCK = threading.Lock()


def out(method, key, value):
    with _LOCK:
        print(f"  [+] {method:<10} {key:<26} {value}")
        RESULTS.setdefault(method, {})[key] = value


def err(method, msg):
    with _LOCK:
        print(f"  [-] {method:<10} {msg}")


def info(msg):
    with _LOCK:
        print(msg)


# ==========================================================================
#  PASSIVE: candidate derivation (public-suffix aware) + DNS SRV
# ==========================================================================
_MULTI_SUFFIXES = {
    "muni.il", "co.il", "org.il", "gov.il", "ac.il", "net.il", "k12.il", "idf.il",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "nhs.uk", "police.uk", "sch.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "govt.nz", "org.nz", "co.za", "org.za", "gov.za",
    "co.jp", "or.jp", "go.jp", "ac.jp", "com.br", "gov.br",
    "com.tr", "gov.tr", "com.cn", "gov.cn", "com.mx", "gob.mx",
    "com.sg", "gov.sg", "com.hk", "gov.hk",
}


def registrable(fqdn):
    """Return (seed_label, registrable_domain) honoring multi-label suffixes."""
    labels = fqdn.lower().strip(".").split(".")
    for n in (3, 2):
        if len(labels) > n:
            suffix = ".".join(labels[-n:])
            if suffix in _MULTI_SUFFIXES:
                return labels[-(n + 1)], ".".join(labels[-(n + 1):])
    if len(labels) >= 2:
        return labels[-2], ".".join(labels[-2:])
    return fqdn, fqdn


def build_candidates(fqdn):
    seed, pub = registrable(fqdn)
    prefixes = ["", "corp.", "ad.", "internal.", "int.", "hq.", "dc.", "win.",
                "office.", "us.", "eu.", "prod.", "priv."]
    tlds = ["local", "lan", "internal", "ad", "corp", "intra", "intranet",
            "domain", "priv", "network", "home", "office"]
    cands = [pub]
    for p in prefixes:
        if p:
            cands.append(f"{p}{pub}")
    for t in tlds:
        cands.append(f"{seed}.{t}")
    for p in ("ad.", "corp.", "dc."):
        for t in ("local", "internal", "corp"):
            cands.append(f"{p}{seed}.{t}")
    seen, ordered = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def probe_dns_srv(candidates):
    info("[*] DNS SRV brute  _ldap._tcp.dc._msdcs.<candidate>  (public DNS)")
    try:
        import dns.resolver
    except ImportError:
        err("dns", "dnspython not installed (pip install dnspython)")
        return
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    hit = False
    for c in candidates:
        q = f"_ldap._tcp.dc._msdcs.{c}"
        try:
            ans = resolver.resolve(q, "SRV", lifetime=4)
            targets = ", ".join(str(r.target).rstrip(".") for r in ans)
            out("dns", "AD domain", c)
            out("dns", "  via SRV", f"{q} -> {targets}")
            hit = True
        except Exception:
            continue
    if not hit:
        err("dns", "no _msdcs SRV records resolved for any candidate")


def run_passive(fqdn):
    seed, reg = registrable(fqdn)
    cands = build_candidates(fqdn)
    info(f"[*] FQDN            : {fqdn}")
    info(f"[*] Org seed        : {seed}")
    info(f"[*] Registrable     : {reg}")
    info(f"[*] Candidate internal AD domains ({len(cands)}):")
    for c in cands:
        info(f"      {c}")
    info("")
    probe_dns_srv(cands)
    info("\n[=] Passive best guess:")
    val = RESULTS.get("dns", {}).get("AD domain")
    if val:
        info(f"    {val}   (confirmed via public SRV record)")
    else:
        info("    no public SRV hit — most likely a split-brain or .local")
        info("    candidate above; confirm only on an authorized host with:")
        info("    python3 loader.py --fqdn <candidate> --host <authorized-host>")
        info("      --authorized --scope <your-CIDR> --only rpc")
    return val, cands


# ==========================================================================
#  NTLMSSP CHALLENGE parser (shared)
# ==========================================================================
_AV_IDS = {1: "NetBIOS computer", 2: "NetBIOS domain", 3: "DNS computer",
           4: "DNS domain", 5: "DNS forest"}


def parse_ntlm_challenge(blob, method):
    try:
        if blob[:8] != b"NTLMSSP\x00" or struct.unpack("<I", blob[8:12])[0] != 2:
            return
        tn_len, _, tn_off = struct.unpack("<HHI", blob[12:20])
        if tn_len:
            out(method, "target name", blob[tn_off:tn_off + tn_len].decode("utf-16-le", "replace"))
        ti_len, _, ti_off = struct.unpack("<HHI", blob[40:48])
        data = blob[ti_off:ti_off + ti_len]
        i = 0
        while i + 4 <= len(data):
            av_id, av_len = struct.unpack("<HH", data[i:i + 4])
            i += 4
            if av_id == 0:
                break
            val = data[i:i + av_len].decode("utf-16-le", "replace")
            i += av_len
            label = _AV_IDS.get(av_id)
            if label and val:
                out(method, label, val)
    except Exception as e:
        err(method, f"challenge parse failed: {type(e).__name__}: {e}")


# ==========================================================================
#  ACTIVE probes
# ==========================================================================
def probe_smb(target):
    info("[*] SMB / NTLMSSP negotiation (445)")
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(target, target, sess_port=445, timeout=6)
        try:
            conn.login("", "")
        except Exception:
            pass
        for label, fn in (
            ("DNS domain", conn.getServerDNSDomainName),
            ("NetBIOS domain", conn.getServerDomain),
            ("DNS forest", getattr(conn, "getServerDNSForestName", lambda: None)),
            ("DC DNS host", conn.getServerDNSHostName),
            ("computer name", conn.getServerName),
            ("Server OS", conn.getServerOS),
        ):
            try:
                v = fn()
                if v:
                    out("smb", label, v)
            except Exception:
                pass
        try:
            out("smb", "signing required", str(conn.isSigningRequired()))
        except Exception:
            pass
        conn.close()
    except ImportError:
        err("smb", "impacket not installed")
    except Exception as e:
        err("smb", f"{type(e).__name__}: {e}")


def _dn_to_domain(dn):
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().lower().startswith("dc=")]
    return ".".join(parts) if parts else None


def probe_ldap(target):
    info("[*] LDAP rootDSE (389)")
    try:
        from impacket.ldap import ldap as ldaplib
        conn = ldaplib.LDAPConnection(f"ldap://{target}")
        try:
            conn.login()
        except Exception:
            pass
        resp = conn.search(searchBase="", scope=0, searchFilter="(objectClass=*)",
                           attributes=["defaultNamingContext", "rootDomainNamingContext",
                                       "dnsHostName", "ldapServiceName", "serverName"])
        for entry in resp:
            try:
                for attr in entry["attributes"]:
                    name = str(attr["type"])
                    val = attr["vals"][0].asOctets().decode(errors="replace")
                    if name == "defaultNamingContext":
                        out("ldap", "defaultNamingContext", val)
                        d = _dn_to_domain(val)
                        if d:
                            out("ldap", "-> domain", d)
                    elif name == "rootDomainNamingContext":
                        out("ldap", "rootDomainNC", val)
                        d = _dn_to_domain(val)
                        if d:
                            out("ldap", "-> forest root", d)
                    elif name == "dnsHostName":
                        out("ldap", "dnsHostName", val)
                    elif name == "ldapServiceName":
                        out("ldap", "ldapServiceName", val)
                    elif name == "serverName":
                        out("ldap", "serverName", val)
            except Exception:
                continue
    except ImportError:
        err("ldap", "impacket not installed")
    except Exception as e:
        err("ldap", f"{type(e).__name__}: {e}")


def probe_kerberos(target, candidates):
    info("[*] Kerberos realm probe (88)")
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except ImportError:
        err("kerberos", "impacket not installed")
        return
    found = False
    for realm in candidates:
        try:
            user = Principal("nonexistent-user-probe",
                             type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            getKerberosTGT(user, "", realm.upper(), None, None, None, kdcHost=target)
        except Exception as e:
            if any(t in str(e) for t in ("KDC_ERR_C_PRINCIPAL_UNKNOWN",
                                         "KDC_ERR_PREAUTH_REQUIRED",
                                         "KDC_ERR_CLIENT_REVOKED")):
                out("kerberos", "valid realm", realm.upper())
                found = True
    if not found:
        err("kerberos", "no realm confirmed from candidates")


def probe_netbios(target):
    info("[*] NetBIOS name service (137/udp)")
    try:
        from impacket.nmb import NetBIOS
        nb = NetBIOS()
        names = nb.getNodeStatus("*", target, timeout=4)
        if not names:
            err("netbios", "no node status reply")
            return
        for e in names:
            try:
                nm = e.get_nbname().strip()
                flags = e.get_nametype()
                out("netbios", f"name(0x{flags:02x})", nm)
            except Exception:
                continue
    except ImportError:
        err("netbios", "impacket not installed")
    except Exception as e:
        err("netbios", f"{type(e).__name__}: {e}")


_NTLM_TYPE1 = base64.b64decode("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")


def _http_ntlm(target, port, scheme):
    method = f"http:{port}"
    try:
        import http.client
        if scheme == "https":
            conn = http.client.HTTPSConnection(target, port, timeout=6,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(target, port, timeout=6)
        for path in ("/", "/ews/", "/rpc/", "/autodiscover/autodiscover.xml"):
            try:
                conn.request("GET", path, headers={"Authorization": "NTLM " + base64.b64encode(_NTLM_TYPE1).decode()})
                r = conn.getresponse()
                www = r.getheader("WWW-Authenticate", "") or ""
                r.read()
                for tok in www.split(","):
                    tok = tok.strip()
                    if tok.upper().startswith("NTLM ") and len(tok) > 6:
                        parse_ntlm_challenge(base64.b64decode(tok[5:]), method)
                        conn.close()
                        return True
            except Exception:
                continue
        conn.close()
    except Exception as e:
        err(method, f"{type(e).__name__}: {e}")
    return False


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_seq_token(token):
    octet = b"\x04" + _der_len(len(token)) + token
    inner0 = b"\xa0" + _der_len(len(octet)) + octet
    seq2 = b"\x30" + _der_len(len(inner0)) + inner0
    return b"\x30" + _der_len(len(seq2)) + seq2


def _rdp_ntlm(target, port=3389):
    method = "rdp:3389"
    try:
        s = socket.create_connection((target, port), timeout=6)
        neg = b"\x01\x00\x08\x00\x03\x00\x00\x00"
        cookie = b"Cookie: mstshash=probe\r\n"
        x224 = b"\x0e\xe0\x00\x00\x00\x00\x00" + neg
        tpkt_body = cookie + x224
        s.sendall(b"\x03\x00" + struct.pack(">H", len(tpkt_body) + 4) + tpkt_body)
        s.recv(1024)
        ts = ssl._create_unverified_context().wrap_socket(s, server_hostname=target)
        token = _NTLM_TYPE1
        nego = b"\xa0" + _der_len(len(_der_seq_token(token))) + _der_seq_token(token)
        ver = b"\xa0\x03\x02\x01\x06"
        body = ver + b"\xa1" + _der_len(len(nego)) + nego
        ts.sendall(b"\x30" + _der_len(len(body)) + body)
        data = ts.recv(4096)
        idx = data.find(b"NTLMSSP\x00")
        if idx >= 0:
            parse_ntlm_challenge(data[idx:], method)
            ts.close()
            return True
        ts.close()
    except Exception as e:
        err(method, f"{type(e).__name__}: {e}")
    return False


def probe_ntlm_extra(target):
    info("[*] NTLM CHALLENGE via RDP / HTTP")
    got = _rdp_ntlm(target)
    got |= _http_ntlm(target, 443, "https")
    got |= _http_ntlm(target, 80, "http")
    if not got:
        err("ntlm", "no NTLM challenge from RDP/HTTP endpoints")


def probe_ldaps_cert(target, port=636):
    info("[*] LDAPS certificate SAN (636)")
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((target, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            out("ldaps", "cert", "retrieved (empty parse under unverified ctx)")
            return
        cn = None
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                if k == "commonName":
                    cn = v
        if cn:
            out("ldaps", "subject CN", cn)
            d = ".".join(cn.split(".")[1:]) if "." in cn else cn
            if d:
                out("ldaps", "-> domain", d)
        for typ, val in cert.get("subjectAltName", ()):
            out("ldaps", f"SAN {typ}", val)
    except Exception as e:
        err("ldaps", f"{type(e).__name__}: {e}")


def probe_rpc(target):
    info("[*] MSRPC null-session domain lookup (LSARPC/SAMR)")
    try:
        from impacket.dcerpc.v5 import transport, lsad, samr
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    except ImportError:
        err("rpc", "impacket not installed")
        return
    try:
        rt = transport.DCERPCTransportFactory(r"ncacn_np:%s[\pipe\lsarpc]" % target)
        rt.set_connect_timeout(6)
        try:
            rt.set_credentials("", "", "", "", "")
        except Exception:
            pass
        dce = rt.get_dce_rpc()
        dce.connect()
        dce.bind(lsad.MSRPC_UUID_LSAD)
        handle = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)["PolicyHandle"]
        try:
            dom = lsad.hLsarQueryInformationPolicy2(
                dce, handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
            )["PolicyInformation"]["PolicyAccountDomainInfo"]
            if dom["DomainName"]["Buffer"]:
                out("rpc", "NetBIOS domain", str(dom["DomainName"]["Buffer"]))
        except Exception:
            pass
        try:
            dns = lsad.hLsarQueryInformationPolicy2(
                dce, handle, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
            )["PolicyInformation"]["PolicyDnsDomainInfo"]
            if dns["Name"]["Buffer"]:
                out("rpc", "NetBIOS domain", str(dns["Name"]["Buffer"]))
            if dns["DnsDomainName"]["Buffer"]:
                out("rpc", "DNS domain", str(dns["DnsDomainName"]["Buffer"]))
            if dns["DnsForestName"]["Buffer"]:
                out("rpc", "DNS forest", str(dns["DnsForestName"]["Buffer"]))
        except Exception:
            pass
        dce.disconnect()
    except Exception as e:
        err("rpc", f"lsarpc: {type(e).__name__}: {e}")
    try:
        rt = transport.DCERPCTransportFactory(r"ncacn_np:%s[\pipe\samr]" % target)
        rt.set_connect_timeout(6)
        try:
            rt.set_credentials("", "", "", "", "")
        except Exception:
            pass
        dce = rt.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        h = samr.hSamrConnect(dce)["ServerHandle"]
        for d in samr.hSamrEnumerateDomainsInSamServer(dce, h)["Buffer"]["Buffer"]:
            nm = d["Name"]
            if nm and nm.lower() != "builtin":
                out("rpc", "SAM domain", str(nm))
        dce.disconnect()
    except Exception as e:
        err("rpc", f"samr: {type(e).__name__}: {e}")


def probe_epm(target):
    info("[*] RPC endpoint mapper (135)")
    try:
        from impacket.dcerpc.v5 import transport, epm
        rt = transport.DCERPCTransportFactory(r"ncacn_ip_tcp:%s[135]" % target)
        rt.set_connect_timeout(6)
        rt.get_dce_rpc().connect()
        entries = epm.hept_lookup(target)
        seen = set()
        for e in entries or []:
            try:
                for fl in e["tower"]["Floors"]:
                    s = str(getattr(fl, "getData", lambda: b"")() or b"")
                    if "." in s:
                        seen.add(s)
            except Exception:
                continue
        for s in list(seen)[:10]:
            out("epm", "tower", s)
        if not seen:
            err("epm", "no useful tower data")
    except ImportError:
        err("epm", "impacket not installed")
    except Exception as e:
        err("epm", f"{type(e).__name__}: {e}")


def probe_axfr(target, candidates):
    info("[*] DNS AXFR zone-transfer attempt")
    try:
        import dns.query
        import dns.zone
        import dns.resolver
    except ImportError:
        err("axfr", "dnspython not installed")
        return
    hit = False
    for zone in candidates:
        ns_hosts = set()
        try:
            for rr in dns.resolver.resolve(zone, "NS", lifetime=4):
                ns_hosts.add(str(rr.target).rstrip("."))
        except Exception:
            pass
        ns_hosts.add(target)
        for ns in ns_hosts:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, zone, timeout=6, lifetime=8))
                out("axfr", "zone transferred", zone)
                out("axfr", "  from NS", ns)
                out("axfr", "  sample", ", ".join([str(n) for n in z.nodes.keys()][:5]))
                hit = True
            except Exception:
                continue
    if not hit:
        err("axfr", "no zone allowed transfer")


# ==========================================================================
#  Subnet sweep
# ==========================================================================
AD_PORTS = {53: "dns", 88: "kerberos", 135: "epm", 139: "smb", 389: "ldap",
            445: "smb", 464: "kpasswd", 636: "ldaps", 3268: "gc", 3389: "rdp",
            80: "http", 443: "https", 5985: "winrm", 5986: "winrm-s"}
DC_MARKERS = [88, 389, 445, 135, 636, 3268]


def resolve_ip(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None


def expand_subnet(ip, cidr):
    net = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 2 else [ipaddress.ip_address(ip)]
    return net, [str(h) for h in hosts]


def _host_alive(ip, ports, timeout):
    op = []
    for p in ports:
        try:
            s = socket.create_connection((ip, p), timeout=timeout)
            s.close()
            op.append(p)
        except Exception:
            continue
    return ip, op


def sweep_subnet(ip, cidr, threads, timeout):
    net, hosts = expand_subnet(ip, cidr)
    info(f"[*] Sweeping {net} ({len(hosts)} hosts) for AD ports {DC_MARKERS}")
    live, dcs = [], []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_host_alive, h, DC_MARKERS, timeout): h for h in hosts}
        for fut in as_completed(futs):
            h, op = fut.result()
            if op:
                live.append(h)
                is_dc = any(p in op for p in (88, 389, 636, 3268))
                out("sweep", f"{h} [{'DC?' if is_dc else 'host'}]",
                    ",".join(str(p) for p in sorted(op)))
                if is_dc:
                    dcs.append(h)
    info(f"[*] {len(live)} live, {len(dcs)} look like DCs")
    return dcs + [h for h in live if h not in dcs], dcs


# ==========================================================================
def verdict():
    info("\n[=] Best guess at internal AD domain:")
    order = [("rpc", "DNS domain"), ("ldap", "-> domain"), ("smb", "DNS domain"),
             ("ntlm", "DNS domain"), ("ldaps", "-> domain"), ("kerberos", "valid realm"),
             ("rpc", "NetBIOS domain"), ("netbios", "name(0x00)"),
             ("axfr", "zone transferred"), ("dns", "AD domain")]
    for method, key in order:
        val = RESULTS.get(method, {}).get(key)
        if val:
            info(f"    {val}   (from {method})")
            return val
    info("    inconclusive — no authoritative leak and no SRV hit.")
    return None


def scan_host(target, candidates, only, aggressive):
    info(f"\n{'='*60}\n[*] Active scan: {target}")
    if candidates:
        info(f"[*] Candidates ({len(candidates)}): {', '.join(candidates[:10])}...")
    info("")
    steps = {
        "rpc": lambda: probe_rpc(target),
        "smb": lambda: probe_smb(target),
        "ldap": lambda: probe_ldap(target),
        "kerberos": lambda: probe_kerberos(target, candidates),
        "netbios": lambda: probe_netbios(target),
        "ntlm": lambda: probe_ntlm_extra(target),
        "ldaps": lambda: probe_ldaps_cert(target),
        "epm": lambda: probe_epm(target),
        "axfr": lambda: probe_axfr(target, candidates),
    }
    heavy = {"epm", "axfr"}
    for name, fn in steps.items():
        if only == name:
            fn()
        elif only is None and (aggressive or name not in heavy):
            fn()
    return verdict()


# ==========================================================================
#  Authorization gate
# ==========================================================================
def in_scope(ip, scope_cidrs):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in scope_cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def main():
    ap = argparse.ArgumentParser(
        description="Derive the internal AD domain from a public FQDN/host (passive by default).")
    ap.add_argument("--fqdn", help="public FQDN, e.g. lab.example.com")
    ap.add_argument("--host", help="specific host/IP to actively scan (active mode)")
    ap.add_argument("--authorized", action="store_true",
                    help="assert you have written authorization to actively test the scope")
    ap.add_argument("--scope", action="append", default=[], metavar="CIDR",
                    help="authorized CIDR(s); active methods only fire on in-scope IPs (repeatable)")
    ap.add_argument("--only", choices=["smb", "ldap", "kerberos", "netbios", "ntlm",
                                       "ldaps", "rpc", "epm", "axfr"],
                    help="active mode: run only one method")
    ap.add_argument("-A", "--aggressive", action="store_true",
                    help="active mode: run every method including epm/axfr")
    ap.add_argument("-s", "--subnet", nargs="?", const=24, type=int, metavar="MASK",
                    help="active mode: sweep the target's /MASK subnet (default /24) then scan each in-scope host")
    ap.add_argument("--sweep-timeout", type=float, default=1.0)
    ap.add_argument("--threads", type=int, default=64)
    ap.add_argument("--dc-only", action="store_true", help="after a sweep, only scan likely DCs")
    ap.add_argument("--json", help="write results to this JSON file")
    args = ap.parse_args()

    if not args.fqdn and not args.host:
        ap.error("provide --fqdn (passive) and/or --host (active)")

    candidates = build_candidates(args.fqdn) if args.fqdn else []
    all_results = {}

    # ---- PASSIVE (always safe, no host contact) ----
    if args.fqdn and not args.host and not args.subnet and not args.only and not args.aggressive:
        v, _ = run_passive(args.fqdn)
        all_results["__passive__"] = {"verdict": v, "detail": json.loads(json.dumps(RESULTS))}
        if args.json:
            with open(args.json, "w") as f:
                json.dump(all_results, f, indent=2)
        return

    # ---- ACTIVE: enforce the authorization gate ----
    want_active = bool(args.host or args.subnet or args.only or args.aggressive)
    base = args.host or args.fqdn
    ip = resolve_ip(base) if base else None
    if args.fqdn and not args.host and not args.subnet and args.authorized and not args.scope:
        if ip:
            args.scope = [f"{ip}/32"]
            info(f"[*] Scope from FQDN resolution: {ip}/32")
    if want_active:
        if not args.authorized or not args.scope:
            info("[-] Active scanning requires --authorized and a resolvable scope.")
            info("    This gate exists so the tool cannot be pointed at a network")
            info("    you have not been authorized to test. If you have written")
            info("    permission, pass --scope <CIDR>, or use --fqdn to scope its IP")
            if args.fqdn:
                info("\n[*] Running PASSIVE inference only for now:\n")
                run_passive(args.fqdn)
            sys.exit(2)

    # build active target list
    active_targets = []
    if args.subnet is not None:
        if not ip:
            sys.exit(f"[-] could not resolve {base} to an IP")
        hosts, dcs = sweep_subnet(ip, args.subnet, args.threads, args.sweep_timeout)
        picked = dcs if args.dc_only else hosts
        active_targets = [h for h in picked if in_scope(h, args.scope)]
        skipped = [h for h in picked if not in_scope(h, args.scope)]
        if skipped:
            info(f"[*] {len(skipped)} live host(s) skipped: outside --scope")
        if not active_targets:
            sys.exit("[-] no in-scope live hosts to scan")
    else:
        if not in_scope(ip, args.scope):
            sys.exit(f"[-] {base} ({ip}) is not inside --scope {args.scope}; refusing.")
        active_targets = [ip]

    info(f"\n[*] Authorized active scan of {len(active_targets)} in-scope host(s)\n")
    for t in active_targets:
        RESULTS.clear()
        if args.fqdn:
            for k, v in {"__candidates__": candidates}.items():
                pass
        v = scan_host(t, candidates, args.only, args.aggressive)
        all_results[t] = {"verdict": v, "detail": json.loads(json.dumps(RESULTS))}

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=2)
        info(f"\n[*] Results written to {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)