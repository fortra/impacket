#!/usr/bin/env python3
"""
tds_named_pipe.py - MSSQL Named Pipe transport for impacket's tds.py

Key fix:
    The server may close the SMB pipe immediately if the wrong initial
    handshake is used (PRELOGIN vs direct LOGIN7).

    Therefore:
        - each handshake attempt must use a fresh SMB pipe
        - no reuse of broken transport
"""

import sys
import struct
import argparse
import random

from impacket.tds import (
    MSSQL,
    TDS_PRELOGIN,
    TDS_LOGIN,
    TDS_LOGIN7,
    TDS_PRE_LOGIN,
    TDS_LOGINACK_TOKEN,
    TDS_LOGIN7_VERSION_71,
    TDS_INIT_LANG_FATAL,
    TDS_ODBC_ON,
    TDS_ENCRYPT_OFF,
    TDS_ENCRYPT_ON,
    TDS_ENCRYPT_REQ,
    TDS_ENCRYPT_STRICT,
)
from impacket.smbconnection import SMBConnection
from impacket import LOG
from impacket.mssql.version import MSSQL_VERSION


# ============================================================
# SMB Named Pipe Transport
# ============================================================

class NamedPipeTransport:
    MSSQL_PIPE = "sql\\query"

    def __init__(self, address, pipe_name=None):
        self.address = address
        self.pipe_name = pipe_name or self.MSSQL_PIPE
        self._smb = None
        self._tid = None
        self._fid = None
        self._recv_buf = b""

    def connect(self, timeout=30):
        self._smb = SMBConnection(self.address, self.address, timeout=timeout)

    def authenticate_ntlm(self, username, password, domain, lmhash="", nthash=""):
        self._smb.login(username, password, domain, lmhash, nthash)
        self._open_pipe()

    def authenticate_kerberos(self, username, password, domain, lmhash="", nthash="", aesKey="", kdcHost=None, TGT=None, TGS=None, useCache=True):
        self._smb.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, kdcHost, TGT, TGS, useCache)
        self._open_pipe()

    def _open_pipe(self):
        self._tid = self._smb.connectTree("IPC$")
        self._fid = self._smb.openFile(
            self._tid,
            self.pipe_name,
            desiredAccess=0x0012019F,
        )

    def sendall(self, data):
        self._smb.writeFile(self._tid, self._fid, data)

    def recv(self, bufsize):
        if self._recv_buf:
            chunk = self._recv_buf[:bufsize]
            self._recv_buf = self._recv_buf[bufsize:]
            return chunk

        data = self._smb.readFile(self._tid, self._fid, bytesToRead=bufsize)
        if not data:
            return b""

        if len(data) > bufsize:
            self._recv_buf = data[bufsize:]
            return data[:bufsize]

        return data

    def settimeout(self, timeout):
        pass

    def close(self):
        try:
            if self._fid:
                self._smb.closeFile(self._tid, self._fid)
            if self._tid:
                self._smb.disconnectTree(self._tid)
            if self._smb:
                self._smb.logoff()
                self._smb.close()
        except Exception as e:
            LOG.debug(f"close error: {e}")
        finally:
            self._fid = None
            self._tid = None
            self._smb = None


# ============================================================
# MSSQL Named Pipe Client
# ============================================================

class MSSQLNamedPipe(MSSQL):

    def __init__(self, address, pipe_name=None, **kwargs):
        super().__init__(address, **kwargs)
        self._pipe_name = pipe_name or NamedPipeTransport.MSSQL_PIPE
        self._transport = None

    # --------------------------------------------------------
    # IMPORTANT: always rebuild transport per attempt
    # --------------------------------------------------------

    def _create_transport(self, username, password, domain, lmhash="", nthash="", kerberos=False, timeout=30):
        transport = NamedPipeTransport(self.server, self._pipe_name)
        transport.connect(timeout)

        if kerberos:
            transport.authenticate_kerberos( username, password, domain, lmhash, nthash, "", None, None, None, True )
        else:
            transport.authenticate_ntlm(username, password, domain, lmhash, nthash)

        self._transport = transport
        self.socket = transport

    # --------------------------------------------------------
    # connection override
    # --------------------------------------------------------

    def connect(self, timeout=30):
        pass

    def disconnect(self):
        try:
            if self._transport:
                self._transport.close()
        finally:
            self._transport = None
            self.socket = 0
            self._reset_tls_state()

    # --------------------------------------------------------
    # IO dispatch
    # --------------------------------------------------------

    def socketSendall(self, data):
        if self.tlsSocket is None:
            return self.socket.sendall(data)
        return self.tls_send(data)

    def socketRecv(self, bufsize):
        if self.tlsSocket is None:
            data = self.socket.recv(bufsize)
            if not data:
                raise ConnectionError("Named pipe closed")
            return data
        return self.tls_recv(bufsize)

    # --------------------------------------------------------
    # PRELOGIN
    # --------------------------------------------------------

    def preLogin(self):
        prelogin = TDS_PRELOGIN()
        prelogin["Version"] = b"\x08\x00\x01\x55\x00\x00"
        prelogin["Encryption"] = TDS_ENCRYPT_OFF
        prelogin["ThreadID"] = struct.pack("<L", random.randint(0, 65535))
        prelogin["Instance"] = b"MSSQLServer\x00"

        self.sendTDS(TDS_PRE_LOGIN, prelogin.getData(), 0)

        tds = self.recvTDS()
        resp = TDS_PRELOGIN(tds["Data"])

        self.mssql_version = MSSQL_VERSION(resp["Version"])
        return resp

    def _negotiate_encryption(self):
        resp = self.preLogin()

        print(resp["Encryption"] )
        if resp["Encryption"] == TDS_ENCRYPT_STRICT:
            raise NotImplementedError("ENCRYPT_STRICT not supported")

        if resp["Encryption"] in (TDS_ENCRYPT_REQ, TDS_ENCRYPT_ON):
            self.set_tls_context()

        return resp

    # --------------------------------------------------------
    # LOGIN builder
    # --------------------------------------------------------

    def _send_login(self, database=None):

        login = TDS_LOGIN()
        login["TDSVersion"] = TDS_LOGIN7_VERSION_71
        self._set_session_login7_tds_version(TDS_LOGIN7_VERSION_71)

        login["HostName"] = self.workstation_id.encode("utf-16le")
        login["AppName"] = self.application_name.encode("utf-16le")
        login["ServerName"] = self.remoteName.encode("utf-16le")
        login["CltIntName"] = self.client_interface_name.encode("utf-16le")

        login["ClientPID"] = random.randint(0, 1024)
        login["PacketSize"] = self.packetSize

        login["OptionFlags2"] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON

        login["SSPI"] = b""
        login["UserName"] = b""
        login["Password"] = b""

        if database:
            login["Database"] = database.encode("utf-16le")

        login["Length"] = len(login.getData())

        self.sendTDS(TDS_LOGIN7, login.getData())

        tds = self.recvTDS()
        self.replies = self.parseReply(tds["Data"])

        return TDS_LOGINACK_TOKEN in self.replies

    # legacy login
    def _login_legacy(self, database=None):

        return self._send_login(database)

    # --------------------------------------------------------
    # CRITICAL FIX: handshake with full pipe rebuild
    # --------------------------------------------------------

    def login_named_pipe(self, username, password, domain, lmhash="", nthash="", database=None, kerberos=False):

        # -------------------------
        # Attempt 1: PRELOGIN
        # -------------------------
        try:
            self._create_transport(username, password, domain, lmhash, nthash, kerberos) 
            self._negotiate_encryption()
            return self._send_login(database)
        except Exception as e:
            print(f"PRELOGIN failed -> retry legacy: {e}")
        self.disconnect()

        # -------------------------
        # Attempt 2: LEGACY LOGIN
        # -------------------------
        try:
            self._create_transport(username, password, domain, lmhash, nthash, kerberos)
            return self._login_legacy(database)

        except Exception as e:
            print(f"Legacy login failed: {e}")
            raise ConnectionError("Instance is probably exposed with force strict encryption enabled.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("domain")
    parser.add_argument("--pipe", default=NamedPipeTransport.MSSQL_PIPE)
    parser.add_argument("--query", default="SELECT @@VERSION")
    parser.add_argument("--database", default="master")
    parser.add_argument("--kerberos", action="store_true")
    args = parser.parse_args()

    mssql = MSSQLNamedPipe(args.target, pipe_name=args.pipe, remoteName=args.target)
    print(f"[*] Connecting \\\\{args.target}\\pipe\\{args.pipe}")
    ok = mssql.login_named_pipe(args.username, args.password, args.domain, database=args.database, kerberos=args.kerberos)

    if not ok:
        print("[-] login failed")
        mssql.printReplies()
        mssql.disconnect()
        sys.exit(1)

    print("[+] authenticated via named pipe")
    rows = mssql.batch(args.query)
    for r in rows or []:
        print(r)

    mssql.disconnect()


if __name__ == "__main__":
    main()