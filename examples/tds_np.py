#!/usr/bin/env python3
"""
tds_named_pipe.py - MSSQL Named Pipe transport patch for impacket's tds.py

Usage:
    python tds_named_pipe.py <target> <username> <password> <domain>

Example:
    python tds_named_pipe.py 192.168.1.10 Administrator Password123 CORP
    python tds_named_pipe.py 192.168.1.10 Administrator '' CORP --hashes :aabbcc...
"""

import sys
import argparse
import random
from impacket.tds import (
    MSSQL, TDS_LOGIN, TDS_LOGIN7, TDS_LOGINACK_TOKEN,
    TDS_LOGIN7_VERSION_71, TDS_INIT_LANG_FATAL, TDS_ODBC_ON,
)
from impacket.smbconnection import SMBConnection
from impacket import LOG


class NamedPipeTransport:
    """
    Transport layer for MSSQL over Named Pipes via SMB.
    Duck-typed to replace self.socket in MSSQL.
    Auth (NTLM/Kerberos) happens at SMB level, before any TDS exchange.
    """

    MSSQL_PIPE = "sql\\query"

    def __init__(self, address, pipe_name=None):
        self.address = address
        self.pipe_name = pipe_name or self.MSSQL_PIPE
        self._smb = None
        self._tid = None
        self._fid = None
        self._recv_buffer = b""

    def connect(self, timeout=30):
        self._smb = SMBConnection(self.address, self.address, timeout=timeout)

    def authenticate_ntlm(self, username, password, domain, lmhash="", nthash=""):
        self._smb.login(username, password, domain, lmhash, nthash)
        self._open_pipe()

    def authenticate_kerberos(self, username, password, domain,
                               lmhash="", nthash="", aesKey="",
                               kdcHost=None, TGT=None, TGS=None, useCache=True):
        self._smb.kerberosLogin(username, password, domain,
                                lmhash, nthash, aesKey,
                                kdcHost, TGT, TGS, useCache)
        self._open_pipe()

    def _open_pipe(self):
        self._tid = self._smb.connectTree("IPC$")
        self._fid = self._smb.openFile(
            self._tid,
            self.pipe_name,
            desiredAccess=0x0012019F,  # GENERIC_READ | GENERIC_WRITE
        )

    def sendall(self, data):
        self._smb.writeFile(self._tid, self._fid, data)

    def recv(self, bufsize):
        if self._recv_buffer:
            chunk = self._recv_buffer[:bufsize]
            self._recv_buffer = self._recv_buffer[bufsize:]
            return chunk
        data = self._smb.readFile(self._tid, self._fid, bytesToRead=bufsize)
        if len(data) > bufsize:
            self._recv_buffer = data[bufsize:]
            return data[:bufsize]
        return data

    def close(self):
        if self._smb:
            try:
                if self._fid:
                    self._smb.closeFile(self._tid, self._fid)
                if self._tid:
                    self._smb.disconnectTree(self._tid)
                self._smb.logoff()
                self._smb.close()
            except Exception as e:
                LOG.debug(f"NamedPipeTransport.close() error: {e}")
            finally:
                self._fid = None
                self._tid = None
                self._smb = None


class MSSQLNamedPipe(MSSQL):
    """
    MSSQL subclass with Named Pipe transport support.
    Overrides connect/disconnect/socketSendall/socketRecv.

    Key difference vs TCP:
        - Auth is done at SMB level (NTLM/Kerberos) before TDS
        - preLogin() is skipped entirely: SQL Server accepts a direct TDS_LOGIN7
          on named pipe without the preLogin handshake
        - login()/kerberosLogin() must NOT re-authenticate via SSPI
          -> we send a TDS_LOGIN7 with empty SSPI and no Windows auth flag
        - No TLS negotiation: confidentiality is handled by SMB signing/encryption
    """

    def __init__(self, address, pipe_name=None, **kwargs):
        super().__init__(address, **kwargs)
        self._pipe_name = pipe_name or NamedPipeTransport.MSSQL_PIPE
        self._named_pipe_transport = None

    def connect_named_pipe(self, username, password, domain,
                           lmhash="", nthash="", timeout=30):
        """
        Connect and authenticate via Named Pipe (NTLM).
        Must be called instead of connect() for named pipe mode.
        """
        self._reset_tls_state()
        transport = NamedPipeTransport(self.server, self._pipe_name)
        transport.connect(timeout)
        transport.authenticate_ntlm(username, password, domain, lmhash, nthash)
        self._named_pipe_transport = transport
        self.socket = transport
        LOG.info(f"Named pipe connected: \\\\{self.server}\\pipe\\{self._pipe_name}")

    def connect_named_pipe_kerberos(self, username, password, domain,
                                     lmhash="", nthash="", aesKey="",
                                     kdcHost=None, TGT=None, TGS=None,
                                     useCache=True, timeout=30):
        """
        Connect and authenticate via Named Pipe (Kerberos).
        """
        self._reset_tls_state()
        transport = NamedPipeTransport(self.server, self._pipe_name)
        transport.connect(timeout)
        transport.authenticate_kerberos(username, password, domain,
                                         lmhash, nthash, aesKey,
                                         kdcHost, TGT, TGS, useCache)
        self._named_pipe_transport = transport
        self.socket = transport
        LOG.info(f"Named pipe connected (Kerberos): \\\\{self.server}\\pipe\\{self._pipe_name}")

    def disconnect(self):
        try:
            if self._named_pipe_transport:
                self._named_pipe_transport.close()
            elif self.socket:
                self.socket.close()
        finally:
            self.socket = 0
            self._named_pipe_transport = None
            self._reset_tls_state()

    def socketSendall(self, data):
        if self._named_pipe_transport:
            return self._named_pipe_transport.sendall(data)
        return super().socketSendall(data)

    def socketRecv(self, bufsize):
        if self._named_pipe_transport:
            data = self._named_pipe_transport.recv(bufsize)
            if not data:
                raise ConnectionError("Named pipe: server closed connection")
            return data
        return super().socketRecv(bufsize)

    def login_named_pipe(self, database=None):
        """
        TDS login for named pipe connections.
        Auth is already done at SMB level so we skip preLogin entirely
        and send a minimal TDS_LOGIN7 without SSPI and without Windows auth flag.
        """
        login = TDS_LOGIN()
        login["TDSVersion"] = TDS_LOGIN7_VERSION_71
        self._set_session_login7_tds_version(TDS_LOGIN7_VERSION_71)
        login["HostName"] = self.workstation_id.encode("utf-16le")
        login["AppName"] = self.application_name.encode("utf-16le")
        login["ServerName"] = self.remoteName.encode("utf-16le")
        login["CltIntName"] = self.client_interface_name.encode("utf-16le")
        login["ClientPID"] = random.randint(0, 1024)
        login["PacketSize"] = self.packetSize
        if database:
            login["Database"] = database.encode("utf-16le")
        login["OptionFlags2"] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON
        login["SSPI"] = b""
        login["UserName"] = b""
        login["Password"] = b""
        login["Length"] = len(login.getData())

        self.sendTDS(TDS_LOGIN7, login.getData())
        tds = self.recvTDS()
        self.replies = self.parseReply(tds["Data"])

        if TDS_LOGINACK_TOKEN in self.replies:
            return True
        return False


def main():
    parser = argparse.ArgumentParser(description="MSSQL Named Pipe test client")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("username", help="Username")
    parser.add_argument("password", help="Password")
    parser.add_argument("domain", help="Domain")
    parser.add_argument("--hashes", help="LM:NT hashes", default="")
    parser.add_argument("--pipe", help="Pipe name", default=NamedPipeTransport.MSSQL_PIPE)
    parser.add_argument("--query", help="SQL query to run", default="SELECT @@VERSION")
    parser.add_argument("--database", help="Database", default="master")
    args = parser.parse_args()

    lmhash = ""
    nthash = ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":")

    mssql = MSSQLNamedPipe(args.target, pipe_name=args.pipe, remoteName=args.target)

    print(f"[*] Connecting to \\\\{args.target}\\pipe\\{args.pipe}")
    mssql.connect_named_pipe(
        username=args.username,
        password=args.password,
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
    )

    print("[*] Sending TDS login...")
    if mssql.login_named_pipe(database=args.database):
        print("[+] Authenticated via named pipe")
    else:
        print("[-] TDS login failed")
        mssql.printReplies()
        mssql.disconnect()
        sys.exit(1)

    print(f"[*] Running: {args.query}")
    rows = mssql.batch(args.query)
    mssql.printReplies()

    if rows:
        for row in rows:
            print(row)
    else:
        print("(no rows)")

    mssql.disconnect()


if __name__ == "__main__":
    main()