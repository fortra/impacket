#!/usr/bin/env python
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
#   Simple ICMP6 ping.
#
#   This implementation of ping uses the ICMP echo and echo-reply packets
#   to check the status of a host. If the remote host is up, it should reply
#   to the echo probe with an echo-reply packet.
#   Note that this isn't a definite test, as in the case the remote host is up
#   but refuses to reply the probes.
#   Also note that the user must have special access to be able to open a raw
#   socket, which this program requires.
#
# Authors:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   ImpactPacket: ICMP6
#   ImpactDecoder
#

import argparse
import select
import socket
import time
import sys

from impacket import ImpactDecoder, IP6, ICMP6, version

print(version.BANNER)

parser = argparse.ArgumentParser(add_help=True, description='Simple ICMP6 ping.')
parser.add_argument('src', help='Source IP')
parser.add_argument('dst', help='Destination IP')

group = parser.add_argument_group('SOCKS Proxy Options')
group.add_argument('-socks', action='store_true', default=False,
                    help='Use a SOCKS proxy for the connection')
group.add_argument('-socks-address', default='127.0.0.1', help='SOCKS5 server address')
group.add_argument('-socks-port', default=1080, type=int, help='SOCKS5 server port')

options = parser.parse_args()

# Relay connections through a socks proxy
if (options.socks):
    print('Relaying connections through SOCKS proxy (%s:%s)', options.socks_address, options.socks_port)
    import socket
    import socks

    socks.set_default_proxy(socks.SOCKS5, options.socks_address, options.socks_port)
    socket.socket = socks.socksocket

src = options.src
dst = options.dst

# Create a new IP packet and set its source and destination addresses.

ip = IP6.IP6()
ip.set_ip_src(src)
ip.set_ip_dst(dst)
ip.set_traffic_class(0)
ip.set_flow_label(0)
ip.set_hop_limit(64)

# Open a raw socket. Special permissions are usually required.
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)

payload = b"A"*156

print("PING %s %d data bytes" % (dst, len(payload)))
seq_id = 0
while 1:
    # Give the ICMP packet the next ID in the sequence.
    seq_id += 1
    icmp = ICMP6.ICMP6.Echo_Request(1, seq_id, payload)

    # Have the IP packet contain the ICMP packet (along with its payload).
    ip.contains(icmp)
    ip.set_next_header(ip.child().get_ip_protocol_number())
    ip.set_payload_length(ip.child().get_size())
    icmp.calculate_checksum()

    # Send it to the target host.
    s.sendto(icmp.get_packet(), (dst, 0))

    # Wait for incoming replies.
    if s in select.select([s], [], [], 1)[0]:
        reply = s.recvfrom(2000)[0]

        # Use ImpactDecoder to reconstruct the packet hierarchy.
        rip = ImpactDecoder.ICMP6Decoder().decode(reply)

        # If the packet matches, report it to the user.
        if ICMP6.ICMP6.ECHO_REPLY == rip.get_type():
            print("%d bytes from %s: icmp_seq=%d " % (rip.child().get_size()-4, dst, rip.get_echo_sequence_number()))

        time.sleep(1)
