#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
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

import select
import socket
import time
import sys

from impacket import ImpactDecoder, IP6, ICMP6, version

print(version.BANNER)

if len(sys.argv) < 3:
    print("Use: %s <src ip> <dst ip>" % sys.argv[0])
    sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2]

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
