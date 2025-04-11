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
#   Simple packet sniffer.
#
#   This packet sniffer uses a raw socket to listen for packets
#   in transit corresponding to the specified protocols.
#
#   Note that the user might need special permissions to be able to use
#   raw sockets.
#
# Authors:
#   Gerardo Richarte (@gerasdf)
#   Javier Kohen
#
# Reference for:
#   ImpactDecoder
#

import argparse
from select import select
import socket
import sys

from impacket import ImpactDecoder

DEFAULT_PROTOCOLS = ('icmp', 'tcp', 'udp')

parser = argparse.ArgumentParser(add_help=True, description='Simple packet sniffer.')
parser.add_argument('protocols', nargs='*', help='A list of protocols', default=DEFAULT_PROTOCOLS)

group = parser.add_argument_group('SOCKS Proxy Options')
group.add_argument('-socks', action='store_true', default=False,
                    help='Use a SOCKS proxy for the connection')
group.add_argument('-socks-address', default='127.0.0.1', help='SOCKS5 server address')
group.add_argument('-socks-port', default=1080, type=int, help='SOCKS5 server port')

options = parser.parse_args()
toListen = options.protocols

# Relay connections through a socks proxy
if (options.socks):
    print('Relaying connections through SOCKS proxy (%s:%s)', options.socks_address, options.socks_port)
    import socket
    import socks

    socks.set_default_proxy(socks.SOCKS5, options.socks_address, options.socks_port)
    socket.socket = socks.socksocket

# Open one socket for each specified protocol.
# A special option is set on the socket so that IP headers are included with
# the returned data.
sockets = []
for protocol in toListen:
    try:
        protocol_num = socket.getprotobyname(protocol)
    except socket.error:
        print("Ignoring unknown protocol:", protocol)
        toListen.remove(protocol)
        continue
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol_num)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sockets.append(s)

if 0 == len(toListen):
    print("There are no protocols available.")
    sys.exit(0)

print("Listening on protocols:", toListen)

# Instantiate an IP packets decoder.
# As all the packets include their IP header, that decoder only is enough.
decoder = ImpactDecoder.IPDecoder()

while len(sockets) > 0:
    # Wait for an incoming packet on any socket.
    ready = select(sockets, [], [])[0]
    for s in ready:
        packet = s.recvfrom(4096)[0]
        if 0 == len(packet):
            # Socket remotely closed. Discard it.
            sockets.remove(s)
            s.close()
        else:
            # Packet received. Decode and display it.
            packet = decoder.decode(packet)
            print(packet)
