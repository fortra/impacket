#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Simple packet sniffer.
#
#   This packet sniffer uses the pcap library to listen for packets in
#   transit over the specified interface. The returned packages can be
#   filtered according to a BPF filter (see tcpdump(3) for further
#   information on BPF filters).
#
#   Note that the user might need special permissions to be able to use pcap.
#
# Authors:
#   Maximiliano Caceres
#   Javier Kohen
#
# Reference for:
#   pcapy: findalldevs, open_live
#   ImpactDecoder
#

import sys
from threading import Thread
import pcapy
from pcapy import findalldevs, open_live

from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


class DecoderThread(Thread):
    def __init__(self, pcapObj):
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        Thread.__init__(self)

    def run(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        # Display the packet in human-readable form.
        print(self.decoder.decode(data))


def getInterface():
    # Grab a list of interfaces that pcap is able to listen on.
    # The current user will be able to listen from all returned interfaces,
    # using open_live to open them.
    ifs = findalldevs()

    # No interfaces available, abort.
    if 0 == len(ifs):
        print("You don't have enough permissions to open any interface on this system.")
        sys.exit(1)

    # Only one interface available, use it.
    elif 1 == len(ifs):
        print('Only one interface present, defaulting to it.')
        return ifs[0]

    # Ask the user to choose an interface from the list.
    count = 0
    for iface in ifs:
        print('%i - %s' % (count, iface))
        count += 1
    idx = int(input('Please select an interface: '))

    return ifs[idx]

def main(filter):
    dev = getInterface()

    # Open interface for catpuring.
    p = open_live(dev, 1500, 0, 100)

    # Set the BPF filter. See tcpdump(3).
    p.setfilter(filter)

    print("Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink()))

    # Start sniffing thread and finish main thread.
    DecoderThread(p).start()

# Process command-line arguments. Take everything as a BPF filter to pass
# onto pcap. Default to the empty filter (match all).
filter = ''
if len(sys.argv) > 1:
    filter = ' '.join(sys.argv[1:])

main(filter)
