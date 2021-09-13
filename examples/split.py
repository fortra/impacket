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
#   Pcap dump splitter
#
#   This tools splits pcap capture files into smaller ones, one for each
#   different TCP/IP connection found in the original.
#
# Authors:
#   Alejandro D. Weil
#   Javier Kohen
#
# Reference for:
#   pcapy: open_offline, pcapdumper
#   ImpactDecoder
#

from __future__ import division
from __future__ import print_function
import sys
import pcapy
from pcapy import open_offline

from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


class Connection:
    """This class can be used as a key in a dictionary to select a connection
    given a pair of peers. Two connections are considered the same if both
    peers are equal, despite the order in which they were passed to the
    class constructor.
    """

    def __init__(self, p1, p2):
        """This constructor takes two tuples, one for each peer. The first
        element in each tuple is the IP address as a string, and the
        second is the port as an integer.
        """

        self.p1 = p1
        self.p2 = p2

    def getFilename(self):
        """Utility function that returns a filename composed by the IP
        addresses and ports of both peers.
        """
        return '%s.%d-%s.%d.pcap'%(self.p1[0],self.p1[1],self.p2[0],self.p2[1])

    def __cmp__(self, other):
        if ((self.p1 == other.p1 and self.p2 == other.p2)
            or (self.p1 == other.p2 and self.p2 == other.p1)):
            return 0
        else:
            return -1

    def __hash__(self):
        return (hash(self.p1[0]) ^ hash(self.p1[1])
                ^ hash(self.p2[0]) ^ hash(self.p2[1]))


class Decoder:
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
        self.connections = {}

    def start(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        """Handles an incoming pcap packet. This method only knows how
        to recognize TCP/IP connections.
        Be sure that only TCP packets are passed onto this handler (or
        fix the code to ignore the others).

        Setting r"ip proto \tcp" as part of the pcap filter expression
        suffices, and there shouldn't be any problem combining that with
        other expressions.
        """

        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        p = self.decoder.decode(data)
        ip = p.child()
        tcp = ip.child()

        # Build a distinctive key for this pair of peers.
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )
        con = Connection(src,dst)

        # If there isn't an entry associated yetwith this connection,
        # open a new pcapdumper and create an association.
        if ('%s%s' % (con.p1, con.p2)) not in self.connections:
            fn = con.getFilename()
            print("Found a new connection, storing into:", fn)
            try:
                dumper = self.pcap.dump_open(fn)
            except pcapy.PcapError:
                print("Can't write packet to:", fn)
                return
            self.connections['%s%s' % (con.p1, con.p2)] = dumper

        # Write the packet to the corresponding file.
        self.connections['%s%s' % (con.p1, con.p2)].dump(hdr, data)



def main(filename):
    # Open file
    p = open_offline(filename)

    # At the moment the callback only accepts TCP/IP packets.
    p.setfilter(r'ip proto \tcp')

    print("Reading from %s: linktype=%d" % (filename, p.datalink()))

    # Start decoding process.
    Decoder(p).start()


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Usage: %s <filename>" % sys.argv[0])
        sys.exit(1)

    main(sys.argv[1])
