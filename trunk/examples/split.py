#!/usr/bin/python
# $Id$
#
# Pcap dump splitter.
#
# This tools splits pcap capture files into smaller ones, one for each
# TCP connection found in the original.
#
# Authors:
#  Alejandro D. Weil <aweil@coresecurity.com>
#  Javier Kohen <jkohen@coresecurity.com>
#
# Reference for:
#  pcapy: open_offline.
#  ImpactDecoder.

import sys
import string
from threading import Thread

import pcapy
from pcapy import open_offline
import impact
from impact.ImpactDecoder import EthDecoder, LinuxSLLDecoder

class Connection:
    def __init__(self, p1, p2):
        self.p1 = p1
        self.p2 = p2

    def getFilename(self):
        return '%s:%d-%s:%d.pcap'%(self.p1[0],self.p1[1],self.p2[0],self.p2[1])

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
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        # Display the packet in human-readable form.

        p = self.decoder.decode(data)
        ip = p.child()
        tcp = ip.child()
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )
        con = Connection(src,dst)
        print '.',

        if not self.connections.has_key(con):
            print con.getFilename()
            dumper = self.pcap.dump_open(con.getFilename())
            self.connections[con] = dumper

        self.connections[con].dump(hdr, data)



def main(filename):
    # Open file
    p = open_offline(filename)
    p.setfilter('ip proto \\tcp')

    print "Reading from %s: linktype=%d" % (filename, p.datalink())

    # Start sniffing thread and finish main thread.
    Decoder(p).start()


# Process command-line arguments. Take everything as a BPF filter to pass
# onto pcap. Default to the empty filter (match all).
if __name__ == '__main__':
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = 'test.pcap'
    main(filename)
