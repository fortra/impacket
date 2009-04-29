from impacket import ImpactPacket, ImpactDecoder, structure

O_ETH = 0
O_IP  = 1
O_ARP = 1
O_UDP = 2
O_TCP = 2
O_ICMP = 2
O_UDP_DATA = 3
O_ICMP_DATA = 3

class PCapFileHeader(structure.Structure):
    structure = (
        ('magic', '"\xd4\xc3\xb2\xa1'),
        ('versionMajor', '<H=2'),
        ('versionMinor', '<H=4'),
        ('GMT2localCorrection', '<l=0'),
        ('timeAccuracy', '<L=0'),
        ('maxLength', '<L=0xffff'),
        ('linkType', '<L=1'),
        ('packets','*:=[]'),
    )

class PCapFilePacket(structure.Structure):
    structure = (
        ('tsec', '<L=0'),
        ('tmsec', '<L=0'),
        ('savedLength', '<L-data'),
        ('realLength', '<L-data'),
        ('data',':'),
    )

    def __init__(self, *args, **kargs):
        structure.Structure.__init__(self, *args, **kargs)
        self['data'] = ''

def process(onion):
    # for dhcp we only want UDP packets
    if len(onion) <= O_UDP: return
    if onion[O_UDP].protocol != ImpactPacket.UDP.protocol:
       return

    # we only want UDP port 67
    if ((onion[O_UDP].get_uh_dport() != 67) and
        (onion[O_UDP].get_uh_sport() != 67)): return

    # we've got a dhcp packet
    
def main():
    import sys

    f_in = open(sys.argv[1],'rb')
    try:
       f_out = open(sys.argv[2],'wb')
       f_out.write(str(PCapFileHeader()))
    except:
       f_out = None

    hdr = PCapFileHeader()
    hdr.fromString(f_in.read(len(hdr)))

    hdr.dump()

    decoder = ImpactDecoder.EthDecoder()
    while 1:
       pkt = PCapFilePacket()
       try:
          pkt.fromString(f_in.read(len(pkt)))
       except:
          break
       pkt['data'] = f_in.read(pkt['savedLength'])
       hdr['packets'].append(pkt)

       p = self.pcap.next()
       try:    in_onion = [self.decoder.decode(p[1])]
       except: in_onion = [self.decoder.decode(p[0])]
       try:
          while 1: in_onion.append(in_onion[-1].child())
       except:
          pass

       process(in_onion)
       #pkt.dump()
       #print "%r" % str(pkt)

       if f_out:
          #print eth

          pkt_out = PCapFilePacket()
          pkt_out['data'] = str(eth.get_packet())

          #pkt_out.dump()

          f_out.write(str(pkt_out))

if __name__ == '__main__':
   main()
    
