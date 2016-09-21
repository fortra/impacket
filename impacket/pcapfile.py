# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

from impacket import ImpactPacket, ImpactDecoder, structure

O_ETH = 0
O_IP  = 1
O_ARP = 1
O_UDP = 2
O_TCP = 2
O_ICMP = 2
O_UDP_DATA = 3
O_ICMP_DATA = 3

MAGIC = '"\xD4\xC3\xB2\xA1'

class PCapFileHeader(structure.Structure):
    structure = (
        ('magic', MAGIC),
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

class PcapFile:
    def __init__(self, fileName = None, mode = 'rb'):
        if not fileName is None:
           self.file = open(fileName, mode)
        self.hdr = None
        self.wroteHeader = False

    def reset(self):
        self.hdr = None
        self.file.seek(0)

    def close(self):
        self.file.close()

    def fileno(self):
        return self.file.fileno()

    def setFile(self, file):
        self.file = file

    def setSnapLen(self, snapLen):
        self.createHeaderOnce()
        self.hdr['maxLength'] = snapLen

    def getSnapLen(self):
        self.readHeaderOnce()
        return self.hdr['maxLength']

    def setLinkType(self, linkType):
        self.createHeaderOnce()
        self.hdr['linkType'] = linkType

    def getLinkType(self):
        self.readHeaderOnce()
        return self.hdr['linkType']

    def readHeaderOnce(self):
        if self.hdr is None:
           self.hdr = PCapFileHeader.fromFile(self.file)

    def createHeaderOnce(self):
        if self.hdr is None:
           self.hdr = PCapFileHeader()
    
    def writeHeaderOnce(self):
        if not self.wroteHeader:
           self.wroteHeader = True
           self.file.seek(0)
           self.createHeaderOnce()
           self.file.write(str(self.hdr))

    def read(self):
       self.readHeaderOnce()
       try:
          pkt = PCapFilePacket.fromFile(self.file)
          pkt['data'] = self.file.read(pkt['savedLength'])
          return pkt
       except:
          return None

    def write(self, pkt):
        self.writeHeaderOnce()
        self.file.write(str(pkt))

    def packets(self):
        self.reset()
        while 1:
           answer = self.read()
           if answer is None: break
           yield answer

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

    #hdr.dump()

    decoder = ImpactDecoder.EthDecoder()
    while 1:
       pkt = PCapFilePacket()
       try:
          pkt.fromString(f_in.read(len(pkt)))
       except:
          break
       pkt['data'] = f_in.read(pkt['savedLength'])
       hdr['packets'].append(pkt)
       p = pkt['data']
       try:    in_onion = [decoder.decode(p[1])]
       except: in_onion = [decoder.decode(p[0])]
       try:
          while 1: in_onion.append(in_onion[-1].child())
       except:
          pass

       process(in_onion)
       pkt.dump()
       #print "%r" % str(pkt)

       if f_out:
          #print eth

          pkt_out = PCapFilePacket()
          pkt_out['data'] = str(eth.get_packet())

          #pkt_out.dump()

          f_out.write(str(pkt_out))

if __name__ == '__main__':
   main()
    
