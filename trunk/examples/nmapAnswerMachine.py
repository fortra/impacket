import random

import os_ident
import pcapy
from impacket import ImpactPacket
from impacket import ImpactDecoder

EMMULATING = 'Adtran NetVanta 3200 router'
# EMMULATING = 'ADIC Scalar 1000 tape library remote management unit'

MAC = "01:02:03:04:05:06"
IP  = "192.168.67.254"
IFACE = "eth0"
TCP_OPEN_PORT = 80
TCP_CLOSED_PORT = 22

O_ETH = 0
O_IP  = 1
O_ARP = 1
O_UDP = 2
O_TCP = 2
O_ICMP = 2

def string2tuple(string):
    if string.find(':') >= 0:
       return [int(x) for x in string.split(':')]
    else:
       return [int(x) for x in string.split('.')]

class Responder:
   def __init__(self, machine, port):
       self.machine = machine
       self.port = port

   def isMine(self, onion):
       return false

   def sendAnswer(self, onion):
       pass

   def process(self, onion):
       if not self.isMine(onion): return False
       print "Got packet for %s" % self.__class__.__name__
       # print onion[0]

       self.sendAnswer(onion)
       return True

   def getIP(self):
       return self.machine.ipAddress

class ARPResponder(Responder):
   def isMine(self, onion):
       if len(onion) < 2: return False

       if onion[O_ARP].ethertype != ImpactPacket.ARP.ethertype:
          return False

       return (
          onion[O_ARP].get_ar_op() == 1 and # ARP REQUEST
          onion[O_ARP].get_ar_tpa() == string2tuple(self.machine.ipAddress))

   def sendAnswer(self, onion):
       eth = ImpactPacket.Ethernet()
       arp = ImpactPacket.ARP()
       eth.contains(arp)

       arp.set_ar_hrd(1)	# Hardward type Ethernet
       arp.set_ar_pro(0x800)	# IP
       arp.set_ar_op(2)	# REPLY
       arp.set_ar_hln(6)
       arp.set_ar_pln(4)
       arp.set_ar_sha(string2tuple(self.machine.macAddress))
       arp.set_ar_spa(string2tuple(self.machine.ipAddress))
       arp.set_ar_tha(onion[O_ARP].get_ar_sha())
       arp.set_ar_tpa(onion[O_ARP].get_ar_spa())

       eth.set_ether_shost(arp.get_ar_sha())
       eth.set_ether_dhost(arp.get_ar_tha())

       self.machine.sendPacket(eth)

class IPResponder(Responder):
   def initAnswer(self, onion):
       eth = ImpactPacket.Ethernet()
       ip = ImpactPacket.IP()

       eth.contains(ip)

       eth.set_ether_shost(onion[O_ETH].get_ether_dhost())
       eth.set_ether_dhost(onion[O_ETH].get_ether_shost())

       ip.set_ip_src(onion[O_IP].get_ip_dst())
       ip.set_ip_dst(onion[O_IP].get_ip_src())

       return eth

   def isMine(self, onion):
       if len(onion) < 2: return False

       return (
           (onion[O_IP].ethertype == ImpactPacket.IP.ethertype) and
           (onion[O_IP].get_ip_dst() == self.machine.ipAddress))

class TCPResponder(IPResponder):
   def initAnswer(self, onion):
       eth = IPResponder.initAnswer(self, onion)
       ip = eth.child()
       tcp = ImpactPacket.TCP()

       ip.contains(tcp)

       tcp.set_th_dport(onion[O_TCP].get_th_sport())
       tcp.set_th_sport(onion[O_TCP].get_th_dport())

       return eth

   def isMine(self, onion):
       if not IPResponder.isMine(self, onion): return False
       if len(onion) < 3: return False

       return onion[O_TCP].protocol == ImpactPacket.TCP.protocol

class TCPClosedPort(TCPResponder):
   def __init__(self, *args):
       TCPResponder.__init__(self, *args)

   def isMine(self, onion):
       if not TCPResponder.isMine(self, onion): return False

       return (
          (onion[O_TCP].get_th_dport() == self.port) and
          onion[O_TCP].get_SYN())

   def sendAnswer(self, onion):
       eth = self.initAnswer(onion)
       ip  = eth.child()
       tcp = ip.child()
       tcp.set_RST()
       tcp.set_th_ack(onion[O_TCP].get_th_seq()+1)

       self.machine.sendPacket(eth)

class TCPOpenPort(TCPResponder):
   def __init__(self, *args):
       TCPResponder.__init__(self, *args)

   def isMine(self, onion):
       if not TCPResponder.isMine(self, onion): return False

       return (
          (onion[O_TCP].get_th_dport() == self.port) and
          onion[O_TCP].get_SYN())

   def initAnswer(self, onion):
       eth = TCPResponder.initAnswer(self, onion)
       ip  = eth.child()
       tcp = ip.child()
       tcp.set_SYN()
       tcp.set_ACK()
       tcp.set_th_ack(onion[O_TCP].get_th_seq()+1)
       tcp.set_th_seq(random.randint(0,65535))

       return eth

   def sendAnswer(self, onion):
       eth = self.initAnswer(onion)
       self.machine.sendPacket(eth)

class nmap2_ecn(TCPOpenPort):
   def __init__(self, *args):
       TCPOpenPort.__init__(self, *args)
       self.template = os_ident.nmap2_ecn_probe(0, ['0.0.0.0',self.getIP()],[self.port, 0])

   def isMine(self, onion):
       if not TCPOpenPort.isMine(self, onion): return False
       
       in_options = onion[O_TCP].get_padded_options()
       template   = self.template.t.get_padded_options()


       return in_options == template

   def sendAnswer(self, onion):
       eth = self.initAnswer(onion)

       fing = self.machine.fingerprint.get_tests()['ECN']

       if (fing['R'] == 'N'): return

       self.machine.sendPacket(eth)

class nmap2_T2(Responder):
   def __init__(self, *args):
       Responder.__init__(self, *args)
       self.template = os_ident.nmap2_tcp_open_2(0, ['0.0.0.0', self.getIP()], [self.port])

class Machine:
   def __init__(self, emmulating, ipAddress, macAddress):
       self.ipAddress = ipAddress
       self.macAddress = macAddress
       self.responders = []
       self.decoder = ImpactDecoder.EthDecoder()

       self.initPcap()
       self.initResponders()
       self.initFingerprint(emmulating)

   def initPcap(self):
       self.pcap = pcapy.open_live(IFACE, 65535, 1, 1)
       self.pcap.setfilter("host %s or ether host %s" % (self.ipAddress, self.macAddress))

   def initResponders(self):
       self.addResponder(ARPResponder(self, 0))
       self.addResponder(nmap2_ecn(self, TCP_OPEN_PORT))
       self.addResponder(TCPOpenPort(self, TCP_OPEN_PORT))
       self.addResponder(TCPClosedPort(self, TCP_CLOSED_PORT))
       # self.addResponder(nmap2_T2(self, TCP_OPEN_PORT))

   def initFingerprint(self, emmulating):
       fpm = os_ident.NMAP2_Fingerprint_Matcher('')
       f = file('nmap-os-db','r')
       for text in fpm.fingerprints(f):
           fingerprint = fpm.parse_fp(text)
           if fingerprint.get_id() == emmulating:
              self.fingerprint = fingerprint
              print "Emmulating: %s" % fingerprint.get_id()
              print fingerprint.get_tests()
              return

       raise Exception, "Couldn't find fingerprint data for %r" % emmulating

   def sendPacket(self, packet):
       print "--> Packet sent"
       self.pcap.sendpacket(packet.get_packet())

   def addResponder(self, aResponder):
       self.responders.append(aResponder)

   def run(self):
       while 1:
          p = self.pcap.next()
          onion = [self.decoder.decode(p[1])]
          try:
             while 1:
                onion.append(onion[-1].child())
          except:
             pass

          for r in self.responders:
              if r.process(onion): break


def main():
   Machine(EMMULATING, IP, MAC).run()

if __name__ == '__main__':
   main()

