import random

import os_ident
import pcapy
from impacket import ImpactPacket
from impacket import ImpactDecoder
from impacket.ImpactPacket import TCPOption

# Fingerprint = 'Adtran NetVanta 3200 router'
# Class Adtran | embedded || router
# SEQ(SP=E3-F1%GCD=1-6%ISR=E4-F8%TI=I|RD%II=I%SS=O|S%TS=U)
# OPS(O1=%O2=%O3=M5B4%O4=M5B4%O5=M5B4%O6=M5B4)
# WIN(W1=DAC%W2=DAC%W3=DAC%W4=DAC%W5=DAC%W6=DAC)
# ECN(R=N)
# T1(R=Y%DF=N%T=FA-104%TG=FF%S=O%A=O|S+%F=A|AS%RD=0%Q=)
# T2(R=Y%DF=N%T=FA-104%TG=FF%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
# T3(R=N)
# T4(R=Y%DF=N%T=FA-104%TG=FF%W=0%S=A%A=S%F=R%O=%RD=0%Q=)
# T5(R=Y%DF=N%T=FA-104%TG=FF%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
# T6(R=Y%DF=N%T=FA-104%TG=FF%W=0%S=A%A=S%F=R%O=%RD=0%Q=)
# T7(R=N)
# U1(DF=N%T=FA-104%TG=FF%TOS=0%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUL=G%RUD=G)
# IE(DFI=N%T=FA-104%TG=FF%TOSI=Z%CD=Z%SI=S%DLI=S)

Fingerprint = 'ADIC Scalar 1000 tape library remote management unit'
# Class ADIC | embedded || storage-misc
# SEQ(SP=14-1E%GCD=FA00|1F400|2EE00|3E800|4E200%ISR=99-A3%II=I%TS=U)
# OPS(O1=M200NW0%O2=M200NW0%O3=M200NW0%O4=M200NW0%O5=M200NW0%O6=M200)
# WIN(W1=578%W2=578%W3=578%W4=578%W5=578%W6=578)
# ECN(R=Y%DF=N%T=3B-45%TG=40%W=578%O=M200NW0%CC=N%Q=)
# T1(R=Y%DF=N%T=3B-45%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
# T2(R=N)
# T3(R=Y%DF=N%T=3B-45%TG=40%W=578%S=O%A=O%F=A%O=%RD=0%Q=)
# T4(R=Y%DF=N%T=3B-45%TG=40%W=578%S=A%A=Z%F=R%O=%RD=0%Q=)
# T5(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
# T6(R=Y%DF=N%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
# T7(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
# U1(DF=N%T=3B-45%TG=40%TOS=0%IPL=38%UN=0%RIPL=G%RID=4210%RIPCK=Z%RUCK=0%RUL=G%RUD=G)
# IE(DFI=S%T=3B-45%TG=40%TOSI=S%CD=S%SI=S%DLI=S)

Fingerprint = 'Sun Solaris 9 (SPARC)'
# Class Sun | Solaris | 9 | general purpose
# SEQ(SP=FC-106%GCD=1-6%ISR=FD-113%TI=I%II=I%SS=S%TS=7)
# OPS(O1=NNT11M5B4NW0NNS%O2=NNT11M5B4NW0NNS%O3=NNT11M5B4NW0%O4=NNT11M5B4NW0NNS%O5=NNT11M5B4NW0NNS%O6=NNT11M5B4NNS)
# WIN(W1=C050%W2=C330%W3=C1CC%W4=C068%W5=C068%W6=C0B7)
# ECN(R=Y%DF=Y%T=3B-45%TG=40%W=C1E8%O=M5B4NW0NNS%CC=Y%Q=)
# T1(R=Y%DF=Y%T=3B-45%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
# T2(R=Y%DF=Y%T=1B-25|3B-45%TG=20|40%W=80%S=A%A=S%F=AR%O=WANM109T10S%RD=0%Q=)
# T3(R=Y%DF=N%T=1B-25|3B-45%TG=20|40%W=100%S=A%A=S%F=AR%O=WANM109T10S%RD=0%Q=)
# T4(R=Y%DF=Y%T=1B-25|3B-45%TG=20|40%W=400%S=A%A=S%F=AR%O=WANM109T10S%RD=0%Q=)
# T5(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=O%A=S+%F=AR%O=%RD=0%Q=)
# T6(R=Y%DF=Y%T=1B-25|3B-45%TG=20|40%W=8000%S=A%A=S%F=AR%O=WANM109T10S%RD=0%Q=)
# T7(R=Y%DF=N%T=1B-25|3B-45%TG=20|40%W=FFFF%S=A%A=S%F=AR%O=WFNM109T10S%RD=0%Q=)
# U1(R=N)
# IE(DFI=Y%T=FA-104%TG=FF%TOSI=20%CD=S%SI=S%DLI=S)

# Fingerprint = 'Sun Solaris 9 (x86)'
# Class Sun | Solaris | 9 | general purpose
# SEQ(SP=92-9C%GCD=1-6%ISR=9D-A7%TI=I%II=I%SS=S%TS=7)
# OPS(O1=NNT11M5B4NW1NNS%O2=NNT11M5B4NW1NNS%O3=NNT11M5B4NW1%O4=NNT11M5B4NW1NNS%O5=NNT11M5B4NW1NNS%O6=NNT11M5B4NNS)
# WIN(W1=8218%W2=8220%W3=80CA%W4=80F4%W5=80F4%W6=FFF7)
# ECN(R=Y%DF=Y%T=37-41%TG=40%W=8052%O=M5B4NW1NNS%CC=Y%Q=)
# T1(R=Y%DF=Y%T=37-41%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
# T2(R=N)
# T3(R=N)
# T4(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
# T5(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
# T6(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
# T7(R=N)
# U1(DF=Y%T=FA-104%TG=FF%TOS=0%IPL=70%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUL=G%RUD=G)
# IE(DFI=Y%T=FA-104%TG=FF%TOSI=S%CD=S%SI=S%DLI=S)

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

   def isMine(self, in_onion):
       return false

   def sendAnswer(self, in_onion):
       pass

   def process(self, in_onion):
       if not self.isMine(in_onion): return False
       print "Got packet for %s" % self.__class__.__name__
       # print in_onion[0]

       self.sendAnswer(in_onion)
       return True

   def getIP(self):
       return self.machine.ipAddress

class ARPResponder(Responder):
   def isMine(self, in_onion):
       if len(in_onion) < 2: return False

       if in_onion[O_ARP].ethertype != ImpactPacket.ARP.ethertype:
          return False

       return (
          in_onion[O_ARP].get_ar_op() == 1 and # ARP REQUEST
          in_onion[O_ARP].get_ar_tpa() == string2tuple(self.machine.ipAddress))

   def sendAnswer(self, in_onion):
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
       arp.set_ar_tha(in_onion[O_ARP].get_ar_sha())
       arp.set_ar_tpa(in_onion[O_ARP].get_ar_spa())

       eth.set_ether_shost(arp.get_ar_sha())
       eth.set_ether_dhost(arp.get_ar_tha())

       self.machine.sendPacket([eth])

class IPResponder(Responder):
   def initAnswer(self, in_onion):
       eth = ImpactPacket.Ethernet()
       ip = ImpactPacket.IP()

       eth.contains(ip)

       eth.set_ether_shost(in_onion[O_ETH].get_ether_dhost())
       eth.set_ether_dhost(in_onion[O_ETH].get_ether_shost())

       ip.set_ip_src(in_onion[O_IP].get_ip_dst())
       ip.set_ip_dst(in_onion[O_IP].get_ip_src())

       return [eth, ip]

   def isMine(self, in_onion):
       if len(in_onion) < 2: return False

       return (
           (in_onion[O_IP].ethertype == ImpactPacket.IP.ethertype) and
           (in_onion[O_IP].get_ip_dst() == self.machine.ipAddress))

class TCPResponder(IPResponder):
   def initAnswer(self, in_onion):
       out_onion = IPResponder.initAnswer(self, in_onion)
       tcp = ImpactPacket.TCP()

       out_onion[O_IP].contains(tcp)
       out_onion.append(tcp)

       tcp.set_th_dport(in_onion[O_TCP].get_th_sport())
       tcp.set_th_sport(in_onion[O_TCP].get_th_dport())

       return out_onion

   def isMine(self, in_onion):
       if not IPResponder.isMine(self, in_onion): return False
       if len(in_onion) < 3: return False

       return in_onion[O_TCP].protocol == ImpactPacket.TCP.protocol

class TCPClosedPort(TCPResponder):
   def __init__(self, *args):
       TCPResponder.__init__(self, *args)

   def isMine(self, in_onion):
       if not TCPResponder.isMine(self, in_onion): return False

       return (
          (in_onion[O_TCP].get_th_dport() == self.port) and
          in_onion[O_TCP].get_SYN())

   def sendAnswer(self, in_onion):
       out_onion = self.initAnswer(in_onion)

       out_onion[O_TCP].set_RST()
       out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq()+1)

       self.machine.sendPacket(out_onion)

class TCPOpenPort(TCPResponder):
   def __init__(self, *args):
       TCPResponder.__init__(self, *args)

   def isMine(self, in_onion):
       if not TCPResponder.isMine(self, in_onion): return False

       return (
          (in_onion[O_TCP].get_th_dport() == self.port) and
          in_onion[O_TCP].get_SYN())

   def initAnswer(self, in_onion):
       out_onion = TCPResponder.initAnswer(self, in_onion)

       out_onion[O_TCP].set_SYN()
       out_onion[O_TCP].set_ACK()
       out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq()+1)
       out_onion[O_TCP].set_th_seq(random.randint(0,2**32))

       return out_onion

   def sendAnswer(self, in_onion):
       out_onion = self.initAnswer(in_onion)
       self.machine.sendPacket(out_onion)

class nmap2_ECN(TCPOpenPort):
   def __init__(self, *args):
       TCPOpenPort.__init__(self, *args)
       self.template = os_ident.nmap2_ecn_probe(0, ['0.0.0.0',self.getIP()],[self.port, 0])
       self.fingerprint = self.machine.fingerprint.get_tests()['ECN']

   def isMine(self, in_onion):
       if not TCPOpenPort.isMine(self, in_onion): return False
       
       in_options = in_onion[O_TCP].get_padded_options()
       template   = self.template.t.get_padded_options()

       return in_options == template

   def initAnswer(self, in_onion):
       out_onion = TCPOpenPort.initAnswer(self, in_onion)

       f = self.fingerprint

       # Test R: There is a response = [YN]
       if (f['R'] == 'N'): return None

       # Test DF: Don't fragment IP bit set = [YN]
       if (f['DF'] == 'Y'): out_onion[O_IP].set_ip_df(True)

       # Test W: Initial TCP windows size
       try: win = int(ingerp['W'])
       except: win = 0
       out_onion[O_TCP].set_th_win(0)

       # Test T: Initial TTL = range_low-range_hi, base 16
       # Assumption: we are using the minimum in the TTL range
       try:
          ttl = f['T'].split('-')
          ttl = int(ttl[0], 16)
       except:
          ttl = 0x7f

       # Test TG: Initial TTL Guess. It's just a number, we prefer this
       try: ttl = int(f['TG'], 16)
       except: pass

       # Test CC: Explicit congestion notification
       # Two TCP flags are used in this test: ECE and CWR
       try:
           cc = f['CC']
           if cc == 'N': ece,cwr = 0,0
           if cc == 'Y': ece,cwr = 1,0
           if cc == 'S': ece,cwr = 1,1
           if cc == 'O': ece,cwr = 0,1
       except:
           ece,cwr = 0,0

       if ece: out_onion[O_TCP].set_ECE()
       else:   out_onion[O_TCP].reset_ECE()
       if cwr: out_onion[O_TCP].set_CWR()
       else:   out_onion[O_TCP].reset_CWR()

       out_onion[O_IP].set_ip_ttl(ttl)

       # Test O: TCP Options
       try: options = f['O']
       except: options = ''
       self.setTCPOptions(out_onion, options)
       
       # Test S: TCP Sequence number
       # Z: Sequence number is zero
       # A: Sequence number is the same as the ACK in the probe
       # A+: Sequence number is the same as the ACK in the probe + 1
       # O: Other value
       try: s = f['S']
       except: s = 'O'
       if s == 'Z': out_onion[O_TCP].set_th_seq(0)
       if s == 'A': out_onion[O_TCP].set_th_seq(in_onion[O_TCP].get_th_ack())
       if s == 'A+': out_onion[O_TCP].set_th_seq(in_onion[O_TCP].get_th_ack()+1)

       # Test A: TCP ACK number
       # Z: Ack is zero
       # S: Ack is the same as the Squence number in the probe
       # S+: Ack is the same as the Squence number in the probe + 1
       # O: Other value
       try: s = f['A']
       except: s = 'O'
       if s == 'Z': out_onion[O_TCP].set_th_ack(0)
       if s == 'S': out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq())
       if s == 'S+': out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq()+1)

       # Test Q: Quirks
       # R: Reserved bit set (right after the header length)
       # U: Urgent pointer non-zero and URG flag clear
       try: 
          if 'R' in f['Q']: out_onion[O_TCP].set_flags(0x800)
       except: pass
       try: 
          if 'U' in f['Q']: out_onion[O_TCP].set_th_urp(1)
       except: pass

       return out_onion

   def setTCPOptions(self, onion, optionsString):
       def getValue(string, i):
           value = 0
           
           idx = i
           for c in optionsString[i:]:
               try:
                   value = value * 0x10 + int(c,16)
               except:
                   break
               idx += 1

           return value, idx

       # Test O,O1=O6: TCP Options
       # L: End of Options
       # N: NOP
       # S: Selective ACK
       # Mx: MSS (x is a hex number)
       # Wx: Windows Scale (x is a hex number)
       # Tve: Timestamp (v and e are two binary digits, v for TSval and e for TSecr

       i = 0
       tcp = onion[O_TCP]
       while i < len(optionsString):
          opt = optionsString[i]
          i += 1
          if opt == 'L': tcp.add_option(TCPOption(TCPOption.TCPOPT_EOL))
          if opt == 'N': tcp.add_option(TCPOption(TCPOption.TCPOPT_NOP))
          if opt == 'S': tcp.add_option(TCPOption(TCPOption.TCPOPT_SACK_PERMITTED))
          if opt == 'T':
             opt = TCPOption(TCPOption.TCPOPT_TIMESTAMP)  # default ts = 0, ts_echo = 0
             if optionsString[i] == '1':  opt.set_ts(0xffffffffL)
             if optionsString[i+1] == '1': opt.set_ts_echo(0xffffffffL)
             tcp.add_option(opt)
             i += 2
          if opt == 'M':
             maxseg, i = getValue(optionsString, i)
             tcp.add_option(TCPOption(TCPOption.TCPOPT_MAXSEG, maxseg))
          if opt == 'W':
             window, i = getValue(optionsString, i)
             tcp.add_option(TCPOption(TCPOption.TCPOPT_WINDOW, window))

   def sendAnswer(self, in_onion):
       out_onion = self.initAnswer(in_onion)
       self.machine.sendPacket(out_onion)

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
       self.initFingerprint(emmulating)
       self.initResponders()

   def initPcap(self):
       self.pcap = pcapy.open_live(IFACE, 65535, 1, 1)
       self.pcap.setfilter("host %s or ether host %s" % (self.ipAddress, self.macAddress))

   def initResponders(self):
       self.addResponder(ARPResponder(self, 0))
       self.addResponder(nmap2_ECN(self, TCP_OPEN_PORT))
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
              print fingerprint.get_tests()['ECN']
              return

       raise Exception, "Couldn't find fingerprint data for %r" % emmulating

   def sendPacket(self, onion):
       if not onion: return
       print "--> Packet sent"
       print onion[0]
       print
       self.pcap.sendpacket(onion[O_ETH].get_packet())

   def addResponder(self, aResponder):
       self.responders.append(aResponder)

   def run(self):
       while 1:
          p = self.pcap.next()
          in_onion = [self.decoder.decode(p[1])]
          try:
             while 1:
                in_onion.append(in_onion[-1].child())
          except:
             pass

          for r in self.responders:
              if r.process(in_onion): break


def main():
   Machine(Fingerprint, IP, MAC).run()

if __name__ == '__main__':
   main()

