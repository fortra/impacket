import random

import os_ident
import uncrc32

try: import pcap as pcapy
except: import pcapy

from impacket import ImpactPacket
from impacket import ImpactDecoder
from impacket.ImpactPacket import TCPOption
from impacket.examples import logger

#defaults

MAC = "01:02:03:04:05:06"
IP  = "192.168.67.254"
IFACE = "eth0"
OPEN_TCP_PORTS = [80, 443]
OPEN_UDP_PORTS = [111]
UDP_CMD_PORT = 12345
nmapOSDB = '/usr/share/nmap/nmap-os-db'

# Fingerprint = 'Adtran NetVanta 3200 router' # CD=Z TOSI=Z <----------- NMAP detects it as Linux!!!
# Fingerprint = 'ADIC Scalar 1000 tape library remote management unit' # DFI=S
# Fingerprint = 'Siemens Gigaset SX541 or USRobotics USR9111 wireless DSL modem' # DFI=O U1(DF=N IPL=38)
# Fingerprint = 'Apple Mac OS X 10.5.6 (Leopard) (Darwin 9.6.0)' # DFI=Y SI=S U1(DF=Y)

Fingerprint = 'Sun Solaris 10 (SPARC)' 
# Fingerprint = 'Sun Solaris 9 (x86)'

# Fingerprint = '3Com OfficeConnect 3CRWER100-75 wireless broadband router'  # TI=Z DFI=N !SS TI=Z II=I
# Fingerprint = 'WatchGuard Firebox X5w firewall/WAP' # TI=RD
# no TI=Hex
# Fingerprint = 'FreeBSD 6.0-STABLE - 6.2-RELEASE' # TI=RI
# Fingerprint = 'Microsoft Windows 98 SE' # TI=BI ----> BROKEN! nmap shows no SEQ() output
# Fingerprint = 'Microsoft Windows NT 4.0 SP5 - SP6' # TI=BI TOSI=S SS=S
# Fingerprint = 'Microsoft Windows Vista Business' # TI=I U1(IPL=164)

# Fingerprint = 'FreeBSD 6.1-RELEASE' # no TI (TI=O)

# Fingerprint = '2Wire 1701HG wireless ADSL modem' # IE(R=N)

# Fingerprint = 'Cisco Catalyst 1912 switch' # TOSI=O SS=S

O_ETH = 0
O_IP  = 1
O_ARP = 1
O_UDP = 2
O_TCP = 2
O_ICMP = 2
O_UDP_DATA = 3
O_ICMP_DATA = 3

def string2tuple(string):
    if string.find(':') >= 0:
       return [int(x) for x in string.split(':')]
    else:
       return [int(x) for x in string.split('.')]

class Responder:
   templateClass = None
   signatureName      = None

   def __init__(self, machine):
       self.machine = machine
       print "Initializing %s" % self.__class__.__name__
       self.initTemplate()
       self.initFingerprint()

   def initTemplate(self):
       if not self.templateClass:
          self.template_onion = None
       else:
          try:
             probe = self.templateClass(0, ['0.0.0.0',self.getIP()],[0, 0])
          except:
             probe = self.templateClass(0, ['0.0.0.0',self.getIP()])
          self.template_onion = [probe.get_packet()]
          try:
             while 1: self.template_onion.append(self.template_onion[-1].child())
          except: pass
       
          # print "Template: %s" % self.template_onion[O_ETH]
          # print "Options: %r" % self.template_onion[O_TCP].get_padded_options()
          # print "Flags: 0x%04x" % self.template_onion[O_TCP].get_th_flags()

   def initFingerprint(self):
       if not self.signatureName:
          self.fingerprint = None
       else:
          self.fingerprint = self.machine.fingerprint.get_tests()[self.signatureName].copy()

   def isMine(self, in_onion):
       return False

   def buildAnswer(self, in_onion):
       return None

   def sendAnswer(self, out_onion):
       self.machine.sendPacket(out_onion)

   def process(self, in_onion):
       if not self.isMine(in_onion): return False
       print "Got packet for %s" % self.__class__.__name__

       out_onion = self.buildAnswer(in_onion)

       if out_onion: self.sendAnswer(out_onion)
       return True

   def getIP(self):
       return self.machine.ipAddress

# Generic Responders (does the word Responder exist?)

class ARPResponder(Responder):
   def isMine(self, in_onion):
       if len(in_onion) < 2: return False

       if in_onion[O_ARP].ethertype != ImpactPacket.ARP.ethertype:
          return False

       return (
          in_onion[O_ARP].get_ar_op() == 1 and # ARP REQUEST
          in_onion[O_ARP].get_ar_tpa() == string2tuple(self.machine.ipAddress))

   def buildAnswer(self, in_onion):
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

       return [eth, arp]

class IPResponder(Responder):
   def buildAnswer(self, in_onion):
       eth = ImpactPacket.Ethernet()
       ip = ImpactPacket.IP()

       eth.contains(ip)

       eth.set_ether_shost(in_onion[O_ETH].get_ether_dhost())
       eth.set_ether_dhost(in_onion[O_ETH].get_ether_shost())

       ip.set_ip_src(in_onion[O_IP].get_ip_dst())
       ip.set_ip_dst(in_onion[O_IP].get_ip_src())
       ip.set_ip_id(self.machine.getIPID())

       return [eth, ip]

   def sameIPFlags(self, in_onion):
       if not self.template_onion: return True
       return (self.template_onion[O_IP].get_ip_off() & 0xe000) == (in_onion[O_IP].get_ip_off() & 0xe000)

   def isMine(self, in_onion):
       if len(in_onion) < 2: return False

       return (
           (in_onion[O_IP].ethertype == ImpactPacket.IP.ethertype) and
           (in_onion[O_IP].get_ip_dst() == self.machine.ipAddress) and
           self.sameIPFlags(in_onion)
       )

   def setTTLFromFingerprint(self, out_onion):
       f = self.fingerprint
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

       out_onion[O_IP].set_ip_ttl(ttl)

class ICMPResponder(IPResponder):
   def buildAnswer(self, in_onion):
       out_onion = IPResponder.buildAnswer(self, in_onion)
       icmp = ImpactPacket.ICMP()

       out_onion[O_IP].contains(icmp)
       out_onion.append(icmp)

       icmp.set_icmp_id(in_onion[O_ICMP].get_icmp_id())
       icmp.set_icmp_seq(in_onion[O_ICMP].get_icmp_seq())

       out_onion[O_IP].set_ip_id(self.machine.getIPID_ICMP())

       return out_onion

   def isMine(self, in_onion):
       if not IPResponder.isMine(self, in_onion): return False
       if len(in_onion) < 3: return False

       return (
           (in_onion[O_ICMP].protocol == ImpactPacket.ICMP.protocol) and
           self.sameICMPTemplate(in_onion))

   def sameICMPTemplate(self, in_onion):
       t_ip           = self.template_onion[O_IP]
       t_icmp         = self.template_onion[O_ICMP]
       t_icmp_datalen = self.template_onion[O_ICMP_DATA].get_size()

       return (
          (t_ip.get_ip_tos() == in_onion[O_IP].get_ip_tos()) and
          (t_ip.get_ip_df() == in_onion[O_IP].get_ip_df()) and
          (t_icmp.get_icmp_type() == in_onion[O_ICMP].get_icmp_type()) and
          (t_icmp.get_icmp_code() == in_onion[O_ICMP].get_icmp_code()) and
          (t_icmp_datalen == in_onion[O_ICMP_DATA].get_size())
       )

class UDPResponder(IPResponder):
   def isMine(self, in_onion):
       return (
           IPResponder.isMine(self, in_onion) and
           (len(in_onion) >= 3) and
           (in_onion[O_UDP].protocol == ImpactPacket.UDP.protocol)
       )

class OpenUDPResponder(UDPResponder):
   def isMine(self, in_onion):
       return (
          UDPResponder.isMine(self, in_onion) and
          self.machine.isUDPPortOpen(in_onion[O_UDP].get_uh_dport()))

   def buildAnswer(self, in_onion):
       out_onion = IPResponder.buildAnswer(self, in_onion)
       udp = ImpactPacket.UDP()

       out_onion[O_IP].contains(udp)
       out_onion.append(udp)

       udp.set_uh_dport(in_onion[O_UDP].get_uh_sport())
       udp.set_uh_sport(in_onion[O_UDP].get_uh_dport())

       return out_onion

class ClosedUDPResponder(UDPResponder):
   def isMine(self, in_onion):
       return (
          UDPResponder.isMine(self, in_onion) and
          not self.machine.isUDPPortOpen(in_onion[O_UDP].get_uh_dport()))

   def buildAnswer(self, in_onion):
       out_onion = IPResponder.buildAnswer(self, in_onion)
       icmp = ImpactPacket.ICMP()

       out_onion[O_IP].contains(icmp)
       out_onion.append(icmp)

       icmp.contains(in_onion[O_IP])
       out_onion += in_onion[O_IP:]

       icmp.set_icmp_type(icmp.ICMP_UNREACH)
       icmp.set_icmp_code(icmp.ICMP_UNREACH_PORT)

       return out_onion

class TCPResponder(IPResponder):
   def buildAnswer(self, in_onion):
       out_onion = IPResponder.buildAnswer(self, in_onion)
       tcp = ImpactPacket.TCP()

       out_onion[O_IP].contains(tcp)
       out_onion.append(tcp)

       tcp.set_th_dport(in_onion[O_TCP].get_th_sport())
       tcp.set_th_sport(in_onion[O_TCP].get_th_dport())

       return out_onion

   def sameTCPFlags(self, in_onion):
       if not self.template_onion: return True
       in_flags = in_onion[O_TCP].get_th_flags() & 0xfff
       t_flags  = self.template_onion[O_TCP].get_th_flags() & 0xfff

       return in_flags == t_flags

   def sameTCPOptions(self, in_onion):
       if not self.template_onion: return True
       in_options = in_onion[O_TCP].get_padded_options()
       t_options  = self.template_onion[O_TCP].get_padded_options()

       return in_options == t_options

   def isMine(self, in_onion):
       if not IPResponder.isMine(self, in_onion): return False
       if len(in_onion) < 3: return False

       return (
           in_onion[O_TCP].protocol == ImpactPacket.TCP.protocol and
           self.sameTCPFlags(in_onion) and
           self.sameTCPOptions(in_onion)
       )

class OpenTCPResponder(TCPResponder):
   def isMine(self, in_onion):
       return (
          TCPResponder.isMine(self, in_onion) and 
          in_onion[O_TCP].get_SYN() and
          self.machine.isTCPPortOpen(in_onion[O_TCP].get_th_dport()))

   def buildAnswer(self, in_onion):
       out_onion = TCPResponder.buildAnswer(self, in_onion)

       out_onion[O_TCP].set_SYN()
       out_onion[O_TCP].set_ACK()
       out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq()+1)
       out_onion[O_TCP].set_th_seq(self.machine.getTCPSequence())

       return out_onion

class ClosedTCPResponder(TCPResponder):
   def isMine(self, in_onion):
       return (
          TCPResponder.isMine(self, in_onion) and 
          in_onion[O_TCP].get_SYN() and
          not self.machine.isTCPPortOpen(in_onion[O_TCP].get_th_dport()))

   def buildAnswer(self, in_onion):
       out_onion = TCPResponder.buildAnswer(self, in_onion)

       out_onion[O_TCP].set_RST()
       out_onion[O_TCP].set_ACK()
       out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq()+1)
       out_onion[O_TCP].set_th_seq(self.machine.getTCPSequence())

       return out_onion

class UDPCommandResponder(OpenUDPResponder):
   # default UDP_CMD_PORT is 12345
   # use with:
   # echo cmd:exit | nc -u $(IP) $(UDP_CMD_PORT)
   # echo cmd:who | nc -u $(IP) $(UDP_CMD_PORT)

   def set_port(self, port):
       self.port = port
       self.machine.openUDPPort(port)
       return self

   def isMine(self, in_onion):
       return (
          OpenUDPResponder.isMine(self, in_onion))# and 
          #in_onion[O_UDP].get_uh_dport() == self.port)

   def buildAnswer(self, in_onion):
       cmd = in_onion[O_UDP_DATA].get_bytes().tostring()
       if cmd[:4] == 'cmd:': cmd = cmd[4:].strip()
       print "Got command: %r" % cmd

       if cmd == 'exit':
          from sys import exit
          exit()

       out_onion = OpenUDPResponder.buildAnswer(self, in_onion)
       out_onion.append(ImpactPacket.Data())
       out_onion[O_UDP].contains(out_onion[O_UDP_DATA])
       if cmd == 'who':
          out_onion[O_UDP_DATA].set_data(self.machine.fingerprint.get_id())
          
       return out_onion

# NMAP2 specific responders
class NMAP2UDPResponder(ClosedUDPResponder):
   signatureName      = 'U1'

   # No real need to filter
   # def isMine(self, in_onion):
   #     return (
   #        ClosedUDPResponder.isMine(self, inOnion) and
   #        (in_onion[O_UDP_DATA].get_size() == 300))

   def buildAnswer(self, in_onion):
       out_onion = ClosedUDPResponder.buildAnswer(self, in_onion)
       f = self.fingerprint

       # assume R = Y
       try:
          if (f['R'] == 'N'): return None
       except: pass

       # Test DF: Don't fragment IP bit set = [YN]
       if (f['DF'] == 'Y'): out_onion[O_IP].set_ip_df(True)
       else: out_onion[O_IP].set_ip_df(False)

       self.setTTLFromFingerprint(out_onion)

       # UN. Assume 0
       try: un = int(f['UN'],16)
       except: un = 0
       out_onion[O_ICMP].set_icmp_void(un)

       # RIPL. Assume original packet just quoted
       try:
          ripl = int(f['RIPL'],16)	# G generates exception
          out_onion[O_ICMP_DATA].set_ip_len(ripl)
       except:
          pass

       # RID. Assume original packet just quoted
       try:
          rid = int(f['RID'],16)	# G generates exception
          out_onion[O_ICMP_DATA].set_ip_id(rid)
       except:
          pass

       # RIPCK. Assume original packet just quoted
       try: ripck = f['RIPCK']
       except: ripck = 'G'
       if   ripck == 'I': out_onion[O_ICMP_DATA].set_ip_sum(0x6765)
       elif ripck == 'Z': out_onion[O_ICMP_DATA].set_ip_sum(0)
       elif ripck == 'G': out_onion[O_ICMP_DATA].auto_checksum = 0

       # RUCK. Assume original packet just quoted
       try:
          ruck = int(f['RUCK'], 16)
          out_onion[O_ICMP_DATA+1].set_uh_sum(ruck)
       except: 
          out_onion[O_ICMP_DATA+1].auto_checksum = 0

       # RUD. Assume original packet just quoted
       try: rud = f['RUD']
       except: rud = 'G'

       if rud == 'I':
          udp_data = out_onion[O_ICMP_DATA+2]
          udp_data.set_data('G'*udp_data.get_size())

       # IPL. Assume all original packet is quoted
       # This has to be the last thing we do
       # as we are going to render the packet before doing it
       try: ipl = int(f['IPL'], 16)
       except: ipl = None

       if not ipl is None:
          data = out_onion[O_ICMP_DATA].get_packet()
          out_onion[O_ICMP].contains(ImpactPacket.Data())
          ip_and_icmp_len = out_onion[O_IP].get_size()

          data = data[:ipl - ip_and_icmp_len]

          data += '\x00'*(ipl-len(data)-ip_and_icmp_len)
          out_onion = out_onion[:O_ICMP_DATA]
          out_onion.append(ImpactPacket.Data(data))
          out_onion[O_ICMP].contains(out_onion[O_ICMP_DATA])

       return out_onion

class NMAP2ICMPResponder(ICMPResponder):
   def buildAnswer(self, in_onion):
       f = self.fingerprint

       # assume R = Y
       try:
          if (f['R'] == 'N'): return None
       except: pass

       out_onion = ICMPResponder.buildAnswer(self, in_onion)

       # assume DFI = N
       try: dfi = f['DFI'] 
       except: dfi = 'N'

       if   dfi == 'N': out_onion[O_IP].set_ip_df(False)
       elif dfi == 'Y': out_onion[O_IP].set_ip_df(True)
       elif dfi == 'S': out_onion[O_IP].set_ip_df(in_onion[O_IP].get_ip_df())
       elif dfi == 'O': out_onion[O_IP].set_ip_df(not in_onion[O_IP].get_ip_df())
       else: raise Exception('Unsupported IE(DFI=%s)' % dfi)

       # assume DLI = S
       try: dli = f['DLI'] 
       except: dli = 'S'

       if   dli == 'S': out_onion[O_ICMP].contains(in_onion[O_ICMP_DATA])
       elif dli != 'Z': raise Exception('Unsupported IE(DFI=%s)' % dli)

       self.setTTLFromFingerprint(out_onion)

       # assume SI = S
       try: si = f['SI'] 
       except: si = 'S'

       if   si == 'S': out_onion[O_ICMP].set_icmp_seq(in_onion[O_ICMP].get_icmp_seq())
       elif si == 'Z': out_onion[O_ICMP].set_icmp_seq(0) # this is not currently supported by nmap, but I've done it already
       else:
           try: out_onion[O_ICMP].set_icmp_seq(int(si, 16)) # this is not supported either by nmap
           except: raise Exception('Unsupported IE(SI=%s)' % si)

       # assume CD = S
       try: cd = f['CD'] 
       except: cd = 'S'

       if   cd == 'Z': out_onion[O_ICMP].set_icmp_code(0)
       elif cd == 'S': out_onion[O_ICMP].set_icmp_code(in_onion[O_ICMP].get_icmp_code())
       elif cd == 'O': out_onion[O_ICMP].set_icmp_code(in_onion[O_ICMP].get_icmp_code()+1)	# no examples in DB
       else:
           try: out_onion[O_ICMP].set_icmp_code(int(cd, 16)) # documented, but no examples available
           except: raise Exception('Unsupported IE(CD=%s)' % cd)

       # assume TOSI = S
       try: tosi = f['TOSI'] 
       except: tosi = 'S'

       if   tosi == 'Z': out_onion[O_IP].set_ip_tos(0)
       elif tosi == 'S': out_onion[O_IP].set_ip_tos(in_onion[O_IP].get_ip_tos())
       elif tosi == 'O': out_onion[O_IP].set_ip_tos(in_onion[O_IP].get_ip_tos()+1)	# no examples in DB
       else:
           try: out_onion[O_IP].set_ip_tos(int(tosi, 16)) # documented, but no examples available
           except: raise Exception('Unsupported IE(TOSI=%s)' % tosi)

       return out_onion

class NMAP2TCPResponder(TCPResponder):
   def buildAnswer(self, in_onion):
       out_onion = TCPResponder.buildAnswer(self, in_onion)

       f = self.fingerprint

       # Test R: There is a response = [YN]
       if (f['R'] == 'N'): return None

       # Test DF: Don't fragment IP bit set = [YN]
       if (f['DF'] == 'Y'): out_onion[O_IP].set_ip_df(True)
       else: out_onion[O_IP].set_ip_df(False)

       # Test W: Initial TCP windows size
       try: win = int(f['W'],16)
       except: win = 0
       out_onion[O_TCP].set_th_win(win)

       self.setTTLFromFingerprint(out_onion)

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
       if s == 'O': out_onion[O_TCP].set_th_seq(self.machine.getTCPSequence())

       # Test A: TCP ACK number
       # Z: Ack is zero
       # S: Ack is the same as the Squence number in the probe
       # S+: Ack is the same as the Squence number in the probe + 1
       # O: Other value
       try: a = f['A']
       except: a = 'O'
       if a == 'Z': out_onion[O_TCP].set_th_ack(0)
       if a == 'S': out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq())
       if a == 'S+': out_onion[O_TCP].set_th_ack(in_onion[O_TCP].get_th_seq()+1)

       # Test Q: Quirks
       # R: Reserved bit set (right after the header length)
       # U: Urgent pointer non-zero and URG flag clear
       try: 
          if 'R' in f['Q']: out_onion[O_TCP].set_flags(0x800)
       except: pass
       try: 
          if 'U' in f['Q']: out_onion[O_TCP].set_th_urp(0xffff)
       except: pass

       # Test F: TCP Flags
       try: flags = f['F']
       except: flags = ''
       if 'E' in flags: out_onion[O_TCP].set_ECE()
       if 'U' in flags: out_onion[O_TCP].set_URG()
       if 'A' in flags: out_onion[O_TCP].set_ACK()
       if 'P' in flags: out_onion[O_TCP].set_PSH()
       if 'R' in flags: out_onion[O_TCP].set_RST()
       if 'S' in flags: out_onion[O_TCP].set_SYN()
       if 'F' in flags: out_onion[O_TCP].set_FIN()

       # Test RD: TCP Data checksum (mostly for data in RST)
       try:
           crc = f['RD']
           if crc != '0':	# when the
               crc = int(crc, 16)
               data  = 'TCP Port is closed\x00'
               data += uncrc32.compensate(data, crc)
               data = ImpactPacket.Data(data) 
               out_onion.append(data)
               out_onion[O_TCP].contains(data)
       except:
           pass
       return out_onion

   def setTCPOptions(self, onion, options):
       def getValue(string, i):
           value = 0
           
           idx = i
           for c in options[i:]:
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
       while i < len(options):
          opt = options[i]
          i += 1
          if opt == 'L': tcp.add_option(TCPOption(TCPOption.TCPOPT_EOL))
          if opt == 'N': tcp.add_option(TCPOption(TCPOption.TCPOPT_NOP))
          if opt == 'S': tcp.add_option(TCPOption(TCPOption.TCPOPT_SACK_PERMITTED))
          if opt == 'T':
             opt = TCPOption(TCPOption.TCPOPT_TIMESTAMP)  # default ts = 0, ts_echo = 0
             if options[i] == '1':  opt.set_ts(self.machine.getTCPTimeStamp())
             if options[i+1] == '1': opt.set_ts_echo(0xffffffffL)
             tcp.add_option(opt)
             i += 2
          if opt == 'M':
             maxseg, i = getValue(options, i)
             tcp.add_option(TCPOption(TCPOption.TCPOPT_MAXSEG, maxseg))
          if opt == 'W':
             window, i = getValue(options, i)
             tcp.add_option(TCPOption(TCPOption.TCPOPT_WINDOW, window))

class nmap2_SEQ(NMAP2TCPResponder):
   templateClass = None
   signatureName = None
   seqNumber     = None

   def initFingerprint(self):
       NMAP2TCPResponder.initFingerprint(self)
       if not self.seqNumber: return
       else:
          OPS = self.machine.fingerprint.get_tests()['OPS']
          WIN = self.machine.fingerprint.get_tests()['WIN']
          self.fingerprint['O'] = OPS['O%d' % self.seqNumber]
          self.fingerprint['W'] = WIN['W%d' % self.seqNumber]

class nmap2_ECN(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_ecn_probe
   signatureName      = 'ECN'

class nmap2_SEQ1(nmap2_SEQ):
   templateClass = os_ident.nmap2_seq_1
   signatureName = 'T1'
   seqNumber     = 1

class nmap2_SEQ2(nmap2_SEQ):
   templateClass = os_ident.nmap2_seq_2
   signatureName = 'T1'
   seqNumber     = 2

class nmap2_SEQ3(nmap2_SEQ):
   templateClass = os_ident.nmap2_seq_3
   signatureName = 'T1'
   seqNumber     = 3

class nmap2_SEQ4(nmap2_SEQ):
   templateClass = os_ident.nmap2_seq_4
   signatureName = 'T1'
   seqNumber     = 4

class nmap2_SEQ5(nmap2_SEQ):
   templateClass = os_ident.nmap2_seq_5
   signatureName = 'T1'
   seqNumber     = 5

class nmap2_SEQ6(nmap2_SEQ):
   templateClass = os_ident.nmap2_seq_6
   signatureName = 'T1'
   seqNumber     = 6

class nmap2_T2(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_tcp_open_2
   signatureName = 'T2'

class nmap2_T3(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_tcp_open_3
   signatureName = 'T3'

class nmap2_T4(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_tcp_open_4
   signatureName = 'T4'

class nmap2_T5(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_tcp_closed_1
   signatureName = 'T5'

class nmap2_T6(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_tcp_closed_2
   signatureName = 'T6'

class nmap2_T7(NMAP2TCPResponder):
   templateClass = os_ident.nmap2_tcp_closed_3
   signatureName = 'T7'

class nmap2_ICMP_1(NMAP2ICMPResponder):
   templateClass = os_ident.nmap2_icmp_echo_probe_1
   signatureName = 'IE'

class nmap2_ICMP_2(NMAP2ICMPResponder):
   templateClass = os_ident.nmap2_icmp_echo_probe_2
   signatureName = 'IE'

class Machine:
   AssumedTimeIntervalPerPacket = 0.11 # seconds
   def __init__(self, emmulating, interface, ipAddress, macAddress, openTCPPorts = [], openUDPPorts = [], nmapOSDB = 'nmap-os-db'):
       self.interface = interface
       self.ipAddress = ipAddress
       self.macAddress = macAddress
       self.responders = []
       self.decoder = ImpactDecoder.EthDecoder()

       self.initPcap()
       self.initFingerprint(emmulating, nmapOSDB)

       self.initSequenceGenerators()
       self.openTCPPorts = openTCPPorts
       self.openUDPPorts = openUDPPorts
       print self

   def openUDPPort(self, port):
       if self.isUDPPortOpen(port): return
       self.openUDPPorts.append(port)

   def isUDPPortOpen(self, port):
       return port in self.openUDPPorts

   def isTCPPortOpen(self, port):
       return port in self.openTCPPorts

   def initPcap(self):
       self.pcap = pcapy.open_live(self.interface, 65535, 1, 0)
       try:       self.pcap.setfilter("host %s or ether host %s" % (self.ipAddress, self.macAddress))
       except:    self.pcap.setfilter("host %s or ether host %s" % (self.ipAddress, self.macAddress), 1, 0xFFFFFF00)

   def initGenericResponders(self):
       # generic responders
       self.addResponder(ARPResponder(self))
       self.addResponder(OpenUDPResponder(self))
       self.addResponder(ClosedUDPResponder(self))
       self.addResponder(OpenTCPResponder(self))
       self.addResponder(ClosedTCPResponder(self))

   def initFingerprint(self, emmulating, nmapOSDB):
       fpm = os_ident.NMAP2_Fingerprint_Matcher('')
       f = file(nmapOSDB, 'r')
       for text in fpm.fingerprints(f):
           fingerprint = fpm.parse_fp(text)
           if fingerprint.get_id() == emmulating:
              self.fingerprint = fingerprint
              self.simplifyFingerprint()
              # print fingerprint
              return

       raise Exception, "Couldn't find fingerprint data for %r" % emmulating

   def simplifyFingerprint(self):
       tests = self.fingerprint.get_tests()
       for probeName in tests:
           probe = tests[probeName]
           for test in probe:
               probe[test] = probe[test].split('|')[0]
               
   def initSequenceGenerators(self):
       self.initIPIDGenerator()
       self.initTCPISNGenerator()
       self.initTCPTSGenerator()

   def initIPIDGenerator(self):
       seq = self.fingerprint.get_tests()['SEQ']
       self.ip_ID = 0

       try: TI = seq['TI']
       except: TI = 'O'

       if   TI == 'Z': self.ip_ID_delta = 0
       elif TI == 'RD': self.ip_ID_delta = 30000
       elif TI == 'RI': self.ip_ID_delta = 1234
       elif TI == 'BI': self.ip_ID_delta = 1024+256
       elif TI == 'I': self.ip_ID_delta = 1
       elif TI == 'O': self.ip_ID_delta = 123
       else: self.ip_ID_delta = int(TI, 16)

       try: ss = seq['SS']
       except: ss = 'O'

       self.ip_ID_ICMP_delta = None
       if ss == 'S': self.ip_ID_ICMP = None
       else:
          self.ip_ID_ICMP = 0
          try: II = seq['II']
          except: II = 'O'

          if   II == 'Z': self.ip_ID_ICMP_delta = 0
          elif II == 'RD': self.ip_ID_ICMP_delta = 30000
          elif II == 'RI': self.ip_ID_ICMP_delta = 1234
          elif II == 'BI': self.ip_ID_ICMP_delta = 1024+256
          elif II == 'I': self.ip_ID_ICMP_delta = 1
          elif II == 'O': self.ip_ID_ICMP_delta = 123
          else: self.ip_ID_ICMP_delta = int(II, 16)

       # generate a few, so we don't start with 0 when we don't have to
       for i in range(10):
           self.getIPID()
           self.getIPID_ICMP()

       print "IP ID Delta: %d" % self.ip_ID_delta
       print "IP ID ICMP Delta: %s" % self.ip_ID_ICMP_delta

   def initTCPISNGenerator(self):
       # tcp_ISN and tcp_ISN_delta for TCP Initial sequence numbers
       self.tcp_ISN = 0
       try:
          self.tcp_ISN_GCD = int(self.fingerprint.get_tests()['SEQ']['GCD'].split('-')[0], 16)
       except:
          self.tcp_ISN_GCD = 1

       try:
          isr = self.fingerprint.get_tests()['SEQ']['ISR'].split('-')
          if len(isr) == 1:
             isr = int(isr[0], 16)
          else:
             isr = (int(isr[0], 16) + int(isr[1], 16)) / 2
       except:
          isr = 0

       try:
          sp = self.fingerprint.get_tests()['SEQ']['SP'].split('-')
          sp = int(sp[0], 16)
       except:
          sp = 0

       self.tcp_ISN_stdDev = (2**(sp/8.0)) * 5 / 4  # n-1 on small populations... erm...

       if self.tcp_ISN_GCD > 9:
          self.tcp_ISN_stdDev *= self.tcp_ISN_GCD

       self.tcp_ISN_stdDev *= self.AssumedTimeIntervalPerPacket

       self.tcp_ISN_delta  = 2**(isr/8.0) * self.AssumedTimeIntervalPerPacket

       # generate a few, so we don't start with 0 when we don't have to
       for i in range(10): self.getTCPSequence()

       print "TCP ISN Delta: %f" % self.tcp_ISN_delta
       print "TCP ISN Standard Deviation: %f" % self.tcp_ISN_stdDev

   def initTCPTSGenerator(self):
       # tcp_TS and tcp_TS_delta for TCP Time stamp generation
       self.tcp_TS = 0

       try: ts = self.fingerprint.get_tests()['SEQ']['TS']
       except: ts = 'U'

       if ts == 'U' or ts == 'Z': self.tcp_TS_delta = 0
       else:
           self.tcp_TS_delta = (2**int(ts, 16)) * self.AssumedTimeIntervalPerPacket

       # generate a few, so we don't start with 0 when we don't have to
       for i in range(10): self.getTCPTimeStamp()

       print "TCP TS Delta: %f" % self.tcp_TS_delta

   def getIPID(self):
       answer = self.ip_ID
       self.ip_ID += self.ip_ID_delta
       self.ip_ID %= 0x10000L
       # print "IP ID: %x" % answer
       return answer

   def getIPID_ICMP(self):
       if self.ip_ID_ICMP is None:
          return self.getIPID()

       answer = self.ip_ID_ICMP
       self.ip_ID_ICMP += self.ip_ID_ICMP_delta
       self.ip_ID_ICMP %= 0x10000L
       # print "---> IP ID: %x" % answer
       return answer

   def getTCPSequence(self):
       answer = self.tcp_ISN + self.tcp_ISN_stdDev # *random.random()
       self.tcp_ISN_stdDev *= -1
       answer = int(int(answer/self.tcp_ISN_GCD) * self.tcp_ISN_GCD)
       self.tcp_ISN += self.tcp_ISN_delta
       self.tcp_ISN %= 0x100000000L
       # print "---> TCP Sequence: %d" % (answer % 0x100000000L)
       return answer % 0x100000000L

   def getTCPTimeStamp(self):
       answer = int(round(self.tcp_TS))
       self.tcp_TS += self.tcp_TS_delta
       self.tcp_TS %= 0x100000000L
       # print "---> TCP Time Stamp: %x" % answer
       return answer

   def sendPacket(self, onion):
       if not onion: return
       print "--> Packet sent:"
       #print onion[0]
       #print
       self.pcap.sendpacket(onion[O_ETH].get_packet())

   def addResponder(self, aResponder):
       self.responders.append(aResponder)

   def run(self):
       while 1:
          p = self.pcap.next()
          try:    in_onion = [self.decoder.decode(p[1])]
          except: in_onion = [self.decoder.decode(p[0])]
          try:
             while 1: in_onion.append(in_onion[-1].child())
          except:
             pass

          #print "-------------- Received: ", in_onion[0]
          for r in self.responders:
              if r.process(in_onion): break


def main():
   def initResponders(machine):
       # cmd responder
       # machine.addResponder(UDPCommandResponder(machine).set_port(UDP_CMD_PORT))

       # nmap2 specific responders
       machine.addResponder(nmap2_SEQ1(machine))
       machine.addResponder(nmap2_SEQ2(machine))
       machine.addResponder(nmap2_SEQ3(machine))
       machine.addResponder(nmap2_SEQ4(machine))
       machine.addResponder(nmap2_SEQ5(machine))
       machine.addResponder(nmap2_SEQ6(machine))
       machine.addResponder(nmap2_ECN(machine))
       machine.addResponder(nmap2_T2(machine))
       machine.addResponder(nmap2_T3(machine))
       machine.addResponder(nmap2_T4(machine))
       machine.addResponder(nmap2_T5(machine))
       machine.addResponder(nmap2_T6(machine))
       machine.addResponder(nmap2_T7(machine))
       machine.addResponder(nmap2_ICMP_1(machine))
       machine.addResponder(nmap2_ICMP_2(machine))
       machine.addResponder(NMAP2UDPResponder(machine))

   from sys import argv, exit
   def usage():
       print """
       if arg == '-h': usage()
       if arg == '--help': usage()
       if arg == '-f': Fingerprint = value
       if arg == '-p': IP = value
       if arg == '-m': MAC = value
       if arg == '-i': IFACE = value
       if arg == '-d': nmapOsDB = value

   where:
       arg = argv[i]
       value = argv[i+1]
       """
       exit()

   global Fingerprint, IFACE, MAC, IP, nmapOSDB
   for i in xrange(len(argv)):
       arg = argv[i]
       try: value = argv[i+1]
       except: value = None
       if arg == '-h': usage()
       if arg == '--help': usage()
       if arg == '-f': Fingerprint = value
       if arg == '-p': IP = value
       if arg == '-m': MAC = value
       if arg == '-i': IFACE = value
       if arg == '-d': nmapOSDB = value

   print "Emulating: %r" % Fingerprint
   print "at %s / %s / %s" % (IFACE, MAC, IP)
   machine = Machine(
       Fingerprint,
       IFACE,
       IP,
       MAC,
       OPEN_TCP_PORTS,
       OPEN_UDP_PORTS,
       nmapOSDB = nmapOSDB)

   initResponders(machine)
   machine.initGenericResponders()
   machine.run()

if __name__ == '__main__':
   # Init the example's logger theme
   logger.init()
   main()

# All Probes
# [x] SEQ
# [x] OPS
# [x] WIN
# [x] T1
# [x] T2
# [x] T3
# [x] T4
# [x] T5
# [x] T6
# [x] T7
# [x] IE
# [x] ECN
# [x] U1

# All Tests

# SEQ()
# [x] TCP ISN sequence predictability index (SP)
# [x] TCP ISN greatest common divisor (GCD)
# [x] TCP ISN counter rate (ISR)
# [x] IP ID sequence generation algorithm on TCP Open ports (TI)
#   [x] Z  - All zeros
#   [x] RD - Random: It increments at least once by at least 20000.
#   [-] Hex Value - fixed IP ID
#   [x] RI - Random positive increments. Any (delta_i > 1000, and delta_i % 256 != 0) or (delta_i > 256000 and delta_i % 256 == 0)
#   [x] BI - Broken increment. All delta_i % 256 = 0 and all delta_i <= 5120.
#   [x] I - Incremental. All delta_i < 10
#   [x] O - (Ommited, the test does not show in the fingerprint). None of the other
# [-] IP ID sequence generation algorithm on TCP closed ports (CI)
# [x] IP ID sequence generation algorithm on ICMP messages (II)
# [x] Shared IP ID sequence Boolean (SS)
# [x] TCP timestamp option algorithm (TS)
#   [x] U - unsupported (don't send TS)
#   [x] 0 - Zero
#   [x] 1 - 0-5.66 (2 Hz)
#   [x] 7 - 70-150 (100 Hz)
#   [x] 8 - 150-350 (200 Hz)
#   [x]   - avg_freq = sum(TS_diff/time_diff) . round(.5 + math.log(avg_freq)/math.log(2)))
#           time_diff = 0.11 segs
# OPS()
# [x] TCP options (O, O1-O6)
# WIN()
# [x] TCP initial window size (W, W1-W6)
# ECN, T1-T7
# [x] TCP options (O, O1-O6)
# [x] TCP initial window size (W, W1-W6)
# [x] Responsiveness (R)
# [x] IP don't fragment bit (DF)
# [x] IP initial time-to-live (T)
# [x] IP initial time-to-live guess (TG)
# [x] Explicit congestion notification (CC)
# [x] TCP miscellaneous quirks (Q)
# [x] TCP sequence number (S)
# [x] TCP acknowledgment number (A)
# [x] TCP flags (F)
# [x] TCP RST data checksum (RD)
# IE()
# [x] Responsiveness (R)
# [x] Don't fragment (ICMP) (DFI)
# [x] IP initial time-to-live (T)
# [x] IP initial time-to-live guess (TG)
# [x] ICMP response code (CD)
#-[x] IP Type of Service (TOSI)
#-[x] ICMP Sequence number (SI)
#-[x] IP Data Length (DLI)
# U1()
# [x] Responsiveness (R)
# [x] IP don't fragment bit (DF)
# [x] IP initial time-to-live (T)
# [x] IP initial time-to-live guess (TG)
# [x] IP total length (IPL)
# [x] Unused port unreachable field nonzero (UN)
# [x] Returned probe IP total length value (RIPL)
# [x] Returned probe IP ID value (RID)
# [x] Integrity of returned probe IP checksum value (RIPCK)
# [x] Integrity of returned probe UDP checksum (RUCK)
# [x] Integrity of returned UDP data (RUD)
# [-] ??? (TOS) Type of Service
# [-] ??? (RUL) Length of return UDP packet is correct

# sudo nmap -O 127.0.0.2 -p 22,111,89
# sudo python nmapAnswerMachine.py -i eth0 -p 192.168.66.254 -f 'Sun Solaris 9 (SPARC)'
