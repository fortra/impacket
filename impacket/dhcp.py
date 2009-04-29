from impacket import structure

class BootpPacket(structure.Structure):
    commonHdr = (
            ('op','b'),
            ('htype','b=1'),    # 1 = Ether
            ('hlen','b-chaddr'),
            ('hops','b=0'),
            ('xid','!L=0'),
            ('secs','!H=0'),
            ('flags','!H=0'),
            ('ciaddr','!L=0'),
            ('yiaddr','!L=0'),
            ('siaddr','!L=0'),
            ('giaddr','!L=0'),
            ('chaddr','16s'),
            ('sname','64s=""'),
            ('file','128s=""'))
        
class DhcpPacket(BootpPacket):
    # DHCP: http://www.faqs.org/rfcs/rfc2131.html
    # DHCP Options: http://www.faqs.org/rfcs/rfc1533.html
    BOOTREQUEST = 1
    BOOTREPLY   = 2

    DHCPDISCOVER= 1
    DHCPOFFER   = 2
    DHCPREQUEST = 3 
    DHCPDECLINE = 4
    DHCPACK     = 5
    DHCPNAK     = 6
    DHCPRELEASE = 7
        

    options = {
        'message-type':(53,'B'),
        'host-name':(12,':'),
        'requested-ip':(50,'!L'),
        'client-id':(61,':'),
        'lease-time':(51,'!L'),
    }
    
    structure = (
            ('cookie','!L'),
            ('_options',':=self.packOptions(options)'),
            ('options','_'))
    
    def packOptions(self, options):
        # options is an array of tuples: ('name',value)

        answer = ''
        for name, value in options:
            code,format = self.options[name]
            val = self.pack(format, value)
            answer += '%c%c%s' % (code, len(val), val)

        return answer

class DHCPTool:
    def initialize(self):
        self.pcap = pcap.open_live(pcap.lookupdev(), -1, 1, 1)
        self.pcap.setfilter("port 67", 1, 0xffffff00)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect(('192.168.1.1',67))
        self.decoder = ImpactDecoder.EthDecoder()

    def targetRun(self):
        for i in range(1,254):
            self.sendDISCOVER('12345%c' % i, ip = '192.168.1.%d' % i)
            self.processPacketsForOneSecond()
            
    def finalize(self):
        self.pcap.close()
        Module.finalize(self)

    def processPacketsForOneSecond(self):
        t = time.time()
        while time.time()-t < 1:
            p = self.pcap.next()
            if p[1][2]:
                pp = self.decoder.decode(p[0])
                print pp
        
    def sendDHCP(self, type, chaddr, hostname = None, ip = None, xid = None,opts = []):
        p = DhcpPacket()

        opt = [('message-type',type)] + list(opts)

        if xid is None:
            xid = randint(0,0xffffffff)
        if ip:
            ip = structure.unpack('!L',socket.inet_aton(ip))[0]
            p['ciaddr'] = ip
            opt.append(('requested-ip',ip))

        if hostname is not None:
            for i in range(0,len(hostname),255):
                opt.append(('host-name',hostname[i:i+255]))

        p['op']     = p.BOOTREQUEST
        p['xid']    = xid
        p['chaddr'] = chaddr
        p['cookie'] = 0x63825363
        p['options'] = opt
        
        self.sock.send(str(p))

    def sendDISCOVER(self, chaddr, hostname = None, ip = None,xid = 0x12345678):
        print 'DHCPDISCOVER: %s' % ip
        self.sendDHCP(DhcpPacket.DHCPDISCOVER, chaddr, hostname, ip, xid)
