from impacket import structure

class BootpPacket(structure.Structure):
    commonHdr = (
            ('op','b'),
            ('htype','b=1'),    # 1 = Ether
            ('hlen','b=len(chaddr)'),
            ('hops','b=0'),
            ('xid','!L=0'),
            ('secs','!H=0'),
            ('flags','!H=0'),
            ('ciaddr','!L=0'),
            ('yiaddr','!L=0'),
            ('siaddr','!L=0'),
            ('giaddr','!L=0'),
            ('_chaddr','16s=chaddr'),
            ('chaddr','_','_chaddr[:hlen]'),
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
        # 3. Vendor Extensions
        'pad':(0,'_'),
        'subnet-mask':(1,'!L'),
        'time-offset':(2,'!L'),
        'router':(3,'*!L'),
        'time-server':(4,'*!L'),
        'name-server':(5,'*!L'),
        'domain-name-server':(6,'*!L'),
        'log-server':(7,'*!L'),
        'cookie-server':(8,'*!L'),
        'lpr-server':(9,'*!L'),
        'impress-server':(10,'*!L'),
        'resource-locator-server':(11,'*!L'),
        'host-name':(12,':'),
        'boot-file-size':(13,'!H'),
        'merit-dump-file':(14,':'),
        'domain-name':(15,':'),
        'swap-server':(16,':'),
        'root-path':(17,':'),
        'extensions-path':(18,':'),

        # 4. IP Layer Parameters per Host
        'ip-forwarding':(19,'B'),
        'non-local-source-routing':(20,'B'),
        'policy-filter':(21,'*!L'),
        'maximum-datagram-reassembly-size':(22,'!H'),
        'default-ip-ttl':(23,'B'),
        'path-mtu-aging-timeout':(24,'!L'),
        'path-mtu-plateau-table':(25,'*!H'),

        # 5. IP Layer Parameters per Interface
        'interface-mtu':(26,'!H'),
        'all-subnets-are-local':(27,'B'),
        'broadcast-address':(28,'!L'),
        'perform-mask-discovery':(29,'B'),
        'mask-supplier':(30,'B'),
        'perform-router-discovery':(31,'B'),
        'router-solicitation-address':(32,'!L'),
        'static-route':(33,'*!L'),

        # 6. Link Layer Parameters per Interface
        'trailer-encapsulation':(34,'B'),
        'arp-cache-timeout':(35,'!L'),
        'ethernet-encapsulation':(36,'B'),

        # 7. TCP parameters
        'tcp-default-ttl':(37,'B'),
        'tcp-keepalive-interval':(38,'!L'),
        'tcp-keepalive-garbage':(39,'B'),

        # 8. Application and Service parameters
        'nis-domain':(40,':'),
        'nis-servers':(41,'*!L'),
        'ntp-servers':(42,'*!L'),


        'vendor-specific':(43,':'),
        'requested-ip':(50,'!L'),
        'lease-time':(51,'!L'),
        'message-type':(53,'B'),
        'parameter-request-list':(55,':'),
        'vendor-class':(60,':'),
        'client-id':(61,':'),
        'fully-qualified-domain-name':(81,':'),
        'auto-configuration':(116,'B'),
        'eof':(255,'_'),

    }
    
    structure = (
            ('cookie','!L'),
            ('_options',':=self.packOptions(options)'),
            ('options','_','self.unpackOptions(_options)'))
    
    def packOptions(self, options):
        # options is an array of tuples: ('name',value)

        answer = ''
        for name, value in options:
            code,format = self.options[name]
            val = self.pack(format, value)
            answer += '%c%c%s' % (code, len(val), val)

        return answer
    
    def getOptionNameAndFormat(self, optionCode):
        for k in self.options:
            code,format = self.options[k]
            if code == optionCode: return k, format
        return optionCode, ':'

    def unpackOptions(self, options):
        # options is a string

        # print '%r' % options
        answer = []
        i = 0
        while i < len(options)-1:
            name, format = self.getOptionNameAndFormat(ord(options[i]))
            # size = self.calcUnpackSize(format, options[i+1:])
            size = ord(options[i+1])
            # print i, name, format, size
            value = self.unpack(format, options[i+2:i+2+size])
            answer.append((name, value))
            i += 2+size

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
