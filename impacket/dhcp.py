# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

from impacket import structure
from impacket.ImpactPacket import ProtocolPacket

class BootpPacket(ProtocolPacket, structure.Structure):
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
            
    def __init__(self, data = None, alignment = 0):
        structure.Structure.__init__(self, data, alignment)

class DhcpPacket(ProtocolPacket, structure.Structure):
    # DHCP: http://www.faqs.org/rfcs/rfc2131.html
    # DHCP Options: http://www.faqs.org/rfcs/rfc1533.html
    # good list of options: http://www.networksorcery.com/enp/protocol/bootp/options.htm
    MAGIC_NUMBER = 0x63825363
    BOOTREQUEST = 1
    BOOTREPLY   = 2

    DHCPDISCOVER= 1
    DHCPOFFER   = 2
    DHCPREQUEST = 3 
    DHCPDECLINE = 4
    DHCPACK     = 5
    DHCPNAK     = 6
    DHCPRELEASE = 7
    DHCPINFORM  = 8
        
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
        'netbios-name-server':(44,'*!L'),
        'netbios-datagrame-distribution-server':(45,'*!L'),
        'netbios-node-type':(46,'B'),
        'netbios-scope':(47,':'),
        'x11-font-server':(48,'*!L'),
        'x11-display-manager':(49,'*!L'),


        # 9. DHCP Extensions
        'requested-ip':(50,'!L'),
        'lease-time':(51,'!L'),
        'option-overload':(52,'B'),
        'message-type':(53,'B'),
        'server-id':(54,'!L'),
        'parameter-request-list':(55,':'),
        'message':(56,':'),
        'maximum-dhcp-message-size':(57,'!H'),
        'renewal-time':(58,'!L'),
        'rebinding-time':(59,'!L'),
        'vendor-class':(60,':'),
        'client-id':(61,':'),

        # other non-rfc1533 options
        'slp-directory-agent':(78,':'),           # http://www.ietf.org/rfc/rfc2610.txt
        'slp-service-scope':(79,':'),             # http://www.ietf.org/rfc/rfc2610.txt
        'fully-qualified-domain-name':(81,':'),   # http://www.ietf.org/rfc/rfc4702.txt
        'default-url': (114, ':'),                # text (URL) - not defined in any RFC but assigned by IANA
        'auto-configuration':(116,'B'),           # http://www.ietf.org/rfc/rfc2563.txt
        'domain-search-list':(119,'B'),           # http://www.ietf.org/rfc/rfc3397.txt
        'classless-route-121':(121, ':'),         # http://www.ietf.org/rfc/rfc3442.txt
        'classless-route-249':(249, ':'),         # http://support.microsoft.com/kb/121005
        'proxy-autoconfig':(252,':'),
        'eof':(255,'_'),
    }
    
    structure = (
            ('cookie','!L'),
            ('_options',':=self.packOptions(options)'),
            ('options','_','self.unpackOptions(_options)'))

    def __init__(self, data = None, alignment = 0):
        structure.Structure.__init__(self, data, alignment)
    
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

    def unpackParameterRequestList(self, options):
        return [self.getOptionNameAndFormat(ord(opt))[0] for opt in options]
        
    def isAskingForProxyAutodiscovery(self):
        for opt in self.fields['options']:
            if opt[0] == 'parameter-request-list':
                for optCode in opt[1]:
                    if ord(optCode) == 252:
                        return True
        return False
    
    def getOptionValue(self, name):
        for opt in self.fields['options']:
            if opt[0] == name:
                return opt[1]
        return None
