# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#    Cisco Discovery Protocol packet codecs.
#
# Author:
#  Martin Candurra
#  martincad at corest.com

from struct import unpack
import socket

from ImpactPacket import Header
from impacket import LOG

IP_ADDRESS_LENGTH = 4

class CDPTypes:

    DeviceID_Type       = 1
    Address_Type        = 2
    PortID_Type         = 3
    Capabilities_Type   = 4
    SoftVersion_Type    = 5
    Platform_Type       = 6
    IPPrefix_Type       = 7
    ProtocolHello_Type  = 8
    MTU_Type            = 17
    SystemName_Type     = 20
    SystemObjectId_Type = 21
    SnmpLocation        = 23
    
class CDP(Header):
    
    Type = 0x2000
    OUI =  0x00000c
    
    def __init__(self, aBuffer = None):
        Header.__init__(self, 8)
        if aBuffer:
            self.load_header(aBuffer)
            self._elements = self._getElements(aBuffer)

    def _getElements(self, aBuffer):
        # Remove version (1 byte), TTL (1 byte), and checksum (2 bytes)
        buff = aBuffer[4:]
        l = []
        finish = False
        while buff:
            elem = CDPElementFactory.create(buff)
            data = elem.get_data()
            l.append( elem )
            buff = buff[ elem.get_length() : ]
        return l

    def get_header_size(self):
        return 8
        
    def get_version(self):
        return self.get_byte(0)
        
    def get_ttl(self):
        return self.get_byte(1)
        
    def get_checksum(self):
        return self.get_word(2)

    def get_type(self):
        return self.get_word(4)
        
    def get_lenght(self):      
        return self.get_word(6)

    def getElements(self):
        return self._elements


    def __str__(self):
        knowcode = 0
        tmp_str = 'CDP Details:\n'
        for element in self._elements:
            tmp_str += "** Type:" + str(element.get_type()) + " " + str(element) + "\n"
        return tmp_str
        

def get_byte(buffer, offset):
    return unpack("!B", buffer[offset:offset+1])[0]

def get_word(buffer, offset):
    return unpack("!h", buffer[offset:offset+2])[0]

def get_long(buffer, offset):
    return unpack("!I", buffer[offset:offset+4])[0]

def get_bytes(buffer, offset, bytes):
    return buffer[offset:offset + bytes]

def mac_to_string(mac_bytes):
    bytes = unpack('!BBBBBB', mac_bytes)
    s = ''
    for byte in bytes:
        s += '%02x:' % byte
    return s[0:-1]
    
    

class CDPElement(Header):

    def __init__(self, aBuffer = None):
        Header.__init__(self, 8)
        if aBuffer:
            self._length = CDPElement.Get_length(aBuffer)
            self.load_header( aBuffer[:self._length] )

    @classmethod
    def Get_length(cls, aBuffer):
        return unpack('!h', aBuffer[2:4])[0]

    def get_header_size(self):
        self._length

    def get_length(self):
        return self.get_word(2)
                
    def get_data(self):        
        return self.get_bytes().tostring()[4:self.get_length()]

    def get_ip_address(self, offset = 0, ip = None):
        if not ip:
            ip = self.get_bytes().tostring()[offset : offset + IP_ADDRESS_LENGTH]
        return socket.inet_ntoa( ip )
        
class CDPDevice(CDPElement):
    Type = 1
    
    def get_type(self):
        return CDPDevice.Type
    
    def get_device_id(self):
        return CDPElement.get_data(self)

    def __str__(self):
        return "Device:" + self.get_device_id()

class Address(CDPElement):
    Type = 2
   
    def __init__(self, aBuffer = None):
        CDPElement.__init__(self, aBuffer)
        if aBuffer:
            data = self.get_bytes().tostring()[8:]
            self._generateAddressDetails(data)

    def _generateAddressDetails(self, buff):
        self.address_details = []
        while buff:
            address = AddressDetails.create(buff)
            self.address_details.append( address )
            buff = buff[address.get_total_length():]

    def get_type(self):
        return Address.Type
    
    def get_number(self):
        return self.get_long(4)
       
    def get_address_details(self):
        return self.address_details
        
    def __str__(self):
        tmp_str = "Addresses:"
        for address_detail in self.address_details:
            tmp_str += "\n" + str(address_detail)
        return tmp_str        
        
class AddressDetails():        
          
    PROTOCOL_IP = 0xcc          
          
    @classmethod
    def create(cls, buff):
        a = AddressDetails(buff)
        return a


    def __init__(self, aBuffer = None):
        if aBuffer:
            addr_length = unpack("!h", aBuffer[3:5])[0]
            self.total_length = addr_length + 5
            self.buffer = aBuffer[:self.total_length]
    
    def get_total_length(self):
        return self.total_length
        
    def get_protocol_type(self):
        return self.buffer[0:1]
        
    def get_protocol_length(self):
        return get_byte( self.buffer, 1)

    def get_protocol(self):
        return get_byte( self.buffer, 2)
        
    def get_address_length(self):
        return get_word( self.buffer, 3)
        
    def get_address(self):
        address =  get_bytes( self.buffer, 5, self.get_address_length() )
        if  self.get_protocol()==AddressDetails.PROTOCOL_IP:
            return socket.inet_ntoa(address)
        else:
            LOG.error("Address not IP")
            return address            
            
    def is_protocol_IP(self):
        return self.get_protocol()==AddressDetails.PROTOCOL_IP
            
    def __str__(self):
        return "Protocol Type:%r Protocol:%r Address Length:%r Address:%s" % (self.get_protocol_type(), self.get_protocol(), self.get_address_length(), self.get_address())            
       
class Port(CDPElement):
    Type = 3
    
    def get_type(self):
        return Port.Type
    
    def get_port(self):
        return CDPElement.get_data(self)                

    def __str__(self):
        return "Port:" + self.get_port()


class Capabilities(CDPElement):
    Type = 4
    
    def __init__(self, aBuffer = None):
        CDPElement.__init__(self, aBuffer)
        self._capabilities_processed = False
        
        self._router = False
        self._transparent_bridge = False
        self._source_route_bridge = False
        self._switch = False
        self._host = False
        self._igmp_capable = False
        self._repeater = False
        self._init_capabilities()
        
    def get_type(self):
        return Capabilities.Type
    
    def get_capabilities(self):
        return CDPElement.get_data(self)  
        
    def _init_capabilities(self):
        if self._capabilities_processed:
            return
        
        capabilities = unpack("!L", self.get_capabilities())[0]
        self._router = (capabilities & 0x1) > 0
        self._transparent_bridge = (capabilities & 0x02) > 0
        self._source_route_bridge = (capabilities & 0x04) > 0
        self._switch = (capabilities & 0x08) > 0
        self._host = (capabilities & 0x10) > 0
        self._igmp_capable = (capabilities & 0x20) > 0
        self._repeater = (capabilities & 0x40) > 0

    def is_router(self):
        return self._router

    def is_transparent_bridge(self):
        return self._transparent_bridge

    def is_source_route_bridge(self):
        return self._source_route_bridge
        
    def is_switch(self):
        return self._switch

    def is_host(self):
        return self.is_host

    def is_igmp_capable(self):
        return self._igmp_capable
        
    def is_repeater(self):
        return self._repeater

                 
    def __str__(self):
        return "Capabilities:" + self.get_capabilities()
                 
                                
class SoftVersion(CDPElement):
    Type = 5
    
    def get_type(self):
        return SoftVersion.Type
    
    def get_version(self):
        return CDPElement.get_data(self)

    def __str__(self):
        return "Version:" + self.get_version()

  
class Platform(CDPElement):
    Type = 6
    
    def get_type(self):
        return Platform.Type
    
    def get_platform(self):
        return CDPElement.get_data(self)                

    def __str__(self):
        return "Platform:%r" % self.get_platform()                
      

class IpPrefix(CDPElement):
    Type = 7
    
    def get_type(self):
        return IpPrefix .Type
    
    def get_ip_prefix(self):
        return CDPElement.get_ip_address(self, 4)                

    def get_bits(self):
        return self.get_byte(8)        
        
    def __str__(self):
        return "IP Prefix/Gateway: %r/%d" % (self.get_ip_prefix(), self.get_bits())
      
class ProtocolHello(CDPElement):
    Type = 8
    
    def get_type(self):
        return ProtocolHello.Type

    def get_master_ip(self):
        return self.get_ip_address(9)

    def get_version(self):
        return self.get_byte(17)

    def get_sub_version(self):
        return self.get_byte(18)

    def get_status(self):
        return self.get_byte(19)

    def get_cluster_command_mac(self):
        return self.get_bytes().tostring()[20:20+6]
            
    def get_switch_mac(self):
        return self.get_bytes().tostring()[28:28+6]
            
    def get_management_vlan(self):
        return self.get_word(36)

    def __str__(self):
        return "\n\n\nProcolHello: Master IP:%s version:%r subversion:%r status:%r Switch's Mac:%r Management VLAN:%r" \
         % (self.get_master_ip(), self.get_version(), self.get_sub_version(), self.get_status(), mac_to_string(self.get_switch_mac()), self.get_management_vlan())
                      
class VTPManagementDomain(CDPElement):
    Type = 9
    
    def get_type(self):
        return VTPManagementDomain.Type
    
    def get_domain(self):
        return CDPElement.get_data(self)                  
  
  
class Duplex(CDPElement):
    Type = 0xb
    
    def get_type(self):
        return Duplex.Type
    
    def get_duplex(self):
        return CDPElement.get_data(self)                
                
    def is_full_duplex(self):
        return self.get_duplex()==0x1
        
class VLAN(CDPElement):
    Type = 0xa
                
    def get_type(self):
        return VLAN.Type
        
    def get_vlan_number(self):
        return CDPElement.get_data(self)



class TrustBitmap(CDPElement):
    Type = 0x12
    
    def get_type(self):
        return TrustBitmap.Type

    def get_trust_bitmap(self):
        return self.get_data()

    def __str__(self):
        return "TrustBitmap Trust Bitmap:%r" % self.get_trust_bitmap()

class UntrustedPortCoS(CDPElement):
    Type = 0x13
    
    def get_type(self):
        return UntrustedPortCoS.Type

    def get_port_CoS(self):
        return self.get_data()

    def __str__(self):
        return "UntrustedPortCoS port CoS %r" % self.get_port_CoS()

class ManagementAddresses(Address):
    Type = 0x16
    
    def get_type(self):
        return ManagementAddresses.Type
        
class MTU(CDPElement):
    Type = 0x11
    
    def get_type(self):
        return MTU.Type
        
class SystemName(CDPElement):
    Type = 0x14
    
    def get_type(self):
        return SystemName.Type

class SystemObjectId(CDPElement):
    Type = 0x15
    
    def get_type(self):
        return SystemObjectId.Type

class SnmpLocation(CDPElement):
    Type = 0x17
    
    def get_type(self):
        return SnmpLocation.Type


class DummyCdpElement(CDPElement):
    Type = 0x99

    def get_type(self):
        return DummyCdpElement.Type

class CDPElementFactory():
    
    elementTypeMap = {
                        CDPDevice.Type            : CDPDevice, 
                        Port.Type                 : Port,
                        Capabilities.Type         : Capabilities,
                        Address.Type              : Address, 
                        SoftVersion.Type          : SoftVersion,
                        Platform.Type             : Platform,
                        IpPrefix.Type             : IpPrefix,
                        ProtocolHello.Type        : ProtocolHello,
                        VTPManagementDomain.Type  : VTPManagementDomain,
                        VLAN.Type                 : VLAN,
                        Duplex.Type               : Duplex,
                        TrustBitmap.Type          : TrustBitmap,
                        UntrustedPortCoS.Type     : UntrustedPortCoS,
                        ManagementAddresses.Type  : ManagementAddresses,
                        MTU.Type                  : MTU,
                        SystemName.Type           : SystemName,
                        SystemObjectId.Type       : SystemObjectId,
                        SnmpLocation.Type         : SnmpLocation
                     }
    
    @classmethod
    def create(cls, aBuffer):
#        print "CDPElementFactory.create aBuffer:", repr(aBuffer)
#        print "CDPElementFactory.create sub_type:", repr(aBuffer[0:2])
        _type = unpack("!h", aBuffer[0:2])[0]
#        print "CDPElementFactory.create _type:", _type
        try:
            class_type = cls.elementTypeMap[_type]
        except KeyError:
            class_type = DummyCdpElement
            #raise Exception("CDP Element type %s not implemented" % _type)
        return class_type( aBuffer )                   
