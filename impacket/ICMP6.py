
from ImpactPacket import Header
from impacket import ImpactPacket
from IP6 import IP6
import array, struct

class ICMP6(Header):
    IP_PROTOCOL_NUMBER = 58
    protocol = IP_PROTOCOL_NUMBER   #Used in ImpactDecoder
    HEADER_SIZE = 4

    #ICMP6 Message Type numbers
    DESTINATION_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4    
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    
    def __init__(self):
        Header.__init__(self, ICMP6.HEADER_SIZE)
    
    def get_header_size(self):
        return self.HEADER_SIZE
    
    def get_ip_protocol_number(self):
        return self.IP_PROTOCOL_NUMBER

    def __str__(self):        
        type = self.get_type()
        code = self.get_code()
        checksum = self.get_checksum()

        s = "Type: " + str(type) + "\n"
        s += "Code: " + str(code) + "\n"
        s += "Checksum: " + str(checksum) + "\n"
        return s
    
############################################################################
    def get_type(self):        
        return (self.get_byte(0))
    
    def get_code(self):
        return (self.get_byte(1))
    
    def get_checksum(self):
        return (self.get_word(2))
    
############################################################################
    def set_type(self, type):
        self.set_byte(0, type)
    
    def set_code(self, code):
        self.set_byte(1, code)
    
    def set_checksum(self, checksum):
        self.set_word(2, checksum)
    
############################################################################
    def calculate_checksum(self):        
        #Initialize the checksum value to 0 to yield a correct calculation
        self.set_checksum(0)        
        #Fetch the pseudo header from the IP6 parent packet
        pseudo_header = self.parent().get_pseudo_header()
        #Fetch the ICMP data
        icmp_header = self.get_bytes()
        #Build an array of bytes concatenating the pseudo_header, the ICMP header and the ICMP data (if present)
        checksum_array = array.array('B')
        checksum_array.extend(pseudo_header)
        checksum_array.extend(icmp_header)
        if (self.child()):
            checksum_array.extend(self.child().get_bytes())
            
        #Compute the checksum over that array
        self.set_checksum(self.compute_checksum(checksum_array))
        
############################################################################
    @classmethod
    def Echo_Request(class_object, id, sequence_number, arbitrary_data = None):
        return class_object.__build_echo_message(ICMP6.ECHO_REQUEST, id, sequence_number, arbitrary_data)
    
    @classmethod
    def Echo_Reply(class_object, id, sequence_number, arbitrary_data = None):
        return class_object.__build_echo_message(ICMP6.ECHO_REPLY, id, sequence_number, arbitrary_data)
    
    @classmethod
    def __build_echo_message(class_object, type, id, sequence_number, arbitrary_data):
        #Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(type)
        icmp_packet.set_code(0)
        
        #Pack ICMP payload
        icmp_bytes = struct.pack('>H', id)
        icmp_bytes += struct.pack('>H', sequence_number)
        if (arbitrary_data is not None):
            icmp_bytes += array.array('B', arbitrary_data).tostring()
        icmp_payload = ImpactPacket.Data()
        icmp_payload.set_data(icmp_bytes)
        
        #Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet
    
    
############################################################################
    @classmethod
    def Destination_Unreachable(class_object, code, originating_packet_data = None):
        unused_bytes = [0x00, 0x00, 0x00, 0x00]
        return class_object.__build_error_message(ICMP6.DESTINATION_UNREACHABLE, code, unused_bytes, originating_packet_data)

    @classmethod
    def Packet_Too_Big(class_object, MTU, originating_packet_data = None):
        MTU_bytes = struct.pack('!L', MTU)
        return class_object.__build_error_message(ICMP6.PACKET_TOO_BIG, 0, MTU_bytes, originating_packet_data)
    
    @classmethod
    def Time_Exceeded(class_object, code, originating_packet_data = None):
        unused_bytes = [0x00, 0x00, 0x00, 0x00]
        return class_object.__build_error_message(ICMP6.TIME_EXCEEDED, code, unused_bytes, originating_packet_data)

    @classmethod
    def Parameter_Problem(class_object, code, pointer, originating_packet_data = None):
        pointer_bytes = struct.pack('!L', pointer)
        return class_object.__build_error_message(ICMP6.PARAMETER_PROBLEM, code, pointer_bytes, originating_packet_data)
    
    @classmethod    
    def __build_error_message(class_object, type, code, data, originating_packet_data):
        #Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(type)
        icmp_packet.set_code(code)
        
        #Pack ICMP payload
        icmp_bytes = array.array('B', data).tostring()
        if (originating_packet_data is not None):
            icmp_bytes += array.array('B', originating_packet_data).tostring()
        icmp_payload = ImpactPacket.Data()
        icmp_payload.set_data(icmp_bytes)
        
        #Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet
            