
from ImpactPacket import Header, Data
#from impacket import ImpactPacket
from IP6 import IP6
import array, struct

class ICMP6(Header):    
    #IP Protocol number for ICMP6
    IP_PROTOCOL_NUMBER = 58
    protocol = IP_PROTOCOL_NUMBER   #ImpactDecoder uses the constant "protocol" as the IP Protocol Number
    
    #Size of ICMP6 header (excluding payload)
    HEADER_SIZE = 4

    #ICMP6 Message Type numbers
    DESTINATION_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4    
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    
    #Destination Unreachable codes
    NO_ROUTE_TO_DESTINATION = 0
    ADMINISTRATIVELY_PROHIBITED = 1
    BEYOND_SCOPE_OF_SOURCE_ADDRESS = 2
    ADDRESS_UNREACHABLE = 3
    PORT_UNREACHABLE = 4
    SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY = 5
    REJECT_ROUTE_TO_DESTINATION = 6
    
    #Time Exceeded codes
    HOP_LIMIT_EXCEEDED_IN_TRANSIT = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1
    
    #Parameter problem codes
    ERRONEOUS_HEADER_FIELD_ENCOUNTERED = 0
    UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED = 1
    UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED = 2

    #ICMP Message semantic types (error or informational)    
    ERROR_MESSAGE = 0
    INFORMATIONAL_MESSAGE = 1
    
    #ICMP message dictionary - specifying text descriptions and valid message codes
    #Key: ICMP message number
    #Data: Tuple ( Message Type (error/informational), Text description, Codes dictionary (can be None) )
    #Codes dictionary
    #Key: Code number
    #Data: Text description
    
    #ICMP message dictionary tuple indexes
    MSG_TYPE_INDEX = 0
    DESCRIPTION_INDEX = 1
    CODES_INDEX = 2

    icmp_messages = {
                     DESTINATION_UNREACHABLE : (ERROR_MESSAGE, "Destination unreachable",
                                                { NO_ROUTE_TO_DESTINATION : "No route to destination",
                                                  ADMINISTRATIVELY_PROHIBITED : "Administratively prohibited",
                                                  BEYOND_SCOPE_OF_SOURCE_ADDRESS : "Beyond scope of source address",
                                                  ADDRESS_UNREACHABLE : "Address unreachable",
                                                  PORT_UNREACHABLE : "Port unreachable",
                                                  SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY : "Source address failed ingress/egress policy",
                                                  REJECT_ROUTE_TO_DESTINATION : "Reject route to destination"
                                                  }),
                     PACKET_TOO_BIG : (ERROR_MESSAGE, "Packet too big", None),
                     TIME_EXCEEDED : (ERROR_MESSAGE, "Time exceeded",
                                        {HOP_LIMIT_EXCEEDED_IN_TRANSIT : "Hop limit exceeded in transit",
                                        FRAGMENT_REASSEMBLY_TIME_EXCEEDED : "Fragment reassembly time exceeded"                                      
                                       }),
                     PARAMETER_PROBLEM : (ERROR_MESSAGE, "Parameter problem",
                                          {
                                           ERRONEOUS_HEADER_FIELD_ENCOUNTERED : "Erroneous header field encountered",
                                           UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED : "Unrecognized Next Header type encountered",
                                           UNRECOGNIZED_IPV6_OPTION_ENCOUNTERED : "Unrecognized IPv6 Option Encountered"
                                           }),
                     ECHO_REQUEST : (INFORMATIONAL_MESSAGE, "Echo request", None),
                     ECHO_REPLY : (INFORMATIONAL_MESSAGE, "Echo reply", None)
                    } 
    
    
    
    
############################################################################
    def __init__(self, buffer = None):
        Header.__init__(self, self.HEADER_SIZE)
        if (buffer):
            self.load_header(buffer)
    
    def get_header_size(self):
        return self.HEADER_SIZE
    
    def get_ip_protocol_number(self):
        return self.IP_PROTOCOL_NUMBER

    def __str__(self):        
        type = self.get_type()
        code = self.get_code()
        checksum = self.get_checksum()

        s = "ICMP6 - Type: " + str(type) + " - "  + self.__get_message_description() + "\n"
        s += "Code: " + str(code)
        if (self.__get_code_description() != ""):
            s += " - " + self.__get_code_description()
        s += "\n"
        s += "Checksum: " + str(checksum) + "\n"
        return s
    
    def __get_message_description(self):
        return self.icmp_messages[self.get_type()][self.DESCRIPTION_INDEX]
    
    def __get_code_description(self):
        code_dictionary = self.icmp_messages[self.get_type()][self.CODES_INDEX]
        if (code_dictionary is None):
            return ""
        else:
            return code_dictionary[self.get_code()]
    
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
        
    def is_informational_message(self):
        return self.icmp_messages[self.get_type()][self.MSG_TYPE_INDEX] == self.INFORMATIONAL_MESSAGE
        
    def is_error_message(self):
        return self.icmp_messages[self.get_type()][self.MSG_TYPE_INDEX] == self.ERROR_MESSAGE
    
    def is_well_formed(self):
        well_formed = True
        
        #Check that the message type is known
        well_formed &= self.get_type() in self.icmp_messages.keys()
        
        #Check that the code is known (zero, if there are no codes defined)
        code_dictionary = self.icmp_messages[self.get_type()][self.CODES_INDEX]
        if (code_dictionary is None):
            well_formed &= self.get_code() == 0
        else:            
            well_formed &= self.get_code() in code_dictionary.keys()
            
        return well_formed 
        
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
        icmp_payload = Data()
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
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        #Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet
############################################################################

    def get_echo_id(self):
        return self.child().get_word(0)
    
    def get_echo_sequence_number(self):
        return self.child().get_word(2)
    
    def get_echo_arbitrary_data(self):
        return self.child().get_bytes()[4:]
    
    def get_mtu(self):
        return self.child().get_long(0)
        
    def get_parm_problem_pointer(self):
        return self.child().get_long(0)
        
    def get_originating_packet_data(self):
        return self.child().get_bytes()[4:]
                    