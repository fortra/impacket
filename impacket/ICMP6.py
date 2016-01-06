# Copyright (c) 2003-2016 CORE Security Technologies
# 
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
# 

import array
import struct

from ImpactPacket import Header, Data
from IP6_Address import IP6_Address


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
    ROUTER_SOLICITATION = 133
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICITATION = 135
    NEIGHBOR_ADVERTISEMENT = 136
    REDIRECT_MESSAGE = 137
    NODE_INFORMATION_QUERY = 139
    NODE_INFORMATION_REPLY = 140
    
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
    
    #Node Information codes
    NODE_INFORMATION_QUERY_IPV6 = 0
    NODE_INFORMATION_QUERY_NAME_OR_EMPTY = 1
    NODE_INFORMATION_QUERY_IPV4 = 2
    NODE_INFORMATION_REPLY_SUCCESS = 0
    NODE_INFORMATION_REPLY_REFUSED = 1
    NODE_INFORMATION_REPLY_UNKNOWN_QTYPE = 2
    
    #Node Information qtypes
    NODE_INFORMATION_QTYPE_NOOP = 0
    NODE_INFORMATION_QTYPE_UNUSED = 1
    NODE_INFORMATION_QTYPE_NODENAME = 2
    NODE_INFORMATION_QTYPE_NODEADDRS = 3
    NODE_INFORMATION_QTYPE_IPv4ADDRS = 4
    
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
                     ECHO_REPLY : (INFORMATIONAL_MESSAGE, "Echo reply", None),
                     ROUTER_SOLICITATION : (INFORMATIONAL_MESSAGE, "Router Solicitation", None),
                     ROUTER_ADVERTISEMENT : (INFORMATIONAL_MESSAGE, "Router Advertisement", None),
                     NEIGHBOR_SOLICITATION : (INFORMATIONAL_MESSAGE, "Neighbor Solicitation", None),
                     NEIGHBOR_ADVERTISEMENT : (INFORMATIONAL_MESSAGE, "Neighbor Advertisement", None),
                     REDIRECT_MESSAGE : (INFORMATIONAL_MESSAGE, "Redirect Message", None),
                     NODE_INFORMATION_QUERY: (INFORMATIONAL_MESSAGE, "Node Information Query", None),
                     NODE_INFORMATION_REPLY: (INFORMATIONAL_MESSAGE, "Node Information Reply", None),
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

    @classmethod
    def Neighbor_Solicitation(class_object, target_address):
        return class_object.__build_neighbor_message(ICMP6.NEIGHBOR_SOLICITATION, target_address)
    
    @classmethod
    def Neighbor_Advertisement(class_object, target_address):
        return class_object.__build_neighbor_message(ICMP6.NEIGHBOR_ADVERTISEMENT, target_address)

    @classmethod
    def __build_neighbor_message(class_object, msg_type, target_address):
        #Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(msg_type)
        icmp_packet.set_code(0)
        
        # Flags + Reserved
        icmp_bytes = array.array('B', [0x00] * 4).tostring()       
        
        # Target Address: The IP address of the target of the solicitation.
        # It MUST NOT be a multicast address.
        icmp_bytes += array.array('B', IP6_Address(target_address).as_bytes()).tostring()
        
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        #Link payload to header
        icmp_packet.contains(icmp_payload)
        
        return icmp_packet

############################################################################

    def get_target_address(self):
        return IP6_Address(self.child().get_bytes()[4:20])

    def set_target_address(self, target_address):
        address = IP6_Address(target_address)
        payload_bytes = self.child().get_bytes()
        payload_bytes[4:20] = address.get_bytes()
        self.child().set_bytes(payload_bytes)

    #  0 1 2 3 4 5 6 7 
    # +-+-+-+-+-+-+-+-+
    # |R|S|O|reserved |
    # +-+-+-+-+-+-+-+-+

    def get_neighbor_advertisement_flags(self):
        return self.child().get_byte(0)

    def set_neighbor_advertisement_flags(self, flags):
        self.child().set_byte(0, flags)

    def get_router_flag(self):
        return (self.get_neighbor_advertisement_flags() & 0x80) != 0
    
    def set_router_flag(self, flag_value):
        curr_flags = self.get_neighbor_advertisement_flags()
        if flag_value:
            curr_flags |= 0x80
        else:
            curr_flags &= ~0x80
        self.set_neighbor_advertisement_flags(curr_flags)
    
    def get_solicited_flag(self):
        return (self.get_neighbor_advertisement_flags() & 0x40) != 0
    
    def set_solicited_flag(self, flag_value):
        curr_flags = self.get_neighbor_advertisement_flags()
        if flag_value:
            curr_flags |= 0x40
        else:
            curr_flags &= ~0x40
        self.set_neighbor_advertisement_flags(curr_flags)
    
    def get_override_flag(self):
        return (self.get_neighbor_advertisement_flags() & 0x20) != 0
    
    def set_override_flag(self, flag_value):
        curr_flags = self.get_neighbor_advertisement_flags()
        if flag_value:
            curr_flags |= 0x20
        else:
            curr_flags &= ~0x20
        self.set_neighbor_advertisement_flags(curr_flags)

############################################################################
    @classmethod
    def Node_Information_Query(class_object, code, payload = None):
        return class_object.__build_node_information_message(ICMP6.NODE_INFORMATION_QUERY, code, payload)

    @classmethod
    def Node_Information_Reply(class_object, code, payload = None):
        return class_object.__build_node_information_message(ICMP6.NODE_INFORMATION_REPLY, code, payload)
        
    @classmethod
    def __build_node_information_message(class_object, type, code, payload = None):
        #Build ICMP6 header
        icmp_packet = ICMP6()
        icmp_packet.set_type(type)
        icmp_packet.set_code(code)
        
        #Pack ICMP payload
        qtype = 0
        flags = 0
        nonce = [0x00] * 8
        
        icmp_bytes = struct.pack('>H', qtype)
        icmp_bytes += struct.pack('>H', flags)
        icmp_bytes += array.array('B', nonce).tostring()
        
        if payload is not None:
            icmp_bytes += array.array('B', payload).tostring()
        
        icmp_payload = Data()
        icmp_payload.set_data(icmp_bytes)
        
        #Link payload to header
        icmp_packet.contains(icmp_payload)

        return icmp_packet
    
    def get_qtype(self):
        return self.child().get_word(0)

    def set_qtype(self, qtype):
        self.child().set_word(0, qtype)

    def get_nonce(self):
        return self.child().get_bytes()[4:12]

    def set_nonce(self, nonce):
        payload_bytes = self.child().get_bytes()
        payload_bytes[4:12] = array.array('B', nonce)
        self.child().set_bytes(payload_bytes)

    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |      unused       |G|S|L|C|A|T|
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    def get_flags(self):
        return self.child().get_word(2)

    def set_flags(self, flags):
        self.child().set_word(2, flags)

    def get_flag_T(self):
        return (self.get_flags() & 0x0001) != 0
    
    def set_flag_T(self, flag_value):
        curr_flags = self.get_flags()
        if flag_value:
            curr_flags |= 0x0001
        else:
            curr_flags &= ~0x0001
        self.set_flags(curr_flags)
        
    def get_flag_A(self):
        return (self.get_flags() & 0x0002) != 0
    
    def set_flag_A(self, flag_value):
        curr_flags = self.get_flags()
        if flag_value:
            curr_flags |= 0x0002
        else:
            curr_flags &= ~0x0002
        self.set_flags(curr_flags)

    def get_flag_C(self):
        return (self.get_flags() & 0x0004) != 0
    
    def set_flag_C(self, flag_value):
        curr_flags = self.get_flags()
        if flag_value:
            curr_flags |= 0x0004
        else:
            curr_flags &= ~0x0004
        self.set_flags(curr_flags)

    def get_flag_L(self):
        return (self.get_flags() & 0x0008) != 0
    
    def set_flag_L(self, flag_value):
        curr_flags = self.get_flags()
        if flag_value:
            curr_flags |= 0x0008
        else:
            curr_flags &= ~0x0008
        self.set_flags(curr_flags)

    def get_flag_S(self):
        return (self.get_flags() & 0x0010) != 0
    
    def set_flag_S(self, flag_value):
        curr_flags = self.get_flags()
        if flag_value:
            curr_flags |= 0x0010
        else:
            curr_flags &= ~0x0010
        self.set_flags(curr_flags)

    def get_flag_G(self):
        return (self.get_flags() & 0x0020) != 0
    
    def set_flag_G(self, flag_value):
        curr_flags = self.get_flags()
        if flag_value:
            curr_flags |= 0x0020
        else:
            curr_flags &= ~0x0020
        self.set_flags(curr_flags)

    def set_node_information_data(self, data):
        payload_bytes = self.child().get_bytes()
        payload_bytes[12:] = array.array('B', data)
        self.child().set_bytes(payload_bytes)

    def get_note_information_data(self):
        return self.child().get_bytes()[12:]

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
                    
