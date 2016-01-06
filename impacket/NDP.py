# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

import array
import struct

from impacket import ImpactPacket
from ICMP6 import ICMP6


class NDP(ICMP6):
    #ICMP message type numbers
    ROUTER_SOLICITATION = 133
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICITATION = 135
    NEIGHBOR_ADVERTISEMENT = 136
    REDIRECT = 137

############################################################################
# Append NDP Option helper

    def append_ndp_option(self, ndp_option):
        #As NDP inherits ICMP6, it is, in fact an ICMP6 "header"
        #The payload (where all NDP options should reside) is a child of the header
        self.child().get_bytes().extend(ndp_option.get_bytes())
                
        
############################################################################
    @classmethod
    def Router_Solicitation(class_object):
        message_data = struct.pack('>L', 0) #Reserved bytes
        return class_object.__build_message(NDP.ROUTER_SOLICITATION, message_data)

    @classmethod
    def Router_Advertisement(class_object, current_hop_limit, 
                             managed_flag, other_flag, 
                             router_lifetime, reachable_time, retransmission_timer):        
        flag_byte = 0x00
        if (managed_flag):
            flag_byte |= 0x80
        if (other_flag):
            flag_byte |= 0x40
            
        message_data = struct.pack('>BBHLL', current_hop_limit, flag_byte, router_lifetime, reachable_time, retransmission_timer)
        return class_object.__build_message(NDP.ROUTER_ADVERTISEMENT, message_data)

    @classmethod
    def Neighbor_Solicitation(class_object, target_address):        
        message_data = struct.pack('>L', 0) #Reserved bytes
        message_data += target_address.as_bytes().tostring()
        return class_object.__build_message(NDP.NEIGHBOR_SOLICITATION, message_data)


    @classmethod
    def Neighbor_Advertisement(class_object, router_flag, solicited_flag, override_flag, target_address):                
        flag_byte = 0x00
        if (router_flag):
            flag_byte |= 0x80
        if (solicited_flag):
            flag_byte |= 0x40
        if (override_flag):
            flag_byte |= 0x20
            
        message_data = struct.pack('>BBBB', flag_byte, 0x00, 0x00, 0x00) #Flag byte and three reserved bytes
        message_data += target_address.as_bytes().tostring()
        return class_object.__build_message(NDP.NEIGHBOR_ADVERTISEMENT, message_data)


    @classmethod
    def Redirect(class_object, target_address, destination_address):        
        message_data = struct.pack('>L', 0)# Reserved bytes
        message_data += target_address.as_bytes().tostring()
        message_data += destination_address.as_bytes().tostring()
        return class_object.__build_message(NDP.REDIRECT, message_data)

    
    @classmethod
    def __build_message(class_object, type, message_data):
        #Build NDP header
        ndp_packet = NDP()
        ndp_packet.set_type(type)
        ndp_packet.set_code(0)
        
        #Pack payload
        ndp_payload = ImpactPacket.Data()
        ndp_payload.set_data(message_data)
        ndp_packet.contains(ndp_payload)
        
        return ndp_packet


    
        
class NDP_Option():
    #NDP Option Type numbers
    SOURCE_LINK_LAYER_ADDRESS = 1
    TARGET_LINK_LAYER_ADDRESS = 2
    PREFIX_INFORMATION = 3
    REDIRECTED_HEADER = 4
    MTU_OPTION = 5
    
############################################################################
    @classmethod    
    #link_layer_address must have a size that is a multiple of 8 octets
    def Source_Link_Layer_Address(class_object, link_layer_address):
        return class_object.__Link_Layer_Address(NDP_Option.SOURCE_LINK_LAYER_ADDRESS, link_layer_address)

    @classmethod    
    #link_layer_address must have a size that is a multiple of 8 octets
    def Target_Link_Layer_Address(class_object, link_layer_address):
        return class_object.__Link_Layer_Address(NDP_Option.TARGET_LINK_LAYER_ADDRESS, link_layer_address)

    @classmethod    
    #link_layer_address must have a size that is a multiple of 8 octets
    def __Link_Layer_Address(class_object, option_type, link_layer_address):
        option_length = (len(link_layer_address) / 8) + 1
        option_data = array.array("B", link_layer_address).tostring()
        return class_object.__build_option(option_type, option_length, option_data)

    @classmethod
    #Note: if we upgraded to Python 2.6, we could use collections.namedtuples for encapsulating the arguments
    #ENHANCEMENT - Prefix could be an instance of IP6_Address 
    def Prefix_Information(class_object, prefix_length, on_link_flag, autonomous_flag, valid_lifetime, preferred_lifetime, prefix):
        
        flag_byte = 0x00
        if (on_link_flag):
            flag_byte |= 0x80
        if (autonomous_flag):
            flag_byte |= 0x40
        
        option_data = struct.pack('>BBLL', prefix_length, flag_byte, valid_lifetime, preferred_lifetime)
        option_data += struct.pack('>L', 0) #Reserved bytes
        option_data += array.array("B", prefix).tostring()
        option_length = 4        
        return class_object.__build_option(NDP_Option.PREFIX_INFORMATION, option_length, option_data)
        
        
    @classmethod    
    def Redirected_Header(class_object, original_packet):
        option_data = struct.pack('>BBBBBB', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)# Reserved bytes
        option_data += array.array("B", original_packet).tostring()
        option_length = (len(option_data) + 4) / 8  
        return class_object.__build_option(NDP_Option.REDIRECTED_HEADER, option_length, option_data)
    
    @classmethod    
    def MTU(class_object, mtu):
        option_data = struct.pack('>BB', 0x00, 0x00)# Reserved bytes
        option_data += struct.pack('>L', mtu)
        option_length = 1
        return class_object.__build_option(NDP_Option.MTU_OPTION, option_length, option_data)


    @classmethod
    def __build_option(class_object, type, length, option_data):
        #Pack data
        data_bytes = struct.pack('>BB', type, length)
        data_bytes += option_data
        ndp_option = ImpactPacket.Data()
        ndp_option.set_data(data_bytes)
        
        return ndp_option
    
